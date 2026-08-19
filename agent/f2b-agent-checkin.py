#!/usr/bin/env python3
"""Агент fail2ban-center — один чекин за запуск (systemd timer, не демон). Только стандартная
библиотека — на управляемом хосте не нужен pip/venv.

Поток: читает локальный конфиг+состояние -> опрашивает баны через f2b-agent-helper, считает
дифф с прошлым снимком -> один POST /api/v1/checkin (результаты прошлых задач + дифф, в ответ —
новые задачи) -> выполняет их через sudo f2b-agent-helper, сверяя jail с локальным
allowed_jails независимо от центра -> сохраняет состояние на диск только после успешного
round-trip, чтобы сбой сети не терял события."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

AGENT_VERSION = "1.0.0"

CONFIG_PATH = os.environ.get("F2B_AGENT_CONFIG", "/etc/f2b-agent/config.json")
STATE_PATH = os.environ.get("F2B_AGENT_STATE", "/var/lib/f2b-agent/state.json")
HELPER_PATH = os.environ.get("F2B_AGENT_HELPER", "/usr/local/sbin/f2b-agent-helper")
REQUEST_TIMEOUT = 15
HELPER_TIMEOUT = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("f2b-agent")

_BANIP_RE = re.compile(r"^(\S+)\s+(.*)$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config() -> dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for key in ("center_url", "token", "agent_name", "allowed_jails"):
        if key not in cfg:
            raise ValueError(f"в {CONFIG_PATH} отсутствует обязательное поле {key!r}")
    return cfg


def load_state() -> dict[str, Any]:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_bans": {}, "pending_results": []}


def save_state(state: dict[str, Any]) -> None:
    tmp = STATE_PATH + ".tmp"
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)
    try:
        os.chmod(STATE_PATH, 0o600)
    except OSError:
        pass


def run_helper(*args: str, stdin_data: Optional[str] = None) -> tuple[int, str, str]:
    cmd = ["sudo", HELPER_PATH, *args]
    try:
        result = subprocess.run(
            cmd, input=stdin_data, capture_output=True, text=True, timeout=HELPER_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return 1, "", f"таймаут выполнения: {' '.join(cmd)}"
    except OSError as e:
        return 1, "", f"не удалось запустить: {e}"
    return result.returncode, result.stdout, result.stderr


def _parse_banip_with_time(output: str) -> list[dict[str, str]]:
    """Разбирает вывод `fail2ban-client get <jail> banip --with-time`. since берётся как
    есть из fail2ban — важна лишь стабильность значения, пока бан непрерывен."""
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.lower() == "none":
            continue
        m = _BANIP_RE.match(line)
        if not m:
            continue
        ip, rest = m.group(1), m.group(2)
        since = rest.split("+", 1)[0].strip() if "+" in rest else rest.strip()
        entries.append({"ip": ip, "since": since or _now_iso()})
    return entries


def ensure_notify_actions(allowed_jails: list[dict[str, Any]]) -> None:
    """Хук уведомления — чистый runtime, не переживает restart fail2ban, поэтому проверяется
    на каждом тике; при уже установленном действии helper мгновенно отвечает "unchanged"."""
    for jail in allowed_jails:
        rc, _out, err = run_helper("ensure-notify-action", jail["name"])
        if rc != 0:
            log.warning("ensure-notify-action %s: %s", jail["name"], err.strip())


def query_current_bans(allowed_jails: list[dict[str, Any]]) -> dict[str, list[dict[str, str]]]:
    current: dict[str, list[dict[str, str]]] = {}
    for jail in allowed_jails:
        name = jail["name"]
        rc, out, err = run_helper("jail-bans", name)
        if rc != 0:
            log.warning("jail-bans %s: %s", name, err.strip())
            continue
        current[name] = _parse_banip_with_time(out)
    return current


def diff_bans(
    last: dict[str, list[dict[str, str]]], current: dict[str, list[dict[str, str]]]
) -> tuple[dict[str, list[dict[str, str]]], dict[str, list[dict[str, str]]]]:
    new_bans: dict[str, list[dict[str, str]]] = {}
    new_unbans: dict[str, list[dict[str, str]]] = {}
    for jail, entries in current.items():
        prev_ips = {e["ip"] for e in last.get(jail, [])}
        appeared = [e for e in entries if e["ip"] not in prev_ips]
        if appeared:
            new_bans[jail] = appeared
    for jail, entries in last.items():
        cur_ips = {e["ip"] for e in current.get(jail, [])}
        disappeared = [e for e in entries if e["ip"] not in cur_ips]
        if disappeared:
            # since разбана — момент обнаружения, не время истечения (fail2ban его не хранит).
            new_unbans[jail] = [{"ip": e["ip"], "since": _now_iso()} for e in disappeared]
    return new_bans, new_unbans


def execute_task(task: dict[str, Any], allowed_jail_names: set[str]) -> dict[str, Any]:
    task_id = task["task_id"]
    ttype = task["type"]
    jail = task.get("jail")

    if jail is not None and jail not in allowed_jail_names:
        # Вторая граница защиты — джейл вне локального allowed_jails не исполняется,
        # даже если задачу прислал центр.
        return {"task_id": task_id, "status": "error", "detail": f"джейл {jail!r} не разрешён"}

    if ttype == "ban":
        rc, _out, err = run_helper("jail-ban", jail, task["ip"])
    elif ttype == "unban":
        rc, _out, err = run_helper("jail-unban", jail, task["ip"])
    elif ttype == "ignore_add":
        rc, _out, err = run_helper("jail-addignoreip", jail, task["ip"])
    elif ttype == "ignore_del":
        rc, _out, err = run_helper("jail-delignoreip", jail, task["ip"])
    elif ttype == "permanent_ignore_sync":
        stdin_data = "\n".join(task.get("ip_list", [])) + "\n"
        rc, _out, err = run_helper("sync-permanent", stdin_data=stdin_data)
    elif ttype == "tor_sync":
        lines = [f"+{ip}" for ip in task.get("ban_ips", [])] + [f"-{ip}" for ip in task.get("unban_ips", [])]
        rc, _out, err = run_helper("tor-sync", stdin_data="\n".join(lines) + "\n")
    elif ttype == "report_full_state":
        return _execute_report_full_state(task_id, allowed_jail_names)
    elif ttype == "ping":
        rc, err = 0, ""
    else:
        return {"task_id": task_id, "status": "error", "detail": f"неизвестный тип задачи: {ttype}"}

    if rc == 0:
        return {"task_id": task_id, "status": "ok"}
    return {"task_id": task_id, "status": "error", "detail": err.strip()[:500]}


def _execute_report_full_state(task_id: str, allowed_jail_names: set[str]) -> dict[str, Any]:
    bans: dict[str, list[dict[str, str]]] = {}
    for name in allowed_jail_names:
        rc, out, err = run_helper("jail-bans", name)
        if rc != 0:
            log.warning("report_full_state: jail-bans %s: %s", name, err.strip())
            continue
        bans[name] = _parse_banip_with_time(out)

    rc, out, err = run_helper("jail-local-ignoreip")
    baseline = [tok for tok in out.split() if tok.strip()] if rc == 0 else []
    if rc != 0:
        log.warning("report_full_state: jail-local-ignoreip: %s", err.strip())

    return {"task_id": task_id, "status": "ok", "data": {"bans": bans, "baseline_ignoreip": baseline}}


def fetch_log_tail(offset: int) -> Optional[dict[str, Any]]:
    """Новые байты лога fail2ban с прошлой позиции — центр сам решает, использовать их
    (log_view_mode='local') или игнорировать. Недорого даже вхолостую: обычно пара строк."""
    rc, out, _err = run_helper("log-tail", str(offset))
    if rc != 0:
        return None
    header, _, content = out.partition("---\n")
    path, size = "", offset
    for line in header.splitlines():
        if line.startswith("PATH:"):
            path = line[5:]
        elif line.startswith("SIZE:"):
            try:
                size = int(line[5:])
            except ValueError:
                pass
    return {"path": path, "new_size": size, "content": content}


def checkin(config: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    url = config["center_url"].rstrip("/") + "/api/v1/checkin"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['token']}",
        },
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    config = load_config()
    allowed_jail_names = {j["name"] for j in config["allowed_jails"]}
    state = load_state()

    ensure_notify_actions(config["allowed_jails"])
    current_bans = query_current_bans(config["allowed_jails"])
    new_bans, new_unbans = diff_bans(state.get("last_bans", {}), current_bans)
    log_offset = state.get("log_offset", 0)
    log_tail = fetch_log_tail(log_offset)

    body = {
        "agent_id": config["agent_name"],
        "agent_version": AGENT_VERSION,
        "results": state.get("pending_results", []),
        "new_bans": new_bans,
        "new_unbans": new_unbans,
        "log_tail": log_tail,
    }

    try:
        response = checkin(config, body)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        log.error("checkin не удался: %s (состояние не изменено, повтор на следующем запуске)", e)
        return 1

    results = [execute_task(t, allowed_jail_names) for t in response.get("tasks", [])]
    for r in results:
        level = log.info if r["status"] == "ok" else log.error
        level("задача %s: %s%s", r["task_id"], r["status"], f" — {r['detail']}" if r.get("detail") else "")

    new_log_offset = log_tail["new_size"] if log_tail else log_offset
    save_state({
        "last_bans": current_bans,
        "pending_results": results,
        "log_offset": new_log_offset,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
