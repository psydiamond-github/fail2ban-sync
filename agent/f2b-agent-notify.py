#!/usr/bin/env python3
"""Быстрый канал уведомления центра о бане/разбане — ускоритель: тот же факт всё равно
попадёт в дифф ближайшего чекина, поэтому все ошибки подавляются.

Два режима:
  f2b-agent-notify ban|unban <jail> <ip>   — сразу отправить (хосты без systemd, через setsid)
  f2b-agent-notify --flush-spool            — отправить строки, которые fail2ban дописал в
      /run/fail2ban/f2b-agent.events (хосты с systemd: запускает f2b-agent-notify.path).
      Из самого fail2ban слать нельзя: под SELinux домену fail2ban_t запрещены и systemd-run,
      и исходящее соединение к центру, а писать в свой /run/fail2ban — можно."""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.request

CONFIG_PATH = os.environ.get("F2B_AGENT_CONFIG", "/etc/f2b-agent/config.json")
SPOOL_PATH = os.environ.get("F2B_AGENT_SPOOL", "/run/fail2ban/f2b-agent.events")
TIMEOUT = 3
# Не больше стольких событий за запуск: при массовой волне банов остальное и так придёт
# в чекине, а сотни последовательных запросов только задержали бы следующие уведомления.
MAX_EVENTS = 200
_LINE_RE = re.compile(r"^(ban|unban) ([A-Za-z0-9_.-]+) (\S+)$")


def _load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def send(config: dict, event: str, jail: str, ip: str) -> None:
    if not config["center_url"].lower().startswith("https://"):
        return  # токен — только по HTTPS; факт бана всё равно уйдёт в ближайшем чекине
    ca_cert = config.get("ca_cert")
    context = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
    req = urllib.request.Request(
        config["center_url"].rstrip("/") + "/api/v1/event",
        data=json.dumps({"jail": jail, "ip": ip, "event": event}).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {config['token']}"},
    )
    urllib.request.urlopen(req, timeout=TIMEOUT, context=context).read()


def flush_spool() -> None:
    config = _load_config()
    # Пока файл отправляется, fail2ban может дописывать новые строки — забираем его
    # переименованием и повторяем, пока он появляется снова.
    for _ in range(10):
        taken = SPOOL_PATH + ".sending"
        try:
            os.replace(SPOOL_PATH, taken)
        except FileNotFoundError:
            return
        with open(taken, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        os.unlink(taken)
        for line in lines[:MAX_EVENTS]:
            m = _LINE_RE.match(line.strip())
            if not m:
                continue
            try:
                send(config, *m.groups())
            except Exception:
                pass  # best-effort — см. docstring


def main() -> int:
    try:
        if sys.argv[1:] == ["--flush-spool"]:
            flush_spool()
        elif len(sys.argv) == 4:
            send(_load_config(), sys.argv[1], sys.argv[2], sys.argv[3])
    except Exception:
        pass  # best-effort — намеренно; см. docstring
    return 0


if __name__ == "__main__":
    sys.exit(main())
