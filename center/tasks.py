"""Бизнес-логика протокола центр<->агент и действий, инициированных из UI."""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from typing import Any, Optional

import requests

import db


class IpPinRejected(Exception):
    """ip_pin_mode='strict' нарушён — checkin отклоняется без обработки тела запроса."""


def validate_ipv4(ip: str) -> None:
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as e:
        raise ValueError(f"Некорректный IPv4-адрес: {ip}") from e


def validate_jail_allowed(agent: dict[str, Any], jail: str) -> None:
    names = {j["name"] for j in agent["allowed_jails"]}
    if jail not in names:
        raise ValueError(f"Джейл {jail!r} не входит в разрешённый список агента {agent['name']!r}")


# === Протокол: checkin ========================================================================

def _normalize_ip_entries(entries: list) -> list[dict[str, str]]:
    """Принимает и голые IP-строки, и объекты {"ip","since"}."""
    out = []
    fallback_ts = db.now()
    for e in entries:
        if isinstance(e, dict):
            out.append({"ip": e.get("ip"), "since": e.get("since") or fallback_ts})
        else:
            out.append({"ip": e, "since": fallback_ts})
    return out


def _check_ip_pin(agent: dict[str, Any], remote_ip: str) -> None:
    pinned = agent.get("pinned_ip")
    if not pinned or remote_ip == pinned:
        return
    db.log_action(
        "system", agent["id"], "ip_pin_anomaly",
        detail=f"чекин с {remote_ip}, ожидался {pinned} (режим {agent.get('ip_pin_mode')})",
    )
    if agent.get("ip_pin_mode") == "strict":
        raise IpPinRejected(f"IP {remote_ip} не совпадает с закреплённым {pinned}")


def _check_rate_anomaly(agent: dict[str, Any]) -> None:
    """Логируется, но не блокирует — в отличие от ip_pin в strict-режиме."""
    last_seen = agent.get("last_seen")
    if not last_seen:
        return
    try:
        last_dt = datetime.fromisoformat(last_seen)
    except ValueError:
        return
    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=timezone.utc)
    interval = int(db.get_setting("checkin_interval_seconds", "60"))
    elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds()
    if elapsed < interval * 0.5:
        db.log_action(
            "system", agent["id"], "checkin_rate_anomaly",
            detail=f"чекин через {elapsed:.0f}с, ожидалось ~{interval}с",
        )


def process_checkin(agent: dict[str, Any], body: dict[str, Any], remote_ip: str) -> dict[str, Any]:
    _check_ip_pin(agent, remote_ip)
    _check_rate_anomaly(agent)
    db.touch_agent_checkin(agent["id"], remote_ip, body.get("agent_version"))

    discovered_jails = body.get("discovered_jails") or []
    if discovered_jails:
        db.merge_agent_discovered_jails(agent["id"], discovered_jails)

    for result in body.get("results", []) or []:
        _apply_result(agent, result)

    for jail, entries in (body.get("new_bans") or {}).items():
        for e in _normalize_ip_entries(entries):
            if e["ip"]:
                handle_new_ban(agent, jail, e["ip"], e["since"], source="checkin")

    for jail, entries in (body.get("new_unbans") or {}).items():
        for e in _normalize_ip_entries(entries):
            if e["ip"]:
                handle_new_unban(agent, jail, e["ip"], e["since"], source="checkin")

    _apply_log_tail(agent["id"], body.get("log_tail"))

    tasks = db.take_pending_tasks(agent["id"])
    return {
        "tasks": [
            {"task_id": f"t-{t['id']}", "type": t["type"], **t["payload"]}
            for t in tasks
        ]
    }


def _parse_task_id(raw: str) -> Optional[int]:
    try:
        return int(raw.split("-", 1)[1]) if raw.startswith("t-") else int(raw)
    except (ValueError, IndexError):
        return None


def _apply_result(agent: dict[str, Any], result: dict[str, Any]) -> None:
    task_id = _parse_task_id(str(result.get("task_id", "")))
    status = result.get("status")
    if task_id is None or status not in ("ok", "error"):
        return
    detail = result.get("detail")
    db_status = "done" if status == "ok" else "error"
    task = db.apply_task_result(agent["id"], task_id, db_status, detail)
    if task is None:
        return

    if status == "ok":
        data = result.get("data") or {}
        if task["type"] == "report_full_state":
            db.replace_full_ban_state(agent["id"], data.get("bans") or {})
            if "baseline_ignoreip" in data:
                db.set_agent_baseline_ignoreip(agent["id"], data["baseline_ignoreip"])
        elif task["type"] == "tor_sync":
            ban_ips = task["payload"].get("ban_ips", [])
            unban_ips = task["payload"].get("unban_ips", [])
            current = db.get_tor_applied(agent["id"])
            current |= set(ban_ips)
            current -= set(unban_ips)
            db.set_tor_applied(agent["id"], current)
            # Иначе agent-tor-block не появляется в «Баны по джейлам» до следующего
            # чекина — новый бан там иначе узнают только из диффа new_bans/new_unbans.
            db.bulk_upsert_ban_state(agent["id"], db.TOR_BLOCK_JAIL, ban_ips)
            db.bulk_remove_ban_state(agent["id"], db.TOR_BLOCK_JAIL, unban_ips)
        elif task["type"] in ("ban", "unban"):
            jail = task["payload"].get("jail")
            ip = task["payload"].get("ip")
            if jail and ip:
                if task["type"] == "ban":
                    db.upsert_ban_state(agent["id"], jail, ip, db.now())
                else:
                    db.remove_ban_state(agent["id"], jail, ip)

    db.log_action(
        f"agent:{agent['name']}", agent["id"], f"task_{status}",
        detail=f"{task['type']}" + (f": {detail}" if detail else ""),
    )


# === Протокол: быстрый канал уведомления ======================================================

def process_event(agent: dict[str, Any], body: dict[str, Any]) -> None:
    jail = body.get("jail")
    ip = body.get("ip")
    event = body.get("event")
    since = body.get("since") or db.now()
    if not jail or not ip or event not in ("ban", "unban"):
        raise ValueError("некорректное тело события: нужны jail, ip, event=ban|unban")
    if event == "ban":
        handle_new_ban(agent, jail, ip, since, source="event")
    else:
        handle_new_unban(agent, jail, ip, since, source="event")


# === Локальный кэш лога (альтернатива Graylog) ===============================================

def _log_cache_path(agent_id: int) -> str:
    cache_dir = os.path.join(db.DATA_DIR, "log_cache")
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, f"{agent_id}.log")


def _trim_log_cache_file(path: str, max_bytes: int) -> None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size <= max_bytes:
        return
    with open(path, "rb") as f:
        f.seek(size - max_bytes)
        data = f.read()
    with open(path, "wb") as f:
        f.write(data)


def _apply_log_tail(agent_id: int, log_tail: Optional[dict[str, Any]]) -> None:
    if not log_tail:
        return
    path = log_tail.get("path") or ""
    new_size = log_tail.get("new_size", 0)
    db.set_log_cache_state(agent_id, path, new_size)
    if db.get_setting("log_view_mode", "none") != "local":
        return
    content = log_tail.get("content") or ""
    if not content:
        return
    cache_file = _log_cache_path(agent_id)
    with open(cache_file, "a", encoding="utf-8") as f:
        f.write(content)
    max_bytes = int(db.get_setting("local_log_max_bytes", "2000000"))
    _trim_log_cache_file(cache_file, max_bytes)


def read_local_log(agent_id: int, max_lines: int = 300) -> str:
    """Новые строки сверху, как в референсе. max_lines=0 — весь кэш целиком."""
    cache_file = _log_cache_path(agent_id)
    if not os.path.exists(cache_file):
        return ""
    with open(cache_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    if max_lines and len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(reversed(lines))


# === Общая обработка банов/разбанов — из checkin-диффа и из события ==========================

def handle_new_ban(agent: dict[str, Any], jail: str, ip: str, since: str, source: str) -> None:
    is_new = db.record_event(agent["id"], jail, ip, "ban", source, since)
    if not is_new:
        return
    db.upsert_ban_state(agent["id"], jail, ip, since)
    db.log_action(f"agent:{agent['name']}", agent["id"], "jail_ban", ip=ip, jail=jail, detail=source)

    if jail in (db.PERMANENT_BAN_JAIL, db.TOR_BLOCK_JAIL):
        return
    if db.get_setting("global_block_enabled", "0") != "1":
        return
    if db.is_ip_globally_ignored(ip):
        return
    count = db.bump_ban_counter(agent["id"], ip)
    threshold = int(db.get_setting("global_block_threshold", "5"))
    if count >= threshold:
        apply_global_block_everywhere(ip, agent["id"], count)


def handle_new_unban(agent: dict[str, Any], jail: str, ip: str, since: str, source: str) -> None:
    is_new = db.record_event(agent["id"], jail, ip, "unban", source, since)
    if not is_new:
        return
    db.remove_ban_state(agent["id"], jail, ip)
    db.log_action(f"agent:{agent['name']}", agent["id"], "jail_unban", ip=ip, jail=jail, detail=source)

    # Разбан именно в джейле, куда был применён глобальный блок, — почти всегда ручное
    # решение администратора на самом сервере.
    applied_here = [
        r for r in db.list_global_applied(ip) if r["agent_id"] == agent["id"] and r["jail"] == jail
    ]
    if applied_here:
        revoke_global_block_everywhere(ip, actor="scheduler", except_agent_id=agent["id"])


# === Глобальный блок-лист =====================================================================

def apply_global_block_everywhere(ip: str, triggered_by_agent_id: Optional[int], ban_count: int, actor: str = "scheduler") -> None:
    db.upsert_global_block(ip, triggered_by_agent_id, ban_count)

    mode = db.get_setting("global_block_duration_mode", "permanent")
    already_applied = {r["agent_id"] for r in db.list_global_applied(ip)}
    for agent in db.list_agents():
        if agent["revoked_at"] or agent["id"] in already_applied:
            continue
        if mode == "longest_jail_bantime":
            jail, _bantime = db.longest_bantime_jail(agent["id"])
            if jail is None:
                jail = db.PERMANENT_BAN_JAIL
        else:
            jail = db.PERMANENT_BAN_JAIL
        db.queue_task(agent["id"], "ban", {"jail": jail, "ip": ip}, actor)
        db.mark_global_applied(ip, agent["id"], jail)
        db.log_action(actor, agent["id"], "global_block_ban", ip=ip, jail=jail)


def revoke_global_block_everywhere(ip: str, actor: str = "scheduler", except_agent_id: Optional[int] = None) -> None:
    for row in db.list_global_applied(ip):
        if row["agent_id"] == except_agent_id:
            continue
        db.queue_task(row["agent_id"], "unban", {"jail": row["jail"], "ip": ip}, actor)
        db.log_action(actor, row["agent_id"], "global_block_unban", ip=ip, jail=row["jail"])
        db.unmark_global_applied(ip, row["agent_id"])
    db.delete_global_block(ip)


MIN_IGNORE_PREFIXLEN = 8


def add_global_block_ignore(network: str, comment: str, actor: str) -> None:
    net = ipaddress.ip_network(network, strict=False)
    if net.prefixlen < MIN_IGNORE_PREFIXLEN:
        raise ValueError(f"Сеть шире /{MIN_IGNORE_PREFIXLEN} не принимается (опечатка в маске?): {network}")
    db.add_global_block_ignore(str(net), comment, actor)
    db.log_action(actor, None, "global_block_ignore_add", ip=str(net), detail=comment)


def remove_global_block_ignore(ignore_id: int, actor: str) -> None:
    db.remove_global_block_ignore(ignore_id)
    db.log_action(actor, None, "global_block_ignore_remove", detail=str(ignore_id))


def import_global_block_ignore_text(text: str, actor: str) -> tuple[int, list[str]]:
    """По одной сети/IP на строку, `#`-комментарии и пустые строки пропускаются."""
    existing = {row["network"] for row in db.list_global_block_ignore()}
    added = 0
    errors: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = str(ipaddress.ip_network(line, strict=False))
        except ValueError:
            errors.append(f"строка {lineno}: некорректный IP/сеть: {line!r}")
            continue
        if ipaddress.ip_network(net).prefixlen < MIN_IGNORE_PREFIXLEN:
            errors.append(f"строка {lineno}: сеть шире /{MIN_IGNORE_PREFIXLEN} отклонена: {line!r}")
            continue
        if net in existing:
            continue
        db.add_global_block_ignore(net, "", actor)
        existing.add(net)
        added += 1
    if added:
        db.log_action(actor, None, "global_block_ignore_import", detail=f"добавлено {added}")
    return added, errors


def export_global_block_ignore_text() -> str:
    lines = []
    for row in db.list_global_block_ignore():
        if row["comment"]:
            lines.append(f"# {row['comment']}")
        lines.append(row["network"])
    return "\n".join(lines) + ("\n" if lines else "")


def add_to_global_blocklist_manually(ip: str, actor: str) -> None:
    validate_ipv4(ip)
    existing = db.get_global_block(ip)
    count = max(existing["ban_count"] if existing else 0, 1)
    apply_global_block_everywhere(ip, triggered_by_agent_id=None, ban_count=count, actor=actor)


def delete_from_global_blocklist(ip: str, actor: str) -> None:
    db.delete_global_block(ip)
    db.log_action(actor, None, "global_block_delete", ip=ip)


def manual_unban_everywhere(ip: str, actor: str) -> None:
    for row in db.list_global_applied(ip):
        db.queue_task(row["agent_id"], "unban", {"jail": row["jail"], "ip": ip}, actor)
        db.log_action(actor, row["agent_id"], "global_block_unban", ip=ip, jail=row["jail"])
        db.unmark_global_applied(ip, row["agent_id"])
    db.deactivate_global_block(ip)


# === Ручные действия из UI ====================================================================

def manual_ban(agent_id: int, jail: str, ip: str, actor: str) -> None:
    agent = db.get_agent(agent_id)
    validate_jail_allowed(agent, jail)
    validate_ipv4(ip)
    db.queue_task(agent_id, "ban", {"jail": jail, "ip": ip}, actor)
    db.log_action(actor, agent_id, "manual_ban_queued", ip=ip, jail=jail)


def ban_forever(agent_id: int, ip: str, actor: str) -> None:
    manual_ban(agent_id, db.PERMANENT_BAN_JAIL, ip, actor)


def manual_unban(agent_id: int, jail: str, ip: str, actor: str) -> None:
    validate_ipv4(ip)
    db.queue_task(agent_id, "unban", {"jail": jail, "ip": ip}, actor)
    db.log_action(actor, agent_id, "manual_unban_queued", ip=ip, jail=jail)


def queue_temp_ignore_add(agent_id: int, jail: str, ip: str, seconds: int, actor: str, comment: str = "") -> None:
    agent = db.get_agent(agent_id)
    validate_jail_allowed(agent, jail)
    validate_ipv4(ip)
    db.add_temp_ignore(agent_id, jail, ip, seconds, actor, comment)
    db.queue_task(agent_id, "ignore_add", {"jail": jail, "ip": ip, "ttl": seconds}, actor)
    db.log_action(actor, agent_id, "temp_ignore_add", ip=ip, jail=jail, detail=comment)


def queue_temp_ignore_remove(agent_id: int, jail: str, ip: str, actor: str) -> None:
    db.remove_temp_ignore(agent_id, jail, ip)
    db.queue_task(agent_id, "ignore_del", {"jail": jail, "ip": ip}, actor)
    db.log_action(actor, agent_id, "temp_ignore_remove", ip=ip, jail=jail)


def sync_permanent_ignore(agent_id: int, actor: str) -> None:
    agent = db.get_agent(agent_id)
    baseline = agent.get("baseline_ignoreip") or []
    ours = [r["ip"] for r in db.list_permanent_ignore(agent_id)]
    merged = list(dict.fromkeys(list(baseline) + ours))
    db.queue_task(agent_id, "permanent_ignore_sync", {"ip_list": merged}, actor)


def add_permanent_ignore(agent_id: int, ip: str, actor: str, comment: str = "") -> None:
    validate_ipv4(ip)
    db.add_permanent_ignore(agent_id, ip, actor, comment)
    sync_permanent_ignore(agent_id, actor)
    db.log_action(actor, agent_id, "permanent_ignore_add", ip=ip, detail=comment)


def remove_permanent_ignore(agent_id: int, ip: str, actor: str) -> None:
    db.remove_permanent_ignore(agent_id, ip)
    sync_permanent_ignore(agent_id, actor)
    db.log_action(actor, agent_id, "permanent_ignore_remove", ip=ip)


def request_full_state(agent_id: int, actor: str = "system") -> None:
    db.queue_task(agent_id, "report_full_state", {}, actor)


def request_ping(agent_id: int, actor: str = "system") -> None:
    db.queue_task(agent_id, "ping", {}, actor)


# === Бан сети Tor ==============================================================================

def _parse_ipv4_lines(text: str) -> list[str]:
    ips = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.IPv4Address(line)
        except ValueError:
            continue
        ips.append(line)
    return ips


def refresh_tor_exit_nodes() -> int:
    """Источник — локальный файл (tor_block_source_path), если задан: не ходит в сеть
    вообще, ожидает, что список туда кладёт что-то внешнее (cron/rsync и т.п.). Иначе —
    HTTP(S) по tor_block_source_url, опционально через прокси (tor_block_proxy_url,
    например socks5h://host:port — see check.torproject.org недоступен напрямую)."""
    path = db.get_setting("tor_block_source_path") or ""
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        url = db.get_setting("tor_block_source_url") or ""
        if not url:
            return 0
        proxy_url = db.get_setting("tor_block_proxy_url") or ""
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        resp = requests.get(url, timeout=20, proxies=proxies)
        resp.raise_for_status()
        text = resp.text
    ips = _parse_ipv4_lines(text)
    db.replace_tor_exit_nodes(ips)
    return len(ips)


def sync_tor_block(agent_id: int, actor: str = "scheduler") -> None:
    nodes = db.list_tor_exit_nodes()
    applied = db.get_tor_applied(agent_id)
    to_ban = nodes - applied
    to_unban = applied - nodes
    if not to_ban and not to_unban:
        return
    db.queue_task(
        agent_id, "tor_sync", {"ban_ips": sorted(to_ban), "unban_ips": sorted(to_unban)}, actor
    )


def sync_tor_block_all_agents(actor: str = "scheduler") -> None:
    if db.get_setting("tor_block_enabled", "0") != "1":
        return
    for agent in db.list_agents():
        if agent["revoked_at"]:
            continue
        sync_tor_block(agent["id"], actor)


# === Периодические проверки для scheduler.py ==================================================

def scan_temp_ignore_expiry() -> int:
    rows = db.pop_expired_temp_ignore()
    for row in rows:
        db.queue_task(row["agent_id"], "ignore_del", {"jail": row["jail"], "ip": row["ip"]}, "scheduler")
        db.log_action("scheduler", row["agent_id"], "temp_ignore_expired", ip=row["ip"], jail=row["jail"])
    return len(rows)


def scan_stale_tasks() -> int:
    missed = int(db.get_setting("agent_task_stale_after_missed", "5"))
    interval = int(db.get_setting("checkin_interval_seconds", "60"))
    return db.mark_stale_tasks(missed * interval)
