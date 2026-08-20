"""Слой доступа к БД центра. Прямой SQL поверх db/schema.sql, без ORM."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

DATA_DIR = os.environ.get("F2B_CENTER_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
DB_PATH = os.path.join(DATA_DIR, "f2b-center.sqlite3")

_MODULE_DIR = Path(__file__).parent
_SCHEMA_SQL = (_MODULE_DIR / "db" / "schema.sql").read_text()
_SEED_SQL = (_MODULE_DIR / "db" / "seed.sql").read_text()

# Служебные джейлы, управляемые центром автоматически (не выбор администратора).
PERMANENT_BAN_JAIL = "agent-permanent-ban"
TOR_BLOCK_JAIL = "agent-tor-block"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_conn() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with closing(get_conn()) as conn:
        conn.executescript(_SCHEMA_SQL)
        conn.executescript(_SEED_SQL)
        conn.commit()


def load_secret_key() -> bytes:
    """Секрет сессий Flask и пеппер для HMAC-хэширования токенов агентов."""
    path = os.path.join(DATA_DIR, "secret_key")
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(path, 0o600)
    with open(path, "rb") as f:
        return f.read()


def _hash_token(secret: bytes, token: str) -> str:
    return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _loads(text: Optional[str], default: Any = None) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


# === Пользователи ============================================================================

def create_user(username: str, password_hash: str, role: str = "operator") -> int:
    with closing(get_conn()) as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, now()),
        )
        conn.commit()
        return cur.lastrowid


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user(user_id: int) -> Optional[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_users() -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM users ORDER BY username").fetchall()


def count_admins() -> int:
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").fetchone()
        return row["n"]


def set_user_role(user_id: int, role: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()


def set_user_password(user_id: int, password_hash: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()


def delete_user(user_id: int) -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


# === Группы агентов ==========================================================================

def create_group(name: str, parent_id: Optional[int] = None) -> int:
    with closing(get_conn()) as conn:
        cur = conn.execute(
            "INSERT INTO agent_groups (name, parent_id, created_at) VALUES (?, ?, ?)",
            (name, parent_id, now()),
        )
        conn.commit()
        return cur.lastrowid


def list_groups() -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM agent_groups ORDER BY name").fetchall()


def rename_group(group_id: int, name: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute("UPDATE agent_groups SET name = ? WHERE id = ?", (name, group_id))
        conn.commit()


def move_group(group_id: int, parent_id: Optional[int]) -> None:
    with closing(get_conn()) as conn:
        conn.execute("UPDATE agent_groups SET parent_id = ? WHERE id = ?", (parent_id, group_id))
        conn.commit()


def delete_group(group_id: int) -> bool:
    with closing(get_conn()) as conn:
        has_sub = conn.execute(
            "SELECT 1 FROM agent_groups WHERE parent_id = ? LIMIT 1", (group_id,)
        ).fetchone()
        has_agents = conn.execute(
            "SELECT 1 FROM agents WHERE group_id = ? LIMIT 1", (group_id,)
        ).fetchone()
        if has_sub or has_agents:
            return False
        conn.execute("DELETE FROM agent_groups WHERE id = ?", (group_id,))
        conn.commit()
        return True


# === Агенты ===================================================================================

def register_agent(
    name: str,
    allowed_jails: list[dict[str, Any]],
    group_id: Optional[int] = None,
    ip_pin_mode: str = "advisory",
    pinned_ip: Optional[str] = None,
    graylog_source: Optional[str] = None,
) -> tuple[int, str]:
    """Возвращает (id, raw_token) — токен отдаётся только сейчас, в БД остаётся лишь хэш."""
    jails = list(allowed_jails)
    if not any(j.get("name") == PERMANENT_BAN_JAIL for j in jails):
        jails.append({"name": PERMANENT_BAN_JAIL, "bantime": -1})
    token = secrets.token_hex(32)
    token_hash = _hash_token(load_secret_key(), token)
    with closing(get_conn()) as conn:
        cur = conn.execute(
            """INSERT INTO agents
               (name, token_hash, allowed_jails, group_id, pinned_ip, ip_pin_mode,
                graylog_source, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, token_hash, _dumps(jails), group_id, pinned_ip, ip_pin_mode,
             graylog_source, now()),
        )
        conn.commit()
        return cur.lastrowid, token


def regenerate_token(agent_id: int) -> str:
    token = secrets.token_hex(32)
    token_hash = _hash_token(load_secret_key(), token)
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE agents SET token_hash = ?, revoked_at = NULL WHERE id = ?",
            (token_hash, agent_id),
        )
        conn.commit()
    return token


def revoke_agent(agent_id: int) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE agents SET token_hash = NULL, revoked_at = ? WHERE id = ?",
            (now(), agent_id),
        )
        conn.commit()


def delete_agent(agent_id: int) -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        conn.commit()


def _parse_agent(row: Optional[sqlite3.Row]) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    d = dict(row)
    d["allowed_jails"] = _loads(d.get("allowed_jails"), [])
    d["baseline_ignoreip"] = _loads(d.get("baseline_ignoreip"), [])
    return d


def get_agent(agent_id: int) -> Optional[dict[str, Any]]:
    with closing(get_conn()) as conn:
        return _parse_agent(conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone())


def get_agent_by_name(name: str) -> Optional[dict[str, Any]]:
    with closing(get_conn()) as conn:
        return _parse_agent(conn.execute("SELECT * FROM agents WHERE name = ?", (name,)).fetchone())


def verify_agent_token(token: str) -> Optional[dict[str, Any]]:
    token_hash = _hash_token(load_secret_key(), token)
    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE token_hash = ? AND revoked_at IS NULL", (token_hash,)
        ).fetchone()
        return _parse_agent(row)


def list_agents(group_id: Optional[int] = None) -> list[dict[str, Any]]:
    with closing(get_conn()) as conn:
        if group_id is None:
            rows = conn.execute("SELECT * FROM agents ORDER BY name").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM agents WHERE group_id = ? ORDER BY name", (group_id,)
            ).fetchall()
        return [_parse_agent(r) for r in rows]


def touch_agent_checkin(agent_id: int, remote_ip: str, agent_version: Optional[str]) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE agents SET last_ip = ?, last_seen = ?, last_agent_version = ? WHERE id = ?",
            (remote_ip, now(), agent_version, agent_id),
        )
        conn.commit()


def set_agent_baseline_ignoreip(agent_id: int, ip_list: list[str]) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE agents SET baseline_ignoreip = ? WHERE id = ?", (_dumps(ip_list), agent_id)
        )
        conn.commit()


def set_agent_allowed_jails(agent_id: int, jails: list[dict[str, Any]]) -> None:
    if not any(j.get("name") == PERMANENT_BAN_JAIL for j in jails):
        jails = list(jails) + [{"name": PERMANENT_BAN_JAIL, "bantime": -1}]
    with closing(get_conn()) as conn:
        conn.execute("UPDATE agents SET allowed_jails = ? WHERE id = ?", (_dumps(jails), agent_id))
        conn.commit()


def merge_agent_discovered_jails(agent_id: int, discovered: list[dict[str, Any]]) -> None:
    """Добавляет в allowed_jails агента джейлы, которые он сам обнаружил через
    fail2ban-client status на чекине и которых там ещё нет (по имени) — только добавляет,
    bantime уже известных джейлов не трогает (админ мог задать его вручную)."""
    agent = get_agent(agent_id)
    if agent is None:
        return
    existing_names = {j["name"] for j in agent["allowed_jails"]}
    new_jails = [
        {"name": j["name"], "bantime": j.get("bantime", 600)}
        for j in discovered
        if j.get("name") and j["name"] not in existing_names
    ]
    if not new_jails:
        return
    set_agent_allowed_jails(agent_id, list(agent["allowed_jails"]) + new_jails)


def reconcile_agent_jails(agent_id: int, discovered: list[dict[str, Any]]) -> None:
    """Как merge_agent_discovered_jails, но ещё и убирает из allowed_jails джейлы, которых
    в discovered больше нет (кроме синтетических agent-permanent-ban/agent-tor-block —
    ими управляет сам центр, их в discovered никогда не бывает по дизайну helper'а).
    Только по явному запросу (см. mark_jail_resync/pop_jail_resync) — обычный чекин
    делает исключительно merge, чтобы разовый сбой автообнаружения не сносил джейл molча."""
    agent = get_agent(agent_id)
    if agent is None:
        return
    discovered_names = {j["name"] for j in discovered if j.get("name")}
    kept = [
        j for j in agent["allowed_jails"]
        if j["name"] in discovered_names or j["name"] in (PERMANENT_BAN_JAIL, TOR_BLOCK_JAIL)
    ]
    kept_names = {j["name"] for j in kept}
    new_jails = [
        {"name": j["name"], "bantime": j.get("bantime", 600)}
        for j in discovered if j["name"] not in kept_names
    ]
    set_agent_allowed_jails(agent_id, kept + new_jails)


def mark_jail_resync(agent_id: int) -> None:
    set_setting(f"jail_resync_pending:{agent_id}", "1")


def pop_jail_resync_pending(agent_id: int) -> bool:
    """True и сбрасывает флаг, если для агента запрошена пересинхронизация джейлов."""
    pending = get_setting(f"jail_resync_pending:{agent_id}") == "1"
    if pending:
        set_setting(f"jail_resync_pending:{agent_id}", "0")
    return pending


def set_agent_group(agent_id: int, group_id: Optional[int]) -> None:
    with closing(get_conn()) as conn:
        conn.execute("UPDATE agents SET group_id = ? WHERE id = ?", (group_id, agent_id))
        conn.commit()


def set_agent_ip_pin(agent_id: int, pinned_ip: Optional[str], mode: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE agents SET pinned_ip = ?, ip_pin_mode = ? WHERE id = ?",
            (pinned_ip, mode, agent_id),
        )
        conn.commit()


def set_agent_graylog_source(agent_id: int, source: Optional[str]) -> None:
    with closing(get_conn()) as conn:
        conn.execute("UPDATE agents SET graylog_source = ? WHERE id = ?", (source, agent_id))
        conn.commit()


def longest_bantime_jail(agent_id: int) -> tuple[Optional[str], Optional[int]]:
    """Джейл с максимальным bantime среди разрешённых джейлов агента, кроме
    agent-permanent-ban. -1 считается длиннее любого положительного числа."""
    agent = get_agent(agent_id)
    if not agent:
        return None, None
    best_jail, best_bantime = None, None
    for j in agent["allowed_jails"]:
        if j.get("name") == PERMANENT_BAN_JAIL:
            continue
        bt = j.get("bantime")
        if bt is None:
            continue
        if best_bantime is None:
            best_jail, best_bantime = j["name"], bt
        elif best_bantime == -1:
            continue
        elif bt == -1 or bt > best_bantime:
            best_jail, best_bantime = j["name"], bt
    return best_jail, best_bantime


# === Очередь задач ============================================================================

def queue_task(agent_id: int, task_type: str, payload: dict[str, Any], created_by: str) -> int:
    with closing(get_conn()) as conn:
        cur = conn.execute(
            """INSERT INTO agent_tasks (agent_id, type, payload, status, created_by, created_at)
               VALUES (?, ?, ?, 'pending', ?, ?)""",
            (agent_id, task_type, _dumps(payload), created_by, now()),
        )
        conn.commit()
        return cur.lastrowid


def take_pending_tasks(agent_id: int) -> list[dict[str, Any]]:
    with closing(get_conn()) as conn:
        rows = conn.execute(
            "SELECT * FROM agent_tasks WHERE agent_id = ? AND status = 'pending' ORDER BY id",
            (agent_id,),
        ).fetchall()
        if rows:
            ids = [r["id"] for r in rows]
            conn.execute(
                f"UPDATE agent_tasks SET status = 'delivered', delivered_at = ? "
                f"WHERE id IN ({','.join('?' * len(ids))})",
                [now(), *ids],
            )
            conn.commit()
        return [{"id": r["id"], "type": r["type"], "payload": _loads(r["payload"], {})} for r in rows]


def apply_task_result(agent_id: int, task_id: int, status: str, detail: Optional[str]) -> Optional[dict[str, Any]]:
    """None, если задача не найдена, принадлежит другому агенту, либо результат уже применён."""
    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT * FROM agent_tasks WHERE id = ? AND agent_id = ?", (task_id, agent_id)
        ).fetchone()
        if row is None or row["status"] not in ("delivered", "pending"):
            return None
        conn.execute(
            "UPDATE agent_tasks SET status = ?, completed_at = ?, result_detail = ? WHERE id = ?",
            (status, now(), detail, task_id),
        )
        conn.commit()
        return {"id": row["id"], "type": row["type"], "payload": _loads(row["payload"], {})}


def mark_stale_tasks(older_than_seconds: int) -> int:
    threshold = (datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds)).isoformat(
        timespec="seconds"
    )
    with closing(get_conn()) as conn:
        cur = conn.execute(
            """UPDATE agent_tasks SET status = 'error', result_detail = 'нет ответа от агента (timeout)'
               WHERE status = 'delivered' AND delivered_at < ?""",
            (threshold,),
        )
        conn.commit()
        return cur.rowcount


def list_tasks_for_agent(agent_id: int, limit: int = 50) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute(
            "SELECT * FROM agent_tasks WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()


# === Журнал событий ============================================================================

def record_event(agent_id: int, jail: str, ip: str, kind: str, source: str, since: str) -> bool:
    """True — событие новое, False — дубликат по (agent_id, jail, ip, kind, since)."""
    with closing(get_conn()) as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO agent_events
               (agent_id, jail, ip, kind, source, since, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (agent_id, jail, ip, kind, source, since, now()),
        )
        conn.commit()
        return cur.rowcount > 0


# === Текущее состояние банов ==================================================================

def replace_full_ban_state(agent_id: int, state: dict[str, list[dict[str, Any]]]) -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM agent_ban_state WHERE agent_id = ?", (agent_id,))
        ts = now()
        for jail, entries in state.items():
            for e in entries:
                conn.execute(
                    """INSERT INTO agent_ban_state (agent_id, jail, ip, since, updated_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (agent_id, jail, e.get("ip"), e.get("since"), ts),
                )
        conn.commit()


def upsert_ban_state(agent_id: int, jail: str, ip: str, since: Optional[str]) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT INTO agent_ban_state (agent_id, jail, ip, since, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(agent_id, jail, ip) DO UPDATE SET since = excluded.since,
                   updated_at = excluded.updated_at""",
            (agent_id, jail, ip, since, now()),
        )
        conn.commit()


def bulk_upsert_ban_state(agent_id: int, jail: str, ips: list[str]) -> None:
    """Как upsert_ban_state, но одним соединением/коммитом на весь список — для больших
    партий (например, разовое применение tor-block) один commit-с-fsync на N строк
    ощутимо быстрее N отдельных."""
    if not ips:
        return
    ts = now()
    with closing(get_conn()) as conn:
        conn.executemany(
            """INSERT INTO agent_ban_state (agent_id, jail, ip, since, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(agent_id, jail, ip) DO UPDATE SET since = excluded.since,
                   updated_at = excluded.updated_at""",
            [(agent_id, jail, ip, ts, ts) for ip in ips],
        )
        conn.commit()


def bulk_remove_ban_state(agent_id: int, jail: str, ips: list[str]) -> None:
    if not ips:
        return
    with closing(get_conn()) as conn:
        conn.executemany(
            "DELETE FROM agent_ban_state WHERE agent_id = ? AND jail = ? AND ip = ?",
            [(agent_id, jail, ip) for ip in ips],
        )
        conn.commit()


def remove_ban_state(agent_id: int, jail: str, ip: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "DELETE FROM agent_ban_state WHERE agent_id = ? AND jail = ? AND ip = ?",
            (agent_id, jail, ip),
        )
        conn.commit()


def list_ban_state(agent_id: int, jail: Optional[str] = None) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        if jail is None:
            return conn.execute(
                "SELECT * FROM agent_ban_state WHERE agent_id = ? ORDER BY jail, ip", (agent_id,)
            ).fetchall()
        return conn.execute(
            "SELECT * FROM agent_ban_state WHERE agent_id = ? AND jail = ? ORDER BY ip",
            (agent_id, jail),
        ).fetchall()


def ban_state_has(agent_id: int, jail: str, ip: str) -> bool:
    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT 1 FROM agent_ban_state WHERE agent_id = ? AND jail = ? AND ip = ?",
            (agent_id, jail, ip),
        ).fetchone()
        return row is not None


# === Игнор-листы ===============================================================================

def add_permanent_ignore(agent_id: int, ip: str, created_by: str, comment: str = "") -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT OR IGNORE INTO permanent_ignore (agent_id, ip, created_by, created_at, comment)
               VALUES (?, ?, ?, ?, ?)""",
            (agent_id, ip, created_by, now(), comment),
        )
        conn.commit()


def remove_permanent_ignore(agent_id: int, ip: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "DELETE FROM permanent_ignore WHERE agent_id = ? AND ip = ?", (agent_id, ip)
        )
        conn.commit()


def list_permanent_ignore(agent_id: int) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute(
            "SELECT * FROM permanent_ignore WHERE agent_id = ? ORDER BY ip", (agent_id,)
        ).fetchall()


def add_temp_ignore(agent_id: int, jail: str, ip: str, seconds: int, created_by: str, comment: str = "") -> None:
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="seconds")
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT INTO temp_ignore (agent_id, jail, ip, created_by, created_at, expires_at, comment)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id, jail, ip) DO UPDATE SET expires_at = excluded.expires_at,
                   created_by = excluded.created_by, comment = excluded.comment""",
            (agent_id, jail, ip, created_by, now(), expires_at, comment),
        )
        conn.commit()


def remove_temp_ignore(agent_id: int, jail: str, ip: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "DELETE FROM temp_ignore WHERE agent_id = ? AND jail = ? AND ip = ?", (agent_id, jail, ip)
        )
        conn.commit()


def list_temp_ignore(agent_id: Optional[int] = None) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        if agent_id is None:
            return conn.execute("SELECT * FROM temp_ignore ORDER BY expires_at").fetchall()
        return conn.execute(
            "SELECT * FROM temp_ignore WHERE agent_id = ? ORDER BY expires_at", (agent_id,)
        ).fetchall()


def pop_expired_temp_ignore() -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM temp_ignore WHERE expires_at <= ?", (now(),)).fetchall()
        if rows:
            ids = [r["id"] for r in rows]
            conn.execute(f"DELETE FROM temp_ignore WHERE id IN ({','.join('?' * len(ids))})", ids)
            conn.commit()
        return rows


# === Аудит-лог ==================================================================================

def log_action(actor: str, agent_id: Optional[int], action: str, ip: Optional[str] = None,
                jail: Optional[str] = None, detail: Optional[str] = None) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT INTO audit_log (ts, actor, agent_id, action, ip, jail, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (now(), actor, agent_id, action, ip, jail, detail),
        )
        conn.commit()


def list_audit(agent_id: Optional[int] = None, limit: int = 200) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        if agent_id is None:
            return conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return conn.execute(
            "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()


# === Настройки ===================================================================================

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()


def all_settings() -> dict[str, str]:
    with closing(get_conn()) as conn:
        return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}


# === Глобальный блок-лист ========================================================================

def bump_ban_counter(agent_id: int, ip: str) -> int:
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT INTO ip_ban_counters (agent_id, ip, ban_count, updated_at) VALUES (?, ?, 1, ?)
               ON CONFLICT(agent_id, ip) DO UPDATE SET ban_count = ban_count + 1, updated_at = excluded.updated_at""",
            (agent_id, ip, now()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT ban_count FROM ip_ban_counters WHERE agent_id = ? AND ip = ?", (agent_id, ip)
        ).fetchone()
        return row["ban_count"]


def get_global_block(ip: str) -> Optional[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM global_blocklist WHERE ip = ?", (ip,)).fetchone()


def upsert_global_block(ip: str, triggered_by_agent_id: Optional[int], ban_count: int) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT INTO global_blocklist (ip, triggered_by_agent_id, ban_count, active, added_at, updated_at)
               VALUES (?, ?, ?, 1, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET active = 1, ban_count = excluded.ban_count,
                   updated_at = excluded.updated_at""",
            (ip, triggered_by_agent_id, ban_count, now(), now()),
        )
        conn.commit()


def deactivate_global_block(ip: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_blocklist SET active = 0, updated_at = ? WHERE ip = ?", (now(), ip)
        )
        conn.commit()


def delete_global_block(ip: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM global_blocklist WHERE ip = ?", (ip,))
        conn.execute("DELETE FROM global_block_applied WHERE ip = ?", (ip,))
        conn.commit()


def list_global_blocklist(active_only: bool = False) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        if active_only:
            return conn.execute(
                "SELECT * FROM global_blocklist WHERE active = 1 ORDER BY updated_at DESC"
            ).fetchall()
        return conn.execute("SELECT * FROM global_blocklist ORDER BY updated_at DESC").fetchall()


def mark_global_applied(ip: str, agent_id: int, jail: str) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT INTO global_block_applied (ip, agent_id, jail, applied_at) VALUES (?, ?, ?, ?)
               ON CONFLICT(ip, agent_id) DO UPDATE SET jail = excluded.jail, applied_at = excluded.applied_at""",
            (ip, agent_id, jail, now()),
        )
        conn.commit()


def unmark_global_applied(ip: str, agent_id: int) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            "DELETE FROM global_block_applied WHERE ip = ? AND agent_id = ?", (ip, agent_id)
        )
        conn.commit()


def list_global_applied(ip: str) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM global_block_applied WHERE ip = ?", (ip,)).fetchall()


def list_global_applied_for_agent(agent_id: int) -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute(
            "SELECT * FROM global_block_applied WHERE agent_id = ?", (agent_id,)
        ).fetchall()


def add_global_block_ignore(network: str, comment: str, added_by: str) -> None:
    net = str(ipaddress.ip_network(network, strict=False))
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT OR IGNORE INTO global_block_ignore (network, comment, added_by, added_at)
               VALUES (?, ?, ?, ?)""",
            (net, comment, added_by, now()),
        )
        conn.commit()


def remove_global_block_ignore(ignore_id: int) -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM global_block_ignore WHERE id = ?", (ignore_id,))
        conn.commit()


def clear_global_block_ignore() -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM global_block_ignore")
        conn.commit()


def list_global_block_ignore() -> list[sqlite3.Row]:
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM global_block_ignore ORDER BY network").fetchall()


def is_ip_globally_ignored(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    for row in list_global_block_ignore():
        if addr in ipaddress.ip_network(row["network"], strict=False):
            return True
    return False


# === Локальный кэш лога ==========================================================================

def get_log_cache_state(agent_id: int) -> tuple[Optional[str], int]:
    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT path, offset_pos FROM agent_log_cache WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return (row["path"], row["offset_pos"]) if row else (None, 0)


def set_log_cache_state(agent_id: int, path: str, offset: int) -> None:
    with closing(get_conn()) as conn:
        conn.execute(
            """INSERT INTO agent_log_cache (agent_id, path, offset_pos, updated_at) VALUES (?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET path = excluded.path, offset_pos = excluded.offset_pos,
                   updated_at = excluded.updated_at""",
            (agent_id, path, offset, now()),
        )
        conn.commit()


# === Бан сети Tor ================================================================================

def replace_tor_exit_nodes(ip_list: list[str]) -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM tor_exit_nodes")
        ts = now()
        conn.executemany(
            "INSERT INTO tor_exit_nodes (ip, updated_at) VALUES (?, ?)",
            [(ip, ts) for ip in ip_list],
        )
        conn.commit()


def list_tor_exit_nodes() -> set[str]:
    with closing(get_conn()) as conn:
        return {r["ip"] for r in conn.execute("SELECT ip FROM tor_exit_nodes")}


def get_tor_applied(agent_id: int) -> set[str]:
    with closing(get_conn()) as conn:
        return {
            r["ip"]
            for r in conn.execute("SELECT ip FROM tor_block_applied WHERE agent_id = ?", (agent_id,))
        }


def set_tor_applied(agent_id: int, ip_set: set[str]) -> None:
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM tor_block_applied WHERE agent_id = ?", (agent_id,))
        ts = now()
        conn.executemany(
            "INSERT INTO tor_block_applied (agent_id, ip, applied_at) VALUES (?, ?, ?)",
            [(agent_id, ip, ts) for ip in ip_set],
        )
        conn.commit()
