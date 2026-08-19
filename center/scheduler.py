"""Фоновый планировщик — раз в 30с проверяет TTL временного игнора, зависшие задачи,
ежедневный пересбор списка Tor exit-нод. Агентов не опрашивает — инициатива у них."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

import db
import tasks

logger = logging.getLogger("f2b_center.scheduler")

_TICK_SECONDS = 30
_TOR_REFRESH_INTERVAL_SECONDS = 24 * 3600
_started = False
_lock = threading.Lock()


def _tor_refresh_due() -> bool:
    last = db.get_setting("tor_block_last_refresh_at")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - last_dt).total_seconds() >= _TOR_REFRESH_INTERVAL_SECONDS


def _tick() -> None:
    try:
        n = tasks.scan_temp_ignore_expiry()
        if n:
            logger.info("temp_ignore: %d записей истекло, поставлены ignore_del", n)
    except Exception:
        logger.exception("scan_temp_ignore_expiry упал")

    try:
        n = tasks.scan_stale_tasks()
        if n:
            logger.warning("%d задач помечены потерянными (нет ответа от агента)", n)
    except Exception:
        logger.exception("scan_stale_tasks упал")

    try:
        if db.get_setting("tor_block_enabled", "0") == "1" and _tor_refresh_due():
            count = tasks.refresh_tor_exit_nodes()
            db.set_setting("tor_block_last_refresh_at", db.now())
            logger.info("Tor exit-nodes обновлены: %d адресов", count)
            tasks.sync_tor_block_all_agents()
    except Exception:
        logger.exception("обновление/синхронизация Tor-бана упала")


def _run_loop() -> None:
    while True:
        _tick()
        time.sleep(_TICK_SECONDS)


def start() -> None:
    """Один раз на процесс — --workers 1 обязателен, иначе потоки задублируются."""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_run_loop, name="f2b-center-scheduler", daemon=True).start()
