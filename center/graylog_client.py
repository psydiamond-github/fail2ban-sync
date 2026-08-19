"""Клиент Graylog REST API. Все запросы идут только с backend — токен никогда не попадает в браузер."""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlencode

import requests

import db


class GraylogError(Exception):
    pass


def _config() -> tuple[str, str, str]:
    url = (db.get_setting("graylog_url") or "").rstrip("/")
    token = db.get_setting("graylog_api_token") or ""
    stream_id = db.get_setting("graylog_stream_id") or ""
    return url, token, stream_id


def is_configured() -> bool:
    url, token, _ = _config()
    return bool(url and token)


def build_query(source: str, jail: Optional[str] = None) -> str:
    q = f'source:"{source}" AND (program:"fail2ban" OR facility:"fail2ban")'
    if jail:
        q += f' AND message:"{jail}"'
    return q


def search(source: str, jail: Optional[str] = None, range_hours: int = 24,
           limit: int = 300, offset: int = 0) -> list[dict[str, Any]]:
    """Список сообщений, новые сверху. Бросает GraylogError при недоступности/неверной настройке."""
    url, token, stream_id = _config()
    if not url or not token:
        raise GraylogError("Graylog не настроен (пустой URL или токен в настройках центра).")

    query = build_query(source, jail)
    params = {
        "query": query,
        "range": range_hours * 3600,
        "limit": limit,
        "offset": offset,
        "sort": "timestamp:desc",
        "fields": "timestamp,source,message",
    }
    if stream_id:
        params["filter"] = f"streams:{stream_id}"

    try:
        resp = requests.get(
            f"{url}/api/search/universal/relative?{urlencode(params)}",
            auth=(token, "token"),
            headers={"Accept": "application/json", "X-Requested-By": "fail2ban-center"},
            timeout=10,
        )
    except requests.RequestException as e:
        raise GraylogError(f"Не удалось связаться с Graylog: {e}") from e

    if resp.status_code == 401:
        raise GraylogError("Graylog отклонил токен (401) — проверьте настройки.")
    if resp.status_code != 200:
        raise GraylogError(f"Graylog вернул {resp.status_code}: {resp.text[:300]}")

    data = resp.json()
    return data.get("messages", [])


def deep_link(source: str, jail: Optional[str] = None, range_hours: int = 24) -> Optional[str]:
    url, _token, _stream = _config()
    if not url:
        return None
    query = build_query(source, jail)
    params = {"q": query, "rangetype": "relative", "relative": range_hours * 3600}
    return f"{url}/search?{urlencode(params)}"
