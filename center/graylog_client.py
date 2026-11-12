"""Клиент Graylog REST API. Все запросы идут только с backend — токен никогда не попадает в браузер.

Центр в Graylog только читает: логи хостов туда собирает инфраструктура (rsyslog, journald,
агенты Graylog). Нужен токен пользователя с правом поиска (роль Reader + доступ к потокам)."""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Optional
from urllib.parse import urlencode

import requests

import db

# Как отличить в Graylog сообщения fail2ban от остальных логов хоста: вкладка «Лог»
# показывает только их.
DEFAULT_FAIL2BAN_QUERY = "application_name:fail2ban*"


class GraylogError(Exception):
    pass


def _validate_http_url(url: str) -> str:
    """Только http/https: иначе requests со схемами file://, ftp://, gopher:// и т.п. даёт
    SSRF/чтение файлов. Пустой URL — не настроено, это не ошибка здесь."""
    if url and not url.lower().startswith(("http://", "https://")):
        raise GraylogError(f"URL Graylog должен начинаться с http:// или https:// (получено: {url[:40]})")
    return url


def _config() -> tuple[str, str, str]:
    url = _validate_http_url((db.get_setting("graylog_url") or "").strip().rstrip("/"))
    token = db.get_setting("graylog_api_token") or ""
    stream_id = db.get_setting("graylog_stream_id") or ""
    return url, token, stream_id


def is_configured() -> bool:
    url, token, _ = _config()
    return bool(url and token)


class _NotFound(GraylogError):
    pass


def _request(method: str, path: str, params: Optional[dict[str, Any]] = None, json_body: Any = None,
             accept: str = "application/json", timeout: int = 15) -> requests.Response:
    url, token, _ = _config()
    if not url or not token:
        raise GraylogError("Graylog не настроен (пустой URL или токен в настройках центра).")
    full = f"{url}{path}" + (f"?{urlencode(params)}" if params else "")
    try:
        resp = requests.request(
            method,
            full,
            json=json_body,
            auth=(token, "token"),
            headers={"Accept": accept, "X-Requested-By": "fail2ban-center"},
            timeout=timeout,
            verify=db.get_setting("graylog_verify_tls", "1") == "1",
        )
    except requests.exceptions.SSLError as e:
        raise GraylogError(
            f"Сертификат Graylog не прошёл проверку: {e}. Если у Graylog самоподписанный "
            "сертификат — снимите «Проверять сертификат Graylog» в настройках."
        ) from e
    except requests.RequestException as e:
        raise GraylogError(f"Не удалось связаться с Graylog: {e}") from e

    if resp.status_code == 401:
        raise GraylogError("Graylog отклонил токен (401) — проверьте настройки.")
    if resp.status_code == 403:
        raise GraylogError(
            "У пользователя токена нет прав на поиск (403): дайте ему доступ на чтение к потоку с логами "
            "(Streams → Share, в том числе для «All messages»)."
        )
    if resp.status_code == 404:
        raise _NotFound(f"{path}: 404")
    if resp.status_code != 200:
        raise GraylogError(f"Graylog вернул {resp.status_code}: {resp.text[:300]}")
    return resp


def _get(path: str, params: Optional[dict[str, Any]] = None, timeout: int = 15) -> Any:
    resp = _request("GET", path, params=params, timeout=timeout)
    try:
        return resp.json()
    except ValueError as e:
        raise GraylogError(f"Graylog вернул не JSON (неверный URL?): {resp.text[:200]}") from e


def search_messages(query: str, range_seconds: int, limit: int = 300, fields: str = "timestamp,source,message",
                    offset: int = 0) -> list[dict[str, Any]]:
    """Сообщения за последние range_seconds, новые сверху — список словарей полей сообщения.

    Graylog 5+: API экспорта сообщений — ему достаточно права на чтение потока, роль Reader
    подходит. Старый universal/relative в Graylog 6 роли Reader недоступен (нужно право
    searches:relative), поэтому он — только запасной путь для Graylog 4.x, где нового API нет."""
    _, _, stream_id = _config()
    names = [f.strip() for f in fields.split(",") if f.strip()]
    if "timestamp" not in names:
        names.insert(0, "timestamp")
    body: dict[str, Any] = {
        # Пустая строка — все сообщения; "*" этот API отвергает (ведущий wildcard).
        "query_string": {"type": "elasticsearch", "query_string": query or ""},
        "timerange": {"type": "relative", "range": max(int(range_seconds), 1)},
        "fields_in_order": names,
        "limit": limit + offset,
    }
    if stream_id:
        body["streams"] = [stream_id]
    try:
        resp = _request("POST", "/api/views/search/messages", json_body=body, accept="text/csv", timeout=30)
    except _NotFound:
        return _search_universal(query, range_seconds, limit, ",".join(names), offset)
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return rows[offset:offset + limit]


def _search_universal(query: str, range_seconds: int, limit: int, fields: str, offset: int) -> list[dict[str, Any]]:
    _, _, stream_id = _config()
    params: dict[str, Any] = {
        "query": query or "*",
        "range": max(int(range_seconds), 1),
        "limit": limit,
        "offset": offset,
        "sort": "timestamp:desc",
        "fields": fields,
    }
    if stream_id:
        params["filter"] = f"streams:{stream_id}"
    data = _get("/api/search/universal/relative", params)
    return [m.get("message", {}) for m in data.get("messages", [])]


def check_connection() -> str:
    """Версия Graylog + поиск сообщений fail2ban за сутки: проверяет адрес, токен, право на
    поиск и то, что фильтр сообщений fail2ban вообще что-то находит."""
    info = _get("/api/system")
    field = host_field()
    rows = search_messages(fail2ban_query(), 24 * 3600, limit=5000, fields=f"timestamp,{field}")
    sources = sorted({r.get(field, "") for r in rows if r.get(field)})
    text = f"Graylog {info.get('version', '?')}: подключение и право на поиск в порядке. "
    if not rows:
        return text + ("Сообщений fail2ban за сутки не найдено — проверьте, что лог fail2ban хостов "
                       "попадает в Graylog и что фильтр сообщений fail2ban подходит.")
    known = {a["name"] for a in db.list_agents()} | {a["graylog_source"] for a in db.list_agents() if a.get("graylog_source")}
    without_agent = [s for s in sources if s not in known]
    text += (f"Сообщений fail2ban за сутки: {len(rows)}{'+' if len(rows) >= 5000 else ''}, "
             f"хосты (поле {field}): {', '.join(sources[:20]) or '—'}.")
    if without_agent:
        text += f" Не совпадают ни с одним агентом: {', '.join(without_agent[:20])}."
    return text


def host_field() -> str:
    """Поле сообщения с именем хоста. Обычно source, но если логи идут через сборщик, в
    source бывает IP отправителя, а имя хоста — в другом поле (например, hostname)."""
    field = (db.get_setting("graylog_host_field") or "source").strip()
    return field if re.fullmatch(r"[A-Za-z0-9_.@-]+", field) else "source"


def fail2ban_query(extra: str = "") -> str:
    """Запрос только по сообщениям fail2ban, с необязательным уточнением."""
    base = (db.get_setting("graylog_fail2ban_query") or DEFAULT_FAIL2BAN_QUERY).strip()
    return f"({base}) AND ({extra.strip()})" if extra.strip() else base


def build_log_query(source: str, jail: Optional[str] = None) -> str:
    q = f'{host_field()}:"{source.replace(chr(34), "")}" AND ({fail2ban_query()})'
    if jail:
        q += f' AND "{jail.replace(chr(34), "")}"'
    return q


def search(source: str, jail: Optional[str] = None, range_hours: int = 24,
           limit: int = 300, offset: int = 0) -> list[dict[str, Any]]:
    """Лог хоста для вкладки «Лог». Бросает GraylogError при недоступности/неверной настройке."""
    return search_messages(build_log_query(source, jail), range_hours * 3600, limit=limit, offset=offset)


def deep_link(source: str, jail: Optional[str] = None, range_hours: int = 24) -> Optional[str]:
    url, _token, _stream = _config()
    if not url:
        return None
    params = {"q": build_log_query(source, jail), "rangetype": "relative", "relative": range_hours * 3600}
    return f"{url}/search?{urlencode(params)}"
