"""Graylog только принимает логи; центр из него только читает лог fail2ban хостов."""
from conftest import login


def _graylog(monkeypatch, messages):
    import graylog_client
    calls = []

    def fake(query, range_seconds, limit=300, fields="", offset=0):
        calls.append({"query": query, "range": range_seconds, "fields": fields})
        return messages

    monkeypatch.setattr(graylog_client, "search_messages", fake)
    return calls


def test_log_query_is_limited_to_fail2ban_messages(center):
    db = center["db"]
    import graylog_client
    assert graylog_client.build_log_query("web1") == 'source:"web1" AND (application_name:fail2ban*)'
    db.set_setting("graylog_fail2ban_query", "facility:fail2ban")
    assert graylog_client.build_log_query("web1", "sshd") == 'source:"web1" AND (facility:fail2ban) AND "sshd"'


def test_log_tab_falls_back_to_host_log_when_graylog_has_none(center, monkeypatch):
    """Хост не шлёт лог в Graylog — вкладка «Лог» показывает лог, прочитанный с хоста."""
    db, app = center["db"], center["app"]
    from auth import hash_password
    db.create_user("adm", hash_password("secret1"), "admin")
    agent_id, token = db.register_agent("web1", [])
    db.set_setting("log_view_mode", "graylog")
    app.test_client().post("/api/v1/checkin", json={
        "agent_id": "web1", "results": [],
        "log_tail": {"path": "/var/log/fail2ban.log", "new_size": 60,
                     "content": "2026-11-12 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.70\n"},
    }, headers={"Authorization": f"Bearer {token}"})

    c = app.test_client()
    login(c, "adm", "secret1")
    page = c.get(f"/agents/{agent_id}")
    assert "Graylog не настроен".encode() in page.data and b"Ban 203.0.113.70" in page.data

    db.set_setting("graylog_url", "https://graylog.test")
    db.set_setting("graylog_api_token", "t")
    _graylog(monkeypatch, [])
    page = c.get(f"/agents/{agent_id}?tab=log")
    assert "В Graylog нет сообщений fail2ban".encode() in page.data and b"Ban 203.0.113.70" in page.data

    _graylog(monkeypatch, [{"timestamp": "2026-11-12T10:00:00Z", "source": "web1",
                            "message": "fail2ban.actions: из Graylog"}])
    page = c.get(f"/agents/{agent_id}?tab=log")
    assert "из Graylog".encode() in page.data and b"Ban 203.0.113.70" not in page.data


class _Resp:
    def __init__(self, status, text="", data=None):
        self.status_code, self.text, self._data = status, text, data

    def json(self):
        return self._data


def test_client_uses_export_api_and_falls_back_for_old_graylog(center, monkeypatch):
    db = center["db"]
    import graylog_client
    db.set_setting("graylog_url", "https://graylog.test")
    db.set_setting("graylog_api_token", "t")
    seen = []

    def new_graylog(method, url, **kw):
        seen.append((method, url.split("?")[0], kw.get("headers", {}).get("Accept")))
        return _Resp(200, '"timestamp","source","message"\n'
                          '"2026-11-12T10:00:00.000Z","web1","old"\n'
                          '"2026-11-12T11:00:00.000Z","web1","new, с запятой"\n')

    monkeypatch.setattr(graylog_client.requests, "request", new_graylog)
    rows = graylog_client.search_messages("x", 600)
    assert seen[0] == ("POST", "https://graylog.test/api/views/search/messages", "text/csv")
    assert [r["message"] for r in rows] == ["new, с запятой", "old"], "новые сверху, CSV разобран"

    def old_graylog(method, url, **kw):
        if "views" in url:
            return _Resp(404, "not found")
        return _Resp(200, data={"messages": [{"message": {"source": "web1", "message": "v4"}}]})

    monkeypatch.setattr(graylog_client.requests, "request", old_graylog)
    assert graylog_client.search_messages("x", 600)[0]["message"] == "v4"

    monkeypatch.setattr(graylog_client.requests, "request", lambda *a, **k: _Resp(403, "denied"))
    try:
        graylog_client.search_messages("x", 600)
        assert False, "403 должен стать понятной ошибкой"
    except graylog_client.GraylogError as e:
        assert "Share" in str(e)


def test_host_field_and_message_filter_for_logs_via_collector(center, monkeypatch):
    """Логи через сборщик: в source IP, имя хоста в hostname, программа только в тексте."""
    db = center["db"]
    import graylog_client
    db.set_setting("graylog_host_field", "hostname")
    db.set_setting("graylog_fail2ban_query", "message:fail2ban.* AND NOT message:fail2ban.service")
    assert graylog_client.build_log_query("mail1") == \
        'hostname:"mail1" AND (message:fail2ban.* AND NOT message:fail2ban.service)'

    db.set_setting("graylog_host_field", 'hostname:"x" OR source')  # не имя поля — игнорируется
    assert graylog_client.build_log_query("mail1").startswith('source:"mail1"')

    db.set_setting("graylog_host_field", "hostname")
    db.set_setting("graylog_url", "https://graylog.test")
    db.set_setting("graylog_api_token", "t")
    db.register_agent("mail1", [])
    monkeypatch.setattr(graylog_client, "_get", lambda *a, **k: {"version": "6.1"})
    calls = _graylog(monkeypatch, [{"hostname": "mail1", "source": "10.0.0.5"},
                                   {"hostname": "mail2", "source": "10.0.0.6"}])
    text = graylog_client.check_connection()
    assert calls[0]["fields"] == "timestamp,hostname"
    assert "хосты (поле hostname): mail1, mail2" in text
    assert "Не совпадают ни с одним агентом: mail2" in text
