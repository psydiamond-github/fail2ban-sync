"""End-to-end проверка протокола центр<->агент и веб-интерфейса — через flask.testing
(не настоящий HTTP, но полный стек Flask/DB) для web-части, и напрямую через
db.py/tasks.py для бизнес-логики, которую в проде вызывает f2b-agent-checkin.py."""
import pytest

from conftest import csrf, login


def _register(db, name="srv-test", jails=None):
    jails = jails or [{"name": "sshd", "bantime": 600}]
    return db.register_agent(name, jails)


def test_web_login_and_dashboard(center):
    db, app = center["db"], center["app"]
    db.create_user("admin", __import__("auth").hash_password("secret123"), role="admin")
    _register(db)

    client = app.test_client()
    r = login(client, "admin", "secret123")
    assert b"srv-test" in r.data


def test_rbac_operator_cannot_ban_or_admin(center):
    db, app = center["db"], center["app"]
    auth = __import__("auth")
    db.create_user("admin", auth.hash_password("secret123"), role="admin")
    db.create_user("op1", auth.hash_password("secret123"), role="operator")
    agent_id, _token = _register(db)

    client = app.test_client()
    login(client, "op1", "secret123")

    assert client.get("/admin/users").status_code == 403

    r = client.get(f"/agents/{agent_id}")
    r = client.post(
        f"/agents/{agent_id}/ban",
        data={"jail": "sshd", "ip": "1.1.1.1", "csrf_token": csrf(r)},
    )
    assert r.status_code == 403


def test_manual_ban_flows_through_checkin_to_ban_state(center):
    db, tasks, app = center["db"], center["tasks"], center["app"]
    auth = __import__("auth")
    db.create_user("admin", auth.hash_password("secret123"), role="admin")
    agent_id, token = _register(db)

    web = app.test_client()
    login(web, "admin", "secret123")
    r = web.get(f"/agents/{agent_id}")
    r = web.post(
        f"/agents/{agent_id}/ban",
        data={"jail": "sshd", "ip": "5.6.7.8", "csrf_token": csrf(r)},
        follow_redirects=True,
    )
    assert r.status_code == 200

    api = app.test_client()
    r = api.post(
        "/api/v1/checkin",
        json={"agent_id": "srv-test", "results": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert len(body["tasks"]) == 1
    task = body["tasks"][0]
    assert task["type"] == "ban" and task["ip"] == "5.6.7.8"

    r = api.post(
        "/api/v1/checkin",
        json={
            "agent_id": "srv-test",
            "results": [{"task_id": task["task_id"], "status": "ok"}],
            "new_bans": {"sshd": [{"ip": "5.6.7.8", "since": "2026-08-19T10:00:00Z"}]},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200

    state = db.list_ban_state(agent_id, "sshd")
    assert any(row["ip"] == "5.6.7.8" for row in state)

    task_row = db.list_tasks_for_agent(agent_id)[0]
    assert task_row["status"] == "done"


def test_wrong_token_rejected(center):
    app = center["app"]
    _register(center["db"])
    api = app.test_client()
    r = api.post(
        "/api/v1/checkin",
        json={"agent_id": "srv-test", "results": []},
        headers={"Authorization": "Bearer wrong-token-0000"},
    )
    assert r.status_code == 401


def test_fast_event_channel(center):
    db, app = center["db"], center["app"]
    _agent_id, token = _register(db)
    api = app.test_client()
    r = api.post(
        "/api/v1/event",
        json={"jail": "sshd", "ip": "9.9.9.9", "event": "ban", "since": "2026-08-19T10:05:00Z"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 204


def test_global_blocklist_threshold_triggers_ban_on_other_agents(center):
    db, app = center["db"], center["app"]
    db.set_setting("global_block_enabled", "1")
    db.set_setting("global_block_threshold", "3")
    _agent1_id, token1 = _register(db, "srv-1")
    agent2_id, _token2 = _register(db, "srv-2")

    api = app.test_client()
    for i in range(3):
        r = api.post(
            "/api/v1/checkin",
            json={
                "agent_id": "srv-1",
                "results": [],
                "new_bans": {"sshd": [{"ip": "6.6.6.6", "since": f"2026-08-19T11:0{i}:00Z"}]},
            },
            headers={"Authorization": f"Bearer {token1}"},
        )
        assert r.status_code == 200

    gb = db.get_global_block("6.6.6.6")
    assert gb is not None and gb["active"] == 1 and gb["ban_count"] == 3

    applied = {row["agent_id"] for row in db.list_global_applied("6.6.6.6")}
    assert agent2_id in applied, "глобальный бан должен быть поставлен и на ДРУГОМ агенте"


def test_manual_unban_on_server_revokes_global_block_everywhere(center):
    db, app = center["db"], center["app"]
    db.set_setting("global_block_enabled", "1")
    db.set_setting("global_block_threshold", "2")
    _agent1_id, token1 = _register(db, "srv-1")
    agent2_id, token2 = _register(db, "srv-2")

    api1, api2 = app.test_client(), app.test_client()
    for i in range(2):
        api1.post(
            "/api/v1/checkin",
            json={
                "agent_id": "srv-1", "results": [],
                "new_bans": {"sshd": [{"ip": "7.7.7.7", "since": f"2026-08-19T12:0{i}:00Z"}]},
            },
            headers={"Authorization": f"Bearer {token1}"},
        )
    assert db.get_global_block("7.7.7.7") is not None

    r = api2.post(
        "/api/v1/checkin",
        json={"agent_id": "srv-2", "results": []},
        headers={"Authorization": f"Bearer {token2}"},
    )
    ban_task = next(t for t in r.get_json()["tasks"] if t["ip"] == "7.7.7.7")

    # srv-2 подтверждает бан, затем администратор разбанивает ПРЯМО НА ХОСТЕ (не через
    # центр) — агент репортит это как new_unban на том же джейле, куда сам блок-лист банил.
    api2.post(
        "/api/v1/checkin",
        json={
            "agent_id": "srv-2",
            "results": [{"task_id": ban_task["task_id"], "status": "ok"}],
            "new_bans": {ban_task["jail"]: [{"ip": "7.7.7.7", "since": "2026-08-19T12:10:00Z"}]},
        },
        headers={"Authorization": f"Bearer {token2}"},
    )
    api2.post(
        "/api/v1/checkin",
        json={
            "agent_id": "srv-2", "results": [],
            "new_unbans": {ban_task["jail"]: [{"ip": "7.7.7.7", "since": "2026-08-19T12:20:00Z"}]},
        },
        headers={"Authorization": f"Bearer {token2}"},
    )

    assert db.get_global_block("7.7.7.7") is None, "ручной разбан на сервере должен полностью забыть IP"

    r1 = api1.post(
        "/api/v1/checkin",
        json={"agent_id": "srv-1", "results": []},
        headers={"Authorization": f"Bearer {token1}"},
    )
    tasks_for_srv1 = r1.get_json()["tasks"]
    assert any(t["type"] == "unban" and t["ip"] == "7.7.7.7" for t in tasks_for_srv1), \
        "разбан должен долететь и до исходного (triggering) агента тоже"


def test_agent_rejects_task_for_disallowed_jail_locally(center):
    """Дублирует проверку agent/f2b-agent-checkin.py::execute_task — здесь на уровне
    того, что если бы центр (по ошибке/багу) создал задачу вне allowed_jails, у неё всё
    равно нет способа обойти локальную проверку агента (это тестируется в самом агенте,
    не здесь — см. агентские тесты); здесь же фиксируем, что центр в принципе НЕ создаёт
    такую задачу через штатный путь manual_ban."""
    db, tasks = center["db"], center["tasks"]
    agent_id, _token = _register(db)
    with pytest.raises(ValueError):
        tasks.manual_ban(agent_id, "not-allowed-jail", "1.2.3.4", "admin")


def test_global_block_ignore_import_export_roundtrip(center):
    db, tasks = center["db"], center["tasks"]
    text = "# офис\n203.0.113.0/24\n\nnot-an-ip\n198.51.100.5\n203.0.113.0/24\n0.0.0.0/0\n"
    added, errors = tasks.import_global_block_ignore_text(text, "admin")
    assert added == 2  # дубликат и /0 и невалидная строка не считаются
    assert len(errors) == 2
    exported = tasks.export_global_block_ignore_text()
    assert "203.0.113.0/24" in exported and "198.51.100.5" in exported


def test_global_block_ignore_rejects_wide_networks(center):
    db, tasks = center["db"], center["tasks"]
    with pytest.raises(ValueError):
        tasks.add_global_block_ignore("0.0.0.0/0", "опечатка", "admin")
    tasks.add_global_block_ignore("203.0.113.0/24", "офис", "admin")
    assert any(r["network"] == "203.0.113.0/24" for r in db.list_global_block_ignore())


def test_login_rate_limited_after_repeated_failures(center):
    """Ручная пентест-проверка на реальном развёртывании показала: до этого исправления
    /login не имел вообще никакой защиты от перебора пароля на уровне самого приложения
    (только опциональная рекомендация nginx limit_req в примере конфига)."""
    db, app = center["db"], center["app"]
    auth = __import__("auth")
    db.create_user("admin", auth.hash_password("secret123"), role="admin")

    client = app.test_client()
    for _ in range(auth._LOGIN_LOCKOUT_THRESHOLD):
        r = client.get("/login")
        client.post(
            "/login",
            data={"username": "admin", "password": "wrong", "csrf_token": csrf(r)},
        )

    r = client.get("/login")
    r = client.post(
        "/login",
        data={"username": "admin", "password": "secret123", "csrf_token": csrf(r)},
        follow_redirects=True,
    )
    body = r.data.decode()
    assert "Слишком много неудачных попыток" in body, "верный пароль должен быть заблокирован после превышения порога"


def test_graylog_log_tab_range_hours_default_is_numeric(center, monkeypatch):
    """Найдено вручную на реальном развёртывании: request.args.get(key, default, type=int)
    приводит к int ТОЛЬКО значение из query string — при отсутствии параметра default
    (строка из settings, где всё хранится как TEXT) возвращался как есть, и
    "24" * 3600 давало мусорную строку вместо 24*3600=86400 в deep_link на Graylog."""
    db, app = center["db"], center["app"]
    auth = __import__("auth")
    db.create_user("admin", auth.hash_password("secret123"), role="admin")
    _register(db)
    db.set_setting("log_view_mode", "graylog")
    db.set_setting("graylog_url", "http://127.0.0.1:1")  # заведомо недоступен, важен только deep_link
    db.set_setting("graylog_api_token", "x")

    client = app.test_client()
    login(client, "admin", "secret123")
    r = client.get("/agents/1?tab=log")
    assert b"relative=86400" in r.data
    assert b"relative=24242424" not in r.data


def test_vpn_ip_allocation_skips_used_and_center(center):
    db = center["db"]
    import vpn
    db.set_setting("vpn_subnet", "10.99.0.0/24")
    db.set_setting("vpn_center_ip", "10.99.0.1")
    agent1_id, _ = _register(db, "a1")
    agent2_id, _ = _register(db, "a2")
    with __import__("contextlib").closing(db.get_conn()) as conn:
        conn.execute(
            "INSERT INTO agent_vpn_peers (agent_id, wg_pubkey, assigned_ip, added_at) VALUES (?, 'x', '10.99.0.2', ?)",
            (agent1_id, db.now()),
        )
        conn.commit()
    assert vpn.allocate_ip() == "10.99.0.3"


def test_local_log_cache_incremental(center):
    db, tasks = center["db"], center["tasks"]
    agent_id, _token = _register(db)
    db.set_setting("log_view_mode", "local")

    tasks._apply_log_tail(agent_id, {"path": "/var/log/fail2ban.log", "new_size": 20, "content": "line one\n"})
    tasks._apply_log_tail(agent_id, {"path": "/var/log/fail2ban.log", "new_size": 40, "content": "line two\n"})

    text = tasks.read_local_log(agent_id)
    assert "line one" in text and "line two" in text
    assert text.splitlines()[0] == "line two"  # новые сверху

    path, offset = db.get_log_cache_state(agent_id)
    assert offset == 40


def test_graylog_token_not_leaked_and_survives_empty_field(center):
    """Найдено вручную на реальном развёртывании: форма настроек эхировала секрет обратно
    в value= HTML-формы (секрет не должен отдаваться в UI). Пустое поле
    при сохранении не должно стирать уже сохранённый токен — иначе им невозможно
    воспользоваться без повторного ввода."""
    db, app = center["db"], center["app"]
    auth = __import__("auth")
    db.create_user("admin", auth.hash_password("secret123"), role="admin")
    db.set_setting("graylog_api_token", "SUPER-SECRET-VALUE")

    client = app.test_client()
    login(client, "admin", "secret123")
    r = client.get("/admin/settings")
    assert b"SUPER-SECRET-VALUE" not in r.data

    client.post(
        "/admin/settings",
        data={
            "csrf_token": csrf(r),
            "checkin_interval_seconds": "60",
            "session_idle_timeout_minutes": "30",
            "global_block_threshold": "5",
            "global_block_duration_mode": "permanent",
            "global_block_bulk_max_workers": "8",
            "graylog_default_range_hours": "24",
            "graylog_default_log_lines": "300",
            "graylog_api_token": "",
        },
    )
    assert db.get_setting("graylog_api_token") == "SUPER-SECRET-VALUE"


def test_settings_checkbox_can_be_turned_off(center):
    db, app = center["db"], center["app"]
    auth = __import__("auth")
    db.create_user("admin", auth.hash_password("secret123"), role="admin")
    db.set_setting("global_block_enabled", "1")

    client = app.test_client()
    login(client, "admin", "secret123")
    r = client.get("/admin/settings")
    # чекбокс НЕ отмечен в форме -> браузер не пришлёт ключ вовсе; настройка должна стать "0"
    r = client.post(
        "/admin/settings",
        data={
            "csrf_token": csrf(r),
            "checkin_interval_seconds": "60",
            "session_idle_timeout_minutes": "30",
            "global_block_threshold": "5",
            "global_block_duration_mode": "permanent",
            "global_block_bulk_max_workers": "8",
            "graylog_default_range_hours": "24",
            "graylog_default_log_lines": "300",
        },
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert db.get_setting("global_block_enabled") == "0"


def _set_event_only(db, agent_id):
    with db.closing(db.get_conn()) as conn:
        conn.execute("UPDATE agents SET event_only = 1 WHERE id = ?", (agent_id,))
        conn.commit()


def test_event_only_agent_shown_active_and_gets_no_tasks(center):
    db, tasks = center["db"], center["tasks"]
    ids_id, _ = db.register_agent("ids", [{"name": "ids-suricata", "bantime": 86400}])
    other_id, _ = db.register_agent("other", [{"name": "agent-permanent-ban", "bantime": -1}])
    _set_event_only(db, ids_id)

    tasks.process_event(db.get_agent(ids_id), {"jail": "ids-suricata", "ip": "203.0.113.5", "event": "ban"}, "192.0.2.34")
    agent = db.get_agent(ids_id)
    assert agent["last_seen"] and agent["last_ip"] == "192.0.2.34"
    assert db.get_agent(other_id)["last_seen"] is None

    tasks.apply_global_block_everywhere("203.0.113.5", ids_id, 5)
    tasks.revoke_global_block_everywhere("203.0.113.6")
    assert db.queue_task(ids_id, "ping", {}, "test") == 0
    assert db.take_pending_tasks(ids_id) == []
    assert len(db.take_pending_tasks(other_id)) == 1
    assert ids_id not in {r["agent_id"] for r in db.list_global_applied("203.0.113.5")}


def test_set_event_only_closes_pending_tasks(center):
    db = center["db"]
    aid, _ = db.register_agent("a", [{"name": "dovecot", "bantime": 3600}])
    db.queue_task(aid, "ping", {}, "test")
    db.set_agent_event_only(aid, True)
    assert db.take_pending_tasks(aid) == []
    assert db.get_agent(aid)["event_only"] == 1
    db.set_agent_event_only(aid, False)
    assert db.queue_task(aid, "ping", {}, "test") > 0


def test_regular_agent_event_does_not_touch_last_seen(center):
    db, tasks = center["db"], center["tasks"]
    aid, _ = db.register_agent("a", [{"name": "dovecot", "bantime": 3600}])
    tasks.process_event(db.get_agent(aid), {"jail": "dovecot", "ip": "203.0.113.7", "event": "ban"}, "10.0.0.1")
    assert db.get_agent(aid)["last_seen"] is None


def test_init_db_adds_event_only_to_existing_database(center):
    db = center["db"]
    with db.closing(db.get_conn()) as conn:
        conn.execute("ALTER TABLE agents DROP COLUMN event_only")
        conn.commit()
    db.init_db()
    with db.closing(db.get_conn()) as conn:
        assert "event_only" in {r["name"] for r in conn.execute("PRAGMA table_info(agents)")}


def test_ca_cert_endpoint_and_fingerprint(center, tmp_path, monkeypatch):
    import subprocess

    import center_ca

    client = center["app"].test_client()
    monkeypatch.setenv("F2B_CENTER_CA_CERT", str(tmp_path / "нет.crt"))
    assert client.get("/api/v1/ca.crt").status_code == 404
    assert center_ca.ca_fingerprint() is None

    ca = tmp_path / "ca.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "ca.key"),
         "-out", str(ca), "-days", "1", "-subj", "/CN=test-ca"],
        check=True, capture_output=True,
    )
    monkeypatch.setenv("F2B_CENTER_CA_CERT", str(ca))
    r = client.get("/api/v1/ca.crt")
    assert r.status_code == 200
    assert r.data.decode() == ca.read_text()

    expected = subprocess.run(
        ["openssl", "x509", "-in", str(ca), "-noout", "-fingerprint", "-sha256"],
        check=True, capture_output=True, text=True,
    ).stdout.strip().split("=", 1)[1]
    assert center_ca.ca_fingerprint() == expected


def _global_block_on_two_agents(db, tasks, ips):
    """Общий блок-лист, применённый на srv-1 и srv-2 (как после эскалации по порогу)."""
    a1, t1 = _register(db, "srv-1")
    a2, t2 = _register(db, "srv-2")
    for ip in ips:
        tasks.add_to_global_blocklist_manually(ip, "admin")
    return (a1, t1), (a2, t2)


def _pending(db, agent_id, ttype):
    import json
    return [
        {**dict(t), "payload": json.loads(t["payload"]) if isinstance(t["payload"], str) else t["payload"]}
        for t in db.list_tasks_for_agent(agent_id, limit=500)
        if t["type"] == ttype and t["status"] == "pending"
    ]


def test_mass_unban_on_fail2ban_restart_keeps_global_blocklist(center):
    db, tasks, app = center["db"], center["tasks"], center["app"]
    ips = [f"5.5.5.{i}" for i in range(1, 16)]
    (a1, _t1), (a2, t2) = _global_block_on_two_agents(db, tasks, ips)
    unban_before = len(_pending(db, a1, "unban"))

    # fail2ban на srv-2 перезапустился — агент разом сообщил о «разбане» всех 15 общих IP.
    r = app.test_client().post(
        "/api/v1/checkin",
        json={"agent_id": "srv-2", "results": [],
              "new_unbans": {db.PERMANENT_BAN_JAIL: [{"ip": ip, "since": "2026-11-09T10:00:00Z"} for ip in ips]}},
        headers={"Authorization": f"Bearer {t2}"},
    )
    assert r.status_code == 200
    assert all(db.get_global_block(ip) is not None for ip in ips), "массовый разбан не должен снимать общий блок-лист"
    assert len(_pending(db, a1, "unban")) == unban_before, "другим серверам разбан не рассылается"
    assert any(t["type"] == "report_full_state" for t in r.get_json()["tasks"]), "центр перечитывает состояние агента"
    assert any(e["action"] == "global_block_mass_unban_ignored" for e in db.list_audit(agent_id=a2))


def test_event_unban_does_not_revoke_but_next_checkin_does(center):
    db, tasks, app = center["db"], center["tasks"], center["app"]
    (a1, _t1), (a2, t2) = _global_block_on_two_agents(db, tasks, ["8.8.4.4"])
    api = app.test_client()
    auth = {"Authorization": f"Bearer {t2}"}

    api.post("/api/v1/event", json={"jail": db.PERMANENT_BAN_JAIL, "ip": "8.8.4.4", "event": "unban"}, headers=auth)
    assert db.get_global_block("8.8.4.4") is not None, "одиночное уведомление само общий бан не снимает"

    api.post("/api/v1/checkin", json={
        "agent_id": "srv-2", "results": [],
        "new_unbans": {db.PERMANENT_BAN_JAIL: [{"ip": "8.8.4.4", "since": "2026-11-12T10:00:00Z"}]},
    }, headers=auth)
    assert db.get_global_block("8.8.4.4") is None, "ручной разбан на сервере снимает общий бан везде"
    assert any(t["payload"]["ip"] == "8.8.4.4" for t in _pending(db, a1, "unban"))


def test_panel_unban_of_global_ip_revokes_everywhere_immediately(center):
    db, tasks = center["db"], center["tasks"]
    (a1, _t1), (a2, _t2) = _global_block_on_two_agents(db, tasks, ["4.4.4.4"])
    tasks.manual_unban(a2, db.PERMANENT_BAN_JAIL, "4.4.4.4", "admin")
    assert db.get_global_block("4.4.4.4") is None
    assert any(t["payload"]["ip"] == "4.4.4.4" for t in _pending(db, a1, "unban"))
    assert any(t["payload"]["ip"] == "4.4.4.4" for t in _pending(db, a2, "unban"))


def test_reban_with_same_since_restores_ban_state(center):
    db, app = center["db"], center["app"]
    agent_id, token = _register(db, "srv-1")
    api = app.test_client()
    auth = {"Authorization": f"Bearer {token}"}
    entry = {"sshd": [{"ip": "3.3.3.3", "since": "2026-11-01 10:00:00"}]}

    api.post("/api/v1/checkin", json={"agent_id": "srv-1", "results": [], "new_bans": entry}, headers=auth)
    api.post("/api/v1/checkin", json={"agent_id": "srv-1", "results": [],
                                      "new_unbans": {"sshd": [{"ip": "3.3.3.3", "since": "2026-11-09T10:00:00Z"}]}},
             headers=auth)
    assert not [r for r in db.list_ban_state(agent_id) if r["ip"] == "3.3.3.3"]

    # fail2ban восстановил бан после перезапуска — с тем же since, что и в первый раз.
    api.post("/api/v1/checkin", json={"agent_id": "srv-1", "results": [], "new_bans": entry}, headers=auth)
    assert [r for r in db.list_ban_state(agent_id) if r["ip"] == "3.3.3.3"], "повторный бан должен вернуться в учёт"


def test_agent_diff_ignores_jail_that_could_not_be_read():
    import importlib.util
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "..", "agent", "f2b-agent-checkin.py")
    spec = importlib.util.spec_from_file_location("f2b_agent_checkin", path)
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)

    last = {"agent-permanent-ban": [{"ip": "1.1.1.1", "since": "x"}], "sshd": [{"ip": "2.2.2.2", "since": "y"}]}
    current = {"sshd": []}  # agent-permanent-ban не прочитался: fail2ban перезапускается
    new_bans, new_unbans = agent.diff_bans(last, current)
    assert "agent-permanent-ban" not in new_unbans
    assert [e["ip"] for e in new_unbans["sshd"]] == ["2.2.2.2"]
