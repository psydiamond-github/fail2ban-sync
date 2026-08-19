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

    assert db.get_global_block("7.7.7.7") is None, "§3.3: ручной разбан на сервере должен полностью забыть IP"

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
    в value= HTML-формы (нарушение §7/§10 ТЗ: 'секрет, не отдаётся в API/UI'). Пустое поле
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
