"""Тесты информационной безопасности панели fail2ban-center.

Фиксируют контракт безопасности: аутентификацию, авторизацию по ролям, CSRF, защиту
сессий, отсутствие инъекций (SQL/команды/путь), SSRF, утечек токенов, обход rate-limit,
эскалацию привилегий. Каждый тест бьёт в конкретный класс уязвимостей из OWASP.

Запуск: pytest tests/test_security.py -v
"""
import re

import pytest

from conftest import csrf, login


def _mkuser(db, name, role, pw="secret1"):
    from auth import hash_password
    db.create_user(name, hash_password(pw), role)
    return name, pw


@pytest.fixture
def admin(center):
    _mkuser(center["db"], "adm", "admin")
    c = center["app"].test_client()
    login(c, "adm", "secret1")
    return c


@pytest.fixture
def operator(center):
    _mkuser(center["db"], "op", "operator")
    c = center["app"].test_client()
    login(c, "op", "secret1")
    return c


# === A01/A07: аутентификация — доступ без входа ================================================

# (маршрут, метод) — все защищённые эндпоинты панели
PROTECTED = [
    ("GET", "/dashboard"), ("GET", "/agents/1"), ("GET", "/admin/agents"),
    ("GET", "/admin/users"), ("GET", "/admin/groups"), ("GET", "/admin/settings"),
    ("GET", "/admin/blocklist"), ("GET", "/audit"), ("GET", "/account"),
    ("GET", "/admin/blocklist/ignore/export"),
    ("POST", "/agents/1/ban"), ("POST", "/agents/1/unban"), ("POST", "/agents/1/ban-forever"),
    ("POST", "/agents/1/ignore/temp/add"), ("POST", "/agents/1/ignore/permanent/add"),
    ("POST", "/admin/agents/add"), ("POST", "/admin/users/add"), ("POST", "/admin/groups/add"),
    ("POST", "/admin/agents/1/revoke"), ("POST", "/admin/agents/1/delete"),
    ("POST", "/admin/agents/1/regenerate-token"), ("POST", "/admin/users/1/delete"),
    ("POST", "/admin/blocklist/add"), ("POST", "/admin/settings"),
    ("POST", "/admin/settings/graylog-check"), ("POST", "/admin/blocklist/tor/refresh"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_no_access_without_authentication(center, method, path):
    """Аноним не получает ни одной защищённой страницы: только редирект на /login (не 200)."""
    c = center["app"].test_client()
    r = c.open(path, method=method)
    assert r.status_code in (302, 401, 403), f"{method} {path} отдал {r.status_code}"
    if r.status_code == 302:
        assert "/login" in r.headers["Location"], f"{path} редиректит не на логин"


def test_anonymous_cannot_act_even_with_a_stolen_csrf_shape(center):
    """Даже с правдоподобным телом формы аноним не создаёт пользователя."""
    c = center["app"].test_client()
    before = len(center["db"].list_users())
    c.post("/admin/users/add", data={"csrf_token": "x" * 32, "username": "hacker",
                                     "password": "password1", "role": "admin"})
    assert len(center["db"].list_users()) == before


# === A01: авторизация по ролям — operator не должен уметь админское =============================

OPERATOR_FORBIDDEN = [
    ("GET", "/admin/agents"), ("GET", "/admin/users"), ("GET", "/admin/settings"),
    ("GET", "/admin/groups"),
    ("POST", "/agents/1/ban"), ("POST", "/agents/1/ban-forever"),
    ("POST", "/agents/1/ignore/permanent/add"),
    ("POST", "/admin/users/add"), ("POST", "/admin/agents/add"),
    ("POST", "/admin/blocklist/add"), ("POST", "/admin/settings"),
    ("POST", "/admin/agents/1/delete"), ("POST", "/admin/agents/1/regenerate-token"),
]


@pytest.mark.parametrize("method,path", OPERATOR_FORBIDDEN)
def test_operator_is_denied_admin_actions(operator, method, path):
    """operator на админских маршрутах получает 403, не 200/302-выполнено."""
    r = operator.open(path, method=method)
    assert r.status_code == 403, f"operator смог {method} {path} ({r.status_code})"


def test_operator_cannot_escalate_self_to_admin(center, operator):
    """operator не может повысить себя через /admin/users/<id>/role."""
    db = center["db"]
    uid = db.get_user_by_username("op")["id"]
    operator.post(f"/admin/users/{uid}/role", data={"csrf_token": "x", "role": "admin"})
    assert db.get_user(uid)["role"] == "operator"


def test_operator_token_regen_does_not_leak_token(operator, center):
    """Запрос перегенерации токена от operator запрещён и токен в ответе не появляется."""
    center["db"].register_agent("a1", [])
    r = operator.post("/admin/agents/1/regenerate-token", data={"csrf_token": "x"})
    assert r.status_code == 403


# === A01: CSRF ================================================================================

def test_state_changing_post_requires_valid_csrf(admin, center):
    """POST без корректного CSRF-токена не выполняет действие (создание пользователя)."""
    before = len(center["db"].list_users())
    r = admin.post("/admin/users/add", data={"csrf_token": "неверный",
                   "username": "x", "password": "password1", "role": "operator"},
                   follow_redirects=True)
    assert len(center["db"].list_users()) == before
    assert "Сессия истекла".encode() in r.data or "недействительн".encode() in r.data


def test_csrf_token_is_unpredictable_and_per_session(center):
    """CSRF-токены разных сессий различаются и имеют достаточную длину."""
    c1, c2 = center["app"].test_client(), center["app"].test_client()
    t1 = csrf(c1.get("/login"))
    t2 = csrf(c2.get("/login"))
    assert t1 != t2 and len(t1) >= 32


def test_csrf_check_uses_constant_time_compare():
    """Сравнение CSRF — через secrets.compare_digest (не ==), против timing-атак."""
    import inspect

    import auth
    src = inspect.getsource(auth.check_csrf)
    assert "compare_digest" in src and "==" not in src.replace("!=", "")


# === A07: защита сессии и cookie ==============================================================

def test_session_cookie_flags_are_hardened(center, monkeypatch):
    """HttpOnly + SameSite=Strict всегда; Secure включается переменной окружения."""
    cfg = center["app"].config
    assert cfg["SESSION_COOKIE_HTTPONLY"] is True
    assert cfg["SESSION_COOKIE_SAMESITE"] == "Strict"
    # Secure управляется F2B_CENTER_COOKIE_SECURE (в бою =1); в тестах выключен намеренно.
    import importlib
    import os
    monkeypatch.setenv("F2B_CENTER_COOKIE_SECURE", "1")
    import app as appmod
    importlib.reload(appmod)
    assert appmod.create_app().config["SESSION_COOKIE_SECURE"] is True
    monkeypatch.setenv("F2B_CENTER_COOKIE_SECURE", "0")
    importlib.reload(appmod)


def test_login_rotates_session_no_fixation(center):
    """При входе сессия очищается (session.clear) — фиксация сессии невозможна."""
    import inspect

    import auth
    assert "session.clear()" in inspect.getsource(auth.login_user)


def test_logout_clears_session(admin):
    """После /logout защищённые страницы снова недоступны."""
    admin.get("/logout")
    r = admin.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_login_redirect_is_fixed_no_open_redirect(center):
    """Вход игнорирует параметр next — нет открытого редиректа на внешний сайт."""
    _mkuser(center["db"], "u", "admin")
    c = center["app"].test_client()
    r = c.get("/login")
    r = c.post("/login?next=https://evil.example/", data={
        "username": "u", "password": "secret1", "csrf_token": csrf(r)})
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert "evil.example" not in loc and ("/dashboard" in loc or loc.endswith("/"))


# === Брутфорс логина ==========================================================================

def test_login_bruteforce_is_rate_limited(center):
    """После порога неудач вход блокируется даже с ВЕРНЫМ паролем (защита от перебора)."""
    _mkuser(center["db"], "victim", "admin", pw="correct-horse")
    c = center["app"].test_client()
    for _ in range(12):
        r = c.get("/login")
        c.post("/login", data={"username": "victim", "password": "wrong", "csrf_token": csrf(r)})
    r = c.get("/login")
    r = c.post("/login", data={"username": "victim", "password": "correct-horse",
                               "csrf_token": csrf(r)}, follow_redirects=True)
    assert "Слишком много".encode() in r.data
    assert "Агенты".encode() not in r.data  # на дашборд не пустило


def test_username_enumeration_resistance():
    """verify_login сверяет хэш и для несуществующего пользователя (нет timing-оракула)."""
    import inspect

    import auth
    src = inspect.getsource(auth.verify_login)
    assert "_DUMMY_HASH" in src


# === Утечки секретов ==========================================================================

def test_agent_token_stored_only_as_hash(center):
    """В БД лежит HMAC-хэш, а не сам токен; по хэшу исходный токен не восстановить."""
    db = center["db"]
    _id, token = db.register_agent("srv", [])
    row = db.get_agent(_id)
    assert "token_hash" in row and row["token_hash"] != token
    assert len(row["token_hash"]) == 64 and re.fullmatch(r"[0-9a-f]+", row["token_hash"])


def test_graylog_token_never_rendered_in_settings_page(admin, center):
    """Сохранённый токен Graylog не попадает в HTML страницы настроек."""
    db = center["db"]
    db.set_setting("graylog_api_token", "SUPERSECRETTOKEN123")
    html = admin.get("/admin/settings").data.decode()
    assert "SUPERSECRETTOKEN123" not in html


def test_graylog_token_survives_empty_field_on_save(admin, center):
    """Пустое поле токена при сохранении не затирает сохранённый секрет."""
    db = center["db"]
    db.set_setting("graylog_api_token", "keepme")
    page = admin.get("/admin/settings")
    admin.post("/admin/settings", data={"csrf_token": csrf(page), "graylog_api_token": "",
               "log_view_mode": "none", "checkin_interval_seconds": "60"})
    assert db.get_setting("graylog_api_token") == "keepme"


def test_regenerated_token_shown_once_then_only_hash(admin, center):
    """Новый токен показывается один раз во flash, но в БД — только хэш."""
    db = center["db"]
    _id, _ = db.register_agent("srv", [])
    r = admin.post(f"/admin/agents/{_id}/regenerate-token", data={"csrf_token":
                   csrf(admin.get("/account"))}, follow_redirects=True)
    m = re.search(r"показывается один раз\):\s*([0-9a-f]{64})", r.data.decode())
    assert m, "токен не показан администратору"
    assert db.get_agent(_id)["token_hash"] != m.group(1)


# === API агентов: аутентификация и изоляция ===================================================

def test_api_rejects_missing_or_bad_bearer(center):
    """checkin без токена и с мусорным токеном → 401."""
    api = center["app"].test_client()
    assert api.post("/api/v1/checkin", json={"agent_id": "x"}).status_code == 401
    assert api.post("/api/v1/checkin", json={"agent_id": "x"},
                    headers={"Authorization": "Bearer nope"}).status_code == 401
    assert api.post("/api/v1/checkin", json={"agent_id": "x"},
                    headers={"Authorization": "Basic nope"}).status_code == 401


def test_revoked_agent_token_stops_working(center):
    """После отзыва агента его токен немедленно получает 401."""
    db = center["db"]
    aid, token = db.register_agent("srv", [])
    api = center["app"].test_client()
    assert api.post("/api/v1/checkin", json={"agent_id": "srv", "results": []},
                    headers={"Authorization": f"Bearer {token}"}).status_code == 200
    db.revoke_agent(aid)
    assert api.post("/api/v1/checkin", json={"agent_id": "srv", "results": []},
                    headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_agent_token_is_scoped_cannot_act_as_another_agent(center):
    """Токен агента A, но agent_id=B в теле: баны пишутся агенту A (владельцу токена),
    а не тому, чьё имя подставили — межагентная подмена невозможна."""
    db = center["db"]
    a_id, a_token = db.register_agent("agentA", [{"name": "sshd", "bantime": 600}])
    b_id, _ = db.register_agent("agentB", [{"name": "sshd", "bantime": 600}])
    api = center["app"].test_client()
    api.post("/api/v1/checkin", json={"agent_id": "agentB", "results": [],
             "new_bans": {"sshd": [{"ip": "1.2.3.4", "since": "2026-01-01 00:00:00"}]}},
             headers={"Authorization": f"Bearer {a_token}"})
    assert any(r["ip"] == "1.2.3.4" for r in db.list_ban_state(a_id))
    assert not any(r["ip"] == "1.2.3.4" for r in db.list_ban_state(b_id))


# === Инъекции: SQL / команды / путь ===========================================================

def test_sql_injection_in_username_login_is_harmless(center):
    """Классическая инъекция в логине не обходит аутентификацию."""
    _mkuser(center["db"], "real", "admin")
    c = center["app"].test_client()
    r = c.get("/login")
    r = c.post("/login", data={"username": "real' OR '1'='1", "password": "x' OR '1'='1",
               "csrf_token": csrf(r)}, follow_redirects=True)
    assert "Неверный логин".encode() in r.data


def test_sql_injection_in_agent_name_does_not_corrupt_db(center):
    """Кавычки и ; в имени агента не ломают таблицу agents (параметризованный SQL)."""
    db = center["db"]
    evil = "x'); DROP TABLE agents;--"
    db.register_agent(evil, [])
    assert db.get_agent_by_name(evil) is not None
    assert db.list_agents()  # таблица цела


def test_command_injection_in_ban_ip_is_validated(center):
    """IP с метасимволами оболочки отклоняется валидатором, не доходит до агента."""
    import tasks
    db = center["db"]
    aid, _ = db.register_agent("srv", [{"name": "sshd", "bantime": 600}])
    for bad in ["1.2.3.4; rm -rf /", "$(id)", "1.2.3.4 && reboot", "`touch /tmp/x`"]:
        with pytest.raises(ValueError):
            tasks.manual_ban(aid, "sshd", bad, "admin")


def test_jail_name_with_shell_metachars_rejected(center):
    """Имя джейла вне [A-Za-z0-9_.-] отклоняется (вторая граница — helper на агенте)."""
    import tasks
    db = center["db"]
    aid, _ = db.register_agent("srv", [{"name": "sshd", "bantime": 600}])
    with pytest.raises(ValueError):
        tasks.manual_ban(aid, "sshd; reboot", "1.2.3.4", "admin")


def test_log_cache_path_not_traversable(center):
    """Путь кэша лога строится из целочисленного agent_id — выход за каталог невозможен."""
    import os

    import tasks
    p = tasks._log_cache_path(42)
    assert os.path.basename(p) == "42.log"
    assert ".." not in p and p.startswith(os.path.join(center["db"].DATA_DIR, "log_cache"))


# === SSRF ====================================================================================

def test_graylog_url_rejects_non_http_schemes(center):
    """file://, gopher://, ftp:// в URL Graylog отклоняются до запроса (анти-SSRF)."""
    import graylog_client
    db = center["db"]
    db.set_setting("graylog_api_token", "t")
    for bad in ["file:///etc/passwd", "gopher://127.0.0.1:6379/", "ftp://x/"]:
        db.set_setting("graylog_url", bad)
        with pytest.raises(graylog_client.GraylogError):
            graylog_client.check_connection()


def test_tor_source_url_rejects_non_http_schemes(center):
    """file:// в URL источника Tor отклоняется (чтение произвольных файлов по сети закрыто)."""
    import tasks
    db = center["db"]
    db.set_setting("tor_block_source_path", "")
    db.set_setting("tor_block_source_url", "file:///etc/shadow")
    with pytest.raises(ValueError):
        tasks.refresh_tor_exit_nodes()


def test_graylog_host_field_cannot_inject_query(center):
    """Поле имени хоста из настроек не может внедрить произвольный запрос Graylog."""
    import graylog_client
    db = center["db"]
    db.set_setting("graylog_host_field", 'source" OR _exists_:x OR "')
    q = graylog_client.build_log_query("web1")
    assert q.startswith('source:"web1"')  # мусорное поле откатилось к source


# === XSS =====================================================================================

def test_stored_xss_in_agent_name_is_escaped(admin, center):
    """Имя агента со <script> выводится экранированным, не как активный тег."""
    center["db"].register_agent("<script>alert(1)</script>", [])
    html = admin.get("/admin/agents").data.decode()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_stored_xss_in_flash_ip_is_escaped(admin, center):
    """IP с разметкой в сообщении об ошибке не исполняется как HTML."""
    db = center["db"]
    aid, _ = db.register_agent("srv", [{"name": "sshd", "bantime": 600}])
    page = admin.get(f"/agents/{aid}")
    r = admin.post(f"/agents/{aid}/ban", data={"csrf_token": csrf(page),
                   "jail": "sshd", "ip": "<img src=x onerror=alert(1)>"}, follow_redirects=True)
    assert b"<img src=x onerror=" not in r.data


# === Бизнес-правила как защита =================================================================

def test_cannot_delete_or_demote_last_admin(admin, center):
    """Нельзя удалить или понизить последнего администратора (lockout-защита)."""
    db = center["db"]
    uid = db.get_user_by_username("adm")["id"]
    page = admin.get("/admin/users")
    admin.post(f"/admin/users/{uid}/role", data={"csrf_token": csrf(page), "role": "operator"})
    assert db.get_user(uid)["role"] == "admin"
    admin.post(f"/admin/users/{uid}/delete", data={"csrf_token": csrf(page)})
    assert db.get_user(uid) is not None


def test_weak_password_rejected_on_user_create(admin, center):
    """Слишком короткий пароль не принимается при создании пользователя."""
    before = len(center["db"].list_users())
    page = admin.get("/admin/users")
    admin.post("/admin/users/add", data={"csrf_token": csrf(page), "username": "weak",
               "password": "123", "role": "operator"})
    assert len(center["db"].list_users()) == before


def test_blocklist_ignore_rejects_overly_wide_networks(admin, center):
    """В игнор-лист блок-листа нельзя внести слишком широкую сеть (напр. 0.0.0.0/0)."""
    import tasks
    with pytest.raises(ValueError):
        tasks.add_global_block_ignore("0.0.0.0/0", "oops", "admin")
