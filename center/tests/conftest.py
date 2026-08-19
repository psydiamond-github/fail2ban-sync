import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

_MODULES = ["db", "auth", "graylog_client", "vpn", "tasks", "scheduler", "api", "app"]


@pytest.fixture
def center(tmp_path, monkeypatch):
    """Свежий центр на изолированной БД для каждого теста. db.py (и остальные модули)
    хранят DATA_DIR/DB_PATH как константы уровня модуля, вычисленные при импорте — без
    полной переимпортации второй тест делил бы одну БД с первым (тот же нюанс, что и в
    референсном проекте, см. его tests/README)."""
    monkeypatch.setenv("F2B_CENTER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("F2B_CENTER_COOKIE_SECURE", "0")
    for name in _MODULES:
        sys.modules.pop(name, None)

    import app as appmodule
    import db
    import tasks

    appmodule.app.testing = True
    return {"db": db, "tasks": tasks, "app": appmodule.app}


def csrf(resp) -> str:
    m = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data)
    assert m, "csrf_token не найден на странице"
    return m.group(1).decode()


def login(client, username, password):
    r = client.get("/login")
    r = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf(r)},
        follow_redirects=True,
    )
    assert r.status_code == 200
    return r
