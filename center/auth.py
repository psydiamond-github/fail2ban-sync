"""Аутентификация пользователей веб-интерфейса: сессии Flask, роли admin/operator, CSRF."""
from __future__ import annotations

import secrets
import threading
import time
from functools import wraps
from typing import Optional

from flask import abort, flash, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import db

hash_password = generate_password_hash

# Rate-limit на попытки входа — в памяти процесса (безопасно при --workers 1).
# Второй рубеж поверх nginx limit_req, не замена ему.
_LOGIN_LOCKOUT_THRESHOLD = 10
_LOGIN_LOCKOUT_WINDOW_SECONDS = 300
_login_lock = threading.Lock()
_login_failures: dict[str, list[float]] = {}


def login_rate_limited(remote_ip: str) -> bool:
    now = time.time()
    with _login_lock:
        attempts = [t for t in _login_failures.get(remote_ip, []) if now - t < _LOGIN_LOCKOUT_WINDOW_SECONDS]
        _login_failures[remote_ip] = attempts
        return len(attempts) >= _LOGIN_LOCKOUT_THRESHOLD


def record_login_failure(remote_ip: str) -> None:
    with _login_lock:
        _login_failures.setdefault(remote_ip, []).append(time.time())


def record_login_success(remote_ip: str) -> None:
    with _login_lock:
        _login_failures.pop(remote_ip, None)


def verify_login(username: str, password: str) -> Optional[dict]:
    user = db.get_user_by_username(username)
    if user is None or not check_password_hash(user["password_hash"], password):
        return None
    return dict(user)


def login_user(user: dict) -> None:
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session.permanent = True


def logout_user() -> None:
    session.clear()


def current_username() -> Optional[str]:
    return session.get("username")


def current_role() -> Optional[str]:
    return session.get("role")


def is_admin() -> bool:
    return session.get("role") == "admin"


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def check_csrf(form) -> bool:
    submitted = form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(expected) and secrets.compare_digest(submitted, expected)


def flash_csrf_error() -> None:
    flash("Сессия истекла или недействительный запрос — попробуйте ещё раз.", "error")
