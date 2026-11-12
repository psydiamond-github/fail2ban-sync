"""REST API для агентов: Bearer-токен, JSON, отдельный Blueprint от веб-UI (без сессии/CSRF)."""
from __future__ import annotations

from typing import Optional

from flask import Blueprint, Response, jsonify, request

import center_ca
import db
import tasks

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _authenticate() -> Optional[dict]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):].strip()
    if not token:
        return None
    return db.verify_agent_token(token)


@bp.route("/ca.crt", methods=["GET"])
def ca_cert():
    # Без авторизации: сертификат публичный. Агент скачивает его до того, как может
    # проверить TLS, поэтому доверяет ему только при совпадении отпечатка из панели.
    pem = center_ca.ca_pem()
    if pem is None:
        return jsonify({"error": "CA центра не настроен"}), 404
    return Response(pem, mimetype="application/x-pem-file")


@bp.route("/checkin", methods=["POST"])
def checkin():
    agent = _authenticate()
    if agent is None:
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "тело запроса должно быть JSON-объектом"}), 400

    try:
        result = tasks.process_checkin(agent, body, request.remote_addr or "")
    except tasks.IpPinRejected as e:
        return jsonify({"error": str(e)}), 403
    except (ValueError, TypeError) as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result), 200


@bp.route("/event", methods=["POST"])
def event():
    agent = _authenticate()
    if agent is None:
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "тело запроса должно быть JSON-объектом"}), 400

    try:
        tasks.process_event(agent, body, request.remote_addr or "")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return "", 204
