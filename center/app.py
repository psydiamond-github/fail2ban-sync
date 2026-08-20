from __future__ import annotations

import os
from datetime import timedelta

from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for

import api
import auth
import db
import graylog_client
import scheduler
import tasks
import vpn

DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES = 30


def _actor() -> str:
    return auth.current_username() or "unknown"


def _agent_or_404(agent_id: int) -> dict:
    agent = db.get_agent(agent_id)
    if agent is None:
        abort(404)
    return agent


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = db.load_secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("F2B_CENTER_COOKIE_SECURE", "1") == "1",
        SESSION_COOKIE_NAME="f2b_center_session",
    )

    if os.environ.get("F2B_CENTER_TRUST_PROXY") == "1":
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    db.init_db()
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        minutes=int(db.get_setting("session_idle_timeout_minutes", str(DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES)))
    )

    app.register_blueprint(api.bp)

    @app.after_request
    def _security_headers(response):
        # Базовое хардening — сама вебка не делает ничего опасного, но эти заголовки
        # ничего не стоят и закрывают типовые классы атак (clickjacking, MIME-sniffing).
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.context_processor
    def inject_globals():
        nav_tree = {"groups": [], "agents": []}
        nav_active_chain = []
        if auth.current_username():
            nav_tree, nav_active_chain = _build_nav_tree()
        return {
            "csrf_token": auth.csrf_token,
            "current_username": auth.current_username(),
            "current_role": auth.current_role(),
            "nav_tree": nav_tree,
            "nav_active_chain": nav_active_chain,
            "current_agent_id": request.view_args.get("agent_id") if request.view_args else None,
        }

    def _build_nav_tree():
        """Дерево навигации: {"groups": [{"id","name","children": {...}}], "agents": [...]},
        группы верхнего уровня и агенты вне групп — в одном узле (parent_id/group_id=None).
        Возвращает (tree, active_chain) — путь id-групп до текущего открытого агента."""
        groups = db.list_groups()
        groups_by_id = {g["id"]: g for g in groups}
        children_by_parent: dict = {}
        for g in groups:
            children_by_parent.setdefault(g["parent_id"], []).append(g)
        for lst in children_by_parent.values():
            lst.sort(key=lambda g: g["name"].lower())

        agents = db.list_agents()
        agents_by_group: dict = {}
        for a in agents:
            agents_by_group.setdefault(a["group_id"], []).append(a)
        for lst in agents_by_group.values():
            lst.sort(key=lambda a: a["name"].lower())

        def build(parent_id):
            return {
                "groups": [
                    {"id": g["id"], "name": g["name"], "children": build(g["id"])}
                    for g in children_by_parent.get(parent_id, [])
                ],
                "agents": [{"id": a["id"], "name": a["name"]} for a in agents_by_group.get(parent_id, [])],
            }

        tree = build(None)

        active_chain = []
        cur_agent_id = request.view_args.get("agent_id") if request.view_args else None
        if cur_agent_id is not None:
            agent = db.get_agent(cur_agent_id)
            gid = agent["group_id"] if agent else None
            while gid is not None:
                active_chain.append(gid)
                g = groups_by_id.get(gid)
                gid = g["parent_id"] if g else None
            active_chain.reverse()
        return tree, active_chain

    def _group_path(gid, groups_by_id):
        parts = []
        while gid is not None:
            g = groups_by_id.get(gid)
            if not g:
                break
            parts.append(g["name"])
            gid = g["parent_id"]
        return " / ".join(reversed(parts))

    def _group_choices():
        """(список {"id","path"} для <select>, отсортированный по пути; groups_by_id)."""
        groups = db.list_groups()
        groups_by_id = {g["id"]: g for g in groups}
        choices = sorted(
            ({"id": g["id"], "path": _group_path(g["id"], groups_by_id)} for g in groups),
            key=lambda c: c["path"].lower(),
        )
        return choices, groups_by_id

    # === Аутентификация =====================================================================

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            remote_ip = request.remote_addr or ""
            if auth.login_rate_limited(remote_ip):
                flash("Слишком много неудачных попыток входа — попробуйте позже.", "error")
                return redirect(url_for("login"))
            if not auth.check_csrf(request.form):
                auth.flash_csrf_error()
                return redirect(url_for("login"))
            user = auth.verify_login(request.form.get("username", ""), request.form.get("password", ""))
            if user is None:
                auth.record_login_failure(remote_ip)
                flash("Неверный логин или пароль.", "error")
                return redirect(url_for("login"))
            auth.record_login_success(remote_ip)
            auth.login_user(user)
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        auth.logout_user()
        return redirect(url_for("login"))

    @app.route("/")
    def index():
        return redirect(url_for("dashboard"))

    # === Дашборд и страница агента ============================================================

    @app.route("/dashboard")
    @auth.require_login
    def dashboard():
        agents = db.list_agents()
        groups_by_id = {g["id"]: g for g in db.list_groups()}
        group_path_by_agent = {
            a["id"]: _group_path(a["group_id"], groups_by_id) for a in agents if a["group_id"] is not None
        }
        return render_template("dashboard.html", agents=agents, group_path_by_agent=group_path_by_agent)

    @app.route("/agents/<int:agent_id>")
    @auth.require_login
    def agent_detail(agent_id):
        agent = _agent_or_404(agent_id)
        # Джейлы вроде agent-tor-block/recidive легко разрастаются до тысяч записей —
        # рендерить их все inline раздувало страницу до мегабайт и вешало браузер;
        # показываем последние BANS_PER_JAIL_LIMIT, остальное — только счётчиком в табе.
        BANS_PER_JAIL_LIMIT = 200
        bans_by_jail: dict[str, list] = {j["name"]: [] for j in agent["allowed_jails"]}
        bans_total_by_jail: dict[str, int] = {j["name"]: 0 for j in agent["allowed_jails"]}
        for row in db.list_ban_state(agent_id):
            bans_by_jail.setdefault(row["jail"], [])
            bans_total_by_jail[row["jail"]] = bans_total_by_jail.get(row["jail"], 0) + 1
            if len(bans_by_jail[row["jail"]]) < BANS_PER_JAIL_LIMIT:
                bans_by_jail[row["jail"]].append(dict(row))
        temp_ignore = db.list_temp_ignore(agent_id)
        permanent_ignore = db.list_permanent_ignore(agent_id)
        recent_tasks = db.list_tasks_for_agent(agent_id, limit=30)

        log_view_mode = db.get_setting("log_view_mode", "none")
        log_messages, log_error, log_link, local_log_text = [], None, None, None
        # default НЕ проходит через type=int у request.args.get — приводим сами,
        # иначе строка "24" из settings даст "24"*3600 вместо 24*3600.
        range_hours = request.args.get("range_hours", type=int) or int(
            db.get_setting("graylog_default_range_hours", "24") or "24"
        )
        if log_view_mode == "local":
            # Дёшево (локальный кэш-файл, не сеть) — рендерим сразу, вкладка переключается
            # мгновенно на клиенте, без перезагрузки страницы (как вкладки джейлов).
            lines = int(db.get_setting("fail2ban_log_lines", "300") or "300")
            local_log_text = tasks.read_local_log(agent_id, max_lines=lines)
        elif log_view_mode == "graylog" and request.args.get("tab") == "log":
            # Graylog — живой запрос во внешнюю систему, оставляем по явному сабмиту формы.
            source = agent.get("graylog_source") or agent["name"]
            jail_filter = request.args.get("jail") or None
            limit = int(db.get_setting("graylog_default_log_lines", "300") or "300") or 300
            try:
                log_messages = graylog_client.search(
                    source, jail=jail_filter, range_hours=range_hours, limit=limit
                )
            except graylog_client.GraylogError as e:
                log_error = str(e)
            log_link = graylog_client.deep_link(source, jail=jail_filter, range_hours=range_hours)

        return render_template(
            "agent_detail.html",
            agent=agent,
            bans_by_jail=bans_by_jail,
            bans_total_by_jail=bans_total_by_jail,
            temp_ignore=temp_ignore,
            permanent_ignore=permanent_ignore,
            recent_tasks=recent_tasks,
            log_view_mode=log_view_mode,
            log_messages=log_messages,
            log_error=log_error,
            log_link=log_link,
            local_log_text=local_log_text,
            range_hours=range_hours,
            graylog_configured=graylog_client.is_configured(),
        )

    @app.route("/agents/<int:agent_id>/ban", methods=["POST"])
    @auth.require_admin
    def agent_ban(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        jail = request.form.get("jail", "")
        ip = request.form.get("ip", "").strip()
        try:
            tasks.manual_ban(agent_id, jail, ip, _actor())
            flash(f"Бан {ip} в {jail} поставлен в очередь.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/ban-forever", methods=["POST"])
    @auth.require_admin
    def agent_ban_forever(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        ip = request.form.get("ip", "").strip()
        try:
            tasks.ban_forever(agent_id, ip, _actor())
            flash(f"Бан навсегда {ip} поставлен в очередь.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/unban", methods=["POST"])
    @auth.require_login
    def agent_unban(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        jail = request.form.get("jail", "")
        ip = request.form.get("ip", "").strip()
        try:
            tasks.manual_unban(agent_id, jail, ip, _actor())
            flash(f"Разбан {ip} в {jail} поставлен в очередь.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/ignore/temp/add", methods=["POST"])
    @auth.require_login
    def agent_temp_ignore_add(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        jail = request.form.get("jail", "")
        ip = request.form.get("ip", "").strip()
        try:
            minutes = int(request.form.get("minutes", "60"))
            seconds = max(minutes, 1) * 60
            tasks.queue_temp_ignore_add(agent_id, jail, ip, seconds, _actor(), request.form.get("comment", ""))
            flash(f"Временный игнор {ip} в {jail} на {minutes} мин поставлен в очередь.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/ignore/temp/remove", methods=["POST"])
    @auth.require_login
    def agent_temp_ignore_remove(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        jail = request.form.get("jail", "")
        ip = request.form.get("ip", "").strip()
        tasks.queue_temp_ignore_remove(agent_id, jail, ip, _actor())
        flash(f"Снятие временного игнора {ip} в {jail} поставлено в очередь.", "ok")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/ignore/permanent/add", methods=["POST"])
    @auth.require_admin
    def agent_permanent_ignore_add(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        ip = request.form.get("ip", "").strip()
        try:
            tasks.add_permanent_ignore(agent_id, ip, _actor(), request.form.get("comment", ""))
            flash(f"Постоянный игнор {ip} поставлен в очередь.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/ignore/permanent/remove", methods=["POST"])
    @auth.require_admin
    def agent_permanent_ignore_remove(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        ip = request.form.get("ip", "").strip()
        tasks.remove_permanent_ignore(agent_id, ip, _actor())
        flash(f"Снятие постоянного игнора {ip} поставлено в очередь.", "ok")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/refresh", methods=["POST"])
    @auth.require_login
    def agent_refresh(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        tasks.request_full_state(agent_id, _actor())
        flash("Запрос полного состояния поставлен в очередь.", "ok")
        return redirect(url_for("agent_detail", agent_id=agent_id))

    @app.route("/agents/<int:agent_id>/resync-jails", methods=["POST"])
    @auth.require_login
    def agent_resync_jails(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("agent_detail", agent_id=agent_id))
        _agent_or_404(agent_id)
        db.mark_jail_resync(agent_id)
        db.log_action(_actor(), agent_id, "jail_resync_requested")
        flash(
            "Пересинхронизация джейлов запрошена — применится на следующем чекине агента "
            "(добавит новые, уберёт те, которых на хосте больше нет).", "ok",
        )
        return redirect(url_for("agent_detail", agent_id=agent_id))

    # === Администрирование агентов ============================================================

    @app.route("/admin/agents")
    @auth.require_admin
    def admin_agents():
        agents = db.list_agents()
        group_choices, groups_by_id = _group_choices()
        group_path_by_agent = {
            a["id"]: _group_path(a["group_id"], groups_by_id) for a in agents if a["group_id"] is not None
        }
        return render_template(
            "admin_agents.html", agents=agents, group_choices=group_choices, group_path_by_agent=group_path_by_agent
        )

    @app.route("/admin/agents/add", methods=["POST"])
    @auth.require_admin
    def admin_agents_add():
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_agents"))
        name = request.form.get("name", "").strip()
        group_id = request.form.get("group_id", type=int) or None
        jail_lines = request.form.get("allowed_jails", "")
        jails = []
        for line in jail_lines.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            jail_name = parts[0]
            bantime = int(parts[1]) if len(parts) > 1 else 600
            jails.append({"name": jail_name, "bantime": bantime})
        if not name:
            flash("Имя агента обязательно.", "error")
            return redirect(url_for("admin_agents"))
        agent_id, token = db.register_agent(name, jails, group_id=group_id)
        db.log_action(_actor(), agent_id, "agent_registered")
        jail_flags = "".join(f" --jail {j['name']}:{j['bantime']}" for j in jails)
        flash(
            f"Агент «{name}» создан. Токен (показывается один раз, сохраните сейчас): {token}. "
            f"Установка: sudo agent/install_agent.sh --center-url <URL> --token {token} "
            f"--agent-name {name}{jail_flags}",
            "ok",
        )
        return redirect(url_for("admin_agents"))

    @app.route("/admin/agents/<int:agent_id>/edit", methods=["GET", "POST"])
    @auth.require_admin
    def admin_agent_edit(agent_id):
        agent = _agent_or_404(agent_id)
        if request.method == "POST":
            if not auth.check_csrf(request.form):
                auth.flash_csrf_error()
                return redirect(url_for("admin_agent_edit", agent_id=agent_id))
            group_id = request.form.get("group_id", type=int) or None
            db.set_agent_group(agent_id, group_id)
            pinned_ip = request.form.get("pinned_ip", "").strip() or None
            ip_pin_mode = request.form.get("ip_pin_mode", "advisory")
            db.set_agent_ip_pin(agent_id, pinned_ip, ip_pin_mode)
            graylog_source = request.form.get("graylog_source", "").strip() or None
            db.set_agent_graylog_source(agent_id, graylog_source)
            jails = []
            for line in request.form.get("allowed_jails", "").splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                jails.append({"name": parts[0], "bantime": int(parts[1]) if len(parts) > 1 else 600})
            db.set_agent_allowed_jails(agent_id, jails)
            db.log_action(_actor(), agent_id, "agent_edited")
            flash("Агент обновлён.", "ok")
            return redirect(url_for("admin_agent_edit", agent_id=agent_id))
        group_choices, _ = _group_choices()
        return render_template(
            "admin_agent_edit.html", agent=agent, group_choices=group_choices,
            vpn_enabled=vpn.is_enabled(), vpn_peer=vpn.get_peer(agent_id),
            vpn_center_pubkey=db.get_setting("vpn_pubkey"),
            vpn_endpoint=f"{db.get_setting('vpn_endpoint_host')}:{db.get_setting('vpn_listen_port')}",
            vpn_subnet_prefix=db.get_setting("vpn_subnet", "10.99.0.0/24").split("/")[1],
        )

    @app.route("/admin/agents/<int:agent_id>/vpn/add", methods=["POST"])
    @auth.require_admin
    def admin_agent_vpn_add(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_agent_edit", agent_id=agent_id))
        pubkey = request.form.get("wg_pubkey", "").strip()
        if not pubkey:
            flash("Публичный ключ обязателен.", "error")
        else:
            assigned_ip = vpn.add_peer(agent_id, pubkey)
            db.log_action(_actor(), agent_id, "vpn_peer_added", detail=assigned_ip)
            flash(f"VPN-пир добавлен, выданный адрес: {assigned_ip}. Данные для агента показаны ниже.", "ok")
        return redirect(url_for("admin_agent_edit", agent_id=agent_id))

    @app.route("/admin/agents/<int:agent_id>/vpn/remove", methods=["POST"])
    @auth.require_admin
    def admin_agent_vpn_remove(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_agent_edit", agent_id=agent_id))
        vpn.remove_peer(agent_id)
        db.log_action(_actor(), agent_id, "vpn_peer_removed")
        flash("VPN-пир удалён.", "ok")
        return redirect(url_for("admin_agent_edit", agent_id=agent_id))

    @app.route("/admin/agents/<int:agent_id>/revoke", methods=["POST"])
    @auth.require_admin
    def admin_agent_revoke(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_agents"))
        db.revoke_agent(agent_id)
        db.log_action(_actor(), agent_id, "agent_revoked")
        flash("Агент отозван — следующий чекин получит 401.", "ok")
        return redirect(url_for("admin_agents"))

    @app.route("/admin/agents/<int:agent_id>/regenerate-token", methods=["POST"])
    @auth.require_admin
    def admin_agent_regenerate_token(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_agents"))
        token = db.regenerate_token(agent_id)
        db.log_action(_actor(), agent_id, "agent_token_regenerated")
        flash(f"Новый токен (показывается один раз): {token}", "ok")
        return redirect(url_for("admin_agents"))

    @app.route("/admin/agents/<int:agent_id>/delete", methods=["POST"])
    @auth.require_admin
    def admin_agent_delete(agent_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_agents"))
        db.log_action(_actor(), None, "agent_deleted", detail=f"agent_id={agent_id}")
        db.delete_agent(agent_id)
        flash("Агент удалён.", "ok")
        return redirect(url_for("admin_agents"))

    # === Группы ================================================================================

    @app.route("/admin/groups")
    @auth.require_admin
    def admin_groups():
        group_choices, groups_by_id = _group_choices()
        tree, _ = _build_nav_tree()
        return render_template(
            "admin_groups.html", tree=tree, group_choices=group_choices, groups_by_id=groups_by_id
        )

    @app.route("/admin/groups/add", methods=["POST"])
    @auth.require_admin
    def admin_groups_add():
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_groups"))
        name = request.form.get("name", "").strip()
        parent_id = request.form.get("parent_id", type=int) or None
        if name:
            db.create_group(name, parent_id)
            flash("Группа создана.", "ok")
        return redirect(url_for("admin_groups"))

    @app.route("/admin/groups/<int:group_id>/rename", methods=["POST"])
    @auth.require_admin
    def admin_groups_rename(group_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_groups"))
        db.rename_group(group_id, request.form.get("name", "").strip())
        return redirect(url_for("admin_groups"))

    @app.route("/admin/groups/<int:group_id>/move", methods=["POST"])
    @auth.require_admin
    def admin_groups_move(group_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_groups"))
        db.move_group(group_id, request.form.get("parent_id", type=int) or None)
        return redirect(url_for("admin_groups"))

    @app.route("/admin/groups/<int:group_id>/delete", methods=["POST"])
    @auth.require_admin
    def admin_groups_delete(group_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_groups"))
        if not db.delete_group(group_id):
            flash("Нельзя удалить непустую группу — сначала перенесите подгруппы/агентов.", "error")
        return redirect(url_for("admin_groups"))

    # === Пользователи ==========================================================================

    @app.route("/admin/users")
    @auth.require_admin
    def admin_users():
        return render_template("admin_users.html", users=db.list_users())

    @app.route("/admin/users/add", methods=["POST"])
    @auth.require_admin
    def admin_users_add():
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_users"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "operator")
        if role not in ("admin", "operator"):
            role = "operator"
        if not username or not password:
            flash("Логин и пароль обязательны.", "error")
        elif len(password) < 6:
            flash("Пароль слишком короткий (минимум 6 символов).", "error")
        elif db.get_user_by_username(username):
            flash("Такой пользователь уже существует.", "error")
        else:
            db.create_user(username, auth.hash_password(password), role)
            flash(f"Пользователь «{username}» создан.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @auth.require_admin
    def admin_users_role(user_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_users"))
        user = db.get_user(user_id)
        new_role = request.form.get("role", "operator")
        if new_role not in ("admin", "operator"):
            flash("Некорректная роль.", "error")
            return redirect(url_for("admin_users"))
        if user and user["role"] == "admin" and new_role != "admin" and db.count_admins() <= 1:
            flash("Нельзя понизить последнего administrator.", "error")
        else:
            db.set_user_role(user_id, new_role)
            flash("Роль обновлена.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
    @auth.require_admin
    def admin_users_reset_password(user_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_users"))
        password = request.form.get("password", "")
        if len(password) < 6:
            flash("Пароль слишком короткий.", "error")
        else:
            db.set_user_password(user_id, auth.hash_password(password))
            flash("Пароль сброшен.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @auth.require_admin
    def admin_users_delete(user_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_users"))
        user = db.get_user(user_id)
        if user and user["role"] == "admin" and db.count_admins() <= 1:
            flash("Нельзя удалить последнего администратора.", "error")
        else:
            db.delete_user(user_id)
            flash("Пользователь удалён.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/account", methods=["GET", "POST"])
    @auth.require_login
    def account():
        if request.method == "POST":
            if not auth.check_csrf(request.form):
                auth.flash_csrf_error()
                return redirect(url_for("account"))
            user = db.get_user(session["user_id"])
            current = auth.verify_login(user["username"], request.form.get("current_password", ""))
            new_password = request.form.get("new_password", "")
            if current is None:
                flash("Текущий пароль неверен.", "error")
            elif len(new_password) < 6:
                flash("Новый пароль слишком короткий.", "error")
            else:
                db.set_user_password(user["id"], auth.hash_password(new_password))
                flash("Пароль изменён.", "ok")
            return redirect(url_for("account"))
        return render_template("account.html")

    # === Глобальный блок-лист ==================================================================

    @app.route("/admin/blocklist")
    @auth.require_login
    def admin_blocklist():
        return render_template(
            "admin_blocklist.html",
            entries=db.list_global_blocklist(),
            ignore_entries=db.list_global_block_ignore(),
            tor_nodes_count=len(db.list_tor_exit_nodes()),
            tor_enabled=db.get_setting("tor_block_enabled", "0") == "1",
        )

    @app.route("/admin/blocklist/add", methods=["POST"])
    @auth.require_admin
    def admin_blocklist_add():
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_blocklist"))
        ip = request.form.get("ip", "").strip()
        try:
            tasks.add_to_global_blocklist_manually(ip, _actor())
            flash(f"{ip} добавлен в глобальный блок-лист.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("admin_blocklist"))

    @app.route("/admin/blocklist/<ip>/unban", methods=["POST"])
    @auth.require_login
    def admin_blocklist_unban(ip):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_blocklist"))
        tasks.manual_unban_everywhere(ip, _actor())
        flash(f"Разбан {ip} на всех агентах поставлен в очередь.", "ok")
        return redirect(url_for("admin_blocklist"))

    @app.route("/admin/blocklist/<ip>/delete", methods=["POST"])
    @auth.require_admin
    def admin_blocklist_delete(ip):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_blocklist"))
        tasks.delete_from_global_blocklist(ip, _actor())
        flash(f"{ip} удалён из базы блок-листа.", "ok")
        return redirect(url_for("admin_blocklist"))

    @app.route("/admin/blocklist/ignore/add", methods=["POST"])
    @auth.require_admin
    def admin_blocklist_ignore_add():
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_blocklist"))
        network = request.form.get("network", "").strip()
        try:
            tasks.add_global_block_ignore(network, request.form.get("comment", ""), _actor())
            flash(f"{network} добавлена в игнор-лист блок-листа.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("admin_blocklist"))

    @app.route("/admin/blocklist/ignore/<int:ignore_id>/delete", methods=["POST"])
    @auth.require_admin
    def admin_blocklist_ignore_delete(ignore_id):
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_blocklist"))
        tasks.remove_global_block_ignore(ignore_id, _actor())
        return redirect(url_for("admin_blocklist"))

    @app.route("/admin/blocklist/ignore/export")
    @auth.require_admin
    def admin_blocklist_ignore_export():
        text = tasks.export_global_block_ignore_text()
        return Response(
            text, mimetype="text/plain",
            headers={"Content-Disposition": "attachment; filename=global_block_ignore.txt"},
        )

    @app.route("/admin/blocklist/ignore/import", methods=["POST"])
    @auth.require_admin
    def admin_blocklist_ignore_import():
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_blocklist"))
        f = request.files.get("file")
        if f is None or not f.filename:
            flash("Файл не выбран.", "error")
            return redirect(url_for("admin_blocklist"))
        text = f.read().decode("utf-8", errors="replace")
        added, errors = tasks.import_global_block_ignore_text(text, _actor())
        flash(f"Импортировано записей: {added}.", "ok")
        if errors:
            flash("Пропущены строки: " + "; ".join(errors[:10]) + (" …" if len(errors) > 10 else ""), "error")
        return redirect(url_for("admin_blocklist"))

    @app.route("/admin/blocklist/tor/refresh", methods=["POST"])
    @auth.require_admin
    def admin_blocklist_tor_refresh():
        if not auth.check_csrf(request.form):
            auth.flash_csrf_error()
            return redirect(url_for("admin_blocklist"))
        try:
            count = tasks.refresh_tor_exit_nodes()
            db.set_setting("tor_block_last_refresh_at", db.now())
            tasks.sync_tor_block_all_agents(_actor())
            flash(f"Список Tor exit-нод обновлён: {count} адресов, синхронизация поставлена в очередь.", "ok")
        except Exception as e:
            flash(f"Не удалось обновить список: {e}", "error")
        return redirect(url_for("admin_blocklist"))

    # === Настройки =============================================================================

    @app.route("/admin/settings", methods=["GET", "POST"])
    @auth.require_admin
    def admin_settings():
        if request.method == "POST":
            if not auth.check_csrf(request.form):
                auth.flash_csrf_error()
                return redirect(url_for("admin_settings"))
            text_keys = [
                "checkin_interval_seconds", "agent_task_stale_after_missed",
                "session_idle_timeout_minutes", "global_block_threshold",
                "global_block_duration_mode", "global_block_bulk_max_workers",
                "tor_block_source_url", "tor_block_proxy_url", "tor_block_source_path",
                "log_view_mode", "fail2ban_log_lines", "local_log_max_bytes",
                "graylog_url", "graylog_stream_id",
                "graylog_default_range_hours", "graylog_default_log_lines",
            ]
            checkbox_keys = ["global_block_enabled", "tor_block_enabled"]
            for key in text_keys:
                if key in request.form:
                    db.set_setting(key, request.form.get(key, "").strip())
            # чекбоксы: браузер вообще не шлёт ключ, если он снят — иначе выключить было бы нельзя
            for key in checkbox_keys:
                db.set_setting(key, "1" if request.form.get(key) == "1" else "0")
            # Пустое поле = "не менять" (форма не отдаёт секрет обратно, см. шаблон).
            new_token = request.form.get("graylog_api_token", "").strip()
            if new_token:
                db.set_setting("graylog_api_token", new_token)
            app.permanent_session_lifetime = timedelta(
                minutes=int(db.get_setting("session_idle_timeout_minutes", "30"))
            )
            flash("Настройки сохранены.", "ok")
            return redirect(url_for("admin_settings"))
        return render_template("admin_settings.html", settings=db.all_settings())

    # === Аудит-лог ==============================================================================

    @app.route("/audit")
    @auth.require_login
    def audit():
        agent_id = request.args.get("agent", type=int)
        return render_template("audit.html", entries=db.list_audit(agent_id=agent_id), agent_id=agent_id)

    scheduler.start()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("F2B_CENTER_PORT", "8766")), debug=False)
