#!/bin/bash
# Установщик центра fail2ban-center. Ставит ТОЛЬКО сам центр (веб-интерфейс + API для
# агентов) — установка агентов на управляемые хосты отдельная, см. agent/install_agent.sh.
#
# Использование:
#   sudo deploy/install.sh install     # первая установка (спросит порт/адрес/пользователя)
#   sudo deploy/install.sh status
#   sudo deploy/install.sh start|stop|restart
#   sudo deploy/install.sh uninstall

set -euo pipefail

INSTALL_DIR="/opt/fail2ban-center"
SERVICE_NAME="fail2ban-center"
SERVICE_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"  # корень center/

require_root() {
    [[ $EUID -eq 0 ]] || { echo "запустите через sudo/от root" >&2; exit 1; }
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then echo apt-get
    elif command -v dnf >/dev/null 2>&1; then echo dnf
    elif command -v yum >/dev/null 2>&1; then echo yum
    else echo none; fi
}

install_python_deps() {
    local pm; pm=$(detect_pkg_manager)
    case "$pm" in
        apt-get) apt-get update -y && apt-get install -y python3 python3-venv python3-pip ;;
        dnf)     dnf install -y python3 python3-pip ;;
        yum)     yum install -y python3 python3-pip ;;
        *)       echo "не удалось определить пакетный менеджер — убедитесь, что python3/venv/pip установлены вручную" >&2 ;;
    esac
}

cmd_install() {
    require_root
    echo "==== fail2ban-center: установка ===="

    read -rp "Порт [8766]: " PORT
    PORT="${PORT:-8766}"
    read -rp "Адрес для прослушивания gunicorn [127.0.0.1]: " BIND_ADDR
    BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
    read -rp "Системный пользователь сервиса [fail2ban-center]: " SERVICE_USER
    SERVICE_USER="${SERVICE_USER:-fail2ban-center}"

    install_python_deps

    id "$SERVICE_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$SERVICE_USER"

    mkdir -p "$INSTALL_DIR"
    rsync -a --exclude='__pycache__' --exclude='.pytest_cache' --exclude='data' \
        "$SCRIPT_DIR/" "$INSTALL_DIR/"

    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

    mkdir -p "$INSTALL_DIR/data"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

    sudo -u "$SERVICE_USER" env F2B_CENTER_DATA_DIR="$INSTALL_DIR/data" \
        "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/manage.py" init-db

    if ! (cd "$INSTALL_DIR" && sudo -u "$SERVICE_USER" env F2B_CENTER_DATA_DIR="$INSTALL_DIR/data" \
        "$INSTALL_DIR/venv/bin/python3" -c "import db, sys; sys.exit(0 if db.list_users() else 1)" 2>/dev/null); then
        echo "==== Первый администратор ===="
        sudo -u "$SERVICE_USER" env F2B_CENTER_DATA_DIR="$INSTALL_DIR/data" \
            "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/manage.py" create-admin
    fi

    echo "==== VPN-хелпер (WireGuard, опционально — используется, только если включите VPN) ===="
    if command -v wg-quick >/dev/null 2>&1; then
        install -o root -g root -m 700 "$SCRIPT_DIR/deploy/f2b-center-vpn-helper.sh" /usr/local/sbin/f2b-center-vpn-helper
        sed "s/CHANGE_ME_SERVICE_USER/$SERVICE_USER/" "$SCRIPT_DIR/deploy/sudoers-f2b-center-vpn" > /tmp/.f2b-center-vpn-sudoers.new
        visudo -cf /tmp/.f2b-center-vpn-sudoers.new
        install -o root -g root -m 440 /tmp/.f2b-center-vpn-sudoers.new /etc/sudoers.d/f2b-center-vpn
        rm -f /tmp/.f2b-center-vpn-sudoers.new
    else
        echo "wireguard-tools не найден — пропущено (VPN-хаб можно будет включить, поставив wg-quick, позже)."
    fi

    sed \
        -e "s/CHANGE_ME_SERVICE_USER/$SERVICE_USER/" \
        -e "s/127\.0\.0\.1:8766/$BIND_ADDR:$PORT/" \
        "$SCRIPT_DIR/deploy/fail2ban-center.service" > "$SERVICE_UNIT"

    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"

    echo
    echo "==== Готово ===="
    echo "Слушает на $BIND_ADDR:$PORT — снаружи только через reverse-proxy с TLS (см. README.md)."
    systemctl status "$SERVICE_NAME" --no-pager || true
}

cmd_status()  { systemctl status "$SERVICE_NAME" --no-pager; }
cmd_start()   { systemctl start "$SERVICE_NAME"; }
cmd_stop()    { systemctl stop "$SERVICE_NAME"; }
cmd_restart() { systemctl restart "$SERVICE_NAME"; }

cmd_uninstall() {
    require_root
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_UNIT"
    systemctl daemon-reload
    read -rp "Удалить также $INSTALL_DIR/data (БД, секрет сессий)? [y/N]: " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
    else
        rm -rf "$INSTALL_DIR"/{app.py,auth.py,api.py,db.py,tasks.py,scheduler.py,graylog_client.py,manage.py,requirements.txt,templates,static,db,deploy,venv,__pycache__}
        echo "Код и venv удалены, $INSTALL_DIR/data сохранён."
    fi
    echo "Готово."
}

case "${1:-}" in
    install)   cmd_install ;;
    status)    cmd_status ;;
    start)     cmd_start ;;
    stop)      cmd_stop ;;
    restart)   cmd_restart ;;
    uninstall) cmd_uninstall ;;
    *) echo "использование: $0 {install|status|start|stop|restart|uninstall}" >&2; exit 1 ;;
esac
