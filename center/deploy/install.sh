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
    read -rp "Системный пользователь сервиса [fail2ban-center]: " SERVICE_USER
    SERVICE_USER="${SERVICE_USER:-fail2ban-center}"

    echo
    echo "==== Сетевой адрес(а) для приёма подключений (агентов и/или браузера) ===="
    echo "0) 127.0.0.1 — только локально (админ заходит через SSH-туннень, агенты — только"
    echo "   с этого же хоста)"
    IFACE_IPS=(); IFACE_NAMES=()
    n=1
    while read -r iface addr; do
        [[ -z "$iface" ]] && continue
        ip_only="${addr%/*}"
        echo "$n) $ip_only  (интерфейс $iface)"
        IFACE_IPS+=("$ip_only"); IFACE_NAMES+=("$iface")
        n=$((n + 1))
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}')
    VPN_OPT=$n
    echo "$n) Создать отдельную VPN-сеть для агентов (WireGuard-хаб) — если агентам не видна"
    echo "   ни одна из сетей выше напрямую (например, они за NAT/на других хостах)"
    echo
    read -rp "Выбор, можно несколько через пробел (например «0 2») [0]: " BIND_CHOICES
    BIND_CHOICES="${BIND_CHOICES:-0}"

    BIND_ADDRS=(); WANT_VPN=0
    for c in $BIND_CHOICES; do
        if [[ "$c" == "0" ]]; then
            BIND_ADDRS+=("127.0.0.1")
        elif [[ "$c" == "$VPN_OPT" ]]; then
            WANT_VPN=1
        elif [[ "$c" =~ ^[0-9]+$ ]] && (( c >= 1 && c < VPN_OPT )); then
            BIND_ADDRS+=("${IFACE_IPS[$((c - 1))]}")
        else
            echo "пропускаю нераспознанный вариант: $c" >&2
        fi
    done
    [[ ${#BIND_ADDRS[@]} -gt 0 || "$WANT_VPN" -eq 1 ]] || BIND_ADDRS=("127.0.0.1")

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

    if [[ "$WANT_VPN" -eq 1 ]]; then
        echo "==== VPN-хаб (WireGuard) ===="
        if ! command -v wg-quick >/dev/null 2>&1; then
            case "$(detect_pkg_manager)" in
                apt-get) apt-get update -y && apt-get install -y wireguard-tools ;;
                dnf)     dnf install -y wireguard-tools ;;
                yum)     yum install -y wireguard-tools ;;
                *) echo "не удалось поставить wireguard-tools автоматически — установите вручную и повторите" >&2; exit 1 ;;
            esac
        fi
        install -o root -g root -m 700 "$SCRIPT_DIR/deploy/f2b-center-vpn-helper.sh" /usr/local/sbin/f2b-center-vpn-helper
        sed "s/CHANGE_ME_SERVICE_USER/$SERVICE_USER/" "$SCRIPT_DIR/deploy/sudoers-f2b-center-vpn" > /tmp/.f2b-center-vpn-sudoers.new
        visudo -cf /tmp/.f2b-center-vpn-sudoers.new
        install -o root -g root -m 440 /tmp/.f2b-center-vpn-sudoers.new /etc/sudoers.d/f2b-center-vpn
        rm -f /tmp/.f2b-center-vpn-sudoers.new

        echo "Адрес/домен, по которому агенты будут стучаться для VPN-хендшейка (обычно один из"
        echo "адресов выше, либо публичный IP этого хоста, если агенты снаружи):"
        read -rp "Endpoint: " VPN_ENDPOINT
        [[ -n "$VPN_ENDPOINT" ]] || { echo "endpoint обязателен для VPN-хаба" >&2; exit 1; }
        read -rp "VPN-подсеть [10.99.0.0/24]: " VPN_SUBNET
        VPN_SUBNET="${VPN_SUBNET:-10.99.0.0/24}"
        read -rp "VPN-порт, UDP [51820]: " VPN_PORT
        VPN_PORT="${VPN_PORT:-51820}"

        sudo -u "$SERVICE_USER" env F2B_CENTER_DATA_DIR="$INSTALL_DIR/data" \
            "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/manage.py" vpn-init \
            --subnet "$VPN_SUBNET" --port "$VPN_PORT" --endpoint "$VPN_ENDPOINT"

        VPN_CENTER_IP=$(python3 -c "import ipaddress; print(next(ipaddress.ip_network('$VPN_SUBNET', strict=False).hosts()))")
        BIND_ADDRS+=("$VPN_CENTER_IP")
        echo "VPN-хаб поднят, центр слушает и на $VPN_CENTER_IP — агенты подключаются через"
        echo "install_agent.sh --setup-vpn (см. README/agent/README.md)."
    fi

    python3 - "$SCRIPT_DIR/deploy/fail2ban-center.service" "$SERVICE_USER" "$PORT" "${BIND_ADDRS[*]}" <<'PYEOF' > "$SERVICE_UNIT"
import sys
tmpl_path, service_user, port, bind_addrs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split()
with open(tmpl_path) as f:
    content = f.read()
content = content.replace("CHANGE_ME_SERVICE_USER", service_user)
bind_lines = " \\\n".join(f"    --bind {addr}:{port}" for addr in bind_addrs)
content = content.replace("    --bind 127.0.0.1:8766 \\", bind_lines + " \\")
sys.stdout.write(content)
PYEOF

    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"

    echo
    echo "==== Готово ===="
    for addr in "${BIND_ADDRS[@]}"; do
        echo "Слушает на $addr:$PORT"
    done
    echo "Кроме прямого localhost — только через reverse-proxy с TLS (см. README.md)."
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
