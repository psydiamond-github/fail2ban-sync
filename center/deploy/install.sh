#!/bin/bash
# Установщик центра fail2ban-center. Ставит ТОЛЬКО сам центр (веб-интерфейс + API для
# агентов) — установка агентов на управляемые хосты отдельная, см. agent/install_agent.sh.
#
# Центр работает только по HTTPS: TLS завершает сам gunicorn, сертификат выпускает
# собственный CA центра (/etc/fail2ban-center/tls). Веб-панель и API агентов слушают
# одни и те же выбранные при установке интерфейсы и один порт.
#
# Использование:
#   sudo deploy/install.sh install     # первая установка (порт, пользователь, интерфейсы, сертификат)
#   sudo deploy/install.sh configure   # заново выбрать интерфейсы и перевыпустить сертификат
#                                      # (CA сохраняется — агентам ничего менять не нужно)
#   sudo deploy/install.sh update      # новая версия кода, база и настройки сохраняются
#   sudo deploy/install.sh status
#   sudo deploy/install.sh start|stop|restart
#   sudo deploy/install.sh uninstall

set -euo pipefail

INSTALL_DIR="/opt/fail2ban-center"
SERVICE_NAME="fail2ban-center"
SERVICE_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
TLS_DIR="/etc/fail2ban-center/tls"

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
        apt-get) apt-get update -y && apt-get install -y python3 python3-venv python3-pip openssl ;;
        dnf)     dnf install -y python3 python3-pip openssl ;;
        yum)     yum install -y python3 python3-pip openssl ;;
        *)       echo "не удалось определить пакетный менеджер — убедитесь, что python3/venv/pip/openssl установлены вручную" >&2 ;;
    esac
}

copy_code() {
    rsync -a --exclude='__pycache__' --exclude='.pytest_cache' --exclude='data' --exclude='venv' \
        "$SCRIPT_DIR/" "$INSTALL_DIR/"
}

# Python центра от имени пользователя сервиса (БД принадлежит ему).
center_python() {
    (cd "$INSTALL_DIR" && sudo -u "$SERVICE_USER" env F2B_CENTER_DATA_DIR="$INSTALL_DIR/data" \
        F2B_CENTER_CA_CERT="$TLS_DIR/ca.crt" "$INSTALL_DIR/venv/bin/python3" "$@")
}

center_setting() {
    center_python -c 'import sys, db; print(db.get_setting(sys.argv[1]) or "")' "$1"
}

# Выбор интерфейсов: результат — BIND_ADDRS (адреса без VPN) и WANT_VPN.
# Веб-панель и приём HTTPS от агентов идут через одни и те же адреса.
select_bind_addrs() {
    local vpn_ip="${1:-}"
    echo
    echo "==== На каких интерфейсах работать (веб-панель + приём HTTPS от агентов) ===="
    echo "0) 127.0.0.1 — только локально (админ — через SSH-туннель, агент — только на этом хосте)"
    IFACE_IPS=()
    local n=1 iface addr
    while read -r iface addr; do
        [[ -z "$iface" ]] && continue
        [[ "$iface" == "f2b0" ]] && continue  # VPN-интерфейс центра — отдельный пункт ниже
        echo "$n) ${addr%/*}  (интерфейс $iface)"
        IFACE_IPS+=("${addr%/*}")
        n=$((n + 1))
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}')
    VPN_OPT=$n
    if [[ -n "$vpn_ip" ]]; then
        echo "$n) $vpn_ip  (VPN-сеть агентов f2b0, уже поднята)"
    else
        echo "$n) Создать отдельную VPN-сеть для агентов (WireGuard-хаб) — если агентам не видна"
        echo "   ни одна из сетей выше напрямую (например, они за NAT/на других хостах)"
    fi
    echo
    read -rp "Выбор, можно несколько через пробел (например «0 2») [${DEFAULT_CHOICES:-0}]: " BIND_CHOICES || true
    BIND_CHOICES="${BIND_CHOICES:-${DEFAULT_CHOICES:-0}}"

    BIND_ADDRS=(); WANT_VPN=0
    local c
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
}

# Номера пунктов меню, соответствующие текущим --bind (для configure: Enter = оставить как есть).
default_choices_from_unit() {
    local bound=" $1 " vpn_ip="$2" choices="" n=1 iface addr
    [[ "$bound" == *" 127.0.0.1 "* ]] && choices="0"
    while read -r iface addr; do
        [[ -z "$iface" || "$iface" == "f2b0" ]] && continue
        [[ "$bound" == *" ${addr%/*} "* ]] && choices="$choices $n"
        n=$((n + 1))
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}')
    [[ -n "$vpn_ip" && "$bound" == *" $vpn_ip "* ]] && choices="$choices $n"
    echo "${choices# }"
}

setup_vpn_hub() {
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
    local endpoint subnet port
    read -rp "Endpoint: " endpoint
    [[ -n "$endpoint" ]] || { echo "endpoint обязателен для VPN-хаба" >&2; exit 1; }
    read -rp "VPN-подсеть [10.99.0.0/24]: " subnet || true
    subnet="${subnet:-10.99.0.0/24}"
    read -rp "VPN-порт, UDP [51820]: " port || true
    port="${port:-51820}"

    center_python "$INSTALL_DIR/manage.py" vpn-init --subnet "$subnet" --port "$port" --endpoint "$endpoint"
    VPN_CENTER_IP=$(center_setting vpn_center_ip)
    echo "VPN-хаб поднят, центр будет слушать и на $VPN_CENTER_IP."
}

# Собственный CA (создаётся один раз и потом переиспользуется) + серверный сертификат,
# в SAN которого все адреса прослушивания, 127.0.0.1, имя хоста и дополнительные имена.
# Агенты проверяют адрес из center_url именно по SAN.
issue_certificate() {
    echo
    echo "==== Сертификат HTTPS центра ===="
    local -a san_args=() extra=()
    local addr name
    declare -A seen=()
    for addr in 127.0.0.1 "${BIND_ADDRS[@]}"; do
        [[ -n "$addr" && -z "${seen[$addr]:-}" ]] || continue
        seen[$addr]=1
        san_args+=(--ip "$addr")
    done
    for name in "$(hostname -f 2>/dev/null || true)" "$(hostname 2>/dev/null || true)"; do
        [[ -n "$name" && -z "${seen[$name]:-}" ]] || continue
        seen[$name]=1
        san_args+=(--dns "$name")
    done
    echo "В сертификат войдут: ${!seen[*]}"
    echo "Если агенты обращаются к центру по другому адресу (публичный IP за NAT, DNS-имя),"
    read -rp "впишите его здесь через пробел (Enter — ничего не добавлять): " -a extra || true
    for name in "${extra[@]:-}"; do
        [[ -n "$name" && -z "${seen[$name]:-}" ]] || continue
        seen[$name]=1
        if python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$name" 2>/dev/null; then
            san_args+=(--ip "$name")
        else
            san_args+=(--dns "$name")
        fi
    done

    install -d -o root -g root -m 755 "$TLS_DIR"
    "$SCRIPT_DIR/deploy/generate-internal-ca.sh" --out-dir "$TLS_DIR" "${san_args[@]}" >/dev/null
    # gunicorn работает от пользователя сервиса — ему нужен ключ сертификата, но не ключ CA.
    chown root:"$SERVICE_USER" "$TLS_DIR/server.key"
    chmod 640 "$TLS_DIR/server.key"
    chmod 600 "$TLS_DIR/ca.key"
    echo "Сертификат выпущен: $TLS_DIR/server.crt (CA: $TLS_DIR/ca.crt)"
}

ask_trust_proxy() {
    local current="${1:-0}" ans
    local hint="y/N"; [[ "$current" == "1" ]] && hint="Y/n"
    read -rp "Перед центром стоит свой reverse-proxy (передаёт X-Forwarded-*)? [$hint]: " ans || true
    case "${ans:-}" in
        [Yy]*) TRUST_PROXY=1 ;;
        [Nn]*) TRUST_PROXY=0 ;;
        *)     TRUST_PROXY="$current" ;;
    esac
}

write_unit() {
    python3 - "$SCRIPT_DIR/deploy/fail2ban-center.service" "$SERVICE_USER" "$PORT" "$TRUST_PROXY" \
        "${BIND_ADDRS[*]}" <<'PYEOF' > "$SERVICE_UNIT"
import sys
tmpl_path, service_user, port, trust_proxy, bind_addrs = sys.argv[1:6]
with open(tmpl_path) as f:
    content = f.read()
content = content.replace("CHANGE_ME_SERVICE_USER", service_user)
content = content.replace("F2B_CENTER_TRUST_PROXY=0", f"F2B_CENTER_TRUST_PROXY={trust_proxy}")
bind_lines = " \\\n".join(f"    --bind {addr}:{port}" for addr in bind_addrs.split())
content = content.replace("    --bind 127.0.0.1:8766 \\", bind_lines + " \\")
sys.stdout.write(content)
PYEOF
    systemctl daemon-reload
}

print_summary() {
    local fingerprint addr
    fingerprint=$(center_python "$INSTALL_DIR/manage.py" ca-fingerprint)
    echo
    echo "==== Готово ===="
    for addr in "${BIND_ADDRS[@]}"; do
        echo "Слушает: https://$addr:$PORT"
    done
    echo
    echo "Отпечаток CA центра (SHA-256) — для install_agent.sh --center-ca-sha256 и для"
    echo "проверки в браузере при добавлении $TLS_DIR/ca.crt в доверенные:"
    echo "  $fingerprint"
    echo
    echo "Агент подключается по адресу из списка выше:"
    echo "  sudo agent/install_agent.sh --center-url https://<адрес>:$PORT --token <ТОКЕН> \\"
    echo "      --agent-name <ИМЯ> --center-ca-sha256 $fingerprint"
}

cmd_install() {
    require_root
    echo "==== fail2ban-center: установка ===="

    read -rp "Порт HTTPS [8766]: " PORT || true
    PORT="${PORT:-8766}"
    read -rp "Системный пользователь сервиса [fail2ban-center]: " SERVICE_USER || true
    SERVICE_USER="${SERVICE_USER:-fail2ban-center}"

    DEFAULT_CHOICES=0
    select_bind_addrs ""
    ask_trust_proxy 0

    install_python_deps

    id "$SERVICE_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$SERVICE_USER"

    mkdir -p "$INSTALL_DIR"
    copy_code

    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

    mkdir -p "$INSTALL_DIR/data"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

    center_python "$INSTALL_DIR/manage.py" init-db

    if ! center_python -c "import db, sys; sys.exit(0 if db.list_users() else 1)" 2>/dev/null; then
        echo "==== Первый администратор ===="
        center_python "$INSTALL_DIR/manage.py" create-admin
    fi

    if [[ "$WANT_VPN" -eq 1 ]]; then
        setup_vpn_hub
        BIND_ADDRS+=("$VPN_CENTER_IP")
    fi

    issue_certificate
    write_unit
    systemctl enable --now "$SERVICE_NAME"
    print_summary
    systemctl status "$SERVICE_NAME" --no-pager || true
}

# Для уже установленного центра: заново выбрать интерфейсы, перевыпустить сертификат,
# переписать юнит. Пользователь, порт и прокси по умолчанию берутся из текущего юнита.
cmd_configure() {
    require_root
    [[ -f "$SERVICE_UNIT" && -d "$INSTALL_DIR/venv" ]] || { echo "центр не установлен: сначала install" >&2; exit 1; }

    SERVICE_USER=$(sed -n 's/^User=//p' "$SERVICE_UNIT" | head -n1)
    local current_port current_binds current_proxy
    current_binds=$(grep -oE -- '--bind [^ ]+' "$SERVICE_UNIT" | awk '{print $2}' | sed 's/:[0-9]*$//' | paste -sd' ')
    current_port=$(grep -oE -- '--bind [^ ]+' "$SERVICE_UNIT" | head -n1 | sed 's/.*://')
    current_proxy=$(sed -n 's/^Environment=F2B_CENTER_TRUST_PROXY=//p' "$SERVICE_UNIT" | head -n1)

    echo "==== fail2ban-center: интерфейсы и HTTPS ===="
    echo "Сейчас слушает: ${current_binds:-—}, порт ${current_port:-—}"
    read -rp "Порт HTTPS [${current_port:-8766}]: " PORT || true
    PORT="${PORT:-${current_port:-8766}}"

    VPN_CENTER_IP=""
    [[ "$(center_setting vpn_enabled)" == "1" ]] && VPN_CENTER_IP=$(center_setting vpn_center_ip)
    DEFAULT_CHOICES=$(default_choices_from_unit "$current_binds" "$VPN_CENTER_IP")
    select_bind_addrs "$VPN_CENTER_IP"
    ask_trust_proxy "${current_proxy:-0}"

    if [[ "$WANT_VPN" -eq 1 ]]; then
        [[ -n "$VPN_CENTER_IP" ]] || setup_vpn_hub
        BIND_ADDRS+=("$VPN_CENTER_IP")
    fi

    issue_certificate
    write_unit
    systemctl restart "$SERVICE_NAME"
    print_summary
    echo
    echo "Агентам, установленным до перехода на HTTPS, нужно один раз выполнить на их хосте:"
    echo "  sudo agent/install_agent.sh --update --center-url https://<адрес>:$PORT --center-ca-sha256 <отпечаток выше>"
}

# Настройки, база и юнит не меняются; миграции схемы выполняет init-db.
cmd_update() {
    require_root
    [[ -d "$INSTALL_DIR/venv" ]] || { echo "центр не установлен: сначала install" >&2; exit 1; }
    local service_user
    service_user=$(stat -c %U "$INSTALL_DIR/data")
    local backup="$INSTALL_DIR/data/backup-$(date +%Y%m%d-%H%M%S).sqlite3"
    sqlite3 "$INSTALL_DIR/data/f2b-center.sqlite3" ".backup $backup"
    chown "$service_user:$service_user" "$backup"
    echo "Резервная копия базы: $backup"

    systemctl stop "$SERVICE_NAME"
    copy_code
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    chown -R "$service_user:$service_user" "$INSTALL_DIR"
    sudo -u "$service_user" env F2B_CENTER_DATA_DIR="$INSTALL_DIR/data" \
        "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/manage.py" init-db
    systemctl start "$SERVICE_NAME"
    systemctl is-active "$SERVICE_NAME"
    if ! grep -q -- '--certfile' "$SERVICE_UNIT"; then
        echo
        echo "ВНИМАНИЕ: центр всё ещё работает по обычному HTTP. Переведите его на HTTPS:"
        echo "  sudo deploy/install.sh configure"
    fi
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
    read -rp "Удалить также $INSTALL_DIR/data (БД, секрет сессий) и CA центра $TLS_DIR? [y/N]: " ans || true
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR" "$TLS_DIR"
    else
        rm -rf "$INSTALL_DIR"/{app.py,auth.py,api.py,center_ca.py,db.py,tasks.py,scheduler.py,graylog_client.py,vpn.py,manage.py,requirements.txt,templates,static,db,deploy,venv,__pycache__}
        echo "Код и venv удалены, $INSTALL_DIR/data и $TLS_DIR сохранены."
    fi
    echo "Готово."
}

case "${1:-}" in
    install)   cmd_install ;;
    configure) cmd_configure ;;
    update)    cmd_update ;;
    status)    cmd_status ;;
    start)     cmd_start ;;
    stop)      cmd_stop ;;
    restart)   cmd_restart ;;
    uninstall) cmd_uninstall ;;
    *) echo "использование: $0 {install|configure|update|status|start|stop|restart|uninstall}" >&2; exit 1 ;;
esac
