#!/bin/bash
# Установка агента fail2ban-center на управляемый хост. Требует root (sudo). fail2ban должен
# уже быть установлен и запущен — этот скрипт его не ставит (см. docs/TZ.md §1).
#
# Использование:
#   sudo ./install_agent.sh --center-url https://center.example.org --token <TOKEN> \
#       --agent-name srv-42 [--jail sshd:600 --jail nginx-req-limit:3600 ...]
#
# --center-url/--token/--agent-name — берутся из вывода "Добавить агента" в веб-интерфейсе
# центра (или manage.py add-agent). --jail — ТЕ ЖЕ джейлы (имя:bantime_секунд, -1 — навсегда),
# что были указаны при регистрации на центре — agent-permanent-ban добавляется автоматически
# и здесь, и там, повторно указывать не нужно.

set -euo pipefail

CENTER_URL=""
TOKEN=""
AGENT_NAME=""
JAILS=()
SETUP_VPN=0
VPN_SERVER_PUBKEY=""
VPN_SERVER_ENDPOINT=""
VPN_ASSIGNED_IP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --center-url) CENTER_URL="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --agent-name) AGENT_NAME="$2"; shift 2 ;;
        --jail) JAILS+=("$2"); shift 2 ;;
        --setup-vpn) SETUP_VPN=1; shift ;;
        --vpn-server-pubkey) VPN_SERVER_PUBKEY="$2"; shift 2 ;;
        --vpn-server-endpoint) VPN_SERVER_ENDPOINT="$2"; shift 2 ;;
        --vpn-assigned-ip) VPN_ASSIGNED_IP="$2"; shift 2 ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
    esac
done

[[ -n "$CENTER_URL" && -n "$TOKEN" && -n "$AGENT_NAME" ]] || {
    echo "нужны --center-url, --token и --agent-name (см. -h/шапку скрипта)" >&2
    exit 1
}
[[ $EUID -eq 0 ]] || { echo "запустите через sudo/от root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_USER="f2b-agent"
INSTALL_DIR="/opt/f2b-agent"
CONFIG_DIR="/etc/f2b-agent"
STATE_DIR="/var/lib/f2b-agent"

echo "==== Проверка fail2ban на этом хосте ===="
if ! fail2ban-client ping >/dev/null 2>&1; then
    echo "ВНИМАНИЕ: fail2ban-client ping не отвечает — убедитесь, что fail2ban установлен и запущен." >&2
    echo "Продолжаю установку агента — но чекины будут падать до тех пор, пока fail2ban не заработает." >&2
fi

# REDOS/RHEL — dnf/yum; Ubuntu/Debian/ALT Linux — apt-get (ALT тоже APT, поверх RPM).
echo "==== Python 3 ===="
if ! command -v python3 >/dev/null 2>&1; then
    if command -v dnf >/dev/null 2>&1; then dnf install -y python3
    elif command -v yum >/dev/null 2>&1; then yum install -y python3
    elif command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y python3
    else echo "не удалось определить пакетный менеджер — установите python3 вручную" >&2; exit 1
    fi
fi

# Путь nologin-шелла отличается между дистрибутивами.
NOLOGIN_SHELL="/usr/sbin/nologin"
[[ -x "$NOLOGIN_SHELL" ]] || NOLOGIN_SHELL="/sbin/nologin"
[[ -x "$NOLOGIN_SHELL" ]] || NOLOGIN_SHELL="/bin/false"

echo "==== Системный пользователь $AGENT_USER ===="
id "$AGENT_USER" >/dev/null 2>&1 || useradd -r -s "$NOLOGIN_SHELL" -d "$STATE_DIR" "$AGENT_USER"

echo "==== Каталоги ===="
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"

echo "==== Файлы агента ===="
install -o root -g root -m 644 "$SCRIPT_DIR/f2b-agent-checkin.py" "$INSTALL_DIR/f2b-agent-checkin.py"
install -o root -g root -m 700 "$SCRIPT_DIR/f2b-agent-helper.sh" /usr/local/sbin/f2b-agent-helper
install -o root -g root -m 700 "$SCRIPT_DIR/f2b-agent-notify.py" /usr/local/sbin/f2b-agent-notify

echo "==== Конфигурация ($CONFIG_DIR/config.json) ===="
{
    python3 - "$CENTER_URL" "$TOKEN" "$AGENT_NAME" "${JAILS[@]:-}" <<'PYEOF'
import json
import sys

center_url, token, agent_name = sys.argv[1], sys.argv[2], sys.argv[3]
jails = []
for spec in sys.argv[4:]:
    if not spec:
        continue
    name, _, bantime = spec.partition(":")
    jails.append({"name": name, "bantime": int(bantime) if bantime else 600})
jails.append({"name": "agent-permanent-ban", "bantime": -1})

print(json.dumps({
    "center_url": center_url,
    "token": token,
    "agent_name": agent_name,
    "allowed_jails": jails,
}, ensure_ascii=False, indent=2))
PYEOF
} > "$CONFIG_DIR/config.json"
chown root:"$AGENT_USER" "$CONFIG_DIR/config.json"
chmod 640 "$CONFIG_DIR/config.json"
chown "$AGENT_USER:$AGENT_USER" "$STATE_DIR"
chmod 700 "$STATE_DIR"

echo "==== sudoers (узкое правило только на f2b-agent-helper) ===="
sed "s/CHANGE_ME_AGENT_USER/$AGENT_USER/" "$SCRIPT_DIR/deploy/sudoers-f2b-agent" > /tmp/.f2b-agent-sudoers.new
visudo -cf /tmp/.f2b-agent-sudoers.new
install -o root -g root -m 440 /tmp/.f2b-agent-sudoers.new /etc/sudoers.d/f2b-agent
rm -f /tmp/.f2b-agent-sudoers.new

echo "==== Проверка sudo-доступа и провижининг agent-permanent-ban ===="
if sudo -u "$AGENT_USER" sudo -n /usr/local/sbin/f2b-agent-helper ensure-permanent-jail; then
    echo "OK — sudoers работает, служебный джейл agent-permanent-ban готов."
else
    echo "ОШИБКА: $AGENT_USER не может выполнить f2b-agent-helper через sudo — проверьте sudoers." >&2
    exit 1
fi

echo "==== systemd: timer + service ===="
install -o root -g root -m 644 "$SCRIPT_DIR/deploy/f2b-agent-checkin.service" /etc/systemd/system/
install -o root -g root -m 644 "$SCRIPT_DIR/deploy/f2b-agent-checkin.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now f2b-agent-checkin.timer

if [[ "$SETUP_VPN" -eq 1 ]]; then
    echo "==== VPN (WireGuard) ===="
    if ! command -v wg >/dev/null 2>&1; then
        if command -v dnf >/dev/null 2>&1; then dnf install -y wireguard-tools
        elif command -v yum >/dev/null 2>&1; then yum install -y wireguard-tools
        elif command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y wireguard-tools
        fi
    fi
    WG_DIR="/etc/f2b-agent"
    if [[ ! -f "$WG_DIR/wg_privkey" ]]; then
        umask 077
        wg genkey > "$WG_DIR/wg_privkey"
        wg pubkey < "$WG_DIR/wg_privkey" > "$WG_DIR/wg_pubkey"
        chown "$AGENT_USER:$AGENT_USER" "$WG_DIR/wg_privkey" "$WG_DIR/wg_pubkey"
    fi
    AGENT_PUBKEY="$(cat "$WG_DIR/wg_pubkey")"

    if [[ -z "$VPN_SERVER_PUBKEY" || -z "$VPN_SERVER_ENDPOINT" || -z "$VPN_ASSIGNED_IP" ]]; then
        echo
        echo "Публичный ключ этого агента (внесите на странице агента в веб-панели центра):"
        echo "  $AGENT_PUBKEY"
        echo "Затем повторите установку с флагами --vpn-server-pubkey/--vpn-server-endpoint/--vpn-assigned-ip"
        echo "(центр покажет готовую команду после добавления ключа)."
    else
        SERVER_VPN_IP="${VPN_ASSIGNED_IP%.*}.1"  # .1 в той же /24 — адрес центра (см. vpn.py::init_hub)
        cat > /etc/wireguard/f2b0.conf <<EOF
[Interface]
PrivateKey = $(cat "$WG_DIR/wg_privkey")
Address = ${VPN_ASSIGNED_IP}

[Peer]
PublicKey = ${VPN_SERVER_PUBKEY}
Endpoint = ${VPN_SERVER_ENDPOINT}
AllowedIPs = ${SERVER_VPN_IP}/32
PersistentKeepalive = 25
EOF
        chmod 600 /etc/wireguard/f2b0.conf
        systemctl enable --now "wg-quick@f2b0"
        # Переключаем чекины агента на VPN-адрес центра — исходный CENTER_URL был нужен только
        # для первичной установки (или уже совпадает, если это переустановка).
        python3 - "$CONFIG_DIR/config.json" "$SERVER_VPN_IP" <<'PYEOF'
import json, sys
path, server_ip = sys.argv[1], sys.argv[2]
with open(path) as f:
    cfg = json.load(f)
old = cfg["center_url"]
port = old.rsplit(":", 1)[-1] if old.count(":") >= 2 else "8765"
cfg["center_url"] = f"http://{server_ip}:{port}"
with open(path, "w") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
PYEOF
        echo "VPN поднят, center_url переключён на http://${SERVER_VPN_IP}:<порт> — трафик агента идёт через WireGuard."
    fi
fi

echo
echo "==== Готово ===="
echo "Первый чекин — по таймеру (см. systemctl list-timers f2b-agent-checkin.timer) либо сразу:"
echo "  sudo systemctl start f2b-agent-checkin.service"
echo "Логи: sudo journalctl -u f2b-agent-checkin.service -f"
