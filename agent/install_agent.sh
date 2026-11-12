#!/bin/bash
# Установка агента fail2ban-center на управляемый хост. Требует root (sudo). fail2ban должен
# уже быть установлен и запущен — этот скрипт его не ставит.
#
# Использование:
#   sudo ./install_agent.sh --center-url https://10.0.5.10:8766 --token <TOKEN> \
#       --agent-name srv-42 --center-ca-sha256 <ОТПЕЧАТОК> [--jail sshd:600 ...]
#   sudo ./install_agent.sh --update     # только новая версия файлов агента
#   sudo ./install_agent.sh --update --center-url https://... --center-ca-sha256 <ОТПЕЧАТОК>
#                                        # перевод уже установленного агента на HTTPS
#
# На хостах без systemd (OpenWrt и т.п.) агент работает от root по cron: без отдельного
# пользователя и sudo. VPN (--setup-vpn) там не поддерживается.
#
# --center-url/--token/--agent-name — берутся из вывода "Добавить агента" в веб-интерфейсе
# центра (или manage.py add-agent). --jail — не обязателен, джейлы центр находит сам (см.
# README) — используйте, только если для конкретного джейла нужен другой bantime, чем
# реально настроен на хосте.
#
# Связь с центром — только HTTPS. Центр сам выпускает сертификат от собственного CA, агент
# доверяет только этому CA (/etc/f2b-agent/center-ca.crt), а не системному хранилищу:
#   --center-ca-sha256 <ОТПЕЧАТОК> — скачать ca.crt с центра и принять его, только если
#       совпал SHA-256 отпечаток (показан в панели «Управление агентами» и в выводе
#       deploy/install.sh; на центре: manage.py ca-fingerprint);
#   --center-ca-cert <файл> — тот же ca.crt, скопированный с центра заранее.
# Без обоих флагов в интерактивном запуске скрипт покажет отпечаток скачанного CA и
# попросит сверить его с панелью.
#
# Если --center-url/--token/--agent-name не переданы флагами и запуск интерактивный (не из
# автоматизации) — спросит их сам, включая выбор между прямым URL и подключением через
# отдельную VPN-сеть (--setup-vpn).

set -euo pipefail

CENTER_URL=""
TOKEN=""
AGENT_NAME=""
JAILS=()
SETUP_VPN=0
VPN_SERVER_PUBKEY=""
VPN_SERVER_ENDPOINT=""
VPN_ASSIGNED_IP=""
CENTER_CA_CERT=""
CENTER_CA_SHA256=""
UPDATE=0

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
        --center-ca-cert) CENTER_CA_CERT="$2"; shift 2 ;;
        --center-ca-sha256) CENTER_CA_SHA256="$2"; shift 2 ;;
        --update) UPDATE=1; shift ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "запустите через sudo/от root" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/f2b-agent"
CONFIG_DIR="/etc/f2b-agent"
STATE_DIR="/var/lib/f2b-agent"
CA_DEST="$CONFIG_DIR/center-ca.crt"

HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    HAS_SYSTEMD=1
    AGENT_USER="f2b-agent"
else
    AGENT_USER="root"
fi

install_agent_files() {
    install -o root -g root -m 644 "$SCRIPT_DIR/f2b-agent-checkin.py" "$INSTALL_DIR/f2b-agent-checkin.py"
    install -o root -g root -m 700 "$SCRIPT_DIR/f2b-agent-helper.sh" /usr/local/sbin/f2b-agent-helper
    install -o root -g root -m 700 "$SCRIPT_DIR/f2b-agent-notify.py" /usr/local/sbin/f2b-agent-notify
    if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
        # Быстрый канал уведомлений: fail2ban пишет событие в файл, .path сразу отправляет его.
        install -o root -g root -m 644 "$SCRIPT_DIR/deploy/f2b-agent-notify.path" /etc/systemd/system/
        install -o root -g root -m 644 "$SCRIPT_DIR/deploy/f2b-agent-notify.service" /etc/systemd/system/
        systemctl daemon-reload
        # reset-failed: path-юнит старой версии мог остаться в failed (unit-start-limit-hit).
        systemctl reset-failed f2b-agent-notify.path f2b-agent-notify.service >/dev/null 2>&1 || true
        systemctl enable f2b-agent-notify.path >/dev/null 2>&1
        systemctl restart f2b-agent-notify.path
    fi
}

agent_helper() {
    if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
        sudo -u "$AGENT_USER" sudo -n /usr/local/sbin/f2b-agent-helper "$@"
    else
        /usr/local/sbin/f2b-agent-helper "$@"
    fi
}

require_https_url() {
    [[ "${1,,}" == https://* ]] || {
        echo "адрес центра должен начинаться с https:// (получено: $1) — агент передаёт токен" >&2
        echo "только по зашифрованному каналу" >&2
        exit 1
    }
}

# Скачивает ca.crt с центра. TLS здесь ещё не проверить (доверять пока нечему), поэтому
# сертификат принимается, только если его SHA-256 отпечаток совпал с ожидаемым.
# Печатает фактический отпечаток; код 3 — не совпал.
fetch_center_ca() {
    python3 - "$1" "$2" "$3" <<'PYEOF'
import hashlib, ssl, sys, urllib.request
url, expected, out = sys.argv[1:4]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    pem = urllib.request.urlopen(url.rstrip("/") + "/api/v1/ca.crt", timeout=15, context=ctx).read().decode("ascii")
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
except Exception as e:
    print(f"не удалось скачать CA центра с {url}: {e}", file=sys.stderr)
    sys.exit(2)
print(":".join(digest[i:i + 2] for i in range(0, len(digest), 2)))
if expected and expected.replace(":", "").replace(" ", "").upper() != digest:
    sys.exit(3)
with open(out, "w") as f:
    f.write(pem)
PYEOF
}

# Кладёт доверенный CA центра в $CA_DEST (из файла, по отпечатку или с подтверждением).
install_center_ca() {
    local url="$1" tmp fp rc ans
    tmp=$(mktemp)
    if [[ -n "$CENTER_CA_CERT" ]]; then
        [[ -f "$CENTER_CA_CERT" ]] || { echo "--center-ca-cert: файл не найден: $CENTER_CA_CERT" >&2; exit 1; }
        cp "$CENTER_CA_CERT" "$tmp"
    elif [[ -n "$CENTER_CA_SHA256" ]]; then
        rc=0; fp=$(fetch_center_ca "$url" "$CENTER_CA_SHA256" "$tmp") || rc=$?
        if [[ $rc -eq 3 ]]; then
            echo "ОШИБКА: отпечаток CA центра не совпал — возможна подмена, установка прервана." >&2
            echo "  ожидался: $CENTER_CA_SHA256" >&2
            echo "  получен:  $fp" >&2
            rm -f "$tmp"; exit 1
        fi
        [[ $rc -eq 0 ]] || { rm -f "$tmp"; exit 1; }
    elif [[ -t 0 ]]; then
        rc=0; fp=$(fetch_center_ca "$url" "" "$tmp") || rc=$?
        [[ $rc -eq 0 ]] || { rm -f "$tmp"; exit 1; }
        echo "Отпечаток CA, полученного с центра (SHA-256):"
        echo "  $fp"
        read -rp "Совпадает с отпечатком в панели центра («Управление агентами»)? [y/N]: " ans
        [[ "$ans" =~ ^[Yy]$ ]] || { echo "установка прервана" >&2; rm -f "$tmp"; exit 1; }
    else
        rm -f "$tmp"
        echo "нужен --center-ca-sha256 <отпечаток> или --center-ca-cert <файл> (CA центра)" >&2
        exit 1
    fi
    install -o root -g root -m 644 "$tmp" "$CA_DEST"
    rm -f "$tmp"
    echo "OK — CA центра сохранён в $CA_DEST."
}

# Реальный TLS-хендшейк с проверкой сертификата — ловит адрес, которого нет в SAN
# сертификата центра, сразу при установке, а не на первом чекине.
check_center_tls() {
    python3 - "$1" "$CA_DEST" <<'PYEOF'
import ssl, sys, urllib.request
url, cafile = sys.argv[1:3]
try:
    ctx = ssl.create_default_context(cafile=cafile)
    urllib.request.urlopen(url.rstrip("/") + "/api/v1/ca.crt", timeout=15, context=ctx).read()
except Exception as e:
    print(f"ОШИБКА: HTTPS-соединение с {url} не прошло проверку: {e}", file=sys.stderr)
    if "mismatch" in str(e) or "doesn't match" in str(e):
        print("Адреса из --center-url нет в сертификате центра — добавьте его на центре:", file=sys.stderr)
        print("  sudo deploy/install.sh configure", file=sys.stderr)
    elif "CERTIFICATE_VERIFY_FAILED" in str(e):
        print("Сертификат выдан не CA центра. Если CA скачан верно, соединение перехватывает", file=sys.stderr)
        print("что-то на пути (антивирус с проверкой HTTPS, прокси) — исключите из перехвата", file=sys.stderr)
        print("соединения python3 к адресу центра. Проверить, кто выдал сертификат:", file=sys.stderr)
        print(f"  echo | openssl s_client -connect <адрес>:<порт> 2>/dev/null | grep issuer=", file=sys.stderr)
    sys.exit(1)
print(f"OK — HTTPS до {url} работает, сертификат центра проверен.")
PYEOF
}

# Обновляет поля config.json агента (center_url и/или ca_cert), остальное не трогает.
update_config() {
    python3 - "$CONFIG_DIR/config.json" "$@" <<'PYEOF'
import json, sys
path, pairs = sys.argv[1], sys.argv[2:]
with open(path) as f:
    cfg = json.load(f)
for pair in pairs:
    key, _, value = pair.partition("=")
    cfg[key] = value
with open(path, "w") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
PYEOF
}

config_center_url() {
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["center_url"])' "$CONFIG_DIR/config.json"
}

if [[ "$UPDATE" -eq 1 ]]; then
    [[ -d "$INSTALL_DIR" ]] || { echo "агент не установлен: $INSTALL_DIR не найден" >&2; exit 1; }
    install_agent_files
    echo "Файлы агента обновлены, новая версия подхватится на следующем чекине."
    if [[ -n "$CENTER_URL" ]]; then
        require_https_url "$CENTER_URL"
        update_config "center_url=$CENTER_URL"
    fi
    url=$(config_center_url)
    if [[ "${url,,}" != https://* ]]; then
        echo >&2
        echo "ВНИМАНИЕ: в $CONFIG_DIR/config.json адрес центра $url — без HTTPS агент работать" >&2
        echo "не будет. Повторите с --center-url https://<адрес>:<порт> --center-ca-sha256 <отпечаток>." >&2
        exit 1
    fi
    if [[ -n "$CENTER_CA_CERT" || -n "$CENTER_CA_SHA256" ]]; then
        install_center_ca "$url"
        update_config "ca_cert=$CA_DEST"
    fi
    if [[ -f "$CA_DEST" ]]; then
        check_center_tls "$url"
    fi
    exit 0
fi

if [[ "$SETUP_VPN" -eq 1 && "$HAS_SYSTEMD" -eq 0 ]]; then
    echo "--setup-vpn требует systemd (wg-quick@): поднимите WireGuard средствами системы" >&2
    exit 1
fi

# Если центр/токен/имя не заданы флагами и это интерактивный запуск (не CI/скрипт) —
# спрашиваем, а не просто падаем с ошибкой. При обычном флаговом вызове (stdin не tty,
# например из автоматизации) поведение не меняется — сразу проверка ниже и выход с ошибкой.
if [[ ( -z "$CENTER_URL" || -z "$TOKEN" || -z "$AGENT_NAME" ) && -t 0 ]]; then
    echo "==== Подключение к центру ===="
    if [[ -z "$CENTER_URL" ]]; then
        echo "Как агент будет соединяться с центром?"
        echo "1) Напрямую по URL — центр виден с этого хоста уже сейчас (обычная сеть/HTTPS)"
        echo "2) Через выделенную VPN-сеть (WireGuard) — если центр не виден напрямую"
        echo "   (агент за NAT, разные сети и т.п.)"
        read -rp "Выбор [1]: " CONN_CHOICE
        if [[ "${CONN_CHOICE:-1}" == "2" ]]; then
            SETUP_VPN=1
            echo "Даже для VPN нужен URL, по которому центр доступен ПРЯМО СЕЙЧАС — он нужен для"
            echo "самого первого чекина и получения данных VPN; после настройки VPN адрес"
            echo "переключится на внутренний сам."
        fi
        read -rp "URL центра (например, https://10.0.5.10:8766): " CENTER_URL
    fi
    [[ -n "$TOKEN" ]] || read -rp "Токен агента (получен при регистрации в панели/manage.py add-agent): " TOKEN
    [[ -n "$AGENT_NAME" ]] || read -rp "Имя агента (= agent_id в протоколе): " AGENT_NAME
fi

[[ -n "$CENTER_URL" && -n "$TOKEN" && -n "$AGENT_NAME" ]] || {
    echo "нужны --center-url, --token и --agent-name (см. -h/шапку скрипта)" >&2
    exit 1
}
require_https_url "$CENTER_URL"

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
    elif command -v apk >/dev/null 2>&1; then apk add python3
    elif command -v opkg >/dev/null 2>&1; then opkg update && opkg install python3
    else echo "не удалось определить пакетный менеджер — установите python3 вручную" >&2; exit 1
    fi
fi

# Путь nologin-шелла отличается между дистрибутивами.
NOLOGIN_SHELL="/usr/sbin/nologin"
[[ -x "$NOLOGIN_SHELL" ]] || NOLOGIN_SHELL="/sbin/nologin"
[[ -x "$NOLOGIN_SHELL" ]] || NOLOGIN_SHELL="/bin/false"

if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
    echo "==== Системный пользователь $AGENT_USER ===="
    id "$AGENT_USER" >/dev/null 2>&1 || useradd -r -s "$NOLOGIN_SHELL" -d "$STATE_DIR" "$AGENT_USER"
fi

echo "==== Каталоги ===="
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" /usr/local/sbin

echo "==== Доверенный CA центра (HTTPS) ===="
install_center_ca "$CENTER_URL"
check_center_tls "$CENTER_URL"

echo "==== Файлы агента ===="
install_agent_files

echo "==== Автообнаружение джейлов текущего fail2ban ===="
# То же самое, что f2b-agent-checkin.py делает на каждом чекине (см. discover_jails()) —
# запускаем и здесь тоже, чтобы config.json сразу отражал реальные джейлы хоста, а не
# ждал первого успешного чекина. Мы уже root — helper вызываем напрямую, без sudo.
DISCOVERED_JAILS=()
if /usr/local/sbin/f2b-agent-helper jails >/tmp/.f2b-agent-jails.$$ 2>/dev/null; then
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        DISCOVERED_JAILS+=("${line// /:}")
    done < /tmp/.f2b-agent-jails.$$
    echo "найдено: ${DISCOVERED_JAILS[*]:-(нет)}"
else
    echo "автообнаружение не удалось (fail2ban не отвечает?) — довыполнится на первом чекине."
fi
rm -f /tmp/.f2b-agent-jails.$$

echo "==== Конфигурация ($CONFIG_DIR/config.json) ===="
{
    python3 - "$CENTER_URL" "$TOKEN" "$AGENT_NAME" "$CA_DEST" "${JAILS[@]:-}" -- "${DISCOVERED_JAILS[@]:-}" <<'PYEOF'
import json
import sys

center_url, token, agent_name, ca_cert = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
rest = sys.argv[5:]
sep = rest.index("--")
explicit, discovered = rest[:sep], rest[sep + 1:]

seen = set()
jails = []
# --jail с командной строки имеет приоритет над тем, что само нашлось на хосте —
# позволяет сознательно переопределить bantime для конкретного джейла.
for spec in explicit + discovered:
    if not spec:
        continue
    name, _, bantime = spec.partition(":")
    if name in seen:
        continue
    seen.add(name)
    jails.append({"name": name, "bantime": int(bantime) if bantime else 600})
if "agent-permanent-ban" not in seen:
    jails.append({"name": "agent-permanent-ban", "bantime": -1})

print(json.dumps({
    "center_url": center_url,
    "token": token,
    "agent_name": agent_name,
    "ca_cert": ca_cert,
    "allowed_jails": jails,
}, ensure_ascii=False, indent=2))
PYEOF
} > "$CONFIG_DIR/config.json"
chown root:"$AGENT_USER" "$CONFIG_DIR/config.json"
chmod 640 "$CONFIG_DIR/config.json"
chown "$AGENT_USER:$AGENT_USER" "$STATE_DIR"
chmod 700 "$STATE_DIR"

if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
    echo "==== sudoers (узкое правило только на f2b-agent-helper) ===="
    sed "s/CHANGE_ME_AGENT_USER/$AGENT_USER/" "$SCRIPT_DIR/deploy/sudoers-f2b-agent" > /tmp/.f2b-agent-sudoers.new
    visudo -cf /tmp/.f2b-agent-sudoers.new
    install -o root -g root -m 440 /tmp/.f2b-agent-sudoers.new /etc/sudoers.d/f2b-agent
    rm -f /tmp/.f2b-agent-sudoers.new
fi

echo "==== Провижининг agent-permanent-ban и захват базового ignoreip хоста ===="
# ensure-permanent-jail создаёт служебный джейл и один раз сохраняет текущий эффективный
# ignoreip хоста (вместе с дефолтом 127.0.0.1/8 из jail.conf) в 00-f2b-agent-base.local.
# Этот файл дальше принадлежит хосту: центр его не трогает, а 99-файл ссылается на него
# переменной — поэтому база не теряется и не затирается синхронизацией с центром.
if agent_helper ensure-permanent-jail; then
    echo "OK — helper работает, служебный джейл готов, база сохранена: $(agent_helper base-ignoreip)"
else
    echo "ОШИБКА: $AGENT_USER не может выполнить f2b-agent-helper — проверьте sudoers и fail2ban" >&2
    exit 1
fi

if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
    echo "==== systemd: timer + service ===="
    install -o root -g root -m 644 "$SCRIPT_DIR/deploy/f2b-agent-checkin.service" /etc/systemd/system/
    install -o root -g root -m 644 "$SCRIPT_DIR/deploy/f2b-agent-checkin.timer" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now f2b-agent-checkin.timer
else
    echo "==== cron: чекин раз в минуту ===="
    CHECKIN_CMD="python3 $INSTALL_DIR/f2b-agent-checkin.py 2>&1 | logger -t f2b-agent"
    command -v flock >/dev/null 2>&1 && CHECKIN_CMD="flock -n /tmp/f2b-agent.lock $CHECKIN_CMD"
    if [[ -d /etc/crontabs ]]; then
        touch /etc/crontabs/root
        { grep -v 'f2b-agent-checkin.py' /etc/crontabs/root || true; echo "* * * * * $CHECKIN_CMD"; } > /tmp/.f2b-agent-cron.new
        install -m 600 /tmp/.f2b-agent-cron.new /etc/crontabs/root
        rm -f /tmp/.f2b-agent-cron.new
    elif [[ -d /etc/cron.d ]]; then
        echo "* * * * * root $CHECKIN_CMD" > /etc/cron.d/f2b-agent
        chmod 644 /etc/cron.d/f2b-agent
    else
        echo "не нашёл ни /etc/crontabs, ни /etc/cron.d — добавьте вручную: * * * * * $CHECKIN_CMD" >&2
        exit 1
    fi
    [[ -x /etc/init.d/cron ]] && /etc/init.d/cron restart || true
    # OpenWrt: без этого файлы агента не переживут обновление прошивки.
    if [[ -f /etc/sysupgrade.conf ]]; then
        for p in "$INSTALL_DIR" "$CONFIG_DIR" /usr/local/sbin/f2b-agent-helper /usr/local/sbin/f2b-agent-notify; do
            grep -qxF "$p" /etc/sysupgrade.conf || echo "$p" >> /etc/sysupgrade.conf
        done
    fi
fi

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
port = old.rstrip("/").rsplit(":", 1)[-1] if old.count(":") >= 2 else "443"
# Внутри туннеля — тоже HTTPS: VPN-адрес центра входит в его сертификат (install.sh).
cfg["center_url"] = f"https://{server_ip}:{port}"
with open(path, "w") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
PYEOF
        echo "VPN поднят, center_url переключён на https://${SERVER_VPN_IP}:<порт> — HTTPS внутри WireGuard."
    fi
fi

echo
echo "==== Готово ===="
if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
    echo "Первый чекин — по таймеру (см. systemctl list-timers f2b-agent-checkin.timer) либо сразу:"
    echo "  sudo systemctl start f2b-agent-checkin.service"
    echo "Логи: sudo journalctl -u f2b-agent-checkin.service -f"
else
    echo "Первый чекин — по cron в течение минуты либо сразу: python3 $INSTALL_DIR/f2b-agent-checkin.py"
    echo "Логи: logread | grep f2b-agent (OpenWrt) или системный журнал"
fi
