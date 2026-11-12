#!/bin/bash
# Root-обёртка для fail2ban-center-agent: /usr/local/sbin/f2b-agent-helper, chmod 700,
# NOPASSWD только на этот бинарь в sudoers. Каждая подкоманда валидирует свои аргументы
# (IP/джейл) регэкспом — вторая граница защиты поверх f2b-agent-checkin.py.

set -euo pipefail

IPV4_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
JAIL_RE='^[A-Za-z0-9_.-]+$'

PERMANENT_JAIL="agent-permanent-ban"
TOR_JAIL="agent-tor-block"

die() { echo "f2b-agent-helper: $*" >&2; exit 1; }

require_ipv4() {
    [[ "$1" =~ $IPV4_RE ]] || die "некорректный IPv4: $1"
    local IFS=.
    local -a octets=($1)
    for o in "${octets[@]}"; do
        ((o >= 0 && o <= 255)) || die "некорректный IPv4: $1"
    done
}

require_jail() {
    [[ "$1" =~ $JAIL_RE ]] || die "некорректное имя джейла: $1"
}

# Идемпотентная запись jail.d-файла(ов) + reload с ретраями и откатом при неудаче.
# $1 = имя для отчёта, $2.. = пары "путь:содержимое".
write_config_and_reload() {
    local label="$1"; shift
    local -a paths=() contents=() had=() backups=()
    local changed=0

    local pair path content
    for pair in "$@"; do
        path="${pair%%:::*}"
        content="${pair#*:::}"
        paths+=("$path")
        contents+=("$content")
        if [[ -f "$path" ]] && [[ "$(cat "$path")" == "$(printf '%s' "$content")" ]]; then
            had+=(1); backups+=("$(cat "$path")")
        else
            changed=1
            if [[ -f "$path" ]]; then had+=(1); backups+=("$(cat "$path")"); else had+=(0); backups+=(""); fi
        fi
    done

    if [[ $changed -eq 0 ]]; then
        echo "unchanged"
        return 0
    fi

    local i tmp
    for i in "${!paths[@]}"; do
        tmp=$(mktemp)
        printf '%s' "${contents[$i]}" > "$tmp"
        install -o root -g root -m 644 "$tmp" "${paths[$i]}"
        rm -f "$tmp"
    done

    local attempt ok=0
    for attempt in 1 2 3 4 5; do
        if fail2ban-client reload 2>/tmp/.f2b-agent-reload-err; then
            ok=1
            break
        fi
        [[ $attempt -lt 5 ]] && sleep "$attempt"
    done
    if [[ $ok -ne 1 ]]; then
        for i in "${!paths[@]}"; do
            if [[ "${had[$i]}" == 1 ]]; then
                tmp=$(mktemp); printf '%s' "${backups[$i]}" > "$tmp"
                install -o root -g root -m 644 "$tmp" "${paths[$i]}"; rm -f "$tmp"
            else
                rm -f "${paths[$i]}"
            fi
        done
        cat /tmp/.f2b-agent-reload-err >&2
        rm -f /tmp/.f2b-agent-reload-err
        die "fail2ban-client reload не удался после 5 попыток ($label откачен к предыдущему состоянию)"
    fi
    rm -f /tmp/.f2b-agent-reload-err
    echo "installed"
}

NOOP_FILTER_PATH="/etc/fail2ban/filter.d/f2b-agent-noop.conf"
NOOP_FILTER_CONTENT='# Установлено автоматически f2b-agent-helper. No-op фильтр — никогда ничего не
# матчит, нужен только для валидности agent-permanent-ban/agent-tor-block.
[Definition]
failregex =
ignoreregex =
'
PERMANENT_JAIL_PATH="/etc/fail2ban/jail.d/99-f2b-agent-permanent.local"
TOR_JAIL_PATH="/etc/fail2ban/jail.d/99-f2b-agent-tor.local"
# Базовый ignoreip хоста живёт в ОТДЕЛЬНОМ файле, который центр не трогает. 99-файл выше
# ссылается на него переменной (%(f2b_base_ignoreip)s), а не копирует значение — поэтому
# правка базы на хосте переживает любую синхронизацию с центром, а центр шлёт только СВОИ
# адреса. Захватывается один раз (эффективный ignoreip, вместе с дефолтом 127.0.0.1/8 из
# jail.conf), дальше принадлежит администратору хоста.
BASE_IGNOREIP_PATH="/etc/fail2ban/jail.d/00-f2b-agent-base.local"
BASE_IGNOREIP_VAR="f2b_base_ignoreip"

# Адреса из вывода `fail2ban-client get <jail> ignoreip`. Вывод — заголовок плюс строки
# списка с префиксами "|- " и "`- "; берём ТОЛЬКО элементы списка (иначе в базу попал бы
# мусор вроде "ed:" из слова "ignored:"), и только токены, похожие на IP/IPv6/CIDR.
IP_TOKEN_RE='^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:]+)(/[0-9]{1,3})?$'
_extract_ignoreip() {
    local line tok
    while IFS= read -r line; do
        line="${line#*- }"                       # срезаем префикс "|- " / "`- "
        tok="${line%%[[:space:]]*}"              # первый токен строки
        [[ "$tok" =~ $IP_TOKEN_RE ]] && echo "$tok"
    done
}

# Эффективный ignoreip хоста БЕЗ наших добавлений: читаем live-значение любого обычного
# джейла (оно включает дефолт из jail.conf, jail.local и прочие jail.d), затем вычитаем
# адреса, которые добавил центр (переданы аргументами). Нужно только для первичного
# захвата базы, когда файла 00- ещё нет.
_host_base_ignoreip() {
    local base_jail eff
    base_jail=$(fail2ban-client status 2>/dev/null \
        | sed -n 's/^.*Jail list:[[:space:]]*//p' | tr ',' '\n' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | grep -vxF "$PERMANENT_JAIL" | grep -vxF "$TOR_JAIL" | head -n1)
    [[ -n "$base_jail" ]] && eff=$(fail2ban-client get "$base_jail" ignoreip 2>/dev/null | _extract_ignoreip)

    # Без ассоциативных массивов (переносимость на OpenWrt/старый bash): членство проверяем
    # по строке " a b c ". exclude — адреса центра (их в базу не берём).
    local exclude=" $* " result=" "
    local a
    # Loopback в конце списка-кандидатов: держим всегда, иначе при пустом eff fail2ban мог бы
    # забанить 127.0.0.1.
    for a in $eff 127.0.0.0/8 ::1; do
        case "$exclude" in *" $a "*) continue;; esac   # адрес добавил центр — пропускаем
        case "$result" in *" $a "*) continue;; esac     # уже есть — дедуп
        result="$result$a "
    done
    echo "${result# }" | sed 's/[[:space:]]*$//'
}

# Создаёт 00-файл с базой, если его ещё нет. Аргументы — адреса от центра (их исключаем
# из захватываемой базы). Существующий файл не трогаем: база принадлежит хосту.
ensure_base_ignoreip_file() {
    [[ -f "$BASE_IGNOREIP_PATH" ]] && return 0
    local base_line
    base_line=$(_host_base_ignoreip "$@")
    local tmp; tmp=$(mktemp)
    cat > "$tmp" <<EOF
# Базовый ignoreip этого хоста, захваченный при установке агента fail2ban-center.
# Правьте ЗДЕСЬ — центр этот файл не перезаписывает. 99-f2b-agent-permanent.local
# подставляет это значение через %(${BASE_IGNOREIP_VAR})s. НЕ удаляйте файл: без него
# переменная станет неопределённой и fail2ban не загрузит конфиг.
[DEFAULT]
${BASE_IGNOREIP_VAR} = ${base_line}
EOF
    install -o root -g root -m 644 "$tmp" "$BASE_IGNOREIP_PATH"
    rm -f "$tmp"
}

# Значение базы для показа в панели (из 00-файла; fallback — jail.local).
cmd_base_ignoreip() {
    if [[ -f "$BASE_IGNOREIP_PATH" ]]; then
        sed -n "s/^[[:space:]]*${BASE_IGNOREIP_VAR}[[:space:]]*=[[:space:]]*//p" "$BASE_IGNOREIP_PATH" | head -n1
    else
        cmd_jail_local_ignoreip
    fi
}

ensure_noop_filter_content() {
    if [[ ! -f "$NOOP_FILTER_PATH" ]] || [[ "$(cat "$NOOP_FILTER_PATH")" != "$(printf '%s' "$NOOP_FILTER_CONTENT")" ]]; then
        local tmp; tmp=$(mktemp)
        printf '%s' "$NOOP_FILTER_CONTENT" > "$tmp"
        install -o root -g root -m 644 "$tmp" "$NOOP_FILTER_PATH"
        rm -f "$tmp"
    fi
}

# agent-permanent-ban (bantime=-1) + постоянный игнор. ignoreip собирается из базы хоста
# (переменная из 00-файла) и адресов, присланных центром на stdin — центр шлёт ТОЛЬКО свои
# адреса, базу не копирует. Идемпотентно при каждом sync-permanent.
cmd_sync_permanent() {
    local ip
    local -a ips=()
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        [[ "$ip" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "некорректный IP/CIDR в ignoreip: $ip"
        ips+=("$ip")
    done

    ensure_noop_filter_content
    ensure_base_ignoreip_file "${ips[@]}"

    # %(f2b_base_ignoreip)s — база хоста из 00-файла (fail2ban интерполирует переменные
    # внутри [DEFAULT]); дальше — адреса центра. Строка ignoreip есть всегда, поэтому даже
    # без адресов центра база сохраняется (и 127.0.0.1/8 из неё не теряется).
    local ignoreip_line="%(${BASE_IGNOREIP_VAR})s${ips[*]:+ ${ips[*]}}"

    local jail_content
    jail_content=$(cat <<EOF
# Установлено автоматически f2b-agent-helper.
[DEFAULT]
ignoreip = ${ignoreip_line}

[${PERMANENT_JAIL}]
enabled = true
bantime = -1
filter = f2b-agent-noop
logpath = /dev/null
maxretry = 999999
EOF
)
    write_config_and_reload "постоянный игнор/${PERMANENT_JAIL}" "${PERMANENT_JAIL_PATH}:::${jail_content}"
}

cmd_ensure_permanent_jail() {
    # Провижининг джейла + захват базы хоста (на установке, пока наших файлов ещё нет,
    # база = чистый эффективный ignoreip). ignoreip не меняет сверх базы.
    if [[ -f "$PERMANENT_JAIL_PATH" && -f "$BASE_IGNOREIP_PATH" ]]; then
        echo "unchanged"
        return 0
    fi
    printf '' | cmd_sync_permanent
}

ensure_tor_jail_now() {
    ensure_noop_filter_content
    local tor_content
    tor_content=$(cat <<EOF
# Установлено автоматически f2b-agent-helper.
[${TOR_JAIL}]
enabled = true
bantime = -1
filter = f2b-agent-noop
logpath = /dev/null
maxretry = 999999
EOF
)
    write_config_and_reload "$TOR_JAIL" "${TOR_JAIL_PATH}:::${tor_content}" >/dev/null
}

# Идемпотентно создаёт джейл (если ещё нет) и применяет diff — одна задача tor_sync = один вызов.
# Списки в тысячи адресов: один вызов fail2ban-client на пачку, иначе таймаут агента.
TOR_BATCH=200

tor_apply() {
    local action="$1"; shift
    local -a ips=("$@")
    local i
    for ((i = 0; i < ${#ips[@]}; i += TOR_BATCH)); do
        fail2ban-client set "$TOR_JAIL" "$action" "${ips[@]:i:TOR_BATCH}" >/dev/null || return 1
    done
}

cmd_tor_sync() {
    ensure_tor_jail_now
    local line op ip
    local -a to_ban=() to_unban=()
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        op="${line:0:1}"
        ip="${line:1}"
        require_ipv4 "$ip"
        case "$op" in
            +) to_ban+=("$ip") ;;
            -) to_unban+=("$ip") ;;
            *) die "некорректная строка (ожидался префикс +/-): $line" ;;
        esac
    done
    # Ошибка должна дойти до центра, иначе он запишет адреса как применённые.
    tor_apply banip "${to_ban[@]}" || die "не удалось применить бан пачкой"
    tor_apply unbanip "${to_unban[@]}" || die "не удалось снять бан пачкой"
    echo "banned=${#to_ban[@]} unbanned=${#to_unban[@]}"
}

# Хук быстрого уведомления — чистый runtime (fail2ban-client addaction + action ...
# actionban/actionunban), не переживает restart, поэтому проверяется на каждом чекине.
NOTIFY_ACTION_NAME="f2b-agent-notify"
NOTIFY_BIN="/usr/local/sbin/f2b-agent-notify"
NOTIFY_SPOOL="/run/fail2ban/f2b-agent.events"

# Есть ли такой джейл сейчас в fail2ban. Обращение к несуществующему джейлу (например,
# agent-tor-block до первой синхронизации Tor) fail2ban пишет в свой лог как ERROR — раз в
# минуту на каждом чекине, поэтому сначала проверяем список.
jail_exists() {
    fail2ban-client status 2>/dev/null | sed -n 's/^.*Jail list:[[:space:]]*//p' | tr ',' '\n' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -qxF "$1"
}

cmd_ensure_notify_action() {
    require_jail "$1"
    local jail="$1"
    if ! jail_exists "$jail"; then
        echo "absent"
        return 0
    fi
    local has_action=0
    fail2ban-client get "$jail" actions 2>/dev/null | grep -qw "$NOTIFY_ACTION_NAME" && has_action=1
    # Баны agent-tor-block ставит сам центр (tor_sync) и знает о них из результата задачи;
    # уведомление на каждый из тысяч адресов ничего не добавляет.
    if [[ "$jail" == "$TOR_JAIL" ]]; then
        if [[ $has_action -eq 1 ]]; then
            fail2ban-client set "$jail" delaction "$NOTIFY_ACTION_NAME" >/dev/null
            echo "removed"
        else
            echo "skipped"
        fi
        return 0
    fi
    # Имя джейла — буквальной подстановкой, не через тег <name>: такого тега в fail2ban
    # нет (<ip> подставляется, <name> остаётся литералом). jail провалидирован require_jail.
    local expected_ban expected_unban
    if [[ -d /run/systemd/system ]]; then
        # fail2ban только дописывает строку в свой каталог /run/fail2ban, а отправляет её
        # f2b-agent-notify.service по сигналу f2b-agent-notify.path. Напрямую из fail2ban
        # нельзя: под SELinux (РЕД ОС, RHEL) домену fail2ban_t запрещены и systemd-run
        # ("Access denied", tclass=system), и исходящее TCP-соединение к центру (name_connect).
        expected_ban="echo 'ban $jail <ip>' >> $NOTIFY_SPOOL"
        expected_unban="echo 'unban $jail <ip>' >> $NOTIFY_SPOOL"
    else
        # Без systemd (OpenWrt) — отдельная сессия: fail2ban после команды убивает её process
        # group (killpg), голый "&" погиб бы раньше, чем notify сходит в сеть.
        expected_ban="setsid $NOTIFY_BIN ban $jail <ip> >/dev/null 2>&1 &"
        expected_unban="setsid $NOTIFY_BIN unban $jail <ip> >/dev/null 2>&1 &"
    fi
    # Без actionflush fail2ban при остановке/перезапуске джейла вызывает actionunban на
    # КАЖДЫЙ бан — центр получал сотни «разбанов» и снимал общий блок-лист на всех серверах.
    # Непустой actionflush выполняется вместо них (fail2ban actions.py, __flushBan).
    local expected_flush="true"
    # Сравниваем содержимое команд, не просто наличие действия — иначе устаревшая
    # команда не обновится без restart fail2ban.
    local current_ban current_flush
    if [[ $has_action -eq 1 ]]; then
        current_ban=$(fail2ban-client get "$jail" action "$NOTIFY_ACTION_NAME" actionban 2>/dev/null || true)
        current_flush=$(fail2ban-client get "$jail" action "$NOTIFY_ACTION_NAME" actionflush 2>/dev/null || true)
        if [[ "$current_ban" == "$expected_ban" && "$current_flush" == "$expected_flush" ]]; then
            echo "unchanged"
            return 0
        fi
    else
        fail2ban-client set "$jail" addaction "$NOTIFY_ACTION_NAME" >/dev/null
    fi
    fail2ban-client set "$jail" action "$NOTIFY_ACTION_NAME" actionban "$expected_ban" >/dev/null
    fail2ban-client set "$jail" action "$NOTIFY_ACTION_NAME" actionunban "$expected_unban" >/dev/null
    fail2ban-client set "$jail" action "$NOTIFY_ACTION_NAME" actionflush "$expected_flush" >/dev/null
    echo "installed"
}

cmd_ping() { fail2ban-client ping; }

# Живой список джейлов этого хоста — "имя bantime" построчно, включая служебные
# agent-permanent-ban/agent-tor-block (центру их агент не сообщает — см. discover_jails()).
# Источник правды для автообнаружения на стороне f2b-agent-checkin.py.
cmd_jails() {
    local raw name bt
    raw=$(fail2ban-client status)
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        [[ "$name" =~ $JAIL_RE ]] || continue
        bt=$(fail2ban-client get "$name" bantime 2>/dev/null)
        [[ "$bt" =~ ^-?[0-9]+$ ]] || bt=600
        echo "$name $bt"
    done < <(printf '%s\n' "$raw" | sed -n 's/^.*Jail list:[[:space:]]*//p' | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
}

cmd_jail_bans() {
    require_jail "$1"
    fail2ban-client get "$1" banip --with-time
}

cmd_jail_ban() {
    require_jail "$1"
    require_ipv4 "$2"
    if [[ "$1" == "$PERMANENT_JAIL" ]] && ! fail2ban-client status "$PERMANENT_JAIL" >/dev/null 2>&1; then
        cmd_ensure_permanent_jail >/dev/null
    fi
    if [[ "$1" == "$TOR_JAIL" ]] && ! fail2ban-client status "$TOR_JAIL" >/dev/null 2>&1; then
        ensure_tor_jail_now
    fi
    fail2ban-client set "$1" banip "$2"
}

cmd_jail_unban() {
    require_jail "$1"
    require_ipv4 "$2"
    fail2ban-client set "$1" unbanip "$2"
}

cmd_jail_addignoreip() {
    require_jail "$1"
    require_ipv4 "$2"
    fail2ban-client set "$1" addignoreip "$2"
}

cmd_jail_delignoreip() {
    require_jail "$1"
    require_ipv4 "$2"
    fail2ban-client set "$1" delignoreip "$2"
}

# [DEFAULT] ignoreip из jail.local, не живой через fail2ban-client (тот уже включает наш
# оверрайд — читали бы самих себя). Предполагает однострочный ignoreip.
cmd_jail_local_ignoreip() {
    [[ -f /etc/fail2ban/jail.local ]] || return 0
    awk '
        /^\[/ { insec = ($0 == "[DEFAULT]") }
        insec && /^ignoreip[ \t]*=/ { sub(/^ignoreip[ \t]*=[ \t]*/, ""); print }
    ' /etc/fail2ban/jail.local
}

# Инкрементальный хвост лога fail2ban — только новые байты с прошлой позиции, не весь файл
# каждый раз. Путь берётся динамически (fail2ban-client get logtarget).
cmd_log_tail() {
    local last_offset="$1"
    [[ "$last_offset" =~ ^[0-9]+$ ]] || die "некорректный offset: $last_offset"
    local raw target size
    raw=$(fail2ban-client get logtarget 2>/dev/null || true)
    target=$(echo "$raw" | sed -n 's/^[`|]-\s*//p' | tail -n1)
    if [[ -z "$target" || "$target" == "STDOUT" || "$target" == "STDERR" || ! -r "$target" ]]; then
        printf 'PATH:\nSIZE:0\n---\n'
        return 0
    fi
    size=$(stat -c%s -- "$target" 2>/dev/null || echo 0)
    [[ "$last_offset" -gt "$size" ]] && last_offset=0  # ротация/усечение файла
    printf 'PATH:%s\nSIZE:%s\n---\n' "$target" "$size"
    tail -c "+$((last_offset + 1))" -- "$target"
}

[[ $# -ge 1 ]] || die "нужна подкоманда"
sub="$1"; shift || true

case "$sub" in
    ping)                 [[ $# -eq 0 ]] || die "usage: ping";                        cmd_ping ;;
    jails)                [[ $# -eq 0 ]] || die "usage: jails";                       cmd_jails ;;
    jail-bans)            [[ $# -eq 1 ]] || die "usage: jail-bans <jail>";            cmd_jail_bans "$@" ;;
    jail-ban)             [[ $# -eq 2 ]] || die "usage: jail-ban <jail> <ip>";        cmd_jail_ban "$@" ;;
    jail-unban)           [[ $# -eq 2 ]] || die "usage: jail-unban <jail> <ip>";      cmd_jail_unban "$@" ;;
    jail-addignoreip)     [[ $# -eq 2 ]] || die "usage: jail-addignoreip <jail> <ip>"; cmd_jail_addignoreip "$@" ;;
    jail-delignoreip)     [[ $# -eq 2 ]] || die "usage: jail-delignoreip <jail> <ip>"; cmd_jail_delignoreip "$@" ;;
    jail-local-ignoreip)  [[ $# -eq 0 ]] || die "usage: jail-local-ignoreip";         cmd_jail_local_ignoreip ;;
    base-ignoreip)        [[ $# -eq 0 ]] || die "usage: base-ignoreip";                cmd_base_ignoreip ;;
    sync-permanent)       [[ $# -eq 0 ]] || die "usage: sync-permanent (< ignoreip построчно на stdin)"; cmd_sync_permanent ;;
    ensure-permanent-jail) [[ $# -eq 0 ]] || die "usage: ensure-permanent-jail";      cmd_ensure_permanent_jail ;;
    ensure-notify-action) [[ $# -eq 1 ]] || die "usage: ensure-notify-action <jail>"; cmd_ensure_notify_action "$@" ;;
    tor-sync)             [[ $# -eq 0 ]] || die "usage: tor-sync (< +ip/-ip построчно на stdin)"; cmd_tor_sync ;;
    log-tail)             [[ $# -eq 1 ]] || die "usage: log-tail <offset>";        cmd_log_tail "$@" ;;
    *) die "неизвестная подкоманда: $sub" ;;
esac
