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

ensure_noop_filter_content() {
    if [[ ! -f "$NOOP_FILTER_PATH" ]] || [[ "$(cat "$NOOP_FILTER_PATH")" != "$(printf '%s' "$NOOP_FILTER_CONTENT")" ]]; then
        local tmp; tmp=$(mktemp)
        printf '%s' "$NOOP_FILTER_CONTENT" > "$tmp"
        install -o root -g root -m 644 "$tmp" "$NOOP_FILTER_PATH"
        rm -f "$tmp"
    fi
}

# agent-permanent-ban (bantime=-1) + [DEFAULT] ignoreip (постоянный игнор, замещение — не
# патч). Провижинится install-скриптом, здесь — идемпотентно при каждом sync-permanent.
cmd_sync_permanent() {
    local ip line
    local -a ips=()
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        [[ "$ip" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "некорректный IP/CIDR в ignoreip: $ip"
        ips+=("$ip")
    done
    local ignoreip_line="${ips[*]:-}"

    ensure_noop_filter_content

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
    # Как cmd_sync_permanent, но без изменения ignoreip.
    if [[ -f "$PERMANENT_JAIL_PATH" ]]; then
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
cmd_tor_sync() {
    ensure_tor_jail_now
    local line op ip banned=0 unbanned=0
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        op="${line:0:1}"
        ip="${line:1}"
        require_ipv4 "$ip"
        case "$op" in
            +) fail2ban-client set "$TOR_JAIL" banip "$ip" >/dev/null && banned=$((banned + 1)) ;;
            -) fail2ban-client set "$TOR_JAIL" unbanip "$ip" >/dev/null && unbanned=$((unbanned + 1)) ;;
            *) die "некорректная строка (ожидался префикс +/-): $line" ;;
        esac
    done
    echo "banned=$banned unbanned=$unbanned"
}

# Хук быстрого уведомления — чистый runtime (fail2ban-client addaction + action ...
# actionban/actionunban), не переживает restart, поэтому проверяется на каждом чекине.
NOTIFY_ACTION_NAME="f2b-agent-notify"
NOTIFY_BIN="/usr/local/sbin/f2b-agent-notify"

cmd_ensure_notify_action() {
    require_jail "$1"
    local jail="$1"
    # НЕ голый "&": fail2ban убивает всю process group команды после исполнения (killpg),
    # и фон внутри той же группы гибнет раньше, чем notify успевает сходить в сеть
    # (подтверждено на реальном стенде). systemd-run --no-block запускает transient-юнит
    # вне процесс-дерева fail2ban — переживает эту очистку.
    # Имя джейла — буквальной подстановкой, не через тег <name>: такого тега в fail2ban
    # нет (обнаружено на стенде — <ip> подставляется, <name> остаётся литералом и ломает
    # команду). jail уже провалидирован require_jail, экранирование не нужно.
    local expected_ban="systemd-run --quiet --collect --no-block $NOTIFY_BIN ban $jail <ip>"
    local expected_unban="systemd-run --quiet --collect --no-block $NOTIFY_BIN unban $jail <ip>"
    # Сравниваем содержимое actionban, не просто наличие действия — иначе устаревшая
    # команда не обновится без restart fail2ban.
    local current_ban
    current_ban=$(fail2ban-client get "$jail" action "$NOTIFY_ACTION_NAME" actionban 2>/dev/null || true)
    if [[ "$current_ban" == "$expected_ban" ]]; then
        echo "unchanged"
        return 0
    fi
    if ! fail2ban-client get "$jail" actions 2>/dev/null | grep -qw "$NOTIFY_ACTION_NAME"; then
        fail2ban-client set "$jail" addaction "$NOTIFY_ACTION_NAME"
    fi
    fail2ban-client set "$jail" action "$NOTIFY_ACTION_NAME" actionban "$expected_ban"
    fail2ban-client set "$jail" action "$NOTIFY_ACTION_NAME" actionunban "$expected_unban"
    echo "installed"
}

cmd_ping() { fail2ban-client ping; }

# Живой список джейлов этого хоста — "имя bantime" построчно, синтетические
# agent-permanent-ban/agent-tor-block исключены (ими управляет сам центр отдельно).
# Источник правды для автообнаружения на стороне f2b-agent-checkin.py.
cmd_jails() {
    local raw name bt
    raw=$(fail2ban-client status)
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        [[ "$name" == "$PERMANENT_JAIL" || "$name" == "$TOR_JAIL" ]] && continue
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
    sync-permanent)       [[ $# -eq 0 ]] || die "usage: sync-permanent (< ignoreip построчно на stdin)"; cmd_sync_permanent ;;
    ensure-permanent-jail) [[ $# -eq 0 ]] || die "usage: ensure-permanent-jail";      cmd_ensure_permanent_jail ;;
    ensure-notify-action) [[ $# -eq 1 ]] || die "usage: ensure-notify-action <jail>"; cmd_ensure_notify_action "$@" ;;
    tor-sync)             [[ $# -eq 0 ]] || die "usage: tor-sync (< +ip/-ip построчно на stdin)"; cmd_tor_sync ;;
    log-tail)             [[ $# -eq 1 ]] || die "usage: log-tail <offset>";        cmd_log_tail "$@" ;;
    *) die "неизвестная подкоманда: $sub" ;;
esac
