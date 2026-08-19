#!/bin/bash
# Root-обёртка для WireGuard-операций центра. /usr/local/sbin/f2b-center-vpn-helper,
# chmod 700, NOPASSWD только на этот бинарь для пользователя сервиса центра (см.
# deploy/sudoers-f2b-center-vpn) — сам процесс центра непривилегирован.
set -euo pipefail

IFACE="f2b0"
CONF_PATH="/etc/wireguard/${IFACE}.conf"

die() { echo "f2b-center-vpn-helper: $*" >&2; exit 1; }

cmd_write_and_sync() {
    local tmp
    tmp=$(mktemp)
    cat > "$tmp"
    install -o root -g root -m 600 "$tmp" "$CONF_PATH"
    rm -f "$tmp"
    if ip link show "$IFACE" >/dev/null 2>&1; then
        wg-quick strip "$CONF_PATH" | wg syncconf "$IFACE" /dev/stdin
    fi
}

cmd_up() {
    ip link show "$IFACE" >/dev/null 2>&1 || wg-quick up "$IFACE"
    systemctl enable "wg-quick@${IFACE}" >/dev/null 2>&1 || true
}

[[ $# -eq 1 ]] || die "нужна ровно одна подкоманда"
case "$1" in
    write-and-sync) cmd_write_and_sync ;;
    up)             cmd_up ;;
    *) die "неизвестная подкоманда: $1" ;;
esac
