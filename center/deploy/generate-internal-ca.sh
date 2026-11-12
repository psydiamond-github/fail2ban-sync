#!/bin/bash
# Собственный CA + серверный сертификат fail2ban-center. Вызывается из deploy/install.sh
# (install/configure) — вручную запускать не нужно. Центр сам завершает TLS (gunicorn
# --certfile/--keyfile), агенты доверяют только этому CA (install_agent.sh --center-ca-sha256).
# Если ca.key/ca.crt уже есть, CA переиспользуется: перевыпуск сертификата сервера (например,
# после смены интерфейсов) не требует ничего менять на агентах.
#
# Использование:
#   ./generate-internal-ca.sh --out-dir /etc/fail2ban-center/tls \
#       --ip 10.0.5.10 --ip 192.168.1.10 [--dns center.internal] [--days 825] [--ca-days 3650]
#
# Нужен хотя бы один --ip или --dns — это SAN сертификата. Агенты и браузер сверяют адрес из
# URL именно с SAN, поэтому сюда входят все адреса, по которым к центру обращаются.
set -euo pipefail

OUT_DIR=""
IPS=()
DNS_NAMES=()
DAYS=825
CA_DAYS=3650

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --ip) IPS+=("$2"); shift 2 ;;
        --dns) DNS_NAMES+=("$2"); shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        --ca-days) CA_DAYS="$2"; shift 2 ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 1 ;;
    esac
done

[[ -n "$OUT_DIR" ]] || { echo "нужен --out-dir" >&2; exit 1; }
[[ ${#IPS[@]} -gt 0 || ${#DNS_NAMES[@]} -gt 0 ]] || {
    echo "нужен хотя бы один --ip или --dns (это SAN сертификата)" >&2
    exit 1
}
command -v openssl >/dev/null 2>&1 || { echo "нужен openssl" >&2; exit 1; }

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

SAN=""
for ip in "${IPS[@]:-}"; do
    [[ -n "$ip" ]] || continue
    SAN="${SAN:+$SAN,}IP:$ip"
done
for name in "${DNS_NAMES[@]:-}"; do
    [[ -n "$name" ]] || continue
    SAN="${SAN:+$SAN,}DNS:$name"
done

echo "==== Корневой CA (действителен $CA_DAYS дней) ===="
if [[ -f ca.key && -f ca.crt ]]; then
    echo "ca.key/ca.crt уже есть в $OUT_DIR — переиспользую (удалите файлы, если нужен новый CA)."
else
    openssl genrsa -out ca.key 4096
    openssl req -x509 -new -nodes -key ca.key -sha256 -days "$CA_DAYS" \
        -subj "/CN=fail2ban-center internal CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out ca.crt
fi

echo "==== Серверный сертификат центра (действителен $DAYS дней, SAN: $SAN) ===="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=fail2ban-center" -out server.csr

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "$DAYS" -sha256 -extfile server.ext

rm -f server.csr server.ext ca.srl
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt

echo
echo "Готово, файлы в $OUT_DIR:"
echo "  ca.crt      — корневой CA: агенты получают его с центра по отпечатку, браузер администратора — вручную"
echo "  ca.key      — приватный ключ CA, хранить только на центре, не раздавать никуда"
echo "  server.crt  — сертификат центра (gunicorn --certfile)"
echo "  server.key  — ключ сертификата центра (gunicorn --keyfile)"
