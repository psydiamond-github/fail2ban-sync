"""Корневой сертификат собственного CA центра: раздаётся агентам при установке, отпечаток
SHA-256 показывается администратору, чтобы агент мог проверить скачанный сертификат."""
from __future__ import annotations

import hashlib
import os
import ssl
from typing import Optional

DEFAULT_CA_CERT = "/etc/fail2ban-center/tls/ca.crt"


def ca_cert_path() -> str:
    return os.environ.get("F2B_CENTER_CA_CERT", DEFAULT_CA_CERT)


def ca_pem() -> Optional[str]:
    try:
        with open(ca_cert_path(), "r", encoding="ascii") as f:
            return f.read()
    except OSError:
        return None


def sha256_fingerprint(pem: str) -> str:
    """Тот же формат, что у `openssl x509 -noout -fingerprint -sha256`, без префикса."""
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def ca_fingerprint() -> Optional[str]:
    pem = ca_pem()
    return sha256_fingerprint(pem) if pem else None
