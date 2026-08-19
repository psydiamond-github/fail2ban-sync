"""WireGuard-хаб для сети агентов (опционально) — центр как единственный узел, к которому
подключаются агенты (звезда, не полносвязный mesh: агентам не нужно видеть друг друга).
Бутстрап пира — БЕЗ публичного раскрытия API: агент печатает свой публичный ключ при
установке, администратор вносит его через веб-панель, получает обратно данные для настройки
на самом агенте. Никакого нового сетевого доступа снаружи для этого не требуется."""
from __future__ import annotations

import ipaddress
import os
import subprocess
from contextlib import closing
from typing import Optional

import db

IFACE = "f2b0"
HELPER = "/usr/local/sbin/f2b-center-vpn-helper"


def _run(cmd: list[str], input_text: str = None) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, input=input_text)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {result.stderr.strip()}")
    return result.stdout.strip()


def generate_keypair() -> tuple[str, str]:
    privkey = _run(["wg", "genkey"])
    pubkey = subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True, text=True).stdout.strip()
    return privkey, pubkey


def _privkey_path() -> str:
    return os.path.join(db.DATA_DIR, "vpn_privkey")


def load_center_privkey() -> Optional[str]:
    path = _privkey_path()
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return f.read().strip()


def save_center_privkey(privkey: str) -> None:
    path = _privkey_path()
    os.makedirs(db.DATA_DIR, exist_ok=True)
    with open(path, "w") as f:
        f.write(privkey + "\n")
    os.chmod(path, 0o600)


def is_enabled() -> bool:
    return db.get_setting("vpn_enabled", "0") == "1"


def allocate_ip() -> str:
    """Следующий свободный адрес в подсети (после .1, зарезервированного за центром)."""
    subnet = ipaddress.ip_network(db.get_setting("vpn_subnet", "10.99.0.0/24"), strict=False)
    used = {row["assigned_ip"] for row in list_peers()}
    for host in subnet.hosts():
        ip = str(host)
        if ip == db.get_setting("vpn_center_ip", "10.99.0.1"):
            continue
        if ip not in used:
            return ip
    raise RuntimeError("свободных адресов в VPN-подсети не осталось")


def add_peer(agent_id: int, wg_pubkey: str) -> str:
    assigned_ip = allocate_ip()
    with closing(db.get_conn()) as conn:
        conn.execute(
            """INSERT INTO agent_vpn_peers (agent_id, wg_pubkey, assigned_ip, added_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET wg_pubkey = excluded.wg_pubkey,
                   assigned_ip = excluded.assigned_ip""",
            (agent_id, wg_pubkey, assigned_ip, db.now()),
        )
        conn.commit()
    reconcile_config()
    return assigned_ip


def remove_peer(agent_id: int) -> None:
    with closing(db.get_conn()) as conn:
        conn.execute("DELETE FROM agent_vpn_peers WHERE agent_id = ?", (agent_id,))
        conn.commit()
    reconcile_config()


def list_peers() -> list:
    with closing(db.get_conn()) as conn:
        return conn.execute("SELECT * FROM agent_vpn_peers").fetchall()


def get_peer(agent_id: int):
    with closing(db.get_conn()) as conn:
        return conn.execute(
            "SELECT * FROM agent_vpn_peers WHERE agent_id = ?", (agent_id,)
        ).fetchone()


def reconcile_config() -> None:
    """Идемпотентно перегенерирует f2b0.conf из БД и применяет БЕЗ разрыва уже активных
    туннелей (wg syncconf), не через wg-quick down/up."""
    privkey = load_center_privkey()
    if not privkey:
        return
    center_ip = db.get_setting("vpn_center_ip", "10.99.0.1")
    subnet = db.get_setting("vpn_subnet", "10.99.0.0/24")
    port = db.get_setting("vpn_listen_port", "51820")

    lines = [
        "[Interface]",
        f"PrivateKey = {privkey}",
        f"Address = {center_ip}/{subnet.split('/')[1]}",
        f"ListenPort = {port}",
        "",
    ]
    for row in list_peers():
        lines += [
            "[Peer]",
            f"PublicKey = {row['wg_pubkey']}",
            f"AllowedIPs = {row['assigned_ip']}/32",
            "",
        ]
    content = "\n".join(lines)
    _run(["sudo", HELPER, "write-and-sync"], input_text=content)


def init_hub(subnet: str, port: int, endpoint_host: str) -> str:
    """Разовый бутстрап центра как WG-хаба. Возвращает публичный ключ центра."""
    privkey, pubkey = generate_keypair()
    save_center_privkey(privkey)
    center_ip = str(next(ipaddress.ip_network(subnet, strict=False).hosts()))
    db.set_setting("vpn_enabled", "1")
    db.set_setting("vpn_subnet", subnet)
    db.set_setting("vpn_center_ip", center_ip)
    db.set_setting("vpn_pubkey", pubkey)
    db.set_setting("vpn_listen_port", str(port))
    db.set_setting("vpn_endpoint_host", endpoint_host)
    reconcile_config()
    _run(["sudo", HELPER, "up"])
    return pubkey
