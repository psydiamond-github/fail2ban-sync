#!/usr/bin/env python3
"""CLI-утилита администрирования центра — init-db, create-admin, agent add/revoke/list."""
from __future__ import annotations

import argparse
import getpass
import sys

import auth
import db
import vpn


def cmd_init_db(_args) -> None:
    db.init_db()
    print(f"БД инициализирована: {db.DB_PATH}")


def cmd_create_admin(_args) -> None:
    username = input("Логин: ").strip()
    if db.get_user_by_username(username):
        print(f"Пользователь «{username}» уже существует.", file=sys.stderr)
        sys.exit(1)
    password = getpass.getpass("Пароль: ")
    confirm = getpass.getpass("Повторите пароль: ")
    if password != confirm:
        print("Пароли не совпадают.", file=sys.stderr)
        sys.exit(1)
    db.create_user(username, auth.hash_password(password), role="admin")
    print(f"Администратор «{username}» создан.")


def cmd_add_agent(args) -> None:
    jails = []
    for spec in args.jail:
        if ":" in spec:
            name, bantime = spec.split(":", 1)
            jails.append({"name": name, "bantime": int(bantime)})
        else:
            jails.append({"name": spec, "bantime": 600})
    agent_id, token = db.register_agent(args.name, jails)
    print(f"Агент «{args.name}» создан, id={agent_id}")
    print(f"Токен (сохраните сейчас, повторно не показывается): {token}")
    print()
    jail_flags = "".join(f" --jail {j['name']}:{j['bantime']}" for j in jails)
    print("Установка на управляемом хосте (см. agent/README.md):")
    print(f"  sudo agent/install_agent.sh --center-url <URL> --token {token} "
          f"--agent-name {args.name}{jail_flags}")


def cmd_list_agents(_args) -> None:
    for a in db.list_agents():
        status = "отозван" if a["revoked_at"] else "активен"
        jails = ", ".join(j["name"] for j in a["allowed_jails"])
        print(f"[{a['id']}] {a['name']}  ({status}, last_seen={a['last_seen'] or '—'})  джейлы: {jails}")


def cmd_revoke_agent(args) -> None:
    agent = db.get_agent_by_name(args.name)
    if agent is None:
        print(f"Агент «{args.name}» не найден.", file=sys.stderr)
        sys.exit(1)
    db.revoke_agent(agent["id"])
    print(f"Агент «{args.name}» отозван.")


def cmd_regenerate_token(args) -> None:
    agent = db.get_agent_by_name(args.name)
    if agent is None:
        print(f"Агент «{args.name}» не найден.", file=sys.stderr)
        sys.exit(1)
    token = db.regenerate_token(agent["id"])
    print(f"Новый токен «{args.name}» (сохраните сейчас): {token}")


def cmd_vpn_init(args) -> None:
    if db.get_setting("vpn_enabled", "0") == "1":
        print("VPN-хаб уже инициализирован (см. настройки).", file=sys.stderr)
        sys.exit(1)
    pubkey = vpn.init_hub(args.subnet, args.port, args.endpoint)
    print(f"WG-интерфейс {vpn.IFACE} поднят.")
    print(f"Публичный ключ центра: {pubkey}")
    print(f"Endpoint для агентов: {args.endpoint}:{args.port}")
    print("Дальше — на каждом агенте: sudo agent/install_agent.sh ... --setup-vpn")
    print("(напечатает публичный ключ агента — добавьте его на странице агента в веб-панели).")


def cmd_vpn_add_peer(args) -> None:
    agent = db.get_agent_by_name(args.agent_name)
    if agent is None:
        print(f"Агент «{args.agent_name}» не найден.", file=sys.stderr)
        sys.exit(1)
    assigned_ip = vpn.add_peer(agent["id"], args.pubkey)
    print(f"Пир добавлен: {args.agent_name} -> {assigned_ip}")
    print(f"На агенте: --vpn-server-pubkey {db.get_setting('vpn_pubkey')} "
          f"--vpn-server-endpoint {db.get_setting('vpn_endpoint_host')}:{db.get_setting('vpn_listen_port')} "
          f"--vpn-assigned-ip {assigned_ip}/{db.get_setting('vpn_subnet', '10.99.0.0/24').split('/')[1]}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="manage.py")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db").set_defaults(func=cmd_init_db)
    sub.add_parser("create-admin").set_defaults(func=cmd_create_admin)
    sub.add_parser("list-agents").set_defaults(func=cmd_list_agents)

    p = sub.add_parser("add-agent")
    p.add_argument("name")
    p.add_argument("--jail", action="append", default=[],
                    help="имя[:bantime_секунд], можно повторять; -1 = навсегда")
    p.set_defaults(func=cmd_add_agent)

    p = sub.add_parser("revoke-agent")
    p.add_argument("name")
    p.set_defaults(func=cmd_revoke_agent)

    p = sub.add_parser("regenerate-token")
    p.add_argument("name")
    p.set_defaults(func=cmd_regenerate_token)

    p = sub.add_parser("vpn-init")
    p.add_argument("--subnet", default="10.99.0.0/24")
    p.add_argument("--port", type=int, default=51820)
    p.add_argument("--endpoint", required=True, help="публичный адрес/домен центра для агентов")
    p.set_defaults(func=cmd_vpn_init)

    p = sub.add_parser("vpn-add-peer")
    p.add_argument("agent_name")
    p.add_argument("pubkey")
    p.set_defaults(func=cmd_vpn_add_peer)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
