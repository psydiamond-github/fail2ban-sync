#!/usr/bin/env python3
"""Уведомление о бане/разбане — вызывается действием fail2ban (actionban/actionunban),
исполняется от root, sudo не нужен. Короткий таймаут и подавление всех ошибок обязательны:
недоступность центра не должна тормозить обработку следующих банов — это лишь ускоритель,
тот же факт всё равно попадёт в дифф на ближайшем обычном чекине."""
from __future__ import annotations

import json
import sys
import urllib.request

CONFIG_PATH = "/etc/f2b-agent/config.json"
TIMEOUT = 3


def main() -> int:
    if len(sys.argv) != 4:
        return 0
    event, jail, ip = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
        body = json.dumps({"jail": jail, "ip": ip, "event": event}).encode("utf-8")
        req = urllib.request.Request(
            config["center_url"].rstrip("/") + "/api/v1/event",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {config['token']}",
            },
        )
        urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception:
        pass  # best-effort — намеренно; см. docstring
    return 0


if __name__ == "__main__":
    sys.exit(main())
