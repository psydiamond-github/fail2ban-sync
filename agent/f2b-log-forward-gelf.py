#!/usr/bin/env python3
"""Опциональный форвардер лога fail2ban в Graylog по GELF TCP — нужен только при
log_view_mode=graylog в настройках центра (режим 'local' его не требует вообще, там докачку
делает сам f2b-agent-checkin.py). Не часть обязательной установки агента.

Использование:
  f2b-log-forward-gelf.py <graylog_host> <graylog_port> <source_name> <logfile>

<source_name> должен совпадать с именем агента на центре (или его graylog_source, если
задан отдельно) — по этому полю центр сопоставляет сообщения с конкретным сервером."""
from __future__ import annotations

import json
import socket
import sys
import time


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 1
    graylog_host, graylog_port, source_host, logfile = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

    sock: socket.socket | None = None
    while True:
        try:
            with open(logfile, "r", errors="replace") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    payload = json.dumps({
                        "version": "1.1",
                        "host": source_host,
                        "short_message": line[:1000],
                        "timestamp": time.time(),
                        "level": 6,
                        "_facility": "fail2ban",
                    }).encode("utf-8") + b"\x00"
                    if sock is None:
                        sock = socket.create_connection((graylog_host, graylog_port), timeout=10)
                    try:
                        sock.sendall(payload)
                    except OSError:
                        sock.close()
                        sock = socket.create_connection((graylog_host, graylog_port), timeout=10)
                        sock.sendall(payload)
        except FileNotFoundError:
            time.sleep(5)  # лог ещё не создан/временно недоступен — не падаем насовсем
        except OSError as e:
            print(f"соединение с Graylog потеряно: {e}, повтор через 5с", file=sys.stderr)
            sock = None
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
