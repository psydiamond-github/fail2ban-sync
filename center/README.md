# fail2ban-center

Центральный узел управления fail2ban на множестве серверов через агентов, которые сами
исходящим HTTPS стучатся в центр (не наоборот — см. `../docs/TZ.md` за полным ТЗ и
обоснованием архитектуры). Установка агента — отдельный шаг, см. `../agent/README.md`.

## Быстрый старт

```bash
sudo deploy/install.sh install    # спросит порт, адрес прослушивания, пользователя сервиса
```

Слушает только `127.0.0.1:<порт>` — снаружи доступен через reverse-proxy с TLS, см.
`deploy/nginx-example.conf`. TLS обязателен (§10 ТЗ) — центр принимает пароли пользователей и
токены агентов.

Первый администратор создаётся интерактивно в процессе `install.sh install` (или отдельно —
`venv/bin/python3 manage.py create-admin`).

## Добавление агента

В веб-интерфейсе: «Управление агентами» → «Добавить агента» — укажите имя и список
разрешённых джейлов (`имя bantime_секунд` по строке, `-1` = навсегда). Токен показывается
один раз сразу после создания. Он же — через CLI:

```bash
venv/bin/python3 manage.py add-agent srv-42 --jail sshd:600 --jail nginx-req-limit:3600
```

Дальше — на управляемом хосте, см. `../agent/README.md` (готовая команда установки печатается
сразу после создания агента).

## Ручное управление сервисом

```bash
sudo deploy/install.sh status|start|stop|restart
sudo journalctl -u fail2ban-center -f
```

## Обновление

```bash
sudo rsync -a --exclude='__pycache__' --exclude='data' ./ /opt/fail2ban-center/
sudo chown -R fail2ban-center:fail2ban-center /opt/fail2ban-center
sudo /opt/fail2ban-center/venv/bin/pip install -r /opt/fail2ban-center/requirements.txt
sudo systemctl restart fail2ban-center
```

## На чём это работает

Python 3 + Flask + gunicorn, SQLite (`db/schema.sql`, без ORM), `requests` — для Graylog API и
скачивания списка Tor exit-нод. Фоновый планировщик (`scheduler.py`) — один поток на процесс,
поэтому `gunicorn --workers 1` обязателен (см. комментарий в `deploy/fail2ban-center.service`).

## Модель данных

См. `db/README.md` — таблицы и их соответствие разделам ТЗ, включая уточнения протокола,
сделанные при реализации (формат `new_bans`/`new_unbans`, поле `data` в результатах задач).

## Тесты

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Покрывает протокол `checkin`/`event` end-to-end (через `flask.testing`, БД — временная,
`tmp_path`), RBAC admin/operator, глобальный блок-лист (порог, применение на ДРУГИХ агентах,
приоритет за ручным разбаном прямо на сервере — §3.3 ТЗ), защиту от широких сетей в
игнор-листе блок-листа, и regression-случай с чекбоксами в форме настроек (браузер не
присылает ключ для снятого чекбокса — наивная реализация не смогла бы его выключить).

Сам `agent/f2b-agent-checkin.py` отдельно прогонялся при разработке против реального
поднятого центра (не test-client, настоящий HTTP) с подставным `f2b-agent-helper` —
воспроизводит логику `tests/`, но живёт как процедура разработки, не как файл в репозитории;
при желании довести до автоматического теста — самый естественный путь — обернуть в
`pytest` с фикстурой, поднимающей центр в отдельном потоке (`werkzeug.serving.make_server`).
