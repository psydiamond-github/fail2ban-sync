# База центра — SQLite

- `schema.sql` — таблицы, `seed.sql` — значения настроек по умолчанию. Оба идемпотентны
  (`IF NOT EXISTS`, `INSERT OR IGNORE`) и применяются кодом: `db.init_db()` при старте и в
  `install.sh update` (`manage.py init-db`). Новые столбцы в существующие таблицы добавляет
  `db.init_db()` через `ALTER TABLE`.
- Внешние ключи в SQLite включаются на каждое соединение: `db.get_conn()` выполняет
  `PRAGMA foreign_keys = ON`. При работе с базой вручную — делать то же.
- Назначение таблиц и логика — `docs/ARCHITECTURE.md`, раздел «Модель данных».

Вручную, только для чтения, на работающем центре:

```bash
sudo sqlite3 -readonly /opt/fail2ban-center/data/f2b-center.sqlite3 "select name, last_seen from agents"
```
