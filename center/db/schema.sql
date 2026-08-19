-- Схема БД центра fail2ban-center (SQLite). См. docs/TZ.md — разделы указаны в комментариях
-- к каждой таблице. Без ORM, прямой SQL — тот же принцип, что и в референсном SSH-проекте.
--
-- Применение: sqlite3 data/f2b-center.sqlite3 < center/db/schema.sql
-- Подключение из кода должно каждый раз выставлять: PRAGMA foreign_keys = ON;
-- (это per-connection настройка SQLite, в файл схемы не сохраняется).

PRAGMA foreign_keys = ON;

-- === Пользователи веб-интерфейса (§3.6, §8) ===============================================

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator' CHECK (role IN ('admin', 'operator')),
    created_at    TEXT NOT NULL
);

-- === Группы агентов — чисто навигационная фича (§3.5), произвольная вложенность ===========

CREATE TABLE IF NOT EXISTS agent_groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    parent_id  INTEGER REFERENCES agent_groups(id),
    created_at TEXT NOT NULL
);

-- === Агенты (§4, §6, §7, §9, §10) ==========================================================
-- Аналог `servers` в SSH-референсе, но без ssh_*/jump-host полей — вместо них токен
-- (только хэш) и статичный список разрешённых джейлов, который агент проверяет САМ,
-- независимо от того, что прислал центр (вторая граница защиты, см. §6).

CREATE TABLE IF NOT EXISTS agents (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    name                      TEXT NOT NULL UNIQUE,   -- он же agent_id в протоколе (§5)
    token_hash                TEXT UNIQUE,             -- HMAC-SHA256(токен); NULL — агент отозван
    allowed_jails             TEXT NOT NULL DEFAULT '[]',  -- JSON-массив имён джейлов
    group_id                  INTEGER REFERENCES agent_groups(id) ON DELETE SET NULL,
    pinned_ip                 TEXT,                    -- NULL — привязка к IP не используется
    ip_pin_mode               TEXT NOT NULL DEFAULT 'advisory'
                                   CHECK (ip_pin_mode IN ('advisory', 'strict')),  -- см. §10
    last_ip                   TEXT,                    -- IP, с которого пришёл последний чекин
    last_seen                 TEXT,                    -- время последнего успешного чекина
    last_agent_version        TEXT,                    -- версия агента из последнего чекина (§9.3)
    checkin_interval_seconds  INTEGER,                 -- NULL → settings.checkin_interval_seconds
    graylog_source            TEXT,                    -- NULL → использовать name (§3.9)
    baseline_ignoreip         TEXT NOT NULL DEFAULT '[]',  -- JSON-массив, кэш [DEFAULT] ignoreip
                                   -- из jail.local агента (§3.2) — обновляется результатом
                                   -- задачи report_full_state (см. приложение A в TZ.md),
                                   -- нужен для merge при пересборке permanent_ignore_sync
    created_at                TEXT NOT NULL,
    revoked_at                TEXT                     -- NULL — активен; см. §9.4
);

-- === Очередь задач агенту (§5.2, §5.4, §5.5) ===============================================
-- Внешний task_id протокола = 't-' || id.

CREATE TABLE IF NOT EXISTS agent_tasks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id       INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    type           TEXT NOT NULL CHECK (type IN (
                       'ban', 'unban', 'ignore_add', 'ignore_del',
                       'permanent_ignore_sync', 'tor_sync', 'report_full_state', 'ping'
                   )),
    payload        TEXT NOT NULL DEFAULT '{}',  -- JSON: jail/ip/ttl/ip_list/ban_ips/unban_ips — по type
    status         TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'delivered', 'done', 'error')),
    created_by     TEXT NOT NULL,       -- логин пользователя, либо 'scheduler'/'system'
    created_at     TEXT NOT NULL,
    delivered_at   TEXT,                -- отдана агенту в ответе checkin
    completed_at   TEXT,                -- получен result (ok/error) от агента
    result_detail  TEXT                 -- из results[].detail при status='error'
);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_pending ON agent_tasks(agent_id, status);

-- === Журнал банов/разбанов от агентов (§3.3, §5.2, §5.3, §6.1) =============================
-- Заполняется из двух каналов: диффом в checkin (new_bans/new_unbans) и мгновенно через
-- /api/v1/event. Дедупликация — по (agent_id, jail, ip, kind, since): "since" обязан
-- приходить с КАЖДЫМ IP в обоих каналах, иначе дедуп не сможет отличить один и тот же факт,
-- пришедший дважды, от двух разных эпизодов. В JSON-примере §5.2 new_bans показан как
-- {"jail": [ip, ip, ...]} без since на каждый IP — при реализации протокола это нужно
-- расширить до {"jail": [{"ip": ..., "since": ...}, ...]} (см. пояснение в README рядом).

CREATE TABLE IF NOT EXISTS agent_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    jail         TEXT NOT NULL,
    ip           TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('ban', 'unban')),
    source       TEXT NOT NULL CHECK (source IN ('checkin', 'event')),
    since        TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    UNIQUE (agent_id, jail, ip, kind, since)
);

CREATE INDEX IF NOT EXISTS idx_agent_events_received ON agent_events(received_at);

-- === Материализованное текущее состояние банов (§3.1) =======================================
-- То, что реально показывает UI на странице сервера — прямое чтение с агента невозможно
-- (pull-модель, не реалтайм). Полностью перезаписывается результатом report_full_state,
-- инкрементально корректируется каждым agent_events.

CREATE TABLE IF NOT EXISTS agent_ban_state (
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    jail        TEXT NOT NULL,
    ip          TEXT NOT NULL,
    since       TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (agent_id, jail, ip)
);

-- === Игнор-листы (§3.2) =====================================================================
-- Источник истины по самим спискам ignoreip — конфиг/runtime на стороне агента; эти две
-- таблицы — только audit "кем и когда добавлено" + TTL для временного игнора (runtime-only
-- на стороне fail2ban).

CREATE TABLE IF NOT EXISTS permanent_ignore (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    comment     TEXT,
    UNIQUE (agent_id, ip)
);

CREATE TABLE IF NOT EXISTS temp_ignore (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    jail        TEXT NOT NULL,
    ip          TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    comment     TEXT,
    UNIQUE (agent_id, jail, ip)
);

-- === Аудит-лог (§3.7) =======================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,     -- логин пользователя, либо 'agent:<name>'/'scheduler'
    agent_id  INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    action    TEXT NOT NULL,
    ip        TEXT,
    jail      TEXT,
    detail    TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_agent_ts ON audit_log(agent_id, ts);

-- === Настройки (§3.8, §9-§12) — key/value, см. db/seed.sql на список ключей по умолчанию ===

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- === Глобальный блок-лист (§3.3) ============================================================

-- Число отдельных эпизодов бана IP на КОНКРЕТНОМ агенте — порог считается отдельно на
-- каждом, не суммарно (см. §3.3). В отличие от SSH-референса, не нужен отдельный "снимок
-- предыдущего опроса" (там — ip_ban_seen): дифф уже посчитан агентом локально, каждая
-- строка agent_events(kind='ban') — уже готовый новый отдельный эпизод.
CREATE TABLE IF NOT EXISTS ip_ban_counters (
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    ban_count   INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (agent_id, ip)
);

-- Список подтверждённых нарушителей. active=0 — разбанен вручную, запись остаётся
-- ("липкая" память для реактивации без нового набора порога).
CREATE TABLE IF NOT EXISTS global_blocklist (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    ip                     TEXT NOT NULL UNIQUE,
    triggered_by_agent_id  INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    ban_count              INTEGER NOT NULL DEFAULT 0,
    active                 INTEGER NOT NULL DEFAULT 1,
    added_at               TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);

-- Где именно применён глобальный бан — источник для сверки "приоритет за ручным разбаном
-- на сервере" (§3.3): если строка пропала из agent_ban_state для соответствующего джейла,
-- но осталась здесь — значит бан сняли на месте не через центр.
CREATE TABLE IF NOT EXISTS global_block_applied (
    ip          TEXT NOT NULL,
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    jail        TEXT NOT NULL,
    applied_at  TEXT NOT NULL,
    PRIMARY KEY (ip, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_global_block_applied_agent ON global_block_applied(agent_id);

-- "Белый список" глобального блок-листа — IP/сеть, никогда не банится автоматически.
CREATE TABLE IF NOT EXISTS global_block_ignore (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    network    TEXT NOT NULL UNIQUE,
    comment    TEXT,
    added_by   TEXT NOT NULL,
    added_at   TEXT NOT NULL
);

-- === WireGuard-хаб (опционально, звезда: агенты видят только центр) ========================
CREATE TABLE IF NOT EXISTS agent_vpn_peers (
    agent_id     INTEGER PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    wg_pubkey    TEXT NOT NULL,
    assigned_ip  TEXT NOT NULL UNIQUE,
    added_at     TEXT NOT NULL
);

-- === Локальный кэш лога fail2ban (альтернатива Graylog) ====================================
-- Дополняется инкрементально на каждом чекине (новые байты с прошлой позиции). Сам текст —
-- в data/log_cache/<agent_id>.log.
CREATE TABLE IF NOT EXISTS agent_log_cache (
    agent_id    INTEGER PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    path        TEXT,
    offset_pos  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL
);

-- === Бан сети Tor (§3.4) ====================================================================

-- Официальный список exit-нод, скачанный ЦЕНТРОМ — единый на все агенты, не per-agent.
-- Полностью перезаписывается раз в сутки/по кнопке "Обновить сейчас".
CREATE TABLE IF NOT EXISTS tor_exit_nodes (
    ip          TEXT PRIMARY KEY,
    updated_at  TEXT NOT NULL
);

-- Что реально применено на каждом агенте в служебном джейле Tor-бана — источник для
-- расчёта diff (ban_ips/unban_ips) очередной задачи tor_sync.
CREATE TABLE IF NOT EXISTS tor_block_applied (
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    applied_at  TEXT NOT NULL,
    PRIMARY KEY (agent_id, ip)
);
