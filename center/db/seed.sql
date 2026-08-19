-- Значения settings по умолчанию (§3.8, §9-§12 docs/TZ.md). Идемпотентно — безопасно
-- запускать повторно поверх уже заполненной БД, существующие значения не трогает.
--
-- Применение: sqlite3 data/f2b-center.sqlite3 < center/db/seed.sql

INSERT OR IGNORE INTO settings (key, value) VALUES
    -- Протокол агентов (§4, §5)
    ('checkin_interval_seconds',        '60'),   -- §4: "по умолчанию 60 с (настраиваемый)"
    ('agent_task_stale_after_missed',   '5'),     -- §5.5: столько пропущенных чекинов без result — задача "потеряна"
    ('agent_ip_pin_default_mode',       'advisory'),  -- §10 — режим по умолчанию для новых агентов

    -- Веб-интерфейс
    ('session_idle_timeout_minutes',    '30'),

    -- Глобальный блок-лист (§3.3)
    ('global_block_enabled',            '0'),
    ('global_block_threshold',          '5'),
    ('global_block_duration_mode',      'permanent'),  -- 'permanent' | 'longest_jail_bantime'
    ('global_block_bulk_max_workers',   '8'),

    -- Бан сети Tor (§3.4)
    ('tor_block_enabled',               '0'),
    ('tor_block_source_url',            'https://check.torproject.org/torbulkexitlist'),

    -- VPN-хаб (WireGuard, опционально) — настраивается через manage.py vpn-init
    ('vpn_enabled',                     '0'),

    -- Просмотр логов (§3.9): 'none' | 'local' | 'graylog'
    ('log_view_mode',                   'none'),
    ('local_log_max_bytes',             '2000000'),
    ('fail2ban_log_lines',              '300'),

    -- Graylog (§3.9) — url/token пустые, пока явно не настроено в UI
    ('graylog_url',                     ''),
    ('graylog_api_token',               ''),
    ('graylog_stream_id',               ''),
    ('graylog_default_range_hours',     '24'),
    ('graylog_default_log_lines',       '300');
