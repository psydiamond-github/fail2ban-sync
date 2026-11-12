-- Значения settings по умолчанию. Идемпотентно — безопасно
-- запускать повторно поверх уже заполненной БД, существующие значения не трогает.
--
-- Применение: sqlite3 data/f2b-center.sqlite3 < center/db/seed.sql

INSERT OR IGNORE INTO settings (key, value) VALUES
    -- Протокол агентов
    ('checkin_interval_seconds',        '60'),   -- "по умолчанию 60 с (настраиваемый)"
    ('agent_task_stale_after_missed',   '5'),     -- столько пропущенных чекинов без result — задача "потеряна"
    ('agent_ip_pin_default_mode',       'advisory'),  -- режим по умолчанию для новых агентов

    -- Веб-интерфейс
    ('session_idle_timeout_minutes',    '30'),

    -- Глобальный блок-лист
    ('global_block_enabled',            '0'),
    ('global_block_threshold',          '5'),
    ('global_block_duration_mode',      'permanent'),  -- 'permanent' | 'longest_jail_bantime'
    ('global_block_bulk_max_workers',   '8'),

    -- Бан сети Tor
    ('tor_block_enabled',               '0'),
    ('tor_block_source_url',            'https://check.torproject.org/torbulkexitlist'),

    -- VPN-хаб (WireGuard, опционально) — настраивается через manage.py vpn-init
    ('vpn_enabled',                     '0'),

    -- Просмотр логов: 'none' | 'local' | 'graylog'
    ('log_view_mode',                   'none'),
    ('local_log_max_bytes',             '2000000'),
    ('fail2ban_log_lines',              '300'),

    -- Graylog — url/token пустые, пока явно не настроено в UI
    ('graylog_url',                     ''),
    ('graylog_api_token',               ''),
    ('graylog_stream_id',               ''),
    ('graylog_default_range_hours',     '24'),
    ('graylog_default_log_lines',       '300'),
    ('graylog_verify_tls',              '1'),
    -- Как отличить в Graylog сообщения fail2ban от остальных логов хоста (вкладка «Лог»)
    ('graylog_fail2ban_query',          'application_name:fail2ban*'),
    -- Поле сообщения с именем хоста: source, а если там IP сборщика — например, hostname
    ('graylog_host_field',              'source');
