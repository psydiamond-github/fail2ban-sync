# Безопасность fail2ban-center

Модель угроз, реализованные защиты, что покрыто тестами и остаточные риски.
Автотесты — `center/tests/test_security.py` (71 тест, `pytest tests/test_security.py -v`).

## Поверхность атаки

| Вход | Кто обращается | Защита |
|---|---|---|
| Веб-панель (HTTPS) | администратор/оператор из браузера | логин+сессия, роли, CSRF |
| API агентов `POST /api/v1/{checkin,event}` | агенты на серверах | Bearer-токен, привязка к агенту |
| `GET /api/v1/ca.crt` | кто угодно | публичный сертификат, секретов не отдаёт |
| Внешние: Graylog, источник Tor | исходящие запросы центра | только admin настраивает, только http(s) |

Всё — только по HTTPS (TLS в gunicorn, свой CA). Центр сам к серверам не подключается.

## Реализованные защиты и соответствующие тесты

**Аутентификация и сессии**
- Без входа ни одна защищённая страница не отдаётся (редирект на `/login`) —
  `test_no_access_without_authentication` (параметризован по всем маршрутам).
- Сессия Flask: `HttpOnly`, `SameSite=Strict`, `Secure` (в бою `F2B_CENTER_COOKIE_SECURE=1`) —
  `test_session_cookie_flags_are_hardened`.
- При входе `session.clear()` — фиксация сессии невозможна — `test_login_rotates_session_no_fixation`.
- Редирект после входа захардкожен на `/dashboard`, параметр `next` игнорируется — нет
  открытого редиректа — `test_login_redirect_is_fixed_no_open_redirect`.
- Брутфорс логина блокируется после 10 неудач за 5 минут (по IP, в памяти процесса) —
  `test_login_bruteforce_is_rate_limited`.
- Логин сверяет хэш и для несуществующего пользователя — нет перечисления по времени
  (`auth._DUMMY_HASH`) — `test_username_enumeration_resistance`.

**Авторизация (роли)**
- Админские маршруты под `@require_admin`, остальные — `@require_login`; оператор получает 403
  на бан, настройки, управление пользователями/агентами — `test_operator_is_denied_admin_actions`.
- Оператор не может повысить себя до admin — `test_operator_cannot_escalate_self_to_admin`.
- Нельзя удалить/понизить последнего администратора — `test_cannot_delete_or_demote_last_admin`.

**CSRF**
- Все изменяющие POST требуют корректный токен; сравнение через `secrets.compare_digest` —
  `test_state_changing_post_requires_valid_csrf`, `test_csrf_check_uses_constant_time_compare`.
- Токен на сессию, непредсказуем — `test_csrf_token_is_unpredictable_and_per_session`.

**Токены агентов**
- В БД только HMAC-SHA256 (ключ `data/secret_key`), сам токен — один раз при выдаче —
  `test_agent_token_stored_only_as_hash`, `test_regenerated_token_shown_once_then_only_hash`.
- Нет токена/мусор/не-Bearer → 401; отзыв агента мгновенно даёт 401 —
  `test_api_rejects_missing_or_bad_bearer`, `test_revoked_agent_token_stops_working`.
- Токен привязан к агенту: с токеном A нельзя действовать за B, даже подставив `agent_id` —
  `test_agent_token_is_scoped_cannot_act_as_another_agent`.

**Инъекции**
- SQL везде параметризован: инъекция в логине не обходит вход, кавычки/`;` в имени агента не
  ломают таблицу — `test_sql_injection_in_*`.
- IP и имена джейлов валидируются (двойная граница: центр и helper на агенте); метасимволы
  оболочки отклоняются — `test_command_injection_in_ban_ip_is_validated`,
  `test_jail_name_with_shell_metachars_rejected`.
- Путь кэша лога строится из целого `agent_id` — обхода каталога нет —
  `test_log_cache_path_not_traversable`.

**SSRF**
- URL Graylog и источника Tor — только `http(s)://` (нет `file://`, `gopher://`) —
  `test_graylog_url_rejects_non_http_schemes`, `test_tor_source_url_rejects_non_http_schemes`.
- Поле имени хоста Graylog из настроек не внедряет произвольный запрос (валидация regex) —
  `test_graylog_host_field_cannot_inject_query`.

**Утечки и XSS**
- Токен Graylog не рендерится в HTML и не затирается пустым полем —
  `test_graylog_token_never_rendered_in_settings_page`, `..._survives_empty_field_on_save`.
- Jinja автоэкранирует: `<script>` в имени агента и разметка в IP выводятся безопасно —
  `test_stored_xss_in_*`.

## Остаточные риски (не покрываются кодом, под контролем администратора)

1. **SSRF на уровне admin (by design).** Администратор задаёт URL Graylog и источника Tor —
   значит может направить центр на внутренний адрес (`http://169.254.169.254/…`). Блокировать
   приватные сети нельзя: Graylog обычно и есть во внутренней сети. Смысл имеет только для того,
   у кого уже есть админ-доступ. Блокируются лишь не-HTTP схемы.
2. **`F2B_CENTER_TRUST_PROXY`.** Включать только если перед центром реально стоит доверенный
   reverse-proxy. Иначе `X-Forwarded-For` подделывается клиентом и обходит rate-limit входа и
   строгую привязку агента к IP. По умолчанию выключено; `install.sh` спрашивает явно.
3. **Политика паролей — минимум 6 символов.** Защита от перебора — rate-limit, не сложность.
   Короткие пароли отклоняются (`test_weak_password_rejected_on_user_create`), но стойкость —
   на администраторе. Рекомендуется длинный пароль.
4. **Rate-limit входа — в памяти процесса.** Переживает только пока жив worker (`--workers 1`).
   При рестарте счётчик сбрасывается — приемлемо для внутренней панели, не публичного сервиса.
5. **Антивирусы с перехватом HTTPS** на серверах подменяют сертификат центра — агент такое
   соединение отвергает. Требует исключения на стороне сервера (см. `agent/README.md`).
6. **Размер тела запроса.** gunicorn без лимита тела; если центр выставлен наружу без
   reverse-proxy, стоит ограничить размер тела на фронте. Для внутренней сети не критично.
7. **DoS.** Проект — не средство защиты от DoS: один процесс, SQLite. Публичного доступа к
   панели быть не должно (только внутренняя сеть или SSH-туннель).

## Что проверять при изменениях кода

- Новый маршрут — обязательно `@require_admin`/`@require_login` и проверка CSRF на POST;
  параметризованный тест `test_no_access_without_authentication` поймёт пропуск, если дописать
  маршрут в список `PROTECTED`.
- Любой вывод данных агента/пользователя в шаблон — только через Jinja (без `|safe`).
- Любой новый внешний запрос — проверка схемы URL и учёт, что значение задал администратор.
- SQL — только через параметры (`?`), не через f-string со значениями.
