# Контракт волны 1 (этапы 1–3)

Обязателен для задач T1.1 (сервер), T1.2 (клиент), T1.3a (аудио), T1.3b (бот), T1.4 (сквозные тесты). Задачи идут
параллельно и сверяются только с этим документом. Если реализация расходится с контрактом, верен контракт; изменить
его может только интегратор. Общие решения — в docs/dev/roadmap.md.

## 1. Сброс старой схемы (T1.1, roadmap R0)

**Признак старой схемы** (проверяется под блокировкой миграций, до создания таблиц): у таблицы `users` есть колонка
`email` или `password`, либо таблица `users` есть, а `schema_meta` нет.

**Сброс** выполняется одной транзакцией:
- посчитать пользователей и сообщения — только числа;
- `DROP TABLE IF EXISTS … CASCADE` для всех таблиц приложения v2.0.0: `reactions`, `message_expiry`, `chat_settings`,
  `room_settings`, `e2ee_key_shares`, `join_requests`, `security_events`, `unread`, `room_participants`, `messages`,
  `chats`, `rooms`, `users`, `identity_keys`, `signed_prekeys`, `one_time_prekeys`, `signed_pq_prekeys`, `session`;
- `DROP FUNCTION IF EXISTS nyxo_random_id(regclass)`.

**Файлы вложений** удаляются после COMMIT. Из `UPLOADS_DIR` удаляются только файлы, имя которых подходит под шаблон
загрузок v2.0.0: `^\d{13}-[0-9a-f]{24}(\.[a-z0-9]{2,5})?$`, а также временные файлы с `-cleaned-` в имени. Остальные
файлы и папки не трогаются.

**Лог** — ровно эти строки, только числа:
```
[Reset] Обнаружена старая схема: удаляются тестовые данные (пользователей: N, сообщений: M)
[Reset] Удалено файлов вложений: K
```

После сброса создаётся итоговая схема и `schema_meta` (из T0.1). Если `schema_meta` есть и колонок `email`/`password`
нет, сброс не выполняется никогда.

## 2. Итоговая схема этапа 1 (T1.1)

`users`:
- `id INTEGER PRIMARY KEY DEFAULT nyxo_random_id('users')`;
- `unique_code TEXT UNIQUE NOT NULL`, `username TEXT UNIQUE NOT NULL`, `avatar TEXT DEFAULT ''`;
- `created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now())`;
- `read_receipts BOOLEAN NOT NULL DEFAULT FALSE` (4.2);
- `anon_lifetime TEXT NOT NULL CHECK (anon_lifetime IN ('tab','day','week'))`;
- `last_active_at TIMESTAMPTZ NOT NULL`;
- индекс `idx_users_lifetime (anon_lifetime, last_active_at)`.

Колонок `email` и `password`, таблицы `security_events` нет.

Таблица `session` создаётся в `initDatabase` тем же DDL, что у connect-pg-simple, плюс индекс
`idx_session_user ON session ((sess->>'userId'))`.

Остальные таблицы — как в v2.0.0, но без шагов совместимости со старыми схемами. Сообщения, порядок, время и E2EE
меняются в волне 2: T1.1 их не трогает.

## 3. HTTP API

### GET /api/auth

Продлевает сессию (раздел 4) и выдаёт CSRF-куку, если её нет.

Вошёл:
```json
{ "authenticated": true,
  "user": { "id": 123, "username": "Гость-AB12", "uniqueCode": "…", "isAnonymous": true, "readReceipts": false,
            "anonLifetime": "tab" | "day" | "week", "anonInactivitySeconds": 1800,
            "anonExpiresAt": "2026-10-03T12:05:00.000Z" | null },
  "onionUrl": "http://<56>.onion/" | null }
```
- `anonExpiresAt` для day/week = корзина `last_active_at` + срок; для tab — `null`.
- `onionUrl` отдаётся ровно при тех же условиях, что заголовок `Onion-Location`: ONION_ADDRESS и ONION_PORT заданы и
  запрос пришёл не через onion. Иначе `null`.

Не вошёл:
```json
{ "authenticated": false, "reason": "expired", "expired": true, "onionUrl": null }
```
- `reason`/`expired` — только если сессия была, а аккаунт удалён по сроку или сессия недействительна. Иначе этих полей нет.

### POST /api/register/anonymous

Запрос: `{ lifetime?: 'tab'|'day'|'week' (по умолчанию 'tab'), pow: { token, nonce } }`.

Ответ:
```json
{ "success": true, "user": { …как в /api/auth…, "readReceipts": false }, "botChatId": 456 }
```

Ошибки:
- живая сессия → HTTP 409 `{success:false, code:'already-authenticated', message:'Вы уже вошли в аккаунт'}`.
  Проверяется до PoW;
- PoW не прошёл → `{success:false, powRequired:true, message}`;
- неверный lifetime → `{success:false, message}`.

### POST /api/user/lifetime (новый)

Запрос: `{ lifetime: 'tab'|'day'|'week' }`, поле обязательно, без значения по умолчанию.

Ответ: `{ success:true, anonLifetime, anonInactivitySeconds, anonExpiresAt }`.

Что делает сервер:
- `last_active_at` обновляется на текущую корзину;
- сессия пересоздаётся (новый sid) с новым сроком: у tab — кука без Expires, у day/week — с Expires;
- CSRF-кука выдаётся заново.

Клиент после успеха переподключает сокет.

### POST /api/account/delete и POST /api/logout (псевдоним)

Запрос: тело `{}`, пароль не нужен.

Ответ: `{ success:true, message:'Аккаунт и все данные удалены' }` и заголовок `Clear-Site-Data: "cache"`.

Что делает сервер:
- удаляет всё: сообщения, файлы, комнаты, где пользователь остался последним, ключи, сессии, заявки;
- закрывает сокеты;
- очищает куку сессии и выдаёт новую CSRF-куку.

### Прочие маршруты

- `GET /api/user` → `{ success:true, user:{ id, username, uniqueCode, readReceipts, anonLifetime, anonInactivitySeconds, anonExpiresAt } }`.
- `POST /api/user/privacy` `{readReceipts:boolean}` — без изменений.
- Удалены (JSON-404 `{success:false, message:'Не найдено'}` при валидном CSRF):
  - `POST /api/register`;
  - `POST /api/login`;
  - `POST /api/change-password`;
  - `POST /api/user/avatar-color`;
  - `GET /api/security-events`.
- `GET /api/pow/challenge?purpose=register` → 400, `purpose=register-anon` → как раньше.
- `GET /api/messages/:chatId` у чата с ботом добавляет `chat.quickReplies: string[]` (T1.3b). У комнат этого поля нет.

## 4. Сессии и срок жизни (числа)

| Параметр | Значение |
|---|---|
| Срок без активности | tab 30 мин, day 24 ч, week 7 дн. Потолка от создания нет |
| Корзина активности | `ceil(now / 5 мин) * 5 мин`; `last_active_at` пишется не чаще раза за корзину и только вверх |
| Продление сессии | если `sess.renewBucket !== floor(now / interval)`, interval = 5 мин (`NYXO_TEST_RENEW_INTERVAL_MS` при NODE_ENV=test) |
| Кука day / week | `maxAge` = срок + 15 мин; Set-Cookie при каждом продлении |
| Кука tab | сессионная, без Expires; строку `session` продлевает touch сокетов |
| TTL строки session | 24 ч |
| Touch открытых сокетов | раз в 2,5 мин: `last_active_at` и `session.expire = GREATEST(expire, now + 24 ч)` у tab-сессий |
| Чистка неактивных | раз в 5 мин (`NYXO_TEST_MAINTENANCE_MS`); пропускает пользователей с открытым сокетом на этом экземпляре |
| NyxoPgStore | в БД `cookie.expires` огрублён вверх до 5 мин, `createdAt` не хранится |

`validateSession`: сессия без `isAnonymous` недействительна; пользователя нет → `expired`.

Признак онлайна для чистки и touch — сокет. HTTP-запрос продлевает активность через корзину.

## 5. Обязательства клиента (T1.2)

- **Keepalive.** `GET /api/auth` раз в 4 мин; при `visibilitychange → visible`, если с прошлого запроса прошло больше
  60 с; на `online`; на reconnect сокета; на disconnect с причиной `io server disconnect`.
- **Смена срока.** После `POST /api/user/lifetime` — переподключить сокет.
- **botChatId** хранить в `localStorage['nyxo-bot-chat:' + userId]`; понадобится в волне 2.
- **BroadcastChannel `nyxo-session`.** События:
  - `{type:'session-started', userId}`;
  - `{type:'account-deleted', userId}`;
  - `{type:'lifetime-changed', userId, anonLifetime}`.
- **Поле приглашения** принимает:
  - полный URL с `#join=КОД` или `#join=КОД.СЕКРЕТ`. СЕКРЕТ — 22 символа base64url, зарезервирован для 5.4: его нужно
    сохранить и передать дальше, сейчас он не используется;
  - `join=КОД`;
  - сам КОД: 26 символов алфавита `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`; пробелы, дефисы и тире игнорируются, регистр не
    важен.

  Неверный формат → ошибка до PoW.
- **Удалить:**
  - вкладки и формы входа и регистрации;
  - окно смены пароля;
  - окно «Выйти, сохранив ключи»;
  - журнал безопасности;
  - email и строку «Код: …» в профиле.
- **«Удалить и выйти»** — одна кнопка с одним подтверждением. Если сеть недоступна, локальные ключи не стираются.
- **Отметки о прочтении** по умолчанию выключены: `readReceiptsEnabled()` возвращает true только при `readReceipts === true`.
- **Тексты** — по плану клиента §1.3 с решениями roadmap, раздел 5.

## 6. Владение кодом в волне 1

| Задача | Владеет | Не трогает |
|---|---|---|
| T1.1 | server.js: сессии, auth- и account-маршруты, активность, чистка, deleteUserAccount, initDatabase (схема и сброс); lib/anon-lifetime.js; lib/legacy-reset.js (новый); удаление lib/passwords.js; lib/privacy.js (addRandomDelay); lib/security-utils.js (classifyUserAgent, normalizeEmail); lib/pow.js (цель register); lib/env-check.js (PASSWORD_PEPPER, HIBP_CHECK → «не используется»); их тесты | бот, загрузка и MIME, клиентские файлы, `anonWelcomeText` |
| T1.3a | lib/security-utils.js (MIME и обезличенные имена); public/media-sanitizer.js; server.js (checkMagicBytes, загрузка, /uploads, текст ошибки загрузки); клиент (файлы, запись голоса, accept, иконки mic/music, стили); тесты | сессии, бот |
| T1.3b | lib/bot-guide.js (новый); server.js (BOT_RESPONSES, scheduleBotReply, место, где выбирается текст приветствия, `quickReplies` в ответе истории); клиент (кнопки-подсказки через `sendText`, слот в поле ввода, стили); тесты | сессии, загрузка |
| T1.2 | клиент: экран входа, «Как это работает», профиль, модалки, заметка в сайдбаре, сессия, keepalive, BroadcastChannel; public/lib/{invite,lifetime}.js; тесты client-lib | сервер |
| T1.4 | test/e2e/* (наборы ниже), test/forbidden-terms.test.js, docs/dev/forbidden-terms.md | прод-код |

`insertUserWithBotChat` правит T1.1 (колонки, возврат `{userId, botChatId}`); текст приветствия передаёт вызывающий.
T1.3b меняет только выражение, которое этот текст вычисляет. После слияния интегратор удаляет `anonWelcomeText` из
lib/anon-lifetime.js и его тест.

## 7. Сквозные наборы волны 1 (T1.4)

- **reset.** Загрузить фикстуру v2.0.0 и положить в UPLOADS_DIR два файла по старому шаблону и один посторонний.
  После старта:
  - в логе обе строки `[Reset]`;
  - нет колонок `email`/`password` и таблицы `security_events`; `users` пуста;
  - файлы по шаблону удалены, посторонний на месте.

  Повторный старт: строк `[Reset]` нет, снимок схемы тот же.
- **lifetime:**
  - tab/day/week: `anonExpiresAt` по формуле;
  - перемотка `last_active_at` за срок → чистка удаляет пользователя, его сессии, сообщения и комнаты, где он был один;
  - у самой границы срока пользователь жив;
  - week с `created_at` 30 дней назад и свежей активностью жив;
  - tab с открытым сокетом переживает перемотку (touch).
- **session-renewal:**
  - day/week: после смены корзины есть Set-Cookie, а `session.expire` сдвинулся; в той же корзине Set-Cookie нет;
  - tab: Set-Cookie без Expires, строку продлевает touch.
- **lifetime-change:**
  - tab → week: Expires есть;
  - week → tab: сессионная кука;
  - старый sid недействителен;
  - неверное значение — ошибка.
- **auth-removed:**
  - удалённые маршруты с валидным CSRF → JSON-404;
  - без токена → 403;
  - `purpose=register` → 400;
  - в `/api/user` нет `email`.
- **double-register:** 409 `already-authenticated`.
- **account:**
  - удаление стирает всё;
  - сокет закрыт;
  - копия куки во втором клиенте недействительна;
  - есть `Clear-Site-Data`;
  - `/api/logout` работает как псевдоним.
- **read-receipts:** у нового аккаунта события `messagesRead` нет; когда отметки включены у обоих — есть.
- **files-audio (T1.3a):**
  - загрузка `audio/mpeg`, `audio/ogg`, `audio/wav`, `audio/webm` → 400 с текстом «Разрешены только фото, видео, PDF и TXT»;
  - `video/webm` с сигнатурой OggS → 400.
- **bot (T1.3b):**
  - каждая подпись из `quickReplies` и каждое ключевое слово через сокет дают ответ своей темы;
  - приветствие заканчивается «Напишите „гайд“, чтобы узнать, как всё устроено»;
  - `quickReplies` есть только у чата с ботом.
- **forbidden-terms**, правила этапов 1–2 (обоснования — в docs/dev/forbidden-terms.md):
  - `email|password|/api/login|register-btn|парол` в server.js, lib/**, public/** (кроме vendor), test/*.test.js;
    разрешены сброс схемы, проверка `url.password` в security-utils, env-check, фраза интерфейса «ни email, ни
    телефона, ни паролей»;
  - `record|mic|голосов|MediaRecorder|getUserMedia|audio/` в прод-коде; разрешено `microphone=()`.
