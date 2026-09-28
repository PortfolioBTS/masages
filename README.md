# Nyxo Messenger

Мессенджер на Node.js/Express/Socket.io с PostgreSQL. Обычная и анонимная
регистрация, 1:1 и групповые чаты, файлы, реакции, ответы, исчезающие
сообщения, поиск. Сквозное шифрование (E2EE) в комнатах включено по
умолчанию: постквантовый гибрид PQXDH (X25519 + ML-KEM-768) и Sender Keys, с
кодами безопасности как в Signal. Файлы в комнатах шифруются в браузере.

## Интерфейс

- Строгий чёрно-белый монохром без цветовых оттенков, тёмная и светлая
  тема (по умолчанию — как в системе, переключатель в сайдбаре и профиле).
- Иконки вместо эмодзи: SVG-спрайт на основе Lucide (ISC) и собственный знак
  Nyxo (`public/icons.js`), реакции тоже иконками.
- PWA: `manifest.webmanifest`, значки 192/512/maskable, apple-touch-icon.
- Адаптивная вёрстка (≤ 768 px — одна колонка), фокус с клавиатуры,
  `prefers-reduced-motion`.

## Возможности

- **Исчезающие сообщения на всю комнату** (5 мин / 1 ч / 1 д / 7 д): таймер
  общий для всех участников, виден в шапке, изменения — служебной строкой.
- **Приглашения:** код 26 символов и QR-код ссылки `…/#join=КОД` (фрагмент не
  уходит на сервер), срок действия, лимит участников, вступление после
  одобрения (включено по умолчанию), отключение кода.
- **Заявки на вступление:** заявитель видит «ожидает одобрения», участники —
  полосу заявок и кнопки «Впустить/Отклонить». Принятый участник видит только
  сообщения после одобрения, ключ E2EE ему передаётся автоматически.
- **Чаты:** закрепление, режим «без звука», архив.
- **Приватный режим:** срок жизни аккаунта — пока открыта вкладка / 1 день /
  7 дней без активности (не дольше 7 дней), обратный отсчёт в сайдбаре.
- **Журнал безопасности** в профиле: входы, неудачные попытки, смена пароля —
  без IP, только семейство браузера и ОС.
- **Выход со стиранием данных устройства:** ключи E2EE и локальные настройки
  удаляются, ключи отзываются на сервере.
- **Файлы:** перетаскивание, несколько файлов за раз, прогресс и отмена.
- Кнопка «вниз» со счётчиком новых сообщений, индикатор соединения,
  уведомления без текста сообщения и имени отправителя.

## Стек

- Backend: Node.js 24, Express 4, Socket.io 4, PostgreSQL (`pg`)
- Сессии: `express-session` + `connect-pg-simple` (хранилище сессий — та же БД)
- Пароли: bcrypt (`bcryptjs`) поверх HMAC-SHA256 — см. `lib/passwords.js`
- Файлы: `multer` (диск), `sharp` (изображения), собственный изоморфный
  очиститель метаданных `public/media-sanitizer.js` (видео, аудио, PDF — и на
  сервере, и в браузере перед шифрованием)
- Frontend: без фреймворка и сборщика — HTML/CSS/vanilla JS (`public/`)
- Криптография клиента: только Web Crypto API + собственная реализация
  ML-KEM-768 по FIPS 203 (`public/mlkem.js`, сверена с реализацией Node побайтно)
- Отдельные сервисы:
  - `e2ee-key-server` (Rust) — хранение публичных E2EE-ключей;
  - `anon-service` (Rust, необязательный) — генерация анонимных имён;
  - `tor-service` (tor + socat, необязательный) — onion-адрес.

## Запуск

```
npm install
cp .env.example .env    # заполнить переменные, см. ниже
npm start                # или: npm run dev (перезапуск при изменении файлов)
npm test                 # тесты без БД
```

Точка входа — `server.js`. По умолчанию слушает `0.0.0.0:3000`.

При старте `server.js` сам создаёт недостающие таблицы и накатывает миграции
(`initDatabase()`) — отдельный шаг миграции не нужен. Порт открывается только
после завершения миграций. Миграции идемпотентны: повторный старт ничего не
перестраивает. `database.sql` — слепок схемы для ручного наката; при
расхождении верен `server.js`.

Первый запуск этой версии на существующей БД:

- перевыпускает все старые короткие инвайт-коды (уже разосланные коды
  перестанут работать — участникам нужно отправить новые);
- обезличивает имена ранее загруженных файлов;
- физически удаляет строки сообщений, помеченные удалёнными в старой схеме;
- новые пользователи, комнаты и чаты получают случайные id (старые не меняются).

## Переменные окружения

| Переменная | Обязательна | Назначение |
|---|---|---|
| `SESSION_SECRET` | да | секрет подписи сессионных cookie, ≥32 символов |
| `DATABASE_URL` | да | строка подключения к PostgreSQL (13+) |
| `MESSAGE_ENCRYPTION_KEY` | да | ключ AES-256-GCM (32 байта в base64) для шифрования текста сообщений в БД. Генерация: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` |
| `MESSAGE_ENCRYPTION_KEY_PREVIOUS` | нет | старые ключи через запятую — только для расшифровки, для ротации ключа без перешифровки всей таблицы |
| `NODE_ENV` | нет | `production` — чистый HTTP за прокси хостинга (TLS там), HSTS, Secure-cookie. Иначе — локальный HTTPS через `localhost+1.pem` (mkcert) или HTTP |
| `PORT`, `HOST` | нет | порт и адрес (по умолчанию `3000`, `0.0.0.0`). Для private network Railway — `HOST=::` |
| `DB_CA_CERT` | в production — да, кроме случаев ниже | цепочка CA для TLS к Postgres. Без неё сервер в production стартует, только если хост `DATABASE_URL` оканчивается на `.railway.internal` (приватная сеть) или задан `DB_TLS_INSECURE=true` |
| `DB_TLS_INSECURE` | нет | `true` — осознанно подключаться к Postgres без проверки сертификата |
| `DUMP_CA` | разовая утилита | `DUMP_CA=true npm start` — печатает цепочку сертификатов БД для `DB_CA_CERT` и завершает процесс |
| `PG_POOL_MAX` | нет | размер пула соединений (по умолчанию `10`) |
| `INTERNAL_KEY_SERVER_SECRET`, `KEY_SERVER_URL` | для E2EE | секрет (≥32 символов) и адрес `e2ee-key-server`. Без них E2EE недоступно: клиент один раз предупредит и будет отправлять без сквозного шифрования |
| `ANON_SERVICE_URL`, `ANON_SERVICE_SECRET` | нет | адрес и общий секрет `anon-service`. Не задан — встроенный генератор |
| `UPLOADS_DIR` | нет | папка вложений. По умолчанию — `RAILWAY_VOLUME_MOUNT_PATH`, иначе `./uploads`. Нужен постоянный диск |
| `UPLOAD_QUOTA_MB` | нет | квота вложений на пользователя (по умолчанию `500`) |
| `INVITE_TTL_HOURS` | нет | срок жизни инвайт-кода (по умолчанию `168` — неделя) |
| `ALLOWED_ORIGINS` | нет | дополнительные разрешённые источники (через запятую) для HTTP и WebSocket. Свой хост и onion-адрес разрешены всегда |
| `POW_DIFFICULTY` | нет | сложность proof-of-work при регистрации, 8..28 бит (по умолчанию `18`, ~0,1 с в браузере с JIT) |
| `PASSWORD_PEPPER` | нет | секрет для HMAC паролей. После запуска **нельзя менять или терять** — все пароли перестанут сходиться |
| `HIBP_CHECK` | нет | `true` — проверять новые пароли по базе утечек Have I Been Pwned (k-anonymity). По умолчанию выключено: это запрос к третьей стороне |
| `ONION_ADDRESS`, `ONION_PORT` | нет | onion-адрес и внутренний порт для `tor-service` — см. `tor-service/README.md` |
| `CF_IP_RANGES` | нет | переопределение диапазонов IP Cloudflare для доверия `CF-Connecting-IP` |
| `DEFAULT_MESSAGE_EXPIRY_SECONDS` | нет | если `> 0` — срок жизни новых сообщений, для которых в чате не задан свой |
| `CLEANUP_INTERVAL_MS` | нет | период удаления просроченных сообщений (по умолчанию `60000`) |

## Безопасность и приватность

### Сквозное шифрование (E2EE)

`public/e2ee.js` — клиент поверх Web Crypto API, без внешних библиотек и
сборщика. Тот же файл прогоняется в протокольных тестах под Node.

- **Обмен ключами — PQXDH-гибрид.** X3DH на X25519/Ed25519 плюс ML-KEM-768
  (`public/mlkem.js`). Подписанный постквантовый prekey обязателен: отката на
  классический X3DH нет, сервер не может понизить версию протокола.
- **Сообщения — Sender Keys** (как группы Signal): KDF-цепочка на каждое
  сообщение, подпись отправителя, AAD с комнатой, отправителем и ключом.
- **Коды безопасности** (окно «Участники и ключи» в шапке комнаты): 60 цифр,
  как в Signal. Identity-ключ собеседника закрепляется при первом контакте;
  смена ключа показывается баннером, и сообщения такому собеседнику не
  уходят, пока пользователь не примет новый ключ.
- **Состав комнаты** запоминается на устройстве: вход и выход участников
  показываются в ленте, при выходе участника свой Sender Key ротируется.
- **Защита от повтора**: сервер не может выдать старый конверт за новое
  сообщение.
- **Паддинг** (Padmé): длина шифротекста не выдаёт длину сообщения.
- **Файлы** в комнатах: очистка метаданных в браузере → AES-256-GCM со
  случайным ключом → сервер хранит непрозрачный `.bin` без имени и типа.
- **Ключи на устройстве** — неизвлекаемые `CryptoKey` в IndexedDB (XSS не
  может их выгрузить). Signed prekey и PQ-prekey ротируются раз в 7 дней.
- Канал доставки Sender Key — симметричная цепочка с удалением использованных
  ключей (прямая секретность).

Честные ограничения E2EE:

- код клиента доставляет тот же сервер (свойство любого веб-E2EE);
- сервер видит метаданные: кто в какой комнате, когда и кому пишет;
- состав комнаты задаёт сервер — клиент только показывает его изменения;
- нет post-compromise security для Sender Keys, кроме ротации при выходе
  участника; ключи истории хранятся на устройстве (иначе после перезагрузки
  история не открывалась бы);
- первый контакт — TOFU, пока коды безопасности не сверены;
- одно устройство на аккаунт;
- PQ-prekey — один подписанный «last resort» ключ, без одноразовых PQ-prekey.

### Шифрование в БД

`lib/message-crypto.js`: текст сообщений (в том числе E2EE-конверты)
шифруется AES-256-GCM перед записью. Формат `enc:v2` привязан к комнате и
отправителю через AAD — шифротекст, перенесённый в другую комнату или строку,
не расшифруется. Ключ выбирается по kid, поэтому его можно ротировать через
`MESSAGE_ENCRYPTION_KEY_PREVIOUS`. Старые записи `enc:v1` читаются.

Не защищает от компрометации самого сервера приложения: у кого есть ключ и
процесс, тот расшифрует незашифрованные E2EE сообщения (например, чат с
ботом) так же, как сервер.

### Веб-безопасность

- CSRF-токен + проверка Origin на всех небезопасных запросах.
- Рукопожатие Socket.io — только со своего Origin (защита от Cross-Site
  WebSocket Hijacking); сессионная кука `SameSite=Lax`.
- CSP с nonce, без `unsafe-inline`; `worker-src`, `connect-src` ограничены
  своим хостом; HSTS в production; `Referrer-Policy: no-referrer`.
- Rate limiting: по IP (с проверкой Cloudflare), по аккаунту (вход, API,
  сокеты), лимиты на запрос чужих ключей.
- Регистрация защищена proof-of-work (`lib/pow.js`, `public/pow-worker.js`).
- Пароли: политика по NIST SP 800-63B (8..256 символов, блок-лист частых
  паролей, без правил состава), bcrypt поверх HMAC — без обрезки на 72 байтах,
  старые хэши перехэшируются при входе.

### Анонимность и метаданные

- Анонимный вход без почты и телефона; данные удаляются при выходе или после
  выбранного срока неактивности (30 минут после закрытия вкладки, 1 день или
  7 дней, не дольше 7 дней от создания). На устройстве при этом стираются
  ключи E2EE и локальные настройки, сервер присылает `Clear-Site-Data: "cache"`.
- Метаданные снимаются со всех разрешённых типов файлов: EXIF/GPS/XMP,
  GPS-дорожки видео (GoPro, DJI, Apple), теги MP3/OGG/WAV, PDF. Имена файлов
  обезличиваются.
- Вложения отдаются с `Cache-Control: no-store`.
- Случайные id пользователей, комнат и чатов — по ним нельзя восстановить
  порядок и время регистрации.
- Отметки о прочтении можно отключить (тогда не видны и чужие — как в Signal).
- Удалённые и исчезающие сообщения удаляются физически.
- Инвайт-код — 26 символов (≈130 бит), со сроком жизни, лимитом участников,
  перевыпуском и одобрением вступления (включено по умолчанию, в том числе для
  существующих комнат). Новый участник не видит историю до одобрения.
- Onion-сервис (`tor-service/`) с определением onion-соединений по отдельному
  внутреннему порту.
- Удаление аккаунта — полное: сообщения, файлы, ключи, сессии.

### Известные ограничения

- Метаданные PDF внутри сжатых object streams (PDF 1.5+) не затираются.
- Поиск по тексту работает только по сообщениям без E2EE (последние 500).
- Лимиты и одноразовые токены proof-of-work живут в памяти процесса — при
  нескольких репликах нужен общий стор.
- Rust-сервисы (`e2ee-key-server`, `anon-service`) собираются через свои
  Dockerfile; см. их README.

## Структура проекта

```
server.js                  # backend: маршруты, Socket.io, initDatabase()
lib/
  message-crypto.js        # шифрование текста сообщений в БД (enc:v2, AAD, ротация)
  passwords.js             # хэширование и политика паролей
  pow.js                   # proof-of-work для регистрации
  security-utils.js        # проверка Origin, инвайт-коды, обезличенные имена, семейство User-Agent
  invites.js               # параметры приглашений и заявок
  chat-settings.js         # общий таймер исчезающих сообщений комнаты
  anon-lifetime.js         # срок жизни анонимного аккаунта по неактивности
  disappearing-messages.js # таймеры и физическое удаление сообщений
  metadata-stripper.js     # очистка метаданных вложений на сервере
  privacy.js               # заголовки приватности, санитайзинг текста
  e2ee-proxy.js            # прокси к e2ee-key-server (с проверкой общей комнаты)
  e2ee-groups.js           # участники комнаты + доставка Sender Key
  tor-support.js           # onion-порт, Onion-Location
public/
  index.html, style.css, script.js
  theme.js                 # тёмная/светлая тема без мигания при загрузке
  icons.js                 # SVG-спрайт иконок (Lucide, ISC) и window.Icons
  icons/, manifest.webmanifest  # значки и манифест PWA
  vendor/qrcode.js         # qrcode-generator (MIT) для QR-кода приглашения
  e2ee.js                  # клиентский E2EE (PQXDH + Sender Keys)
  mlkem.js                 # ML-KEM-768 (FIPS 203) на чистом JS
  media-sanitizer.js       # очистка метаданных (браузер + сервер)
  pow-worker.js            # Web Worker для proof-of-work
e2ee-key-server/           # Rust-сервис публичных E2EE-ключей
anon-service/              # Rust-сервис анонимных имён (необязательный)
tor-service/               # onion-сервис для Railway (необязательный)
test/                      # тесты (node test/*.test.js)
database.sql               # слепок схемы БД
```

## API

Аутентификация — сессионная cookie; на все небезопасные методы нужен заголовок
`X-CSRF-Token`, совпадающий с cookie `csrf_token`, и Origin своего сайта.

- `GET /api/pow/challenge?purpose=register|register-anon`
- `POST /api/register`, `POST /api/register/anonymous` (с `pow: {token, nonce}`),
  `POST /api/login`, `POST /api/logout`, `GET /api/auth`, `GET /api/user`,
  `POST /api/user/avatar-color`, `POST /api/user/privacy` (`{readReceipts}`),
  `POST /api/change-password`, `POST /api/account/delete` (`{password?}`)
- `GET /api/chats` (с `pinned`, `muted`, `archived`, `member_count`,
  `expiry_seconds`), `POST /api/chats`, `DELETE /api/chats/:chatId`,
  `POST /api/chats/:chatId/prefs` (`{pinned?, muted?, archived?}`),
  `POST /api/chats/:chatId/expiry` (`{seconds}`: 0/300/3600/86400/604800),
  `GET /api/chats/:chatId/participants`
- Приглашения: `GET /api/chats/invite/:chatId`,
  `POST /api/chats/:chatId/invite/rotate` (`{ttlSeconds, maxMembers, requireApproval}`),
  `POST /api/chats/:chatId/invite/disable`, `POST /api/chats/join/preview`,
  `POST /api/chats/join` (с одобрением → `{pending, requestId}`)
- Заявки: `GET /api/chats/:chatId/join-requests`,
  `POST /api/join-requests/:id/approve`, `POST /api/join-requests/:id/deny`,
  `GET /api/join-requests/mine`, `DELETE /api/join-requests/:id`
- `GET /api/security-events`
- `GET /api/messages/:chatId?before=<id>&limit=<1..200>`,
  `POST /api/chats/:chatId/read`, `POST /api/messages`,
  `PUT /api/messages/:messageId`, `DELETE /api/messages/:messageId`,
  `POST /api/messages/file` (для E2EE: поля `encrypted=true` и `envelope` до файла)
- `POST /api/reactions`, `DELETE /api/reactions/:messageId/:emoji`
- `GET /api/search?q=`
- `POST /api/messages/:messageId/set-expiry`,
  `POST /api/chats/:chatId/set-default-expiry`, `GET /api/chats/:chatId/settings`
- E2EE: `PUT /api/keys/identity`, `PUT /api/keys/signed-prekey`,
  `PUT /api/keys/pq-prekey`, `POST /api/keys/one-time-prekeys`,
  `GET /api/keys/one-time-prekeys/count`, `GET /api/keys/identities?ids=`,
  `GET /api/keys/bundle/:targetUserId`, `DELETE /api/keys`,
  `POST /api/keys/key-shares`, `GET /api/keys/key-shares/:chatId`
- `GET /uploads/:filename` — только участникам чата, вступившим до сообщения
- Socket.io: `joinChat` (клиент → сервер); `newMessage`, `messageEdited`,
  `messageDeleted`, `messagesRead`, `e2eeKeyShare`, `roomMembersChanged`,
  `chatExpiryChanged`, `joinRequestsChanged`, `joinRequestDecided`,
  `chatListChanged` (сервер → клиент)

## Тесты

Без Postgres и Rust-сервисов — фейковые БД/сервер в памяти, чистый Node:

```
npm test                            # все наборы ниже
node test/mlkem.test.js            # ML-KEM-768 и SHA-3 против реализации Node
node test/e2ee.protocol.test.js    # PQXDH, Sender Keys, коды безопасности,
                                    # смена ключа, повтор, паддинг, файлы, ротация
node test/media-sanitizer.test.js  # очистка метаданных всех форматов + фазз
node test/server-routes.test.js    # прокси ключей, участники, key-shares
node test/server-libs.test.js      # шифрование в БД, пароли, заголовки
node test/security-utils.test.js   # Origin, инвайт-коды, имена файлов
node test/pow.test.js              # proof-of-work и onion-порт
node test/lib.test.js              # metadata-stripper, исчезающие сообщения
```
