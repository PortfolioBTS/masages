# Nyxo Messenger

Мессенджер на Node.js/Express/Socket.io с PostgreSQL. Поддерживает обычную и
анонимную регистрацию, 1:1 и групповые чаты, файлы, реакции, ответы на
сообщения, disappearing messages, поиск. Текст сообщений шифруется перед
записью в БД.

## Стек

- Backend: Node.js, Express 4, Socket.io 4, PostgreSQL (`pg`)
- Сессии: `express-session` + `connect-pg-simple` (хранилище сессий — та же БД)
- Пароли: `bcryptjs`
- Файлы: `multer` (диск), `sharp` (снятие метаданных из изображений)
- Frontend: без фреймворка — HTML/CSS/vanilla JS (`public/`)
- Опционально, отдельными процессами: два Rust-сервиса — `anon-service`
  (генерация анонимных identity) и `e2ee-key-server` (хранение E2EE-ключей).
  Оба не обязательны для работы приложения — см. раздел "Опциональные
  компоненты".

## Запуск

```
npm install
cp .env.example .env    # заполнить переменные, см. ниже
npm start                # или: npm run dev
```

Точка входа — `server.js`. По умолчанию слушает `0.0.0.0:3000`.

При старте `server.js` сам создаёт недостающие таблицы и накатывает миграции
(`initDatabase()` в начале файла) — отдельный шаг миграции не нужен.
`database.sql` — best-effort слепок схемы для тех, кто хочет накатить её
вручную; при расхождении верен `server.js`, а не этот файл.

## Переменные окружения

| Переменная | Обязательна | Назначение |
|---|---|---|
| `SESSION_SECRET` | да | секрет для подписи сессионных cookie, ≥32 символов |
| `DATABASE_URL` | да | строка подключения к PostgreSQL |
| `MESSAGE_ENCRYPTION_KEY` | да | ключ AES-256-GCM (32 байта в base64) для шифрования текста сообщений перед записью в БД. Без него сервер не стартует. Генерация: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` |
| `NODE_ENV` | нет | `production` — сервер поднимается на чистом HTTP (TLS предполагается на уровне прокси/хостинга), cookie `secure`/`sameSite=none`. Иначе — пробует локальный HTTPS через `localhost+1.pem`/`localhost+1-key.pem` (mkcert), при их отсутствии — HTTP с предупреждением в консоль |
| `PORT`, `HOST` | нет | адрес и порт (по умолчанию `3000`, `0.0.0.0`) |
| `ANON_SERVICE_URL` | нет | адрес `anon-service` (генератор анонимных имён/кодов). Недоступен — используется встроенный JS-фоллбэк, деградации функциональности нет |
| `INTERNAL_KEY_SERVER_SECRET`, `KEY_SERVER_URL` | нет | адрес и секрет `e2ee-key-server`. Клиентского E2EE-шифрования в браузере в проекте нет — см. "Известные ограничения" |
| `TOR_PROXY_HOST`, `TOR_PROXY_PORT`, `ENABLE_TOR_ROUTING` | нет | Tor routing, требует дополнительно настроенного hidden service |
| `CF_IP_RANGES` | нет | переопределение диапазонов IP Cloudflare (через запятую), используется для доверия заголовку `CF-Connecting-IP` при определении реального IP клиента для rate-limit |
| `DB_CA_CERT` | нет (обязательна в production при SSL-подключении к управляемому Postgres) | цепочка сертификатов CA |
| `DUMP_CA` | нет, разовая утилита | `DUMP_CA=true npm start` — сервер подключается к БД, печатает в консоль цепочку сертификатов и завершает процесс. Используется один раз, чтобы получить значение для `DB_CA_CERT` |

## Реализовано

- Регистрация (обычная по email/паролю и анонимная), логин, сессии в БД
- 1:1 чаты и групповые комнаты (таблицы `rooms`/`room_participants`, вход по
  инвайт-коду)
- Отправка, редактирование, удаление сообщений (soft-delete), реакции
  (фиксированный набор из 5 эмодзи), ответы на сообщения
- Файлы: загрузка с проверкой magic bytes (содержимое файла должно
  соответствовать заявленному MIME-типу), белый список типов, снятие
  EXIF/метаданных из изображений и PDF, отдача файла только участникам
  соответствующего чата/комнаты
- Disappearing messages: удаление по таймеру и по факту прочтения. Технически
  это soft-delete — строка в БД остаётся, `text` заменяется на плейсхолдер и
  выставляется `deleted=1`, сама запись не удаляется
- Поиск по названиям чатов (SQL `ILIKE`) и по тексту сообщений (текст
  зашифрован в БД — поиск идёт расшифровкой кандидатов и фильтрацией на
  стороне приложения, не SQL `LIKE`)
- Rate limiting на login/register/смену пароля/API (`express-rate-limit`,
  ключ — реальный IP с учётом Cloudflare)
- CSRF-токен в cookie + заголовке на все небезопасные методы
- Экранирование пользовательского текста на фронте (без `innerHTML` для
  сообщений), CSP-заголовки
- Шифрование текста сообщений (AES-256-GCM) непосредственно перед записью в
  БД и расшифровка при чтении — см. раздел ниже

## Известные ограничения

- **E2EE не реализован end-to-end.** Есть отдельная инфраструктура —
  Rust-сервис `e2ee-key-server` и API-эндпоинты для работы с ключами (X3DH),
  но клиентского шифрования в браузере (`public/script.js`) нет. Сообщения
  идут на сервер открытым текстом по HTTPS и шифруются только в момент
  записи в БД — см. модель угроз ниже.
- **Tor routing** требует ручной настройки hidden service на хосте и
  `ENABLE_TOR_ROUTING=true`; сам код только проксирует запросы через
  указанный SOCKS5, поднятие Tor-демона — вне зоны ответственности этого
  репозитория.
- **Disappearing messages не удаляют данные физически** (см. выше) — если
  требуется полное удаление строки, `lib/disappearing-messages.js` нужно
  менять на `DELETE FROM messages` вместо `UPDATE ... SET deleted = 1`.
- Существующие сообщения, записанные до включения `MESSAGE_ENCRYPTION_KEY`,
  остаются в БД открытым текстом — обратная миграция (шифрование задним
  числом) не выполняется автоматически.

## Модель безопасности шифрования сообщений

`lib/message-crypto.js` шифрует `messages.text` по алгоритму AES-256-GCM
непосредственно перед `INSERT`/`UPDATE` и расшифровывает при чтении. Ключ
хранится только в переменной окружения `MESSAGE_ENCRYPTION_KEY`.

Защищает: дамп/бэкап БД, утечку на стороне хостера Postgres, чтение базы
в обход приложения — без ключа это нечитаемые байты.

Не защищает: компрометацию самого процесса Node.js/переменных окружения —
у кого есть `MESSAGE_ENCRYPTION_KEY` и доступ к серверу, тот расшифрует
данные так же, как это делает само приложение при каждом запросе. Это
шифрование на стороне сервера ("at rest"), а не end-to-end.

## Структура проекта

```
server.js                  # весь backend: маршруты, Socket.io, initDatabase()
lib/
  message-crypto.js        # шифрование/расшифровка текста сообщений
  disappearing-messages.js # таймеры удаления сообщений
  metadata-stripper.js     # снятие EXIF/метаданных из файлов
  privacy.js                # санитайзинг текста, IP-анонимизация, заголовки приватности
  e2ee-proxy.js             # прокси к e2ee-key-server
  tor-support.js            # поддержка Tor/SOCKS5
public/                    # frontend (index.html, script.js, style.css)
anon-service/               # опциональный Rust-сервис генерации анонимных identity
e2ee-key-server/            # опциональный Rust-сервис хранения E2EE-ключей
database.sql                 # слепок схемы БД (см. выше про приоритет server.js)
```

## API

Аутентификация — сессионная cookie; на все небезопасные методы (кроме
`/socket.io`) требуется заголовок `X-CSRF-Token`, совпадающий со значением
cookie `csrf_token`.

- `POST /api/register`, `POST /api/register/anonymous`, `POST /api/login`,
  `POST /api/logout`, `GET /api/auth`, `GET /api/user`,
  `POST /api/user/avatar-color`, `POST /api/change-password`
- `GET /api/chats`, `POST /api/chats`, `DELETE /api/chats/:chatId`,
  `GET /api/chats/invite/:chatId`, `POST /api/chats/join`
- `GET /api/messages/:chatId`, `POST /api/messages`,
  `PUT /api/messages/:messageId`, `DELETE /api/messages/:messageId`,
  `POST /api/messages/file`
- `POST /api/reactions`, `DELETE /api/reactions/:messageId/:emoji`
- `GET /api/search?q=`
- `POST /api/messages/:messageId/set-expiry`,
  `POST /api/chats/:chatId/set-default-expiry`,
  `GET /api/chats/:chatId/settings`
- `GET /uploads/:filename` — отдача файла, только участникам чата/комнаты
- Socket.io события: `joinChat` (клиент → сервер), `newMessage`,
  `messageEdited`, `messageDeleted` (сервер → клиент)

Формат ответа JSON-эндпоинтов — `{ success: boolean, ... }`, HTTP-статус в
большинстве случаев остаётся `200` даже при ошибке (сама ошибка — в поле
`success`/`message`); отдельные коды `401`/`403`/`404`/`500` используются
в `/api/messages/file` и `/uploads/:filename`.
