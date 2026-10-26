# Nyxo Messenger

Анонимный веб-мессенджер со сквозным шифрованием на Node.js, Express, Socket.io и PostgreSQL. Без номера, почты и регистрации: аккаунт временный, имя выдаётся случайное, а когда выбранный срок без активности кончается, аккаунт и его сообщения удаляются. Группы, приглашения по ссылке и QR, файлы, ответы, реакции, исчезающие сообщения. Клиент — обычная страница без фреймворка и сборщика.

Что защищено и что нет, сказано честно в [модели угроз](docs/threat-model.md). Коротко: содержимое групп сервер прочитать не может, но видит, кто в каких группах состоит и когда подключён, а код клиента вы получаете от того же сервера.

## Возможности

**Аккаунт**
- Временный анонимный аккаунт: срок хранения выбирается при входе и меняется в «Профиле» — пока открыта вкладка (аккаунт удаляется через 30 минут после закрытия последней вкладки), 1 день или 7 дней без активности. Потолка от даты создания нет: пока человек заходит, аккаунт живёт. В боковой панели постоянно написано, когда аккаунт удалится.
- Создание аккаунта защищено proof-of-work, лимитами и CSRF-токеном. Массовым регистрациям мешают потолок в минуту на весь сервер (в том числе через onion) и рост сложности proof-of-work, когда темп выше обычного; у аккаунта есть суточная квота текста и потолок числа комнат.
- «Удалить и выйти» удаляет аккаунт, сообщения (в том числе у собеседников), файлы и ключи на сервере и стирает ключи и настройки на устройстве.
- Восстановления нет: аккаунт живёт только в этом браузере.

**Группы и приглашения**
- Код приглашения — 26 символов; ссылка `…/#join=КОД.СЕКРЕТ` и QR на неё. Фрагмент ссылки не уходит на сервер.
- По умолчанию вход идёт через заявку: её одобряет любой участник, и одобрение подписывается его ключом. Если одобрение выключить, ссылка с секретом впускает сразу (вход подписан приглашением), а код без секрета всё равно даёт только заявку.
- Срок кода (до 30 суток), лимит участников, новый код и отключение; когда участник выходит, код заменяется, а подписанная ссылка сбрасывается.
- Новый участник не видит сообщения, отправленные до его вступления.

**Шифрование** (обязательно для групп, выключателя нет)
- Обмен ключами PQXDH: X25519 плюс ML-KEM-768 с одноразовыми PQ-prekey; сообщения — Sender Keys с ротацией раз в 100 сообщений или 7 дней и при выходе участника.
- Коды безопасности (60 цифр) в окне «Участники и ключи»; смена ключа собеседника блокирует передачу ему ключа группы до явного подтверждения. Принять новый ключ можно только там, где собеседник был подтверждён до смены: в группе, где его никто не подписывал, он остаётся неподтверждённым. Если ключ группы некому передать (остальные участники не подтверждены, сменили ключ или расходятся с журналом), отправка блокируется с причиной `keys-withheld` и просьбой подтвердить участников: иначе сообщение не прочитал бы никто, в том числе подтверждённый позже.
- Подписанный состав группы: участник без подписи допуска помечен «не подтверждён» и ключа группы не получает, пока вы не нажмёте «Доверять участнику». Если у вас самого нет записи о способе входа (учётную запись добавил сервер или данные устройства потеряны), окно участников пишет «Способ входа в группу неизвестен» (`how = unknown`), а не «Вы создали группу».
- Журнал ключей (прозрачность ключей): работает, если оператор задал `KT_SIGNING_KEY`; выявляет подмену ключа сервером, но не защищает от сервера, который с самого начала показывает разным группам разные журналы. Открытый ключ журнала публикуется в `/client-manifest.json` (`keys.kt`) и в релизе (переменная репозитория `KT_PUBLIC_KEY`); клиент сверяет его при первом закреплении ([docs/VERIFY.md](docs/VERIFY.md)). Клиент сам проверяет журнал на чужие записи под своей меткой: если самопроверка не удаётся довести до конца 6 часов подряд (сервер не отдаёт данные `/api/kt/self`), поднимается отдельная тревога `self-unreachable`, а ответ 404 на поколение, которое сервер обязан отдавать, — тревога `log-fork`.
- Режим «Не хранить историю на этом устройстве» для группы; исчезающие сообщения стирают ключи вместе с сообщениями.
- Скрытие автора сообщения на хранении (sealed sender): в базе у сообщения группы нет ссылки на аккаунт, есть только недельный тег. Косвенные признаки (позиция чтения, время активности, квота вложений) остаются, поэтому анонимным дамп не считается.

**Сообщения и файлы**
- Ответы, реакции, правка и удаление своих сообщений, общий для группы таймер исчезающих сообщений (5 минут, 1 час, 1 день, 7 дней), время сообщений огрублено до минуты.
- Отметки о прочтении выключены по умолчанию и работают взаимно; уведомления выключены по умолчанию, приходят только при скрытой вкладке и без текста.
- Поиск работает только на устройстве: по названиям чатов и по сообщениям, загруженным в браузер.
- Файлы: фото, видео, PDF и TXT, до 50 МБ и до 10 за раз; метаданные удаляются в браузере до шифрования; в группах файл шифруется на устройстве, сервер видит только размер. PDF со сжатыми метаданными отклоняется. Открытые вложения (их принимает только чат с ботом) сервер разбирает сам и защищается от «бомб»: по умолчанию изображение крупнее 24 Мпикс (у анимации — на все кадры вместе) или длиннее 500 кадров отклоняется до декодирования, файлы обрабатываются по одному, а когда очередь из четырёх ожидающих полна, сервер отвечает 503 с `Retry-After` (пределы задаются переменными из таблицы ниже).
- Чат с ботом-помощником (гайд по мессенджеру) сквозным шифрованием не защищён, и интерфейс об этом говорит.

**Проверка кода клиента**
- Манифест SHA-256 всех файлов клиента (`/client-manifest.json`), релиз с аттестацией, сверка скриптом `scripts/verify-deployment.js`, страница `/verify.html`, ежедневный сторож в CI ([docs/VERIFY.md](docs/VERIFY.md)).
- Закрепление версии кода в service worker: новая версия включается только после согласия пользователя ([docs/ops/service-worker.md](docs/ops/service-worker.md)).

**Прочее**
- Onion-сервис для Tor Browser (`tor-service/`, необязателен).
- Интерфейс: строгий монохром, тёмная и светлая тема, иконки на SVG-спрайте (`public/icons.js`), PWA-манифест, адаптивная вёрстка (до 768 px — одна колонка), `prefers-reduced-motion`.
- Эксплуатация: `/healthz`, `/readyz`, `/metrics` по токену, `/.well-known/security.txt`, точные лимиты в PostgreSQL.

## Стек

- Сервер: Node.js 24, Express 4, Socket.io 4, PostgreSQL 13+ (`pg`); сессии — `express-session` и `connect-pg-simple` в той же базе.
- Файлы: `multer` (диск или volume), `sharp` (изображения на сервере для открытых вложений), собственный изоморфный очиститель метаданных `public/media-sanitizer.js` (работает и в браузере перед шифрованием, и на сервере).
- Клиент: HTML, CSS и vanilla JS из `public/`, без сборщика. Криптография — Web Crypto API и собственная реализация ML-KEM-768 по FIPS 203 (`public/mlkem.js`, сверена с реализацией Node побайтно, независимого аудита не было). Вендорные библиотеки: `socket.io` и `qrcode-generator` (`public/vendor/`).
- Ключи шифрования клиентов хранит встроенное хранилище `lib/key-store.js` в той же базе: отдельных сервисов для ключей и имён нет. Необязательный отдельный сервис один — `tor-service/` (tor и socat для onion-адреса).

## Запуск

```
npm install
cp .env.example .env    # задать SESSION_SECRET, DATABASE_URL, MESSAGE_ENCRYPTION_KEY
npm start               # или npm run dev (перезапуск при изменении файлов)
```

Нужны Node.js 24 и PostgreSQL 13+. По умолчанию сервер слушает `0.0.0.0:3000`; вне production он поднимает HTTPS, если рядом лежат `localhost+1.pem` и `localhost+1-key.pem` (mkcert), иначе HTTP. Для быстрой проверки интерфейса `npm run dev:local -- --port 3101` сам поднимает временный PostgreSQL в Docker ([docs/dev/testing.md](docs/dev/testing.md)).

При старте сервер (`server.js` → `src/lifecycle.js`) сам создаёт схему и накатывает миграции (`initDatabase()`, [docs/dev/migrations.md](docs/dev/migrations.md)); порт открывается только после них. Версия схемы записана в таблице `schema_meta`: если она новее кода, сервер не стартует. Если в базе схема прежней версии 2.0.0, при первом запуске она один раз полностью сбрасывается вместе с файлами вложений: реальных пользователей на тот момент не было ([docs/ops/deploy-railway.md](docs/ops/deploy-railway.md)). Источник истины схемы — `initDatabase()` в `src/db/schema.js`; `database.sql` — слепок, сгенерированный из него.

Проверка настроек и секретов выполняется при каждом старте (значения не печатаются) и вручную:

```
npm run check-env              # локально, читает .env
railway run npm run check-env  # с переменными сервиса на Railway
```

Развёртывание на Railway шаг за шагом — [docs/ops/stage-0-checklist.md](docs/ops/stage-0-checklist.md) и [docs/ops/deploy-railway.md](docs/ops/deploy-railway.md).

## Переменные окружения

Полная таблица с рекомендациями, значениями по умолчанию и ротацией — [docs/ops/deploy-railway.md](docs/ops/deploy-railway.md); образец файла — `.env.example`. Главное:

| Переменная | Обязательна | Назначение |
|---|---|---|
| `SESSION_SECRET` | да | секрет подписи сессий, не короче 32 символов; из него же выводятся ключи лимитов, CSRF и proof-of-work |
| `DATABASE_URL` | да | подключение к PostgreSQL; в production хост `*.railway.internal` или заданный `DB_CA_CERT` |
| `MESSAGE_ENCRYPTION_KEY` | да | ключ слоя шифрования сообщений на сервере (AES-256-GCM, 32 байта в base64); без него сервер не стартует, потеря делает сохранённые сообщения нечитаемыми |
| `NODE_ENV` | в production — да | `production`: HTTP за прокси хостинга, HSTS, cookie с `Secure` |
| `UPLOADS_DIR`, `UPLOAD_QUOTA_MB` | нет | папка вложений (на Railway — volume) и квота на 30 суток |
| `IMAGE_MAX_PIXELS`, `IMAGE_MAX_FRAMES`, `UPLOAD_PROCESS_CONCURRENCY`, `UPLOAD_PROCESS_QUEUE` | нет | обработка открытых вложений: потолок пикселей изображения (24 000 000; у анимации — на все кадры вместе) и кадров GIF/WebP (500), сколько файлов обрабатывается одновременно (1) и сколько ждёт очереди (4; дальше 503 с `Retry-After`) |
| `REGISTER_GLOBAL_PER_MIN`, `REGISTER_PACE_PER_MIN` | нет | регистраций в минуту на весь сервер (120; сверх потолка 429 `registration-busy`) и обычный темп (20), выше которого растёт сложность proof-of-work |
| `TEXT_QUOTA_MB_PER_DAY`, `ROOMS_PER_USER_MAX` | нет | суточный объём текста сообщений на аккаунт, МБ (20; сверх — 429 `text-quota`) и число комнат на аккаунте (50; сверх — 403 `rooms-limit`) |
| `UPLOAD_MIN_FREE_MB` | нет | свободное место на томе вложений, МБ (256): ниже порога загрузки отклоняются (507 `storage-full`) |
| `UPLOADS_IP_PER_MIN`, `UPLOADS_USER_PER_15MIN` | нет | выдача вложений (`GET /uploads/*`): запросов в минуту с одного IP (600; для onion не считается) и за 15 минут с одного аккаунта (3000); сверх — 429 |
| `OPEN_UPLOADS_PER_10MIN` | нет | открытых вложений (в чат с ботом) за 10 минут на аккаунт (20): их сервер разбирает сам, поэтому частота ограничена до записи файла; сверх — 429 `open-uploads-limit` |
| `SOCKET_EVENT_RATE`, `SOCKET_EVENT_BURST` | нет | события от одного сокета, в секунду в среднем (5) и всплеск (20); клиент почти ничего не шлёт, превысивший частоту сокет закрывается |
| `TRUST_PROXY` | нет | сколько прокси стоит перед приложением: `1` (по умолчанию, край Railway) или `0` (приложение открыто напрямую, заголовки `X-Forwarded-*` игнорируются) |
| `ONION_ALLOWED_CIDR` | нет | кому можно подключаться к `ONION_PORT`: адреса или CIDR через запятую; по умолчанию только частные и loopback-адреса |
| `DB_LOCK_TIMEOUT_MS`, `DB_STATEMENT_TIMEOUT_MS`, `DB_IDLE_TX_TIMEOUT_MS` | нет | таймауты сессии PostgreSQL, мс (5000, 30000, 30000): запрос, не дождавшийся блокировки или своего времени, получает 503 `busy` с `Retry-After`, а не занимает пул соединений |
| `KT_SIGNING_KEY` | нет | ключ подписи журнала ключей; без него журнал выключен. Открытая часть попадает в `/client-manifest.json` (`keys.kt`); релиз получает её из переменной репозитория `KT_PUBLIC_KEY`. Сброс базы требует нового ключа |
| `METRICS_TOKEN` | нет | токен для `/metrics`; без него адрес отвечает 404 |
| `PUBLIC_ORIGIN`, `SECURITY_CONTACT`, `SECURITY_TXT_EXPIRES` | нет | `security.txt` |
| `HSTS_PRELOAD` | нет | `yes` — HSTS preload (только для своего домена) |
| `SW_KILL_SWITCH` | нет | `yes` — аварийно снять закрепление кода в service worker |
| `ONION_ADDRESS`, `ONION_PORT` | нет | onion-адрес и внутренний порт для `tor-service` |
| `ALLOWED_ORIGINS`, `POW_DIFFICULTY`, `INVITE_TTL_HOURS`, `PG_POOL_MAX`, `DEFAULT_MESSAGE_EXPIRY_SECONDS`, `CLEANUP_INTERVAL_MS`, `CF_IP_RANGES`, `DB_CA_CERT`, `DB_TLS_INSECURE`, `PORT`, `HOST`, `MESSAGE_ENCRYPTION_KEY_PREVIOUS`, `KT_SIGNING_KEY_PREVIOUS` | нет | см. [docs/ops/deploy-railway.md](docs/ops/deploy-railway.md) |

У каждого экземпляра свой пул соединений (`PG_POOL_MAX`, по умолчанию 10) плюс отдельные соединения под блокировки задач: суммарное число не должно превышать `max_connections` базы ([docs/ops/scaling.md](docs/ops/scaling.md)).

## Тесты

```
npm test                  # юнит-тесты, без БД, только Node 24; файлы идут пулом до 4 процессов
npm test -- --serial      # по одному, вывод сразу (отладка зависшего файла)
npm run test:coverage     # юнит-тесты с покрытием (информативно, порога нет)
npm run test:e2e          # сквозные: настоящий Postgres 16, E2E_DATABASE_URL
npm run test:e2e:docker   # то же во временном контейнере Docker
npm run test:browser      # смоук в настоящем Chrome/Chromium/Edge (CDP) + Postgres
npm run test:all          # юнит, затем сквозные
```

Как устроены наборы, как запускать один файл и как проверять руками — [docs/dev/testing.md](docs/dev/testing.md); что проверяет CI и как повторить это локально — [docs/dev/ci.md](docs/dev/ci.md). Тесты-запреты, не дающие вернуться удалённому, — [docs/dev/forbidden-terms.md](docs/dev/forbidden-terms.md).

## Безопасность

- Сообщить об уязвимости: [SECURITY.md](SECURITY.md).
- Что защищаем, от кого, что видит и хранит сервер: [docs/threat-model.md](docs/threat-model.md) (версия указана в начале).
- Проверка кода клиента: [docs/VERIFY.md](docs/VERIFY.md).
- Объём независимого аудита криптографии: [docs/security/audit-scope.md](docs/security/audit-scope.md); аудит ещё не проводился.
- Дизайн-документы протоколов: [порядок и идентификаторы сообщений](docs/security/message-ordering.md), [скрытие автора](docs/security/sealed-sender.md), [подписанный состав группы](docs/security/signed-membership.md), [прозрачность ключей](docs/security/key-transparency.md).
- Слой сервера: текст сообщений перед записью в базу шифруется ещё и ключом сервера (`lib/message-crypto.js`, формат `enc:v3` привязан к id сообщения); его снимает тот, у кого есть `MESSAGE_ENCRYPTION_KEY`, поэтому E2EE-слой он не заменяет. Смена ключа — [docs/ops/message-key-rotation.md](docs/ops/message-key-rotation.md).
- Веб-слой: проверка Origin (с сверкой схемы; хост берётся из `X-Forwarded-Host` только при доверенном прокси) и CSRF-токен на изменяющих запросах, отказ 403 любому межсайтовому запросу к `/api` по `Sec-Fetch-Site` (в том числе GET), рукопожатие сокета только со своего Origin, CSP без inline-скриптов, заголовки изоляции, `Referrer-Policy: no-referrer`, вложения с `Cache-Control: no-store`.
- Лимиты нагрузки и ресурсов: потолки обработки изображений (раздел «Сообщения и файлы» выше), глобальный потолок регистраций и рост сложности proof-of-work, суточная квота текста, потолок числа комнат, порог свободного места для загрузок, лимиты выдачи вложений, ограничение частоты событий сокета, таймауты сессии PostgreSQL (все — в таблице переменных). Режим onion включает сам порт `ONION_PORT`, поэтому к нему принимаются только частные и loopback-адреса (`ONION_ALLOWED_CIDR`).

## Известные ограничения

Полный список — раздел 8 [модели угроз](docs/threat-model.md). Главное:

- код клиента доставляет тот же сервер: злонамеренный сервер может выдать изменённый клиент; сверка и закрепление в service worker помогают заметить подмену, но не предотвращают адресную подмену при первом заходе;
- сервер видит метаданные: кто подключён и когда, в каких группах состоит, названия групп, время сообщений до минуты, размеры; автор сообщения скрыт только на хранении (и там выдаётся косвенными признаками дампа), а в момент отправки известен;
- первый контакт с собеседником — на доверии, пока вы не сверили коды безопасности; журнал ключей работает без внешнего свидетеля и необязателен;
- ключи цепочек и seed ML-KEM лежат в IndexedDB открытыми байтами, а история читается, пока ключи не стёрты;
- одно устройство на аккаунт, восстановления нет; чат с ботом не шифруется сквозным шифрованием;
- PDF с метаданными в сжатом виде отклоняется, а картинки внутри PDF сохраняют свои метаданные;
- звук внутри видеоконтейнера не распознаётся, а тип зашифрованного вложения проверяет только клиент отправителя;
- платформенные журналы хостинга видят IP вместе с номерами групп в адресах запросов;
- одна реплика сервера: лимиты `/api` и список сокетов живут в памяти процесса ([docs/ops/scaling.md](docs/ops/scaling.md));
- независимого аудита криптографии не было.

## Структура проекта

```
server.js                  # точка входа (запуск); весь код сервера — в src/
src/                       # config, create-server, context, lifecycle; db/, http/ (middleware/, routes/), realtime/, services/, jobs/
lib/                       # серверные модули (чистые функции и тонкие слои над БД)
  key-store.js, e2ee-keys.js, e2ee-groups.js, e2ee-envelope.js   # публичные ключи, ключи комнат, форма конверта
  kt-log.js, kt-service.js, kt-routes.js                         # журнал ключей
  membership-certs.js, invites.js                                # подписанный состав, приглашения
  author-tag.js, message-ids.js, message-order-schema.js, coarse-time.js  # скрытие автора, порядок и время
  message-crypto.js, message-retag.js, derive-key.js             # слой шифрования сервера, ключи от секретов
  anon-lifetime.js, anon-activity.js, session-store.js, csrf.js, pow.js, pg-limits.js  # аккаунты, сессии, лимиты
  disappearing-messages.js, chat-settings.js, upload-quota.js, metadata-stripper.js    # таймеры, квоты, вложения
  bot-guide.js, privacy.js, security-utils.js, security-txt.js, tor-support.js         # бот, заголовки, onion
  client-manifest.js, client-sri.js, sw-kill-switch.js           # манифест клиента и service worker
  account-limits.js, registration-pressure.js, text-quota.js, disk-space.js, work-limiter.js, token-bucket.js  # лимиты против массовых аккаунтов и «бомб»
  sanitizer-pool.js, sanitizer-worker.js                         # очистка PDF и видео в отдельном потоке: тайм-аут, предел памяти
  trust-proxy.js, onion-access.js, db-errors.js, pg-client-guard.js, ids.js, room-name.js, drain-batches.js, orphan-uploads.js  # прокси и onion-порт, 503 busy, разбор id и названий, чистка
  env-check.js, numeric-knobs.js, legacy-reset.js, metrics.js, advisory-locks.js, tx-retry.js, log-error.js, proto.js
  jobs/, routes/, migrations/                                    # фоновые задачи, вынесенные маршруты, миграции
public/                    # клиент без сборщика
  index.html, css/ (tokens, controls, auth, app-shell, messages, composer, modals, popups, responsive), js/ (01-state.js … 18-init.js — классические скрипты в порядке подключения), theme.js, icons.js, icons/, manifest.webmanifest
  e2ee.js, mlkem.js        # клиентское E2EE: PQXDH, Sender Keys; ML-KEM-768 на чистом JS
  media-sanitizer.js, pow-worker.js
  sw.js, verify.html, verify.js, verify.css   # service worker и страница сверки файлов
  lib/                     # модули клиента: порядок сообщений, состав группы (membership*.js), журнал ключей
                           # (kt*.js), Ed25519, политика E2EE, приглашения, срок аккаунта, поиск, service worker
  vendor/                  # socket.io и qrcode-generator
scripts/                   # check-env, dev-local, release-manifest, verify-deployment, update-sri,
                           # retag-messages, audit-check
tor-service/               # onion-сервис (tor и socat), необязателен
docs/                      # документация, оглавление — docs/README.md
  security/, ops/, dev/, design/, legal/, threat-model.md, VERIFY.md
test/                      # юнит-тесты (test/*.test.js) и сквозные (test/e2e/)
.github/workflows/         # CI, CodeQL, релиз, ежедневный сторож
database.sql               # слепок схемы (генерируется из initDatabase)
SECURITY.md                # политика сообщений об уязвимостях
```

## API

Сессионная cookie; на изменяющие запросы нужны заголовок `X-CSRF-Token`, совпадающий с cookie `csrf_token`, и Origin своего сайта. Клиент передаёт признак версии `proto`: слишком старая страница получает 400 с кодом `client-outdated`. Другие коды отказов: `bad-message-id` и `id-conflict` (идентификатор сообщения выбирает клиент), `busy` (хранилище лимитов или базы занято, в том числе запрос не дождался блокировки или своего времени, 503 с `Retry-After`: повторить), `e2ee-required`, `bad-envelope` и `e2ee-not-allowed` (в группу принимается только корректный E2EE-конверт), `already-member`, `bad-request`. Лимиты отвечают отдельными кодами: `registration-busy` (429, регистраций слишком много), `text-quota` (429, суточный объём текста исчерпан), `rooms-limit` (403, у аккаунта предельное число комнат), `storage-full` (507, на томе вложений кончилось место), `open-uploads-limit` (429, слишком много открытых вложений в чат с ботом). Битое %-кодирование в адресе даёт 400 `Некорректный запрос`, а нечисловой или слишком большой id — обычный отказ JSON, а не 500.

- Аккаунт: `GET /api/pow/challenge`, `POST /api/register/anonymous`, `GET /api/auth`, `GET /api/user`, `POST /api/user/lifetime`, `POST /api/user/privacy`, `POST /api/logout`, `POST /api/account/delete`
- Чаты: `GET /api/chats`, `POST /api/chats`, `DELETE /api/chats/:chatId` (выход из группы, `?deleteMessages=1`), `POST /api/chats/:chatId/prefs`, `POST /api/chats/:chatId/expiry`, `GET /api/chats/:chatId/settings`, `GET /api/chats/:chatId/participants`
- Приглашения и заявки: `GET /api/chats/invite/:chatId`, `POST /api/chats/:chatId/invite/rotate`, `POST /api/chats/:chatId/invite/disable`, `POST /api/chats/join/preview`, `POST /api/chats/join`, `GET /api/chats/:chatId/join-requests`, `POST /api/join-requests/:id/approve`, `POST /api/join-requests/:id/deny`, `GET /api/join-requests/mine`, `DELETE /api/join-requests/:id`
- Состав группы: `GET` и `POST /api/chats/:chatId/member-certs`
- Сообщения: `GET /api/messages/:chatId` (курсор `beforeSeq`), `POST /api/chats/:chatId/read`, `POST /api/messages` (в группу — только E2EE-конверт, открытый текст принимает лишь чат с ботом), `PUT` и `DELETE /api/messages/:messageId`, `POST /api/messages/file`, `POST /api/messages/:messageId/set-expiry`, `POST /api/reactions` и `DELETE /api/reactions/:messageId/:emoji` (ответ `{success, count, mine, v}`: сколько человек поставили это эмодзи, стоит ли оно теперь у вас и версия итога — ответ и события приходят в любом порядке, клиент применяет только более новый итог; допустим фиксированный набор из пяти эмодзи; в истории `GET /api/messages/:chatId` реакции приходят как `[{emoji, count, mine}]`)
- Ключи: `PUT /api/keys/identity`, `PUT /api/keys/signed-prekey`, `PUT /api/keys/pq-prekey`, `POST /api/keys/one-time-prekeys`, `POST` и `DELETE /api/keys/pq-one-time-prekeys`, `GET /api/keys/one-time-prekeys/count`, `GET /api/keys/identities`, `GET /api/keys/bundle/:targetUserId`, `DELETE /api/keys`, `POST /api/keys/key-shares`, `GET /api/keys/key-shares/:chatId`, `POST /api/keys/key-requests`, `GET /api/keys/key-requests/:chatId`, `POST /api/keys/key-requests/done`
- Журнал ключей: `GET /api/kt/head`, `/api/kt/roots`, `/api/kt/proof`, `/api/kt/self` (без `KT_SIGNING_KEY`: `/api/kt/head` отвечает `{enabled:false}`, остальные — 503)
- Файлы: `GET /uploads/:filename` — только участникам чата, вступившим до сообщения
- Служебные: `GET /healthz`, `/readyz`, `/metrics` (по токену), `/client-manifest.json`, `/.well-known/security.txt`
- Socket.io: клиент событий не отправляет — на свои чаты сокет подписывает сам сервер при подключении (событие `joinChat` убрано; частота входящих событий ограничена токен-бакетом `SOCKET_EVENT_RATE`/`SOCKET_EVENT_BURST`, превысивший её сокет закрывается); сервер присылает `newMessage`, `messageEdited`, `messageDeleted`, `messagesRead`, `reactionChanged` (`{id, emoji, count, v, room_id | chat_id}`, в копии автору реакции ещё `mine`), `e2eeKeyShare`, `e2eeKeyRequest`, `roomMembersChanged`, `chatExpiryChanged`, `chatListChanged`, `joinRequestsChanged`, `joinRequestDecided`

## Документация

Оглавление — [docs/README.md](docs/README.md): модель угроз, дизайн протоколов, эксплуатация, юридические черновики, документы для разработчиков.

## Лицензия

MIT.
