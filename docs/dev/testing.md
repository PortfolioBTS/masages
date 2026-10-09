# Тесты Nyxo

| Уровень | Команда | Что нужно |
|---|---|---|
| Юнит | `npm test` | только Node 24 |
| Сквозные (E2E) | `npm run test:e2e` | Postgres 16 (`E2E_DATABASE_URL`) |
| Сквозные во временном контейнере | `npm run test:e2e:docker` | Docker |
| Всё | `npm run test:all` | юнит, затем E2E |
| Ручная проверка интерфейса | `npm run dev:local -- --port 3101` | Docker |

## Юнит-тесты

`test/run-unit.js` сам находит `test/*.test.js` и запускает каждый файл отдельным
процессом; `node test/run-unit.js pow lib` — только файлы с этими подстроками в
имени. Новый тест — **новый файл** `test/<тема>.test.js` в стиле существующих
(мини-харнесс `test(name, fn)`, `process.exitCode = 1` при падении), без
дописывания в большие общие файлы. Новая серверная логика выносится в `lib/` с
внедряемыми `pool`, часами и логом и проверяется фейками (пример —
`test/advisory-locks.test.js`).

`test/forbidden-terms.test.js` — поисковые критерии этапов как тест (правила,
разрешения и их обоснования — `docs/dev/forbidden-terms.md`). На ветке, куда ещё не
влита реализация этапов 1–2, его можно временно пропустить:
`NYXO_SKIP_FORBIDDEN=1 npm test`; в CI пропуск не действует.

## Сквозные тесты: запуск

Нужен Postgres 16 и админ-URL с правом `CREATE DATABASE`:

```bash
docker run -d --name nyxo-pg-test -e POSTGRES_USER=nyxo -e POSTGRES_PASSWORD=<пароль> \
  -p 127.0.0.1:55432:5432 postgres:16-alpine
E2E_DATABASE_URL=postgresql://nyxo:<пароль>@127.0.0.1:55432/postgres npm run test:e2e
```

Пароль — только в переменной окружения; в файлы проекта и коммиты его не
пишем. `npm run test:e2e:docker` поднимает временный контейнер сам (пароль
генерируется в памяти, данные в tmpfs, `fsync=off`) и удаляет его после прогона.

Параметры раннера (`npm run test:e2e -- …` или `node test/e2e/run.js …`):

- `rooms files` — только наборы с этими подстроками в имени файла;
- `--grep 'бот'` — только тесты с подходящим именем (`--test-name-pattern`);
- `--junit out/e2e.xml` — ещё и отчёт JUnit (для CI);
- `--docker` — временный Postgres.

Без `E2E_DATABASE_URL` (и без `--docker`) раннер печатает подсказку и выходит
с кодом 1. Если набор упал, в `test/e2e/.logs/` (папка в `.gitignore`)
остаются логи всех его серверов и файл `<метка>-<набор>-suite.log` с причинами
(см. «Упавший набор» ниже); в конце прогона раннер печатает, куда смотреть.

Полный прогон — около 15 секунд. Несколько прогонов параллельно (из разных
worktree, на одном контейнере) друг другу не мешают.

## Как устроено

- **Раннер** `test/e2e/run.js` проверяет подключение, удаляет базы упавших
  прогонов старше 2 ч (время — в имени базы, поэтому базы параллельного прогона
  не задеваются) и запускает `node --test` с явным списком
  `test/e2e/*.e2e.test.js`: каждый файл — отдельным процессом, по 2 файла
  одновременно, тайм-аут теста 60 с.
- **Своя база на файл-набор**: `nyxo_e2e_<unixtime>_<rand>`, после набора —
  `DROP DATABASE … WITH (FORCE)`. Одна база на весь прогон не годится: фоновая
  чистка одного сервера удаляла бы «перемотанных» пользователей чужих тестов.
  Внутри набора тесты изолированы свежими анонимами.
- **Сервер — настоящий `server.js` отдельным процессом**: его нельзя
  импортировать (при загрузке читает `.env`, открывает пул, ставит таймеры,
  вызывает `process.exit`), а тестам нужны рестарты и реплики. `cwd` — временная
  папка (не подхватываются `.env` и `localhost+1*.pem`), порт — свободный,
  готовность — `GET /api/auth`. Если процесс теста умрёт, сервер выйдет сам
  (`helpers/child-guard.js` слушает канал IPC).
- **Окружение сервера — явное**, без копии `process.env`: системные переменные
  (`PATH`, `SystemRoot`, `TEMP`…), `NODE_ENV=test`, `HOST=127.0.0.1`, `PORT`,
  `DATABASE_URL`, случайные `SESSION_SECRET` и `MESSAGE_ENCRYPTION_KEY` на набор
  (общие для его реплик), `POW_DIFFICULTY=8`, `UPLOADS_DIR=<tmp>/uploads`,
  `PG_POOL_MAX=3`, `CLEANUP_INTERVAL_MS=500`, `NYXO_TEST_MAINTENANCE_MS=300`.
  Свои переменные набора — `createSuite(name, { env })`, значение `null` убирает
  переменную.
- **Тестовые ручки** — переменные `NYXO_TEST_*`, действуют **только** при
  `NODE_ENV=test`; при `NODE_ENV=production` `env-check` считает любую из них
  ошибкой.
  - `NYXO_TEST_MAINTENANCE_MS=N` — первые запуски и интервалы чистки анонимов,
    чистки заявок и продления активности сокетов становятся N мс; после каждого
    выполненного прохода чистки анонимов сервер пишет
    `[Test] maintenance tick <n>` (`server.waitForTick()`).
  - `NYXO_TEST_RENEW_INTERVAL_MS=N` — интервал продления сессии (по умолчанию 5 минут)
    становится N мс: сессия продлевается, когда `sess.renewBucket` отличается от
    `floor(now / N)`. Наборы, которым нужно «та же корзина» без случайностей, ставят
    огромное N и сбрасывают маркер вручную (`forceRenewal` в `helpers/anon.js`).
- **Сокеты** — свой минимальный клиент Engine.IO v4 / Socket.IO v5 на
  глобальном `WebSocket` Node 24 (`helpers/socket.js`), без пакета
  `socket.io-client`: заголовки `Cookie`, `Origin`, `X-Forwarded-For` под полным
  контролем (проверка CSWSH и лимитов по IP), без автоматических переподключений
  и буферизации, которые прячут ошибки. Сам клиент проверяется юнит-тестом
  `test/socket-client.test.js` против настоящего `socket.io`.
- **Упавший набор не остаётся без следов.** Набор (файл) может упасть не
  тестом: исключение в хуке, сбой старта сервера, необработанное исключение из
  таймера после конца теста — runner показывает это как «tests N+1, fail 1» с
  названием файла. Поэтому `createSuite` (`helpers/scenarios.js`,
  `helpers/failure-log.js`) при любой такой причине сохраняет в
  `test/e2e/.logs/` логи всех серверов набора и `…-suite.log`: упавшие тесты с
  ошибками, ошибки хуков, необработанные исключения, код выхода процесса, сбои
  уборки. Папку можно переопределить `NYXO_E2E_LOGS_DIR` (так её подменяет
  `harness-failures.e2e.test.js`, проверяющий всё это вложенными прогонами).
  Уборка (остановка серверов, удаление базы) исключений не бросает: её сбой при
  зелёных тестах — предупреждение `# ВНИМАНИЕ, уборка набора …`, база останется
  до уборки раннером (2 ч). Создание и удаление базы и старт сервера повторяются
  при временных сбоях Postgres (кончились слоты соединений `53300` — общий
  контейнер делят несколько прогонов).
- **Тишина перед выходом.** На Windows процесс набора, завершаемый сразу после
  остановки серверов, падает в libuv («Assertion failed: !(handle->flags &
  UV_HANDLE_CLOSING), src/win/async.c»): файл красный при всех зелёных тестах
  и без единого лога. Воспроизводится: любой `fetch` к серверу → kill сервера →
  немедленный выход. Конец `after`-хука поэтому ждёт, пока не исчезнут
  дескрипторы дочерних процессов и не пройдёт 150 мс с завершения последнего
  сервера (`settleBeforeExit` в `helpers/server.js`). Если пишете свой код
  остановки серверов вне `createSuite`, вызовите `settleBeforeExit()` последним.
- **Легаси-фикстура** `test/e2e/fixtures/legacy-2.0.0.{sql,json}` — база версии
  2.0.0; хелпер только загружает её в свежую базу (реальных пользователей нет,
  новая версия сбрасывает старую схему).

## Как написать набор

Файл `test/e2e/<тема>.e2e.test.js` — раннер найдёт его сам:

```js
'use strict';
const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('my-topic', { env: { UPLOAD_QUOTA_MB: '1' } });

test('владелец и участник переписываются', async (t) => {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const sock = await member.socket();          // подключаемся ДО действия
    t.after(() => sock.close());
    const { ownerChat } = await roomWithMember(owner, member);
    const sent = await owner.send(ownerChat.id, 'привет');
    const got = await sock.waitFor('newMessage', m => m.id === sent.id);
    assert.strictEqual(got.text, 'привет');
});
```

Правила:

- **Никаких `sleep`** — только ожидание условия с тайм-аутом: событие сокета
  (`sock.waitFor`), строка лога (`server.logs.waitFor`), проход фоновой задачи
  (`server.waitForTick`), в крайнем случае `waitUntil(check)` для того, что не
  сообщает о себе (файл удалён с диска).
- **Время — от `NOW()` базы**: «прошло 40 минут» делается перемоткой данных
  назад (`suite.time.*`), а не ожиданием и не подменой часов.
- **Каждому клиенту — свой «браузер»** (`suite.client()`): свои куки и свой
  `X-Forwarded-For` — лимиты по IP не пересекаются.
- **Сокет подключайте до действия**, событие которого ждёте: на новые комнаты
  (создание, одобрение заявки) сервер подписывает уже открытые сокеты сразу,
  через личную комнату пользователя. А на чаты, которые были у пользователя до
  подключения, сокет подписывается **асинхронно** (запрос к базе после
  `connect`): событие такого чата сразу после подключения может не дойти. Там
  ждите событие, которое приходит позже (ответ бота — через ~1.5 с), или
  подключайтесь до создания комнаты.
- **Отсутствие события** проверяйте барьером, а не паузой: сделайте действие,
  событие которого точно придёт следом (сообщение в тот же чат), дождитесь его и
  проверьте `sock.collect(...)`: события одного сокета приходят по порядку.
- Набор не зависит от других наборов и от порядка тестов в других файлах.

## Справочник хелперов (`test/e2e/helpers/`)

**`scenarios.js`**
- `createSuite(name, { env, legacy, startServer })` → `suite`: регистрирует
  хуки (база, фикстура, сервер; уборка, логи упавших тестов).
  - `suite.server` — первый сервер; `suite.client(opts)` — клиент к нему;
  - `suite.startServer({ env, name })` — ещё сервер (реплика) на ту же базу,
    с теми же секретами; `suite.newServer(...)` — без запуска;
  - `suite.db` — пул к базе набора, `suite.query(sql, params)`;
  - `suite.time` — перемотка (см. `time.js`); `suite.legacy` — метаданные
    фикстуры (при `legacy: true`);
  - `startServer: false` — сервер набор запускает сам.
- `roomWithMember(owner, member, { name })` → `{ roomId, code, ownerChat,
  memberChat, requestId }`: комната владельца, участник вошёл по заявке.
- `waitUntil(check, { timeoutMs, intervalMs, what })`.

**`server.js`** — `ServerHandle`: `start()`, `stop()`, `restart({ env })`
(та же база, `UPLOADS_DIR` и порт), `baseUrl`, `uploadsDir`, `logs`,
`waitForTick(count)` (2 — гарантированно полный проход после вызова),
`waitForExit()`, `client(opts)`. `spawnServer(opts)` — запуск без ожидания
готовности (для проверок «сервер не стартует»). `freePort()`.

**`client.js`** — `TestClient` (один «браузер»):
- сырые `get/post/put/del(path, json?, { headers, origin, csrf, binary })`,
  `request(method, path, opts)` → `{ status, headers, body, text }`;
  `origin: null` — без заголовка Origin; `csrf: false` — без токена;
- `csrfToken()`, `withCookie(name, value)`, `jar` (куки);
- аккаунт: `registerAnon({ lifetime })`, `auth()`, `logout()`,
  `deleteAccount(password?)`; `user` — после регистрации;
- комнаты: `chats()`, `botChat()`, `createRoom(name)`, `invite(chatId)`,
  `rotateInvite(chatId, settings)`, `joinPreview(code)`, `join(code)`,
  `joinRequests(chatId)`, `approve(id)`, `deny(id)`, `leave(chatId)`;
- сообщения и файлы: `send(chatId, text)`, `messages(chatId, query)`,
  `upload(chatId, bytes, mime, { filename, text })`, `uploadRaw(...)` (сырой
  ответ — для отказов), `download(fileUrl)`;
- `socket({ origin, cookie, xff })` — сокет с куками, Origin и XFF клиента.

Методы API бросают `ApiError` (со статусом и телом), если `success !== true`.

**`socket.js`** — `connectSocket(...)` / `client.socket()` → сокет:
`emit(event, ...args)`, `emitWithAck(event, ...args)`,
`waitFor(event, predicate, { timeoutMs, since })` (смотрит и уже пришедшие
события), `collect(event, { since })`, `mark()`, `close()`, `connected`.
Отказ подключения — ошибка с `kind`: `handshake` (с `reason`, например
`Origin not allowed`, и `status`), `connect_error` (`reason` — сообщение
middleware сервера, например `Не авторизован`), `timeout`, `closed`. В истории
есть служебные `connect`, `disconnect` (`{ reason }`) и `engine:ping`.

**`logs.js`** — `server.logs`: `mark()`, `waitFor(re, { from, timeoutMs })`
(сразу падает, если процесс завершился), `find`, `count`, `text`, `tail`,
`assertNoSensitive({ ids, usernames, codes, inviteCodes, emails, ips, sids })`.
Маркер фоновой задачи после старта:

```js
const mark = server.logs.mark();
await server.restart();
await server.logs.waitFor(/\[Legacy\] …/, { from: mark });
```

**`time.js`** — `suite.time`: `rewindUser(id, { lastActiveMs, createdMs })`,
`rewindSession(sid, ms)`, `rewindUserSessions(userId, ms)`,
`rewindJoinRequest(id, ms)`, `rewindInvite(roomId, ms)`, `expireInvite(roomId)`,
`rewindMessage(id, ms)`, `expireMessage(id)`; `sessionIdFromCookie(value)`.
Кэш активности анонимов в памяти сервера перемотка не трогает — сбрасывается
рестартом.

**`pg.js`** — `createDatabase()`, `dropDatabase(name)`, `dropStaleDatabases()`,
`connectPool(url)`, `resetSchema(db)`, `schemaSnapshot(db)` (таблицы и колонки,
индексы, ограничения, функции).

**`legacy.js`** — `loadLegacyFixture(url)`, `legacyMeta()`,
`legacyServerSecrets()`.

**`env.js`** — пути, `serverEnv(...)`, `randomSecrets()`,
`testOnionAddress(seed)` — валидный тестовый v3-адрес `.onion`.

**`anon.js`** — для наборов про срок жизни и сессии: числа контракта §4 (`LIFETIME_MS`,
`BUCKET_MS`, `COOKIE_EXTRA_MS`, `bucketCeil`) — копия контракта, а не импорт из
`lib/`, чтобы тест сверял сервер с контрактом; `registerRaw(client, lifetime)` —
сырой ответ регистрации; `setCookies(res, name)` — разобранные `Set-Cookie`;
`sessionCookie(client)`, `signSessionCookie(sid, secret)`; `userRow`, `sessionRow`
(`expire` читается средствами базы: колонка без часового пояса), `count`;
`setLastActive(suite, id, lifetime, { pastMs })` — `last_active_at` на границе
корзины «сейчас − срок − запас»; `forceRenewal(suite, sid, { rewindExpireMs })` —
сбросить маркер продления сессии.

**`samples.js`** — минимальные настоящие PDF, MP4, WebM с метаданными (сервер их
вычищает) и «головы» звуковых файлов для проверок отказа по типу.

## Ручная проверка интерфейса

```bash
npm run dev:local -- --port 3101            # временный Postgres в Docker
npm run dev:local -- --port 3101 --onion    # + тестовый ONION_ADDRESS
node scripts/dev-local.js --port 3101       # база на E2E_DATABASE_URL
```

Секреты генерируются в памяти, `POW_DIFFICULTY=8`, `NODE_ENV=development`,
сервер идёт по HTTP; база (и контейнер) удаляются при выходе по Ctrl+C.
Контейнеры прошлых запусков, оставшиеся после жёсткого завершения, удаляются при
следующем `--docker`, базы `nyxo_dev_*` — через сутки.

- У каждого, кто проверяет интерфейс параллельно, — **свой порт**.
- Два пользователя в одном браузере: вкладка A на `http://localhost:ПОРТ`,
  вкладка B на `http://127.0.0.1:ПОРТ` — у них разные куки.
- Для встроенного браузера — локальная (не в git) `.claude/launch.json`:

```json
{
  "version": "0.0.1",
  "configurations": [
    { "name": "nyxo-dev", "runtimeExecutable": "node",
      "runtimeArgs": ["scripts/dev-local.js", "--docker", "--port", "3101"], "port": 3101 }
  ]
}
```

## Миграции

Изменения схемы и их проверка — `docs/dev/migrations.md`.
