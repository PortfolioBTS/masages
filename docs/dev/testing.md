# Тесты Nyxo

| Уровень | Команда | Что нужно |
|---|---|---|
| Юнит | `npm test` | только Node 24 |
| Юнит с покрытием | `npm run test:coverage` | только Node 24 |
| Сквозные (E2E) | `npm run test:e2e` | Postgres 16 (`E2E_DATABASE_URL`) |
| Сквозные во временном контейнере | `npm run test:e2e:docker` | Docker |
| Всё | `npm run test:all` | юнит, затем E2E |
| Смоук в настоящем браузере | `npm run test:browser` | Chrome, Chromium или Edge и Postgres 16 |
| Ручная проверка интерфейса | `npm run dev:local -- --port 3101` | Docker |

## Юнит-тесты

`test/run-unit.js` сам находит `test/*.test.js` и запускает каждый файл отдельным
процессом; `node test/run-unit.js pow lib` — только файлы с этими подстроками в
имени. Новый тест — **новый файл** `test/<тема>.test.js` в стиле существующих
(мини-харнесс `test(name, fn)`, `process.exitCode = 1` при падении), без
дописывания в большие общие файлы. Новая серверная логика выносится в `lib/` с
внедряемыми `pool`, часами и логом и проверяется фейками (пример —
`test/advisory-locks.test.js`).

Файл, который не ставит `process.exitCode` (или не вызывает итог общего
харнесса: `finish()` из `test/sender-keys-helpers.js` и `test/membership-world.js`,
`done()` из `test/client-vm.js`), не сможет покраснеть: раннер судит по коду
выхода. Это проверяет `test/repo-hygiene.test.js` (список харнессов в нём —
`HARNESSES`; новый общий харнесс вносится туда же).

**Скорость.** Файлы идут пулом из `min(os.availableParallelism(), 4)` процессов:
полный `npm test` (154 файла на конец волны 7) занимает около минуты вместо
нескольких (замер T7.4 на 107 файлах и машине с чужой нагрузкой: 176 с по
очереди, 50-53 с в пуле; на 154 файлах пул — 47-60 с). Вывод файла
печатается целиком, когда он закончился; упавший файл помечен строкой
`ПАДЕНИЕ <имя>: <причина>` (в GitHub Actions ещё и аннотацией `::error`), в
конце печатается сводка со временем каждого файла. Зависший файл убивается через
300 с вместе с дочерними процессами и считается упавшим. Параметры:

- `--serial` — по одному, вывод идёт сразу (отладка зависшего файла);
- `--jobs=N` — размер пула; `--timeout=СЕК` — тайм-аут на файл.

Две проверки, о которых полезно знать при правках сервера: новая числовая
переменная окружения (лимит) вносится в `NUMERIC_KNOBS` (`lib/numeric-knobs.js`; сервер читает её через `knobValue` — тот же разбор, что у env-check),
`.env.example` и `docs/ops/deploy-railway.md` одновременно, согласованность этих
трёх мест проверяет `test/env-check-limits.test.js`; новый слой Express
(middleware) вносится в `EXPECTED_STACK` теста `test/server-structure.test.js`.

Юнит-тесты не делят порты, базы и файлы (серверным хватает порта 0 и временных
папок). Новый тест с общим ресурсом (фиксированный порт, файл внутри репозитория)
в пуле мешал бы соседям: берите порт 0 и `os.tmpdir()`. Сам раннер проверяет
`test/run-unit.test.js`.

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

Полный прогон — несколько минут (64 набора; на машине с другой нагрузкой около
4,5-5 мин; наборы идут по 2 одновременно). Несколько прогонов параллельно (из разных
worktree, на одном контейнере) друг другу не мешают, но удлиняют каждый. Для
итерации запускайте нужные наборы по имени: `npm run test:e2e -- rooms files`.

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
- **Сервер — настоящий `server.js` отдельным процессом**: тестам нужны
  рестарты и реплики, а `start()` (src/lifecycle.js) вешает обработчики процесса,
  открывает порт и вызывает `process.exit`. Сборку без запуска (`createServer` из
  `src/create-server.js`, без базы и порта) проверяет юнит-тест
  `test/server-structure.test.js`. `cwd` — временная
  папка (не подхватываются `.env` и `localhost+1*.pem`), порт — свободный,
  готовность — `GET /api/auth`. Если процесс теста умрёт, сервер выйдет сам
  (`helpers/child-guard.js` слушает канал IPC).
- **Окружение сервера — явное**, без копии `process.env`: системные переменные
  (`PATH`, `SystemRoot`, `TEMP`…), `NODE_ENV=test`, `HOST=127.0.0.1`, `PORT`,
  `DATABASE_URL`, случайные `SESSION_SECRET` и `MESSAGE_ENCRYPTION_KEY` на набор
  (общие для его реплик), `POW_DIFFICULTY=8`, `UPLOADS_DIR=<tmp>/uploads`,
  `PG_POOL_MAX=3`, `CLEANUP_INTERVAL_MS=500`, `NYXO_TEST_MAINTENANCE_MS=300`,
  а также ослабленные лимиты против массовых аккаунтов: `REGISTER_GLOBAL_PER_MIN=100000`,
  `REGISTER_PACE_PER_MIN=100000` (иначе набор, заводящий сотни аккаунтов за минуту, упрётся в потолок
  регистраций и рост сложности PoW) и `UPLOAD_MIN_FREE_MB=1` (результат не зависит от свободного места
  диска). Свои лимиты проверяют `registration-limits`, `account-quotas`, `upload-disk-guard`.
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
  - `KT_SIGNING_KEY` + `KT_EPOCH_SECONDS=2`, `KT_GENERATION_EPOCHS`, `KT_GRACE_EPOCHS`, `KT_COMPACT_MIN` —
    журнал ключей (`test/e2e/key-transparency*.e2e.test.js`): эпоха в секундах, поколение и льготный срок
    в эпохах, порог компактного индекса. Это константы протокола, а не настройки: ручки действуют только при
    `NODE_ENV=test`, в production `env-check` считает их ошибкой. Протокол клиента проверяют юнит-тесты
    `test/kt-client.*.test.js` (журнал в памяти `test/fake-kt.js`, оснастка `test/kt-harness.js`).
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

## Подписанный состав группы в тестах

Вход по ссылке, одобрение заявки и приглашение без одобрения требуют сертификатов, подписанных identity-ключом (docs/security/signed-membership.md).

- **Сквозные тесты.** `TestClient.join(code)`, `approve(requestId)` и `rotateInvite(chatId, { requireApproval: false })` подписывают сами (`test/e2e/helpers/membership.js`):
  у клиента заводится identity (`tc.identity`), сертификат строится общим модулем `public/lib/membership.js`. `rotateInvite` запоминает секрет ссылки по коду, и `join(code)`
  входит как человек со ссылкой; `join(code, { secret: null })` — вход кодом без секрета (заявка), `joinRaw` — сырой ответ. Тест, который регистрирует ключи сам (`PUT /api/keys/identity`),
  должен задать `tc.identity = { signPub, dhPub, sign }`; тест с настоящим клиентом E2EE — `tc.e2ee = client` после `client.init()`: тогда подписывает он (`signApproval`, `signInvite`, `prepareJoin`).
- **Протокольные тесты.** `test/membership-world.js` поднимает fake-server с сертификатами и настоящие клиенты E2EE без автоподтверждения; прежние протокольные тесты, которым состав не важен,
  подключают `test/membership-harness.js` (`install(E2EE)`): клиент вручную подтверждает всех участников, переданных в `ensureRoomSession`.

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

## Смоук в настоящем браузере

Юнит-тесты проверяют модули, сквозные — сервер через HTTP и сокеты. Что страница
вообще загружается, все скрипты подключены, CSP ничего не блокирует, а кнопки
нажимаются, не проверяет ни то, ни другое. Это закрывает набор `test/browser`: он
управляет **настоящим Chrome** по Chrome DevTools Protocol (CDP). Он страхует
правки, которые меняют состав файлов клиента (разбиение, как уже сделанное в
волне 6 `script.js` на `public/js/` и `style.css` на `public/css/`, новые модули,
закрепление кода service worker'ом): после такой правки он должен
остаться зелёным, а снимки экрана — совпасть.

```bash
E2E_DATABASE_URL=postgresql://… npm run test:browser          # Postgres как у E2E
npm run test:browser -- --docker                             # временный контейнер
npm run test:browser -- group files                          # только эти файлы
npm run test:browser -- --grep 'ссылка' --headed             # с окном браузера
```

Раннер (`test/browser/run.js`) принимает те же `--docker`, `--grep`, `--junit` и
подстроки имён файлов, что и раннер E2E, плюс `--headed` (показать окна; то же,
что `NYXO_BROWSER_HEADED=1`). Полный прогон — около полутора минут: наборы идут
по одному, в каждом сценарии запускаются свои процессы браузера.

**Какой браузер.** `CHROME_PATH` (явный путь к `chrome.exe`, `google-chrome`,
`chromium`, `msedge`), иначе типичные места: Windows — Program Files и
`%LOCALAPPDATA%\Google\Chrome`, macOS — `/Applications`, Linux — `/usr/bin`,
`/snap/bin` и каталоги из `PATH`; сначала Chrome, потом Chromium, потом Edge (на
Chromium, CDP тот же). Раннер печатает версию и путь найденного. Если `CHROME_PATH`
задан, но файла нет, — ошибка, а не молчаливый поиск другого. Браузера нет:
локально прогон **пропускается** с сообщением и кодом 0, в CI (переменная `CI`) —
**падает** с кодом 1: молча не запустившийся смоук был бы дырой. Логика поиска
проверяется юнит-тестом `test/browser-path.test.js` без браузера.

### Как устроено

- Новых зависимостей нет: CDP говорит по вебсокету встроенными средствами Node
  (`test/browser/helpers/cdp.js`). Порт отладки выбирает сам браузер
  (`--remote-debugging-port=0`, номер читается из `DevToolsActivePort` профиля) и
  слушает только 127.0.0.1.
- **Профиль — отдельный временный каталог** (`user-data-dir` в папке временных
  файлов ОС) на каждый «аккаунт»; после набора каталог удаляется, процессы
  браузера завершаются. Профили человека не открываются и не меняются. Два профиля —
  два устройства со своими куками, localStorage и IndexedDB; две вкладки одного
  профиля — два окна одного браузера.
- Сервер и база — из харнесса E2E (`createSuite`: своя база `nyxo_e2e_*`, настоящий
  `server.js` на свободном порту, `POW_DIFFICULTY=8`). Адрес — не 127.0.0.1, а
  `http://smoke.localhost:<порт>`: на `localhost` и 127.0.0.1 service worker выключен
  намеренно (режим разработки), на поддомене `*.localhost` он работает как в бою.
  Chrome сам считает `*.localhost` петлёвым адресом и безопасным контекстом.
- Действия — как у человека: клик идёт настоящим событием мыши в точку элемента
  (`Input.dispatchMouseEvent`), а если элемент перекрыт модальным окном или
  баннером, тест падает и называет перекрывающий элемент; текст вводится
  `Input.insertText`; файлы выбираются в `<input type="file">`
  (`DOM.setFileInputFiles`); `confirm` страницы принимается автоматически
  (`Page.javascriptDialogOpening`). Селекторы — по `id` и классам, а не по тексту
  кнопок; тексты проверяются только там, где проверяется сам текст
  (`TEXT` в `test/browser/helpers/app.js`).
- **Консоль без ошибок.** По всем вкладкам и воркерам (service worker, PoW)
  собираются `console.error`, необработанные исключения, `Log.entryAdded` уровня
  error (в том числе «Failed to load resource»), нарушения CSP (`Audits.issueAdded`) и
  отказавшие запросы. После каждого теста любая такая запись — падение с её текстом.
  Известное безвредное сообщение допускается явно: `page.allow(/шаблон/)` в
  самом тесте с комментарием, почему. Сейчас не допускается ничего. Проверено
  «мутациями»: искусственные `console.error`, исключение, inline-скрипт и
  inline-стиль, `fetch`/картинка с чужого origin, 404 и ошибка в воркере ловятся.
- При падении сценария снимки всех его вкладок сохраняются как
  `test/browser/.screens/FAIL-<набор>-<тест>-<профиль>-<n>.png`, логи серверов — как у
  E2E, в `test/e2e/.logs/`. Переменные: `NYXO_BROWSER_SCREENS_DIR` — куда писать
  снимки, `NYXO_BROWSER_NO_SANDBOX=1` — запуск без песочницы Chrome (в CI включается
  сам: там изоляция на уровне раннера).

### Сценарии

| Файл | Что проверяет |
|---|---|
| `login-bot.browser.test.js` | экран входа (срок хранения, светлая тема, «Как это работает»); «Начать анонимно» — PoW в воркере браузера; чат с ботом, кнопка-подсказка и ответ; service worker: регистрация, кэш оболочки, страница под его управлением после перезагрузки; снимки в тёмной и светлой теме и в узкой раскладке |
| `group.browser.test.js` | группа и подписанная ссылка без одобрения (буфер обмена, фрагмент `#join=` стёрт из адреса), вход вторым профилем, надпись «Состав группы подтверждён по подписи приглашения», E2EE-сообщения в обе стороны, авторы верны после перезагрузки; заявка по коду без секрета, одобрение, статусы участников |
| `files.browser.test.js` | PNG через `input[type=file]` доходит картинкой нужного размера (blob из расшифрованных данных), исходное имя фото не показывается, `.mp3` отклоняется до отправки |
| `search.browser.test.js` | поиск по ленте (регистр, «е»/«ё», счётчик, переходы, подсветка, Escape) и по списку чатов; ни одного сетевого запроса за время поиска, контрольный запрос доказывает, что журнал сети его видит |
| `account-delete.browser.test.js` | удаление аккаунта: localStorage, sessionStorage и IndexedDB пусты, на сервере аккаунта нет, вторая вкладка видит «Аккаунт удалён в другой вкладке» |
| `composer.browser.test.js` | правки клиента по ревью W7 R3 (T7.3): правка и ответ с плашками и Esc, многострочное поле, меню сообщения и чата с клавиатуры; реакции между двумя профилями без перезагрузки; окно подтверждения выхода из группы (Отмена, Escape, затемнение); экран 320×640 и цели нажатия не меньше 44 px |
| `console-guard.browser.test.js` | проверка самого стража консоли: искусственная ошибка, исключение, нарушения CSP, 404 и ошибка воркера должны попасть в замечания, иначе зелёные сценарии ничего не значили бы |

### Снимки экрана и ручная сверка до/после правок

Ключевые экраны сохраняются в `test/browser/.screens/<набор>-<номер>-<что>.png`
(папка в `.gitignore`): `login-01…07` (вход, тема, «Как это работает», чат с ботом
в тёмной и светлой теме, узкая раскладка и список чатов), `group-01…06`
(приглашение, предпросмотр вступления, чат, участники, заявка в ожидании),
`files-01…03` (выбор файлов, картинка у получателя, отказ по типу),
`search-01…02` и `account-01…03`. Сравнивать по пикселям не нужно (в кадре время
сообщений и случайные имена `Гость-XXXX`), достаточно глазами:

1. На базовой ветке: `NYXO_BROWSER_SCREENS_DIR=<папка>/до npm run test:browser`.
2. На ветке с правкой: то же с `<папка>/после`.
3. Открыть пары одноимённых файлов и сравнить: расположение блоков, иконки, шрифты,
   обрезанный или наехавший текст, цвета в светлой теме, узкая раскладка. Расхождение
   в тексте времени и имён гостей — не повод для тревоги; сдвиг или пропавший значок — повод.

### Как добавить сценарий

Новый файл `test/browser/<тема>.browser.test.js` (раннер находит его сам):

```js
const { createBrowserSuite } = require('./helpers/suite');
const app = require('./helpers/app');
const suite = createBrowserSuite('тема');

suite.test('что проверяется', async () => {
    await suite.withProfiles(['alice', 'bob'], async ([alice, bob]) => {
        const page = await alice.newPage();
        await app.startAnonymously(page, `${suite.baseUrl}/`);
        await page.click('#new-chat-btn');           // настоящий клик
        await page.waitForSelector('#new-chat-modal:not(.hidden)');
        await page.screenshot('тема-01-новый-чат');
    });
});
```

`withProfiles` запускает по браузеру на имя, после теста проверяет консоль и закрывает
браузеры. Ожидания — только через `waitFor*` (состояние, а не пауза «на всякий случай»).

### CI

Job `browser` в `.github/workflows/ci.yml` (ubuntu-latest, Chrome там предустановлен)
запускает `npm run test:browser` на Postgres-сервисе, как job `e2e`; при падении
снимки экрана и логи серверов сохраняются артефактом.

**Статус job `browser`.** Сценарии (четырнадцать в семи файлах) ещё не доказали стабильность на образе
ubuntu-latest (локально они идут на Windows), поэтому job не входит в обязательные
проверки защиты `main` и не является условием релиза. Правило ввода: 10 прогонов
`main` подряд зелёным — тогда его добавляют в защиту `main` (`docs/dev/ci.md`) и в
`needs` релиза. Красный прогон не прячется: job виден в проверках PR. Пока этого
нет, UI-сценарии в CI ничего не гарантируют — перед слиянием правок интерфейса их
запускают локально.

**Релиз** (`release.yml`) ждёт не только юнит-тесты на двух ОС (`build`), но и
сквозные тесты и аудит зависимостей на коммите тега (`e2e`, `audit` — копии jobs из
`ci.yml`; `test/ci-release-gates.test.js` следит, чтобы копии не разошлись).

**Покрытие.** `npm run test:coverage` — `node --test --experimental-test-coverage`
по `test/*.test.js` (покрытие `src`, `lib`, `public` без `public/vendor`; новых
зависимостей нет). В CI это информативный job `coverage` (`continue-on-error`,
таблица в сводке прогона и артефакт `coverage-unit`); порога нет. На момент добавления
(октябрь 2026): 85 % строк, 90 % ветвей, 86 % функций, около 1 мин 45 с. Серверный процесс
сквозных тестов в покрытие не входит. Покрытие — подсказка, где искать пробелы;
качество тестов проверяют мутациями (сломать одну строку — тест должен покраснеть).

## Миграции

Изменения схемы и их проверка — `docs/dev/migrations.md`.
