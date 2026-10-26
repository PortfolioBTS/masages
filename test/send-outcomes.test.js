'use strict';
// Исходы отправки сообщения на клиенте (docs/security/message-ordering.md, 6.5 и 12) — клиентская
// половина идемпотентности (ревью W7 R5, В-6). Сервер по clientMessageId не создаст дубликат, но
// только если клиент после обрыва шлёт ТОТ ЖЕ запрос с ТЕМ ЖЕ id, а после 409 берёт новый id и
// шифрует заново, и если он не повторяет то, что повторять нельзя. Раньше это держалось только на
// регэкспах по исходнику и «счастливом пути» в браузере; здесь — таблица исходов на настоящем
// public/lib/send-outcomes.js с подставными post/buildRequest/delay (без сети, без пауз).
//
// Запуск: node test/send-outcomes.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Outcomes = require('../public/lib/send-outcomes.js');
const { createClient, createHarness, fakeElements } = require('./client-vm');
const { clientScriptFiles } = require('./client-script-source');

const { test, done } = createHarness();
const { SEND_RETRY_DELAYS_MS, MAX_ID_CONFLICTS, isUnknownSendOutcome, sendWithOutcomes } = Outcomes;

// ---- Стенд ----

const OK = { success: true, httpStatus: 200, message: { id: 5 } };
const CONFLICT = { success: false, httpStatus: 409, code: 'id-conflict', message: 'занят' };
const NETWORK = { success: false, networkError: true, message: 'Нет соединения с сервером' };
const TIMEOUT = { success: false, timedOut: true, message: 'Сервер не отвечает' };
const HTTP = (httpStatus, extra = {}) => ({ success: false, httpStatus, message: `HTTP ${httpStatus}`, ...extra });

// responses — очередь ответов post() по порядку; лишний POST — ошибка теста (бесконечный повтор
// поломанной логики не повиснет, а упадёт). Каждый buildRequest создаёт НОВЫЙ объект запроса:
// «тот же запрос» проверяется тождеством объектов, а не равенством полей.
function rig({ responses, roomId = 10, shouldStop, reuse = null, buildNull = [] }) {
    const queue = [...responses];
    const log = { posts: [], builds: [], delays: [], idCalls: 0, stopChecks: 0 };
    const options = {
        roomId,
        reuse,
        delay: async (ms) => { log.delays.push(ms); },
        newClientMessageId: () => `id-${++log.idCalls}`,
        buildRequest: async (clientMessageId) => {
            log.builds.push(clientMessageId);
            if (buildNull.includes(log.builds.length)) return null;
            return { n: log.builds.length, clientMessageId };
        },
        post: async (request) => {
            log.posts.push(request);
            if (queue.length === 0) throw new Error(`лишний POST №${log.posts.length}: логика повторов зациклилась`);
            return queue.shift();
        },
    };
    if (shouldStop) options.shouldStop = () => { log.stopChecks++; return shouldStop(log.stopChecks); };
    return { log, run: () => sendWithOutcomes(options) };
}

// ---- Константы и признак «исход неизвестен» ----

test('константы совпадают с контрактом 6.5: три повтора с нарастающей паузой, три конфликта id подряд', () => {
    assert.strictEqual(SEND_RETRY_DELAYS_MS.length, 3, '«не больше трёх раз»');
    assert.ok(SEND_RETRY_DELAYS_MS.every((ms, i) => ms > 0 && (i === 0 || ms > SEND_RETRY_DELAYS_MS[i - 1])), 'пауза растёт');
    assert.strictEqual(MAX_ID_CONFLICTS, 3, '«не больше трёх конфликтов подряд»');
});

test('isUnknownSendOutcome: обрыв, таймаут и 5xx — неизвестно; успех и отказы 4xx — нет', () => {
    for (const data of [NETWORK, TIMEOUT, HTTP(500), HTTP(502), HTTP(503), HTTP(599)]) {
        assert.strictEqual(isUnknownSendOutcome(data), true, JSON.stringify(data));
    }
    for (const data of [OK, HTTP(400), HTTP(403), HTTP(404), HTTP(409, { code: 'id-conflict' }), HTTP(413), HTTP(499), { success: false, message: 'x' }, { success: false, networkError: false, timedOut: false }]) {
        assert.strictEqual(isUnknownSendOutcome(data), false, JSON.stringify(data));
    }
    // Успех не бывает «неизвестным», даже если в теле остались признаки сбоя.
    assert.strictEqual(isUnknownSendOutcome({ success: true, httpStatus: 500 }), false);
});

// ---- Неизвестный исход: тот же запрос ----

const UNKNOWN = [
    ['обрыв сети', NETWORK],
    ['таймаут', TIMEOUT],
    ['500', HTTP(500)],
    ['502', HTTP(502)],
    ['503 busy', HTTP(503, { code: 'busy' })],
];

for (const [label, failure] of UNKNOWN) {
    test(`${label}: тот же запрос (тот же объект и clientMessageId) до SEND_RETRY_DELAYS_MS, затем отказ с последним ответом`, async () => {
        const s = rig({ responses: Array.from({ length: 1 + SEND_RETRY_DELAYS_MS.length }, () => failure) });
        const result = await s.run();
        assert.strictEqual(s.log.posts.length, 1 + SEND_RETRY_DELAYS_MS.length, 'первая попытка и три повтора, не больше');
        assert.ok(s.log.posts.every((request) => request === s.log.posts[0]), 'повторы идут тем же запросом, а не пересобранным');
        assert.deepStrictEqual(s.log.builds, ['id-1'], 'содержимое шифруется один раз');
        assert.strictEqual(s.log.idCalls, 1, 'новый id не выбирался');
        assert.deepStrictEqual(s.log.delays, SEND_RETRY_DELAYS_MS, 'паузы — ровно по таблице, по порядку');
        assert.strictEqual(result.data, failure);
        assert.strictEqual(result.request, s.log.posts[0], 'запрос возвращается вызывающему — он запомнит его для повторного «Отправить»');
        assert.strictEqual(result.clientMessageId, 'id-1');
    });

    test(`${label}, затем успех на последнем допустимом повторе: сообщение отправлено тем же запросом`, async () => {
        const s = rig({ responses: [...Array.from({ length: SEND_RETRY_DELAYS_MS.length }, () => failure), OK] });
        const result = await s.run();
        assert.strictEqual(result.data, OK);
        assert.strictEqual(s.log.posts.length, 1 + SEND_RETRY_DELAYS_MS.length);
        assert.ok(s.log.posts.every((request) => request === s.log.posts[0]));
        assert.strictEqual(s.log.builds.length, 1);
    });
}

test('успех с первой попытки: один запрос, ни одной паузы', async () => {
    const s = rig({ responses: [OK] });
    const result = await s.run();
    assert.strictEqual(s.log.posts.length, 1);
    assert.deepStrictEqual(s.log.delays, []);
    assert.deepStrictEqual({ ...result }, { data: OK, request: s.log.posts[0], clientMessageId: 'id-1' });
});

// ---- Отказы, которые повторять нельзя ----

const NO_RETRY = [
    ['400 client-outdated', HTTP(400, { code: 'client-outdated' })],
    ['400 bad-message-id', HTTP(400, { code: 'bad-message-id' })],
    ['400', HTTP(400)],
    ['401', HTTP(401)],
    ['403', HTTP(403)],
    ['404', HTTP(404)],
    ['409 с другим кодом', HTTP(409, { code: 'other' })],
    ['409 без кода', HTTP(409)],
    ['413', HTTP(413)],
    ['499', HTTP(499)],
    ['отказ без статуса', { success: false, message: 'Нельзя' }],
];

for (const [label, failure] of NO_RETRY) {
    test(`${label}: без повтора, id не меняется, ответ возвращается как есть`, async () => {
        const s = rig({ responses: [failure] });
        const result = await s.run();
        assert.strictEqual(s.log.posts.length, 1, 'повторять нельзя');
        assert.deepStrictEqual(s.log.delays, []);
        assert.deepStrictEqual(s.log.builds, ['id-1']);
        assert.strictEqual(s.log.idCalls, 1);
        assert.strictEqual(result.data, failure);
        assert.strictEqual(result.clientMessageId, 'id-1');
    });
}

// ---- 409 id-conflict: новый id, новое шифрование ----

test('409 id-conflict: новый id и заново собранный запрос; прежний запрос не отправляется второй раз', async () => {
    const s = rig({ responses: [CONFLICT, OK] });
    const result = await s.run();
    assert.deepStrictEqual(s.log.builds, ['id-1', 'id-2'], 'содержимое зашифровано заново под новым id');
    assert.strictEqual(s.log.posts.length, 2);
    assert.notStrictEqual(s.log.posts[1], s.log.posts[0]);
    assert.strictEqual(s.log.posts[1].clientMessageId, 'id-2');
    assert.deepStrictEqual(s.log.delays, [], 'конфликт — не повод для паузы');
    assert.strictEqual(result.data, OK);
    assert.strictEqual(result.clientMessageId, 'id-2', 'вызывающему возвращается id, под которым сообщение принято');
    assert.strictEqual(result.request, s.log.posts[1]);
});

test('409 id-conflict без конца: не больше MAX_ID_CONFLICTS попыток (MAX_ID_CONFLICTS − 1 новых id), затем отказ пользователю', async () => {
    const s = rig({ responses: Array.from({ length: MAX_ID_CONFLICTS }, () => CONFLICT) });
    const result = await s.run();
    assert.strictEqual(s.log.posts.length, MAX_ID_CONFLICTS);
    assert.strictEqual(s.log.idCalls, MAX_ID_CONFLICTS, 'первый id и MAX_ID_CONFLICTS − 1 новых');
    assert.strictEqual(new Set(s.log.builds).size, MAX_ID_CONFLICTS, 'каждая попытка — со своим id');
    assert.strictEqual(new Set(s.log.posts).size, MAX_ID_CONFLICTS, 'и со своим запросом');
    assert.strictEqual(result.data, CONFLICT, 'отказ с кодом id-conflict доходит до вызывающего');
    assert.strictEqual(result.data.code, 'id-conflict');
    assert.strictEqual(result.clientMessageId, `id-${MAX_ID_CONFLICTS}`);
});

test('409 id-conflict в чате с ботом (нет roomId): без повтора, clientMessageId не выдаётся', async () => {
    const s = rig({ responses: [CONFLICT], roomId: null });
    const result = await s.run();
    assert.strictEqual(s.log.posts.length, 1);
    assert.deepStrictEqual(s.log.builds, [null]);
    assert.strictEqual(s.log.idCalls, 0, 'у чата с ботом id сообщения клиент не выбирает');
    assert.strictEqual(result.clientMessageId, null);
    assert.strictEqual(result.data, CONFLICT);
});

test('чат с ботом: обрыв сети повторяется тем же запросом (id нет, но запрос тот же)', async () => {
    const s = rig({ responses: [NETWORK, NETWORK, OK], roomId: null });
    const result = await s.run();
    assert.strictEqual(s.log.posts.length, 3);
    assert.ok(s.log.posts.every((request) => request === s.log.posts[0]));
    assert.deepStrictEqual(s.log.builds, [null]);
    assert.deepStrictEqual(s.log.delays, SEND_RETRY_DELAYS_MS.slice(0, 2));
    assert.strictEqual(result.data, OK);
});

test('409 после повторов: сначала тот же запрос, потом новый id; у нового запроса счётчик повторов начинается заново', async () => {
    const s = rig({ responses: [NETWORK, CONFLICT, ...Array.from({ length: SEND_RETRY_DELAYS_MS.length }, () => TIMEOUT), OK] });
    const result = await s.run();
    const [first, retried, second, ...rest] = s.log.posts;
    assert.strictEqual(retried, first, 'повтор после обрыва — тот же запрос');
    assert.notStrictEqual(second, first, 'после 409 запрос пересобран');
    assert.ok(rest.every((request) => request === second), 'повторы нового запроса идут им же');
    assert.deepStrictEqual(s.log.builds, ['id-1', 'id-2']);
    assert.deepStrictEqual(s.log.delays, [SEND_RETRY_DELAYS_MS[0], ...SEND_RETRY_DELAYS_MS], 'у нового запроса снова все паузы с первой');
    assert.strictEqual(result.data, OK);
    assert.strictEqual(result.clientMessageId, 'id-2');
});

// ---- shouldStop ----

test('shouldStop обрывает повторы: ни паузы, ни второго запроса; запрос возвращается для запоминания', async () => {
    const s = rig({ responses: [TIMEOUT], shouldStop: () => true });
    const result = await s.run();
    assert.strictEqual(s.log.posts.length, 1);
    assert.deepStrictEqual(s.log.delays, []);
    assert.strictEqual(result.data, TIMEOUT);
    assert.strictEqual(result.request, s.log.posts[0]);
    assert.strictEqual(result.clientMessageId, 'id-1');
});

test('shouldStop проверяется перед каждой паузой: стоп после первого повтора оставляет ровно два запроса', async () => {
    const s = rig({ responses: [NETWORK, NETWORK, NETWORK, NETWORK], shouldStop: (checks) => checks >= 2 });
    const result = await s.run();
    assert.strictEqual(s.log.stopChecks, 2);
    assert.strictEqual(s.log.posts.length, 2);
    assert.deepStrictEqual(s.log.delays, [SEND_RETRY_DELAYS_MS[0]]);
    assert.strictEqual(result.data, NETWORK);
});

test('shouldStop не мешает отправке без сбоев', async () => {
    const s = rig({ responses: [OK], shouldStop: () => true });
    assert.strictEqual((await s.run()).data, OK);
});

// ---- reuse: запрос прошлой отправки с неизвестным исходом ----

test('reuse: первая попытка идёт запомненным запросом и его id, без нового шифрования и без нового id', async () => {
    const request = { remembered: true };
    const s = rig({ responses: [OK], reuse: { clientMessageId: 'old-id', request } });
    const result = await s.run();
    assert.deepStrictEqual(s.log.builds, [], 'buildRequest не вызывался');
    assert.strictEqual(s.log.idCalls, 0);
    assert.strictEqual(s.log.posts.length, 1);
    assert.strictEqual(s.log.posts[0], request, 'ушёл тот самый объект запроса');
    assert.deepStrictEqual({ ...result }, { data: OK, request, clientMessageId: 'old-id' });
});

test('reuse и снова обрыв: повторы идут тем же запомненным запросом', async () => {
    const request = { remembered: true };
    const s = rig({ responses: [NETWORK, NETWORK, OK], reuse: { clientMessageId: 'old-id', request } });
    await s.run();
    assert.ok(s.log.posts.every((sent) => sent === request));
    assert.strictEqual(s.log.posts.length, 3);
    assert.deepStrictEqual(s.log.builds, []);
});

test('reuse и 409 id-conflict: id занят — новый id и заново собранный запрос, а не тот же', async () => {
    const request = { remembered: true };
    const s = rig({ responses: [CONFLICT, OK], reuse: { clientMessageId: 'old-id', request } });
    const result = await s.run();
    assert.strictEqual(s.log.posts[0], request);
    assert.deepStrictEqual(s.log.builds, ['id-1'], 'пересборка — один раз, под свежим id');
    assert.notStrictEqual(s.log.posts[1], request);
    assert.strictEqual(result.clientMessageId, 'id-1');
});

test('reuse в чате с ботом: запомненный запрос уходит как есть', async () => {
    const request = { remembered: true };
    const s = rig({ responses: [OK], roomId: null, reuse: { clientMessageId: null, request } });
    const result = await s.run();
    assert.strictEqual(s.log.posts[0], request);
    assert.deepStrictEqual(s.log.builds, []);
    assert.strictEqual(result.clientMessageId, null);
});

// ---- buildRequest вернул null ----

test('buildRequest → null (собрать нельзя): ничего не отправляется, отказ с пустым сообщением', async () => {
    const s = rig({ responses: [], buildNull: [1] });
    const result = await s.run();
    assert.strictEqual(s.log.posts.length, 0);
    assert.deepStrictEqual(s.log.delays, []);
    assert.deepStrictEqual({ ...result }, { data: { success: false, message: '' } });
});

test('buildRequest → null при пересборке после 409: повторного запроса нет', async () => {
    const s = rig({ responses: [CONFLICT], buildNull: [2] });
    const result = await s.run();
    assert.strictEqual(s.log.posts.length, 1);
    assert.strictEqual(result.data.success, false);
    assert.strictEqual(result.data.message, '');
});

// ---- Подключение к странице ----

test('обёртка sendWithOutcomes из 14-send.js подставляет паузу страницы и генератор id (NyxoMessageOrder)', async () => {
    const delays = [];
    let n = 0;
    const responses = [NETWORK, CONFLICT, OK];
    const client = createClient({
        functions: ['sendWithOutcomes'],
        sandbox: {
            elements: fakeElements(),
            NyxoSendOutcomes: Outcomes,
            NyxoMessageOrder: { newClientMessageId: () => `page-id-${++n}` },
            delay: async (ms) => { delays.push(ms); },
        },
    });
    const built = [];
    client.context.__options = {
        roomId: 7,
        buildRequest: async (id) => { built.push(id); return { id }; },
        post: async () => responses.shift(),
    };
    const result = await client.run('sendWithOutcomes(__options)');
    assert.deepStrictEqual(delays, [SEND_RETRY_DELAYS_MS[0]], 'пауза — функция delay страницы');
    assert.deepStrictEqual(built, ['page-id-1', 'page-id-2'], 'id — из NyxoMessageOrder.newClientMessageId');
    assert.strictEqual(result.data.success, true);
    assert.strictEqual(result.clientMessageId, 'page-id-2');
});

test('index.html подключает lib/send-outcomes.js после message-order.js и до скриптов приложения, с integrity', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
    const at = (name) => html.indexOf(`<script src="${name}"`);
    assert.ok(at('lib/send-outcomes.js') > at('lib/message-order.js') && at('lib/message-order.js') > 0, 'порядок: message-order, затем send-outcomes');
    assert.ok(at('lib/send-outcomes.js') < at(clientScriptFiles()[0]), 'send-outcomes грузится раньше js/*');
    assert.match(html, /<script src="lib\/send-outcomes\.js" integrity="sha384-[A-Za-z0-9+/=]+"><\/script>/);
});

done();
