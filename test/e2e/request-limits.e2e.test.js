'use strict';
// Лимиты, значения которых заданы константами кода (ревью W7 R5, З-5). Лимиты из окружения (SOCKET_EVENT_*,
// UPLOAD_*, REGISTER_*, ROOMS_PER_USER_MAX, TEXT_QUOTA_MB_PER_DAY) проверяют свои наборы со сниженными значениями;
// здесь - те, которые настроить нельзя, поэтому тесты упираются в настоящие числа:
//   * общий лимит /api: 1000 запросов за 15 минут на аккаунт (вне входа - на IP), src/http/middleware/rate-limits.js;
//   * вложение: до 50 МБ включительно, 50 МБ + 1 байт - 413; второй файл в запросе - отказ (middleware/upload.js);
//   * сокеты: 10 на аккаунт и 20 на IP (src/realtime/io.js).

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const { createSuite, waitUntil } = require('./helpers/scenarios');
const { fakeEnvelope } = require('./helpers/envelope');
const { newClientMessageId, PROTO } = require('./helpers/client');

const suite = createSuite('request-limits');

const API_LIMIT = 1000;
const FILE_LIMIT = 50 * 1024 * 1024;

// n запросов подряд пачками по 25 (порядок не важен: лимит считает запросы, а не их содержание).
async function hit(client, n, path = '/api/auth') {
    const statuses = [];
    for (let done = 0; done < n; done += 25) {
        const batch = await Promise.all(Array.from({ length: Math.min(25, n - done) }, () => client.get(path).then(res => res.status)));
        statuses.push(...batch);
    }
    return statuses;
}

test('общий лимит API: аккаунту доступно ровно 1000 запросов за окно, 1001-й - 429; другой аккаунт не затронут', async () => {
    const heavy = suite.client({ name: 'много запросов' });
    const other = suite.client({ name: 'другой' });
    await heavy.registerAnon();
    await other.registerAnon();
    await heavy.csrfToken();   // GET за кукой csrf_token тоже считается: делаем его до отсчёта

    const first = await heavy.get('/api/auth');
    assert.strictEqual(first.status, 200);
    // Заголовки лимитера (standardHeaders) называют сам предел: его же и проверяем счётом ниже.
    const limitHeader = first.headers.get('ratelimit-limit') || /limit=(\d+)/.exec(first.headers.get('ratelimit') || '')?.[1];
    assert.strictEqual(Number(limitHeader), API_LIMIT, `заголовок лимита: ${limitHeader}`);

    const rest = await hit(heavy, API_LIMIT - 1);
    assert.ok(rest.every(s => s === 200), `первые ${API_LIMIT} запросов проходят: ${[...new Set(rest)]}`);
    const over = await heavy.get('/api/auth');
    assert.strictEqual(over.status, 429, 'запрос сверх предела');
    assert.deepStrictEqual(over.body, { success: false, message: 'Слишком много запросов. Попробуйте позже.' });
    assert.strictEqual((await heavy.get('/api/chats')).status, 429, 'лимит общий для всех маршрутов /api');
    // Счёт идёт по аккаунту, а не по IP: у другого аккаунта (и другого IP) он свой.
    assert.strictEqual((await other.get('/api/auth')).status, 200);
    assert.strictEqual((await other.get('/api/chats')).status, 200);
});

test('общий лимит API до входа считается по IP: 1000 запросов проходят, 1001-й - 429, другой IP не затронут', async () => {
    const anonymous = suite.client({ xff: '10.98.0.1' });
    const neighbour = suite.client({ xff: '10.98.0.2' });
    await anonymous.csrfToken();   // GET /api/auth за кукой - первый из запросов окна
    const statuses = await hit(anonymous, API_LIMIT - 1);
    assert.ok(statuses.every(s => s === 200), `первые ${API_LIMIT} запросов проходят: ${[...new Set(statuses)]}`);
    assert.strictEqual((await anonymous.get('/api/auth')).status, 429);
    assert.strictEqual((await neighbour.get('/api/auth')).status, 200);
});

// ---- Размер и число файлов в запросе ----

// Шифротекст нужного размера: сервер вложения в комнате не читает, ему важны только размер и конверт.
const cipher = (size) => Buffer.alloc(size, 0x5a);
const filesOnDisk = () => fs.readdirSync(suite.server.uploadsDir).filter(name => !name.startsWith('.'));
const fileMessages = async (roomId) => (await suite.query('SELECT count(*)::int AS n FROM messages WHERE room_id = $1 AND file_url IS NOT NULL', [roomId])).rows[0].n;

test('вложение: ровно 50 МБ принимается, 50 МБ + 1 байт - 413 «Файл слишком большой», на диске и в базе ничего', async () => {
    const owner = suite.client({ name: 'владелец' });
    await owner.registerAnon();
    const chat = await owner.createRoom('Размер файла');
    const before = filesOnDisk().length;

    const over = await owner.uploadCipherRaw(chat.id, { bytes: cipher(FILE_LIMIT + 1), label: 'на байт больше' });
    assert.strictEqual(over.status, 413, JSON.stringify(over.body));
    assert.deepStrictEqual(over.body, { success: false, message: 'Файл слишком большой (макс. 50 МБ)' });
    await waitUntil(() => filesOnDisk().length === before, { what: 'отклонённый по размеру файл не остался на диске' });
    assert.strictEqual(await fileMessages(chat.room_id), 0, 'сообщение с вложением не создано');

    const exact = await owner.uploadCipherRaw(chat.id, { bytes: cipher(FILE_LIMIT), label: 'ровно предел' });
    assert.strictEqual(exact.status, 200, JSON.stringify(exact.body).slice(0, 300));
    assert.strictEqual(await fileMessages(chat.room_id), 1);
    assert.strictEqual(filesOnDisk().length, before + 1);
});

test('вложение: второй файл в запросе - отказ «Too many files», первый не остаётся ни на диске, ни в базе', async () => {
    const owner = suite.client({ name: 'владелец' });
    await owner.registerAnon();
    const chat = await owner.createRoom('Два файла');
    const before = filesOnDisk().length;

    // Поля - ДО файлов (как требует контракт), потом два файла под одним именем поля.
    const form = new FormData();
    form.append('proto', String(PROTO));
    form.append('chatId', String(chat.id));
    form.append('encrypted', 'true');
    form.append('clientMessageId', newClientMessageId());
    form.append('envelope', fakeEnvelope('два файла'));
    form.append('file', new Blob([cipher(300)], { type: 'application/octet-stream' }), 'one.bin');
    form.append('file', new Blob([cipher(300)], { type: 'application/octet-stream' }), 'two.bin');
    const res = await owner.request('POST', '/api/messages/file', { body: form });
    // Именно лимит files (busboy: filesLimit -> LIMIT_FILE_COUNT -> «Too many files»); без него второй файл
    // отсекал бы только upload.single('file') другим текстом («Unexpected field»).
    assert.strictEqual(res.status, 400, JSON.stringify(res.body));
    assert.strictEqual(res.body.message, 'Ошибка загрузки: Too many files');
    await waitUntil(() => filesOnDisk().length === before, { what: 'файлы отклонённого запроса удалены с диска' });
    assert.strictEqual(await fileMessages(chat.room_id), 0, 'сообщение с вложением не создано');
    // Контроль: тот же запрос с одним файлом проходит.
    const single = await owner.uploadCipherRaw(chat.id, { label: 'один файл' });
    assert.strictEqual(single.status, 200, JSON.stringify(single.body).slice(0, 300));
});

// ---- Одновременные сокеты ----

test('сокеты: 11-й сокет аккаунта - «Слишком много подключений», после закрытия одного подключение снова проходит', async (t) => {
    const user = suite.client({ name: 'много вкладок' });
    await user.registerAnon();
    const sockets = [];
    t.after(() => Promise.all(sockets.map(s => s.close())));
    for (let i = 0; i < 10; i++) sockets.push(await user.socket());

    await assert.rejects(user.socket(), (err) => {
        assert.strictEqual(err.kind, 'connect_error');
        assert.strictEqual(err.reason, 'Слишком много подключений');
        return true;
    });
    // Предел на аккаунт: сокеты другого аккаунта (и IP) не мешают и не считаются.
    const other = suite.client({ name: 'другой' });
    await other.registerAnon();
    sockets.push(await other.socket());

    // Закрытое соединение освобождает место (disconnect уменьшает счётчик на сервере - асинхронно).
    await sockets.shift().close();
    let replacement = null;
    await waitUntil(async () => {
        try {
            replacement = await user.socket();
            return true;
        } catch (err) {
            if (err.reason !== 'Слишком много подключений') throw err;
            return false;
        }
    }, { what: 'после закрытия сокета подключение снова принимается' });
    sockets.push(replacement);
});

test('сокеты: 21-й сокет с одного IP - «Слишком много подключений с вашего IP», пока счёт ведётся по адресу, а не по аккаунту', async (t) => {
    const xff = '10.98.7.7';
    const users = [];
    for (let i = 0; i < 3; i++) {
        const c = suite.client({ name: `за одним адресом ${i}`, xff });
        await c.registerAnon();
        users.push(c);
    }
    const sockets = [];
    t.after(() => Promise.all(sockets.map(s => s.close())));
    // 7 + 7 + 6 = 20 сокетов, у каждого аккаунта - меньше своего предела в 10.
    for (const [i, c] of users.entries()) {
        for (let n = 0; n < (i < 2 ? 7 : 6); n++) sockets.push(await c.socket());
    }
    await assert.rejects(users[2].socket(), (err) => {
        assert.strictEqual(err.kind, 'connect_error');
        assert.strictEqual(err.reason, 'Слишком много подключений с вашего IP');
        return true;
    });
    // С другого адреса тот же аккаунт подключается.
    sockets.push(await users[2].socket({ xff: '10.98.7.8' }));
});
