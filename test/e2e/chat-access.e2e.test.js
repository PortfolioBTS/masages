'use strict';
// Чужой chatId (IDOR): каждый маршрут, принимающий номер чата, на личную строку chats ДРУГОГО пользователя
// отвечает «Чат не найден», а в базе ничего не меняется (ревью W7 R5, В-3).
//
// Единственная проверка владения для большинства маршрутов - getOwnChat (src/services/chats.js:
// `c.id = $1 AND c.user_id = $2`); participants и member-certs (lib/e2ee-groups.js, resolveOwnRoom) и
// prefs (UPDATE ... WHERE user_id) проверяют владельца своим запросом. Тест не знает, какой из слоёв
// отказал: он требует итог - отказ в ответе, тот же, что и для несуществующего номера (иначе по
// ответу можно было бы перебирать чужие id), и неизменные таблицы.
//
// Нападающие:
//   * посторонний - аккаунт без комнат;
//   * участник ДРУГОЙ комнаты - у него есть своя комната, и проверка «состоит ли в какой-нибудь комнате»
//     его бы пропустила;
//   * сосед по комнате - участник той же комнаты, но с id личной строки владельца: проверка по комнате
//     (`EXISTS room_participants ... user_id = $2`) его пропускает, а личная строка принадлежит не ему
//     (двигать чужой маркер прочтения, менять чужие закрепление и архив ему нельзя).
// Цели: личная строка владельца в комнате и его чат с ботом.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');
const { fakeEnvelope } = require('./helpers/envelope');
const { dbSnapshot } = require('./helpers/db-snapshot');

const suite = createSuite('chat-access');

const NOT_FOUND = 'Чат не найден';
const UNKNOWN_CHAT_ID = 2147483000;

let worldPromise = null;
// Один мир на файл: владелец с комнатой, участник и заявитель в ней, посторонний, участник другой комнаты.
function world() {
    if (!worldPromise) {
        worldPromise = (async () => {
            const [owner, neighbor, applicant, stranger, outsider] = ['владелец', 'сосед', 'заявитель', 'посторонний', 'участник другой комнаты']
                .map(name => suite.client({ name }));
            for (const client of [owner, neighbor, applicant, stranger, outsider]) await client.registerAnon();
            const room = await roomWithMember(owner, neighbor, { name: 'Закрытая' });
            const { code } = await owner.invite(room.ownerChat.id);
            const pending = await applicant.join(code);
            assert.strictEqual(pending.pending, true, 'заявка ожидает одобрения');
            // Непрочитанное у владельца: отправка двигает маркер прочтения самого отправителя, поэтому последним
            // пишет сосед - маркер владельца отстаёт, и чужой POST /read было бы чему двигать.
            await owner.send(room.ownerChat.id, 'от владельца');
            const incoming = await neighbor.send(room.memberChat.id, 'от соседа');
            assert.strictEqual((await owner.chats()).find(c => c.id === room.ownerChat.id).unread, 1, 'фикстура: у владельца одно непрочитанное');
            const outsiderRoom = await outsider.createRoom('Чужая комната');
            const ownerBot = await owner.botChat();
            return { owner, neighbor, applicant, stranger, outsider, room, ownerBot, outsiderRoom, incoming };
        })();
    }
    return worldPromise;
}

// Маршруты с номером чата. call(client, chatId, w) -> сырой ответ. expect - ожидаемый отказ.
const REFUSED = { status: 200, message: NOT_FOUND };
const ROUTES = [
    { name: 'GET /api/messages/:chatId', call: (c, id) => c.get(`/api/messages/${id}`) },
    { name: 'POST /api/chats/:chatId/read', call: (c, id, w) => c.post(`/api/chats/${id}/read`, { upToSeq: w.incoming.seq }) },
    { name: 'GET /api/chats/invite/:chatId', call: (c, id) => c.get(`/api/chats/invite/${id}`) },
    { name: 'POST /api/chats/:chatId/invite/rotate', call: (c, id) => c.post(`/api/chats/${id}/invite/rotate`, { requireApproval: true }) },
    { name: 'POST /api/chats/:chatId/invite/disable', call: (c, id) => c.post(`/api/chats/${id}/invite/disable`, {}) },
    { name: 'GET /api/chats/:chatId/join-requests', call: (c, id) => c.get(`/api/chats/${id}/join-requests`) },
    { name: 'GET /api/chats/:chatId/participants', call: (c, id) => c.get(`/api/chats/${id}/participants`) },
    { name: 'GET /api/chats/:chatId/member-certs', call: (c, id, w) => c.get(`/api/chats/${id}/member-certs?subjects=${w.owner.user.id}`) },
    {
        name: 'POST /api/chats/:chatId/member-certs',
        call: (c, id, w) => c.post(`/api/chats/${id}/member-certs`, { subjectId: w.owner.user.id, cert: 'AAAA', snap: 'AAAA' }),
        expect: { status: 404, message: NOT_FOUND, code: 'not-participant' },
    },
    { name: 'POST /api/chats/:chatId/prefs', call: (c, id) => c.post(`/api/chats/${id}/prefs`, { pinned: true, muted: true, archived: true }) },
    { name: 'GET /api/chats/:chatId/settings', call: (c, id) => c.get(`/api/chats/${id}/settings`) },
    { name: 'POST /api/chats/:chatId/expiry', call: (c, id) => c.post(`/api/chats/${id}/expiry`, { seconds: 3600 }) },
    { name: 'POST /api/chats/:chatId/set-default-expiry', call: (c, id) => c.post(`/api/chats/${id}/set-default-expiry`, { expirySeconds: 3600 }) },
    { name: 'DELETE /api/chats/:chatId', call: (c, id) => c.del(`/api/chats/${id}`) },
    { name: 'DELETE /api/chats/:chatId?deleteMessages=1', call: (c, id) => c.del(`/api/chats/${id}?deleteMessages=1`) },
    // Тело без raw - текст бота и конверт комнаты разные; здесь важен только отказ по владельцу, поэтому конверт.
    {
        name: 'POST /api/messages',
        call: (c, id) => c.sendRaw(id, fakeEnvelope('чужой чат'), { raw: true, encrypted: true }),
    },
    {
        name: 'POST /api/messages/file',
        call: (c, id) => c.uploadCipherRaw(id),
        expect: { status: 404, message: NOT_FOUND },
    },
];

// Нужное в ответе-отказе: success false, текст отказа и ни одного поля с данными чата.
const DATA_FIELDS = ['messages', 'participants', 'requests', 'settings', 'certs', 'invite', 'roomId', 'message_id'];

// Тело ответа в сообщении об ошибке - коротко: в успешном ответе на историю лежит шифротекст.
const brief = body => JSON.stringify(body).slice(0, 160);

// Что не так с ответом: строка с причиной или null, если это ожидаемый отказ.
function refusalProblem(route, res) {
    const expect = route.expect || REFUSED;
    if (res.status !== expect.status) return `статус ${res.status} вместо ${expect.status}, тело ${brief(res.body)}`;
    if (!res.body || res.body.success !== false) return `ожидался отказ, пришло ${brief(res.body)}`;
    if (res.body.message !== expect.message) return `текст отказа «${res.body.message}» вместо «${expect.message}»`;
    if (expect.code && res.body.code !== expect.code) return `код отказа ${res.body.code} вместо ${expect.code}`;
    const leaked = DATA_FIELDS.filter(field => field in res.body);
    return leaked.length > 0 ? `в отказе утекли поля: ${leaked.join(', ')}` : null;
}

const ATTACKERS = [
    { key: 'stranger', title: 'посторонний (аккаунт без комнат)' },
    { key: 'outsider', title: 'участник другой комнаты' },
    { key: 'neighbor', title: 'сосед по комнате с id личной строки владельца' },
];
const TARGETS = [
    { key: 'room', title: 'личная строка владельца в комнате', chatId: w => w.room.ownerChat.id },
    { key: 'bot', title: 'чат владельца с ботом', chatId: w => w.ownerBot.id },
];

for (const attackerInfo of ATTACKERS) {
    for (const target of TARGETS) {
        test(`${attackerInfo.title} -> ${target.title}: каждый маршрут отвечает отказом, база не меняется`, async () => {
            const w = await world();
            const attacker = w[attackerInfo.key];
            const chatId = target.chatId(w);
            // Нарушения копятся по всем маршрутам: один красный прогон показывает, какие маршруты пропускают чужого.
            const problems = [];
            for (const route of ROUTES) {
                const before = await dbSnapshot(suite);
                const res = await route.call(attacker, chatId, w);
                const problem = refusalProblem(route, res);
                if (problem) problems.push(`${route.name}: ${problem}`);
                const after = await dbSnapshot(suite);
                const changed = Object.keys(before).filter(table => JSON.stringify(before[table]) !== JSON.stringify(after[table]));
                if (changed.length > 0) problems.push(`${route.name}: изменил таблицы ${changed.join(', ')}`);
            }
            assert.deepStrictEqual(problems, [], 'чужой chatId принят:\n' + problems.join('\n'));
        });
    }
}

test('отказ для чужого id неотличим от отказа для несуществующего и некорректного: перебирать id по ответу нельзя', async () => {
    const w = await world();
    const comparable = res => JSON.stringify({ status: res.status, body: res.body });
    const problems = [];
    for (const route of ROUTES) {
        const foreign = await route.call(w.stranger, w.room.ownerChat.id, w);
        const missing = await route.call(w.stranger, UNKNOWN_CHAT_ID, w);
        if (comparable(foreign) !== comparable(missing)) {
            problems.push(`${route.name}: чужой chatId -> ${brief(foreign.body)}, несуществующий -> ${brief(missing.body)}`);
        }
        const garbage = await route.call(w.stranger, 'abc', w);
        if (!garbage.body || garbage.body.success !== false) problems.push(`${route.name}: некорректный chatId принят: ${brief(garbage.body)}`);
    }
    assert.deepStrictEqual(problems, [], 'по ответу можно отличить чужой id от несуществующего:\n' + problems.join('\n'));
});

test('контроль набора: владелец теми же маршрутами со своим chatId получает данные (иначе отказы выше ничего не доказывают)', async () => {
    const w = await world();
    const { owner, room } = w;
    // Непрочитанное есть до чтения истории (GET messages отмечает прочитанным), и POST /read двигает его к нулю.
    assert.strictEqual((await owner.chats()).find(c => c.id === room.ownerChat.id).unread, 1, 'у владельца одно непрочитанное');
    assert.strictEqual((await owner.post(`/api/chats/${room.ownerChat.id}/read`, { upToSeq: w.incoming.seq })).body.success, true);
    assert.strictEqual((await owner.chats()).find(c => c.id === room.ownerChat.id).unread, 0);
    const history = await owner.get(`/api/messages/${room.ownerChat.id}`);
    assert.strictEqual(history.body.success, true);
    assert.strictEqual(history.body.messages.length, 2, 'два сообщения комнаты');
    assert.strictEqual((await owner.get(`/api/chats/invite/${room.ownerChat.id}`)).body.success, true);
    const requests = await owner.get(`/api/chats/${room.ownerChat.id}/join-requests`);
    assert.strictEqual(requests.body.success, true);
    assert.strictEqual(requests.body.requests.length, 1, 'заявка заявителя видна владельцу');
    const participants = await owner.get(`/api/chats/${room.ownerChat.id}/participants`);
    assert.strictEqual(participants.body.participants.length, 2);
    assert.strictEqual((await owner.get(`/api/chats/${room.ownerChat.id}/settings`)).body.success, true);
    assert.strictEqual((await owner.post(`/api/chats/${room.ownerChat.id}/prefs`, { pinned: true })).body.success, true);
    assert.strictEqual((await owner.get(`/api/messages/${w.ownerBot.id}`)).body.success, true);
});
