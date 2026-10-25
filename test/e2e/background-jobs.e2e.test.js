'use strict';
// Фоновые задачи сервера, которые срабатывают без обращения клиента (ревью W7 R5, З-6). Время не ждётся, а
// перематывается (suite.time), проходы идут каждые 0,3 с (NYXO_TEST_MAINTENANCE_MS):
//   * purgeExpiredJoinRequests (src/services/rooms.js): заявка старше недели исчезает из БД сама, заявителю
//     уходит «отклонена», участникам - «список заявок изменился». Выборки API просроченные заявки и так не
//     показывают, поэтому тест смотрит в таблицу, а не в ответы API;
//   * purgeExpiredAnonymousUsers (src/services/accounts.js): аккаунт с открытым сокетом чистка пропускает
//     (userSocketCount.keys() -> NOT (id = ANY($4))), даже если last_active_at давно истёк.
//
// Второе нельзя проверить перемоткой «в лоб»: задача touchOnlineSockets (тоже каждые 0,3 с) возвращает активность
// открытого сокета в текущую корзину быстрее, чем чистка успевает выбрать строку, и без пропуска сокетов аккаунт
// всё равно выживал бы (так мутацию и не замечали). Поэтому тест ставит в БД своего набора триггер, который
// не даёт last_active_at пользователя расти: touch (и запись активности при отключении) становятся пустыми, и
// аккаунт защищает ТОЛЬКО пропуск открытых сокетов.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, waitUntil } = require('./helpers/scenarios');
const { MINUTE_MS, userRow } = require('./helpers/anon');

const suite = createSuite('background-jobs');

const DAY_MS = 24 * 60 * MINUTE_MS;

test('просроченная заявка на вступление удаляется из базы сама; заявитель и участники узнают по сокету, свежая заявка остаётся', async (t) => {
    const owner = suite.client({ name: 'владелец' });
    const stale = suite.client({ name: 'опоздавший заявитель' });
    const fresh = suite.client({ name: 'свежий заявитель' });
    for (const c of [owner, stale, fresh]) await c.registerAnon();
    const chat = await owner.createRoom('Заявки');
    const { code } = await owner.invite(chat.id);
    const staleRequest = await stale.join(code);
    const freshRequest = await fresh.join(code);
    assert.ok(staleRequest.pending && freshRequest.pending, 'в комнате с одобрением вход - заявка');
    const ownerSock = await owner.socket();
    const staleSock = await stale.socket();
    t.after(() => Promise.all([ownerSock.close(), staleSock.close()]));

    const requestExists = async (id) => (await suite.query('SELECT 1 FROM join_requests WHERE id = $1', [id])).rowCount === 1;
    assert.ok(await requestExists(staleRequest.requestId));

    // Неделя + сутки назад: за сроком. Дальше клиенты не делают ни одного запроса.
    const ownerMark = ownerSock.mark();
    await suite.time.rewindJoinRequest(staleRequest.requestId, 8 * DAY_MS);
    await waitUntil(async () => !(await requestExists(staleRequest.requestId)), { what: 'просроченная заявка удалена фоновой задачей' });

    const decided = await staleSock.waitFor('joinRequestDecided', p => p.requestId === staleRequest.requestId);
    assert.strictEqual(decided.approved, false);
    assert.deepStrictEqual(await ownerSock.waitFor('joinRequestsChanged', p => p.roomId === chat.room_id, { since: ownerMark }), { roomId: chat.room_id });
    assert.ok(await requestExists(freshRequest.requestId), 'свежая заявка не тронута');
    // Заявитель остаётся аккаунтом без комнаты, а у владельца в списке только свежая заявка.
    assert.deepStrictEqual((await owner.joinRequests(chat.id)).map(r => r.id), [freshRequest.requestId]);
    assert.ok(!(await stale.chats()).some(c => c.room_id === chat.room_id));
});

test('аккаунт с открытым сокетом не удаляется чисткой при истёкшем last_active_at; без сокета - удаляется', async () => {
    const client = suite.client({ name: 'открытая вкладка' });
    const user = await client.registerAnon({ lifetime: 'tab' });
    const sock = await client.socket();
    // Триггер только на этого пользователя и только против РОСТА last_active_at (перемотка назад проходит).
    await suite.query(`
        CREATE FUNCTION nyxo_test_keep_last_active() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.id = ${Number(user.id)} AND NEW.last_active_at > OLD.last_active_at THEN
                NEW.last_active_at := OLD.last_active_at;
            END IF;
            RETURN NEW;
        END $$`);
    await suite.query('CREATE TRIGGER nyxo_test_keep_last_active BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION nyxo_test_keep_last_active()');
    try {
        // Срок tab - 30 минут; активность два часа назад.
        await suite.time.rewindUser(user.id, { lastActiveMs: 2 * 60 * MINUTE_MS });
        const rewound = await userRow(suite, user.id);
        assert.ok(rewound.lastActiveMs < Date.now() - 60 * MINUTE_MS, 'активность в БД за сроком');

        // Несколько полных проходов чистки при открытом сокете.
        await suite.server.waitForTick(4);
        const after = await userRow(suite, user.id);
        assert.ok(after, 'аккаунт с открытым сокетом удалён чисткой');
        assert.strictEqual(after.lastActiveMs, rewound.lastActiveMs, 'триггер держит активность старой: аккаунт защищает только открытый сокет');
        assert.strictEqual(sock.connected, true, 'сокет жив');

        // Контроль: сокет закрыт - тот же аккаунт за сроком, и чистка его забирает.
        await sock.close();
        await waitUntil(async () => (await userRow(suite, user.id)) === null, { what: 'без сокета просроченный аккаунт удалён чисткой' });
    } finally {
        await suite.query('DROP TRIGGER IF EXISTS nyxo_test_keep_last_active ON users');
        await suite.query('DROP FUNCTION IF EXISTS nyxo_test_keep_last_active()');
        await sock.close();
    }
});
