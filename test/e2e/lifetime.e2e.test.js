'use strict';
// Срок жизни анонимного аккаунта (контракт волны 1, §3–§4; roadmap R2).
//
// Аккаунт живёт выбранный срок БЕЗ АКТИВНОСТИ: tab 30 минут, day 24 часа,
// week 7 дней; потолка от создания нет. Активность хранится корзинами по
// 5 минут (users.last_active_at, округление вверх). Время здесь не ждётся, а
// перематывается: last_active_at сдвигается назад (suite.time), чистку ведёт
// сам сервер (NYXO_TEST_MAINTENANCE_MS=300 — проход каждые 0,3 с).
//
// Что проверяется:
//   * anonExpiresAt: у day/week — корзина last_active_at + срок, у tab — null;
//     одно и то же в регистрации, /api/auth и /api/user;
//   * за сроком чистка удаляет пользователя, сессии, сообщения, файлы и
//     комнаты, где он был один; общие комнаты остаются;
//   * у самой границы срока пользователь жив;
//   * потолка от создания нет: week с created_at 30 дней назад и свежей
//     активностью жив;
//   * открытый сокет — признак «в сети»: чистка такого пользователя
//     пропускает, а touch продлевает last_active_at; закрыли сокет — удалён;
//   * запись активности — раз в корзину и только вверх.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createSuite, roomWithMember, waitUntil } = require('./helpers/scenarios');
const { LIFETIME_MS, LIFETIME_SECONDS, BUCKET_MS, MINUTE_MS, bucketCeil, userRow, count, setLastActive } = require('./helpers/anon');
const { createAuthorTags } = require('../../lib/author-tag');

const suite = createSuite('lifetime');

const LIFETIMES = ['tab', 'day', 'week'];
const PURGED_LINE = /\[Anon\] Удалено просроченных анонимных аккаунтов: (\d+)/;
// 1×1 PNG: вложение, которое должно уйти с диска вместе с аккаунтом.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');

const expectedExpiresAt = (lifetime, lastActiveMs) => (lifetime === 'tab' ? null : new Date(lastActiveMs + LIFETIME_MS[lifetime]).toISOString());
const uploadsOf = () => (fs.existsSync(suite.server.uploadsDir) ? fs.readdirSync(suite.server.uploadsDir) : []);

// Полный проход чистки анонимов, начатый после вызова.
const afterPurgePass = () => suite.server.waitForTick(2);

test('anonExpiresAt по формуле: tab — null, day/week — корзина last_active_at + срок; везде одинаково', async () => {
    for (const lifetime of LIFETIMES) {
        const client = suite.client();
        const before = Date.now();
        const registered = await client.registerAnon({ lifetime });
        const after = Date.now();

        const row = await userRow(suite, registered.id);
        assert.strictEqual(row.anon_lifetime, lifetime);
        // Корзина: кратна 5 минутам и ровно «ближайшая сверху» к моменту регистрации.
        assert.strictEqual(row.lastActiveMs % BUCKET_MS, 0, `${lifetime}: last_active_at не на границе корзины`);
        assert.ok(row.lastActiveMs >= bucketCeil(before) && row.lastActiveMs <= bucketCeil(after),
            `${lifetime}: last_active_at ${new Date(row.lastActiveMs).toISOString()} не округлён вверх от момента регистрации`);
        // created_at — до минуты.
        const created = new Date(row.created_at);
        assert.ok(created.getUTCSeconds() === 0 && created.getUTCMilliseconds() === 0, `${lifetime}: created_at должен быть округлён до минуты`);

        const expected = {
            anonLifetime: lifetime,
            anonInactivitySeconds: LIFETIME_SECONDS[lifetime],
            anonExpiresAt: expectedExpiresAt(lifetime, row.lastActiveMs),
        };
        const pick = (user) => ({ anonLifetime: user.anonLifetime, anonInactivitySeconds: user.anonInactivitySeconds, anonExpiresAt: user.anonExpiresAt });
        assert.deepStrictEqual(pick(registered), expected, `${lifetime}: ответ регистрации`);
        assert.strictEqual(registered.readReceipts, false);
        assert.strictEqual(registered.isAnonymous, true);

        const auth = await client.auth();
        assert.strictEqual(auth.authenticated, true);
        assert.deepStrictEqual(pick(auth.user), expected, `${lifetime}: /api/auth`);

        const info = await client.get('/api/user');
        assert.strictEqual(info.body.success, true);
        assert.deepStrictEqual(pick(info.body.user), expected, `${lifetime}: /api/user`);
        if (lifetime !== 'tab') assert.match(auth.user.anonExpiresAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/, 'ISO-время на границе минуты');
    }
});

test('активность пишется раз в корзину и только вверх; запрос после долгого молчания возвращает её в текущую корзину', async () => {
    const client = suite.client();
    const user = await client.registerAnon({ lifetime: 'week' });

    // Кэш активности живёт в памяти сервера, перемотку базы он не видит —
    // «долгое молчание» наступает после рестарта (новый процесс читает базу).
    await suite.time.rewindUser(user.id, { lastActiveMs: 3 * 24 * 60 * MINUTE_MS });
    const stale = (await userRow(suite, user.id)).lastActiveMs;
    await suite.server.restart();

    for (let attempt = 1; ; attempt++) {
        const bucketBefore = bucketCeil(Date.now());
        assert.strictEqual((await client.auth()).authenticated, true, 'через трое суток молчания неделя ещё жива');
        const refreshed = (await userRow(suite, user.id)).lastActiveMs;
        // Второй запрос в той же корзине: в базе ничего не меняется (даже если значение подменили вручную).
        await suite.query('UPDATE users SET last_active_at = $2 WHERE id = $1', [user.id, new Date(refreshed - MINUTE_MS)]);
        assert.strictEqual((await client.auth()).authenticated, true);
        const sameBucket = bucketCeil(Date.now()) === bucketBefore;
        const second = (await userRow(suite, user.id)).lastActiveMs;
        if (!sameBucket && attempt < 3) continue;   // границу корзины перешли между запросами — повторить
        assert.ok(refreshed > stale, 'запрос после молчания записал новую корзину');
        assert.strictEqual(refreshed % BUCKET_MS, 0);
        assert.ok(refreshed >= bucketBefore && refreshed <= bucketBefore + BUCKET_MS, 'корзина — ближайшая сверху от момента запроса');
        assert.strictEqual(second, refreshed - MINUTE_MS, 'во второй раз в той же корзине запись не повторяется');
        break;
    }

    // Только вверх: значение из будущего запрос не откатывает.
    const future = bucketCeil(Date.now()) + 2 * 60 * MINUTE_MS;
    await suite.query('UPDATE users SET last_active_at = $2 WHERE id = $1', [user.id, new Date(future)]);
    await suite.server.restart();
    assert.strictEqual((await client.auth()).authenticated, true);
    assert.strictEqual((await userRow(suite, user.id)).lastActiveMs, future, 'last_active_at никогда не уменьшается');
});

for (const lifetime of LIFETIMES) {
    test(`${lifetime}: за сроком чистка удаляет пользователя, сессии, сообщения, файлы и одинокие комнаты; общая комната остаётся`, async () => {
        const victim = suite.client();
        const survivor = suite.client();
        const victimUser = await victim.registerAnon({ lifetime });
        const survivorUser = await survivor.registerAnon({ lifetime: 'week' });

        // Что у пользователя есть: чат с ботом (приветствие и своё сообщение), файл, одинокая комната и комната с другим человеком.
        const bot = await victim.botChat();
        await victim.send(bot.id, 'сообщение боту');
        const file = await victim.upload(bot.id, PNG, 'image/png', { filename: 'a.png' });
        const solo = await victim.createRoom('Комната одного');
        await victim.send(solo.id, 'одинокое сообщение');
        const shared = await roomWithMember(victim, survivor, { name: 'Общая комната' });
        const sharedMessage = await victim.send(shared.ownerChat.id, 'сообщение в общей комнате');
        const survivorMessage = await survivor.send(shared.memberChat.id, 'сообщение выжившего');
        // Сообщения комнат (sealed sender) user_id не несут: их следы - строки с тегами автора.
        const tagLib = createAuthorTags([Buffer.from(suite.secrets.MESSAGE_ENCRYPTION_KEY, 'base64')]);
        const victimCreated = (await userRow(suite, victimUser.id)).created_at;
        const victimTags = [solo.room_id, shared.roomId].flatMap(roomId => tagLib.tagsForAccount(roomId, victimUser.id, victimCreated, Date.now()));
        assert.strictEqual(await count(suite, 'SELECT 1 FROM messages WHERE author_tag = ANY($1::bytea[])', [victimTags]), 2, 'до чистки: одинокое и общее сообщения');
        assert.ok(uploadsOf().includes(path.basename(file.file_url)), 'файл лежит на диске');
        assert.ok(await count(suite, 'SELECT 1 FROM session WHERE sess->>\'userId\' = $1', [String(victimUser.id)]) >= 1);

        // Срок вышел минуту назад.
        const mark = suite.server.logs.mark();
        await setLastActive(suite, victimUser.id, lifetime, { pastMs: MINUTE_MS });
        await suite.server.logs.waitFor(PURGED_LINE, { from: mark });

        assert.strictEqual(await userRow(suite, victimUser.id), null, 'пользователь удалён');
        const id = [victimUser.id];
        assert.strictEqual(await count(suite, 'SELECT 1 FROM chats WHERE user_id = $1', id), 0, 'чаты');
        assert.strictEqual(await count(suite, 'SELECT 1 FROM messages WHERE user_id = $1', id), 0, 'сообщения');
        assert.strictEqual(await count(suite, 'SELECT 1 FROM messages WHERE author_tag = ANY($1::bytea[])', [victimTags]), 0, 'сообщения в комнатах (по тегам автора)');
        assert.strictEqual(await count(suite, 'SELECT 1 FROM room_participants WHERE user_id = $1', id), 0, 'участие в комнатах');
        assert.strictEqual(await count(suite, 'SELECT 1 FROM session WHERE sess->>\'userId\' = $1', [String(victimUser.id)]), 0, 'сессии');
        assert.strictEqual(await count(suite, 'SELECT 1 FROM rooms WHERE id = $1', [solo.room_id]), 0, 'комната, где он был один, удалена');
        assert.strictEqual(await count(suite, 'SELECT 1 FROM messages WHERE room_id = $1', [solo.room_id]), 0, 'сообщения одинокой комнаты');
        await waitUntil(() => !uploadsOf().includes(path.basename(file.file_url)), { what: 'файл удалённого аккаунта убран с диска' });

        // Общая комната осталась у выжившего; чужие сообщения целы, сообщения ушедшего — нет.
        assert.strictEqual(await count(suite, 'SELECT 1 FROM rooms WHERE id = $1', [shared.roomId]), 1, 'общая комната на месте');
        const members = (await suite.query('SELECT user_id FROM room_participants WHERE room_id = $1', [shared.roomId])).rows.map(r => r.user_id);
        assert.deepStrictEqual(members, [survivorUser.id]);
        const kept = (await survivor.messages(shared.memberChat.id)).messages.map(m => m.id);
        assert.ok(kept.includes(survivorMessage.id), 'сообщение выжившего осталось');
        assert.ok(!kept.includes(sharedMessage.id), 'сообщение удалённого аккаунта исчезло');

        assert.deepStrictEqual(await victim.auth(), { authenticated: false, onionUrl: null }, 'сессия удалённого аккаунта недействительна');
        assert.strictEqual((await survivor.auth()).authenticated, true, 'остальные не затронуты');
    });
}

test('у самой границы срока пользователь жив: до конца срока остаётся от полутора до шести с половиной минут — чистка его не трогает', async () => {
    for (const lifetime of LIFETIMES) {
        const client = suite.client();
        const user = await client.registerAnon({ lifetime });
        const bot = await client.botChat();
        await client.send(bot.id, 'я ещё здесь');
        // last_active_at = «сейчас − срок + 90 секунд» (на границе корзины, вверх): до удаления остаётся не меньше 90 с.
        await setLastActive(suite, user.id, lifetime, { pastMs: -90 * 1000 });
        await afterPurgePass();
        const row = await userRow(suite, user.id);
        assert.ok(row, `${lifetime}: за 90 секунд до границы пользователь удалён раньше срока`);
        assert.ok(row.lastActiveMs < Date.now() - LIFETIME_MS[lifetime] + 7 * MINUTE_MS, `${lifetime}: проверка не должна была продлить аккаунт`);
        assert.strictEqual(await count(suite, 'SELECT 1 FROM messages WHERE user_id = $1', [user.id]) >= 2, true, `${lifetime}: сообщения целы`);
        // И сам он — по-прежнему в аккаунте (этот запрос — уже активность).
        assert.strictEqual((await client.auth()).authenticated, true, `${lifetime}`);
    }
});

test('потолка от создания нет: created_at 30 дней назад и свежая активность — аккаунт жив при любом сроке', async () => {
    for (const lifetime of LIFETIMES) {
        const client = suite.client();
        const user = await client.registerAnon({ lifetime });
        await suite.time.rewindUser(user.id, { createdMs: 30 * 24 * 60 * MINUTE_MS });
        await afterPurgePass();
        assert.ok(await userRow(suite, user.id), `${lifetime}: аккаунт месячной давности со свежей активностью удалён`);
        const auth = await client.auth();
        assert.strictEqual(auth.authenticated, true, lifetime);
        assert.strictEqual(auth.user.anonLifetime, lifetime);
    }
});

for (const [lifetime, rewind] of [['tab', 2 * 60 * MINUTE_MS], ['week', 8 * 24 * 60 * MINUTE_MS]]) {
    test(`${lifetime}: с открытым сокетом аккаунт переживает перемотку за срок (touch), без сокета — нет`, async () => {
        const client = suite.client();
        const user = await client.registerAnon({ lifetime });
        const sock = await client.socket();
        try {
            await suite.time.rewindUser(user.id, { lastActiveMs: rewind });
            // touch открытых сокетов возвращает активность в текущую корзину, а чистка таких пользователей пропускает.
            const refreshed = await waitUntil(async () => {
                const row = await userRow(suite, user.id);
                return row && row.lastActiveMs >= bucketCeil(Date.now() - 5000) ? row : null;
            }, { what: 'touch сокета продлил last_active_at' });
            assert.ok(refreshed.lastActiveMs >= bucketCeil(Date.now() - 5000), 'touch записал текущую корзину');
            await afterPurgePass();
            assert.ok(await userRow(suite, user.id), 'пользователь с открытым сокетом удалён');
            assert.strictEqual((await client.auth()).authenticated, true);
        } finally {
            await sock.close();
        }

        // Сокет закрыт, а в базе — давно: теперь он «ушёл», и чистка его заберёт.
        const mark = suite.server.logs.mark();
        await suite.time.rewindUser(user.id, { lastActiveMs: rewind });
        await suite.server.logs.waitFor(PURGED_LINE, { from: mark });
        assert.strictEqual(await userRow(suite, user.id), null, 'после закрытия сокета аккаунт удаляется по сроку');
    });
}

test('в логе сервера нет id, имён и кодов удалённых аккаунтов — только счётчики', async () => {
    const users = (await suite.query('SELECT id, username, unique_code FROM users')).rows;
    assert.ok(users.length > 0);
    suite.server.logs.assertNoSensitive({
        usernames: users.map(u => u.username),
        codes: users.map(u => u.unique_code),
    });
    assert.ok(suite.server.logs.count(PURGED_LINE) >= 3, 'строки о чистке в логе есть');
});
