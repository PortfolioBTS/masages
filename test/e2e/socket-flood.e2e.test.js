'use strict';
// Поток событий по сокету (W7 R1 п.2): раньше каждый joinChat делал запрос в БД, и 10 сокетов
// по 8000 событий забивали пул соединений (посторонний ждал ~12 с, регистрация получала 503).
// Теперь событий сервер не принимает, а сокет, превысивший частоту, закрывается.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite, roomWithMember } = require('./helpers/scenarios');

const suite = createSuite('socket-flood');
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

test('10 сокетов по 3000 joinChat: сокеты закрываются, пул не занят, посторонние работают без задержек', async () => {
    const attacker = suite.client();
    await attacker.registerAnon();
    const stranger = suite.client();
    await stranger.registerAnon();
    const sockets = [];
    for (let i = 0; i < 10; i++) sockets.push(await attacker.socket());
    const before = (await suite.query("SELECT xact_commit + xact_rollback AS x FROM pg_stat_database WHERE datname = current_database()")).rows[0].x;

    for (const sock of sockets) for (let i = 0; i < 3000; i++) sock.emit('joinChat', `room:${1 + (i % 50)}`);

    const latencies = [];
    let registered = null;
    for (let i = 0; i < 6; i++) {
        const started = Date.now();
        const res = await stranger.get('/api/chats');
        latencies.push(Date.now() - started);
        assert.strictEqual(res.status, 200, `посторонний получил ${res.status}`);
        if (i === 2) {
            const newcomer = suite.client();
            await newcomer.registerAnon();
            registered = true;
        }
        await sleep(50);
    }
    assert.ok(registered, 'регистрация во время потока прошла');
    assert.ok(Math.max(...latencies) < 1500, `задержка постороннего: ${latencies.join(',')} мс`);

    for (const sock of sockets) {
        const gone = await sock.waitFor('disconnect', () => true, { timeoutMs: 5000 });
        assert.ok(gone, 'сокет-нарушитель закрыт сервером');
    }
    await sleep(300);
    const after = (await suite.query("SELECT xact_commit + xact_rollback AS x FROM pg_stat_database WHERE datname = current_database()")).rows[0].x;
    // 30000 событий не должны превратиться в 30000 запросов: обработчика нет.
    assert.ok(Number(after) - Number(before) < 1000, `транзакций за время потока: ${Number(after) - Number(before)}`);
    assert.strictEqual((await attacker.get('/api/chats')).status, 200, 'аккаунт нарушителя цел: закрывается только сокет');
});

test('joinChat на чужую комнату ничего не подписывает: событие игнорируется', async () => {
    const owner = suite.client();
    const member = suite.client();
    const stranger = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    await stranger.registerAnon();
    const { ownerChat } = await roomWithMember(owner, member);
    const roomKey = `room:${ownerChat.room_id}`;
    const outsider = await stranger.socket();
    const mark = outsider.history.length;
    outsider.emit('joinChat', roomKey);
    await sleep(300);
    await owner.uploadCipher(ownerChat.id, { label: 'secret.bin' });
    await sleep(500);
    const leaked = outsider.history.slice(mark).filter(e => e.event === 'newMessage');
    assert.deepStrictEqual(leaked, [], 'посторонний не получил сообщения комнаты');
    await outsider.close();
});
