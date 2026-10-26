'use strict';
// Засевает БД СТАРОЙ версией сервера (до этапа 1): два аккаунта с паролем,
// один аноним, комната с одобренными участниками и сообщениями.
// Работает только против сервера версии 2.0.0 (коммит 12f7aa8), см. README.md.
// Запуск: BASE=http://127.0.0.1:3100 node test/e2e/fixtures/seed-legacy-2.0.0.js
const crypto = require('crypto');

const BASE = process.env.BASE || 'http://127.0.0.1:3100';

function makeClient(name) {
    const jar = new Map();
    async function call(path, { method = 'GET', body } = {}) {
        const headers = { 'Content-Type': 'application/json' };
        if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
        if (jar.has('csrf_token')) headers['X-CSRF-Token'] = jar.get('csrf_token');
        const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
        for (const line of res.headers.getSetCookie()) {
            const [pair] = line.split(';');
            const eq = pair.indexOf('=');
            jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
        }
        const data = await res.json().catch(() => null);
        return data;
    }
    return { name, call };
}

function leadingZeroBits(bytes) {
    let bits = 0;
    for (const b of bytes) {
        if (b === 0) { bits += 8; continue; }
        return bits + Math.clz32(b) - 24;
    }
    return bits;
}

async function pow(client, purpose) {
    const ch = await client.call(`/api/pow/challenge?purpose=${purpose}`);
    for (let n = 0; ; n++) {
        const digest = crypto.createHash('sha256').update(`${ch.token}:${n}`, 'utf8').digest();
        if (leadingZeroBits(digest) >= ch.difficulty) return { token: ch.token, nonce: String(n) };
    }
}

function must(data, what) {
    if (!data || data.success === false) throw new Error(`${what}: ${JSON.stringify(data)}`);
    return data;
}

(async () => {
    const alice = makeClient('alice');
    const bob = makeClient('bob');
    const guest = makeClient('guest');
    for (const c of [alice, bob, guest]) await c.call('/api/auth'); // CSRF-кука

    const reg = async (c, username) => must(await c.call('/api/register', {
        method: 'POST',
        body: { username, email: `${username}@example.test`, password: 'Correct-Horse-7351', confirmPassword: 'Correct-Horse-7351', pow: await pow(c, 'register') },
    }), `register ${username}`);
    const a = await reg(alice, 'alice');
    const b = await reg(bob, 'bob');
    const g = must(await guest.call('/api/register/anonymous', { method: 'POST', body: { lifetime: 'day', pow: await pow(guest, 'register-anon') } }), 'anon');

    // Повторный вход alice паролем — событие login в журнале безопасности.
    must(await alice.call('/api/login', { method: 'POST', body: { email: 'alice@example.test', password: 'Correct-Horse-7351' } }), 'login alice');

    const room = must(await alice.call('/api/chats', { method: 'POST', body: { name: 'Команда' } }), 'create room');
    const code = room.chat.invite_code;
    const aliceChatId = room.chat.id;

    for (const c of [bob, guest]) {
        const j = must(await c.call('/api/chats/join', { method: 'POST', body: { code } }), `join ${c.name}`);
        if (!j.pending) throw new Error('ожидалась заявка');
    }
    const reqs = must(await alice.call(`/api/chats/${aliceChatId}/join-requests`), 'requests');
    for (const r of reqs.requests) must(await alice.call(`/api/join-requests/${r.id}/approve`, { method: 'POST' }), 'approve');

    const chatsOf = async (c) => must(await c.call('/api/chats'), 'chats').chats.find(x => x.room_id === room.chat.room_id);
    const bobChat = await chatsOf(bob);
    const guestChat = await chatsOf(guest);

    must(await alice.call('/api/messages', { method: 'POST', body: { chatId: aliceChatId, text: 'Привет всем' } }), 'msg1');
    must(await bob.call('/api/messages', { method: 'POST', body: { chatId: bobChat.id, text: 'Привет, alice' } }), 'msg2');
    must(await guest.call('/api/messages', { method: 'POST', body: { chatId: guestChat.id, text: 'Я гость' } }), 'msg3');
    must(await alice.call('/api/messages', { method: 'POST', body: { chatId: aliceChatId, text: 'Второе сообщение alice' } }), 'msg4');

    // Отдельная комната только у bob — должна исчезнуть целиком вместе с ним.
    must(await bob.call('/api/chats', { method: 'POST', body: { name: 'Личное bob' } }), 'bob room');

    console.log(JSON.stringify({ alice: a.user.id, bob: b.user.id, guest: g.user.id, roomId: room.chat.room_id }));
})().catch((err) => { console.error(err); process.exit(1); });
