'use strict';
// Ответ на сообщение привязан к содержимому (ревью R4 W7, З3; message-ordering.md 3 и 9.1): id цитируемого сообщения
// лежит внутри шифротекста (поле re), и клиент показывает цитату от сервера, только если id совпал с подписанным
// отправителем. Раньше reply_to_id хранился открыто, и сервер мог приписать сообщению участника любую цитату.
// Запуск: node test/reply-binding.test.js

const { assert, E2EE, makeWorld, test, finish } = require('./membership-world');
const Policy = require('../public/lib/e2ee-policy.js');
const Formats = require('../public/lib/e2ee-formats.js');
const fs = require('fs');
const path = require('path');
const { readClientScript } = require('./client-script-source');

const QUOTED = '1234567';   // id цитируемого сообщения (строка по формату 6.1)

async function pair() {
    const w = makeWorld();
    const alice = await w.addUser(1);
    const bob = await w.addUser(2);
    await w.createRoom(alice);
    await w.approve(alice, bob);
    await w.ensure(alice); await w.sync(bob); await w.ensure(bob); await w.sync(alice);
    return { w, alice, bob };
}

async function send(w, from, text, options = {}) {
    const id = options.messageId || String(w.server.newMessageId());
    const env = await from.client.encryptOutgoing(100, text, { messageId: id, ...options });
    if (!options.edit) w.server.postMessage(100, from.id, env, id);
    return { id, env };
}

(async () => {
    console.log('Привязка ответа к содержимому (З3)\n');

    await test('формат: re лежит в содержимом текста, строго по формату id; у файла и в испорченном виде - отказ', () => {
        const withRe = Formats.encodeContent('привет', { mid: '7654321', ts: 5, replyTo: QUOTED });
        assert.deepStrictEqual(withRe, { t: 'text', b: 'привет', mid: '7654321', ts: 5, re: QUOTED });
        assert.strictEqual('re' in Formats.encodeContent('привет', { mid: '7654321', ts: 5 }), false, 'без ответа поля нет');
        assert.throws(() => Formats.encodeContent('привет', { mid: '7654321', ts: 5, replyTo: 'abc' }));
        assert.throws(() => Formats.encodeContent('x', { mid: '7654321', ts: 5, replyTo: '12' }));
        const file = { type: 'file', mime: 'a/b', name: 'n', size: 1, key: Buffer.alloc(32).toString('base64'), iv: Buffer.alloc(12).toString('base64') };
        assert.throws(() => Formats.encodeContent(file, { mid: '7654321', ts: 5, replyTo: QUOTED }), /ответ/);
        assert.strictEqual(Formats.decodeContent(withRe).replyTo, QUOTED);
        assert.strictEqual(Formats.decodeContent({ t: 'text', b: 'x', mid: '1', ts: 1 }).replyTo, null);
        for (const bad of ['abc', 12345678, '', '0123456', '99999999999', null]) {
            assert.strictEqual(Formats.decodeContent({ t: 'text', b: 'x', mid: '1', ts: 1, re: bad }), null, JSON.stringify(bad));
        }
        assert.strictEqual(Formats.decodeContent({ t: 'file', mime: 'a/b', name: 'n', size: 1, key: file.key, iv: file.iv, caption: '', mid: '1', ts: 1, re: QUOTED }), null);
    });

    await test('получатель видит replyTo из расшифровки; без ответа - null; в правке ответ сохраняется', async () => {
        const { w, alice, bob } = await pair();
        const reply = await send(w, alice, 'ответ', { replyTo: QUOTED });
        const got = await bob.client.decryptIncoming(100, null, reply.env, reply.id);
        assert.strictEqual(got.ok, true);
        assert.strictEqual(got.replyTo, QUOTED);
        const plain = await send(w, alice, 'без ответа');
        assert.strictEqual((await bob.client.decryptIncoming(100, null, plain.env, plain.id)).replyTo, null);
        w.clock.advance(1000);
        const edit = await send(w, alice, 'ответ (правка)', { messageId: reply.id, edit: true, replyTo: QUOTED });
        const edited = await bob.client.decryptIncoming(100, null, edit.env, reply.id);
        assert.strictEqual(edited.ok, true);
        assert.strictEqual(edited.edit, true);
        assert.strictEqual(edited.replyTo, QUOTED);
        await assert.rejects(() => alice.client.encryptOutgoing(100, 'x', { messageId: '7654321', replyTo: 'мусор' }), /protocol|ответ|идентификатор/i);
        w.noViolations();
    });

    await test('цитата сервера принимается, только если её id совпал с подписанным отправителем (replyQuoteTrusted)', () => {
        const ok = (replyTo) => ({ ok: true, replyTo });
        assert.strictEqual(Policy.replyQuoteTrusted({ id: 1234567 }, ok(QUOTED)), true, 'id совпал (число в ответе сервера)');
        assert.strictEqual(Policy.replyQuoteTrusted({ id: QUOTED, deleted: true }, ok(QUOTED)), true, 'удалённая цитата тоже сверяется по id');
        assert.strictEqual(Policy.replyQuoteTrusted({ id: 7654321 }, ok(QUOTED)), false, 'сервер приписал другое сообщение');
        assert.strictEqual(Policy.replyQuoteTrusted({ id: 1234567 }, ok(null)), false, 'отправитель не отвечал ни на что');
        assert.strictEqual(Policy.replyQuoteTrusted({ id: 1234567 }, { ok: false, reason: 'no-sender-key' }), false, 'не расшифровано - не проверить');
        assert.strictEqual(Policy.replyQuoteTrusted({ id: 1234567 }, null), false);
        assert.strictEqual(Policy.replyQuoteTrusted(null, ok(null)), true, 'цитаты нет - нечего проверять');
    });

    await test('клиент применяет проверку: отправка передаёт replyTo, расшифровка сообщения комнаты отбрасывает неподтверждённую цитату', () => {
        const script = readClientScript();
        const read = (name) => fs.readFileSync(path.join(__dirname, '..', 'public', 'js', name), 'utf8');
        const rooms = read('04-e2ee-rooms.js');
        const body = rooms.slice(rooms.indexOf('async function decryptMessageInPlace('), rooms.indexOf('async function decryptMessagesInPlace('));
        assert.match(body, /NyxoE2eePolicy\.replyQuoteTrusted\(/);
        assert.match(body, /message\.reply_to = null/, 'неподтверждённая цитата убирается');
        const send = read('14-send.js');
        assert.match(send, /replyTo: replyToId/, 'новое сообщение несёт id цитаты внутри шифротекста');
        assert.match(send, /replyTo: /, 'правка сохраняет ответ');
        assert.match(script, /replyQuoteTrusted/);
    });

    finish();
})().catch((err) => { console.error(err); process.exitCode = 1; });
void E2EE;
