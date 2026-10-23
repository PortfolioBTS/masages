'use strict';
// Sealed sender в public/script.js (docs/security/sealed-sender.md, разделы 9.1, 9.4,
// 9.5, 9.6, 14): автор сообщения комнаты — из результата расшифровки, а не из
// ответа сервера; подсказка mine только косметика; в расшифровку она не попадает;
// подписи авторов, цитаты, признак версии proto. script.js — браузерный скрипт с DOM на
// верхнем уровне, поэтому нужные функции вырезаются по имени и исполняются в песочнице.
// Запуск: node test/sealed-sender-client.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { readClientScript } = require('./client-script-source');
const vm = require('vm');
const { PROTO_CURRENT } = require('../lib/proto');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const source = readClientScript().replace(/\r\n/g, '\n');

// Тело функции верхнего уровня: от «function name(» до парной закрывающей скобки
// (строки и комментарии пропускаются; регулярных выражений в нужных функциях нет).
function extractFunction(name) {
    const re = new RegExp(`^(async )?function ${name}\\(`, 'm');
    const match = re.exec(source);
    assert.ok(match, `в script.js нет функции ${name}`);
    let i = source.indexOf('{', match.index);
    const start = match.index;
    let depth = 0;
    for (; i < source.length; i++) {
        const c = source[i];
        if (c === '/' && source[i + 1] === '/') { i = source.indexOf('\n', i); continue; }
        if (c === '/' && source[i + 1] === '*') { i = source.indexOf('*/', i) + 1; continue; }
        if (c === '\'' || c === '"' || c === '`') {
            for (i++; source[i] !== c; i++) if (source[i] === '\\') i++;
            continue;
        }
        if (c === '{') depth++;
        if (c === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`не найден конец функции ${name}`);
}

function sandbox(functions, globals = {}) {
    const context = vm.createContext({ console, Number, Object, Array, Map, Promise, ...globals });
    vm.runInContext(functions.map(extractFunction).join('\n') + '\n', context);
    return context;
}

async function main() {
    await test('PROTO_VERSION клиента равен PROTO_CURRENT сервера (единственный источник признака версии)', () => {
        const match = /^const PROTO_VERSION = (\d+);/m.exec(source);
        assert.ok(match, 'в script.js нет константы PROTO_VERSION');
        assert.strictEqual(Number(match[1]), PROTO_CURRENT);
    });

    await test('все изменяющие запросы сообщений несут proto: отправка и правка в теле, файл - первым полем FormData до файла', () => {
        assert.match(source, /const payload = \{ chatId, text: outgoingText, encrypted, proto: PROTO_VERSION \};/);
        assert.match(source, /body: JSON\.stringify\(\{ text: outgoingText, proto: PROTO_VERSION \}\)/);
        const build = source.slice(source.indexOf("const formData = new FormData();"), source.indexOf("formData.append('file'"));
        const order = ['proto', 'chatId', 'encrypted', 'clientMessageId', 'envelope'].map(f => build.indexOf(`formData.append('${f}'`));
        assert.ok(order.every(i => i >= 0), 'все поля форм-данных на месте');
        assert.deepStrictEqual(order, order.slice().sort((a, b) => a - b), 'proto, chatId, encrypted, clientMessageId, envelope - по порядку и до файла');
    });

    await test('в комнатах production-код не передаёт подсказку об авторе: decryptEnvelope вызывается с null, user_id и sender_id сообщения не используются', () => {
        const calls = source.split('\n').filter(line => /decryptEnvelope\(/.test(line) && !/^\s*(async )?function decryptEnvelope/.test(line) && !/^\s*\/\//.test(line));
        assert.ok(calls.length >= 4, `вызовов: ${calls.length}`);
        for (const line of calls) assert.match(line, /decryptEnvelope\(\w+, null,/, line.trim());
        assert.doesNotMatch(source, /reply_to\.sender_id|reply\.sender_id/, 'цитата комнаты не несёт sender_id');
        // message.user_id остаётся только в ветке чата с ботом внутри isOwnMessage.
        const userIdUses = source.split('\n').filter(line => /message\.user_id/.test(line) && !/^\s*\/\//.test(line));
        assert.strictEqual(userIdUses.length, 1, userIdUses.join('\n'));
        assert.match(extractFunction('isOwnMessage'), /return message\.user_id === currentUser\.id && Number\(message\.sent\) !== 0;/);
    });

    await test('isOwnMessage в комнате: результат расшифровки главнее подсказки mine; без расшифровки - mine, иначе чужое', () => {
        const ctx = sandbox(['isOwnMessage'], { currentUser: { id: 7 } });
        const own = (message) => ctx.isOwnMessage(message);
        // расшифровка: автор - я, даже если сервер соврал в mine
        assert.strictEqual(own({ room_id: 5, _senderId: 7, mine: false }), true);
        // расшифровка: автор - другой, даже если сервер сказал mine: true
        assert.strictEqual(own({ room_id: 5, _senderId: 8, mine: true }), false);
        // не расшифровано: косметическая подсказка (ответ на отправку, копия на user:<id>)
        assert.strictEqual(own({ room_id: 5, mine: true }), true);
        assert.strictEqual(own({ room_id: 5 }), false, 'без mine и без расшифровки - чужое (история поля mine не несёт)');
        assert.strictEqual(own({ room_id: 5, mine: 'true' }), false, 'только булево true');
        // user_id у сообщения комнаты игнорируется
        assert.strictEqual(own({ room_id: 5, user_id: 7 }), false);
        // чат с ботом - как раньше: по user_id и sent
        assert.strictEqual(own({ room_id: null, chat_id: 3, user_id: 7, sent: 1 }), true);
        assert.strictEqual(own({ room_id: null, chat_id: 3, user_id: 7, sent: 0 }), false, 'ответ бота хранится с user_id владельца');
        assert.strictEqual(own({ room_id: null, chat_id: 3, user_id: 8, sent: 1 }), false);
        const anonymous = sandbox(['isOwnMessage'], { currentUser: null });
        assert.strictEqual(anonymous.isOwnMessage({ room_id: 5, mine: true }), false);
    });

    await test('roomAuthorLabel: текущий - имя; вышедший - имя из карты с пометкой; без имени - «Бывший участник»; не расшифровано - «Участник группы»', () => {
        const roomParticipants = new Map([[5, [{ id: 1, username: 'alice' }, { id: 2, username: '' }]]]);
        const roomMemberNames = new Map([[5, { 1: 'alice', 3: 'carol' }]]);
        const ctx = sandbox(['roomAuthorLabel'], { roomParticipants, roomMemberNames });
        assert.strictEqual(ctx.roomAuthorLabel(5, 1), 'alice');
        assert.strictEqual(ctx.roomAuthorLabel(5, 3), 'carol (вышел(ла))');
        assert.strictEqual(ctx.roomAuthorLabel(5, 4), 'Бывший участник');
        assert.strictEqual(ctx.roomAuthorLabel(5, 2), 'Бывший участник', 'участник без имени и без записи в карте');
        assert.strictEqual(ctx.roomAuthorLabel(5, undefined), 'Участник группы');
        assert.strictEqual(ctx.roomAuthorLabel(5, null), 'Участник группы');
        assert.strictEqual(ctx.roomAuthorLabel(6, 1), 'Участник группы', 'список участников комнаты ещё не загружен');
    });

    await test('formatReplyQuote: автор цитаты комнаты - из расшифровки; у чата с ботом - sender_username как раньше', () => {
        const ctx = sandbox(['formatReplyQuote']);
        assert.strictEqual(ctx.formatReplyQuote({ deleted: true }), 'Сообщение удалено');
        assert.strictEqual(ctx.formatReplyQuote({ text: 'привет', _author: 'alice' }), 'alice: привет');
        assert.strictEqual(ctx.formatReplyQuote({ text: 'нет ответа', _author: '' }), 'нет ответа', 'цитата без расшифровки - без имени');
        assert.strictEqual(ctx.formatReplyQuote({ text: 'бот', sender_username: 'Бот Помощник' }), 'Бот Помощник: бот');
        assert.strictEqual(ctx.formatReplyQuote({ text: 'x' }), 'Неизвестно: x');
    });

    await test('decryptMessageInPlace: автор запоминается из результата расшифровки, цитата получает подпись; сбой - без автора', async () => {
        const calls = [];
        const results = new Map();
        const ctx = sandbox(['decryptMessageInPlace', 'roomAuthorLabel', 'decryptedSummary'], {
            roomParticipants: new Map([[5, [{ id: 1, username: 'alice' }, { id: 2, username: 'bob' }]]]),
            roomMemberNames: new Map(),
            e2eeFailureText: (reason) => `отказ:${reason}`,
            safeDisplayName: (name) => name,
            NyxoE2eePolicy: require('../public/lib/e2ee-policy.js'),
            decryptEnvelope: async (roomId, senderId, text, id) => {
                calls.push([roomId, senderId, id]);
                return results.get(String(id));
            },
        });
        // replyTo - id ответа, подписанный отправителем внутри шифротекста: цитата сервера принимается, только если он совпал (З3).
        results.set('100', { ok: true, text: 'привет', senderId: 2, ts: 1, replyTo: '90' });
        results.set('90', { ok: true, text: 'исходное', senderId: 1, ts: 1 });
        const message = { id: '100', encrypted: true, text: 'конверт', reply_to: { id: '90', encrypted: true, text: 'конверт-цитаты' } };
        await ctx.decryptMessageInPlace(message, 5);
        assert.strictEqual(message.text, 'привет');
        assert.strictEqual(message._senderId, 2);
        assert.strictEqual(message.reply_to.text, 'исходное');
        assert.strictEqual(message.reply_to._author, 'alice');
        assert.deepStrictEqual(calls, [[5, null, '100'], [5, null, '90']], 'senderId = null в обоих вызовах');

        results.set('101', { ok: false, reason: 'no-sender-key' });
        results.set('91', { ok: false, reason: 'key-expired' });
        const failed = { id: '101', encrypted: true, text: 'конверт', reply_to: { id: '91', encrypted: true, text: 'конверт-цитаты' } };
        await ctx.decryptMessageInPlace(failed, 5);
        assert.strictEqual(failed._senderId, undefined, 'автор неизвестен');
        assert.strictEqual(failed._e2eeFailed, true);
        // Сообщение не расшифровано: подписанного id ответа нет, цитата сервера непроверяема и не показывается (З3).
        assert.strictEqual(failed.reply_to, null);

        // Расшифровано, но сервер приписал другую цитату (id не совпал с подписанным) или отправитель ни на что не отвечал.
        results.set('102', { ok: true, text: 'без ответа', senderId: 2, ts: 1, replyTo: null });
        results.set('103', { ok: true, text: 'ответ на 90', senderId: 2, ts: 1, replyTo: '90' });
        const forged = { id: '102', encrypted: true, text: 'конверт', reply_to: { id: '90', encrypted: true, text: 'конверт-цитаты' } };
        await ctx.decryptMessageInPlace(forged, 5);
        assert.strictEqual(forged.text, 'без ответа');
        assert.strictEqual(forged.reply_to, null, 'цитата, которой отправитель не подписывал, убрана');
        const swapped = { id: '103', encrypted: true, text: 'конверт', reply_to: { id: '91', encrypted: true, text: 'конверт-цитаты' } };
        await ctx.decryptMessageInPlace(swapped, 5);
        assert.strictEqual(swapped.reply_to, null, 'другая цитата убрана');
    });

    console.log(`\n${passed} passed, ${failed} failed`);
    if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
