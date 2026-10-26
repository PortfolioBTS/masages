'use strict';
// Порядок и идентификаторы сообщений (docs/security/message-ordering.md,
// раздел 15), без БД и браузера:
//   - public/lib/message-order.js: insertionIndex, mergeBySeq, dedupById,
//     newClientMessageId, displayTimeMs (раздел 9.5);
//   - lib/message-ids.js: parseClientMessageId, parseSeq, isMessageIdConflict;
//   - lib/coarse-time.js: огрубление времени и порог уборки файлов-сирот.
//
// Запуск: node test/message-order.test.js

const assert = require('assert');
const Order = require('../public/lib/message-order.js');
const Ids = require('../lib/message-ids.js');
const Coarse = require('../lib/coarse-time.js');

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

// ---------- insertionIndex ----------

test('insertionIndex: пустой список, начало, середина, конец', () => {
    assert.strictEqual(Order.insertionIndex([], 5), 0);
    assert.strictEqual(Order.insertionIndex([10, 20, 30], 5), 0);
    assert.strictEqual(Order.insertionIndex([10, 20, 30], 25), 2);
    assert.strictEqual(Order.insertionIndex([10, 20, 30], 99), 3);
});

test('insertionIndex: при равном seq вставка после уже показанного', () => {
    assert.strictEqual(Order.insertionIndex([10, 20, 20, 30], 20), 3);
    assert.strictEqual(Order.insertionIndex([20], 20), 1);
});

test('insertionIndex: сообщения, пришедшие переставленными, встают по seq', () => {
    const seqs = [];
    for (const seq of [7, 3, 9, 1, 5, 8, 2]) seqs.splice(Order.insertionIndex(seqs, seq), 0, seq);
    assert.deepStrictEqual(seqs, [1, 2, 3, 5, 7, 8, 9]);
});

test('insertionIndex: большие seq (около 2^31) не ломают сравнение', () => {
    const seqs = [2147483000, 2147483100, 2147483646];
    assert.strictEqual(Order.insertionIndex(seqs, 2147483647), 3);
    assert.strictEqual(Order.insertionIndex(seqs, 2147483050), 1);
});

// ---------- dedupById / mergeBySeq ----------

test('dedupById: id сравниваются как строки, первый экземпляр остаётся', () => {
    const list = [{ id: '5', seq: 1 }, { id: 5, seq: 1 }, { id: '6', seq: 2 }, { id: '7', seq: 3 }];
    assert.deepStrictEqual(Order.dedupById(list).map(m => m.id), ['5', '6', '7']);
    assert.deepStrictEqual(Order.dedupById(list, new Set(['6'])).map(m => m.id), ['5', '7']);
});

test('dedupById: известные id не изменяются и пустой список — пустой результат', () => {
    const known = new Set(['1']);
    Order.dedupById([{ id: '2' }], known);
    assert.deepStrictEqual([...known], ['1']);
    assert.deepStrictEqual(Order.dedupById([]), []);
});

test('mergeBySeq: порядок по seq, повторы id убраны, побеждает первый список', () => {
    const a = [{ id: '1', seq: 10, text: 'a' }, { id: '2', seq: 30, text: 'a' }];
    const b = [{ id: '3', seq: 20, text: 'b' }, { id: '2', seq: 30, text: 'b' }, { id: '4', seq: 40, text: 'b' }];
    const merged = Order.mergeBySeq(a, b);
    assert.deepStrictEqual(merged.map(m => m.id), ['1', '3', '2', '4']);
    assert.strictEqual(merged.find(m => m.id === '2').text, 'a');
});

test('mergeBySeq: равные seq у разных id сохраняют порядок «сначала a, потом b»', () => {
    const merged = Order.mergeBySeq([{ id: '1', seq: 5 }], [{ id: '2', seq: 5 }]);
    assert.deepStrictEqual(merged.map(m => m.id), ['1', '2']);
});

test('mergeBySeq: исходные массивы не меняются', () => {
    const a = [{ id: '2', seq: 2 }];
    const b = [{ id: '1', seq: 1 }];
    Order.mergeBySeq(a, b);
    assert.deepStrictEqual(a.map(m => m.id), ['2']);
    assert.deepStrictEqual(b.map(m => m.id), ['1']);
});

// ---------- newClientMessageId ----------

test('newClientMessageId: формат ^[1-9]\\d{6,9}$ и не больше 2^31-1', () => {
    for (let i = 0; i < 2000; i++) {
        const id = Order.newClientMessageId();
        assert.match(id, /^[1-9]\d{6,9}$/);
        assert.ok(Number(id) >= 1000000 && Number(id) <= 2147483647, id);
        assert.notStrictEqual(Ids.parseClientMessageId(id), null, id);
    }
});

test('newClientMessageId: значения меньше 1 000 000 отбрасываются, старший бит маскируется', () => {
    const source = [5, 999999, 0, 0x80000000, 0x80000000 + 1000000, 1234567];
    let i = 0;
    const id = Order.newClientMessageId(() => source[i++]);
    // 0x80000000 -> 0 после маски (отброшено), 0x80000000+1000000 -> 1000000 (принято).
    assert.strictEqual(id, '1000000');
    assert.strictEqual(i, 5, 'первые четыре значения отброшены');
});

test('newClientMessageId: границы диапазона принимаются', () => {
    assert.strictEqual(Order.newClientMessageId(() => 1000000), '1000000');
    assert.strictEqual(Order.newClientMessageId(() => 0x7fffffff), '2147483647');
    assert.strictEqual(Order.newClientMessageId(() => 0xffffffff), '2147483647', 'старший бит игнорируется');
});

test('newClientMessageId: равномерность по выборке и отсутствие повторов подряд', () => {
    const buckets = new Array(8).fill(0);
    const seen = new Set();
    const total = 8000;
    for (let i = 0; i < total; i++) {
        const id = Number(Order.newClientMessageId());
        buckets[Math.min(7, Math.floor((id / 2147483648) * 8))]++;
        seen.add(id);
    }
    // Каждая из 8 корзин ждёт ~1000; допустимый разброс очень широкий (±25 %),
    // тест ловит перекос (например, маску вместо отбраковки), а не шум выборки.
    for (const count of buckets) assert.ok(count > 750 && count < 1250, `корзины: ${buckets.join(',')}`);
    assert.ok(seen.size > total - 5, 'повторов почти нет');
});

test('newClientMessageId: без crypto.getRandomValues — понятная ошибка', () => {
    const original = globalThis.crypto;
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
    try {
        assert.throws(() => Order.newClientMessageId(), /getRandomValues/);
    } finally {
        Object.defineProperty(globalThis, 'crypto', { value: original, configurable: true });
    }
});

// ---------- parseClientMessageId / parseSeq ----------

test('parseClientMessageId: верные строки', () => {
    assert.strictEqual(Ids.parseClientMessageId('1000000'), 1000000);
    assert.strictEqual(Ids.parseClientMessageId('1234567'), 1234567);
    assert.strictEqual(Ids.parseClientMessageId('2147483647'), 2147483647);
    assert.strictEqual(Ids.parseClientMessageId('1000000000'), 1000000000);
});

test('parseClientMessageId: неверные значения — null', () => {
    const bad = [
        '999999', '123456', '0', '', ' 1234567', '1234567 ', '01234567', '+1234567', '-1234567', '12.34567',
        '1e7', '0x10', '1234567a', '2147483648', '9999999999', '10000000000', '12345678901',
        1234567, 2147483647, null, undefined, true, {}, [], ['1234567'], '١٢٣٤٥٦٧',
    ];
    for (const value of bad) assert.strictEqual(Ids.parseClientMessageId(value), null, JSON.stringify(value));
});

test('parseSeq: положительные целые строкой или числом, иначе null', () => {
    assert.strictEqual(Ids.parseSeq('1'), 1);
    assert.strictEqual(Ids.parseSeq(42), 42);
    assert.strictEqual(Ids.parseSeq('2147483647'), 2147483647);
    for (const value of ['0', 0, -1, '-1', '1.5', 1.5, '', 'abc', '2147483648', 2147483648, null, undefined, NaN, '01', [], {}, '1e3']) {
        assert.strictEqual(Ids.parseSeq(value), null, JSON.stringify(value));
    }
});

test('isMessageIdConflict: только первичный ключ сообщений и надгробие', () => {
    assert.ok(Ids.isMessageIdConflict({ code: '23505', constraint: 'messages_pkey' }));
    assert.ok(Ids.isMessageIdConflict({ code: '23505', constraint: 'message_tombstones_pkey' }));
    assert.ok(!Ids.isMessageIdConflict({ code: '23505', constraint: 'idx_messages_room_seq' }), 'сбой выдачи seq — не конфликт id');
    assert.ok(!Ids.isMessageIdConflict({ code: '23505', constraint: 'idx_messages_chat_seq' }));
    assert.ok(!Ids.isMessageIdConflict({ code: '23503', constraint: 'messages_pkey' }));
    assert.ok(!Ids.isMessageIdConflict({ code: '23505' }));
    assert.ok(!Ids.isMessageIdConflict(null));
    assert.ok(Ids.isDeadlock({ code: '40P01' }) && !Ids.isDeadlock({ code: '40001' }) && !Ids.isDeadlock(undefined));
});

test('тела ошибок контракта: success:false, code, message', () => {
    for (const [body, code] of [[Ids.CLIENT_OUTDATED, 'client-outdated'], [Ids.BAD_MESSAGE_ID, 'bad-message-id'], [Ids.ID_CONFLICT, 'id-conflict'], [Ids.BAD_SEQ, 'bad-seq']]) {
        assert.strictEqual(body.success, false);
        assert.strictEqual(body.code, code);
        assert.ok(typeof body.message === 'string' && body.message.length > 5, code);
        assert.ok(Object.isFrozen(body), `${code}: общий объект не должен меняться`);
    }
    assert.match(Ids.CLIENT_OUTDATED.message, /^Обновите страницу/);
    assert.strictEqual(Ids.ID_CONFLICT.message, 'Идентификатор сообщения занят, повторите отправку');
});

// ---------- displayTimeMs (раздел 9.5) ----------

test('displayTimeMs: ts в пределах 10 минут от created_at показывается, иначе created_at', () => {
    const created = Date.parse('2026-10-09T12:34:00.000Z');
    const message = { created_at: '2026-10-09T12:34:00.000Z', edited_at: null };
    assert.strictEqual(Order.displayTimeMs(message, created + 37000), created + 37000);
    assert.strictEqual(Order.displayTimeMs(message, created + 10 * 60 * 1000), created + 10 * 60 * 1000, 'ровно 10 минут — ещё можно');
    assert.strictEqual(Order.displayTimeMs(message, created + 10 * 60 * 1000 + 1), created, 'на миллисекунду дальше — created_at');
    assert.strictEqual(Order.displayTimeMs(message, created - 11 * 60 * 1000), created, 'часы отстают');
    assert.strictEqual(Order.displayTimeMs(message, created + 3 * 3600 * 1000), created, 'часы убежали');
});

test('displayTimeMs: у правленого сообщения всегда created_at', () => {
    const created = Date.parse('2026-10-09T12:34:00.000Z');
    const message = { created_at: '2026-10-09T12:34:00.000Z', edited_at: '2026-10-09T12:40:00.000Z' };
    assert.strictEqual(Order.displayTimeMs(message, created + 5 * 60 * 1000), created);
});

test('displayTimeMs: нет пригодного ts — created_at; нет ничего — null', () => {
    const created = Date.parse('2026-10-09T12:34:00.000Z');
    const message = { created_at: '2026-10-09T12:34:00.000Z' };
    for (const ts of [undefined, null, -1, 1.5, NaN, '1', Number.MAX_SAFE_INTEGER + 2]) {
        assert.strictEqual(Order.displayTimeMs(message, ts), created, String(ts));
    }
    assert.strictEqual(Order.displayTimeMs({}, 1), null);
    assert.strictEqual(Order.displayTimeMs({ created_at: 'не дата' }, 5), null);
    assert.strictEqual(Order.displayTimeMs(null, 5), null);
});

// ---------- coarse-time ----------

test('floorToMinute / floorToHour: округление вниз, Date и миллисекунды', () => {
    const t = Date.parse('2026-10-09T12:34:56.789Z');
    assert.strictEqual(Coarse.floorToMinute(t).toISOString(), '2026-10-09T12:34:00.000Z');
    assert.strictEqual(Coarse.floorToMinute(new Date(t)).toISOString(), '2026-10-09T12:34:00.000Z');
    assert.strictEqual(Coarse.floorToHour(t).toISOString(), '2026-10-09T12:00:00.000Z');
    assert.strictEqual(Coarse.floorToMinute(Date.parse('2026-10-09T12:34:00.000Z')).toISOString(), '2026-10-09T12:34:00.000Z', 'уже круглое значение не меняется');
});

test('orphanAgeThresholdMs: не меньше двух часов', () => {
    assert.strictEqual(Coarse.ORPHAN_MIN_AGE_MS, 2 * 3600 * 1000);
    assert.strictEqual(Coarse.orphanAgeThresholdMs(60 * 60 * 1000), 2 * 3600 * 1000);
    assert.strictEqual(Coarse.orphanAgeThresholdMs(0), 2 * 3600 * 1000);
    assert.strictEqual(Coarse.orphanAgeThresholdMs(undefined), 2 * 3600 * 1000);
    assert.strictEqual(Coarse.orphanAgeThresholdMs(5 * 3600 * 1000), 5 * 3600 * 1000);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
