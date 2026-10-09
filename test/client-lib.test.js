'use strict';
// Чистые модули клиента public/lib/*.js (UMD, как e2ee.js): в браузере они
// кладут объект в window, в Node — в module.exports.
//   - invite.js: разбор поля «Ссылка или код приглашения» (формат проверяется
//     до PoW, поэтому ошибка здесь — это либо лишний аккаунт, либо отказ
//     настоящему приглашению), вид кода, проверка onion-адреса;
//   - lifetime.js: подписи и тексты о сроке хранения аккаунта.
//
// Даты в тестах — в UTC: модуль показывает время в часовом поясе устройства.
//
// Запуск: node test/client-lib.test.js

process.env.TZ = 'UTC';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const Invite = require('../public/lib/invite.js');
const Lifetime = require('../public/lib/lifetime.js');

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

// 24 буквы алфавита (без I и O) и 2 цифры — ровно 26 символов.
const CODE = 'ABCDEFGHJKLMNPQRSTUVWXYZ23';
// 22 символа base64url, с обоими «особыми» символами и разным регистром.
const SECRET = 'AbCdEfGhIjKlMnOpQr-_09';

function ok(input, secret = null) {
    assert.deepStrictEqual(Invite.parseInviteInput(input), { ok: true, code: CODE, secret }, `вход: ${JSON.stringify(input)}`);
}

function bad(input, reason = 'format') {
    assert.deepStrictEqual(Invite.parseInviteInput(input), { ok: false, reason }, `вход: ${JSON.stringify(input)}`);
}

console.log('Client lib tests\n');

// ---------- invite.js: parseInviteInput ----------

test('constants match the server alphabet and code length', () => {
    assert.strictEqual(Invite.CODE_ALPHABET, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789');
    assert.strictEqual(Invite.CODE_LENGTH, 26);
    assert.strictEqual(Invite.SECRET_LENGTH, 22);
    assert.strictEqual(CODE.length, 26);
    assert.strictEqual(SECRET.length, 22);
});

test('bare code: as is, lower case, grouped by spaces, dashes and Unicode dashes', () => {
    ok(CODE);
    ok(CODE.toLowerCase());
    ok('  ' + CODE + '  ');
    ok(Invite.formatInviteCode(CODE));
    ok('ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-3');
    ok('ABCDE\u2010FGHJK\u2011LMNPQ\u2012RSTUV\u2013WXYZ2\u20143');
    ok('ABCDE\u2015FGHJK\u00A0LMNPQ\tRSTUV\nWXYZ2 3');
});

test('full link from any origin, with path and query before the fragment', () => {
    ok('https://nyxo.example/#join=' + CODE);
    ok('http://localhost:3112/#join=' + CODE.toLowerCase());
    ok('http://' + 'a'.repeat(56) + '.onion/some/path?x=1#join=' + CODE);
    ok('nyxo.example/#join=' + Invite.formatInviteCode(CODE));
});

test('link fragment with extra parameters and percent-encoding', () => {
    ok('https://nyxo.example/#x=1&join=' + CODE + '&y=2');
    ok('https://nyxo.example/#JOIN=' + CODE);
    ok('https://nyxo.example/#join=' + encodeURIComponent(Invite.formatInviteCode(CODE)));
});

test('"join=CODE" without the rest of the link', () => {
    ok('join=' + CODE);
    ok('JOIN=' + CODE.toLowerCase());
    ok('join=' + CODE + '.' + SECRET, SECRET);
});

test('secret after the dot is kept as is (case and "-" "_" preserved)', () => {
    ok('https://nyxo.example/#join=' + CODE + '.' + SECRET, SECRET);
    ok(CODE + '.' + SECRET, SECRET);
    ok(Invite.formatInviteCode(CODE) + '.' + SECRET, SECRET);
    ok('https://nyxo.example/#join=' + CODE + '.' + SECRET.slice(0, 11) + '\n' + SECRET.slice(11), SECRET);
});

test('trailing punctuation from a copied sentence is ignored', () => {
    ok('https://nyxo.example/#join=' + CODE + '.');
    ok('https://nyxo.example/#join=' + CODE + '.' + SECRET + '.', SECRET);
    ok('«https://nyxo.example/#join=' + CODE + '»');
    ok(CODE + ',');
    ok(CODE + '!)');
});

test('empty input', () => {
    bad('', 'empty');
    bad('   \n\t', 'empty');
    bad(null, 'empty');
    bad(undefined, 'empty');
    bad(42, 'empty');
});

test('wrong length or characters outside the alphabet', () => {
    bad(CODE.slice(0, 25));
    bad(CODE + 'A');
    // В алфавите нет только похожих друг на друга O/0 и I/1; 8 и 9 — есть.
    for (const ch of ['O', '0', 'I', '1']) bad(ch + CODE.slice(1));
    assert.strictEqual(Invite.parseInviteInput('89' + CODE.slice(2)).ok, true);
    bad('\u0410' + CODE.slice(1)); // кириллическая «А» похожа, но это другой символ
    bad(CODE.slice(0, 25) + '_');
});

test('malformed secret makes the whole link invalid', () => {
    bad(CODE + '.' + SECRET.slice(0, 21));
    bad(CODE + '.' + SECRET + 'A');
    bad(CODE + '.' + SECRET.slice(0, 21) + '+');
    bad(CODE + '.' + SECRET.slice(0, 21) + '/');
    bad(CODE + '.' + SECRET + '.' + SECRET);
});

test('links without a join parameter or with a broken one', () => {
    bad('https://nyxo.example/');
    bad('https://nyxo.example/#');
    bad('https://nyxo.example/#join=');
    bad('https://nyxo.example/#other=' + CODE);
    bad('https://nyxo.example/?join=' + CODE);
    bad('https://nyxo.example/#join=%E0%A4%A');
    bad('join');
    bad('x'.repeat(5000));
});

// ---------- invite.js: formatInviteCode ----------

test('formatInviteCode groups by 5 and drops existing separators', () => {
    assert.strictEqual(Invite.formatInviteCode(CODE), 'ABCDE FGHJK LMNPQ RSTUV WXYZ2 3');
    assert.strictEqual(Invite.formatInviteCode('ABCDE-FGHJK  LMNPQ'), 'ABCDE FGHJK LMNPQ');
    assert.strictEqual(Invite.formatInviteCode('ABCDE'), 'ABCDE');
    assert.strictEqual(Invite.formatInviteCode(''), '');
    assert.strictEqual(Invite.formatInviteCode(null), '');
});

// ---------- invite.js: parseOnionUrl ----------

const ONION_HOST = 'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion';

test('parseOnionUrl accepts a v3 address and rebuilds the link from protocol and host', () => {
    assert.strictEqual(ONION_HOST.length, 56 + '.onion'.length);
    assert.strictEqual(Invite.parseOnionUrl(`http://${ONION_HOST}/`), `http://${ONION_HOST}/`);
    assert.strictEqual(Invite.parseOnionUrl(`http://${ONION_HOST}`), `http://${ONION_HOST}/`);
    assert.strictEqual(Invite.parseOnionUrl(`https://${ONION_HOST}/`), `https://${ONION_HOST}/`);
    assert.strictEqual(Invite.parseOnionUrl(`http://${ONION_HOST.toUpperCase()}/`), `http://${ONION_HOST}/`);
    assert.strictEqual(Invite.parseOnionUrl(`http://${ONION_HOST}:8080/path?q=1#f`), `http://${ONION_HOST}/`);
    assert.strictEqual(Invite.parseOnionUrl(`http://user:secret@${ONION_HOST}/`), `http://${ONION_HOST}/`);
});

test('parseOnionUrl rejects everything else', () => {
    const rejected = [
        null, undefined, '', 42, {},
        `http://${ONION_HOST.slice(1)}/`,                       // 55 символов
        `http://a${ONION_HOST}/`,                               // 57 символов
        `http://${'0'.repeat(56)}.onion/`,                      // не base32
        `http://${'8'.repeat(56)}.onion/`,
        `ftp://${ONION_HOST}/`,
        `javascript://${ONION_HOST}/%0aalert(1)`,
        `http://${ONION_HOST}.evil.example/`,
        `http://evil.example/?u=${ONION_HOST}`,
        `http://evil.example/#${ONION_HOST}`,
        `${ONION_HOST}`,
        'http://' + 'a'.repeat(400) + '.onion/',
    ];
    for (const value of rejected) {
        assert.strictEqual(Invite.parseOnionUrl(value), null, `вход: ${String(value)}`);
    }
});

// ---------- lifetime.js ----------

test('lifetime list, default and labels', () => {
    assert.deepStrictEqual(Array.from(Lifetime.LIFETIMES), ['tab', 'day', 'week']);
    assert.strictEqual(Lifetime.DEFAULT_LIFETIME, 'tab');
    assert.deepStrictEqual({ ...Lifetime.LIFETIME_LABELS }, { tab: 'Пока открыта вкладка', day: '1 день', week: '7 дней' });
    assert.ok(Lifetime.LIFETIMES.every(Lifetime.isLifetime));
    for (const value of ['', 'month', 'TAB', null, undefined, 1]) assert.strictEqual(Lifetime.isLifetime(value), false);
});

test('sidebar note is static, one per lifetime', () => {
    assert.strictEqual(Lifetime.lifetimeNote('tab'), 'Удалится через 30 минут после закрытия вкладки');
    assert.strictEqual(Lifetime.lifetimeNote('day'), 'Удалится, если не заходить 1 день');
    assert.strictEqual(Lifetime.lifetimeNote('week'), 'Удалится, если не заходить 7 дней');
    assert.strictEqual(Lifetime.lifetimeNote('month'), '');
    assert.strictEqual(Lifetime.lifetimeNote(undefined), '');
});

test('auth screen detail, leave alternative and invite advice exist for every lifetime', () => {
    for (const lifetime of Lifetime.LIFETIMES) {
        assert.ok(Lifetime.lifetimeDetail(lifetime).length > 20, lifetime);
        assert.ok(Lifetime.leaveAlternative(lifetime).length > 20, lifetime);
    }
    assert.match(Lifetime.lifetimeDetail('tab'), /30 минут/);
    assert.match(Lifetime.lifetimeDetail('day'), /суток/);
    assert.match(Lifetime.lifetimeDetail('week'), /7 дней/);
    assert.strictEqual(Lifetime.lifetimeDetail('x'), '');
    assert.strictEqual(Lifetime.leaveAlternative('x'), '');
    assert.match(Lifetime.inviteTabWarning('tab', true), /^Не закрывайте вкладку/);
    assert.match(Lifetime.inviteTabWarning('tab', false), /одобрению/);
    assert.strictEqual(Lifetime.inviteTabWarning('day', true), '');
    assert.strictEqual(Lifetime.inviteTabWarning('week', false), '');
});

test('profile status: tab, day/week with a date, without a date', () => {
    const now = new Date('2026-10-02T12:00:00.000Z');
    assert.strictEqual(Lifetime.lifetimeStatus({ anonLifetime: 'tab', anonExpiresAt: null }, now),
        'Удалится через 30 минут после закрытия последней вкладки');
    assert.strictEqual(Lifetime.lifetimeStatus({ anonLifetime: 'day', anonExpiresAt: '2026-10-03T12:05:00.000Z' }, now),
        'Удалится, если не заходить до 3 октября, 12:05');
    assert.strictEqual(Lifetime.lifetimeStatus({ anonLifetime: 'week', anonExpiresAt: '2026-10-09T07:00:00.000Z' }, now),
        'Удалится, если не заходить до 9 октября, 07:00');
    // Через Новый год — с годом.
    assert.strictEqual(Lifetime.lifetimeStatus({ anonLifetime: 'week', anonExpiresAt: '2027-01-02T00:00:00.000Z' }, new Date('2026-12-30T00:00:00.000Z')),
        'Удалится, если не заходить до 2 января 2027 г., 00:00');
    // Нет даты, дата битая или уже прошла (часы устройства спешат) — общий текст.
    for (const anonExpiresAt of [null, undefined, '', 'not a date', '2026-10-01T00:00:00.000Z']) {
        assert.strictEqual(Lifetime.lifetimeStatus({ anonLifetime: 'day', anonExpiresAt }, now), 'Удалится после суток без входа');
        assert.strictEqual(Lifetime.lifetimeStatus({ anonLifetime: 'week', anonExpiresAt }, now), 'Удалится после 7 дней без входа');
    }
    assert.strictEqual(Lifetime.lifetimeStatus({ anonLifetime: 'month' }, now), '');
    assert.strictEqual(Lifetime.lifetimeStatus(null, now), '');
});

test('profile status without "now" uses the current time', () => {
    const soon = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    assert.match(Lifetime.lifetimeStatus({ anonLifetime: 'day', anonExpiresAt: soon }), /^Удалится, если не заходить до \d{1,2} [а-я]+, \d\d:\d\d$/);
});

// ---------- UMD: ветка браузера ----------

test('in a browser both modules attach themselves to self', () => {
    for (const [file, name, fn] of [['invite.js', 'NyxoInvite', 'parseInviteInput'], ['lifetime.js', 'NyxoLifetime', 'lifetimeStatus']]) {
        const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'lib', file), 'utf8');
        const sandbox = { URL };
        sandbox.self = sandbox;
        vm.runInNewContext(source, sandbox, { filename: file });
        assert.strictEqual(typeof sandbox[name], 'object', `${file}: нет self.${name}`);
        assert.strictEqual(typeof sandbox[name][fn], 'function', `${file}: нет ${name}.${fn}`);
    }
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
