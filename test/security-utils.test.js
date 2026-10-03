'use strict';
// Тесты чистых функций lib/security-utils.js (без БД и сети).
// Запуск: node test/security-utils.test.js

const assert = require('assert');
const utils = require('../lib/security-utils');

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

// Детерминированный "генератор случайных байт" для проверки выборки.
function fixedBytes(values) {
    let i = 0;
    return (n) => {
        const out = Buffer.alloc(n);
        for (let k = 0; k < n; k++) out[k] = values[i++ % values.length];
        return out;
    };
}

const onion = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz234567.onion';
const isOnionHost = (host) => String(host || '').toLowerCase().split(':')[0] === onion;

async function main() {
    console.log('Security utils tests\n');

    // ---- случайные строки ----

    await test('randomString: bytes in the biased tail are rejected (62-char alphabet)', () => {
        // 248..255 — "хвост" для n=62 (256 - 256 % 62 = 248): такие байты пропускаются
        const s = utils.randomString(utils.UNIQUE_CODE_ALPHABET, 4, fixedBytes([248, 255, 0, 61, 62, 247]));
        assert.strictEqual(s, 'A9A' + utils.UNIQUE_CODE_ALPHABET[247 % 62]);
    });

    await test('randomString: 32-char alphabet uses every byte (no rejection)', () => {
        const s = utils.randomString(utils.INVITE_CODE_ALPHABET, 3, fixedBytes([255, 0, 32]));
        assert.strictEqual(s, utils.INVITE_CODE_ALPHABET[31] + utils.INVITE_CODE_ALPHABET[0] + utils.INVITE_CODE_ALPHABET[0]);
    });

    await test('randomString: distribution over 62 chars is roughly uniform', () => {
        const counts = new Map();
        const s = utils.randomString(utils.UNIQUE_CODE_ALPHABET, 62 * 2000);
        for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
        assert.strictEqual(counts.size, 62);
        for (const c of counts.values()) assert.ok(c > 1500 && c < 2500, `count ${c} is out of range`);
    });

    await test('generateUniqueCode: 8 chars of the 62-char alphabet', () => {
        const code = utils.generateUniqueCode();
        assert.match(code, /^[A-Za-z0-9]{8}$/);
    });

    // ---- инвайт-коды ----

    await test('generateInviteCode: 26 chars of the K6 alphabet, valid, unique', () => {
        const seen = new Set();
        for (let i = 0; i < 200; i++) {
            const code = utils.generateInviteCode();
            assert.strictEqual(code.length, 26);
            assert.match(code, /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]+$/);
            assert.ok(utils.isValidInviteCode(code));
            seen.add(code);
        }
        assert.strictEqual(seen.size, 200);
    });

    await test('normalizeInviteCode: case, spaces and dashes are ignored', () => {
        const code = utils.generateInviteCode();
        const typed = ` ${code.slice(0, 5).toLowerCase()}-${code.slice(5, 10)} ${code.slice(10, 20)}–${code.slice(20)}\n`;
        assert.strictEqual(utils.normalizeInviteCode(typed), code);
        assert.strictEqual(utils.normalizeInviteCode(123), '');
        assert.strictEqual(utils.normalizeInviteCode(null), '');
    });

    await test('isValidInviteCode: legacy and malformed codes are rejected', () => {
        assert.strictEqual(utils.isValidInviteCode('ABCDEF'), false, 'legacy 6-char code');
        assert.strictEqual(utils.isValidInviteCode('O'.repeat(26)), false, 'O is not in the alphabet');
        assert.strictEqual(utils.isValidInviteCode('A'.repeat(27)), false);
        assert.strictEqual(utils.isValidInviteCode('a'.repeat(26)), false, 'must be normalized first');
        assert.strictEqual(utils.isValidInviteCode(undefined), false);
    });

    await test('isInviteExpired: past, future, NULL and garbage', () => {
        const now = Date.parse('2026-09-27T12:00:00Z');
        assert.strictEqual(utils.isInviteExpired('2026-09-27T11:59:59Z', now), true);
        assert.strictEqual(utils.isInviteExpired(new Date('2026-09-28T00:00:00Z'), now), false);
        assert.strictEqual(utils.isInviteExpired(null, now), true, 'NULL expiry is fail-closed');
        assert.strictEqual(utils.isInviteExpired('not a date', now), true);
    });

    // ---- вложения ----

    await test('every allowed MIME type has a disk extension and an anonymized name', () => {
        for (const mime of utils.ALLOWED_MIME_TYPES) {
            assert.match(utils.MIME_EXTENSIONS[mime], /^\.[a-z0-9]+$/, mime);
            const name = utils.anonymizedFileName(mime);
            assert.match(name, /^(photo|video|document|text)\.[a-z0-9]+$/, mime);
            assert.ok(utils.ALL_ANONYMIZED_FILE_NAMES.includes(name));
        }
        assert.ok(!utils.ALLOWED_MIME_TYPES.includes(utils.ENCRYPTED_FILE_MIME), 'ciphertext is not a regular upload type');
    });

    await test('the upload white list is exactly photos, video, PDF and TXT (no audio types)', () => {
        // Точный состав — защита от случайного расширения списка: добавить
        // тип можно только осознанно, поправив и этот тест.
        const photoVideoDocs = [
            'application/pdf', 'image/gif', 'image/jpeg', 'image/png', 'image/webp',
            'text/plain', 'video/mp4', 'video/quicktime', 'video/webm',
        ];
        assert.deepStrictEqual([...utils.ALLOWED_MIME_TYPES].sort(), photoVideoDocs);
        assert.deepStrictEqual(Object.keys(utils.MIME_EXTENSIONS).sort(), photoVideoDocs);
        assert.deepStrictEqual(Object.keys(utils.ANONYMIZED_FILE_NAMES).sort(), photoVideoDocs);
        const everything = JSON.stringify([
            utils.ALLOWED_MIME_TYPES, utils.MIME_EXTENSIONS, utils.ANONYMIZED_FILE_NAMES, utils.ALL_ANONYMIZED_FILE_NAMES,
        ]);
        assert.ok(!/audio/i.test(everything), 'no audio type, extension or name anywhere');
    });

    await test('anonymizedFileName: fixed names, never derived from the original name', () => {
        assert.strictEqual(utils.anonymizedFileName('image/jpeg'), 'photo.jpg');
        assert.strictEqual(utils.anonymizedFileName('video/mp4'), 'video.mp4');
        assert.strictEqual(utils.anonymizedFileName('application/pdf'), 'document.pdf');
        assert.strictEqual(utils.anonymizedFileName('text/plain'), 'text.txt');
        assert.strictEqual(utils.anonymizedFileName('application/x-evil'), 'file');
        assert.strictEqual(utils.anonymizedFileName('__proto__'), 'file');
        assert.strictEqual(utils.anonymizedFileName(undefined), 'file');
        assert.ok(utils.ALL_ANONYMIZED_FILE_NAMES.includes('file'));
    });

    await test('anonymizedFileName: an audio type gets the neutral name, not a type-specific one', () => {
        for (const mime of ['audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm']) {
            assert.strictEqual(utils.anonymizedFileName(mime), 'file', mime);
        }
    });

    // Начало файла: сигнатуры форматов (первые 12 байт, как читает сервер).
    const head = (...bytes) => Buffer.concat([Buffer.from(bytes), Buffer.alloc(12)]).subarray(0, 12);
    const ascii = (offset, text) => {
        const buf = Buffer.alloc(12);
        buf.write(text, offset, 'latin1');
        return buf;
    };
    const EBML = head(0x1A, 0x45, 0xDF, 0xA3);
    const OGG = ascii(0, 'OggS');
    const RIFF_WAVE = Buffer.concat([ascii(0, 'RIFF').subarray(0, 8), Buffer.from('WAVE', 'latin1')]);
    const ID3 = ascii(0, 'ID3\x03');
    const MPEG_FRAME = head(0xFF, 0xFB, 0x90, 0x00);
    const FTYP = ascii(4, 'ftyp');

    await test('checkMagicBytes: each allowed type accepts its own signature', () => {
        assert.strictEqual(utils.checkMagicBytes(head(0xFF, 0xD8, 0xFF, 0xE0), 'image/jpeg'), true);
        assert.strictEqual(utils.checkMagicBytes(head(0x89, 0x50, 0x4E, 0x47), 'image/png'), true);
        assert.strictEqual(utils.checkMagicBytes(ascii(0, 'GIF89a'), 'image/gif'), true);
        assert.strictEqual(utils.checkMagicBytes(ascii(0, 'RIFF'), 'image/webp'), true);
        assert.strictEqual(utils.checkMagicBytes(ascii(0, '%PDF-1.7'), 'application/pdf'), true);
        assert.strictEqual(utils.checkMagicBytes(FTYP, 'video/mp4'), true);
        assert.strictEqual(utils.checkMagicBytes(FTYP, 'video/quicktime'), true);
        assert.strictEqual(utils.checkMagicBytes(EBML, 'video/webm'), true);
        assert.strictEqual(utils.checkMagicBytes(Buffer.from('plain text'), 'text/plain'), true);
    });

    await test('checkMagicBytes: video/webm is accepted only by the EBML signature (not OggS)', () => {
        assert.strictEqual(utils.checkMagicBytes(OGG, 'video/webm'), false, 'an Ogg container posing as WebM');
        assert.strictEqual(utils.checkMagicBytes(RIFF_WAVE, 'video/webm'), false);
        assert.strictEqual(utils.checkMagicBytes(ID3, 'video/webm'), false);
        assert.strictEqual(utils.checkMagicBytes(FTYP, 'video/webm'), false);
        assert.strictEqual(utils.checkMagicBytes(head(0x1A, 0x45, 0xDF, 0xA2), 'video/webm'), false, 'one byte off');
        // И наоборот: EBML не выдаётся ни за что другое.
        for (const mime of ['image/png', 'image/jpeg', 'video/mp4', 'application/pdf']) {
            assert.strictEqual(utils.checkMagicBytes(EBML, mime), false, mime);
        }
    });

    await test('checkMagicBytes: audio types are never accepted, even with a matching signature (fail closed)', () => {
        const withSignature = {
            'audio/mpeg': [ID3, MPEG_FRAME],
            'audio/ogg': [OGG],
            'audio/wav': [RIFF_WAVE],
            'audio/webm': [EBML, OGG],
            'audio/x-wav': [RIFF_WAVE],
            'audio/webm;codecs=opus': [EBML],
        };
        for (const [mime, samples] of Object.entries(withSignature)) {
            for (const sample of samples) assert.strictEqual(utils.checkMagicBytes(sample, mime), false, mime);
        }
    });

    await test('checkMagicBytes: signature of another type, unknown type and short input are rejected', () => {
        assert.strictEqual(utils.checkMagicBytes(head(0x89, 0x50, 0x4E, 0x47), 'image/jpeg'), false);
        assert.strictEqual(utils.checkMagicBytes(ascii(0, '%PDF-1.7'), 'image/png'), false);
        assert.strictEqual(utils.checkMagicBytes(ascii(0, 'RIFF'), 'application/x-evil'), false);
        assert.strictEqual(utils.checkMagicBytes(ascii(0, 'RIFF'), utils.ENCRYPTED_FILE_MIME), false);
        assert.strictEqual(utils.checkMagicBytes(ascii(0, 'RIFF'), undefined), false);
        assert.strictEqual(utils.checkMagicBytes(Buffer.from([0x1A, 0x45, 0xDF]), 'video/webm'), false, 'shorter than 4 bytes');
        assert.strictEqual(utils.checkMagicBytes(Buffer.alloc(0), 'text/plain'), false);
        assert.strictEqual(utils.checkMagicBytes(null, 'image/png'), false);
    });

    await test('isInlineUpload: only photos and video are shown inline, everything else downloads', () => {
        const stored = (ext) => `1759000000000-0123456789abcdef01234567${ext}`;
        // Расширения всех разрешённых типов: inline — только image/* и video/*.
        for (const mime of utils.ALLOWED_MIME_TYPES) {
            const inline = /^(image|video)\//.test(mime);
            assert.strictEqual(utils.isInlineUpload(stored(utils.MIME_EXTENSIONS[mime])), inline, mime);
        }
        assert.strictEqual(utils.isInlineUpload(stored('.png')), true);
        assert.strictEqual(utils.isInlineUpload(stored('.mp4')), true);
        assert.strictEqual(utils.isInlineUpload(stored('.pdf')), false);
        assert.strictEqual(utils.isInlineUpload(stored('.txt')), false);
        // Шифротекст E2EE-вложения: тип известен только клиенту.
        assert.strictEqual(utils.isInlineUpload(stored(utils.ENCRYPTED_FILE_EXTENSION)), false);
    });

    await test('isInlineUpload: unknown, missing and tricky extensions fall back to download', () => {
        const stored = (ext) => `1759000000000-0123456789abcdef01234567${ext}`;
        for (const ext of ['', '.', '.html', '.htm', '.svg', '.js', '.mp3', '.ogg', '.wav', '.weba', '.png.html', '.PDF']) {
            assert.strictEqual(utils.isInlineUpload(stored(ext)), false, JSON.stringify(ext));
        }
        // Регистр расширения не влияет на решение для известных типов.
        assert.strictEqual(utils.isInlineUpload(stored('.PNG')), true);
        for (const bad of [undefined, null, 42, {}, ['a.png']]) {
            assert.strictEqual(utils.isInlineUpload(bad), false, String(bad));
        }
    });

    // ---- проверка источника ----

    const allowed = utils.parseAllowedOrigins(' https://app.example.com , admin.example.com:8443,, ftp://x, bad host ');

    await test('parseAllowedOrigins: origins with scheme, bare hosts, invalid entries', () => {
        assert.deepStrictEqual([...allowed.origins], ['https://app.example.com']);
        assert.deepStrictEqual([...allowed.hosts], ['admin.example.com:8443']);
        assert.deepStrictEqual(allowed.invalid, ['ftp://x', 'bad host']);
        const empty = utils.parseAllowedOrigins(undefined);
        assert.strictEqual(empty.origins.size + empty.hosts.size + empty.invalid.length, 0);
    });

    await test('parseOrigin: only bare scheme://host[:port]', () => {
        assert.deepStrictEqual(utils.parseOrigin('https://Chat.Example.com'), { origin: 'https://chat.example.com', host: 'chat.example.com' });
        assert.strictEqual(utils.parseOrigin('http://localhost:3000').host, 'localhost:3000');
        assert.strictEqual(utils.parseOrigin('https://a.com:443').host, 'a.com');
        for (const bad of ['null', '', 'file:///etc', 'https://a.com/path', 'https://u:p@a.com', 'https://a.com, https://b.com', 'javascript:alert(1)', 42]) {
            assert.strictEqual(utils.parseOrigin(bad), null, String(bad));
        }
    });

    const check = (overrides) => utils.isRequestOriginAllowed({
        host: 'chat.example.com', allowed, isOnionHost, ...overrides,
    });

    await test('origin check: same host is allowed (default ports and case ignored)', () => {
        assert.strictEqual(check({ origin: 'https://chat.example.com' }), true);
        assert.strictEqual(check({ origin: 'https://CHAT.example.com', host: 'chat.example.com:443' }), true);
        assert.strictEqual(check({ origin: 'http://localhost:3000', host: 'localhost:3000' }), true);
    });

    await test('origin check: cross-site origins are rejected (CSWSH)', () => {
        assert.strictEqual(check({ origin: 'https://evil.example.net' }), false);
        assert.strictEqual(check({ origin: 'https://chat.example.com.evil.net' }), false);
        assert.strictEqual(check({ origin: 'http://localhost:8080', host: 'localhost:3000' }), false, 'other port = other origin');
        assert.strictEqual(check({ origin: 'null' }), false);
        assert.strictEqual(check({ origin: 'https://evil.net', host: undefined }), false);
    });

    await test('origin check: X-Forwarded-Host counts as the request host', () => {
        assert.strictEqual(check({ origin: 'https://chat.example.com', host: 'internal:8080', forwardedHost: 'chat.example.com, proxy' }), true);
        assert.strictEqual(check({ origin: 'https://evil.net', host: 'internal:8080', forwardedHost: 'chat.example.com' }), false);
    });

    await test('origin check: ALLOWED_ORIGINS and onion host', () => {
        assert.strictEqual(check({ origin: 'https://app.example.com' }), true);
        assert.strictEqual(check({ origin: 'http://app.example.com' }), false, 'scheme is part of an origin entry');
        assert.strictEqual(check({ origin: 'https://admin.example.com:8443' }), true);
        assert.strictEqual(check({ origin: `http://${onion}` }), true);
        assert.strictEqual(check({ origin: 'http://other.onion' }), false);
        assert.strictEqual(utils.isRequestOriginAllowed({ origin: 'https://app.example.com', host: 'x' }), false, 'no allow-list given');
    });

    await test('origin check: no Origin header — decided by Sec-Fetch-Site', () => {
        assert.strictEqual(check({ origin: undefined }), true, 'non-browser client / same-origin polling');
        assert.strictEqual(check({ origin: undefined, secFetchSite: 'same-origin' }), true);
        assert.strictEqual(check({ origin: undefined, secFetchSite: 'none' }), true);
        assert.strictEqual(check({ origin: '', secFetchSite: 'cross-site' }), false);
        assert.strictEqual(check({ origin: undefined, secFetchSite: 'cross-site' }), false);
    });

    // ---- CSP ----

    await test('CSP: K6 directives, nonce and same-host WebSocket', () => {
        const csp = utils.buildContentSecurityPolicy({ nonce: 'abc+/=', host: 'Chat.Example.com', secure: true });
        const directives = Object.fromEntries(csp.split('; ').map(d => {
            const [name, ...rest] = d.split(' ');
            return [name, rest.join(' ')];
        }));
        assert.strictEqual(directives['script-src'], "'self' 'nonce-abc+/='");
        assert.strictEqual(directives['style-src'], "'self'");
        assert.strictEqual(directives['connect-src'], "'self' wss://chat.example.com");
        assert.strictEqual(directives['img-src'], "'self' data: blob:");
        assert.strictEqual(directives['media-src'], "'self' blob:");
        assert.strictEqual(directives['worker-src'], "'self'");
        assert.strictEqual(directives['frame-ancestors'], "'none'");
        assert.strictEqual(directives['object-src'], "'none'");
        assert.strictEqual(directives['form-action'], "'self'");
        assert.strictEqual(directives['base-uri'], "'self'");
        assert.ok(!csp.includes('unsafe-inline'));
    });

    await test('CSP: plain http (onion) gets ws://, a hostile Host is not injected', () => {
        assert.ok(utils.buildContentSecurityPolicy({ nonce: 'n', host: `${onion}`, secure: false }).includes(`connect-src 'self' ws://${onion};`));
        assert.ok(utils.buildContentSecurityPolicy({ nonce: 'n', host: 'localhost:3000', secure: false }).includes("connect-src 'self' ws://localhost:3000;"));
        const hostile = utils.buildContentSecurityPolicy({ nonce: 'n', host: "a.com; script-src 'unsafe-inline'", secure: true });
        assert.ok(hostile.includes("connect-src 'self';"));
        assert.ok(!hostile.includes('unsafe-inline'));
        assert.throws(() => utils.buildContentSecurityPolicy({ nonce: "x' 'unsafe-inline", host: 'a.com' }), TypeError);
    });

    // ---- TLS до Postgres ----

    await test('DB TLS: development — no TLS; CA pinned — full verification', () => {
        assert.deepStrictEqual(utils.resolveDbTlsConfig({ nodeEnv: 'development', databaseUrl: 'postgres://x' }), { ssl: false });
        const pinned = utils.resolveDbTlsConfig({ nodeEnv: 'production', databaseUrl: 'postgres://u:p@db.example.com/x', caCert: 'PEM' });
        assert.deepStrictEqual(pinned.ssl, { ca: 'PEM', rejectUnauthorized: true });
        assert.ok(!pinned.error && !pinned.warning);
    });

    await test('DB TLS: without CA only the Railway private network or an explicit opt-in', () => {
        const internal = utils.resolveDbTlsConfig({ nodeEnv: 'production', databaseUrl: 'postgresql://u:p@postgres.railway.internal:5432/railway' });
        assert.deepStrictEqual(internal.ssl, { rejectUnauthorized: false });
        assert.ok(internal.warning && !internal.error);

        const publicProxy = utils.resolveDbTlsConfig({ nodeEnv: 'production', databaseUrl: 'postgresql://u:p@roundhouse.proxy.rlwy.net:12345/railway' });
        assert.ok(publicProxy.error, 'public host without CA must refuse to start');
        assert.ok(!publicProxy.error.includes('u:p'), 'credentials are never printed');

        const spoof = utils.resolveDbTlsConfig({ nodeEnv: 'production', databaseUrl: 'postgresql://u:p@railway.internal.evil.com/x' });
        assert.ok(spoof.error);

        const optIn = utils.resolveDbTlsConfig({ nodeEnv: 'production', databaseUrl: 'postgresql://u:p@db.example.com/x', insecure: true });
        assert.deepStrictEqual(optIn.ssl, { rejectUnauthorized: false });
        assert.ok(optIn.warning && !optIn.error);

        assert.ok(utils.resolveDbTlsConfig({ nodeEnv: 'production', databaseUrl: undefined }).error);
    });

    // ---- мелочи ----

    await test('createCounter: increments, decrements and forgets zero keys', () => {
        const c = utils.createCounter();
        c.increment('a'); c.increment('a'); c.increment('b');
        assert.strictEqual(c.get('a'), 2);
        assert.deepStrictEqual(c.keys().sort(), ['a', 'b']);
        c.decrement('a'); c.decrement('a'); c.decrement('b'); c.decrement('zzz');
        assert.strictEqual(c.get('a'), 0);
        assert.strictEqual(c.size(), 0);
        assert.deepStrictEqual(c.keys(), []);
    });

    // ---- журнал безопасности: семейство клиента ----

    await test('classifyUserAgent: common browsers and systems', () => {
        const cases = [
            ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36', 'Chrome · Windows'],
            ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0', 'Edge · Windows'],
            ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/113.0.0.0', 'Opera · Windows'],
            ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 YaBrowser/24.7.0.0 Safari/537.36', 'Яндекс Браузер · Windows'],
            ['Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0', 'Firefox · Android'],
            ['Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36', 'Samsung Internet · Android'],
            ['Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36', 'Chrome · Android'],
            ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1', 'Safari · iOS'],
            ['Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.0.0 Mobile/15E148 Safari/604.1', 'Chrome · iOS'],
            ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/130.0 Mobile/15E148 Safari/605.1.15', 'Firefox · iOS'],
            ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15', 'Safari · macOS'],
            ['Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0', 'Firefox · Linux'],
            ['Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36', 'Chrome · ChromeOS'],
            // Tor Browser выдаёт себя за Firefox на Windows — так и показываем.
            ['Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0', 'Firefox · Windows'],
        ];
        for (const [ua, expected] of cases) assert.strictEqual(utils.classifyUserAgent(ua), expected, ua);
    });

    await test('classifyUserAgent: unknown input never leaks into the result', () => {
        assert.strictEqual(utils.classifyUserAgent(undefined), utils.UNKNOWN_CLIENT);
        assert.strictEqual(utils.classifyUserAgent(''), 'Неизвестный клиент');
        assert.strictEqual(utils.classifyUserAgent('   '), utils.UNKNOWN_CLIENT);
        assert.strictEqual(utils.classifyUserAgent(['Chrome/1']), utils.UNKNOWN_CLIENT);
        assert.strictEqual(utils.classifyUserAgent('curl/8.5.0'), utils.UNKNOWN_CLIENT);
        assert.strictEqual(utils.classifyUserAgent('<script>alert(1)</script>'), utils.UNKNOWN_CLIENT);
        // Только ОС или только браузер — без разделителя.
        assert.strictEqual(utils.classifyUserAgent('SomeBot (Windows)'), 'Windows');
        assert.strictEqual(utils.classifyUserAgent('Firefox/130.0'), 'Firefox');
        // Результат — всегда из фиксированного набора, без версий и мусора.
        const allowed = /^(?:(?:Edge|Opera|Яндекс Браузер|Samsung Internet|Firefox|Chrome|Safari)(?: · (?:iOS|Android|Windows|ChromeOS|macOS|Linux))?|iOS|Android|Windows|ChromeOS|macOS|Linux|Неизвестный клиент)$/;
        const hostile = 'Mozilla/5.0 (Windows NT 10.0) Chrome/1.0 ' + 'x'.repeat(100000) + ' Firefox/2';
        const started = Date.now();
        assert.match(utils.classifyUserAgent(hostile), allowed);
        assert.ok(Date.now() - started < 200, 'long User-Agent is cut before matching');
        assert.doesNotMatch(utils.classifyUserAgent('Chrome/128.0.6613.84 (Windows NT 10.0)'), /\d/);
    });

    await test('normalizeEmail and positiveNumberOr', () => {
        assert.strictEqual(utils.normalizeEmail('  Ivan@Example.COM '), 'ivan@example.com');
        assert.strictEqual(utils.normalizeEmail({}), '');
        assert.strictEqual(utils.positiveNumberOr('24', 168), 24);
        assert.strictEqual(utils.positiveNumberOr('0.5', 168), 0.5);
        for (const bad of [undefined, '', '0', '-1', 'abc', 'Infinity']) assert.strictEqual(utils.positiveNumberOr(bad, 168), 168, String(bad));
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
