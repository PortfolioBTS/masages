'use strict';
// Тесты lib/metadata-stripper.js, lib/disappearing-messages.js и чистых
// модулей новых функций (lib/invites.js, lib/chat-settings.js,
// lib/anon-lifetime.js) без БД.
// Запуск: node test/lib.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sharp = require('sharp');
const { stripMetadataFromFile, cleanupStaleTempFiles, _internal } = require('../lib/metadata-stripper');
const DisappearingMessagesManager = require('../lib/disappearing-messages');
const invites = require('../lib/invites');
const chatSettings = require('../lib/chat-settings');
const anon = require('../lib/anon-lifetime');

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

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-lib-test-'));

function makePdf() {
    const objects = [
        '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>\nendobj\n',
        '2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n',
        '3 0 obj\n<< /Author (Ivan \\(secret\\) Petrov) /Creator <4D7943616D> /Title (Report (draft)) >>\nendobj\n',
        '4 0 obj\n<< /Type /Metadata /Subtype /XML /Length 80 >>\nstream\n<x:xmpmeta xmlns:x="adobe:ns:meta/"><dc:creator>Ivan Petrov</dc:creator></x:xmpmeta>\nendstream\nendobj\n',
    ];
    let body = '%PDF-1.4\n';
    const offsets = [];
    for (const obj of objects) { offsets.push(body.length); body += obj; }
    const xrefOffset = body.length;
    body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const off of offsets) body += `${String(off).padStart(10, '0')} 00000 n \n`;
    body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 3 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
    return Buffer.from(body, 'latin1');
}

// Минимальный MP4 "с телефона": ©xyz в moov/udta и время съёмки в mvhd.
function makeMp4() {
    const box = (type, ...parts) => {
        const body = Buffer.concat(parts.map(p => (typeof p === 'string' ? Buffer.from(p, 'latin1') : p)));
        const head = Buffer.alloc(8);
        head.writeUInt32BE(8 + body.length);
        head.write(type, 4, 'latin1');
        return Buffer.concat([head, body]);
    };
    const mvhd = Buffer.alloc(100);
    mvhd.writeUInt32BE(0xDEADBEEF, 4); // creation_time
    mvhd.writeUInt32BE(0xCAFEBABE, 8); // modification_time
    mvhd.writeUInt32BE(1000, 12);
    const gps = '+55.7558+037.6173/';
    const xyz = Buffer.concat([Buffer.from([0, gps.length, 0x15, 0xC7]), Buffer.from(gps, 'latin1')]);
    return Buffer.concat([
        box('ftyp', 'isom', Buffer.alloc(4), 'isommp42'),
        box('moov', box('mvhd', mvhd), box('udta', box('\xa9xyz', xyz), box('\xa9mod', 'SM-G991B'))),
        box('mdat', Buffer.alloc(64, 0x11)),
    ]);
}

// WAV с LIST/INFO (название, автор).
function makeWav() {
    const chunk = (id, data) => {
        const head = Buffer.alloc(8);
        head.write(id, 0, 'latin1');
        head.writeUInt32LE(data.length, 4);
        return Buffer.concat([head, data, Buffer.alloc(data.length & 1)]);
    };
    const fmt = Buffer.alloc(16);
    fmt.writeUInt16LE(1, 0); fmt.writeUInt16LE(1, 2); fmt.writeUInt32LE(8000, 4);
    fmt.writeUInt32LE(16000, 8); fmt.writeUInt16LE(2, 12); fmt.writeUInt16LE(16, 14);
    const info = Buffer.concat([Buffer.from('INFO'), chunk('IART', Buffer.from('Ivan Petrov\0'))]);
    const body = Buffer.concat([Buffer.from('WAVE'), chunk('fmt ', fmt), chunk('LIST', info), chunk('data', Buffer.alloc(8, 0x22))]);
    const head = Buffer.alloc(8);
    head.write('RIFF', 0, 'latin1');
    head.writeUInt32LE(body.length, 4);
    return Buffer.concat([head, body]);
}

const tempFilesLeft = () => fs.readdirSync(tmpDir).filter(f => f.includes('-cleaned-'));

async function main() {
    console.log('Lib tests\n');

    await test('image: EXIF (author, GPS) is removed, orientation is applied', async () => {
        const input = path.join(tmpDir, 'photo.jpg');
        await sharp({ create: { width: 40, height: 20, channels: 3, background: '#336699' } })
            .jpeg()
            .withMetadata({ orientation: 6 })
            .withExifMerge({ IFD0: { Artist: 'Ivan Petrov', Copyright: 'secret' }, IFD3: { GPSLatitudeRef: 'N' } })
            .toFile(input);
        const before = await sharp(input).metadata();
        assert.ok(before.exif && before.exif.toString('latin1').includes('Ivan Petrov'), 'fixture must carry EXIF');
        assert.strictEqual(before.orientation, 6);

        await stripMetadataFromFile(input, 'image/jpeg');
        const after = await sharp(input).metadata();
        assert.strictEqual(after.exif, undefined, 'EXIF must be gone');
        assert.strictEqual(after.xmp, undefined, 'XMP must be gone');
        // Orientation 6 = повернуть на 90° — ширина и высота меняются местами
        assert.strictEqual(after.width, 20);
        assert.strictEqual(after.height, 40);
        assert.deepStrictEqual(fs.readdirSync(tmpDir).filter(f => f.includes('-cleaned-')), [], 'no temp files left');
    });

    await test('image: animated GIF keeps all frames', async () => {
        const input = path.join(tmpDir, 'anim.gif');
        const frame = (color) => sharp({ create: { width: 8, height: 8, channels: 3, background: color } }).png().toBuffer();
        const frames = await Promise.all(['#ff0000', '#00ff00', '#0000ff'].map(frame));
        await sharp(frames, { join: { animated: true } }).gif().toFile(input);
        assert.strictEqual((await sharp(input).metadata()).pages, 3);

        await stripMetadataFromFile(input, 'image/gif');
        assert.strictEqual((await sharp(input).metadata()).pages, 3, 'animation must survive');
    });

    await test('image: an undecodable file is rejected (fail closed), original left for the caller', async () => {
        const input = path.join(tmpDir, 'broken.png');
        fs.writeFileSync(input, Buffer.from('89504E470D0A1A0A0000garbage', 'hex'));
        await assert.rejects(() => stripMetadataFromFile(input, 'image/png'));
        assert.deepStrictEqual(fs.readdirSync(tmpDir).filter(f => f.includes('-cleaned-')), []);
    });

    await test('pdf: Info strings and XMP are blanked, byte offsets unchanged', async () => {
        const pdf = makePdf();
        const originalLength = pdf.length;
        const out = _internal.blankPdfMetadata(Buffer.from(pdf)).toString('latin1');
        assert.strictEqual(out.length, originalLength, 'length (and so every xref offset) must not change');
        assert.ok(!out.includes('Ivan'), 'author must be gone');
        assert.ok(!out.includes('4D7943616D'), 'hex string must be gone');
        assert.ok(!out.includes('draft'), 'nested parentheses handled');
        assert.ok(out.includes('/Author ('), 'dictionary structure stays intact');
        const xrefOffset = Number(out.match(/startxref\n(\d+)/)[1]);
        assert.strictEqual(out.slice(xrefOffset, xrefOffset + 4), 'xref');
        const obj3Offset = Number(out.match(/(\d{10}) 00000 n /g)[2].slice(0, 10));
        assert.ok(out.slice(obj3Offset).startsWith('3 0 obj'), 'object offsets still valid');
    });

    await test('pdf on disk: stripMetadataFromFile goes through MediaSanitizer', async () => {
        const input = path.join(tmpDir, 'doc.pdf');
        const pdf = makePdf();
        fs.writeFileSync(input, pdf);
        await stripMetadataFromFile(input, 'application/pdf');
        const out = fs.readFileSync(input);
        assert.strictEqual(out.length, pdf.length);
        assert.ok(!out.toString('latin1').includes('Ivan'));
        assert.deepStrictEqual(tempFilesLeft(), []);
    });

    await test('video/mp4: GPS (©xyz), device model and creation time removed on disk, length unchanged', async () => {
        const input = path.join(tmpDir, 'clip.mp4');
        const mp4 = makeMp4();
        fs.writeFileSync(input, mp4);
        await stripMetadataFromFile(input, 'video/mp4');
        const out = fs.readFileSync(input);
        assert.strictEqual(out.length, mp4.length, 'offsets inside the file must not move');
        const text = out.toString('latin1');
        assert.ok(!text.includes('55.7558') && !text.includes('SM-G991B'), 'GPS and model must be gone');
        assert.strictEqual(out.indexOf(Buffer.from('DEADBEEF', 'hex')), -1, 'creation time zeroed');
        assert.ok(out.subarray(out.length - 64).every(x => x === 0x11), 'media data intact');
        assert.deepStrictEqual(tempFilesLeft(), []);
    });

    await test('audio/wav: LIST/INFO (author) removed on disk', async () => {
        const input = path.join(tmpDir, 'voice.wav');
        const wav = makeWav();
        fs.writeFileSync(input, wav);
        await stripMetadataFromFile(input, 'audio/wav');
        const out = fs.readFileSync(input);
        assert.strictEqual(out.length, wav.length);
        assert.ok(!out.toString('latin1').includes('Ivan'));
        assert.ok(out.toString('latin1').includes('JUNK'));
        assert.deepStrictEqual(tempFilesLeft(), []);
    });

    await test('audio/mpeg: file without MPEG frames is rejected, original untouched, no temp files', async () => {
        const input = path.join(tmpDir, 'fake.mp3');
        const fake = Buffer.concat([Buffer.from('ID3\x03\x00\x00\x00\x00\x00\x05', 'latin1'), Buffer.from('Ivan!not audio at all')]);
        fs.writeFileSync(input, fake);
        await assert.rejects(() => stripMetadataFromFile(input, 'audio/mpeg'));
        assert.ok(fs.readFileSync(input).equals(fake), 'caller decides what to do with the rejected original');
        assert.deepStrictEqual(tempFilesLeft(), []);
    });

    await test('text/plain is left as is; unsupported MIME is rejected (fail closed)', async () => {
        const input = path.join(tmpDir, 'note.txt');
        fs.writeFileSync(input, 'Ivan says hi');
        assert.strictEqual(await stripMetadataFromFile(input, 'text/plain'), input);
        assert.strictEqual(fs.readFileSync(input, 'utf8'), 'Ivan says hi');
        await assert.rejects(() => stripMetadataFromFile(input, 'image/svg+xml'), /Неподдерживаемый тип/);
        await assert.rejects(() => stripMetadataFromFile(input, 'application/octet-stream'), /Неподдерживаемый тип/);
        assert.deepStrictEqual(tempFilesLeft(), []);
    });

    await test('cleanupStaleTempFiles removes only old *-cleaned-* files, never attachments', async () => {
        const dir = fs.mkdtempSync(path.join(tmpDir, 'uploads-'));
        const attachment = path.join(dir, '123-abc.jpg');
        const staleTemp = path.join(dir, '123-abc-cleaned-deadbeef.jpg');
        const freshTemp = path.join(dir, '456-def-cleaned-cafebabe.jpg');
        for (const f of [attachment, staleTemp, freshTemp]) fs.writeFileSync(f, 'x');
        const old = new Date(Date.now() - 3 * 60 * 60 * 1000);
        fs.utimesSync(attachment, old, old);
        fs.utimesSync(staleTemp, old, old);

        await cleanupStaleTempFiles(dir, 60 * 60 * 1000);
        assert.ok(fs.existsSync(attachment), 'old attachment must stay');
        assert.ok(!fs.existsSync(staleTemp), 'stale temp file must be removed');
        assert.ok(fs.existsSync(freshTemp), 'fresh temp file (processing in progress) must stay');
    });

    await test('disappearing: expiry validation', async () => {
        const { normalizeExpirySeconds, MAX_EXPIRY_SECONDS } = DisappearingMessagesManager;
        assert.strictEqual(normalizeExpirySeconds(60), 60);
        assert.strictEqual(normalizeExpirySeconds('30'), 30);
        assert.strictEqual(normalizeExpirySeconds(1.2), 2);
        for (const bad of [0, -5, NaN, 'abc', null, MAX_EXPIRY_SECONDS + 1]) {
            assert.throws(() => normalizeExpirySeconds(bad), RangeError, String(bad));
        }
    });

    await test('disappearing: timers longer than setTimeout limit are left to the DB worker', async () => {
        const queries = [];
        const pool = { query: async (sql, params) => { queries.push({ sql, params }); return { rows: [] }; } };
        const manager = new DisappearingMessagesManager(pool);
        await manager.setMessageExpiry(1, 30 * 24 * 60 * 60); // 30 суток > 24.8 суток
        assert.strictEqual(manager.scheduledDeletions.has(1), false, 'must not schedule an overflowing setTimeout');
        await manager.setMessageExpiry(2, 60);
        assert.strictEqual(manager.scheduledDeletions.has(2), true);
        clearTimeout(manager.scheduledDeletions.get(2));
        assert.ok(queries.every(q => !q.params.some(p => p instanceof Date)), 'expires_at is computed by Postgres, not passed as a JS Date');
    });

    await test('disappearing: deleteMessages physically deletes rows and reports them to the callback', async () => {
        const deletedRows = [{ id: 7, chat_id: 3, room_id: null, file_url: '/uploads/a.jpg' }];
        const queries = [];
        const pool = {
            query: async (sql, params) => {
                queries.push({ sql, params });
                return { rows: /^\s*DELETE FROM messages\b/.test(sql) ? deletedRows : [] };
            },
        };
        let reported = null;
        const manager = new DisappearingMessagesManager(pool, { onMessagesDeleted: (rows) => { reported = rows; } });
        const result = await manager.deleteMessages([7, 'x', 7]);
        assert.deepStrictEqual(result, deletedRows);
        assert.deepStrictEqual(reported, deletedRows);
        // Одна физическая DELETE-выборка: ни soft-delete (UPDATE), ни
        // плейсхолдера текста; message_expiry/реакции уходят каскадом.
        assert.strictEqual(queries.length, 1);
        assert.match(queries[0].sql, /RETURNING id, chat_id, room_id, file_url/);
        assert.ok(!queries.some(q => /UPDATE messages|deleted\s*=\s*1/.test(q.sql)), 'no soft-delete');
        assert.deepStrictEqual(queries[0].params, [[7]], 'ids are filtered and de-duplicated');
    });

    await test('disappearing: deleteMessages cancels pending timers of deleted messages', async () => {
        const pool = { query: async (sql) => ({ rows: /^\s*DELETE FROM messages\b/.test(sql) ? [{ id: 5, chat_id: 1, room_id: null, file_url: null }] : [] }) };
        const manager = new DisappearingMessagesManager(pool);
        await manager.setMessageExpiry(5, 60);
        assert.strictEqual(manager.scheduledDeletions.has(5), true);
        await manager.deleteMessages([5]);
        assert.strictEqual(manager.scheduledDeletions.has(5), false, 'manual delete must not leave a timer behind');
    });

    await test('disappearing: a DB error is logged, not thrown, and nothing is reported', async () => {
        const pool = { query: async () => { throw new Error('connection terminated'); } };
        let called = false;
        const manager = new DisappearingMessagesManager(pool, { onMessagesDeleted: () => { called = true; } });
        const originalError = console.error;
        console.error = () => {};
        try {
            assert.deepStrictEqual(await manager.deleteMessages([1, 2]), []);
        } finally {
            console.error = originalError;
        }
        assert.strictEqual(called, false);
        assert.deepStrictEqual(await manager.deleteMessages([]), []);
    });

    await test('disappearing: room timer is stored per room; 0 turns it off', async () => {
        const queries = [];
        const pool = { query: async (sql, params) => { queries.push({ sql, params }); return { rows: [] }; } };
        const manager = new DisappearingMessagesManager(pool);
        await manager.setRoomDefaultExpiry(42, 3600);
        assert.match(queries[0].sql, /INSERT INTO room_settings/);
        assert.deepStrictEqual(queries[0].params, [42, 3600]);
        await manager.setRoomDefaultExpiry(42, 0);
        assert.match(queries[1].sql, /DELETE FROM room_settings WHERE room_id = \$1/);
        assert.deepStrictEqual(queries[1].params, [42]);
        await assert.rejects(() => manager.setRoomDefaultExpiry(42, 'abc'), RangeError);
        assert.strictEqual(await manager.getRoomSettings(42), null);
    });

    await test('disappearing: shortenOnly never extends an existing expiry; timer follows the DB', async () => {
        const queries = [];
        // БД вернула, что до удаления осталось 10 с (срок уже был ближе запрошенного часа).
        const pool = { query: async (sql, params) => { queries.push({ sql, params }); return { rows: [{ remaining: 10 }] }; } };
        const manager = new DisappearingMessagesManager(pool);
        await manager.setMessageExpiry(9, 3600, false, { shortenOnly: true });
        assert.match(queries[0].sql, /LEAST\(message_expiry\.expires_at, EXCLUDED\.expires_at\)/);
        const timer = manager.scheduledDeletions.get(9);
        assert.ok(timer, 'timer scheduled');
        assert.ok(timer._idleTimeout <= 10 * 1000, 'timer uses the remaining time from the DB, not the requested hour');
        clearTimeout(timer);
        await manager.setMessageExpiry(10, 60);
        assert.doesNotMatch(queries[1].sql, /LEAST\(/, 'without shortenOnly the expiry is simply replaced');
        clearTimeout(manager.scheduledDeletions.get(10));
    });

    // ---- приглашения (lib/invites.js) ----

    await test('invites: rotate parameters — defaults, allowed TTLs, member limit, approval', () => {
        const { parseInviteSettings } = invites;
        assert.deepStrictEqual(parseInviteSettings({}, { defaultTtlSeconds: 604800 }), { ttlSeconds: 604800, maxMembers: null, requireApproval: true });
        assert.deepStrictEqual(parseInviteSettings(undefined, { defaultTtlSeconds: 7200 }), { ttlSeconds: 7200, maxMembers: null, requireApproval: true }, 'INVITE_TTL_HOURS default may be any value');
        for (const ttl of [3600, 86400, 604800, 2592000]) {
            assert.strictEqual(parseInviteSettings({ ttlSeconds: ttl }, { defaultTtlSeconds: 1 }).ttlSeconds, ttl);
        }
        assert.strictEqual(parseInviteSettings({ ttlSeconds: '86400' }, { defaultTtlSeconds: 1 }).ttlSeconds, 86400);
        for (const bad of [60, 7200, -3600, 3600.5, true, 'abc', [3600], { v: 1 }]) {
            assert.throws(() => parseInviteSettings({ ttlSeconds: bad }, { defaultTtlSeconds: 3600 }), RangeError, JSON.stringify(bad));
        }
        const p = parseInviteSettings({ ttlSeconds: 3600, maxMembers: 10, requireApproval: false }, { defaultTtlSeconds: 1 });
        assert.deepStrictEqual(p, { ttlSeconds: 3600, maxMembers: 10, requireApproval: false });
        assert.strictEqual(parseInviteSettings({ maxMembers: 2 }, { defaultTtlSeconds: 1 }).maxMembers, 2);
        assert.strictEqual(parseInviteSettings({ maxMembers: 1000 }, { defaultTtlSeconds: 1 }).maxMembers, 1000);
        assert.strictEqual(parseInviteSettings({ maxMembers: null }, { defaultTtlSeconds: 1 }).maxMembers, null);
        for (const bad of [1, 0, 1001, 2.5, -5, true, 'ten']) {
            assert.throws(() => parseInviteSettings({ maxMembers: bad }, { defaultTtlSeconds: 1 }), RangeError, JSON.stringify(bad));
        }
        for (const bad of ['true', 1, 0, 'false']) {
            assert.throws(() => parseInviteSettings({ requireApproval: bad }, { defaultTtlSeconds: 1 }), RangeError, JSON.stringify(bad));
        }
        assert.throws(() => parseInviteSettings({}, {}), RangeError, 'no default TTL');
    });

    await test('invites: usable code, room limit, description for members', () => {
        const now = Date.parse('2026-09-27T12:00:00Z');
        const room = { code: 'A'.repeat(26), code_expires_at: '2026-09-28T12:00:00Z', invite_disabled: false, invite_max_members: null, invite_require_approval: true };
        assert.strictEqual(invites.isInviteUsable(room, now), true);
        assert.strictEqual(invites.isInviteUsable({ ...room, invite_disabled: true }, now), false);
        assert.strictEqual(invites.isInviteUsable({ ...room, code_expires_at: '2026-09-27T11:00:00Z' }, now), false);
        assert.strictEqual(invites.isInviteUsable({ ...room, code_expires_at: null }, now), false);
        assert.strictEqual(invites.isInviteUsable(null, now), false);

        assert.strictEqual(invites.isRoomFull(5, null), false);
        assert.strictEqual(invites.isRoomFull(4, 5), false);
        assert.strictEqual(invites.isRoomFull(5, 5), true);
        assert.strictEqual(invites.isRoomFull(7, 5), true, 'limit lowered below the current size — nobody else gets in');

        assert.deepStrictEqual(invites.describeInvite(room, 3, now), {
            code: room.code, expiresAt: '2026-09-28T12:00:00.000Z', expired: false, disabled: false,
            maxMembers: null, requireApproval: true, memberCount: 3,
        });
        const disabled = invites.describeInvite({ ...room, invite_disabled: true, invite_max_members: 10, invite_require_approval: false }, '4', now);
        assert.deepStrictEqual(disabled, { code: null, expiresAt: null, expired: false, disabled: true, maxMembers: 10, requireApproval: false, memberCount: 4 });
        assert.strictEqual(invites.describeInvite({ ...room, code_expires_at: '2026-09-27T11:00:00Z' }, 1, now).expired, true);
    });

    await test('invites: one message for missing, expired and disabled codes; join requests live 7 days', () => {
        assert.strictEqual(invites.INVALID_INVITE_MESSAGE, 'Код недействителен');
        assert.strictEqual(invites.ROOM_FULL_MESSAGE, 'В группе нет свободных мест');
        assert.strictEqual(invites.JOIN_REQUEST_TTL_SECONDS, 7 * 24 * 3600);
        const now = Date.parse('2026-09-27T12:00:00Z');
        assert.strictEqual(invites.isJoinRequestExpired('2026-09-21T12:00:01Z', now), false);
        assert.strictEqual(invites.isJoinRequestExpired('2026-09-20T12:00:00Z', now), true);
        assert.strictEqual(invites.isJoinRequestExpired('garbage', now), true);
    });

    // ---- настройки чата (lib/chat-settings.js) ----

    await test('chat settings: only the fixed expiry options are accepted', () => {
        for (const s of [0, 300, 3600, 86400, 604800]) assert.strictEqual(chatSettings.parseChatExpirySeconds(s), s);
        assert.strictEqual(chatSettings.parseChatExpirySeconds('3600'), 3600);
        for (const bad of [60, 1, 7200, -300, 300.5, null, undefined, '', 'abc', true, [300]]) {
            assert.throws(() => chatSettings.parseChatExpirySeconds(bad), RangeError, JSON.stringify(bad));
        }
    });

    await test('chat settings: legacy personal timers → the shortest one, never longer than asked', () => {
        const { snapLegacyExpirySeconds, pickRoomExpiryFromLegacy } = chatSettings;
        assert.strictEqual(snapLegacyExpirySeconds(3600), 3600);
        assert.strictEqual(snapLegacyExpirySeconds(7200), 3600, '2 h → 1 h, not 1 day');
        assert.strictEqual(snapLegacyExpirySeconds(90000), 86400);
        assert.strictEqual(snapLegacyExpirySeconds(365 * 86400), 604800);
        assert.strictEqual(snapLegacyExpirySeconds(60), 300, 'shorter than every option → the shortest option');
        assert.strictEqual(snapLegacyExpirySeconds(0), 0);
        assert.strictEqual(snapLegacyExpirySeconds(null), 0);
        assert.strictEqual(pickRoomExpiryFromLegacy([86400, 3600, 604800]), 3600);
        assert.strictEqual(pickRoomExpiryFromLegacy([null, 0, 7200]), 3600);
        assert.strictEqual(pickRoomExpiryFromLegacy([null, 0]), 0);
        assert.strictEqual(pickRoomExpiryFromLegacy([]), 0);
    });

    await test('chat settings: a personal expiry cannot outlive the chat timer', () => {
        const { effectiveMessageExpiry } = chatSettings;
        assert.strictEqual(effectiveMessageExpiry(null, null), null);
        assert.strictEqual(effectiveMessageExpiry(60, null), 60);
        assert.strictEqual(effectiveMessageExpiry(null, 3600), 3600);
        assert.strictEqual(effectiveMessageExpiry(60, 3600), 60);
        assert.strictEqual(effectiveMessageExpiry(86400, 3600), 3600);
        assert.strictEqual(effectiveMessageExpiry(0, 300), 300);
    });

    await test('chat settings: prefs must be booleans, at least one', () => {
        const { parseChatPrefs } = chatSettings;
        assert.deepStrictEqual(parseChatPrefs({ pinned: true }), { pinned: true, muted: null, archived: null });
        assert.deepStrictEqual(parseChatPrefs({ pinned: false, muted: true, archived: false, extra: 1 }), { pinned: false, muted: true, archived: false });
        for (const bad of [{}, null, undefined, { pinned: 'true' }, { muted: 1 }, { archived: null }, { other: true }]) {
            assert.throws(() => parseChatPrefs(bad), RangeError, JSON.stringify(bad));
        }
    });

    // ---- срок жизни анонима (lib/anon-lifetime.js) ----

    await test('anon lifetime: allowed values, default and legacy NULL', () => {
        assert.strictEqual(anon.parseAnonLifetime(undefined), 'tab');
        assert.strictEqual(anon.parseAnonLifetime(null), 'tab');
        assert.strictEqual(anon.parseAnonLifetime(''), 'tab');
        for (const v of ['tab', 'day', 'week']) assert.strictEqual(anon.parseAnonLifetime(v), v);
        for (const bad of ['month', 'TAB', 1, true, {}, '__proto__', 'constructor', 'toString']) {
            assert.throws(() => anon.parseAnonLifetime(bad), RangeError, String(bad));
        }
        assert.strictEqual(anon.storedAnonLifetime(null), 'tab', 'accounts created before the choice live by the shortest rule');
        assert.strictEqual(anon.storedAnonLifetime('week'), 'week');
        assert.strictEqual(anon.storedAnonLifetime('__proto__'), 'tab');
        assert.deepStrictEqual(anon.ANON_LIFETIMES, { tab: 1800, day: 86400, week: 604800 });
    });

    await test('anon lifetime: expiry = last activity + TTL, capped at 7 days from creation', () => {
        const created = Date.parse('2026-09-20T00:00:00Z');
        const min = 60 * 1000, day = 24 * 60 * min;
        // Без активности — от создания.
        assert.strictEqual(anon.anonExpiresAtMs({ lifetime: 'tab', createdAtMs: created }), created + 30 * min);
        assert.strictEqual(anon.anonExpiresAtMs({ lifetime: 'tab', createdAtMs: created, lastActiveMs: null }), created + 30 * min);
        assert.strictEqual(anon.anonExpiresAtMs({ lifetime: 'day', createdAtMs: created, lastActiveMs: created + 2 * day }), created + 3 * day);
        // Активность не продлевает дальше 7 дней с создания.
        assert.strictEqual(anon.anonExpiresAtMs({ lifetime: 'week', createdAtMs: created, lastActiveMs: created + 5 * day }), created + 7 * day);
        assert.strictEqual(anon.anonExpiresAtMs({ lifetime: 'tab', createdAtMs: created, lastActiveMs: created + 7 * day - min }), created + 7 * day);
        assert.strictEqual(anon.anonExpiresAtMs({ lifetime: null, createdAtMs: created, lastActiveMs: created + day }), created + day + 30 * min, 'legacy NULL = tab');

        const active = { lifetime: 'tab', createdAtMs: created, lastActiveMs: created + day };
        assert.strictEqual(anon.isAnonExpired({ ...active, now: created + day + 29 * min }), false);
        assert.strictEqual(anon.isAnonExpired({ ...active, now: created + day + 30 * min }), true);
        assert.strictEqual(anon.isAnonExpired({ lifetime: 'week', createdAtMs: created, lastActiveMs: created + 7 * day - 1, now: created + 7 * day }), true, 'hard cap');
        assert.strictEqual(anon.isAnonExpired({ lifetime: 'week', createdAtMs: undefined, lastActiveMs: Date.now(), now: Date.now() }), true, 'no creation time — fail closed');
    });

    await test('anon lifetime: cookie max-age and activity throttling', () => {
        const created = Date.parse('2026-09-20T00:00:00Z');
        const day = 24 * 3600 * 1000;
        assert.strictEqual(anon.anonCookieMaxAgeMs({ lifetime: 'tab', createdAtMs: created, now: created }), null, "'tab' — browser-session cookie");
        assert.strictEqual(anon.anonCookieMaxAgeMs({ lifetime: 'day', createdAtMs: created, now: created }), 7 * day);
        assert.strictEqual(anon.anonCookieMaxAgeMs({ lifetime: 'week', createdAtMs: created, now: created + 2 * day }), 5 * day);
        assert.strictEqual(anon.anonCookieMaxAgeMs({ lifetime: 'week', createdAtMs: created, now: created + 8 * day }), 0);

        const t = 1_000_000;
        assert.strictEqual(anon.shouldPersistActivity(undefined, t), true);
        assert.strictEqual(anon.shouldPersistActivity(t - 59 * 1000, t), false, 'API activity is written at most once a minute');
        assert.strictEqual(anon.shouldPersistActivity(t - 60 * 1000, t), true);
        assert.ok(anon.ANON_SOCKET_ACTIVITY_INTERVAL_MS < anon.ANON_LIFETIMES.tab * 1000 / 2, 'open sockets refresh well within the shortest TTL');
    });

    await test('anon lifetime: welcome text names the chosen rule and has no emoji', () => {
        const emoji = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}️•]/u;
        for (const [lifetime, phrase] of [['tab', '30 минут'], ['day', 'сутки'], ['week', '7 дней без активности'], [null, '30 минут']]) {
            const text = anon.anonWelcomeText(lifetime);
            assert.ok(text.includes(phrase), `${lifetime}: ${text}`);
            assert.ok(text.includes('не позже чем через 7 дней'), 'hard cap is mentioned');
            assert.doesNotMatch(text, emoji);
        }
    });

    fs.rmSync(tmpDir, { recursive: true, force: true });
    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exit(1);
}

main().catch(err => { console.error('Test runner crashed:', err); process.exit(1); });
