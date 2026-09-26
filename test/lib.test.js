'use strict';
// Тесты lib/metadata-stripper.js и lib/disappearing-messages.js без БД.
// Запуск: node test/lib.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sharp = require('sharp');
const { stripMetadataFromFile, cleanupStaleTempFiles, _internal } = require('../lib/metadata-stripper');
const DisappearingMessagesManager = require('../lib/disappearing-messages');

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

    await test('disappearing: deleteMessages reports deleted rows to the callback', async () => {
        const deletedRows = [{ id: 7, chat_id: 3, room_id: null, file_url: '/uploads/a.jpg' }];
        const pool = {
            query: async (sql) => ({ rows: sql.includes('UPDATE messages') ? deletedRows : [] }),
        };
        let reported = null;
        const manager = new DisappearingMessagesManager(pool, { onMessagesDeleted: (rows) => { reported = rows; } });
        const result = await manager.deleteMessages([7, 'x']);
        assert.deepStrictEqual(result, deletedRows);
        assert.deepStrictEqual(reported, deletedRows);
    });

    fs.rmSync(tmpDir, { recursive: true, force: true });
    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exit(1);
}

main().catch(err => { console.error('Test runner crashed:', err); process.exit(1); });
