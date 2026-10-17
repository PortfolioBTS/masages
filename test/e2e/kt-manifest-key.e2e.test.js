'use strict';
// Ключ журнала ключей в манифесте клиента на настоящем сервере (T5.4, roadmap R10,
// docs/security/key-transparency.md, раздел 11): при заданном KT_SIGNING_KEY сервер кладёт в
// /client-manifest.json открытый ключ журнала (keys.kt), и это те же байты, что собирает
// scripts/release-manifest.js с --kt-key; голова журнала подписана тем же ключом, который назван в манифесте.
// Без KT_SIGNING_KEY (набор client-integrity) поля keys в манифесте нет.

const { test } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { spawnSync } = require('child_process');
const NyxoKt = require('../../public/lib/kt.js');
const { createSuite, waitUntil } = require('./helpers/scenarios');

const REPO_ROOT = path.join(__dirname, '..', '..');
const logKey = crypto.generateKeyPairSync('ed25519');
const KT_SIGNING_KEY = logKey.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const LOG_PUB_B64 = logKey.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');

const suite = createSuite('kt-manifest-key', { env: { KT_SIGNING_KEY, KT_EPOCH_SECONDS: 2 } });

test('манифест с ключом журнала: keys.kt = открытый ключ из KT_SIGNING_KEY, те же байты, что у скрипта релиза с --kt-key', async () => {
    const res = await suite.client().get('/client-manifest.json', { binary: true });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('set-cookie'), null, 'манифест не создаёт сессию');
    const manifest = JSON.parse(res.body.toString('utf8'));
    assert.deepStrictEqual(Object.keys(manifest), ['format', 'aliases', 'files', 'keys']);
    assert.deepStrictEqual(manifest.keys, { kt: LOG_PUB_B64 });
    assert.strictEqual(res.headers.get('x-client-manifest-sha256'), crypto.createHash('sha256').update(res.body).digest('hex'));

    const script = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts', 'release-manifest.js'), '--stdout', '--kt-key', LOG_PUB_B64], { cwd: REPO_ROOT });
    assert.strictEqual(script.status, 0, script.stderr.toString());
    assert.ok(res.body.equals(script.stdout), 'сервер и скрипт релиза с тем же ключом отдали разные манифесты');

    // Релиз без ключа (или с чужим) от сервера с журналом отличается: сторож это увидит.
    const without = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts', 'release-manifest.js'), '--stdout'], { cwd: REPO_ROOT, env: { ...process.env, KT_PUBLIC_KEY: '' } });
    assert.strictEqual(without.status, 0, without.stderr.toString());
    assert.ok(!res.body.equals(without.stdout), 'манифест релиза без ключа не должен совпасть с манифестом сервера с журналом');
});

test('ключ из манифеста тот, которым подписана голова журнала (GET /api/kt/head)', async () => {
    const manifest = JSON.parse((await suite.client().get('/client-manifest.json')).text);
    const client = suite.client({ name: 'манифест' });
    await client.registerAnon();
    const dh = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const identity = crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const put = await client.put('/api/keys/identity', { identity_signing_key: identity.toString('base64'), identity_dh_key: dh.toString('base64') });
    assert.strictEqual(put.status, 200, JSON.stringify(put.body));
    const head = await waitUntil(async () => {
        const res = await client.get('/api/kt/head');
        return res.status === 200 && res.body && res.body.pub ? res.body : null;
    }, { timeoutMs: 30000, intervalMs: 150, what: 'голова журнала' });
    assert.strictEqual(head.pub, manifest.keys.kt, 'ключ в голове журнала = ключ в манифесте');
    assert.ok(NyxoKt.isValidLogKey(new Uint8Array(Buffer.from(manifest.keys.kt, 'base64'))));
});
