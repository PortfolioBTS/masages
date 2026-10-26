'use strict';
// Проверки сертификатов состава на сервере (lib/membership-certs.js, signed-membership.md, 7.2) и маршруты
// lib/e2ee-groups.js: участники с сертификатами самого запрашивающего, GET/POST member-certs в транзакции
// (против лёгкой имитации БД: порядок блокировок, 404 для вышедших, потолок допусков, дубли).
// Запуск: node test/membership-certs.test.js

const assert = require('assert');
const crypto = require('crypto');
const M = require('../public/lib/membership.js');
const C = require('../lib/membership-certs.js');
const { registerE2eeGroupRoutes } = require('../lib/e2ee-groups.js');

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

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function makeIdentity(id, seedByte, dhByte) {
    const seed = Buffer.alloc(32, seedByte);
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: 'der', type: 'pkcs8' });
    const signPub = new Uint8Array(crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32));
    const dhPub = new Uint8Array(32).fill(dhByte);
    return {
        id, signPub, dhPub,
        sign: async (m) => new Uint8Array(crypto.sign(null, m, privateKey)),
        row: { identity_signing_key: Buffer.from(signPub), identity_dh_key: Buffer.from(dhPub) },
    };
}
const A = makeIdentity(11, 0xa1, 0xa2);
const J = makeIdentity(22, 0xb1, 0xb2);
const X = makeIdentity(33, 0xc1, 0xc2);
const ROOM = 5000;
const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const nowMin = Math.floor(NOW / 60000);
const nonce = (b) => new Uint8Array(16).fill(b);

async function mySnap() {
    return M.buildSnap([await M.memkey(A.id, A.signPub, A.dhPub)]);
}

async function vouch({ actor = A, subject = J, issuedMin = nowMin, room = ROOM, snapOverride } = {}) {
    const snap = snapOverride || await mySnap();
    const raw = await M.signCert({
        kind: M.KIND.vouch, roomId: room, issuedMin, nonce: nonce(1), subjectId: subject.id, subjectSignPub: subject.signPub,
        subjectDhPub: subject.dhPub, actorId: actor.id, actorKey: actor.signPub, snapN: snap.n, snapHash: snap.hash,
    }, { sig: actor.sign });
    return { raw, certB64: M.toB64(raw), snapB64: M.toB64(snap.snap) };
}

const inviteSecret = new Uint8Array(16).map((_, i) => i + 1);
async function invite({ issuedMin = nowMin, expiresMin = nowMin + 10080, actor = A } = {}) {
    const key = await M.inviteKeyFromSecret(inviteSecret);
    const snap = await mySnap();
    const raw = await M.signCert({
        kind: M.KIND.invite, roomId: ROOM, issuedMin, nonce: nonce(2), actorId: actor.id, actorKey: actor.signPub,
        ref: key.invitePub, expiresMin, snapN: snap.n, snapHash: snap.hash,
    }, { sig: actor.sign, sig2: key.sign });
    return { raw, key, certB64: M.toB64(raw), snapB64: M.toB64(snap.snap) };
}

async function join({ inv, subject = J, issuedMin = nowMin, room = ROOM } = {}) {
    const raw = await M.signCert({
        kind: M.KIND.join, roomId: room, issuedMin, nonce: nonce(3), subjectId: subject.id, subjectSignPub: subject.signPub,
        subjectDhPub: subject.dhPub, actorId: 0, actorKey: inv.key.invitePub, ref: await M.certHash(inv.raw),
    }, { sig: inv.key.sign, sig2: subject.sign });
    return raw;
}

async function main() {
    // ===================== Допуск =====================

    await test('verifyVouch: верный допуск проходит; возвращает разобранный сертификат, снимок и хэш', async () => {
        const v = await vouch();
        const r = await C.verifyVouch({ ...v, allowedKinds: [1], roomId: ROOM, actorId: A.id, subjectId: J.id, actorKeys: A.row, subjectKeys: J.row, now: NOW });
        assert.strictEqual(r.ok, true);
        assert.strictEqual(r.cert.kind, 1);
        assert.strictEqual(r.snap.length, 16);
        assert.strictEqual(M.toHex(r.hash), M.toHex(await M.certHash(v.raw)));
    });

    await test('verifyVouch: нет сертификата - cert-required, нет снимка - snap-required', async () => {
        const v = await vouch();
        const base = { allowedKinds: [1], roomId: ROOM, actorId: A.id, subjectId: J.id, actorKeys: A.row, subjectKeys: J.row, now: NOW };
        for (const certB64 of [undefined, null, '']) {
            const r = await C.verifyVouch({ ...base, certB64, snapB64: v.snapB64 });
            assert.deepStrictEqual([r.ok, r.status, r.code], [false, 400, 'cert-required']);
        }
        for (const snapB64 of [undefined, null, '']) {
            const r = await C.verifyVouch({ ...base, certB64: v.certB64, snapB64 });
            assert.deepStrictEqual([r.ok, r.status, r.code], [false, 400, 'snap-required']);
        }
    });

    await test('verifyVouch: сертификат не от сессии, не для заявителя, с чужими ключами, чужой комнаты, не того вида - bad-cert', async () => {
        const base = { allowedKinds: [1], roomId: ROOM, actorId: A.id, subjectId: J.id, actorKeys: A.row, subjectKeys: J.row, now: NOW };
        const v = await vouch();
        const bad = async (patch, vv = v) => {
            const r = await C.verifyVouch({ ...base, ...vv, ...patch });
            assert.deepStrictEqual([r.ok, r.status, r.code], [false, 400, 'bad-cert'], JSON.stringify(Object.keys(patch)));
        };
        await bad({ actorId: X.id });                              // подписан не сессией
        await bad({ subjectId: X.id });                            // выдан не заявителю
        await bad({ roomId: ROOM + 1 });                           // комната запроса другая
        await bad({ actorKeys: X.row });                           // ключ подписавшего не из key-store
        await bad({ subjectKeys: X.row });                         // ключи заявителя не совпали
        await bad({ allowedKinds: [4] });                          // вид не разрешён маршруту
        await bad({}, await vouch({ room: ROOM + 7 }));            // сертификат другой комнаты
        const forged = M.fromB64(v.certB64); forged[100] ^= 1;     // подпись не сходится
        await bad({ certB64: M.toB64(forged) });
        await bad({ certB64: 'не base64' });
        await bad({ certB64: M.toB64(M.fromB64(v.certB64).subarray(0, 270)) });
        // Снимок не тот: другой хэш.
        const other = await M.buildSnap([await M.memkey(X.id, X.signPub, X.dhPub)]);
        await bad({ snapB64: M.toB64(other.snap) });
        await bad({ snapB64: 'AAAA' });
    });

    await test('verifyVouch: issuedMin вне окна сервера +-10 минут - bad-cert-time; на границах принимается', async () => {
        const base = { allowedKinds: [1], roomId: ROOM, actorId: A.id, subjectId: J.id, actorKeys: A.row, subjectKeys: J.row, now: NOW };
        for (const delta of [-10, 0, 10]) {
            const r = await C.verifyVouch({ ...base, ...(await vouch({ issuedMin: nowMin + delta })) });
            assert.strictEqual(r.ok, true, 'delta ' + delta);
        }
        for (const delta of [-11, 11, -60 * 24]) {
            const r = await C.verifyVouch({ ...base, ...(await vouch({ issuedMin: nowMin + delta })) });
            assert.deepStrictEqual([r.ok, r.status, r.code], [false, 400, 'bad-cert-time'], 'delta ' + delta);
        }
    });

    await test('verifyVouch: повторный допуск (kind 4) без снимка; снимок у него - отказ; ключ малого порядка у субъекта - отказ', async () => {
        const vouchRaw = (await vouch()).raw;
        const raw = await M.signCert({
            kind: M.KIND.revouch, roomId: ROOM, issuedMin: nowMin, nonce: nonce(4), subjectId: J.id, subjectSignPub: J.signPub,
            subjectDhPub: J.dhPub, actorId: A.id, actorKey: A.signPub, ref: await M.certHash(vouchRaw),
        }, { sig: A.sign });
        const base = { allowedKinds: [1, 4], roomId: ROOM, actorId: A.id, subjectId: J.id, actorKeys: A.row, subjectKeys: J.row, now: NOW };
        const ok = await C.verifyVouch({ ...base, certB64: M.toB64(raw) });
        assert.strictEqual(ok.ok, true);
        assert.strictEqual(ok.snap, null);
        const withSnap = await C.verifyVouch({ ...base, certB64: M.toB64(raw), snapB64: (await vouch()).snapB64 });
        assert.strictEqual(withSnap.code, 'bad-cert');
        const lowOrder = await M.signCert({
            kind: M.KIND.vouch, roomId: ROOM, issuedMin: nowMin, nonce: nonce(5), subjectId: J.id,
            subjectSignPub: M.fromHex('0100000000000000000000000000000000000000000000000000000000000000'), subjectDhPub: J.dhPub,
            actorId: A.id, actorKey: A.signPub, snapN: 1, snapHash: (await mySnap()).hash,
        }, { sig: A.sign });
        const weak = await C.verifyVouch({ ...base, allowedKinds: [1], certB64: M.toB64(lowOrder), snapB64: (await vouch()).snapB64,
            subjectKeys: { identity_signing_key: Buffer.from(M.fromHex('0100000000000000000000000000000000000000000000000000000000000000')), identity_dh_key: Buffer.from(J.dhPub) } });
        assert.strictEqual(weak.code, 'bad-cert', 'ключ малого порядка не принимается даже если он записан в key-store');
    });

    // ===================== Приглашение =====================

    await test('verifyInvite: срок сверяется по ДЛИТЕЛЬНОСТИ (+-1 минута), а не по абсолютному времени; часы клиента +-9 минут допустимы', async () => {
        const base = { roomId: ROOM, actorId: A.id, actorKeys: A.row, ttlSeconds: 7 * 86400, now: NOW };
        for (const shift of [-9, -3, 0, 3, 9]) {
            const inv = await invite({ issuedMin: nowMin + shift, expiresMin: nowMin + shift + 10080 });
            assert.strictEqual((await C.verifyInvite({ ...base, ...inv })).ok, true, 'сдвиг ' + shift);
        }
        for (const dur of [10080 - 1, 10080 + 1]) {
            const inv = await invite({ expiresMin: nowMin + dur });
            assert.strictEqual((await C.verifyInvite({ ...base, ...inv })).ok, true, 'длительность ' + dur);
        }
        for (const dur of [10080 - 2, 10080 + 2]) {
            const inv = await invite({ expiresMin: nowMin + dur });
            const r = await C.verifyInvite({ ...base, ...inv });
            assert.deepStrictEqual([r.ok, r.code], [false, 'bad-cert'], 'длительность ' + dur);
        }
        const far = await invite({ issuedMin: nowMin + 11, expiresMin: nowMin + 11 + 10080 });
        assert.strictEqual((await C.verifyInvite({ ...base, ...far })).code, 'bad-cert-time');
    });

    await test('verifyInvite: срок больше 720 часов, чужой автор, чужие ключи, нет снимка - отказ', async () => {
        const base = { roomId: ROOM, actorId: A.id, actorKeys: A.row, ttlSeconds: 720 * 3600, now: NOW };
        const max = await invite({ expiresMin: nowMin + 43200 });
        assert.strictEqual((await C.verifyInvite({ ...base, ...max })).ok, true, '720 часов - можно');
        const over = await invite({ expiresMin: nowMin + 43201 });
        assert.strictEqual((await C.verifyInvite({ ...base, ...over, ttlSeconds: 43201 * 60 })).code, 'bad-cert');
        const inv = await invite({ expiresMin: nowMin + 43200 });
        assert.strictEqual((await C.verifyInvite({ ...base, ...inv, actorId: X.id })).code, 'bad-cert');
        assert.strictEqual((await C.verifyInvite({ ...base, ...inv, actorKeys: X.row })).code, 'bad-cert');
        assert.strictEqual((await C.verifyInvite({ ...base, ...inv, snapB64: undefined })).code, 'snap-required');
        assert.strictEqual((await C.verifyInvite({ ...base, ...inv, certB64: undefined })).code, 'cert-required');
        assert.strictEqual((await C.verifyInvite({ ...base, ...inv, roomId: ROOM + 1 })).code, 'bad-cert');
        // Допуск вместо приглашения.
        assert.strictEqual((await C.verifyInvite({ ...base, ...(await vouch()) })).code, 'bad-cert');
    });

    // ===================== Вход =====================

    await test('verifyJoin: верный вход проходит; границы I.issuedMin - 10 и I.expiresMin + 10 принимаются, за ними - bad-cert-time', async () => {
        const inv = await invite();
        const check = async (issuedMin, nowOverride = issuedMin * 60000) => C.verifyJoin({
            joinRaw: await join({ inv, issuedMin }), inviteRaw: inv.raw, roomId: ROOM, userId: J.id, userKeys: J.row, now: nowOverride,
        });
        assert.strictEqual((await check(nowMin)).ok, true);
        assert.strictEqual((await check(nowMin - 10)).ok, true, 'нижняя граница I.issuedMin - SKEW');
        const below = await check(nowMin - 11);
        assert.deepStrictEqual([below.ok, below.code], [false, 'bad-cert-time']);
        const expires = nowMin + 10080;
        assert.strictEqual((await check(expires + 10)).ok, true, 'верхняя граница I.expiresMin + SKEW');
        assert.strictEqual((await check(expires + 11)).code, 'bad-cert-time');
        // Окно сервера: сертификат из прошлого относительно времени сервера.
        const stale = await C.verifyJoin({ joinRaw: await join({ inv }), inviteRaw: inv.raw, roomId: ROOM, userId: J.id, userKeys: J.row, now: NOW + 11 * 60000 });
        assert.strictEqual(stale.code, 'bad-cert-time');
    });

    await test('verifyJoin: чужой субъект, чужие ключи, чужое приглашение (ref), чужая комната, ключ приглашения не из I - bad-cert', async () => {
        const inv = await invite();
        const raw = await join({ inv });
        const base = { joinRaw: raw, inviteRaw: inv.raw, roomId: ROOM, userId: J.id, userKeys: J.row, now: NOW };
        assert.strictEqual((await C.verifyJoin(base)).ok, true);
        assert.strictEqual((await C.verifyJoin({ ...base, userId: X.id })).code, 'bad-cert');
        assert.strictEqual((await C.verifyJoin({ ...base, userKeys: X.row })).code, 'bad-cert');
        assert.strictEqual((await C.verifyJoin({ ...base, roomId: ROOM + 1 })).code, 'bad-cert');
        const otherInvite = await invite({ expiresMin: nowMin + 100 });
        assert.strictEqual((await C.verifyJoin({ ...base, inviteRaw: otherInvite.raw })).code, 'bad-cert', 'ref - хэш другого приглашения');
        assert.strictEqual((await C.verifyJoin({ ...base, inviteRaw: null })).code, 'bad-cert', 'приглашение отозвано');
        // Вход, подписанный не ключом приглашения: sig2 субъекта на месте, но sig чужой.
        const wrongKey = await M.inviteKeyFromSecret(new Uint8Array(16).fill(9));
        const forged = await M.signCert({
            kind: M.KIND.join, roomId: ROOM, issuedMin: nowMin, nonce: nonce(3), subjectId: J.id, subjectSignPub: J.signPub,
            subjectDhPub: J.dhPub, actorId: 0, actorKey: wrongKey.invitePub, ref: await M.certHash(inv.raw),
        }, { sig: wrongKey.sign, sig2: J.sign });
        assert.strictEqual((await C.verifyJoin({ ...base, joinRaw: forged })).code, 'bad-cert', 'не тот ключ приглашения - тот, что в I, не подписывал');
        // Приглашение вместо входа.
        assert.strictEqual((await C.verifyJoin({ ...base, joinRaw: inv.raw })).code, 'bad-cert');
    });

    await test('parseSubjects: до 200 id, без повторов; мусор, ноль, больше 200 - null', () => {
        assert.deepStrictEqual(C.parseSubjects('1,2,3,2'), [1, 2, 3]);
        const ids200 = Array.from({ length: 200 }, (_, i) => i + 1).join(',');
        assert.strictEqual(C.parseSubjects(ids200).length, 200);
        assert.strictEqual(C.parseSubjects(ids200 + ',201'), null);
        for (const bad of [undefined, '', '0', '-1', '1,,2', '1,a', ' 1', '99999999999', '2147483648', ['1']]) assert.strictEqual(C.parseSubjects(bad), null, JSON.stringify(bad));
        assert.deepStrictEqual(C.parseSubjects('2147483647'), [2147483647]);
    });

    // ===================== Маршруты lib/e2ee-groups.js =====================

    function makeFakeApp() {
        const routes = [];
        const app = {};
        for (const method of ['get', 'post', 'put', 'delete']) app[method] = (path, ...handlers) => { routes.push({ method, path, handlers }); };
        app._find = (method, path) => routes.find(r => r.method === method && r.path === path);
        return app;
    }
    async function call(app, method, path, { session, params, query, body } = {}) {
        const route = app._find(method, path);
        assert.ok(route, 'route not registered: ' + method + ' ' + path);
        const res = {
            statusCode: 200, body: null, headers: {},
            status(code) { this.statusCode = code; return this; },
            json(payload) { this.body = payload; return this; },
            set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
        };
        const req = { session: session || null, params: params || {}, query: query || {}, body: body || {} };
        for (const h of route.handlers) {
            if (res.body !== null) break;
            await h(req, res, () => {});
        }
        return res;
    }

    // Имитация БД: комнаты, участники, ключи, сертификаты; журнал порядка блокировок.
    function makeDb() {
        const state = { chats: [], participants: [], identities: new Map(), certs: [], rooms: new Map(), locks: [], users: new Set() };
        const rows = (list) => ({ rows: list, rowCount: list.length });
        async function run(sql, params, log) {
            if (sql.includes('FROM chats WHERE id')) {
                return state.chats.filter(c => c.id === Number(params[0]) && c.user_id === Number(params[1]));
            }
            if (sql.includes('FROM users u JOIN room_participants')) {
                return state.participants.filter(p => p.room_id === params[0]).map(p => ({ id: p.user_id, username: 'u' + p.user_id }));
            }
            if (sql.includes('count(*)::int AS n FROM room_member_certs')) {
                log.push('room_member_certs');
                return [{ n: state.certs.filter(c => c.room_id === params[0] && c.subject_id === params[1] && [1, 4].includes(c.kind)).length }];
            }
            if (sql.includes('FROM room_member_certs') && sql.includes('subject_id = ANY')) {
                return state.certs.filter(c => c.room_id === params[0] && params[1].includes(c.subject_id));
            }
            if (sql.includes('FROM room_member_certs') && sql.includes('subject_id = $2')) {
                return state.certs.filter(c => c.room_id === params[0] && c.subject_id === Number(params[1]));
            }
            if (sql.includes('SELECT invite_cert FROM rooms')) return [{ invite_cert: (state.rooms.get(params[0]) || {}).invite_cert || null }];
            if (sql.includes('FROM identity_keys')) return state.identities.has(Number(params[0])) ? [state.identities.get(Number(params[0]))] : [];
            if (sql.startsWith('SELECT id FROM users')) { log.push('users'); return state.users.has(params[0]) ? [{ id: params[0] }] : []; }
            if (sql.includes('FROM rooms WHERE id = $1 FOR NO KEY UPDATE')) { log.push('rooms'); return state.rooms.has(params[0]) ? [{ id: params[0] }] : []; }
            if (sql.includes('FROM room_participants WHERE room_id = $1 AND user_id = ANY')) {
                log.push('room_participants');
                return state.participants.filter(p => p.room_id === params[0] && params[1].includes(p.user_id)).map(p => ({ user_id: p.user_id }));
            }
            if (sql.startsWith('INSERT INTO room_member_certs')) {
                const [room_id, subject_id, actor_id, kind, cert, snap] = params;
                if (state.certs.some(c => c.room_id === room_id && c.subject_id === subject_id && c.actor_id === actor_id && c.kind === kind)) return [];
                state.certs.push({ room_id, subject_id, actor_id, kind, cert, snap, aux: null });
                return [{}];
            }
            throw new Error('fake db: unhandled query: ' + sql.slice(0, 100));
        }
        const dbAll = async (sql, params) => run(sql, params, []);
        const dbGet = async (sql, params) => (await dbAll(sql, params))[0] || null;
        const withTransaction = async (work) => {
            const log = [];
            const result = await work({ query: async (sql, params) => { const r = await run(sql, params, log); return rows(r); } });
            state.locks.push(log);
            return result;
        };
        return { state, dbGet, dbAll, dbRun: async () => ({ rowCount: 0 }), withTransaction };
    }

    function fixture() {
        const db = makeDb();
        const emitted = [];
        const io = { to: (room) => ({ emit: (event, payload) => emitted.push({ room, event, payload }) }) };
        const app = makeFakeApp();
        registerE2eeGroupRoutes(app, { dbGet: db.dbGet, dbAll: db.dbAll, dbRun: db.dbRun, io, withTransaction: db.withTransaction });
        db.state.chats.push({ id: 101, user_id: A.id, room_id: ROOM }, { id: 102, user_id: J.id, room_id: ROOM }, { id: 103, user_id: X.id, room_id: ROOM });
        for (const id of [A.id, J.id, X.id]) {
            db.state.participants.push({ room_id: ROOM, user_id: id });
            db.state.users.add(id);
        }
        for (const who of [A, J, X]) db.state.identities.set(who.id, who.row);
        db.state.rooms.set(ROOM, { invite_cert: null });
        return { app, db, emitted };
    }

    await test('POST member-certs: допуск сохраняется в транзакции users -> rooms -> room_participants -> room_member_certs', async () => {
        const { app, db, emitted } = fixture();
        const v = await vouch({ issuedMin: Math.floor(Date.now() / 60000) });
        const res = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: J.id, cert: v.certB64, snap: v.snapB64, proto: 4 },
        });
        assert.deepStrictEqual(res.body, { success: true, stored: true });
        assert.strictEqual(db.state.certs.length, 1);
        assert.strictEqual(db.state.certs[0].kind, 1);
        assert.strictEqual(db.state.certs[0].snap.length, 16);
        assert.deepStrictEqual(db.state.locks[0], ['users', 'rooms', 'room_participants', 'room_member_certs']);
        assert.ok(emitted.some(e => e.event === 'roomMembersChanged' && e.payload.roomId === ROOM));
        // Тот же допуск повторно: дубль - stored:false.
        const again = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: J.id, cert: v.certB64, snap: v.snapB64, proto: 4 },
        });
        assert.deepStrictEqual(again.body, { success: true, stored: false });
        assert.strictEqual(db.state.certs.length, 1);
    });

    await test('POST member-certs: субъект или подписавший уже не в комнате - 404 not-participant и таблица пуста; без proto - client-outdated', async () => {
        const { app, db } = fixture();
        const nowM = Math.floor(Date.now() / 60000);
        const v = await vouch({ issuedMin: nowM });
        db.state.participants = db.state.participants.filter(p => p.user_id !== J.id);
        const gone = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: J.id, cert: v.certB64, snap: v.snapB64, proto: 4 },
        });
        assert.strictEqual(gone.statusCode, 404);
        assert.strictEqual(gone.body.code, 'not-participant');
        assert.strictEqual(db.state.certs.length, 0);
        const outdated = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: J.id, cert: v.certB64, snap: v.snapB64 },
        });
        assert.strictEqual(outdated.statusCode, 400);
        assert.strictEqual(outdated.body.code, 'client-outdated');
        // Подписавший вышел между проверкой подписи и вставкой: у него нет записи участника.
        db.state.participants.push({ room_id: ROOM, user_id: J.id });
        db.state.participants = db.state.participants.filter(p => p.user_id !== A.id);
        const actorGone = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: J.id, cert: v.certB64, snap: v.snapB64, proto: 4 },
        });
        assert.strictEqual(actorGone.statusCode, 404);
        assert.strictEqual(db.state.certs.length, 0);
    });

    await test('POST member-certs: не больше 4 допусков (vouch и revouch вместе) на субъекта - пятый stored:false', async () => {
        const { app, db } = fixture();
        const nowM = Math.floor(Date.now() / 60000);
        for (let i = 0; i < 4; i++) {
            db.state.certs.push({ room_id: ROOM, subject_id: J.id, actor_id: 1000 + i, kind: i % 2 ? 4 : 1, cert: Buffer.alloc(271), snap: null, aux: null });
        }
        const v = await vouch({ issuedMin: nowM });
        const res = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: J.id, cert: v.certB64, snap: v.snapB64, proto: 4 },
        });
        assert.deepStrictEqual(res.body, { success: true, stored: false });
        assert.strictEqual(db.state.certs.length, 4);
    });

    await test('POST member-certs: допуск от имени другого и самому себе отвергаются; мусорный subjectId - 400', async () => {
        const { app } = fixture();
        const v = await vouch({ issuedMin: Math.floor(Date.now() / 60000) });
        const asJ = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: J.id }, params: { chatId: '102' }, body: { subjectId: X.id, cert: v.certB64, snap: v.snapB64, proto: 4 },
        });
        assert.strictEqual(asJ.body.code, 'bad-cert', 'сертификат подписан A, а запрос от J');
        const self = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: A.id, cert: v.certB64, snap: v.snapB64, proto: 4 },
        });
        assert.strictEqual(self.statusCode, 400);
        const junk = await call(app, 'post', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, body: { subjectId: 'x', cert: v.certB64, proto: 4 },
        });
        assert.strictEqual(junk.statusCode, 400);
    });

    await test('GET member-certs: только перечисленные субъекты своей комнаты, не больше 200 id; без снимков', async () => {
        const { app, db } = fixture();
        db.state.certs.push(
            { room_id: ROOM, subject_id: J.id, actor_id: A.id, kind: 1, cert: Buffer.alloc(271, 1), snap: Buffer.alloc(16), aux: null },
            { room_id: ROOM, subject_id: X.id, actor_id: 0, kind: 3, cert: Buffer.alloc(335, 2), snap: null, aux: Buffer.alloc(335, 3) },
            { room_id: ROOM + 1, subject_id: J.id, actor_id: A.id, kind: 1, cert: Buffer.alloc(271, 9), snap: null, aux: null },
        );
        const res = await call(app, 'get', '/api/chats/:chatId/member-certs', { session: { userId: A.id }, params: { chatId: '101' }, query: { subjects: String(J.id) } });
        assert.strictEqual(res.body.success, true);
        assert.strictEqual(res.body.certs.length, 1);
        assert.deepStrictEqual(Object.keys(res.body.certs[0]).sort(), ['actorId', 'cert', 'kind', 'subjectId']);
        const both = await call(app, 'get', '/api/chats/:chatId/member-certs', { session: { userId: A.id }, params: { chatId: '101' }, query: { subjects: `${J.id},${X.id}` } });
        assert.strictEqual(both.body.certs.length, 2);
        assert.ok(both.body.certs.find(c => c.kind === 3).aux, 'у join есть копия приглашения');
        const many = await call(app, 'get', '/api/chats/:chatId/member-certs', {
            session: { userId: A.id }, params: { chatId: '101' }, query: { subjects: Array.from({ length: 201 }, (_, i) => i + 1).join(',') },
        });
        assert.strictEqual(many.statusCode, 400);
        const stranger = await call(app, 'get', '/api/chats/:chatId/member-certs', { session: { userId: 999 }, params: { chatId: '101' }, query: { subjects: '1' } });
        assert.strictEqual(stranger.body.success, false, 'чужой чат');
    });

    await test('GET participants: сертификаты только самого запрашивающего, снимки к ним и приглашение комнаты', async () => {
        const { app, db } = fixture();
        db.state.certs.push(
            { room_id: ROOM, subject_id: J.id, actor_id: A.id, kind: 1, cert: Buffer.alloc(271, 1), snap: Buffer.alloc(32, 7), aux: null },
            { room_id: ROOM, subject_id: X.id, actor_id: A.id, kind: 1, cert: Buffer.alloc(271, 2), snap: Buffer.alloc(16, 8), aux: null },
        );
        db.state.rooms.set(ROOM, { invite_cert: Buffer.alloc(335, 5) });
        const res = await call(app, 'get', '/api/chats/:chatId/participants', { session: { userId: J.id }, params: { chatId: '102' } });
        assert.strictEqual(res.body.success, true);
        assert.strictEqual(res.body.certs.length, 1);
        assert.strictEqual(res.body.certs[0].subjectId, J.id, 'сертификаты других участников здесь не отдаются');
        assert.strictEqual(res.body.snaps.length, 1);
        assert.deepStrictEqual([res.body.snaps[0].actorId, res.body.snaps[0].kind], [A.id, 1]);
        assert.strictEqual(M.fromB64(res.body.snaps[0].snap).length, 32);
        assert.strictEqual(M.fromB64(res.body.invite).length, 335);
        const none = await call(app, 'get', '/api/chats/:chatId/participants', { session: { userId: X.id }, params: { chatId: '103' } });
        assert.strictEqual(none.body.certs.length, 1);
        db.state.rooms.set(ROOM, { invite_cert: null });
        const noInvite = await call(app, 'get', '/api/chats/:chatId/participants', { session: { userId: X.id }, params: { chatId: '103' } });
        assert.strictEqual(noInvite.body.invite, null);
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error(err); process.exitCode = 1; });
