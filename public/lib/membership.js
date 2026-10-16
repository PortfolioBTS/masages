// Подписанный состав группы: форматы и проверки (docs/security/signed-membership.md).
//
// Чистые функции без хранилища и сети: сертификаты допуска (vouch), приглашения
// (invite), входа по приглашению (join) и повторного допуска (revouch) фиксированной
// длины (раздел 6.1), memkey v2 (6.2), хэш снимка состава, хэш взгляда на состав
// (6.3), ключ приглашения из секрета ссылки (6.5), порядок повторного допуска (5.5) и
// проверка сертификата клиентом (6.4) через обратные вызовы — состояние группы
// (V, removed, закреплённые ключи) этому файлу не принадлежит.
//
// Один и тот же файл исполняется в браузере (window.NyxoMembership) и на сервере
// (lib/membership-certs.js): клиент и сервер не могут разойтись в том, что считать
// допустимым сертификатом. Строгая проверка ключей и подписей Ed25519 (6.1) — общий
// модуль public/lib/ed25519-strict.js; здесь она подключается одной функцией
// strictVerify, а не переписывается.
//
// Размеры и метки домена заданы документом; менять их можно только вместе с ним.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(() => require('./ed25519-strict'));
    } else {
        root.NyxoMembership = factory(() => root.NyxoEd25519Strict);
    }
})(typeof self !== 'undefined' ? self : this, function (getStrict) {
    'use strict';

    const te = new TextEncoder();

    const MAGIC = te.encode('NYXOMC01');
    const KIND = Object.freeze({ vouch: 1, invite: 2, join: 3, revouch: 4 });
    const KIND_NAME = Object.freeze({ 1: 'vouch', 2: 'invite', 3: 'join', 4: 'revouch' });
    // Длина сертификата определяется видом: vouch и revouch — без второй подписи.
    const CERT_LENGTH = Object.freeze({ 1: 271, 2: 335, 3: 335, 4: 271 });
    const BODY_LENGTH = 207;      // всё до подписей: их покрывает подпись
    const SIG_LENGTH = 64;
    const MEMKEY_LENGTH = 16;
    const MAX_SNAP = 1024;

    // Смещения полей (6.1).
    const OFF = Object.freeze({
        kind: 8, roomId: 9, issuedMin: 13, nonce: 17, subjectId: 33, subjectSignPub: 37, subjectDhPub: 69,
        actorId: 101, actorKey: 105, ref: 137, expiresMin: 169, snapN: 173, snapHash: 175, sig: 207, sig2: 271,
    });

    // Метки домена (4, реестр). Подпись — с нулевым байтом в конце метки.
    const SIG_LABEL = te.encode('nyxo-member-cert-v1\0');
    const MEMKEY_LABEL = te.encode('nyxo-memkey-v2');
    const SNAP_LABEL = te.encode('nyxo-snap-v1');
    const VIEW_IDS_LABEL = te.encode('nyxo-view-ids-v1');
    const VIEW_KEYS_LABEL = te.encode('nyxo-view-v1');
    const INVITE_SEED_LABEL = te.encode('nyxo-invite-seed-v1');
    const REVOUCH_LABEL = te.encode('nyxo-revouch-v1');

    // Константы времени (6.4), в минутах.
    const FRESH_MIN = 30 * 24 * 60;        // принимаемый сертификат не старше 30 суток
    const SKEW_MIN = 10;                   // допуск часов подписавшего
    const SERVER_WINDOW_MIN = 10;          // окно сервера вокруг его времени
    const INVITE_MAX_MIN = 720 * 60;       // срок приглашения не больше 720 часов
    const REMOVED_KEEP_MIN = FRESH_MIN;    // запись removed живёт столько же, сколько свежесть

    // ===================== Байты =====================

    function concat(...parts) {
        let length = 0;
        for (const p of parts) length += p.length;
        const out = new Uint8Array(length);
        let pos = 0;
        for (const p of parts) { out.set(p, pos); pos += p.length; }
        return out;
    }

    function u32be(n) {
        const b = new Uint8Array(4);
        new DataView(b.buffer).setUint32(0, n >>> 0, false);
        return b;
    }

    function u16be(n) {
        const b = new Uint8Array(2);
        new DataView(b.buffer).setUint16(0, n & 0xffff, false);
        return b;
    }

    function readU32(bytes, off) { return new DataView(bytes.buffer, bytes.byteOffset + off, 4).getUint32(0, false); }
    function readU16(bytes, off) { return new DataView(bytes.buffer, bytes.byteOffset + off, 2).getUint16(0, false); }

    function bytesEqual(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    function isZero(bytes) {
        for (let i = 0; i < bytes.length; i++) if (bytes[i] !== 0) return false;
        return true;
    }

    function compareBytes(a, b) {
        const n = Math.min(a.length, b.length);
        for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
        return a.length - b.length;
    }

    function isU32(n) { return Number.isInteger(n) && n >= 0 && n <= 0xFFFFFFFF; }

    const HEX = '0123456789abcdef';
    function toHex(bytes) {
        let out = '';
        for (const b of bytes) out += HEX[b >> 4] + HEX[b & 15];
        return out;
    }
    function fromHex(hex) {
        const s = String(hex).replace(/\s+/g, '');
        if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new TypeError('hex');
        const out = new Uint8Array(s.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
        return out;
    }

    // Стандартный base64 с заполнением. Декодер строгий: принимает только каноническую
    // запись (повторное кодирование даёт ту же строку) и отвечает null на мусор — сертификаты и
    // снимки приходят от недоверенного сервера.
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    function toB64(bytes) {
        let out = '';
        let i = 0;
        for (; i + 3 <= bytes.length; i += 3) {
            const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
        }
        const rem = bytes.length - i;
        if (rem === 1) {
            const n = bytes[i] << 16;
            out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + '==';
        } else if (rem === 2) {
            const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
            out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + '=';
        }
        return out;
    }
    function fromB64(str) {
        if (typeof str !== 'string' || str.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(str)) return null;
        const pad = str.endsWith('==') ? 2 : str.endsWith('=') ? 1 : 0;
        const out = new Uint8Array((str.length / 4) * 3 - pad);
        let pos = 0;
        for (let i = 0; i < str.length; i += 4) {
            let n = 0;
            for (let j = 0; j < 4; j++) {
                const c = str[i + j];
                n = (n << 6) | (c === '=' ? 0 : B64.indexOf(c));
            }
            if (pos < out.length) out[pos++] = (n >> 16) & 255;
            if (pos < out.length) out[pos++] = (n >> 8) & 255;
            if (pos < out.length) out[pos++] = n & 255;
        }
        return toB64(out) === str ? out : null;
    }

    // Секрет ссылки: base64url без заполнения, ровно 16 байт (22 символа); регистр и символы
    // «_» «-» значимы — строка не нормализуется (6.5).
    function secretFromBase64Url(text) {
        if (typeof text !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(text)) return null;
        const std = text.replace(/-/g, '+').replace(/_/g, '/') + '==';
        const bytes = fromB64(std);
        if (!bytes || bytes.length !== 16) return null;
        // Последний символ 22-символьной записи кодирует лишь 4 значащих бита; неканоническая
        // запись (ненулевые лишние биты) дала бы другую строку для тех же байт.
        return secretToBase64Url(bytes) === text ? bytes : null;
    }
    function secretToBase64Url(bytes) {
        return toB64(bytes).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    }

    function subtleCrypto() {
        const c = typeof globalThis !== 'undefined' ? globalThis.crypto : null;
        if (!c || !c.subtle) throw new Error('Membership: нет Web Crypto');
        return c.subtle;
    }

    async function sha256(...parts) {
        return new Uint8Array(await subtleCrypto().digest('SHA-256', concat(...parts)));
    }

    // ===================== memkey, снимок, взгляд =====================

    // memkey v2 (6.2): привязан к id, чтобы клон с теми же ключами под другим id получал другой memkey.
    async function memkey(id, signPub, dhPub) {
        if (!isU32(id) || !(signPub instanceof Uint8Array) || signPub.length !== 32 || !(dhPub instanceof Uint8Array) || dhPub.length !== 32) {
            throw new TypeError('Membership: некорректные данные memkey');
        }
        return (await sha256(MEMKEY_LABEL, u32be(id), signPub, dhPub)).subarray(0, MEMKEY_LENGTH);
    }

    // Снимок: memkey по возрастанию, без повторов, не больше MAX_SNAP.
    function normalizeMemkeys(list) {
        const seen = new Set();
        const out = [];
        for (const k of list) {
            if (!(k instanceof Uint8Array) || k.length !== MEMKEY_LENGTH) throw new TypeError('Membership: memkey должен быть 16 байт');
            const key = toHex(k);
            if (seen.has(key)) continue;
            seen.add(key);
            out.push(k);
        }
        out.sort(compareBytes);
        if (out.length > MAX_SNAP) throw new RangeError('Membership: в снимке больше ' + MAX_SNAP + ' участников');
        return out;
    }

    async function snapHashOf(snap) {
        const n = snap.length / MEMKEY_LENGTH;
        return sha256(SNAP_LABEL, u16be(n), snap);
    }

    // → { snap, n, hash }
    async function buildSnap(memkeys) {
        const sorted = normalizeMemkeys(memkeys);
        const snap = concat(...sorted);
        return { snap, n: sorted.length, hash: await snapHashOf(snap) };
    }

    // Снимок принят, только если длина равна 16·snapN, он отсортирован, без повторов и хэш совпал (6.1).
    async function checkSnap(snap, snapN, snapHash) {
        if (!(snap instanceof Uint8Array) || !Number.isInteger(snapN) || snapN < 1 || snapN > MAX_SNAP) return false;
        if (snap.length !== snapN * MEMKEY_LENGTH) return false;
        for (let i = 1; i < snapN; i++) {
            if (compareBytes(snap.subarray((i - 1) * MEMKEY_LENGTH, i * MEMKEY_LENGTH), snap.subarray(i * MEMKEY_LENGTH, (i + 1) * MEMKEY_LENGTH)) >= 0) return false;
        }
        return bytesEqual(await snapHashOf(snap), snapHash);
    }

    // Множество memkey снимка (строки hex) для проверки «ключи участника входят в снимок».
    function snapSet(snap) {
        const out = new Set();
        for (let i = 0; i + MEMKEY_LENGTH <= snap.length; i += MEMKEY_LENGTH) out.add(toHex(snap.subarray(i, i + MEMKEY_LENGTH)));
        return out;
    }

    // Хэш взгляда (6.3): entries — [{ id, memkey | null }]; null — у участника нет ключей на сервере
    // (16 нулевых байт). Порядок — по возрастанию id.
    async function viewHash(entries) {
        const list = entries.slice().sort((a, b) => a.id - b.id);
        const ids = (await sha256(VIEW_IDS_LABEL, ...list.map(e => u32be(e.id)))).subarray(0, 16);
        const keys = (await sha256(VIEW_KEYS_LABEL, ...list.flatMap(e => [u32be(e.id), e.memkey || new Uint8Array(MEMKEY_LENGTH)]))).subarray(0, 16);
        return { ids, keys };
    }

    // Порядок задержки повторного допуска (5.5): SHA-256(метка ‖ u32be(X) ‖ u32be(id)). Меньше — раньше.
    async function revouchSortKey(x, id) {
        return sha256(REVOUCH_LABEL, u32be(x), u32be(id));
    }

    // Позиция (от 0) участника me в списке ids без x и a, упорядоченном по ключу revouchSortKey. rank считается по
    // списку сервера S: чужого локального V клиент не знает.
    async function revouchRank(x, a, me, ids) {
        const pool = ids.filter(id => id !== x && id !== a);
        if (!pool.includes(me)) return pool.length;
        const keyed = [];
        for (const id of pool) keyed.push({ id, key: await revouchSortKey(x, id) });
        keyed.sort((p, q) => compareBytes(p.key, q.key));
        return keyed.findIndex(item => item.id === me);
    }

    // Задержка исполнения задачи повторного допуска, минуты: min(rank, 30) × 2.
    const revouchDelayMin = (rank) => Math.min(rank, 30) * 2;

    // ===================== Ключ приглашения (6.5) =====================

    const PKCS8_ED25519_PREFIX = fromHex('302e020100300506032b657004220420');

    function base64UrlDecode(text) {
        const std = String(text).replace(/-/g, '+').replace(/_/g, '/');
        return fromB64(std + '='.repeat((4 - (std.length % 4)) % 4));
    }

    // seed = HKDF-SHA256(ikm = s, salt = 32 нулевых байта, info = метка, L = 32).
    async function inviteSeed(secret) {
        if (!(secret instanceof Uint8Array) || secret.length !== 16) throw new TypeError('Membership: секрет ссылки — 16 байт');
        const subtle = subtleCrypto();
        const key = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
        const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: INVITE_SEED_LABEL }, key, 256);
        return new Uint8Array(bits);
    }

    // Ключ приглашения: открытая часть идёт в сертификат, подписывающий ключ неизвлекаемый.
    // → { seed, invitePub, sign(message) }
    async function inviteKeyFromSecret(secret) {
        const seed = await inviteSeed(secret);
        const subtle = subtleCrypto();
        const pkcs8 = concat(PKCS8_ED25519_PREFIX, seed);
        const temp = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
        const jwk = await subtle.exportKey('jwk', temp);
        const invitePub = base64UrlDecode(jwk.x);
        if (!invitePub || invitePub.length !== 32) throw new Error('Membership: не удалось получить ключ приглашения');
        const priv = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
        return {
            seed, invitePub,
            async sign(message) { return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, priv, message)); },
        };
    }

    // ===================== Сертификаты: сборка и разбор =====================

    const ZERO32 = new Uint8Array(32);

    // fields: { kind, roomId, issuedMin, nonce, subjectId, subjectSignPub, subjectDhPub, actorId, actorKey, ref, expiresMin,
    //           snapN, snapHash } — лишние поля вида игнорируются нулями. → тело 207 байт.
    function encodeBody(fields) {
        const kind = fields.kind;
        if (!CERT_LENGTH[kind]) throw new RangeError('Membership: неизвестный вид сертификата');
        if (!isU32(fields.roomId) || !isU32(fields.issuedMin)) throw new RangeError('Membership: некорректные roomId/issuedMin');
        const nonce = fields.nonce;
        if (!(nonce instanceof Uint8Array) || nonce.length !== 16) throw new RangeError('Membership: nonce — 16 байт');
        const body = new Uint8Array(BODY_LENGTH);
        body.set(MAGIC, 0);
        body[OFF.kind] = kind;
        body.set(u32be(fields.roomId), OFF.roomId);
        body.set(u32be(fields.issuedMin), OFF.issuedMin);
        body.set(nonce, OFF.nonce);
        const put = (name, value, length) => {
            if (value === undefined || value === null) return;
            if (!(value instanceof Uint8Array) || value.length !== length) throw new RangeError('Membership: поле ' + name + ' — ' + length + ' байт');
            body.set(value, OFF[name]);
        };
        if (fields.subjectId !== undefined) body.set(u32be(fields.subjectId), OFF.subjectId);
        put('subjectSignPub', fields.subjectSignPub, 32);
        put('subjectDhPub', fields.subjectDhPub, 32);
        if (fields.actorId !== undefined) body.set(u32be(fields.actorId), OFF.actorId);
        put('actorKey', fields.actorKey, 32);
        put('ref', fields.ref, 32);
        if (fields.expiresMin !== undefined) body.set(u32be(fields.expiresMin), OFF.expiresMin);
        if (fields.snapN !== undefined) body.set(u16be(fields.snapN), OFF.snapN);
        put('snapHash', fields.snapHash, 32);
        return body;
    }

    function signingInput(body) {
        return concat(SIG_LABEL, body.subarray(0, BODY_LENGTH));
    }

    // signers: { sig(message) → 64 байта, sig2(message) → 64 байта (для invite и join) }.
    // Подписывающая сторона по видам (6.1): vouch/revouch — sig актора; invite — sig актора, sig2 ключом приглашения;
    // join — sig ключом приглашения, sig2 identity-ключом субъекта.
    async function signCert(fields, signers) {
        const body = encodeBody(fields);
        const message = signingInput(body);
        const sig = await signers.sig(message);
        const two = fields.kind === KIND.invite || fields.kind === KIND.join;
        const sig2 = two ? await signers.sig2(message) : null;
        if (!(sig instanceof Uint8Array) || sig.length !== SIG_LENGTH || (two && (!(sig2 instanceof Uint8Array) || sig2.length !== SIG_LENGTH))) {
            throw new Error('Membership: подпись должна быть 64 байта');
        }
        return concat(body, sig, ...(two ? [sig2] : []));
    }

    // Разбор с проверкой формы (без подписей): точная длина вида, magic, нули в неиспользуемых полях, snapN.
    // → { ok:true, cert } | { ok:false, reason }
    function parseCert(raw) {
        if (!(raw instanceof Uint8Array)) return { ok: false, reason: 'length' };
        // Вид читается только после проверки magic и минимальной длины: длина зависит от вида.
        if (raw.length < OFF.kind + 1) return { ok: false, reason: 'length' };
        for (let i = 0; i < MAGIC.length; i++) if (raw[i] !== MAGIC[i]) return { ok: false, reason: 'magic' };
        const kind = raw[OFF.kind];
        if (!CERT_LENGTH[kind]) return { ok: false, reason: 'kind' };
        if (raw.length !== CERT_LENGTH[kind]) return { ok: false, reason: 'length' };

        const cert = {
            kind,
            roomId: readU32(raw, OFF.roomId),
            issuedMin: readU32(raw, OFF.issuedMin),
            nonce: raw.slice(OFF.nonce, OFF.nonce + 16),
            subjectId: readU32(raw, OFF.subjectId),
            subjectSignPub: raw.slice(OFF.subjectSignPub, OFF.subjectSignPub + 32),
            subjectDhPub: raw.slice(OFF.subjectDhPub, OFF.subjectDhPub + 32),
            actorId: readU32(raw, OFF.actorId),
            actorKey: raw.slice(OFF.actorKey, OFF.actorKey + 32),
            ref: raw.slice(OFF.ref, OFF.ref + 32),
            expiresMin: readU32(raw, OFF.expiresMin),
            snapN: readU16(raw, OFF.snapN),
            snapHash: raw.slice(OFF.snapHash, OFF.snapHash + 32),
            sig: raw.slice(OFF.sig, OFF.sig + SIG_LENGTH),
            sig2: raw.length > OFF.sig2 ? raw.slice(OFF.sig2, OFF.sig2 + SIG_LENGTH) : null,
            raw: raw.slice(),
        };

        // Неиспользуемые поля — нули (М11): иначе в сертификат под подписью можно протащить произвольные байты.
        const unusedOk = (() => {
            switch (kind) {
                case KIND.vouch:
                    return cert.subjectId !== 0 && cert.actorId !== 0 && isZero(cert.ref) && cert.expiresMin === 0;
                case KIND.invite:
                    return cert.subjectId === 0 && isZero(cert.subjectSignPub) && isZero(cert.subjectDhPub)
                        && cert.actorId !== 0 && !isZero(cert.ref) && cert.expiresMin !== 0;
                case KIND.join:
                    return cert.subjectId !== 0 && cert.actorId === 0 && !isZero(cert.actorKey) && !isZero(cert.ref)
                        && cert.expiresMin === 0 && cert.snapN === 0 && isZero(cert.snapHash);
                case KIND.revouch:
                    return cert.subjectId !== 0 && cert.actorId !== 0 && !isZero(cert.ref) && cert.expiresMin === 0
                        && cert.snapN === 0 && isZero(cert.snapHash);
                default:
                    return false;
            }
        })();
        if (!unusedOk) return { ok: false, reason: 'unused-fields' };
        // vouch и invite несут снимок: 1 ≤ snapN ≤ 1024 и ненулевой хэш; остальные виды проверены выше.
        if (kind === KIND.vouch || kind === KIND.invite) {
            if (cert.snapN < 1 || cert.snapN > MAX_SNAP) return { ok: false, reason: 'snap-n' };
            if (isZero(cert.snapHash)) return { ok: false, reason: 'unused-fields' };
        }
        if (kind !== KIND.invite && kind !== KIND.join && isZero(cert.actorKey)) return { ok: false, reason: 'unused-fields' };
        if ((kind === KIND.vouch || kind === KIND.revouch) && (isZero(cert.subjectSignPub) || isZero(cert.subjectDhPub))) {
            return { ok: false, reason: 'unused-fields' };
        }
        if (kind === KIND.join && (isZero(cert.subjectSignPub) || isZero(cert.subjectDhPub))) return { ok: false, reason: 'unused-fields' };
        if (kind === KIND.invite && isZero(cert.actorKey)) return { ok: false, reason: 'unused-fields' };
        return { ok: true, cert };
    }

    async function certHash(raw) {
        return sha256(raw);
    }

    // ===================== Строгая проверка подписей =====================

    // Единственная точка, где подключается строгий Ed25519 (6.1): проверка ключа (y < p, x = 0 при бите знака 1,
    // [8]P ≠ O), точки R и S < L выполняется ДО платформенного verify.
    async function strictVerify(pub, message, sig) {
        const strict = getStrict();
        if (!strict || typeof strict.verify !== 'function') throw new Error('Membership: не подключён модуль строгой проверки Ed25519');
        return strict.verify(pub, message, sig);
    }

    function isStrictKey(pub) {
        const strict = getStrict();
        if (!strict || typeof strict.isStrictKey !== 'function') throw new Error('Membership: не подключён модуль строгой проверки Ed25519');
        return strict.isStrictKey(pub);
    }

    // Подписи сертификата по ролям ключей (6.1). → { ok:true } | { ok:false, reason }
    async function verifyCertSignatures(cert) {
        const message = signingInput(cert.raw);
        switch (cert.kind) {
            case KIND.vouch:
            case KIND.revouch:
                if (!isStrictKey(cert.subjectSignPub)) return { ok: false, reason: 'key-strict' };
                if (!isStrictKey(cert.actorKey)) return { ok: false, reason: 'key-strict' };
                return (await strictVerify(cert.actorKey, message, cert.sig)) ? { ok: true } : { ok: false, reason: 'sig' };
            case KIND.invite:
                if (!isStrictKey(cert.actorKey) || !isStrictKey(cert.ref)) return { ok: false, reason: 'key-strict' };
                if (!(await strictVerify(cert.actorKey, message, cert.sig))) return { ok: false, reason: 'sig' };
                return (await strictVerify(cert.ref, message, cert.sig2)) ? { ok: true } : { ok: false, reason: 'sig2' };
            case KIND.join:
                if (!isStrictKey(cert.actorKey) || !isStrictKey(cert.subjectSignPub)) return { ok: false, reason: 'key-strict' };
                if (!(await strictVerify(cert.actorKey, message, cert.sig))) return { ok: false, reason: 'sig' };
                return (await strictVerify(cert.subjectSignPub, message, cert.sig2)) ? { ok: true } : { ok: false, reason: 'sig2' };
            default:
                return { ok: false, reason: 'kind' };
        }
    }

    // ===================== Проверка сертификата клиентом (6.4) =====================

    // Общие условия (кроме подписей): комната, свежесть, часы, отзыв по субъекту.
    //   opts.skipFresh — для вложенного приглашения I в join: нижняя граница свежести не применяется;
    //   removedAt(id) → минута выхода | undefined.
    function checkGeneral(cert, ctx, opts = {}) {
        if (cert.roomId !== ctx.roomId) return { ok: false, reason: 'room' };
        if (cert.issuedMin > ctx.nowMin + SKEW_MIN) return { ok: false, reason: 'time-future' };
        if (!opts.skipFresh && cert.issuedMin < ctx.nowMin - FRESH_MIN) return { ok: false, reason: 'time-stale' };
        // Отзыв по субъекту (М3): сертификат субъекта или подписанный им, выданный не позже его выхода, отвергается.
        const removedAt = typeof ctx.removedAt === 'function' ? ctx.removedAt : () => undefined;
        for (const [id, reason] of [[cert.subjectId, 'removed-subject'], [cert.actorId, 'removed-actor']]) {
            if (!id) continue;
            const m = removedAt(id);
            if (m !== undefined && cert.issuedMin <= m) return { ok: false, reason };
        }
        return { ok: true };
    }

    // Пункты проверки invite (6.4): 1) приглашающий (ctx.actorOk — обычная или якорная проверка),
    // 2) sig2 по ref — в verifyCertSignatures, 3) срок. → { ok } | { ok:false, reason }
    function checkInviteRules(cert, ctx) {
        if (cert.expiresMin <= cert.issuedMin || cert.expiresMin - cert.issuedMin > INVITE_MAX_MIN) return { ok: false, reason: 'invite-term' };
        return { ok: true };
    }

    // Полная проверка одного сертификата.
    //   raw — байты; ctx:
    //     roomId, nowMin;
    //     removedAt(id)                       — запись removed;
    //     actorOk(actorId, actorKey, kind)    — подписавший ∈ V, в списке, ключ равен закреплённому, нет changed и log-mismatch
    //                                           (для invite новичка — якорный вариант); → { ok, reason? };
    //     subjectKeysOk(subjectId, signPub, dhPub) — п. 4–5 (ключи субъекта = закреплённым/серверным; для себя — собственным);
    //     expectSubject                       — необязательный id, которому выдан сертификат;
    //     invite(raw)                         — для join: приглашение I (aux или rooms.invite_cert), в виде байт | null;
    //     inviteRef                           — необязательный ожидаемый ref (joinIntent.inviteHash) для join.
    //   → { ok:true, cert, hash, invite? } | { ok:false, reason }
    async function validateCert(raw, ctx) {
        const parsed = parseCert(raw);
        if (!parsed.ok) return parsed;
        const cert = parsed.cert;
        const general = checkGeneral(cert, ctx);
        if (!general.ok) return general;
        if (ctx.expectSubject !== undefined && ctx.expectSubject !== null && cert.kind !== KIND.invite && cert.subjectId !== ctx.expectSubject) {
            return { ok: false, reason: 'subject' };
        }
        const sigs = await verifyCertSignatures(cert);
        if (!sigs.ok) return sigs;

        const hash = await certHash(cert.raw);
        if (cert.kind === KIND.vouch || cert.kind === KIND.revouch) {
            const actor = ctx.actorOk(cert.actorId, cert.actorKey, cert.kind);
            if (!actor.ok) return { ok: false, reason: actor.reason || 'actor' };
            const subject = ctx.subjectKeysOk(cert.subjectId, cert.subjectSignPub, cert.subjectDhPub);
            if (!subject.ok) return { ok: false, reason: subject.reason || 'subject-keys' };
            return { ok: true, cert, hash };
        }
        if (cert.kind === KIND.invite) {
            const terms = checkInviteRules(cert, ctx);
            if (!terms.ok) return terms;
            const actor = ctx.actorOk(cert.actorId, cert.actorKey, cert.kind);
            if (!actor.ok) return { ok: false, reason: actor.reason || 'actor' };
            return { ok: true, cert, hash };
        }
        // join
        const subject = ctx.subjectKeysOk(cert.subjectId, cert.subjectSignPub, cert.subjectDhPub);
        if (!subject.ok) return { ok: false, reason: subject.reason || 'subject-keys' };
        const inviteRaw = typeof ctx.invite === 'function' ? ctx.invite(cert) : ctx.invite;
        if (!(inviteRaw instanceof Uint8Array)) return { ok: false, reason: 'invite-missing' };
        const inviteHash = await certHash(inviteRaw);
        if (!bytesEqual(inviteHash, cert.ref)) return { ok: false, reason: 'invite-ref' };
        if (ctx.inviteRef && !bytesEqual(ctx.inviteRef, cert.ref)) return { ok: false, reason: 'invite-ref' };
        const parsedInvite = parseCert(inviteRaw);
        if (!parsedInvite.ok || parsedInvite.cert.kind !== KIND.invite) return { ok: false, reason: 'invite' };
        const inv = parsedInvite.cert;
        // Вложенное приглашение: все общие условия, кроме нижней границы свежести, плюс пп. 1–3 проверки invite.
        const invGeneral = checkGeneral(inv, ctx, { skipFresh: true });
        if (!invGeneral.ok) return { ok: false, reason: 'invite-' + invGeneral.reason };
        const invSigs = await verifyCertSignatures(inv);
        if (!invSigs.ok) return { ok: false, reason: 'invite-' + invSigs.reason };
        const invTerms = checkInviteRules(inv, ctx);
        if (!invTerms.ok) return { ok: false, reason: invTerms.reason };
        const invActor = ctx.actorOk(inv.actorId, inv.actorKey, KIND.invite);
        if (!invActor.ok) return { ok: false, reason: 'invite-' + (invActor.reason || 'actor') };
        // actorKey в join равен ref приглашения (invitePub); sig проверена этим ключом (verifyCertSignatures).
        if (!bytesEqual(cert.actorKey, inv.ref)) return { ok: false, reason: 'invite-key' };
        // issuedMin(join) ∈ [I.issuedMin − SKEW; I.expiresMin + SKEW].
        if (cert.issuedMin < inv.issuedMin - SKEW_MIN || cert.issuedMin > inv.expiresMin + SKEW_MIN) return { ok: false, reason: 'join-time' };
        return { ok: true, cert, hash, invite: inv, inviteHash };
    }

    // Минута Unix-эпохи (для issuedMin и removed).
    const minuteOf = (ms) => Math.floor(ms / 60000);

    return Object.freeze({
        MAGIC, KIND, KIND_NAME, CERT_LENGTH, BODY_LENGTH, SIG_LENGTH, MEMKEY_LENGTH, MAX_SNAP, OFF,
        FRESH_MIN, SKEW_MIN, SERVER_WINDOW_MIN, INVITE_MAX_MIN, REMOVED_KEEP_MIN,
        concat, u32be, u16be, bytesEqual, isZero, compareBytes, toHex, fromHex, toB64, fromB64,
        secretFromBase64Url, secretToBase64Url, sha256, minuteOf,
        memkey, normalizeMemkeys, snapHashOf, buildSnap, checkSnap, snapSet, viewHash,
        revouchSortKey, revouchRank, revouchDelayMin,
        inviteSeed, inviteKeyFromSecret,
        encodeBody, signingInput, signCert, parseCert, certHash,
        strictVerify, isStrictKey, verifyCertSignatures,
        checkGeneral, validateCert,
    });
});
