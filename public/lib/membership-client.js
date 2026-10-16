// Клиент подписанного состава группы: состояние на устройстве, проверки и действия пользователя
// (docs/security/signed-membership.md, разделы 5, 8, 9). Форматы сертификатов, memkey, снимок и
// строгая проверка подписей — в public/lib/membership.js; здесь — то, что хранит устройство
// (trusted, removed, joinIntent, revouch, delivered, viewPending), алгоритм verifyMembershipLocked
// и действия: подпись допуска, приглашения и входа, ручное подтверждение, поручительство.
//
// Сеть никогда не вызывается внутри withLock (9.1, П10): секции блокировки только читают и пишут
// хранилище; запросы сертификатов идут до блокировки, публикация — после. Функции *Locked вызываются
// ТОЛЬКО изнутри withLock клиента (сами блокировку не берут).
//
// Файл исполняется в браузере (window.NyxoMembershipClient) и в Node (тесты); хранилище, сеть,
// часы, блокировка и доступ к ключам устройства внедряются e2ee.js.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./membership.js'));
    } else {
        root.NyxoMembershipClient = factory(root.NyxoMembership);
    }
})(typeof self !== 'undefined' ? self : this, function (M) {
    'use strict';

    const DAY_MIN = 24 * 60;
    const INTENT_TTL_MIN = 30 * DAY_MIN;       // намерение входа живёт 30 суток (вопрос 15)
    const MAX_REMOVED = 5000;                  // записей removed на комнату
    const MAX_REVOUCH_TASKS = 50;              // задач повторного допуска за проход
    const MAX_VIEW_PENDING = 100;              // очередь сверки взглядов на комнату
    const VIEW_DIV_COUNT = 3;                  // расхождений ids подряд до уведомления
    const VIEW_DIV_MIN = DAY_MIN;              // или суток расхождения
    const VIEW_NOTICE_MIN = DAY_MIN;           // уведомление не чаще раза в сутки на пару
    const MAX_CERTS_PER_SUBJECT = 6;           // 4 допуска + join + запас; лишнее от сервера игнорируется
    const CERT_FETCH_CHUNK = 200;
    const MAX_FETCH_IDS = 1000;
    const HOWS = Object.freeze(['creator', 'approved', 'invite', 'vouched', 'revouched', 'manual']);
    // Подтверждения, которые держатся на подписи участника: при его уходе нужен повторный допуск.
    const REF_HOWS = Object.freeze(['approved', 'invite', 'vouched', 'revouched']);

    const names = Object.freeze({
        trusted: (room) => 'trusted:' + room,
        removed: (room) => 'removed:' + room,
        intent: (room) => 'joinIntent:' + room,
        revouch: (room) => 'revouch:' + room,
        delivered: (room, keyId) => 'delivered:' + room + ':' + keyId,
        deliveredPrefix: (room) => 'delivered:' + room + ':',
        viewPending: (room) => 'viewPending:' + room,
        viewDiv: (room, sender) => 'viewDiv:' + room + ':' + sender,
        viewDivPrefix: (room) => 'viewDiv:' + room + ':',
        viewNotice: (room, sender, kind) => 'viewNotice:' + room + ':' + sender + ':' + kind,
        viewNoticePrefix: (room) => 'viewNotice:' + room + ':',
        inviteSecret: (room) => 'inviteSecret:' + room,
        members: (room) => 'members:' + room,
    });

    const isHex = (value, length) => typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
    const isId = (n) => Number.isInteger(n) && n > 0 && n <= 0xFFFFFFFF;

    // ===================== Нормализация записей хранилища =====================

    function normalizeEntry(raw) {
        if (!raw || typeof raw !== 'object') return null;
        if (!isId(raw.id) || !isHex(raw.memkey, 32)) return null;
        if (raw.status !== 'self' && raw.status !== 'confirmed') return null;
        if (!HOWS.includes(raw.how)) return null;
        const entry = {
            id: raw.id,
            username: typeof raw.username === 'string' ? raw.username : '',
            memkey: raw.memkey,
            status: raw.status,
            how: raw.how,
            by: isId(raw.by) ? raw.by : null,
            certHash: isHex(raw.certHash, 64) ? raw.certHash : null,
            since: Number.isInteger(raw.since) && raw.since >= 0 ? raw.since : 0,
        };
        if (raw.vouchedByMe === true) entry.vouchedByMe = true;
        return entry;
    }

    function normalizeTrusted(raw) {
        const out = { bootstrapDone: false, list: [] };
        if (!raw || typeof raw !== 'object') return out;
        out.bootstrapDone = raw.bootstrapDone === true;
        const seen = new Set();
        for (const item of Array.isArray(raw.list) ? raw.list : []) {
            const entry = normalizeEntry(item);
            if (entry && !seen.has(entry.id)) { seen.add(entry.id); out.list.push(entry); }
        }
        return out;
    }

    function normalizeRemoved(raw, nowMin) {
        const out = {};
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
        for (const [key, minute] of Object.entries(raw)) {
            const id = Number(key);
            // Запись живёт 30 суток от минуты выхода (6.4: сертификат старше FRESH и так не принимается).
            if (isId(id) && Number.isInteger(minute) && minute >= 0 && nowMin - minute <= M.REMOVED_KEEP_MIN) out[id] = minute;
        }
        const ids = Object.keys(out);
        if (ids.length > MAX_REMOVED) {
            ids.sort((a, b) => out[a] - out[b]);
            for (const id of ids.slice(0, ids.length - MAX_REMOVED)) delete out[id];
        }
        return out;
    }

    function normalizeIntent(raw) {
        if (!raw || typeof raw !== 'object') return null;
        if (raw.via !== 'invite' && raw.via !== 'request') return null;
        if (!Number.isInteger(raw.at) || raw.at < 0) return null;
        const intent = { via: raw.via, at: raw.at };
        if (raw.via === 'invite') {
            if (!isHex(raw.inviteHash, 64)) return null;
            intent.inviteHash = raw.inviteHash;
            if (typeof raw.inviteSnap === 'string') intent.inviteSnap = raw.inviteSnap;
            if (typeof raw.joinCert === 'string') intent.joinCert = raw.joinCert;
            if (typeof raw.inviteCert === 'string') intent.inviteCert = raw.inviteCert;
        }
        return intent;
    }

    function normalizeRevouch(raw) {
        const out = [];
        for (const item of Array.isArray(raw) ? raw : []) {
            if (item && isId(item.x) && isHex(item.orig, 64) && Number.isInteger(item.due) && item.due >= 0
                && !out.some(t => t.x === item.x)) out.push({ x: item.x, orig: item.orig, due: item.due });
        }
        return out.slice(0, MAX_REVOUCH_TASKS);
    }

    function sameJson(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

    // Разбор сертификатов из ответа сервера: [{ subjectId, actorId, kind, cert, aux? }] -> Map(subject -> [..]).
    // allowed - множество допустимых субъектов; всё остальное игнорируется (сервер недоверенный).
    function parseCertItems(list, allowed) {
        const out = new Map();
        for (const item of Array.isArray(list) ? list : []) {
            if (!item || typeof item !== 'object') continue;
            const subject = Number(item.subjectId);
            if (!allowed.has(subject)) continue;
            const kind = Number(item.kind);
            if (kind !== 1 && kind !== 3 && kind !== 4) continue;
            const cert = M.fromB64(item.cert);
            if (!cert || cert.length !== M.CERT_LENGTH[kind]) continue;
            const aux = item.aux ? M.fromB64(item.aux) : null;
            if (kind === 3 && (!aux || aux.length !== 335)) continue;
            const bucket = out.get(subject) || [];
            if (bucket.length >= MAX_CERTS_PER_SUBJECT) continue;
            bucket.push({ kind, actorId: Number(item.actorId) || 0, cert, aux });
            out.set(subject, bucket);
        }
        return out;
    }

    // Разбор поля ext.view: { ids, keys } - base64 по 16 байт; иначе null (поле справочное, 6.3).
    function parseViewField(raw) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        const ids = M.fromB64(raw.ids);
        const keys = M.fromB64(raw.keys);
        if (!ids || ids.length !== 16 || !keys || keys.length !== 16) return null;
        return { ids: M.toB64(ids), keys: M.toB64(keys) };
    }

    // ===================== Клиент =====================

    function createMembershipClient(deps) {
        const { storage, transport, withLock, now, getUserId, loadIdentityLocked, sign, logExcluded, checkPeers } = deps;
        const randomBytes = deps.randomBytes || ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
        const nowMin = () => M.minuteOf(now());

        // ---- Закреплённые ключи участников (peer:<id>) ----

        async function loadPins(ids) {
            const out = new Map();
            for (const id of ids) {
                const raw = await storage.get('peer:' + id);
                if (!raw || typeof raw.signPub !== 'string' || typeof raw.dhPub !== 'string') continue;
                const signPub = M.fromB64(raw.signPub);
                const dhPub = M.fromB64(raw.dhPub);
                if (!signPub || !dhPub || signPub.length !== 32 || dhPub.length !== 32) continue;
                out.set(id, { id, signPub, dhPub, pending: Boolean(raw.pending), excluded: Boolean(logExcluded && logExcluded(raw)) });
            }
            return out;
        }

        // memkey по закреплённым ключам (кэш на проход).
        function memkeyCache() {
            const cache = new Map();
            return async (id, signPub, dhPub) => {
                if (!cache.has(id)) cache.set(id, M.toHex(await M.memkey(id, signPub, dhPub)));
                return cache.get(id);
            };
        }

        async function readTrusted(roomId) { return normalizeTrusted(await storage.get(names.trusted(roomId))); }

        async function readIntentLocked(roomId, minute) {
            const raw = await storage.get(names.intent(roomId));
            if (raw === null || raw === undefined) return null;
            const intent = normalizeIntent(raw);
            if (!intent || minute - intent.at > INTENT_TTL_MIN) {
                await storage.delete(names.intent(roomId));
                return null;
            }
            return intent;
        }

        // ===================== Сертификаты других участников (вне блокировки) =====================

        // Кого спрашивать (9.1): тех, кого клиент ещё не подтвердил (S без V), и тех из V, чей подписавший вышел
        // из комнаты (шаг 4а), и участников задач повторного допуска. Только чтение, без блокировки: это
        // план запроса, решение принимает verifyLocked по состоянию внутри блокировки.
        async function planCertFetch(roomId, current, meId) {
            const trusted = await readTrusted(roomId);
            const inV = new Map(trusted.list.map(e => [e.id, e]));
            const inS = new Set(current.map(p => p.id));
            const ids = [];
            for (const p of current) {
                if (p.id === meId) continue;
                const entry = inV.get(p.id);
                if (!entry) ids.push(p.id);
                else if (entry.by !== null && REF_HOWS.includes(entry.how) && !inS.has(entry.by)) ids.push(p.id);
            }
            return ids.slice(0, MAX_FETCH_IDS);
        }

        // → Map(subjectId -> [{ kind, actorId, cert, aux }]); сетевой сбой даёт неполный результат, а не ошибку:
        // участник остаётся неподтверждённым до следующей проверки.
        async function fetchCerts(chatId, ids) {
            const out = new Map();
            if (!ids.length || typeof transport.getMemberCerts !== 'function') return out;
            for (let i = 0; i < ids.length; i += CERT_FETCH_CHUNK) {
                const chunk = ids.slice(i, i + CERT_FETCH_CHUNK);
                let res;
                try { res = await transport.getMemberCerts(chatId, chunk); } catch { continue; }
                if (!res || !res.data || res.data.success !== true) continue;
                for (const [subject, list] of parseCertItems(res.data.certs, new Set(chunk))) out.set(subject, list);
            }
            return out;
        }

        // ===================== verifyMembershipLocked (9.1) =====================

        // input: { roomId, current: [{ id, username }], prevMembers (members:<room> до обновления | null),
        //          certMap: Map(subject -> [...]), snaps: [{ actorId, kind, snap }], me: { id, username, signPub, dhPub },
        //          pins: Map(id -> pin), nowMs }
        // → { V: Map, members, unconfirmed, duplicateKeys, departed, revoked, recipients, anchor, revouchDue, memkeyOf }
        async function verifyLocked(input) {
            const { roomId, current, prevMembers, certMap, snaps, me, pins } = input;
            const minute = M.minuteOf(input.nowMs);
            const S = new Map(current.map(p => [p.id, p]));
            const memkeyOf = memkeyCache();
            const trusted = await readTrusted(roomId);
            const removedStored = await storage.get(names.removed(roomId));
            const removed = normalizeRemoved(removedStored, minute);
            const removedBefore = JSON.stringify(removed);
            let intent = await readIntentLocked(roomId, minute);
            // Намерение входа при уже записанном V бесполезно (якорь невозможен) и не должно блокировать запись V.
            if (intent && trusted.bootstrapDone) { await storage.delete(names.intent(roomId)); intent = null; }

            const V = new Map(trusted.list.map(e => [e.id, e]));
            const meMemkey = M.toHex(await M.memkey(me.id, me.signPub, me.dhPub));
            const prevSelf = V.get(me.id);
            V.set(me.id, {
                id: me.id, username: me.username, memkey: meMemkey, status: 'self',
                how: prevSelf ? prevSelf.how : 'creator', by: prevSelf ? prevSelf.by : null,
                certHash: prevSelf ? prevSelf.certHash : null, since: prevSelf ? prevSelf.since : minute,
            });

            // 1. Ушедшие: все, кто был в прежнем S (или в V) и больше не в S - независимо от членства в V.
            const departed = [];
            const prevIds = Array.isArray(prevMembers) ? prevMembers.map(p => Number(p.id)).filter(isId) : [];
            for (const id of new Set([...prevIds, ...V.keys()])) {
                if (id === me.id || S.has(id)) continue;
                // Отметка выхода - тому, кого мы видели в комнате; запись V без членства (ручное подтверждение до
                // появления в списке) просто убирается.
                if (prevIds.includes(id)) { removed[id] = minute; departed.push(id); }
                V.delete(id);
            }

            // 3. Отзыв: ключ изменился и не принят (pending), либо закреплённые ключи уже не те, на которых участник
            // попал в V. Это единственная причина выпадения из V при X в S.
            const revoked = [];
            for (const [id, entry] of [...V]) {
                if (id === me.id) continue;
                const pin = pins.get(id);
                if (!pin) continue;
                if (pin.pending || entry.memkey !== await memkeyOf(id, pin.signPub, pin.dhPub)) { V.delete(id); revoked.push(id); }
            }

            // 3а. Дубликаты ключей (6.2): кто уже в V по id, там и остаётся; остальные члены группы не подтверждаются.
            const byKeys = new Map();
            for (const p of current) {
                if (p.id === me.id) continue;
                const pin = pins.get(p.id);
                if (!pin) continue;
                const key = M.toHex(pin.signPub) + M.toHex(pin.dhPub);
                if (!byKeys.has(key)) byKeys.set(key, []);
                byKeys.get(key).push(p.id);
            }
            const duplicateKeys = [];
            const blocked = new Set();
            for (const ids of byKeys.values()) {
                if (ids.length < 2) continue;
                duplicateKeys.push({ ids: ids.slice() });
                for (const id of ids) if (!V.has(id)) blocked.add(id);
            }

            // ---- проверки сертификатов ----
            const myKeysEqual = (signPub, dhPub) => M.bytesEqual(signPub, me.signPub) && M.bytesEqual(dhPub, me.dhPub);
            const subjectKeysOk = (id, signPub, dhPub) => {
                if (id === me.id) return myKeysEqual(signPub, dhPub) ? { ok: true } : { ok: false, reason: 'not-mine' };
                const pin = pins.get(id);
                if (!pin || pin.pending) return { ok: false, reason: 'subject-keys' };
                return M.bytesEqual(pin.signPub, signPub) && M.bytesEqual(pin.dhPub, dhPub) ? { ok: true } : { ok: false, reason: 'subject-keys' };
            };
            const actorOkFor = (subject) => (actorId, actorKey) => {
                if (actorId === subject) return { ok: false, reason: 'actor-is-subject' };
                if (!V.has(actorId)) return { ok: false, reason: 'actor-not-trusted' };
                if (!S.has(actorId)) return { ok: false, reason: 'actor-left' };
                if (actorId === me.id) return M.bytesEqual(actorKey, me.signPub) ? { ok: true } : { ok: false, reason: 'actor-key' };
                const pin = pins.get(actorId);
                // Подписавший в состоянии changed или log-mismatch допусков не даёт (6.4, п. 2).
                if (!pin || pin.pending || pin.excluded) return { ok: false, reason: 'actor-suspect' };
                return M.bytesEqual(pin.signPub, actorKey) ? { ok: true } : { ok: false, reason: 'actor-key' };
            };
            const validate = (item, subject) => M.validateCert(item.cert, {
                roomId, nowMin: minute, expectSubject: subject, removedAt: (id) => removed[id],
                actorOk: actorOkFor(subject), subjectKeysOk, invite: item.aux,
            });
            const entryFrom = async (id, res) => {
                const pin = pins.get(id);
                const kind = res.cert.kind;
                return {
                    id, username: S.get(id).username, memkey: await memkeyOf(id, pin.signPub, pin.dhPub), status: 'confirmed',
                    how: kind === M.KIND.vouch ? 'vouched' : kind === M.KIND.revouch ? 'revouched' : 'invite',
                    by: kind === M.KIND.join ? res.invite.actorId : res.cert.actorId,
                    certHash: M.toHex(res.hash), since: minute,
                };
            };

            // 4. Замыкание: пока V растёт, подтверждаем тех из S без V, у кого есть сертификат от участника из V.
            const closure = async () => {
                let progressed = true;
                while (progressed) {
                    progressed = false;
                    for (const x of S.keys()) {
                        if (x === me.id || V.has(x) || blocked.has(x)) continue;
                        const pin = pins.get(x);
                        if (!pin || pin.pending) continue;
                        for (const item of certMap.get(x) || []) {
                            const res = await validate(item, x);
                            if (res.ok) { V.set(x, await entryFrom(x, res)); progressed = true; break; }
                        }
                    }
                }
            };
            await closure();

            // 4а. Ссылки на ушедшего подписавшего: если есть допуск от текущего участника из V - обновить запись.
            const needRevouch = [];
            const refresh = async () => {
                needRevouch.length = 0;
                for (const [x, entry] of V) {
                    if (x === me.id || entry.by === null || !REF_HOWS.includes(entry.how) || S.has(entry.by)) continue;
                    let replaced = false;
                    for (const item of certMap.get(x) || []) {
                        if (item.kind !== M.KIND.vouch && item.kind !== M.KIND.revouch) continue;
                        const res = await validate(item, x);
                        if (!res.ok) continue;
                        entry.how = res.cert.kind === M.KIND.vouch ? 'vouched' : 'revouched';
                        entry.by = res.cert.actorId;
                        entry.certHash = M.toHex(res.hash);
                        replaced = true;
                        break;
                    }
                    if (!replaced) needRevouch.push(x);
                }
            };
            await refresh();

            // 5. Якорная проверка новичка (9.2): только при joinIntent, без bootstrapDone и при V = {я}.
            let anchor = null;
            if (intent && V.size === 1) {
                anchor = await anchorLocked({ intent, roomId, S, V, pins, me, snaps, certMap, blocked, removed, minute, memkeyOf, myKeysEqual });
                if (anchor.ok) { await closure(); await refresh(); }
            }

            // Рассылка и результат.
            const recipients = [];
            for (const [id, entry] of V) {
                if (id === me.id || !S.has(id)) continue;
                const pin = pins.get(id);
                if (!pin || pin.pending || pin.excluded) continue;
                recipients.push({ id, memkey: entry.memkey });
            }
            const unconfirmed = [];
            for (const p of current) {
                if (p.id === me.id || V.has(p.id)) continue;
                unconfirmed.push({ id: p.id, username: p.username, duplicateKeys: blocked.has(p.id) });
            }
            const members = current.map(p => {
                const entry = V.get(p.id);
                if (!entry) return { id: p.id, username: p.username, status: 'unconfirmed', how: null, by: null };
                const item = { id: p.id, username: p.username, status: entry.status, how: entry.how, by: entry.by };
                if (entry.vouchedByMe) item.vouchedByMe = true;
                if (duplicateKeys.some(g => g.ids.includes(p.id))) item.duplicateKeys = true;
                return item;
            });

            // Запись (одной секцией withLock вызывающего): trusted и расход намерения - вместе, а пока намерение
            // живо, trusted не пишет никто, кроме самой якорной проверки (П18).
            const anchorDone = Boolean(anchor && anchor.ok);
            if (!intent || anchorDone) {
                const list = [...V.values()].sort((a, b) => a.id - b.id);
                const next = { bootstrapDone: true, list };
                const before = { bootstrapDone: trusted.bootstrapDone, list: trusted.list.slice().sort((a, b) => a.id - b.id) };
                if (!sameJson(before, next)) await storage.set(names.trusted(roomId), next);
                if (anchorDone) await storage.delete(names.intent(roomId));
            }
            if (JSON.stringify(removed) !== removedBefore || (removedStored !== null && removedStored !== undefined && !sameJson(removedStored, removed))) {
                if (Object.keys(removed).length === 0) await storage.delete(names.removed(roomId));
                else await storage.set(names.removed(roomId), removed);
            }

            // Очередь повторных допусков (5.5, 9.5): задачи для X с уходом подписавшего; снимаются, когда X уже не нужен.
            const revouchDue = await updateRevouchQueueLocked({ roomId, S, V, needRevouch, me, minute });

            return {
                V, members, unconfirmed, duplicateKeys, departed, revoked, recipients, anchor, revouchDue, memkeyOf,
                intentAlive: Boolean(intent) && !anchorDone,
            };
        }

        async function anchorLocked(ctx) {
            const { intent, roomId, S, V, pins, me, snaps, certMap, blocked, removed, minute, memkeyOf, myKeysEqual } = ctx;
            const fail = (reason) => ({ ok: false, reason, via: intent.via });
            const mine = certMap.get(me.id) || [];
            if (intent.via === 'request') {
                for (const item of mine) {
                    if (item.kind !== M.KIND.vouch) continue;       // при заявке годится только vouch
                    const parsed = M.parseCert(item.cert);
                    if (!parsed.ok) continue;
                    const a = parsed.cert.actorId;
                    if (!S.has(a) || a === me.id) continue;
                    if (blocked.has(a)) return fail('duplicate-keys');
                    const pinA = pins.get(a);
                    if (!pinA || pinA.pending || pinA.excluded) continue;
                    const res = await M.validateCert(item.cert, {
                        roomId, nowMin: minute, expectSubject: me.id, removedAt: (id) => removed[id],
                        // Якорь - ключ A, который сообщает сервер (TOFU): A ещё не в V.
                        actorOk: (aid, akey) => (aid === a && M.bytesEqual(akey, pinA.signPub) ? { ok: true } : { ok: false, reason: 'actor-key' }),
                        subjectKeysOk: (id, sp, dp) => (id === me.id && myKeysEqual(sp, dp) ? { ok: true } : { ok: false, reason: 'not-mine' }),
                    });
                    if (!res.ok) continue;
                    const snapItem = (snaps || []).find(s => s.actorId === a && s.kind === M.KIND.vouch);
                    if (!snapItem) return fail('snap-missing');
                    if (!(await M.checkSnap(snapItem.snap, res.cert.snapN, res.cert.snapHash))) return fail('snap-bad');
                    return finishAnchor({ via: 'request', a, certHash: M.toHex(res.hash), snap: snapItem.snap, ...ctx });
                }
                return fail('no-certificate');
            }
            // Вход по ссылке: только join с ref = inviteHash из намерения (приглашение, проверенное секретом).
            for (const item of mine) {
                if (item.kind !== M.KIND.join) continue;
                const parsed = M.parseCert(item.cert);
                if (!parsed.ok || M.toHex(parsed.cert.ref) !== intent.inviteHash) continue;
                const invite = item.aux ? M.parseCert(item.aux) : null;
                if (!invite || !invite.ok || invite.cert.kind !== M.KIND.invite) continue;
                const a = invite.cert.actorId;
                if (!S.has(a) || a === me.id) continue;
                if (blocked.has(a)) return fail('duplicate-keys');
                const pinA = pins.get(a);
                if (!pinA || pinA.pending || pinA.excluded) return fail('inviter-key');
                const res = await M.validateCert(item.cert, {
                    roomId, nowMin: minute, expectSubject: me.id, removedAt: (id) => removed[id],
                    // Условие 1 проверки invite для новичка заменено (9.2): приглашающий ещё не закреплён, поэтому
                    // его ключ из сертификата сверяется с ключом, который сообщает сервер.
                    actorOk: (aid, akey) => (aid === a && M.bytesEqual(akey, pinA.signPub) ? { ok: true } : { ok: false, reason: 'actor-key' }),
                    subjectKeysOk: (id, sp, dp) => (id === me.id && myKeysEqual(sp, dp) ? { ok: true } : { ok: false, reason: 'not-mine' }),
                    invite: item.aux,
                    inviteRef: M.fromHex(intent.inviteHash),
                });
                if (!res.ok) { if (res.reason === 'invite-actor-key') return fail('inviter-substituted'); continue; }
                const snap = intent.inviteSnap ? M.fromB64(intent.inviteSnap) : null;
                if (!snap) return fail('snap-missing');
                if (!(await M.checkSnap(snap, res.invite.snapN, res.invite.snapHash))) return fail('snap-bad');
                return finishAnchor({ via: 'invite', a, certHash: M.toHex(res.hash), snap, ...ctx });
            }
            return fail('no-certificate');
        }

        // V = {я, A} U { X в S : memkey(X) входит в снимок } (9.2). how: заявка - approved/vouched, ссылка - invite.
        async function finishAnchor(ctx) {
            const { via, a, certHash, snap, S, V, pins, me, blocked, minute, memkeyOf } = ctx;
            const set = M.snapSet(snap);
            const selfHow = via === 'request' ? 'approved' : 'invite';
            const selfEntry = V.get(me.id);
            selfEntry.how = selfHow; selfEntry.by = a; selfEntry.certHash = certHash; selfEntry.since = minute;
            const pinA = pins.get(a);
            V.set(a, {
                id: a, username: S.get(a).username, memkey: await memkeyOf(a, pinA.signPub, pinA.dhPub), status: 'confirmed',
                how: selfHow, by: a, certHash, since: minute,
            });
            for (const [id, p] of S) {
                if (id === me.id || id === a || blocked.has(id)) continue;
                const pin = pins.get(id);
                if (!pin || pin.pending) continue;
                const key = await memkeyOf(id, pin.signPub, pin.dhPub);
                if (!set.has(key)) continue;
                V.set(id, {
                    id, username: p.username, memkey: key, status: 'confirmed',
                    how: via === 'request' ? 'vouched' : 'invite', by: a, certHash, since: minute,
                });
            }
            return { ok: true, via, by: a };
        }

        // ===================== Повторный допуск: очередь (5.5, 9.5) =====================

        async function updateRevouchQueueLocked({ roomId, S, V, needRevouch, me, minute }) {
            const raw = await storage.get(names.revouch(roomId));
            let queue = normalizeRevouch(raw);
            // Задача нужна, пока X в S и в V и подписавшего X нет в S.
            queue = queue.filter(t => S.has(t.x) && V.has(t.x) && needRevouch.includes(t.x));
            const ids = [...S.keys()];
            for (const x of needRevouch) {
                if (queue.length >= MAX_REVOUCH_TASKS) break;
                if (queue.some(t => t.x === x)) continue;
                const entry = V.get(x);
                if (!entry.certHash) continue;
                const rank = await M.revouchRank(x, entry.by, me.id, ids);
                queue.push({ x, orig: entry.certHash, due: minute + M.revouchDelayMin(rank) });
            }
            if (!sameJson(queue, normalizeRevouch(raw)) || (raw !== null && !Array.isArray(raw))) {
                if (queue.length === 0) await storage.delete(names.revouch(roomId));
                else await storage.set(names.revouch(roomId), queue);
            }
            return queue.filter(t => t.due <= minute).map(t => t.x);
        }

        // ===================== Журнал доставок (9.1, 9.4) =====================

        // Запись пары { id, memkey } в журнал собственного ключа - ДО сетевого вызова, только на добавление.
        async function appendDeliveredLocked(roomId, senderKeyId, id, memkeyHex, limit) {
            const name = names.delivered(roomId, senderKeyId);
            const list = Array.isArray(await storage.get(name)) ? await storage.get(name) : [];
            if (list.some(p => p.id === id && p.memkey === memkeyHex)) return;
            list.push({ id, memkey: memkeyHex });
            // Не больше |S| пар на ключ: прежние пары того же id вытесняются самыми старыми, чтобы журнал не рос.
            const cap = Math.max(limit || 0, 8) * 2;
            if (list.length > cap) list.splice(0, list.length - cap);
            await storage.set(name, list);
        }

        // Причина ротации по журналу (9.1): пара { id, memkey } собственного ключа, которой нет среди текущих
        // получателей, - ключ уходит в ротацию до рассылки. null - ротация не нужна.
        async function journalRotationReasonLocked(roomId, senderKeyId, recipients, S, V, pins) {
            const list = await storage.get(names.delivered(roomId, senderKeyId));
            if (!Array.isArray(list) || list.length === 0) return null;
            let reason = null;
            const rank = { 'member-left': 4, 'log-mismatch': 3, 'keys-changed': 2, 'membership-revoked': 1 };
            const raise = (r) => { if (!reason || rank[r] > rank[reason]) reason = r; };
            for (const pair of list) {
                if (!pair || !isId(pair.id)) continue;
                if (recipients.some(r => r.id === pair.id && r.memkey === pair.memkey)) continue;
                if (!S.has(pair.id)) raise('member-left');
                else if (pins.get(pair.id) && pins.get(pair.id).excluded) raise('log-mismatch');
                else if (recipients.some(r => r.id === pair.id)) raise('keys-changed');
                else raise('membership-revoked');
            }
            return reason;
        }

        // ===================== Сверка взглядов (9.6) =====================

        // Хэш взгляда на состав и ключи: участники из members:<room> в порядке возрастания id, ключи - по закреплённым.
        async function computeViewLocked(roomId, me) {
            const members = await storage.get(names.members(roomId));
            if (!Array.isArray(members) || members.length === 0) return null;
            const ids = members.map(p => Number(p.id)).filter(isId);
            const pins = await loadPins(ids.filter(id => id !== me.id));
            const entries = [];
            for (const id of ids) {
                if (id === me.id) { entries.push({ id, memkey: await M.memkey(id, me.signPub, me.dhPub) }); continue; }
                const pin = pins.get(id);
                entries.push({ id, memkey: pin ? await M.memkey(id, pin.signPub, pin.dhPub) : null });
            }
            return M.viewHash(entries);
        }

        function encodeView(view) { return { ids: M.toB64(view.ids), keys: M.toB64(view.keys) }; }

        // В блокировке applyShare - только запись задачи (сеть там запрещена).
        async function noteViewLocked(roomId, sender, view) {
            if (!isId(sender)) return;
            const list = (Array.isArray(await storage.get(names.viewPending(roomId))) ? await storage.get(names.viewPending(roomId)) : [])
                .filter(item => item && item.sender !== sender);
            list.push({ sender, view, at: now() });
            if (list.length > MAX_VIEW_PENDING) list.splice(0, list.length - MAX_VIEW_PENDING);
            await storage.set(names.viewPending(roomId), list);
        }

        // Вне блокировки: сверка взглядов отправителей с моим. → { viewMismatch, viewIdsDiverged, notices }
        async function runViewChecks(roomId, me) {
            const result = { viewMismatch: false, viewIdsDiverged: false, notices: [] };
            const queue = await withLock(async () => {
                const list = await storage.get(names.viewPending(roomId));
                return Array.isArray(list) ? list.slice() : [];
            });
            if (queue.length === 0) return result;
            const processed = [];
            for (const item of queue) {
                if (!item || !isId(item.sender) || !item.view) continue;
                const decision = await withLock(async () => {
                    const mine = await computeViewLocked(roomId, me);
                    if (!mine) return { kind: 'skip' };
                    const t = now();
                    const divName = names.viewDiv(roomId, item.sender);
                    if (item.view.ids !== M.toB64(mine.ids)) {
                        const prev = await storage.get(divName);
                        const state = prev && Number.isInteger(prev.count) ? { count: prev.count + 1, since: prev.since } : { count: 1, since: t };
                        await storage.set(divName, state);
                        // Счётчик проверяется ДО выхода: иначе расхождение ids отключало бы сверку без следа.
                        if (state.count >= VIEW_DIV_COUNT || (t - state.since) / 60000 > VIEW_DIV_MIN) {
                            if (await noticeDueLocked(roomId, item.sender, 'ids', t)) return { kind: 'ids-diverged' };
                        }
                        return { kind: 'skip' };
                    }
                    await storage.delete(divName);
                    if (item.view.keys === M.toB64(mine.keys)) return { kind: 'ok' };
                    return { kind: 'keys-differ' };
                });
                processed.push(item.sender);
                if (decision.kind === 'ids-diverged') { result.viewIdsDiverged = true; result.notices.push({ sender: item.sender, kind: 'view-ids-diverged' }); }
                if (decision.kind !== 'keys-differ') continue;
                // Ключи расходятся: сначала свежая сверка закреплённых ключей с сервером (сеть - вне блокировки).
                const ids = await withLock(async () => {
                    const members = await storage.get(names.members(roomId));
                    return (Array.isArray(members) ? members : []).map(p => Number(p.id)).filter(id => isId(id) && id !== me.id);
                });
                if (checkPeers) { try { await checkPeers(ids); } catch { /* сеть недоступна: решаем по тому, что есть */ } }
                const mismatch = await withLock(async () => {
                    const mine = await computeViewLocked(roomId, me);
                    if (!mine) return false;
                    // Расхождение объясняется сменой ключа, которую пользователь уже видел: подавляем.
                    const pins = await loadPins(ids);
                    if ([...pins.values()].some(p => p.pending)) return false;
                    if (item.view.ids !== M.toB64(mine.ids) || item.view.keys === M.toB64(mine.keys)) return false;
                    return noticeDueLocked(roomId, item.sender, 'keys', now());
                });
                if (mismatch) { result.viewMismatch = true; result.notices.push({ sender: item.sender, kind: 'view-mismatch' }); }
            }
            await withLock(async () => {
                const handled = new Set(queue.filter(q => processed.includes(q.sender)).map(q => q.sender + ':' + q.at));
                const current = await storage.get(names.viewPending(roomId));
                const rest = (Array.isArray(current) ? current : []).filter(it => it && !handled.has(it.sender + ':' + it.at));
                if (rest.length === 0) await storage.delete(names.viewPending(roomId));
                else await storage.set(names.viewPending(roomId), rest);
            });
            return result;
        }

        // Уведомление не чаще раза в сутки на пару (комната, отправитель, вид).
        async function noticeDueLocked(roomId, sender, kind, t) {
            const name = names.viewNotice(roomId, sender, kind);
            const last = await storage.get(name);
            if (Number.isFinite(last) && t - last < VIEW_NOTICE_MIN * 60000) return false;
            await storage.set(name, t);
            return true;
        }

        // ===================== Снимок моего V (без ручных) =====================

        // memkey участников V с how != manual (или с поручительством), включая меня. Ключи сверяются с закреплёнными:
        // участник, чьи ключи сменились, в снимок не попадает.
        async function mySnapshotLocked(roomId, me) {
            const trusted = await readTrusted(roomId);
            const pins = await loadPins(trusted.list.map(e => e.id).filter(id => id !== me.id));
            const list = [await M.memkey(me.id, me.signPub, me.dhPub)];
            for (const entry of trusted.list) {
                if (entry.id === me.id) continue;
                if (entry.how === 'manual' && !entry.vouchedByMe) continue;
                const pin = pins.get(entry.id);
                if (!pin || pin.pending) continue;
                const key = await M.memkey(entry.id, pin.signPub, pin.dhPub);
                if (M.toHex(key) !== entry.memkey) continue;
                list.push(key);
            }
            return M.buildSnap(list);
        }

        async function meLocked() {
            const identity = await loadIdentityLocked();
            if (!identity) throw new Error('Membership: нет ключей устройства');
            return { id: Number(getUserId()), signPub: M.fromB64(identity.signPub), dhPub: M.fromB64(identity.dhPub), identity };
        }

        // ===================== Действия пользователя =====================

        // Создатель комнаты (5.1): V = {я}, how = creator, bootstrapDone = true записываются сразу.
        async function noteRoomCreated(roomId, username) {
            return withLock(async () => {
                const me = await meLocked();
                const minute = nowMin();
                await storage.set(names.trusted(roomId), {
                    bootstrapDone: true,
                    list: [{
                        id: me.id, username: username || '', memkey: M.toHex(await M.memkey(me.id, me.signPub, me.dhPub)),
                        status: 'self', how: 'creator', by: null, certHash: null, since: minute,
                    }],
                });
                await storage.delete(names.intent(roomId));
                return true;
            });
        }

        // Подпись одобрения заявки (5.2): vouch(я -> заявитель) со снимком моего V. applicant: { userId, signingKey, dhKey }
        // - ключи заявителя, которые сообщил сервер (одобряющий видел код безопасности и решил).
        async function signApproval(roomId, applicant) {
            const userId = Number(applicant && applicant.userId);
            const signPub = M.fromB64(applicant && applicant.signingKey);
            const dhPub = M.fromB64(applicant && applicant.dhKey);
            if (!isId(userId) || !signPub || signPub.length !== 32 || !dhPub || dhPub.length !== 32) {
                throw new TypeError('Membership: некорректные данные заявителя');
            }
            if (!M.isStrictKey(signPub)) throw new Error('Membership: ключ заявителя недопустим');
            return withLock(async () => signVouchLocked(roomId, userId, signPub, dhPub));
        }

        async function signVouchLocked(roomId, userId, signPub, dhPub) {
            const me = await meLocked();
            const snap = await mySnapshotLocked(roomId, me);
            const raw = await M.signCert({
                kind: M.KIND.vouch, roomId: Number(roomId), issuedMin: nowMin(), nonce: randomBytes(16),
                subjectId: userId, subjectSignPub: signPub, subjectDhPub: dhPub,
                actorId: me.id, actorKey: me.signPub, snapN: snap.n, snapHash: snap.hash,
            }, { sig: (m) => sign(me.identity.signPriv, m) });
            return { cert: M.toB64(raw), snap: M.toB64(snap.snap), hash: M.toHex(await M.certHash(raw)) };
        }

        // Приглашение (5.3): секрет s, сертификат invite и снимок. Секрет остаётся на устройстве (inviteSecret:<room>).
        async function signInvite(roomId, { ttlSeconds } = {}) {
            const ttl = Number(ttlSeconds);
            if (!Number.isInteger(ttl) || ttl < 60 || ttl % 60 !== 0 || ttl > M.INVITE_MAX_MIN * 60) throw new RangeError('Membership: недопустимый срок приглашения');
            return withLock(async () => {
                const me = await meLocked();
                const snap = await mySnapshotLocked(roomId, me);
                const secret = randomBytes(16);
                const key = await M.inviteKeyFromSecret(secret);
                const issuedMin = nowMin();
                const raw = await M.signCert({
                    kind: M.KIND.invite, roomId: Number(roomId), issuedMin, nonce: randomBytes(16),
                    actorId: me.id, actorKey: me.signPub, ref: key.invitePub, expiresMin: issuedMin + ttl / 60,
                    snapN: snap.n, snapHash: snap.hash,
                }, { sig: (m) => sign(me.identity.signPriv, m), sig2: key.sign });
                const certHash = M.toHex(await M.certHash(raw));
                const secretText = M.secretToBase64Url(secret);
                await storage.set(names.inviteSecret(roomId), { s: secretText, certHash });
                return { cert: M.toB64(raw), snap: M.toB64(snap.snap), secret: secretText, certHash };
            });
        }

        // Ссылка показывается, только если сертификат на сервере тот же, с которым она создана (9.3).
        async function getInviteSecret(roomId, serverInviteB64) {
            return withLock(async () => {
                const stored = await storage.get(names.inviteSecret(roomId));
                if (!stored || typeof stored.s !== 'string' || !isHex(stored.certHash, 64)) return null;
                const raw = serverInviteB64 ? M.fromB64(serverInviteB64) : null;
                if (raw && raw.length === 335 && M.toHex(await M.certHash(raw)) === stored.certHash) return stored.s;
                // Приглашение повернул другой участник, выключили или подменили: мёртвую ссылку не показываем.
                await storage.delete(names.inviteSecret(roomId));
                return null;
            });
        }

        async function dropInviteSecret(roomId) {
            return withLock(() => storage.delete(names.inviteSecret(roomId)));
        }

        // Намерение входа (5.2, 5.3): создаётся только действием пользователя. opts: { secret, inviteCert } - вход по
        // ссылке; без них - заявка. → { via, joinCert? (base64), inviteHash? }
        async function prepareJoin(roomId, opts = {}) {
            const room = Number(roomId);
            if (!isId(room)) throw new TypeError('Membership: некорректная комната');
            if (!opts.secret) {
                return withLock(async () => {
                    await storage.set(names.intent(room), { via: 'request', at: nowMin() });
                    return { via: 'request' };
                });
            }
            const secret = M.secretFromBase64Url(opts.secret);
            const inviteRaw = M.fromB64(opts.inviteCert);
            if (!secret) throw joinError('invalid-secret', 'Ссылка повреждена: секрет не распознан');
            if (!inviteRaw) throw joinError('no-invite', 'В этой группе нет приглашения по ссылке. Отправьте заявку');
            const parsed = M.parseCert(inviteRaw);
            if (!parsed.ok || parsed.cert.kind !== M.KIND.invite) throw joinError('invalid-invite', 'Приглашение повреждено');
            const invite = parsed.cert;
            const key = await M.inviteKeyFromSecret(secret);
            // invitePub из секрета должен совпасть с тем, что в сертификате (внешняя точка опоры).
            if (!M.bytesEqual(key.invitePub, invite.ref)) throw joinError('secret-mismatch', 'Секрет ссылки не подходит к приглашению');
            const minute = nowMin();
            const sigs = await M.verifyCertSignatures(invite);
            if (!sigs.ok) throw joinError('invalid-invite', 'Подпись приглашения недействительна');
            if (invite.roomId !== room) throw joinError('invalid-invite', 'Приглашение относится к другой группе');
            if (invite.issuedMin > minute + M.SKEW_MIN) throw joinError('clock', 'Часы устройства отстают: приглашение выдано «в будущем»');
            if (invite.expiresMin <= invite.issuedMin || invite.expiresMin - invite.issuedMin > M.INVITE_MAX_MIN) throw joinError('invalid-invite', 'Срок приглашения недопустим');
            if (invite.expiresMin + M.SKEW_MIN < minute) throw joinError('expired', 'Срок приглашения истёк');
            const inviteHash = M.toHex(await M.certHash(inviteRaw));
            return withLock(async () => {
                const me = await meLocked();
                // join.issuedMin - в окне приглашения [I.issuedMin - SKEW; I.expiresMin + SKEW] и «сейчас».
                const issuedMin = Math.min(Math.max(minute, invite.issuedMin - M.SKEW_MIN), invite.expiresMin + M.SKEW_MIN);
                const raw = await M.signCert({
                    kind: M.KIND.join, roomId: room, issuedMin, nonce: randomBytes(16),
                    subjectId: me.id, subjectSignPub: me.signPub, subjectDhPub: me.dhPub,
                    actorId: 0, actorKey: invite.ref, ref: M.fromHex(inviteHash),
                }, { sig: key.sign, sig2: (m) => sign(me.identity.signPriv, m) });
                const joinCert = M.toB64(raw);
                await storage.set(names.intent(room), { via: 'invite', at: minute, inviteHash, joinCert, inviteCert: M.toB64(inviteRaw) });
                return { via: 'invite', joinCert, inviteHash };
            });
        }

        function joinError(code, message) {
            const err = new Error(message);
            err.code = code;
            return err;
        }

        // Ответ на POST /join потерян или получен: снимок приглашения проверяется по snapHash и сохраняется в намерении.
        async function completeJoin(roomId, inviteSnapB64) {
            return withLock(async () => {
                const intent = normalizeIntent(await storage.get(names.intent(roomId)));
                if (!intent || intent.via !== 'invite' || !intent.inviteCert) return { ok: false, reason: 'no-intent' };
                const invite = M.parseCert(M.fromB64(intent.inviteCert) || new Uint8Array(0));
                const snap = M.fromB64(inviteSnapB64);
                if (!invite.ok || !snap || !(await M.checkSnap(snap, invite.cert.snapN, invite.cert.snapHash))) {
                    return { ok: false, reason: 'snap-bad' };   // «приглашение повреждено»
                }
                intent.inviteSnap = M.toB64(snap);
                await storage.set(names.intent(roomId), intent);
                return { ok: true };
            });
        }

        async function cancelJoinIntent(roomId) {
            return withLock(() => storage.delete(names.intent(roomId)));
        }

        async function getJoinIntent(roomId) {
            return withLock(async () => {
                const intent = await readIntentLocked(roomId, nowMin());
                return intent ? { ...intent } : null;
            });
        }

        // Ручное подтверждение (9.7): локальное решение, сертификата не публикует, в снимки не входит.
        async function trustMember(roomId, userId) {
            const id = Number(userId);
            return withLock(async () => {
                const members = await storage.get(names.members(roomId));
                const member = (Array.isArray(members) ? members : []).find(p => Number(p.id) === id);
                // Решение принимается по закреплённым ключам, а не по запомненному списку сервера: список обновляется
                // следующей проверкой состава, и участник, только что появившийся в комнате, в нём ещё может не стоять.
                // Лишнюю запись V (человека нет в комнате) проверка состава уберёт.
                const pins = await loadPins([id]);
                const pin = pins.get(id);
                if (!pin) return { ok: false, reason: 'no-keys' };
                if (pin.pending) return { ok: false, reason: 'changed' };
                const minute = nowMin();
                const trusted = await readTrusted(roomId);
                const list = trusted.list.filter(e => e.id !== id);
                // Предусловие: «я» в V (после потери данных записи может не быть - создаём).
                const me = await meLocked();
                if (!list.some(e => e.id === me.id)) {
                    list.push({ id: me.id, username: '', memkey: M.toHex(await M.memkey(me.id, me.signPub, me.dhPub)), status: 'self', how: 'creator', by: null, certHash: null, since: minute });
                }
                list.push({
                    id, username: member && typeof member.username === 'string' ? member.username : '',
                    memkey: M.toHex(await M.memkey(id, pin.signPub, pin.dhPub)), status: 'confirmed', how: 'manual', by: null, certHash: null, since: minute,
                });
                // Ручное подтверждение при живом намерении отменяет его: пользователь отказывается от якоря (9.2).
                const hadIntent = (await storage.get(names.intent(roomId))) !== null;
                await storage.set(names.trusted(roomId), { bootstrapDone: true, list: list.sort((a, b) => a.id - b.id) });
                if (hadIntent) await storage.delete(names.intent(roomId));
                return { ok: true, cancelledIntent: hadIntent };
            });
        }

        // Явное поручительство (5.5): vouch(я -> X) со снимком моего V без ручных. Публикует member-certs.
        async function vouchForMember(chatId, roomId, userId) {
            const id = Number(userId);
            const prepared = await withLock(async () => {
                const trusted = await readTrusted(roomId);
                const entry = trusted.list.find(e => e.id === id);
                if (!entry || entry.status !== 'confirmed') return { ok: false, reason: 'not-trusted' };
                const pins = await loadPins([id]);
                const pin = pins.get(id);
                if (!pin || pin.pending) return { ok: false, reason: 'changed' };
                const signed = await signVouchLocked(roomId, id, pin.signPub, pin.dhPub);
                return { ok: true, signed };
            });
            if (!prepared.ok) return prepared;
            let res;
            try { res = await transport.postMemberCert(chatId, { subjectId: id, cert: prepared.signed.cert, snap: prepared.signed.snap }); } catch { res = null; }
            if (!res || !res.data || res.data.success !== true) {
                return { ok: false, reason: 'rejected', message: res && res.data && res.data.message };
            }
            await withLock(async () => {
                const trusted = await readTrusted(roomId);
                const entry = trusted.list.find(e => e.id === id);
                if (!entry) return;
                entry.vouchedByMe = true;
                await storage.set(names.trusted(roomId), trusted);
            });
            return { ok: true, stored: res.data.stored !== false };
        }

        // Задачи повторного допуска, срок которых наступил (5.5, 9.5): подписать revouch(я -> X, ref = orig) и опубликовать.
        // Вызывается после verifyLocked: задачи, для которых допуск уже появился, из очереди снимает он сам.
        async function publishDueRevouches(chatId, roomId, dueIds) {
            const published = [];
            for (const x of dueIds.slice(0, 10)) {
                const prepared = await withLock(async () => {
                    const queue = normalizeRevouch(await storage.get(names.revouch(roomId)));
                    const task = queue.find(t => t.x === x);
                    if (!task) return null;
                    const trusted = await readTrusted(roomId);
                    const entry = trusted.list.find(e => e.id === x);
                    if (!entry || entry.how === 'manual' || entry.by === null) return null;
                    const pin = (await loadPins([x])).get(x);
                    if (!pin || pin.pending) return null;
                    const me = await meLocked();
                    const raw = await M.signCert({
                        kind: M.KIND.revouch, roomId: Number(roomId), issuedMin: nowMin(), nonce: randomBytes(16),
                        subjectId: x, subjectSignPub: pin.signPub, subjectDhPub: pin.dhPub,
                        actorId: me.id, actorKey: me.signPub, ref: M.fromHex(task.orig),
                    }, { sig: (m) => sign(me.identity.signPriv, m) });
                    return { cert: M.toB64(raw), hash: M.toHex(await M.certHash(raw)), me: me.id };
                });
                if (!prepared) continue;
                let res;
                try { res = await transport.postMemberCert(chatId, { subjectId: x, cert: prepared.cert }); } catch { res = null; }
                if (!res || !res.data || res.data.success !== true) continue;
                await withLock(async () => {
                    const trusted = await readTrusted(roomId);
                    const entry = trusted.list.find(e => e.id === x);
                    if (entry) {
                        entry.how = 'revouched'; entry.by = prepared.me; entry.certHash = prepared.hash;
                        await storage.set(names.trusted(roomId), trusted);
                    }
                    const queue = normalizeRevouch(await storage.get(names.revouch(roomId))).filter(t => t.x !== x);
                    if (queue.length === 0) await storage.delete(names.revouch(roomId));
                    else await storage.set(names.revouch(roomId), queue);
                });
                published.push(x);
            }
            return published;
        }

        // Ближайший срок задачи повторного допуска (мс до него) или null - для таймера открытой вкладки.
        async function nextRevouchDueMs(roomId) {
            const queue = normalizeRevouch(await storage.get(names.revouch(roomId)));
            if (queue.length === 0) return null;
            const soonest = Math.min(...queue.map(t => t.due));
            return Math.max(0, (soonest - nowMin()) * 60000);
        }

        // Состав комнаты для окна участников (10): статусы по сохранённому V и списку сервера.
        async function getMembers(roomId) {
            return withLock(async () => {
                const trusted = await readTrusted(roomId);
                const V = new Map(trusted.list.map(e => [e.id, e]));
                const members = await storage.get(names.members(roomId));
                const me = Number(getUserId());
                const list = [];
                for (const p of Array.isArray(members) ? members : []) {
                    const id = Number(p.id);
                    const entry = V.get(id);
                    const item = entry
                        ? { id, username: p.username || entry.username || '', status: id === me ? 'self' : entry.status, how: entry.how, by: entry.by }
                        : { id, username: p.username || '', status: id === me ? 'self' : 'unconfirmed', how: null, by: null };
                    if (entry && entry.vouchedByMe) item.vouchedByMe = true;
                    list.push(item);
                }
                return list;
            });
        }

        // Участник из V (и не я)? Для unverifiedSender: вычисляется при каждой расшифровке по текущему V (9.4).
        async function isTrustedMember(roomId, senderId) {
            const id = Number(senderId);
            if (id === Number(getUserId())) return true;
            const raw = await storage.get(names.trusted(roomId));
            const trusted = normalizeTrusted(raw);
            return trusted.list.some(e => e.id === id);
        }

        // Текущие получатели ключа по сохранённому состоянию (без перепроверки сертификатов): V, находящиеся в S, без
        // log-mismatch и без изменившегося ключа. Для answerKeyRequests и ротации по запросу (9.4).
        async function currentRecipientsLocked(roomId, meId) {
            const trusted = await readTrusted(roomId);
            const members = await storage.get(names.members(roomId));
            const inS = new Set((Array.isArray(members) ? members : []).map(p => Number(p.id)));
            const ids = trusted.list.map(e => e.id).filter(id => id !== meId && inS.has(id));
            const pins = await loadPins(ids);
            const out = [];
            for (const entry of trusted.list) {
                if (entry.id === meId || !inS.has(entry.id)) continue;
                const pin = pins.get(entry.id);
                if (!pin || pin.pending || pin.excluded) continue;
                const key = M.toHex(await M.memkey(entry.id, pin.signPub, pin.dhPub));
                if (key === entry.memkey) out.push({ id: entry.id, memkey: key });
            }
            return out;
        }

        // Подтверждение вручную после принятия нового ключа (9.7): во всех комнатах, где участник есть в списке и
        // нет живого намерения входа. Вызывается из acceptPeerIdentityChange внутри его блокировки.
        async function trustAfterAcceptLocked(peerId, usernameOf) {
            const rooms = [];
            for (const name of await storage.keys('members:')) {
                const roomId = name.slice('members:'.length);
                const members = await storage.get(name);
                if (!Array.isArray(members) || !members.some(p => Number(p.id) === peerId)) continue;
                if ((await storage.get(names.intent(roomId))) !== null) continue;
                const trusted = await readTrusted(roomId);
                if (!trusted.bootstrapDone) continue;
                const pin = (await loadPins([peerId])).get(peerId);
                if (!pin || pin.pending) continue;
                const list = trusted.list.filter(e => e.id !== peerId);
                list.push({
                    id: peerId, username: usernameOf ? usernameOf(members, peerId) : '', memkey: M.toHex(await M.memkey(peerId, pin.signPub, pin.dhPub)),
                    status: 'confirmed', how: 'manual', by: null, certHash: null, since: nowMin(),
                });
                await storage.set(names.trusted(roomId), { bootstrapDone: true, list: list.sort((a, b) => a.id - b.id) });
                rooms.push(roomId);
            }
            return rooms;
        }

        // Комнаты, где участник указан в списке сервера (для проверки правила ротации на уровне человека, 9.1).
        async function roomsWithMemberLocked(peerId) {
            const out = [];
            for (const name of await storage.keys('members:')) {
                const members = await storage.get(name);
                if (Array.isArray(members) && members.some(p => Number(p.id) === peerId)) out.push(name.slice('members:'.length));
            }
            return out;
        }

        // Собственный выход из комнаты (5.6): локальные записи состава стираются, повторный вход начинается заново.
        async function forgetRoomLocked(roomId) {
            let removed = 0;
            for (const name of [
                names.trusted(roomId), names.removed(roomId), names.revouch(roomId), names.intent(roomId),
                names.viewPending(roomId), names.inviteSecret(roomId),
            ]) {
                if ((await storage.get(name)) !== null) { await storage.delete(name); removed++; }
            }
            for (const prefix of [names.viewDivPrefix(roomId), names.deliveredPrefix(roomId), names.viewNoticePrefix(roomId)]) {
                for (const name of await storage.keys(prefix)) { await storage.delete(name); removed++; }
            }
            return removed;
        }

        // Сервер ответил invite: null (поворот, выключение, выход автора): секрет устройства больше не нужен (5.6).
        async function noteServerInvite(roomId, inviteB64) {
            if (inviteB64) return;
            await dropInviteSecret(roomId);
        }

        return {
            names,
            loadPins, planCertFetch, fetchCerts, verifyLocked, appendDeliveredLocked, journalRotationReasonLocked,
            computeViewLocked, encodeView, noteViewLocked, runViewChecks,
            noteRoomCreated, signApproval, signInvite, getInviteSecret, dropInviteSecret, prepareJoin, completeJoin,
            cancelJoinIntent, getJoinIntent, trustMember, vouchForMember, publishDueRevouches, nextRevouchDueMs,
            getMembers, isTrustedMember, currentRecipientsLocked, trustAfterAcceptLocked, roomsWithMemberLocked,
            forgetRoomLocked, noteServerInvite, meLocked,
        };
    }

    return Object.freeze({ createMembershipClient, parseViewField, parseCertItems, normalizeRevouch, MAX_REVOUCH_TASKS, normalizeTrusted, normalizeRemoved, normalizeIntent, names, REF_HOWS, HOWS });
});
