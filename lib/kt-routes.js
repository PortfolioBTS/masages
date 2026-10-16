'use strict';
// Маршруты журнала ключей /api/kt/* (docs/security/key-transparency.md, 6.5).
// Требуют сессию. Корни и головы (head, roots) хэши ничего не раскрывают —
// отдаются любому вошедшему; записи (proof, self) — владельцу, участнику общей
// комнаты и одобряющему для заявителя с открытой заявкой (ревью К12).
//
// Маршрут «корни поколения» назван roots: в черновике контракта его имя содержало слово
// из правила test/forbidden-terms (этап 2, голос и аудио), а обходить правило ради
// имени пути не стоит.
//
// Без ключа журнала маршруты отвечают 503 { code:'kt-disabled' }, кроме head: он
// отвечает 200 { enabled:false, code:'kt-disabled' } — клиент спрашивает head при
// каждом запуске, и штатно выключенный журнал не должен давать ошибку в консоли
// браузера. Клиент, никогда не видевший журнал, считает это «проверка
// недоступна»; клиент, уже видевший журнал, — тревогой (раздел 7.3), поэтому
// признак ответа стабилен.
//
// Лимиты — по образцу выдачи bundle (lib/e2ee-keys.js, lib/pg-limits.js):
// скользящее окно в час. Сбой хранилища лимита закрывает его (503 busy).

const { createSlidingWindowCounter } = require('./e2ee-keys');

const HOUR_MS = 60 * 60 * 1000;
// Заголовки и корни: клиент проверяет журнал на каждом ensureRoomSession (не чаще раза в
// 30 секунд) и раз в час, а новое поколение докачивает одним-двумя запросами корней.
const LOG_LIMIT_PER_CALLER = 600;
// Доказательства: по одному на собеседника и проверку; на пару «кто — чей» их мало.
const PROOF_LIMIT_PER_CALLER = 400;
const PROOF_LIMIT_PER_PAIR = 60;
// Самомониторинг: первый запуск — до шести запросов по 200 эпох, дальше по одному в час.
const SELF_LIMIT_PER_CALLER = 120;
const PG_INT_MAX = 2147483647;

const BUSY = { success: false, code: 'busy', message: 'Сервис сейчас занят. Повторите попытку через несколько секунд.' };

const b64 = (buf) => Buffer.from(buf).toString('base64');

function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    next();
}

// Целое из строки запроса: только цифры, не больше PG_INT_MAX. undefined — параметра нет, null — не число.
function intParam(value, { min = 0, max = PG_INT_MAX } = {}) {
    if (value === undefined) return undefined;
    if (typeof value !== 'string' || !/^\d{1,10}$/.test(value)) return null;
    const n = Number(value);
    return n >= min && n <= max ? n : null;
}

function encodeProof(proof) {
    return { entries: proof.entries.map(b64), bitmap: b64(proof.bitmap), siblings: proof.siblings.map(b64) };
}

// deps: { dbGet, kt, limiter, joinRequestLiveSql } — limiter с tryConsume(lockKey, rules) (lib/pg-limits.js,
// slidingLimiter); без него (юнит-тесты) счётчики в памяти. joinRequestLiveSql() — условие «заявка жива».
function registerKtRoutes(app, deps) {
    const { dbGet, kt, limiter, joinRequestLiveSql } = deps || {};
    if (typeof dbGet !== 'function' || !kt) throw new TypeError('registerKtRoutes(app, { dbGet, kt }): нужны dbGet и kt');

    const memory = new Map();
    function counter(name, max) {
        const key = name + ':' + max;
        if (!memory.has(key)) memory.set(key, createSlidingWindowCounter(HOUR_MS, max));
        return memory.get(key);
    }

    // true — можно (слот занят этим запросом); иначе ответ уже отправлен.
    async function consume(res, userId, rules) {
        if (limiter) {
            let result;
            try {
                result = await limiter.tryConsume(String(userId), rules.map(r => ({ key: r.key, max: r.max })));
            } catch {
                res.set('Retry-After', '5');
                res.status(503).json(BUSY);
                return false;
            }
            const wait = Math.max(0, ...result.waitMs);
            if (wait > 0) return refuse(res, wait);
            return true;
        }
        const nowMs = Date.now();
        const counters = rules.map(r => counter(r.key.split(':')[0], r.max));
        const wait = Math.max(0, ...rules.map((r, i) => counters[i].waitMs(r.key, nowMs)));
        if (wait > 0) return refuse(res, wait);
        rules.forEach((r, i) => counters[i].hit(r.key, nowMs));
        return true;
    }

    function refuse(res, waitMs) {
        const seconds = Math.ceil(waitMs / 1000);
        res.set('Retry-After', String(seconds));
        res.status(429).json({ success: false, code: 'rate-limited', message: `Слишком много запросов к журналу ключей. Повторите через ${Math.max(1, Math.ceil(seconds / 60))} мин.` });
        return false;
    }

    function guard(handler) {
        return async (req, res) => {
            if (!kt.enabled) {
                return res.status(503).json({ success: false, code: 'kt-disabled', message: 'Журнал ключей на сервере выключен' });
            }
            try {
                await handler(req, res);
            } catch (error) {
                console.error('[KT] Ошибка маршрута журнала:', error.message);
                if (!res.headersSent) res.status(500).json({ success: false, message: 'Ошибка журнала ключей' });
            }
        };
    }

    const notFound = (res) => res.status(404).json({ success: false, code: 'kt-not-found', message: 'Нет такого поколения или эпохи' });

    app.get('/api/kt/head', requireAuth, (req, res, next) => {
        if (!kt.enabled) return res.json({ success: true, enabled: false, code: 'kt-disabled' });
        next();
    }, guard(async (req, res) => {
        const userId = Number(req.session.userId);
        if (!(await consume(res, userId, [{ key: `log:${userId}`, max: LOG_LIMIT_PER_CALLER }]))) return;
        const head = await kt.getHead();
        // Журнал включён, но ни одна эпоха ещё не закрыта (первый час после включения).
        if (!head) return res.status(503).json({ success: false, code: 'kt-not-ready', message: 'Журнал ключей запускается' });
        res.json({
            success: true,
            pub: b64(head.pub), gen: head.gen, epoch: head.epoch, head: b64(head.head), sig: b64(head.sig),
            genStart: head.genStart, prevFinalHead: b64(head.prevFinalHead),
            keychange: head.keychange.map(c => ({ oldPub: b64(c.oldPub), newPub: b64(c.newPub), gen: c.gen, epoch: c.epoch, sig: b64(c.sig) })),
        });
    }));

    app.get('/api/kt/roots', requireAuth, guard(async (req, res) => {
        const userId = Number(req.session.userId);
        const gen = intParam(req.query.gen, { min: 1 });
        const from = intParam(req.query.from);
        const limit = intParam(req.query.limit, { min: 1 });
        if (typeof gen !== 'number' || from === null || limit === null) {
            return res.status(400).json({ success: false, message: 'Некорректные параметры' });
        }
        if (!(await consume(res, userId, [{ key: `log:${userId}`, max: LOG_LIMIT_PER_CALLER }]))) return;
        const result = await kt.getRoots(gen, from === undefined ? 0 : from, limit === undefined ? 1000 : limit);
        if (!result) return notFound(res);
        res.json({
            success: true,
            gen: result.gen, genStart: result.genStart, prevFinalHead: b64(result.prevFinalHead), from: result.from,
            roots: result.roots.map(b64),
            last: result.last ? { epoch: result.last.epoch, head: b64(result.last.head), sig: b64(result.last.sig) } : null,
        });
    }));

    // Чужое доказательство: сам, участник общей комнаты или одобряющий для заявителя с живой заявкой.
    async function mayReadProof(me, target) {
        if (me === target) return true;
        const shared = await dbGet(
            'SELECT 1 FROM room_participants a JOIN room_participants b ON a.room_id = b.room_id WHERE a.user_id = $1 AND b.user_id = $2 LIMIT 1',
            [me, target]
        );
        if (shared) return true;
        if (typeof joinRequestLiveSql !== 'function') return false;
        const applicant = await dbGet(
            `SELECT 1 FROM join_requests jr JOIN room_participants rp ON rp.room_id = jr.room_id
             WHERE jr.user_id = $1 AND rp.user_id = $2 AND jr.${joinRequestLiveSql()} LIMIT 1`,
            [target, me]
        );
        return Boolean(applicant);
    }

    app.get('/api/kt/proof', requireAuth, guard(async (req, res) => {
        const me = Number(req.session.userId);
        const target = intParam(req.query.user, { min: 1 });
        const gen = intParam(req.query.gen, { min: 1 });
        const epoch = intParam(req.query.epoch);
        if (typeof target !== 'number' || typeof gen !== 'number' || typeof epoch !== 'number') {
            return res.status(400).json({ success: false, message: 'Некорректные параметры' });
        }
        // Один ответ на «нет доступа» и «нет такого пользователя»: идентификатор не проверяется перебором.
        if (!(await mayReadProof(me, target))) {
            return res.status(403).json({ success: false, code: 'forbidden', message: 'Нет доступа к записям этого пользователя' });
        }
        if (!(await consume(res, me, [
            { key: `proof:${me}`, max: PROOF_LIMIT_PER_CALLER },
            { key: `proofpair:${me}:${target}`, max: PROOF_LIMIT_PER_PAIR },
        ]))) return;
        const proof = await kt.getProof(target, gen, epoch);
        if (!proof) return notFound(res);
        res.json({ success: true, ...encodeProof(proof) });
    }));

    app.get('/api/kt/self', requireAuth, guard(async (req, res) => {
        const me = Number(req.session.userId);
        const gen = intParam(req.query.gen, { min: 1 });
        const from = intParam(req.query.from);
        const limit = intParam(req.query.limit, { min: 1 });
        if (typeof gen !== 'number' || from === null || limit === null) {
            return res.status(400).json({ success: false, message: 'Некорректные параметры' });
        }
        if (!(await consume(res, me, [{ key: `self:${me}`, max: SELF_LIMIT_PER_CALLER }]))) return;
        const result = await kt.getSelfProofs(me, gen, from === undefined ? 0 : from, limit === undefined ? 200 : limit);
        if (!result) return notFound(res);
        res.json({
            success: true,
            proofs: result.proofs.map(p => ({ epoch: p.epoch, ...encodeProof(p) })),
            next: result.next,
        });
    }));
}

module.exports = { registerKtRoutes, intParam };
