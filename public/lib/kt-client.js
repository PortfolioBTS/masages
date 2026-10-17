// Клиент журнала ключей: состояние на устройстве, сеть, проверки
// (docs/security/key-transparency.md, разделы 7 и 11). Формулы и разбор доказательств —
// в public/lib/kt.js; здесь — то, что хранит и спрашивает клиент.
//
//   1. syncLog          — журнал только растёт: цепочка от последней проверенной головы,
//                         ключ журнала закреплён (TOFU), заявления о смене, длина поколения
//                         и льготный срок (7.2, 11);
//   2. проверка ключа   — ключ собеседника входит в журнал; отсутствие доказательства у
//                         клиента, видевшего журнал, — pending, а через 3 закрытые эпохи
//                         или 4 часа mismatch, а не «недоступно» (7.3);
//   3. самомониторинг   — владелец сканирует весь сохранённый журнал под своей меткой (7.4);
//   4. сплетни          — головы журнала из SKDM сверяются с собственной цепочкой (7.5).
//
// Сеть никогда не вызывается внутри withLock клиента (7.6): секции блокировки только
// пишут задачи в kt:queue и результаты; проверки идут в runKtChecks вне блокировки.
// Функции *Locked вызываются ТОЛЬКО изнутри withLock (они сами блокировку не берут).
//
// Файл исполняется в браузере (window.NyxoKtClient) и в Node (тесты); хранилище, сеть,
// часы и блокировка внедряются.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./kt.js'));
    } else {
        root.NyxoKtClient = factory(root.NyxoKt);
    }
})(typeof self !== 'undefined' ? self : this, function (Kt) {
    'use strict';

    const HOUR_MS = 60 * 60 * 1000;
    // pending → mismatch: три закрытые эпохи без доказательства либо 4 часа (7.3, п. 6).
    const PENDING_EPOCHS = 3;
    const PENDING_MS = 4 * HOUR_MS;
    // Голова журнала, полученная меньше стольких мс назад, повторно не запрашивается.
    const SYNC_FRESH_MS = 30 * 1000;
    // Самомониторинг: не чаще раза в 20 минут (7.4).
    const SELF_MIN_INTERVAL_MS = 20 * 60 * 1000;
    // Паузы повтора при сетевой ошибке, секунды (7.3, п. 2).
    const RETRY_STEPS_S = [1, 2, 4, 8, 16, 32, 64, 128, 256, 300];
    const MAX_QUEUE = 200;
    const MAX_ALERTS = 20;
    const MAX_PROMISES = 200;
    const MAX_ACKED = 200;
    const SELF_BATCH = 200;
    const U32_MAX = 0xFFFFFFFF;
    // Тревоги, после которых журнал считается несогласованным (checkTransparency → inconsistent).
    const INCONSISTENT_KINDS = Object.freeze(['log-fork', 'equivocation', 'bad-signature', 'key-changed', 'key-split', 'log-disabled']);

    const hex = Kt.toHex;
    const u8 = (text, len) => Kt.b64decode(text, len);
    const isUint = (n, max = U32_MAX) => Number.isSafeInteger(n) && n >= 0 && n <= max;
    const posOf = (gen, epoch) => ({ gen, epoch });

    // ---------- Ключ журнала из манифеста релиза (R10) ----------

    const MANIFEST_PATH = '/client-manifest.json';
    const MANIFEST_TIMEOUT_MS = 8000;

    // Открытый ключ журнала из манифеста клиента (keys.kt, docs/security/key-transparency.md, раздел 11):
    // строка base64 или null — манифеста нет, в нём нет ключа (журнал выключен или релиз без ключа) или он не разбирается.
    // Любая неудача — null, а не ошибка: сверка с манифестом — дополнительная защита, а не условие работы журнала;
    // ключ, который не удалось сверить, закрепляется как раньше (TOFU). Сеть: тот же источник, что и сам клиент.
    // Честно: манифест приходит с того же сервера, что и журнал; сверка ловит рассинхрон (релиз и сервер с разными
    // ключами) и подмену ключа в обход релиза, а против сервера, подменившего и клиент, и манифест, не защищает
    // (docs/threat-model.md): ценность даёт service worker, закрепивший манифест, и сверка с опубликованным релизом.
    async function fetchManifestKey(fetchImpl, options = {}) {
        const doFetch = fetchImpl || (typeof fetch === 'function' ? fetch : null);
        if (!doFetch) return null;
        try {
            const init = { cache: 'no-store', credentials: 'omit', redirect: 'error' };
            if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') init.signal = AbortSignal.timeout(options.timeoutMs || MANIFEST_TIMEOUT_MS);
            const response = await doFetch(options.url || MANIFEST_PATH, init);
            if (!response || !response.ok) return null;
            return manifestKeyFromText(await response.text());
        } catch {
            return null;
        }
    }

    // Ключ из текста манифеста: каноническое base64 ровно 32 байт, строгая проверка точки (малый порядок и т.п.).
    function manifestKeyFromText(text) {
        if (typeof text !== 'string' || text.length > 4 * 1024 * 1024) return null;
        let data;
        try { data = JSON.parse(text); } catch { return null; }
        const value = data && data.keys && typeof data.keys === 'object' ? data.keys.kt : null;
        if (typeof value !== 'string') return null;
        const bytes = Kt.b64decode(value, 32);
        return bytes && Kt.isValidLogKey(bytes) ? value : null;
    }

    // ---------- Разбор ответов сервера (всё, что пришло, проверяется по форме) ----------

    function parseHead(data) {
        if (!data || typeof data !== 'object') return null;
        const pub = u8(data.pub, 32);
        const head = u8(data.head, 32);
        const sig = u8(data.sig, 64);
        const prevFinalHead = u8(data.prevFinalHead, 32);
        if (!pub || !head || !sig || !prevFinalHead) return null;
        if (!isUint(data.gen) || data.gen < 1 || !isUint(data.epoch) || !isUint(data.genStart) || data.genStart > data.epoch) return null;
        const keychange = [];
        if (data.keychange !== undefined) {
            if (!Array.isArray(data.keychange) || data.keychange.length > 64) return null;
            for (const item of data.keychange) {
                const claim = parseClaim(item);
                if (!claim) return null;
                keychange.push(claim);
            }
        }
        return { pub, gen: data.gen, epoch: data.epoch, head, sig, genStart: data.genStart, prevFinalHead, keychange };
    }

    function parseClaim(item) {
        if (!item || typeof item !== 'object') return null;
        const oldPub = u8(item.oldPub, 32);
        const newPub = u8(item.newPub, 32);
        const sig = u8(item.sig, 64);
        if (!oldPub || !newPub || !sig || !isUint(item.gen) || item.gen < 1 || !isUint(item.epoch)) return null;
        return { oldPub, newPub, gen: item.gen, epoch: item.epoch, sig };
    }

    // { entries, bitmap, siblings } как Uint8Array либо null.
    function parseProof(data) {
        if (!data || typeof data !== 'object' || !Array.isArray(data.entries) || !Array.isArray(data.siblings)) return null;
        if (data.entries.length > Kt.MAX_ENTRIES_PER_LEAF || data.siblings.length > Kt.DEPTH) return null;
        const bitmap = u8(data.bitmap, 16);
        if (!bitmap) return null;
        const entries = [];
        for (const e of data.entries) {
            const c = u8(e, 32);
            if (!c) return null;
            entries.push(c);
        }
        const siblings = [];
        for (const s of data.siblings) {
            const h = u8(s, 32);
            if (!h) return null;
            siblings.push(h);
        }
        return { entries, bitmap, siblings };
    }

    // kt из ответа сервера по ключам пользователя: { gen, epoch, nonce, skt } либо null.
    function parseHint(raw) {
        if (!raw || typeof raw !== 'object') return null;
        const nonce = u8(raw.nonce, 16);
        if (!nonce || !isUint(raw.gen) || raw.gen < 1 || !isUint(raw.epoch)) return null;
        let skt = null;
        if (raw.skt !== null && raw.skt !== undefined) {
            skt = u8(raw.skt, 64);
            if (!skt) return null;
        }
        return { gen: raw.gen, epoch: raw.epoch, nonce, skt };
    }

    // Подсказка в SKDM (ext.kt = { g, e, h, s }): строгая форма либо null.
    function parseGossip(raw) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        const h = u8(raw.h, 32);
        const s = u8(raw.s, 64);
        if (!h || !s || !isUint(raw.g) || raw.g < 1 || !isUint(raw.e)) return null;
        return { g: raw.g, e: raw.e, h, s };
    }

    // ---------- Клиент ----------

    // options:
    //   storage, transport (ktHead/ktRoots/ktProof/ktSelf → { status, data }), withLock, now, getUserId,
    //   getIdentity() → { signPub, dhPub (base64), createdHour } | null,
    //   onAlert(alert), warn, schedule(fn, ms), manifestKey() → base64 | null (ключ журнала из манифеста релиза, R10),
    //   genEpochs, graceEpochs, epochSeconds — константы протокола (тесты задают меньшие).
    function createLogClient(options) {
        const { storage, transport, withLock } = options;
        const now = typeof options.now === 'function' ? options.now : () => Date.now();
        const warn = typeof options.warn === 'function' ? options.warn : (...args) => console.warn(...args);
        const genEpochs = options.genEpochs || Kt.GEN_EPOCHS;
        const graceEpochs = options.graceEpochs || Kt.GRACE_EPOCHS;
        const epochSeconds = options.epochSeconds || Kt.EPOCH_SECONDS;
        const schedule = typeof options.schedule === 'function' ? options.schedule : (fn, ms) => {
            const timer = setTimeout(fn, ms);
            if (timer && typeof timer.unref === 'function') timer.unref();
            return timer;
        };
        const localEpoch = () => Math.floor(now() / 1000 / epochSeconds);

        const supported = () => Boolean(transport) && typeof transport.ktHead === 'function'
            && typeof transport.ktRoots === 'function' && typeof transport.ktProof === 'function' && typeof transport.ktSelf === 'function';

        // Вызов сети: { res } либо { error } (отказ fetch, таймаут, нетипизированная ошибка).
        async function call(method, ...args) {
            try {
                const res = await transport[method](...args);
                if (!res || typeof res.status !== 'number') return { error: new Error('нет ответа') };
                return { res };
            } catch (error) {
                return { error };
            }
        }
        const body = (res) => (res && res.data && typeof res.data === 'object' ? res.data : {});
        // Ответы, которые не повод для вывода о журнале: сеть, шлюз, лимит запросов.
        const transient = (res) => res.status >= 500 || res.status === 429 || res.status === 408 || res.status === 0;

        // ---------- Хранилище ----------

        async function readPins() {
            const list = await storage.get('kt:pub');
            if (!Array.isArray(list)) return [];
            return list.filter(p => p && typeof p.pub === 'string' && p.from && isUint(p.from.gen) && isUint(p.from.epoch));
        }
        const writePinsLocked = (pins) => storage.set('kt:pub', pins);

        const genKey = (gen) => 'kt:gen:' + gen;
        const genCache = new Map(); // gen -> { rec, roots }

        function decodeRoots(rec) {
            const cached = genCache.get(rec.genStart + ':' + rec.headEpoch + ':' + rec.head);
            if (cached) return cached;
            const roots = rec.roots.map(r => u8(r, 32));
            if (roots.some(r => !r)) return null;
            const decoded = { roots, head: u8(rec.head, 32), sig: u8(rec.sig, 64), prevFinalHead: u8(rec.prevFinalHead, 32) };
            if (!decoded.head || !decoded.sig || !decoded.prevFinalHead) return null;
            genCache.set(rec.genStart + ':' + rec.headEpoch + ':' + rec.head, decoded);
            return decoded;
        }

        async function readGen(gen) {
            const rec = await storage.get(genKey(gen));
            if (!rec || !isUint(rec.genStart) || !Array.isArray(rec.roots) || !isUint(rec.headEpoch)) return null;
            if (rec.headEpoch !== rec.genStart + rec.roots.length - 1) return null;
            const decoded = decodeRoots(rec);
            return decoded ? { gen, rec, ...decoded } : null;
        }

        async function storedGens() {
            const names = await storage.keys('kt:gen:');
            const gens = [];
            for (const name of names) {
                const n = Number(name.slice('kt:gen:'.length));
                if (isUint(n) && n >= 1) gens.push(n);
            }
            return gens.sort((a, b) => a - b);
        }

        // Самая свежая подтверждённая голова: { gen, epoch, head, sig } либо null.
        async function latestHead() {
            const gens = await storedGens();
            for (let i = gens.length - 1; i >= 0; i--) {
                const g = await readGen(gens[i]);
                if (g) return { gen: g.gen, epoch: g.rec.headEpoch, head: g.head, sig: g.sig, genStart: g.rec.genStart };
            }
            return null;
        }

        function packGen(gen, genStart, prevFinalHead, roots, headBytes, sig) {
            return {
                genStart, prevFinalHead: Kt.b64encode(prevFinalHead), roots: roots.map(Kt.b64encode),
                head: Kt.b64encode(headBytes), headEpoch: genStart + roots.length - 1, sig: Kt.b64encode(sig),
            };
        }

        // ---------- Тревоги ----------

        async function readAlerts() {
            const list = await storage.get('kt:alerts');
            return Array.isArray(list) ? list : [];
        }

        // Вне withLock. Одна и та же тревога (вид + ключ) записывается один раз; callback — только для новой.
        async function addAlert(kind, detail = {}, key = '') {
            const id = kind + ':' + key;
            let fresh = false;
            await withLock(async () => {
                const list = await readAlerts();
                if (list.some(a => a.id === id)) return;
                list.push({ id, kind, at: now(), detail });
                while (list.length > MAX_ALERTS) list.shift();
                await storage.set('kt:alerts', list);
                fresh = true;
            });
            if (fresh && typeof options.onAlert === 'function') {
                try { options.onAlert({ kind, ...detail }); } catch (error) { warn('Журнал ключей: onTransparencyAlert упал:', error); }
            }
            return fresh;
        }

        async function clearAlerts(kinds) {
            await withLock(async () => {
                const list = await readAlerts();
                const rest = list.filter(a => !kinds.includes(a.kind));
                if (rest.length !== list.length) await storage.set('kt:alerts', rest);
            });
        }

        // ---------- Ключ журнала и синхронизация (7.2, раздел 11) ----------

        function keyFor(pins, gen, epoch) {
            for (let i = pins.length - 1; i >= 0; i--) {
                if (Kt.comparePos(pins[i].from, posOf(gen, epoch)) <= 0) return u8(pins[i].pub, 32);
            }
            return pins.length > 0 ? u8(pins[0].pub, 32) : null;
        }

        let syncInFlight = null;
        let lastSync = null; // { at, result }

        // Результат: { ok: true, head, pins } | { ok: false, reason: 'unavailable' | 'disabled' | 'network' | 'alert' }.
        function syncLog({ force = false } = {}) {
            if (syncInFlight) return syncInFlight;
            if (!force && lastSync && lastSync.result.ok && now() - lastSync.at < SYNC_FRESH_MS) return Promise.resolve(lastSync.result);
            syncInFlight = doSync().then((result) => {
                lastSync = { at: now(), result };
                return result;
            }).finally(() => { syncInFlight = null; });
            return syncInFlight;
        }

        async function doSync() {
            if (!supported()) return { ok: false, reason: 'unavailable' };
            let pins = await readPins();
            const logSeen = pins.length > 0;
            const { res, error } = await call('ktHead');
            if (error) return { ok: false, reason: 'network' };
            const data = body(res);
            // Журнал выключен или маршрута нет: для клиента, видевшего журнал, это тревога, а не «недоступно».
            if ((res.status === 200 && data.enabled === false) || (res.status === 503 && data.code === 'kt-disabled') || res.status === 404) {
                if (!logSeen) return { ok: false, reason: 'unavailable' };
                await addAlert('log-disabled', { status: res.status });
                return { ok: false, reason: 'disabled' };
            }
            if (res.status === 503 && data.code === 'kt-not-ready') {
                return logSeen ? { ok: false, reason: 'network' } : { ok: false, reason: 'unavailable' };
            }
            if (transient(res)) return { ok: false, reason: 'network' };
            if (res.status !== 200 || data.success !== true) {
                warn('Журнал ключей: неожиданный ответ /api/kt/head:', res.status);
                return { ok: false, reason: 'network' };
            }
            const head = parseHead(data);
            if (!head) {
                warn('Журнал ключей: ответ /api/kt/head не той формы');
                return { ok: false, reason: 'network' };
            }
            // Журнал снова отвечает — прежняя тревога «журнал отключён» снимается.
            if (logSeen) await clearAlerts(['log-disabled']);

            // --- Закрепление и смена ключа журнала ---
            const pinOutcome = await resolvePins(pins, head);
            if (!pinOutcome.ok) return { ok: false, reason: 'alert' };
            pins = pinOutcome.pins;

            // --- Подпись головы ---
            const signer = keyFor(pins, head.gen, head.epoch);
            if (!signer || !(await Kt.verifyEd25519(signer, Kt.sthMessage(head.gen, head.epoch, head.head), head.sig))) {
                await addAlert('bad-signature', { gen: head.gen, epoch: head.epoch, head: Kt.b64encode(head.head), sig: Kt.b64encode(head.sig) }, head.gen + ':' + head.epoch);
                return { ok: false, reason: 'alert' };
            }
            // Подпись верна: ключ закреплён (TOFU) только теперь, после проверки подписью.
            if (!logSeen || pinOutcome.changed) await withLock(() => writePinsLocked(pins));

            // --- Цепочка ---
            const chain = await extendChains(pins, head);
            if (!chain.ok) return { ok: false, reason: chain.reason };
            // Голова отстаёт от текущей эпохи на 3 и больше: журнал не обновляется — предупреждение, не блокировка (7.2).
            if (localEpoch() - head.epoch >= PENDING_EPOCHS) noteStale(head.epoch);
            return { ok: true, head, pins };
        }

        // Предупреждение stale: не хранится и не делает журнал «несогласованным»; один раз на значение эпохи.
        let staleReported = null;
        function noteStale(epoch) {
            if (staleReported === epoch) return;
            staleReported = epoch;
            if (typeof options.onAlert !== 'function') return;
            try { options.onAlert({ kind: 'stale', epoch, behind: localEpoch() - epoch }); } catch (error) { warn('Журнал ключей: onTransparencyAlert упал:', error); }
        }

        // Закрепление TOFU и принятие заявлений о смене. { ok, pins, changed }.
        async function resolvePins(pins, head) {
            const serverPub = Kt.b64encode(head.pub);
            if (pins.length === 0) {
                if (!Kt.isValidLogKey(head.pub)) {
                    await addAlert('bad-signature', { reason: 'bad-log-key', pub: serverPub }, 'log-key');
                    return { ok: false };
                }
                // Манифест релиза (R10) — второй источник ключа: несовпадение — тревога.
                if (typeof options.manifestKey === 'function') {
                    let fromManifest = null;
                    try { fromManifest = await options.manifestKey(); } catch { fromManifest = null; }
                    if (typeof fromManifest === 'string' && fromManifest !== '' && fromManifest !== serverPub) {
                        await withLock(() => storage.set('kt:newkey', { pub: serverPub, seenAt: now() }));
                        await addAlert('key-changed', { reason: 'manifest', pub: serverPub, expected: fromManifest }, serverPub);
                        return { ok: false };
                    }
                }
                return { ok: true, pins: [{ pub: serverPub, from: posOf(0, 0) }], changed: true };
            }
            const last = pins[pins.length - 1];
            // Два разных заявления одним прежним ключом — двуличие (раздел 11), даже если ключ уже закреплён.
            const split = await findClaimConflict(pins, head.keychange);
            if (split) return { ok: false };
            if (last.pub === serverPub) return { ok: true, pins, changed: false };

            // Цепочка заявлений от закреплённого ключа к ключу сервера.
            const latest = await latestHead();
            const result = pins.slice();
            let changed = false;
            let current = last;
            for (let guard = 0; guard < 64 && current.pub !== serverPub; guard++) {
                const claim = head.keychange.find(c => Kt.b64encode(c.oldPub) === current.pub);
                if (!claim) break;
                const valid = Kt.isValidLogKey(claim.newPub)
                    && await Kt.verifyEd25519(u8(current.pub, 32), Kt.keychangeMessage(claim.newPub, claim.gen, claim.epoch), claim.sig);
                if (!valid) {
                    await addAlert('key-changed', { reason: 'bad-claim', pub: serverPub, oldPub: current.pub }, serverPub);
                    await withLock(() => storage.set('kt:newkey', { pub: serverPub, seenAt: now() }));
                    return { ok: false };
                }
                // Заявление датировано строго позже любой головы, принятой по прежнему ключу.
                if (latest && Kt.comparePos(posOf(claim.gen, claim.epoch), posOf(latest.gen, latest.epoch)) <= 0) {
                    await addAlert('key-changed', { reason: 'backdated', pub: serverPub, claimGen: claim.gen, claimEpoch: claim.epoch }, serverPub);
                    await withLock(() => storage.set('kt:newkey', { pub: serverPub, seenAt: now() }));
                    return { ok: false };
                }
                current = {
                    pub: Kt.b64encode(claim.newPub), from: posOf(claim.gen, claim.epoch),
                    claim: { oldPub: Kt.b64encode(claim.oldPub), newPub: Kt.b64encode(claim.newPub), gen: claim.gen, epoch: claim.epoch, sig: Kt.b64encode(claim.sig) },
                };
                result.push(current);
                changed = true;
            }
            if (current.pub !== serverPub) {
                // Заявления нет: новый ключ принимается только вручную (раздел 11).
                await withLock(() => storage.set('kt:newkey', { pub: serverPub, seenAt: now() }));
                await addAlert('key-changed', { reason: 'no-claim', pub: serverPub, pinned: last.pub }, serverPub);
                return { ok: false };
            }
            return { ok: true, pins: result, changed };
        }

        // Заявления одним ключом на разные newPub/(g, e) — доказательство двуличия. Сравнивается и
        // со списком сервера, и с заявлениями, принятыми раньше (они лежат в kt:pub).
        async function findClaimConflict(pins, claims) {
            const known = [];
            for (const p of pins) if (p.claim) known.push(p.claim);
            const all = known.concat(claims.map(c => ({
                oldPub: Kt.b64encode(c.oldPub), newPub: Kt.b64encode(c.newPub), gen: c.gen, epoch: c.epoch, sig: Kt.b64encode(c.sig),
            })));
            for (let i = 0; i < all.length; i++) {
                for (let j = i + 1; j < all.length; j++) {
                    const a = all[i];
                    const b = all[j];
                    if (a.oldPub !== b.oldPub) continue;
                    if (a.newPub === b.newPub && a.gen === b.gen && a.epoch === b.epoch) continue;
                    const okA = await Kt.verifyEd25519(u8(a.oldPub, 32), Kt.keychangeMessage(u8(a.newPub, 32), a.gen, a.epoch), u8(a.sig, 64));
                    const okB = await Kt.verifyEd25519(u8(b.oldPub, 32), Kt.keychangeMessage(u8(b.newPub, 32), b.gen, b.epoch), u8(b.sig, 64));
                    if (okA && okB) {
                        await addAlert('equivocation', { reason: 'keychange', claims: [a, b] }, 'keychange:' + a.oldPub);
                        return true;
                    }
                }
            }
            return false;
        }

        async function saveGen(gen, genStart, prevFinalHead, roots, headBytes, sig) {
            const rec = packGen(gen, genStart, prevFinalHead, roots, headBytes, sig);
            await withLock(() => storage.set(genKey(gen), rec));
            return rec;
        }

        // Докачка корней поколения gen с эпохи from по эпоху until включительно.
        // { roots, genStart, prevFinalHead } | { notFound: true } | { network: true } | { fork: причина }.
        async function fetchRoots(gen, from, until) {
            const roots = [];
            let meta = null;
            let last = null;
            let cursor = from;
            while (cursor <= until) {
                const { res, error } = await call('ktRoots', gen, cursor, Math.min(1000, until - cursor + 1));
                if (error) return { network: true };
                if (res.status === 404) return { notFound: true };
                const data = body(res);
                if (transient(res) || res.status !== 200 || data.success !== true) return { network: true };
                const prevFinalHead = u8(data.prevFinalHead, 32);
                if (!Array.isArray(data.roots) || !prevFinalHead || !isUint(data.genStart) || !isUint(data.from) || data.roots.length > 1000) return { network: true };
                last = data.last && isUint(data.last.epoch) && u8(data.last.head, 32) && u8(data.last.sig, 64)
                    ? { epoch: data.last.epoch, head: u8(data.last.head, 32), sig: u8(data.last.sig, 64) } : null;
                const page = data.roots.map(r => u8(r, 32));
                if (page.some(r => !r)) return { network: true };
                if (meta && (meta.genStart !== data.genStart || hex(meta.prevFinalHead) !== hex(prevFinalHead))) return { fork: 'genesis-changed' };
                meta = { genStart: data.genStart, prevFinalHead };
                if (page.length === 0) break;
                if (data.from !== cursor) return { fork: 'gap' };
                roots.push(...page);
                cursor += page.length;
            }
            return { roots, last, genStart: meta ? meta.genStart : null, prevFinalHead: meta ? meta.prevFinalHead : null };
        }

        async function logFork(reason, detail) {
            await addAlert('log-fork', { reason, ...detail }, reason + ':' + (detail.gen || '') + ':' + (detail.epoch || ''));
            return { ok: false, reason: 'alert' };
        }

        // Продление цепочки до подписанной головы head, связь поколений, константы протокола.
        async function extendChains(pins, head) {
            const gen = head.gen;
            let current = await readGen(gen);

            if (current && (current.rec.genStart !== head.genStart || hex(current.prevFinalHead) !== hex(head.prevFinalHead))) {
                return logFork('genesis-changed', { gen, epoch: head.epoch });
            }
            if (current && head.epoch < current.rec.headEpoch) {
                // Сервер показывает голову старше уже виденной подписанной: откат (доказательство — наша голова с подписью).
                return logFork('rollback', {
                    gen, epoch: head.epoch, mine: { gen, epoch: current.rec.headEpoch, head: current.rec.head, sig: current.rec.sig },
                    theirs: { gen, epoch: head.epoch, head: Kt.b64encode(head.head), sig: Kt.b64encode(head.sig) },
                });
            }
            if (current && head.epoch === current.rec.headEpoch) {
                if (hex(current.head) !== hex(head.head)) {
                    // Две подписанные головы одной эпохи — двуличие.
                    await addAlert('equivocation', {
                        reason: 'same-epoch', gen, epoch: head.epoch,
                        mine: { head: current.rec.head, sig: current.rec.sig }, theirs: { head: Kt.b64encode(head.head), sig: Kt.b64encode(head.sig) },
                    }, gen + ':' + head.epoch);
                    return { ok: false, reason: 'alert' };
                }
            } else {
                let roots;
                let prev;
                let from;
                if (current) {
                    const got = await fetchRoots(gen, current.rec.headEpoch + 1, head.epoch);
                    if (got.network) return { ok: false, reason: 'network' };
                    if (got.notFound) return logFork('grace-violated', { gen, epoch: head.epoch });
                    if (got.fork) return logFork(got.fork, { gen, epoch: head.epoch });
                    if (got.roots.length !== head.epoch - current.rec.headEpoch) return logFork('chain-short', { gen, epoch: head.epoch });
                    roots = current.roots.concat(got.roots);
                    prev = current.head;
                    from = current.rec.headEpoch + 1;
                    const heads = Kt.extendChain(prev, gen, from, got.roots);
                    if (hex(heads[heads.length - 1]) !== hex(head.head)) return logFork('chain-mismatch', { gen, epoch: head.epoch });
                } else {
                    const got = await fetchRoots(gen, head.genStart, head.epoch);
                    if (got.network) return { ok: false, reason: 'network' };
                    if (got.notFound) return logFork('chain-short', { gen, epoch: head.epoch });
                    if (got.fork) return logFork(got.fork, { gen, epoch: head.epoch });
                    if (got.genStart !== head.genStart || hex(got.prevFinalHead) !== hex(head.prevFinalHead) || got.roots.length !== head.epoch - head.genStart + 1) {
                        return logFork('chain-short', { gen, epoch: head.epoch });
                    }
                    roots = got.roots;
                    const genesis = Kt.genesisHash(gen, head.prevFinalHead);
                    const heads = Kt.extendChain(genesis, gen, head.genStart, roots);
                    if (hex(heads[heads.length - 1]) !== hex(head.head)) return logFork('chain-mismatch', { gen, epoch: head.epoch });
                }
                await saveGen(gen, head.genStart, head.prevFinalHead, roots, head.head, head.sig);
            }

            // Предыдущее поколение: цепочка дотянута до конца, genesis ссылается на её последнюю голову, длина — 720.
            const gens = await storedGens();
            const previous = gens.filter(g => g < gen).pop();
            if (previous !== undefined && previous === gen - 1) {
                const linked = await linkPrevious(pins, previous, head);
                if (!linked.ok) return linked;
            }
            // Старше предыдущего не храним.
            const stale = gens.filter(g => g < gen - 1);
            if (stale.length > 0) {
                await withLock(async () => { for (const g of stale) await storage.delete(genKey(g)); });
                genCache.clear();
            }
            return { ok: true };
        }

        // Связь поколений gen − 1 и gen = head.gen (7.2): длина поколения — константа, цепочка
        // предыдущего дотянута до конца, а genesis следующего ссылается на её последнюю голову.
        async function linkPrevious(pins, previousGen, head) {
            const gen = head.gen;
            const prev = await readGen(previousGen);
            if (!prev) return { ok: true };
            if (head.genStart - prev.rec.genStart !== genEpochs) {
                return logFork('generation-length', { gen, epoch: head.epoch, length: head.genStart - prev.rec.genStart });
            }
            const lastOfPrev = head.genStart - 1;
            if (prev.rec.headEpoch > lastOfPrev) return logFork('generation-length', { gen: previousGen, epoch: prev.rec.headEpoch });
            let finalHead = prev.head;
            if (prev.rec.headEpoch < lastOfPrev) {
                // Предыдущее поколение не дотянуто до конца: докачиваем, пока сервер обязан его отдавать.
                const got = await fetchRoots(previousGen, prev.rec.headEpoch + 1, lastOfPrev);
                if (got.network) return { ok: false, reason: 'network' };
                if (got.notFound) {
                    if (head.epoch <= head.genStart + graceEpochs) return logFork('grace-violated', { gen: previousGen, epoch: head.epoch });
                    // Срок вышел: непрерывность потеряна без нарушения (раздел 12, строка 11).
                    await withLock(() => storage.delete(genKey(previousGen)));
                    genCache.clear();
                    return { ok: true };
                }
                if (got.fork) return logFork(got.fork, { gen: previousGen, epoch: head.epoch });
                if (got.roots.length !== lastOfPrev - prev.rec.headEpoch) return logFork('chain-short', { gen: previousGen, epoch: head.epoch });
                const heads = Kt.extendChain(prev.head, previousGen, prev.rec.headEpoch + 1, got.roots);
                finalHead = heads[heads.length - 1];
                if (hex(finalHead) !== hex(head.prevFinalHead)) return logFork('prev-final-head', { gen, epoch: head.epoch });
                // Сохраняем дотянутую цепочку, если пришла подписанная голова её конца.
                const signed = got.last;
                if (signed && signed.epoch === lastOfPrev && hex(signed.head) === hex(finalHead)
                    && await Kt.verifyEd25519(keyFor(pins, previousGen, lastOfPrev), Kt.sthMessage(previousGen, lastOfPrev, signed.head), signed.sig)) {
                    await saveGen(previousGen, prev.rec.genStart, prev.prevFinalHead, prev.roots.concat(got.roots), signed.head, signed.sig);
                }
                return { ok: true };
            }
            if (hex(finalHead) !== hex(head.prevFinalHead)) return logFork('prev-final-head', { gen, epoch: head.epoch });
            return { ok: true };
        }

        // ---------- Проверка ключа собеседника (7.3) ----------

        // Задача 'peer': { kind, u, signPub, dhPub, kt }. Результат: { retry: true } либо { status, reason, evidence? }.
        async function evaluatePeer(task, sync) {
            if (!sync.ok) {
                if (sync.reason === 'network') return { retry: true };
                // Клиент, никогда не видевший журнал: единственный случай 'unavailable' (7.3, п. 1).
                if (sync.reason === 'unavailable') return { status: 'unavailable' };
                // Журнал отключён/несогласован у клиента, видевшего его: «нет доказательства» (п. 2, 4).
                return { status: 'pending', reason: 'no-proof' };
            }
            const hint = task.kt ? parseHint(task.kt) : null;
            if (!hint) return { status: 'pending', reason: 'no-proof' };
            const signPub = u8(task.signPub, 32);
            const dhPub = u8(task.dhPub, 32);
            if (!signPub || !dhPub) return { status: 'pending', reason: 'no-proof' };
            const commit = Kt.commit(task.u, signPub, dhPub, hint.nonce);
            const label = Kt.label(task.u);
            const held = await readGen(hint.gen);
            const latest = await latestHead();
            // Эпоха открыта: она новее последней закрытой известной голове этого поколения (для более нового
            // поколения, чем мы знаем, после свежего syncLog — тоже открыта).
            const open = held ? hint.epoch > held.rec.headEpoch : Boolean(latest) && hint.gen > latest.gen;
            if (open) {
                const signer = keyFor(sync.pins, hint.gen, hint.epoch);
                if (hint.skt && signer && await Kt.verifyEd25519(signer, Kt.sktMessage(hint.gen, hint.epoch, label, commit), hint.skt)) {
                    return { status: 'pending', reason: 'open-epoch', evidence: { skt: Kt.b64encode(hint.skt), gen: hint.gen, epoch: hint.epoch } };
                }
                return { status: 'pending', reason: 'no-proof' };
            }
            if (!held) return { status: 'pending', reason: 'no-proof' }; // поколение вне окна хранения
            const { res, error } = await call('ktProof', task.u, hint.gen, hint.epoch);
            if (error) return { retry: true };
            if (transient(res)) return { retry: true };
            const data = body(res);
            if (res.status !== 200 || data.success !== true) return { status: 'pending', reason: 'no-proof' };
            const proof = parseProof(data);
            const root = held.roots[hint.epoch - held.rec.genStart];
            // Ответ не той формы для закрытой эпохи с известным корнем — mismatch (раздел 12, строка 13).
            const bad = (reason) => ({ status: 'mismatch', reason, evidence: hint.skt ? { skt: Kt.b64encode(hint.skt), gen: hint.gen, epoch: hint.epoch } : undefined });
            if (!proof || !root) return bad('bad-proof');
            const folded = Kt.proofRoot(label, proof.entries, proof.bitmap, proof.siblings);
            if (!folded || hex(folded) !== hex(root)) return bad('bad-proof');
            if (proof.entries.some(c => hex(c) === hex(commit))) return { status: 'ok' };
            return bad('not-in-log');
        }

        // Короткая секция: записать результат в peer:<id>.kt, если закрепление не менялось за время запроса.
        // true — результат применён.
        async function applyPeerResult(task, result) {
            return withLock(async () => {
                const name = 'peer:' + task.u;
                const pin = await storage.get(name);
                if (!pin || pin.pending || pin.signPub !== task.signPub || pin.dhPub !== task.dhPub) return false;
                const prev = pin.kt && pin.kt.for === ktFor(pin) ? pin.kt : null;
                const latest = await latestHead();
                const headEpoch = latest ? latest.epoch : null;
                const kt = { status: result.status, reason: result.reason || null, for: ktFor(pin) };
                if (task.kt && isUint(task.kt.gen)) { kt.gen = task.kt.gen; kt.epoch = task.kt.epoch; }
                if (result.status === 'pending' || result.status === 'mismatch') {
                    // since — момент, когда ключ стал pending; не сбрасывается, пока ключ не подтверждён (иначе
                    // сервер, меняя nonce, держал бы его в pending вечно).
                    const since = prev && (prev.status === 'pending' || prev.status === 'mismatch') && prev.since ? { ...prev.since } : { headEpoch, at: now() };
                    if (since.headEpoch === null || since.headEpoch === undefined) since.headEpoch = headEpoch;
                    kt.since = since;
                    // Три закрытые эпохи без доказательства либо 4 часа (если голова не продвигается).
                    const epochsPassed = since.headEpoch !== null && headEpoch !== null ? headEpoch - since.headEpoch : 0;
                    if (result.status === 'pending' && (epochsPassed >= PENDING_EPOCHS || now() - since.at >= PENDING_MS)) {
                        kt.status = 'mismatch';
                        kt.reason = 'no-proof-timeout';
                    }
                }
                // Доказательство нарушения обещания (SKT) сохраняется.
                if (result.evidence) kt.evidence = result.evidence;
                else if (prev && prev.evidence && kt.status !== 'ok') kt.evidence = prev.evidence;
                if (kt.status === 'mismatch' && prev && prev.override) kt.override = true;
                pin.kt = kt;
                await storage.set(name, pin);
                return true;
            });
        }

        const ktFor = (pin) => pin.signPub + ':' + pin.dhPub;

        // ---------- Очередь задач (7.6) ----------

        async function readQueue() {
            const list = await storage.get('kt:queue');
            return Array.isArray(list) ? list : [];
        }

        function enqueueLocked(queue, task) {
            const same = (t) => t.kind === task.kind && (task.kind === 'peer' ? t.u === task.u
                : task.kind === 'gossip' ? t.id === task.id : true);
            const i = queue.findIndex(same);
            if (i >= 0) queue[i] = task; else queue.push(task);
            while (queue.length > MAX_QUEUE) queue.shift();
        }

        // В withLock: ключ собеседника закреплён или проверен сервером; ставит задачу и пометку pending.
        async function notePeerLocked(peerId, ktHint) {
            if (!supported()) return;
            const name = 'peer:' + peerId;
            const pin = await storage.get(name);
            if (!pin || pin.pending) return;
            const same = pin.kt && pin.kt.for === ktFor(pin);
            if (same && pin.kt.status === 'ok') return; // неизменное закрепление, ключ проверен: перепроверка не нужна
            const pins = await readPins();
            if (!same && pins.length > 0) {
                // Пометка «ждёт подтверждения»; since.headEpoch уточнит первая проверка.
                const latest = await latestHead();
                pin.kt = { status: 'pending', reason: 'no-proof', for: ktFor(pin), since: { headEpoch: latest ? latest.epoch : null, at: now() } };
                await storage.set(name, pin);
            }
            const queue = await readQueue();
            enqueueLocked(queue, { kind: 'peer', u: Number(peerId), signPub: pin.signPub, dhPub: pin.dhPub, kt: ktHint || null });
            await storage.set('kt:queue', queue);
        }

        // В withLock: головa журнала из SKDM — отложенная сверка.
        async function noteGossipLocked(raw) {
            if (!supported()) return;
            const gossip = parseGossip(raw);
            if (!gossip) return;
            const id = gossip.g + ':' + gossip.e + ':' + hex(gossip.h);
            const queue = await readQueue();
            enqueueLocked(queue, { kind: 'gossip', id, g: gossip.g, e: gossip.e, h: Kt.b64encode(gossip.h), s: Kt.b64encode(gossip.s) });
            await storage.set('kt:queue', queue);
        }

        // В withLock: подсказка kt из ответа сервера по моим собственным ключам (PUT identity).
        async function noteOwnLocked(ktHint) {
            if (!supported()) return;
            const state = await readSelf();
            state.inbox = ktHint && typeof ktHint === 'object' ? ktHint : null;
            await storage.set('kt:self', state);
            const queue = await readQueue();
            enqueueLocked(queue, { kind: 'self' });
            await storage.set('kt:queue', queue);
        }

        // Голова для SKDM: последняя проверенная подписанная голова либо null (в withLock или без).
        async function gossipHead() {
            const latest = await latestHead();
            if (!latest) return null;
            return { g: latest.gen, e: latest.epoch, h: Kt.b64encode(latest.head), s: Kt.b64encode(latest.sig) };
        }

        // ---------- Сплетни (7.5) ----------

        // Голова журнала из SKDM: подпись по закреплённым ключам, затем сверка с нашей цепочкой для ЛЮБОЙ
        // пары (g, e), корни которой есть локально. { retry } | { done }.
        async function evaluateGossip(task, sync) {
            const h = u8(task.h, 32);
            const s = u8(task.s, 64);
            if (!h || !s) return { done: true };
            let pins = await readPins();
            if (pins.length === 0) {
                // Журнал ещё не виден: без закреплённого ключа подпись проверить нечем.
                if (!sync.ok) return sync.reason === 'network' ? { retry: true } : { done: true };
                pins = sync.pins;
            }
            let signer = keyFor(pins, task.g, task.e);
            let valid = signer ? await Kt.verifyEd25519(signer, Kt.sthMessage(task.g, task.e, h), s) : false;
            if (!valid) {
                // Возможно, мы отстали от заявления о смене ключа: сначала syncLog.
                const fresh = await syncLog({ force: true });
                if (!fresh.ok && fresh.reason === 'network') return { retry: true };
                pins = fresh.ok ? fresh.pins : await readPins();
                signer = keyFor(pins, task.g, task.e);
                valid = signer ? await Kt.verifyEd25519(signer, Kt.sthMessage(task.g, task.e, h), s) : false;
                if (!valid) {
                    await addAlert('key-split', {
                        sent: { g: task.g, e: task.e, h: task.h, s: task.s }, pinned: pins.map(p => ({ pub: p.pub, from: p.from })),
                    }, task.g + ':' + task.e);
                    return { done: true };
                }
            }
            let held = await readGen(task.g);
            let covered = Boolean(held) && task.e >= held.rec.genStart && task.e <= held.rec.headEpoch;
            if (!covered) {
                const latest = await latestHead();
                const newer = !latest || Kt.comparePos(posOf(task.g, task.e), posOf(latest.gen, latest.epoch)) > 0;
                if (!newer) return { done: true }; // старше окна хранения — игнорируем
                // Эпоха новее нашей головы: цепочка сервера обязана дать присланную голову.
                const fresh = await syncLog({ force: true });
                if (!fresh.ok) return fresh.reason === 'network' ? { retry: true } : { done: true };
                held = await readGen(task.g);
                covered = Boolean(held) && task.e >= held.rec.genStart && task.e <= held.rec.headEpoch;
                if (!covered) {
                    await addAlert('equivocation', { reason: 'behind', theirs: { g: task.g, e: task.e, h: task.h, s: task.s } }, task.g + ':' + task.e);
                    return { done: true };
                }
            }
            const heads = Kt.extendChain(Kt.genesisHash(task.g, held.prevFinalHead), task.g, held.rec.genStart,
                held.roots.slice(0, task.e - held.rec.genStart + 1));
            if (hex(heads[heads.length - 1]) !== hex(h)) {
                // Верная подпись под иной головой той же эпохи — двуличие. Сохраняем пару: чужая подписанная
                // голова и наша цепочка с подписью последней головы.
                await addAlert('equivocation', {
                    reason: 'gossip', theirs: { g: task.g, e: task.e, h: task.h, s: task.s },
                    mine: { g: task.g, e: held.rec.headEpoch, h: held.rec.head, s: held.rec.sig, chainFrom: held.rec.genStart, roots: held.rec.roots.length },
                }, task.g + ':' + task.e);
            }
            return { done: true };
        }

        // ---------- Самомониторинг (7.4) ----------

        const emptySelf = () => ({ commits: [], scanned: null, acked: [], alert: null, inbox: null, currentNonce: null, lastScanAt: 0 });

        async function readSelf() {
            const state = await storage.get('kt:self');
            return state && typeof state === 'object' ? { ...emptySelf(), ...state } : emptySelf();
        }

        function myCommit(identity, nonce) {
            const signPub = u8(identity.signPub, 32);
            const dhPub = u8(identity.dhPub, 32);
            if (!signPub || !dhPub) return null;
            return Kt.commit(Number(options.getUserId()), signPub, dhPub, nonce);
        }

        // Шаг 0 самомониторинга: обещание (SKT) из ответа сервера на регистрацию моих ключей. Подпись проверяется
        // закреплённым ключом журнала; верное обещание запоминается, неверное — тревога bad-signature.
        async function absorbOwn(sync, identity) {
            const raw = await withLock(async () => {
                const state = await readSelf();
                const inbox = state.inbox;
                state.inbox = null;
                await storage.set('kt:self', state);
                return inbox;
            });
            const hint = raw ? parseHint(raw) : null;
            if (!hint) return;
            const commit = myCommit(identity, hint.nonce);
            if (!commit) return;
            let promise = null;
            if (hint.skt) {
                const label = Kt.label(Number(options.getUserId()));
                const signer = keyFor(sync.pins, hint.gen, hint.epoch);
                if (signer && await Kt.verifyEd25519(signer, Kt.sktMessage(hint.gen, hint.epoch, label, commit), hint.skt)) {
                    promise = { c: hex(commit), nonce: Kt.b64encode(hint.nonce), gen: hint.gen, epoch: hint.epoch, skt: Kt.b64encode(hint.skt) };
                } else {
                    await addAlert('bad-signature', { reason: 'own-skt', gen: hint.gen, epoch: hint.epoch, skt: Kt.b64encode(hint.skt) }, 'own-skt:' + hint.gen + ':' + hint.epoch);
                }
            }
            await withLock(async () => {
                const state = await readSelf();
                // nonce текущих ключей — из ответа сервера: после потери kt:self текущие ключи тревоги не вызывают.
                state.currentNonce = Kt.b64encode(hint.nonce);
                if (promise && !state.commits.some(p => p.c === promise.c && p.gen === promise.gen && p.epoch === promise.epoch)) {
                    state.commits.push(promise);
                    while (state.commits.length > MAX_PROMISES) state.commits.shift();
                }
                await storage.set('kt:self', state);
            });
        }

        // Сканирование всего сохранённого журнала под моей меткой (весь сохранённый журнал, не «с момента
        // регистрации»: сервер сам выдаёт идентификаторы и мог записать обязательство до регистрации).
        // { network: true }, если часть эпох не удалось получить (повтор позже).
        async function scanSelf(sync, { scan }) {
            const identity = options.getIdentity ? await options.getIdentity() : null;
            const userId = options.getUserId ? Number(options.getUserId()) : 0;
            if (!identity || !userId) return {};
            await absorbOwn(sync, identity);
            if (!scan) return {};
            const state = await readSelf();
            const label = Kt.label(userId);
            const currentCommit = state.currentNonce ? myCommit(identity, u8(state.currentNonce, 16)) : null;
            const currentHex = currentCommit ? hex(currentCommit) : null;
            // Допустимые обязательства — только три набора: сохранённые обещания, отмеченные пользователем и
            // обязательство моих ТЕКУЩИХ ключей с nonce от сервера. Чужой nonce делает обязательство чужим.
            const allowed = new Set(state.commits.map(p => p.c).concat(state.acked.map(a => a.c)));
            if (currentHex) allowed.add(currentHex);

            const foreign = [];
            const missing = [];
            let progress = state.scanned;
            let network = false;
            for (const gen of await storedGens()) {
                if (progress && gen < progress.gen) continue;
                const held = await readGen(gen);
                if (!held) continue;
                let from = progress && progress.gen === gen ? progress.epoch + 1 : held.rec.genStart;
                while (from <= held.rec.headEpoch) {
                    const { res, error } = await call('ktSelf', gen, from, SELF_BATCH);
                    if (error) { network = true; break; }
                    if (res.status === 404) break; // поколение уже не отдаётся (срок вышел)
                    const data = body(res);
                    if (transient(res) || res.status !== 200 || data.success !== true || !Array.isArray(data.proofs)) { network = true; break; }
                    if (data.proofs.length === 0) break;
                    let expected = from;
                    let badProof = false;
                    for (const item of data.proofs) {
                        if (!item || item.epoch !== expected || expected > held.rec.headEpoch) { badProof = true; break; }
                        const proof = parseProof(item);
                        const root = held.roots[expected - held.rec.genStart];
                        const folded = proof && Kt.proofRoot(label, proof.entries, proof.bitmap, proof.siblings);
                        if (!folded || hex(folded) !== hex(root)) { badProof = true; break; }
                        const present = new Set(proof.entries.map(hex));
                        for (const c of present) if (!allowed.has(c)) foreign.push({ c, gen, epoch: expected });
                        for (const p of state.commits) {
                            if (p.gen === gen && p.epoch === expected && !present.has(p.c)) missing.push({ c: p.c, gen, epoch: expected, skt: p.skt, reason: 'skt' });
                        }
                        // Перенос (6.4): в первой эпохе поколения — обязательство моих текущих ключей, если они зарегистрированы раньше.
                        if (expected === held.rec.genStart && currentHex && !present.has(currentHex)) {
                            const origin = state.commits.filter(p => p.c === currentHex).map(p => p.gen);
                            if (origin.length > 0 && Math.min(...origin) < gen && !missing.some(m => m.c === currentHex && m.gen === gen && m.epoch === expected)) {
                                missing.push({ c: currentHex, gen, epoch: expected, reason: 'carry-over' });
                            }
                        }
                        progress = posOf(gen, expected);
                        expected++;
                    }
                    if (badProof) {
                        await addAlert('log-fork', { reason: 'self-proof', gen, epoch: expected }, 'self-proof:' + gen + ':' + expected);
                        network = true; // не засчитываем эпохи с неверным доказательством; повтор не поможет, но и не затираем прогресс
                        break;
                    }
                    from = expected;
                    const saved = progress;
                    await withLock(async () => {
                        const s = await readSelf();
                        s.scanned = saved;
                        await storage.set('kt:self', s);
                    });
                    if (data.next === null || data.next === undefined) break;
                }
                if (network) break;
            }

            if (foreign.length > 0) {
                const created = identity.createdHour === undefined ? null : identity.createdHour;
                await withLock(async () => {
                    const s = await readSelf();
                    s.alert = { kind: 'self-foreign-entry', entries: foreign, createdHour: created, at: now() };
                    await storage.set('kt:self', s);
                });
                await addAlert('self-foreign-entry', { entries: foreign, identityCreatedHour: created }, foreign.map(f => f.c + ':' + f.epoch).join(','));
            }
            for (const m of missing) {
                await addAlert('self-missing', { ...m }, m.c + ':' + m.gen + ':' + m.epoch + ':' + m.reason);
            }
            if (!network) {
                await withLock(async () => {
                    const s = await readSelf();
                    s.lastScanAt = now();
                    await storage.set('kt:self', s);
                });
            }
            return { network };
        }

        // Пользователь подтвердил, что часть обязательств — его прежние ключи («Это были мои прежние ключи»).
        async function ackSelfEntries(list) {
            const chosen = (Array.isArray(list) ? list : []).filter(e => e && typeof e.c === 'string' && isUint(e.epoch));
            await withLock(async () => {
                const state = await readSelf();
                for (const e of chosen) {
                    if (!state.acked.some(a => a.c === e.c)) state.acked.push({ c: e.c, epoch: e.epoch });
                }
                while (state.acked.length > MAX_ACKED) state.acked.shift();
                const done = new Set(state.acked.map(a => a.c));
                if (state.alert) {
                    state.alert.entries = state.alert.entries.filter(e => !done.has(e.c));
                    if (state.alert.entries.length === 0) state.alert = null;
                }
                await storage.set('kt:self', state);
                const alerts = (await readAlerts()).map(a => {
                    if (a.kind !== 'self-foreign-entry') return a;
                    return { ...a, detail: { ...a.detail, entries: a.detail.entries.filter(e => !done.has(e.c)) } };
                }).filter(a => a.kind !== 'self-foreign-entry' || a.detail.entries.length > 0);
                await storage.set('kt:alerts', alerts);
            });
        }

        // ---------- Запуск проверок (7.6) ----------

        let running = null;
        let rerun = false;
        let retryStep = 0;
        let retryTimer = null;
        let selfRequested = false;
        let timerHandle = null;

        function scheduleRetry() {
            if (retryTimer) return;
            const delay = RETRY_STEPS_S[Math.min(retryStep, RETRY_STEPS_S.length - 1)] * 1000;
            retryStep++;
            retryTimer = schedule(() => {
                retryTimer = null;
                return runKtChecks().catch(error => warn('Журнал ключей: повтор проверок не удался:', error));
            }, delay);
        }

        function requestSelfScan() { selfRequested = true; }

        // Одна очередь за раз; вызовы во время работы склеиваются в повторный проход.
        function runKtChecks() {
            if (!supported()) return Promise.resolve();
            if (running) {
                rerun = true;
                return running;
            }
            running = (async () => {
                try {
                    do {
                        rerun = false;
                        await pass();
                    } while (rerun);
                } finally {
                    running = null;
                }
            })();
            return running;
        }

        async function pass() {
            const queue = await readQueue();
            // Обещание из ответа сервера на регистрацию (inbox) ждёт, пока журнал не станет виден, и разбирается тогда.
            const wantSelf = selfRequested || queue.some(t => t.kind === 'self') || Boolean((await readSelf()).inbox);
            // Голова журнала запрашивается при каждом запуске (вход в комнату, таймер, явный вызов), даже если задач нет:
            // иначе откат, двуличие и переписанная история были бы видны только тем, у кого есть неподтверждённые ключи.

            // Свежая голова нужна всякий раз, когда ключ собеседника ещё не подтверждён (задача 'peer' есть только для
            // них): pending меняется, только когда голова продвинулась. Для остальных задач — если спрашивают об эпохе новее известной.
            const latest = await latestHead();
            const needFresh = !latest || wantSelf || queue.some(t => t.kind === 'peer'
                || (t.kind === 'gossip' && (t.g > latest.gen || (t.g === latest.gen && t.e > latest.epoch))));
            const sync = await syncLog({ force: needFresh });
            let retry = !sync.ok && sync.reason === 'network';

            for (const task of queue) {
                if (task.kind === 'self') continue;
                try {
                    const result = task.kind === 'peer' ? await evaluatePeer(task, sync) : await evaluateGossip(task, sync);
                    if (result.retry) { retry = true; continue; }
                    if (task.kind === 'peer') await applyPeerResult(task, result);
                    await removeTask(task);
                } catch (error) {
                    warn('Журнал ключей: проверка не удалась:', error);
                    retry = true;
                }
            }

            if (wantSelf) {
                if (sync.ok) {
                    try {
                        selfRequested = false;
                        const state = await readSelf();
                        const due = state.lastScanAt === 0 || now() - state.lastScanAt >= SELF_MIN_INTERVAL_MS;
                        const done = await scanSelf(sync, { scan: due });
                        if (done.network) retry = true;
                        await removeTask({ kind: 'self' });
                    } catch (error) {
                        warn('Журнал ключей: самомониторинг не удался:', error);
                        retry = true;
                    }
                } else if (sync.reason !== 'network') {
                    selfRequested = false;
                    await removeTask({ kind: 'self' });
                }
            }
            if (retry) scheduleRetry();
            else retryStep = 0;
        }

        async function removeTask(task) {
            await withLock(async () => {
                const queue = await readQueue();
                const rest = queue.filter(t => !(t.kind === task.kind && (task.kind === 'peer' ? t.u === task.u && t.signPub === task.signPub && t.dhPub === task.dhPub
                    : task.kind === 'gossip' ? t.id === task.id : true)));
                if (rest.length !== queue.length) await storage.set('kt:queue', rest);
            });
        }

        // Таймер закрытия эпохи: раз в час проверки идут заново (и самомониторинг).
        function startTimers() {
            if (timerHandle || !supported()) return;
            const tick = () => {
                requestSelfScan();
                timerHandle = schedule(tick, HOUR_MS);
                return runKtChecks().catch(error => warn('Журнал ключей: плановая проверка не удалась:', error));
            };
            timerHandle = schedule(tick, HOUR_MS);
        }

        function stopTimers() {
            if (timerHandle && typeof globalThis.clearTimeout === 'function') globalThis.clearTimeout(timerHandle);
            timerHandle = null;
            if (retryTimer && typeof globalThis.clearTimeout === 'function') globalThis.clearTimeout(retryTimer);
            retryTimer = null;
        }

        // ---------- Состояние для интерфейса ----------

        async function checkTransparency() {
            const pins = await readPins();
            const alerts = await readAlerts();
            const bad = alerts.filter(a => INCONSISTENT_KINDS.includes(a.kind));
            const state = await readSelf();
            const peers = [];
            for (const name of await storage.keys('peer:')) {
                const pin = await storage.get(name);
                if (pin && pin.kt && pin.kt.status) peers.push({ userId: Number(name.slice('peer:'.length)), status: pin.kt.status });
            }
            const selfAlerts = alerts.filter(a => a.kind === 'self-foreign-entry' || a.kind === 'self-missing');
            let self = 'unknown';
            if (selfAlerts.length > 0) self = 'alert';
            else if (state.scanned) self = 'ok';
            let status = 'ok';
            if (bad.length > 0) status = 'inconsistent';
            else if (pins.length === 0) status = 'unavailable';
            return { status, peers, self };
        }

        async function getAlerts() {
            return (await readAlerts()).map(a => ({ kind: a.kind, at: a.at, ...a.detail }));
        }

        async function dismissAlerts(kinds) {
            await clearAlerts(Array.isArray(kinds) ? kinds : [kinds]);
        }

        // Ключ журнала, который сервер показывает вместо закреплённого (раздел 11).
        async function getPendingLogKey() {
            const found = await storage.get('kt:newkey');
            if (!found || typeof found.pub !== 'string') return null;
            const pub = u8(found.pub, 32);
            if (!pub) return null;
            const pins = await readPins();
            return { pub: found.pub, hex: hex(pub), pinned: pins.length > 0 ? pins[pins.length - 1].pub : null, seenAt: found.seenAt };
        }

        // Пользователь сверил отпечаток с опубликованным релизом: принять новый ключ, сбросить цепочки (раздел 11).
        async function acceptLogKey() {
            const found = await getPendingLogKey();
            if (!found || !Kt.isValidLogKey(u8(found.pub, 32))) return false;
            await withLock(async () => {
                await storage.set('kt:pub', [{ pub: found.pub, from: posOf(0, 0) }]);
                for (const name of await storage.keys('kt:gen:')) await storage.delete(name);
                const state = await readSelf();
                state.scanned = null;
                await storage.set('kt:self', state);
                await storage.delete('kt:newkey');
            });
            genCache.clear();
            lastSync = null;
            await clearAlerts(INCONSISTENT_KINDS);
            return true;
        }

        // Проверка ключа по данным сервера без закрепления (одобряющий проверяет заявителя до вступления).
        async function checkKeys(userId, signPubB64, dhPubB64, ktHint) {
            const sync = await syncLog();
            return evaluatePeer({ kind: 'peer', u: Number(userId), signPub: signPubB64, dhPub: dhPubB64, kt: ktHint || null }, sync);
        }

        return {
            supported, syncLog, runKtChecks, notePeerLocked, noteGossipLocked, noteOwnLocked, gossipHead, requestSelfScan,
            startTimers, stopTimers, checkTransparency, getAlerts, dismissAlerts, ackSelfEntries,
            getPendingLogKey, acceptLogKey, checkKeys, latestHead,
            _internal: { parseHead, parseHint, parseGossip, parseProof, readPins },
        };
    }

    return { createLogClient, fetchManifestKey, manifestKeyFromText, parseHint, parseGossip, parseHead, INCONSISTENT_KINDS, PENDING_EPOCHS, PENDING_MS };
});
