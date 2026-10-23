// Форматы данных ядра E2EE (roadmap R14, T6.4): разбор и сборка конвертов, SKDM и содержимого сообщения,
// метки доменов и AAD. Вынесено дословно из public/e2ee.js (разделы «Форматы конвертов» и «Содержимое
// сообщения v2»):
//   - подпись и AAD: pqOneTimeSigInput, sigInputV3, msgAadV3, skdmAadV2 (и метки доменов);
//   - разбор недоверенного ввода: parseShareEnvelope, parseSkdm, parseSkdmExt, parseKtGossip,
//     canonicalSigningKey (ключ подписи проходит строгую проверку Ed25519);
//   - сборка: buildSkdm; содержимое сообщения: encodeContent, decodeContent, isValidMessageId;
//   - размеры ML-KEM-768 (PQ_*_BYTES), предел ext (MAX_EXT_CHARS), предел полей файла (MAX_FILE_FIELD).
// Здесь нет ни хранилища, ни сети, ни состояния клиента. Зависимости: e2ee-codec.js, ed25519-strict.js и
// membership-client.js (разбор поля view в ext). Файл исполняется и в браузере (window.NyxoE2eeFormats,
// подключается до e2ee.js), и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./e2ee-codec.js'), require('./ed25519-strict.js'), require('./membership-client.js'));
    } else {
        root.NyxoE2eeFormats = factory(root.NyxoE2eeCodec, root.NyxoEd25519Strict, root.NyxoMembershipClient);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, ed25519Strict, membershipClient) {
    'use strict';

    const {
        b64decode, b64decodeCanonical, decodeFixed, canonicalPubKey, utf8encode, utf8decode, concatBytes,
        u32be, u64be, isKeyId, isCanonicalKeyId,
    } = Codec;

    // ---- Размеры: поля файла в содержимом, ML-KEM-768 ----

    const MAX_FILE_FIELD = 1024;

    const PQ_PUBLIC_KEY_BYTES = 1184;
    const PQ_CIPHERTEXT_BYTES = 1088;
    const PQ_SEED_BYTES = 64;

    // ===================== Форматы конвертов =====================

    // Подпись одноразового PQ-prekey: Ed25519(IK, метка ‖ u64be(key_id) ‖ pk).
    // Метка и привязка к key_id отличают её от подписи SPK (32 байта) и PQ
    // last-resort («сырые» 1184 байта): сервер не может выдать один вид ключа
    // за другой, а подпись нельзя перенести на другой key_id. Все части
    // фиксированной длины (14 + 8 + 1184).
    const PQ_OPK_LABEL = utf8encode('nyxo-pqopk-v1\0');
    function pqOneTimeSigInput(keyId, publicKey) {
        return concatBytes(PQ_OPK_LABEL, u64be(keyId), publicKey);
    }

    // Подпись конверта сообщения комнаты (версия 3): Ed25519(ключ подписи Sender Key, sigInputV3).
    //   sigInput = "nyxo-skmsg-v3\0" ‖ u32be(roomId) ‖ senderKeyId[16] ‖ u32be(iteration) ‖ iv[12] ‖ ct
    // Метка домена (реестр меток, план криптографии 1.1) отличает эту подпись от любой другой подписи
    // Ed25519 в системе, а комната входит в подписанные байты: конверт, снятый с одной комнаты, не
    // подходит к другой, даже если сервер подсунул чужой индекс отправителей. Все поля до ct —
    // фиксированной длины (14 + 4 + 16 + 4 + 12 = 50 байт), ct (не короче 272 байт) идёт последним:
    // два разных набора полей не дают одну и ту же строку. senderKeyId берётся сырыми 16 байтами,
    // а не текстом base64, поэтому каноничность записи на подпись не влияет. Прежняя версия
    // (iv ‖ ct ‖ iteration ‖ keyId без метки и комнаты) не принимается: R0, конвертов v2 нет.
    const SKMSG_LABEL = utf8encode('nyxo-skmsg-v3\0');

    function sigInputV3(roomId, senderKeyIdBytes, iteration, iv, ct) {
        return concatBytes(SKMSG_LABEL, u32be(roomId), senderKeyIdBytes, u32be(iteration), iv, ct);
    }

    function msgAadV3(roomId, senderId, senderKeyId) {
        return utf8encode('senderkey-v3:' + roomId + ':' + senderId + ':' + senderKeyId);
    }

    // AD key-share v2: помимо комнаты и направления — identity-ключи обеих
    // сторон (требование X3DH: AD = IK_A ‖ IK_B). Подмена identity любой из
    // сторон ломает AEAD, даже если сессионный ключ каким-то образом совпал.
    function skdmAadV2(roomId, senderUserId, recipientUserId, senderSignPub, senderDhPub, recipientSignPub, recipientDhPub) {
        return concatBytes(
            utf8encode('nyxo-skdm-v2:' + roomId + ':' + senderUserId + ':' + recipientUserId),
            b64decode(senderSignPub), b64decode(senderDhPub),
            b64decode(recipientSignPub), b64decode(recipientDhPub)
        );
    }

    // Конверт key-share v2: { v:2, type:'skdm', n, iv, ct, init:{...} }.
    // Заголовок PQXDH (init) повторяется в каждой передаче сессии: получатель
    // узнаёт сессию по эфемерному ключу, а если первая передача потерялась
    // (или была отложена до подтверждения смены identity) — выводит её из
    // заголовка любой следующей.
    function parseShareEnvelope(ciphertext) {
        let env;
        try { env = JSON.parse(ciphertext); } catch { return null; }
        if (!env || typeof env !== 'object' || env.v !== 2 || env.type !== 'skdm') return null;
        if (!Number.isSafeInteger(env.n) || env.n < 0) return null;
        const iv = decodeFixed(env.iv, 12);
        const ct = typeof env.ct === 'string' ? b64decodeCanonical(env.ct) : null;
        if (!iv || !ct || ct.length < 16) return null;
        const h = env.init;
        if (!h || typeof h !== 'object') return null;
        const signPub = canonicalSigningKey(h.senderIdentitySignPub);
        const dhPub = canonicalPubKey(h.senderIdentityDhPub);
        const eph = canonicalPubKey(h.senderEphemeralPub);
        const opkId = h.usedOneTimePrekeyId === null || h.usedOneTimePrekeyId === undefined ? null : h.usedOneTimePrekeyId;
        // Без PQ-части заголовок не принимается вовсе: иначе сервер мог бы
        // "понизить" обмен до классического X3DH.
        const pqCt = decodeFixed(h.pqCiphertext, PQ_CIPHERTEXT_BYTES);
        if (!signPub || !dhPub || !eph || !pqCt) return null;
        if (!isKeyId(h.usedSignedPrekeyId) || !isKeyId(h.usedPqPrekeyId) || (opkId !== null && !isKeyId(opkId))) return null;
        // pqOneTime: true — usedPqPrekeyId указывает на одноразовый PQ-prekey
        // (pqopk:<id>), иначе на запасной (pqpk). Поле в заголовок не
        // подписано, но подмена безвредна: с ключом не той роли общий секрет
        // ML-KEM не сойдётся (implicit rejection) и AEAD отвергнет share.
        const pqOneTime = h.pqOneTime === true;
        return {
            n: env.n, iv, ct,
            init: { signPub, dhPub, eph, spkId: h.usedSignedPrekeyId, opkId, pqId: h.usedPqPrekeyId, pqOneTime, pqCt },
        };
    }

    // Поле ext в SKDM (roadmap R9): расширяемый словарь внутри AEAD key-share,
    // то есть под защитой попарного канала. Сегодня в нём одно известное поле:
    //   prev: { id, final } — прежний ключ отправителя в этой комнате и последняя
    //                         использованная им итерация (5.2). Получатель
    //                         выводит оставшиеся ключи до final и стирает chainKey
    //                         старой цепочки. Дальше сюда лягут view (5.4) и голова
    //                         журнала ключей (5.6).
    // Правила разбора: известное поле обязано быть корректным, иначе SKDM
    // отвергается целиком (испорченный ext — признак сбоя или подделки, молча
    // принять половину нельзя); неизвестные поля игнорируются и наружу не
    // отдаются, чтобы будущая версия могла добавлять поля, а старая — работать.
    const MAX_EXT_CHARS = 2048;

    // kt: { g, e, h, s } — последняя проверенная подписанная голова журнала отправителя (7.5):
    // поколение, эпоха, голова (32 байта) и подпись (64 байта) в base64. Строгий разбор — null при порче.
    function parseKtGossip(raw) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        const isU32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xFFFFFFFF;
        if (!isU32(raw.g) || raw.g < 1 || !isU32(raw.e)) return null;
        if (!decodeFixed(raw.h, 32) || !decodeFixed(raw.s, 64)) return null;
        return { g: raw.g, e: raw.e, h: raw.h, s: raw.s };
    }

    function parseSkdmExt(raw) {
        if (raw === undefined) return {};
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        let json;
        try { json = JSON.stringify(raw); } catch { return null; }
        // kt и view - справочные подсказки, а не условие ключа: при порче или превышении предела ext эти поля
        // отбрасываются с предупреждением, SKDM принимается (строго разбирается только prev).
        let hintsDropped = false;
        if (json.length > MAX_EXT_CHARS) {
            const { kt: ignoredKt, view: ignoredView, ...rest } = raw;
            let restJson;
            try { restJson = JSON.stringify(rest); } catch { return null; }
            if (restJson.length > MAX_EXT_CHARS || (raw.kt === undefined && raw.view === undefined)) return null;
            hintsDropped = true;
        }
        const ext = {};
        if (raw.kt !== undefined) {
            const kt = hintsDropped ? null : parseKtGossip(raw.kt);
            if (kt) ext.kt = kt;
            else console.warn('E2EE: поле kt в SKDM испорчено или не помещается в ext и отброшено');
        }
        if (raw.view !== undefined) {
            const view = hintsDropped || !membershipClient ? null : membershipClient.parseViewField(raw.view);
            if (view) ext.view = view;
            else console.warn('E2EE: поле view в SKDM испорчено или не помещается в ext и отброшено');
        }
        if (raw.prev !== undefined) {
            const prev = raw.prev;
            if (!prev || typeof prev !== 'object' || Array.isArray(prev)) return null;
            if (!isCanonicalKeyId(prev.id)) return null;
            if (!Number.isInteger(prev.final) || prev.final < 0 || prev.final > 0xFFFFFFFF) return null;
            ext.prev = { id: prev.id, final: prev.final };
        }
        return ext;
    }

    function parseSkdm(pt, roomId) {
        let skdm;
        try { skdm = JSON.parse(utf8decode(pt)); } catch { return null; }
        if (!skdm || skdm.v !== 2 || skdm.type !== 'skdm' || Number(skdm.roomId) !== Number(roomId)) return null;
        if (!isCanonicalKeyId(skdm.senderKeyId)) return null;
        if (!decodeFixed(skdm.chainKey, 32)) return null;
        if (!Number.isInteger(skdm.iteration) || skdm.iteration < 0 || skdm.iteration > 0xFFFFFFFF) return null;
        const signingPublicKey = canonicalSigningKey(skdm.signingPublicKey);
        if (!signingPublicKey) return null;
        const ext = parseSkdmExt(skdm.ext);
        if (!ext) return null;
        return {
            senderKeyId: skdm.senderKeyId,
            chainKey: skdm.chainKey,
            iteration: skdm.iteration,
            signingPublicKey,
            ext,
        };
    }

    // SKDM к отправке. ext пишется только когда в нём есть поля: ключ без
    // истории (первый в комнате) уходит ровно в прежнем виде.
    function buildSkdm(roomId, key, ext) {
        const skdm = {
            v: 2, type: 'skdm', roomId,
            senderKeyId: key.senderKeyId,
            chainKey: key.chainKey,
            iteration: key.iteration,
            signingPublicKey: key.signingPublicKey,
        };
        if (ext && Object.keys(ext).length > 0) skdm.ext = ext;
        return skdm;
    }

    // ===================== Содержимое сообщения v2 =====================

    function normalizeFileDescriptor(o) {
        if (!o || typeof o !== 'object') return null;
        const { mime, name, size, key, iv } = o;
        if (typeof mime !== 'string' || mime.length > MAX_FILE_FIELD) return null;
        if (typeof name !== 'string' || name.length > MAX_FILE_FIELD) return null;
        if (!Number.isSafeInteger(size) || size < 0) return null;
        if (!decodeFixed(key, 32) || !decodeFixed(iv, 12)) return null;
        return { mime, name, size, key, iv };
    }

    // Формат содержимого (message-ordering.md, раздел 9.1):
    //   { t:'text', b, mid, ts, e?:1, re?:'<id>' }
    //   { t:'file', mime, name, size, key, iv, caption, mid, ts }
    // mid — String(id сообщения), ts — время отправителя в мс, e:1 — правка
    // (правятся только текстовые сообщения), re — id сообщения, на которое это
    // ответ (только у текста; сервер хранит reply_to_id открыто, и без re он мог бы
    // приписать сообщению любую цитату — клиент сверяет цитату сервера с re).
    function encodeContent(content, { mid, ts, edit = false, replyTo = null }) {
        if (replyTo !== null && replyTo !== undefined && !isValidMessageId(replyTo)) {
            throw new Error('E2EE: некорректный идентификатор сообщения, на которое отвечают');
        }
        const hasReply = replyTo !== null && replyTo !== undefined;
        if (typeof content === 'string') {
            const text = { t: 'text', b: content, mid, ts };
            if (edit) text.e = 1;
            if (hasReply) text.re = replyTo;
            return text;
        }
        if (content && typeof content === 'object' && content.type === 'file') {
            if (edit) throw new Error('E2EE: правятся только текстовые сообщения');
            if (hasReply) throw new Error('E2EE: ответ на сообщение поддержан только у текста');
            const file = normalizeFileDescriptor(content);
            if (!file) throw new Error('E2EE: некорректное описание файла');
            const caption = content.caption === undefined || content.caption === null ? '' : content.caption;
            if (typeof caption !== 'string') throw new Error('E2EE: подпись к файлу должна быть строкой');
            return { t: 'file', mime: file.mime, name: file.name, size: file.size, key: file.key, iv: file.iv, caption, mid, ts };
        }
        throw new Error('E2EE: неподдерживаемое содержимое сообщения');
    }

    // Разбор формы содержимого. mid и ts здесь не проверяются: это делает
    // decryptIncoming по порядку раздела 9.4 (сначала 'no-mid', потом
    // 'id-mismatch', потом 'bad-plaintext' для ts). Признак правки допустим
    // только у текста.
    function decodeContent(obj) {
        if (!obj || typeof obj !== 'object') return null;
        let content;
        if (obj.t === 'text' && typeof obj.b === 'string') {
            // re: строго строка формата id; всё остальное - испорченное содержимое, а не "ответа нет".
            if (obj.re !== undefined && !isValidMessageId(obj.re)) return null;
            content = { text: obj.b, edit: obj.e === 1, replyTo: obj.re === undefined ? null : obj.re };
        } else if (obj.t === 'file') {
            const file = normalizeFileDescriptor(obj);
            if (!file || typeof obj.caption !== 'string' || obj.e !== undefined || obj.re !== undefined) return null;
            content = { text: obj.caption, file, edit: false, replyTo: null };
        } else {
            return null;
        }
        content.mid = obj.mid;
        content.ts = obj.ts;
        return content;
    }

    // Id сообщения (раздел 6.1): строка ^[1-9]\d{6,9}$, не больше 2^31-1.
    function isValidMessageId(value) {
        return typeof value === 'string' && /^[1-9]\d{6,9}$/.test(value) && Number(value) <= 2147483647;
    }

    // Ключ подписи Ed25519 из чужого ввода: каноническое base64 и строгая проверка ключа.
    function canonicalSigningKey(str) {
        const canonical = canonicalPubKey(str);
        if (!canonical || !ed25519Strict.isStrictKey(b64decode(canonical))) return null;
        return canonical;
    }

    return Object.freeze({
        PQ_PUBLIC_KEY_BYTES, PQ_CIPHERTEXT_BYTES, PQ_SEED_BYTES, pqOneTimeSigInput, sigInputV3, msgAadV3,
        skdmAadV2, parseShareEnvelope, MAX_EXT_CHARS, parseKtGossip, parseSkdmExt, parseSkdm,
        buildSkdm, encodeContent, decodeContent, isValidMessageId, canonicalSigningKey,
    });
});
