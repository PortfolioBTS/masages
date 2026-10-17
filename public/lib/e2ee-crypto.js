// Криптография ядра E2EE без состояния клиента (roadmap R14, T6.4). Вынесено дословно из public/e2ee.js
// (разделы «Примитивы», «KDF-цепочка», «Файлы», «Код безопасности» и вывод идентификатора ключа отправителя):
//   - обёртки Web Crypto: randomBytes, generateX25519/generateEd25519, toPrivateKey, dh, sign, hkdf,
//     hmacSha256, aesGcmEncrypt/aesGcmDecrypt;
//   - KDF-цепочка Sender Key и попарного канала key-share: chainStep, getOrDeriveMessageKey, trimChain,
//     dropKeys, closeChain, takePairwiseKey и их пределы MAX_KEYS_PER_CHAIN, MAX_SKIP, MAX_PW_SKIP;
//   - файлы (encryptFile/decryptFile), код безопасности (computeSafetyNumber), идентификатор ключа
//     отправителя (deriveSenderKeyId).
// Функции меняют только свои аргументы (запись цепочки), хранилища и сети здесь нет. Проверка подписи
// Ed25519 (verify) сюда НЕ входит: она остаётся в public/e2ee.js единственной (test/ed25519-strict-paths.test.js).
// Файл исполняется и в браузере (window.NyxoE2eeCrypto, подключается до e2ee.js), и в Node (require).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./e2ee-codec.js'));
    } else {
        root.NyxoE2eeCrypto = factory(root.NyxoE2eeCodec);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec) {
    'use strict';

    const {
        b64encode, b64decode, decodeFixed, utf8encode, concatBytes, u32be,
        toBytes, isU32, isAllZero, filePaddedLength,
    } = Codec;

    const subtle = crypto.subtle;

    // ---- Пределы цепочек и раунды хэша кода безопасности ----

    // Ключей сообщений в одной цепочке (текущей или архивной). Это защита от
    // раздувания записи, а не бюджет истории: при обрезке запоминается
    // expiredBelow, и расшифровка выдаёт 'key-expired', а не немое 'no-message-key'.
    const MAX_KEYS_PER_CHAIN = 5000;
    // Насколько далеко вперёд по цепочке Sender Key можно "перескочить" за
    // одно сообщение. Без предела конверт с iteration = 10^9 (его может
    // подписать любой участник комнаты) заставлял клиента получателя
    // посчитать миллиард HMAC подряд — вкладка намертво зависала.
    const MAX_SKIP = 5000;
    // То же для попарной цепочки key-share: передач ключей на порядки
    // меньше, чем сообщений.
    const MAX_PW_SKIP = 1000;

    const FINGERPRINT_ITERATIONS = 5200;

    // ===================== Примитивы =====================

    function randomBytes(n) {
        return crypto.getRandomValues(new Uint8Array(n));
    }

    // Приватные ключи создаются неизвлекаемыми: их можно использовать, но не
    // выгрузить наружу (exportKey кидает). Публичная половина пары по
    // спецификации WebCrypto извлекаема всегда.
    async function generateX25519() {
        const kp = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        return { pub, priv: kp.privateKey };
    }

    async function generateEd25519() {
        const kp = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        return { pub, priv: kp.privateKey };
    }

    function isCryptoKey(v) {
        return Boolean(v) && typeof v === 'object' && typeof v.type === 'string' && Boolean(v.algorithm) && typeof v.extractable === 'boolean';
    }

    function isJwk(v) {
        return Boolean(v) && typeof v === 'object' && typeof v.kty === 'string';
    }

    // Миграция: JWK, записанный прежней версией, импортируется как
    // неизвлекаемый CryptoKey (после перезаписи в хранилище JWK исчезает).
    async function toPrivateKey(value, algName, usages) {
        if (isCryptoKey(value)) return value;
        if (isJwk(value)) return subtle.importKey('jwk', value, { name: algName }, false, usages);
        throw new Error('E2EE: повреждён приватный ключ в хранилище');
    }

    async function dh(privKey, pubRawBytes) {
        if (pubRawBytes.length !== 32 || isAllZero(pubRawBytes)) {
            throw new Error('E2EE: получен вырожденный (all-zero) публичный ключ');
        }
        const pub = await subtle.importKey('raw', pubRawBytes, { name: 'X25519' }, false, []);
        const bits = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, privKey, 256));
        if (isAllZero(bits)) throw new Error('E2EE: вырожденный результат DH (точка малого порядка)');
        return bits;
    }

    async function sign(privKey, data) {
        return new Uint8Array(await subtle.sign('Ed25519', privKey, data));
    }

    async function hkdf(ikm, salt, infoStr, lengthBytes) {
        const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const bits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt, info: utf8encode(infoStr) },
            key,
            lengthBytes * 8
        );
        return new Uint8Array(bits);
    }

    async function hmacSha256(keyBytes, dataBytes) {
        const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return new Uint8Array(await subtle.sign('HMAC', key, dataBytes));
    }

    async function aesGcmEncrypt(rawKey32, plaintext, aad) {
        const key = await subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['encrypt']);
        const iv = randomBytes(12);
        const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext));
        return { iv, ct };
    }

    async function aesGcmDecrypt(rawKey32, iv, ct, aad) {
        const key = await subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct);
        return new Uint8Array(pt);
    }

    // ===================== KDF-цепочка =====================
    // Стандартная схема Signal: messageKey = HMAC(chainKey, 0x01),
    // nextChainKey = HMAC(chainKey, 0x02). Продвижение необратимо —
    // предыдущий chainKey нельзя восстановить из следующего. Одна и та же
    // схема у Sender Key и у попарного канала key-share.

    async function chainStep(chainKey) {
        const messageKey = await hmacSha256(chainKey, new Uint8Array([0x01]));
        const nextChainKey = await hmacSha256(chainKey, new Uint8Array([0x02]));
        return { messageKey, nextChainKey };
    }

    // Возвращает messageKey для нужной iteration, продвигая цепочку и
    // кэшируя "пропущенные" (и уже использованные — см. шапку файла про
    // историю чата) ключи по пути. hour — часовой индекс «сейчас»: он
    // записывается в keyTimes для каждого выведенного ключа и нужен таймеру
    // комнаты (maintainRoomKeysLocked).
    async function getOrDeriveMessageKey(state, targetIteration, hour) {
        if (targetIteration < state.nextIteration) {
            const cached = state.cachedKeys[targetIteration];
            if (!cached) return null; // ключ удалён (таймер, бюджет, «не хранить историю») или не сохранялся
            return b64decode(cached);
        }
        let chainKey = b64decode(state.chainKey);
        if (!state.keyTimes) state.keyTimes = {};
        for (let it = state.nextIteration; it <= targetIteration; it++) {
            const { messageKey, nextChainKey } = await chainStep(chainKey);
            state.cachedKeys[it] = b64encode(messageKey);
            state.keyTimes[it] = hour;
            chainKey = nextChainKey;
        }
        state.chainKey = b64encode(chainKey);
        state.nextIteration = targetIteration + 1;
        trimChain(state);
        const key = state.cachedKeys[targetIteration];
        return key ? b64decode(key) : null;
    }

    function trimNumericMap(map, max) {
        const keys = Object.keys(map);
        if (keys.length <= max) return;
        keys.map(Number).sort((a, b) => a - b)
            .slice(0, keys.length - max)
            .forEach(k => { delete map[k]; });
    }

    // Удаляет ключи сообщений, для которых shouldDrop(итерация) истинно, и
    // запоминает в expiredBelow, что на этой цепочке ключи удаляли намеренно:
    // отсутствие ключа ниже этой границы — не «никогда не было», а «удалён»
    // ('key-expired'). Возвращает число удалённых ключей.
    function dropKeys(rec, shouldDrop) {
        let dropped = 0;
        let highest = -1;
        for (const name of Object.keys(rec.cachedKeys)) {
            const it = Number(name);
            if (!shouldDrop(it)) continue;
            delete rec.cachedKeys[name];
            if (rec.keyTimes) delete rec.keyTimes[name];
            dropped++;
            if (it > highest) highest = it;
        }
        if (dropped > 0) rec.expiredBelow = Math.max(rec.expiredBelow || 0, highest + 1);
        return dropped;
    }

    // Предел ключей в одной цепочке: самые старые уходят первыми.
    function trimChain(rec) {
        const names = Object.keys(rec.cachedKeys);
        if (names.length <= MAX_KEYS_PER_CHAIN) return;
        const sorted = names.map(Number).sort((a, b) => a - b);
        const boundary = sorted[names.length - MAX_KEYS_PER_CHAIN];
        dropKeys(rec, it => it < boundary);
    }

    // Закрывает архивную цепочку чужого ключа по prev.final: выводит оставшиеся
    // ключи до final включительно (не больше MAX_SKIP — абсурдный final не
    // заставит считать миллиарды HMAC), кэширует их и стирает chainKey: больше
    // эта цепочка ничего не даёт. false — цепочки нет или final меньше уже
    // прочитанного (противоречие: не трогаем). final при обрезке по MAX_SKIP
    // записывается обрезанным: что дальше, прочитать всё равно нельзя.
    async function closeChain(rec, final, hour) {
        if (!rec.chainKey || !Number.isInteger(rec.nextIteration)) return false;
        if (final < rec.nextIteration - 1) return false;
        const last = Math.min(final, rec.nextIteration + MAX_SKIP - 1);
        if (last >= rec.nextIteration) await getOrDeriveMessageKey(rec, last, hour);
        delete rec.chainKey;
        rec.final = last;
        return true;
    }

    // Ключ сообщения n попарной цепочки. В отличие от Sender Key здесь
    // использованный ключ сразу удаляется, а в сессии остаются только
    // следующий chainKey и ключи ещё не пришедших (пропущенных) передач —
    // это и есть прямая секретность канала key-share.
    async function takePairwiseKey(session, n) {
        if (n < session.n) {
            const stored = session.skipped[n];
            if (!stored) return null; // уже использован (повтор) или слишком старый
            delete session.skipped[n];
            return b64decode(stored);
        }
        if (n - session.n > MAX_PW_SKIP) return null;
        let chainKey = b64decode(session.ck);
        let target = null;
        for (let i = session.n; i <= n; i++) {
            const { messageKey, nextChainKey } = await chainStep(chainKey);
            if (i === n) target = messageKey;
            else session.skipped[i] = b64encode(messageKey);
            chainKey = nextChainKey;
        }
        session.ck = b64encode(chainKey);
        session.n = n + 1;
        trimNumericMap(session.skipped, MAX_PW_SKIP);
        return target;
    }

    // ===================== Файлы =====================
    // Каждый файл — свой случайный ключ AES-256-GCM и iv; ключ, iv и
    // исходный размер передаются внутри E2EE-сообщения (encryptOutgoing с
    // объектом { type:'file', ... }), серверу достаётся только шифротекст
    // Padmé-длины.

    const FILE_AAD = utf8encode('nyxo-file-v1');

    async function encryptFile(bytes) {
        const data = toBytes(bytes);
        const padded = new Uint8Array(filePaddedLength(data.length));
        padded.set(data, 0);
        const key = randomBytes(32);
        const { iv, ct } = await aesGcmEncrypt(key, padded, FILE_AAD);
        return { ciphertext: ct, key: b64encode(key), iv: b64encode(iv), size: data.length };
    }

    async function decryptFile(ciphertext, key, iv, size) {
        const keyBytes = decodeFixed(key, 32);
        const ivBytes = decodeFixed(iv, 12);
        if (!keyBytes || !ivBytes) throw new Error('E2EE: некорректный ключ файла');
        if (!Number.isSafeInteger(size) || size < 0) throw new Error('E2EE: некорректный размер файла');
        let pt;
        try {
            pt = await aesGcmDecrypt(keyBytes, ivBytes, toBytes(ciphertext), FILE_AAD);
        } catch {
            throw new Error('E2EE: файл повреждён или подменён');
        }
        // Размер пришёл в подписанном сообщении; несовпадение с длиной
        // расшифрованного — признак чужого файла или испорченного описания.
        if (pt.length !== filePaddedLength(size)) throw new Error('E2EE: размер файла не совпадает');
        for (let i = size; i < pt.length; i++) {
            if (pt[i] !== 0) throw new Error('E2EE: некорректный паддинг файла');
        }
        return pt.slice(0, size);
    }

    // ===================== Код безопасности =====================
    // Как NumericFingerprintGenerator в Signal: для каждой стороны
    // hash0 = 0x0000 ‖ signPub ‖ dhPub ‖ utf8(userId), затем 5200 раз
    // hash = SHA-512(hash ‖ signPub ‖ dhPub); первые 30 байт → 6 блоков по
    // 5 байт → uint40 mod 100000 → по 5 цифр. Половины упорядочены по
    // числовому userId, поэтому обе стороны видят одну и ту же строку.

    async function fingerprintHalf(userId, signPubB64, dhPubB64) {
        const keys = concatBytes(b64decode(signPubB64), b64decode(dhPubB64));
        let hash = concatBytes(new Uint8Array([0, 0]), keys, utf8encode(String(userId)));
        for (let i = 0; i < FINGERPRINT_ITERATIONS; i++) {
            hash = new Uint8Array(await subtle.digest('SHA-512', concatBytes(hash, keys)));
        }
        let out = '';
        for (let i = 0; i < 30; i += 5) {
            let v = 0;
            for (let j = 0; j < 5; j++) v = v * 256 + hash[i + j];
            out += String(v % 100000).padStart(5, '0');
        }
        return out;
    }

    async function computeSafetyNumber(idA, signA, dhA, idB, signB, dhB) {
        const halfA = await fingerprintHalf(idA, signA, dhA);
        const halfB = await fingerprintHalf(idB, signB, dhB);
        const digits = Number(idA) <= Number(idB) ? halfA + halfB : halfB + halfA;
        return digits.match(/.{5}/g).join(' ');
    }

    // Идентификатор ключа отправителя ПРИВЯЗАН к отправителю (sealed-sender.md, 9.2):
    //   senderKeyId = base64( SHA-256( "nyxo-skid-v1" ‖ u32be(roomId) ‖ u32be(senderId) ‖ signingPublicKey[32] )[0..16] )
    // Вход — 52 байта: метка (12 байт, без нулевого) и поля фиксированной длины.
    // Формат значения тот же, что у прежнего случайного идентификатора (16 байт в
    // каноническом base64). Занять чужой идентификатор нельзя: для этого нужен
    // прообраз SHA-256 по 128 битам, а не просто знание чужих keyId и открытого
    // ключа из конвертов. Поэтому на один keyId в комнате приходится ровно один
    // отправитель, и индекс отправителей (skIndex) не знает «кандидатов».
    const SKID_LABEL = utf8encode('nyxo-skid-v1');

    async function deriveSenderKeyId(roomId, senderId, signingPublicKey) {
        const room = Number(roomId);
        const sender = Number(senderId);
        const pub = typeof signingPublicKey === 'string' ? decodeFixed(signingPublicKey, 32) : null;
        if (!isU32(room) || !isU32(sender) || !pub) throw new TypeError('E2EE: не из чего вывести идентификатор ключа отправителя');
        const digest = new Uint8Array(await subtle.digest('SHA-256', concatBytes(SKID_LABEL, u32be(room), u32be(sender), pub)));
        return b64encode(digest.subarray(0, 16));
    }

    return Object.freeze({
        MAX_KEYS_PER_CHAIN, MAX_SKIP, MAX_PW_SKIP, randomBytes, generateX25519, generateEd25519,
        isCryptoKey, toPrivateKey, dh, sign, hkdf, hmacSha256,
        aesGcmEncrypt, aesGcmDecrypt, chainStep, getOrDeriveMessageKey, trimNumericMap, dropKeys,
        trimChain, closeChain, takePairwiseKey, encryptFile, decryptFile, computeSafetyNumber,
        deriveSenderKeyId,
    });
});
