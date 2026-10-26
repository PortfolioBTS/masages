// Порядок и идентификаторы сообщений на клиенте
// (docs/security/message-ordering.md, раздел 13).
//
// Порядок сообщений внутри области (комнаты или чата с ботом) задаёт seq,
// который выдаёт сервер при вставке, а не id и не время: id случайный, время
// хранится с точностью до минуты. Сравнивать seq можно только внутри одной
// области. Функции здесь чистые, без DOM и сети: файл исполняется и в браузере
// (window.NyxoMessageOrder), и в Node (test/message-order.test.js).
//
//   insertionIndex(seqs, seq)  — куда вставить сообщение в уже упорядоченный
//                                список (двоичный поиск); защищает от
//                                переставленной доставки по сокету.
//   mergeBySeq(a, b)           — слияние двух списков сообщений по seq без
//                                повторов id.
//   dedupById(list, known)     — убрать сообщения с уже известными id.
//   newClientMessageId()       — id сообщения комнаты: его выбирает клиент до
//                                шифрования и кладёт внутрь E2EE-содержимого (mid).
//   displayTimeMs(message, ts) — какое время показать (раздел 9.5 контракта).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoMessageOrder = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Диапазон id сообщения: 7–10 цифр, не больше 2^31-1 (как на сервере,
    // lib/message-ids.js).
    const MIN_CLIENT_MESSAGE_ID = 1000000;
    const MAX_CLIENT_MESSAGE_ID = 2147483647;

    // ts из конверта показывается только если он не дальше чем на 10 минут от
    // времени сервера: часы отправителя могут уходить, а сервер мог подставить
    // что угодно.
    const TS_TRUST_WINDOW_MS = 10 * 60 * 1000;

    // Индекс, перед которым вставляется seq в список по возрастанию: после всех
    // элементов с таким же или меньшим значением (при равных seq новое
    // сообщение идёт после уже показанного, порядок вставки сохраняется).
    function insertionIndex(seqs, seq) {
        let lo = 0;
        let hi = seqs.length;
        while (lo < hi) {
            const mid = (lo + hi) >>> 1;
            if (seqs[mid] <= seq) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    // Только новые сообщения: id сравниваются как строки. known — Set строк
    // уже показанных id; сам он не меняется. При повторе внутри списка остаётся
    // первое.
    function dedupById(list, known) {
        const seen = new Set(known || []);
        const out = [];
        for (const message of list) {
            const id = String(message.id);
            if (seen.has(id)) continue;
            seen.add(id);
            out.push(message);
        }
        return out;
    }

    // Слияние двух списков сообщений одной области: по возрастанию seq, повторы
    // id убраны (остаётся тот, что из a). При равных seq сохраняется порядок
    // «сначала a, потом b».
    function mergeBySeq(a, b) {
        const merged = dedupById([...a, ...b]);
        // Array.prototype.sort стабилен (ES2019): равные seq не переставляются.
        return merged.sort((x, y) => Number(x.seq) - Number(y.seq));
    }

    // 31 случайный бит, значения меньше MIN_CLIENT_MESSAGE_ID отбрасываются
    // (около 0,05 %): без смещения. random — источник uint32 (для тестов);
    // по умолчанию crypto.getRandomValues.
    function defaultRandomUint32() {
        const cryptoApi = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined;
        if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
            throw new Error('Нет crypto.getRandomValues: id сообщения создать нельзя');
        }
        const buf = new Uint32Array(1);
        cryptoApi.getRandomValues(buf);
        return buf[0];
    }

    function newClientMessageId(random = defaultRandomUint32) {
        for (;;) {
            const value = random() & 0x7fffffff;
            if (value >= MIN_CLIENT_MESSAGE_ID) return String(value);
        }
    }

    // Время сообщения для показа (мс от эпохи). У неправленого сообщения —
    // ts из конверта, если он в пределах 10 минут от created_at; иначе
    // created_at. У правленого (edited_at задан) — всегда created_at: ts
    // правки — время правки, а время оригинала сервер перезаписал вместе с
    // текстом. Нет ни одного пригодного значения — null.
    function displayTimeMs(message, ts) {
        const created = message && message.created_at ? new Date(message.created_at).getTime() : NaN;
        if (message && message.edited_at) return Number.isFinite(created) ? created : null;
        const sentAt = Number.isSafeInteger(ts) && ts >= 0 ? ts : null;
        if (sentAt !== null && Number.isFinite(created) && Math.abs(sentAt - created) <= TS_TRUST_WINDOW_MS) return sentAt;
        return Number.isFinite(created) ? created : null;
    }

    return {
        MIN_CLIENT_MESSAGE_ID,
        MAX_CLIENT_MESSAGE_ID,
        TS_TRUST_WINDOW_MS,
        insertionIndex,
        dedupById,
        mergeBySeq,
        newClientMessageId,
        displayTimeMs,
    };
});
