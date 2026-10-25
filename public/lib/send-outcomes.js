// Исходы отправки сообщения на клиенте (docs/security/message-ordering.md, раздел 6.5).
//
// Вынесено из public/js/14-send.js в задаче T7.4c (ревью W7 R5, В-6), чтобы клиентскую половину
// идемпотентности можно было проверить таблицей тестов (test/send-outcomes.test.js) без браузера.
// Логика не менялась; от окружения страницы она отвязана двумя параметрами: паузой между
// повторами (delay) и источником id сообщения (newClientMessageId) — их подставляет обёртка
// sendWithOutcomes в 14-send.js. Файл исполняется и в браузере (window.NyxoSendOutcomes), и в Node.
//
//   200                              успех: вызывающий показывает сообщение из ответа;
//   обрыв сети, таймаут, 5xx         исход неизвестен: ТОТ ЖЕ запрос с тем же id и тем же
//                                    конвертом, не больше SEND_RETRY_DELAYS_MS.length раз
//                                    с нарастающей паузой. Повтор идемпотентен;
//   409 id-conflict (только комната) новый id, содержимое шифруется заново, не больше
//                                    MAX_ID_CONFLICTS конфликтов подряд;
//   остальные отказы (400, 403 …)    без повтора: причину показывает вызывающий.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoSendOutcomes = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const SEND_RETRY_DELAYS_MS = [500, 1500, 4000];
    const MAX_ID_CONFLICTS = 3;

    // Исход неизвестен: сервер мог успеть принять сообщение, поэтому повтор безопасен
    // только потому, что уходит тот же запрос с тем же id.
    function isUnknownSendOutcome(data) {
        return !data.success && (data.networkError === true || data.timedOut === true || (Number(data.httpStatus) >= 500));
    }

    // buildRequest(clientMessageId) → запрос (шифрует содержимое под этим id) или
    // null, если собрать нельзя; post(запрос) → тело ответа. clientMessageId —
    // только для комнаты, у чата с ботом он null. shouldStop() — отмена между
    // повторами. reuse = { clientMessageId, request } — запрос прошлой отправки с
    // неизвестным исходом: первая попытка идёт им, без нового шифрования.
    // delay(мс) → Promise и newClientMessageId() → строка — подставляет вызывающий.
    // Возвращает { data, request, clientMessageId } (последние два — для запоминания
    // запроса с неизвестным исходом); data.success === false с кодом из тела — отказ.
    async function sendWithOutcomes({ roomId, buildRequest, post, shouldStop = () => false, reuse = null, delay, newClientMessageId }) {
        let conflicts = 0;
        let clientMessageId = reuse ? reuse.clientMessageId : (roomId ? newClientMessageId() : null);
        let reusable = reuse ? reuse.request : null;
        for (;;) {
            const request = reusable || await buildRequest(clientMessageId);
            reusable = null;
            if (request === null) return { data: { success: false, message: '' } };
            let data = await post(request);
            for (let retry = 0; isUnknownSendOutcome(data) && retry < SEND_RETRY_DELAYS_MS.length; retry++) {
                if (shouldStop()) return { data, request, clientMessageId };
                await delay(SEND_RETRY_DELAYS_MS[retry]);
                data = await post(request);
            }
            if (data.success) return { data, request, clientMessageId };
            if (roomId && data.httpStatus === 409 && data.code === 'id-conflict' && ++conflicts < MAX_ID_CONFLICTS) {
                clientMessageId = newClientMessageId();
                continue;
            }
            return { data, request, clientMessageId };
        }
    }

    return {
        SEND_RETRY_DELAYS_MS,
        MAX_ID_CONFLICTS,
        isUnknownSendOutcome,
        sendWithOutcomes,
    };
});
