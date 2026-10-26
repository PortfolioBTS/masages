// public/js/14-send.js — отправка сообщений и исходы отправки.
// Вынесено из public/script.js (строки 5988–6193 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Отправка ====================

// Замок отправки: пока идёт отправка или правка, повторный Enter/клик
// ничего не делает. Берёт его вызывающий (sendMessage), а не sendText.
let sending = false;

// ---- Исходы отправки сообщения (message-ordering.md, раздел 6.5) ----
//
//   200                              показать сообщение из ответа (дубликат от
//                                    newMessage отсекается по id);
//   обрыв сети, таймаут, 5xx         исход неизвестен: тот же запрос с тем же id
//                                    и тем же конвертом, не больше трёх раз с
//                                    нарастающей паузой. Повтор идемпотентен.
//                                    Таймаут — запрос без ответа дольше SEND_TIMEOUT_MS
//                                    (api() обрывает его, иначе замок отправки
//                                    держался бы вечно); все попытки вместе — не дольше
//                                    SEND_TOTAL_MS. Если исход так и не выяснился, запрос
//                                    запоминается (unknownSend): повторное нажатие
//                                    «Отправить» с тем же текстом шлёт его же, с тем же
//                                    clientMessageId, а не новое сообщение;
//   409 id-conflict                  новый id, содержимое шифруется заново (новый
//                                    mid и итерация цепочки; старая итерация
//                                    остаётся пропуском, получатели его терпят),
//                                    не больше трёх конфликтов подряд;
//   400 client-outdated              «Обновите страницу», не повторять;
//   400 bad-message-id               ошибка клиента: не повторять, в консоль.
const SEND_RETRY_DELAYS_MS = [500, 1500, 4000];
const MAX_ID_CONFLICTS = 3;
const SEND_TIMEOUT_MS = 20 * 1000;
const SEND_TOTAL_MS = 60 * 1000;
const UNKNOWN_SEND_TTL_MS = 5 * 60 * 1000;

function isUnknownSendOutcome(data) {
    return !data.success && (data.networkError === true || data.timedOut === true || (Number(data.httpStatus) >= 500));
}

// buildRequest(clientMessageId) → запрос (шифрует содержимое под этим id) или
// null, если собрать нельзя; post(запрос) → тело ответа. clientMessageId —
// только для комнаты, у чата с ботом он null. shouldStop() — отмена между
// повторами. reuse = { clientMessageId, request } — запрос прошлой отправки с
// неизвестным исходом: первая попытка идёт им, без нового шифрования.
// Возвращает { data, request, clientMessageId } (последние два — для запоминания
// запроса с неизвестным исходом); data.success === false с кодом из тела — отказ.
async function sendWithOutcomes({ roomId, buildRequest, post, shouldStop = () => false, reuse = null }) {
    let conflicts = 0;
    let clientMessageId = reuse ? reuse.clientMessageId : (roomId ? NyxoMessageOrder.newClientMessageId() : null);
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
            clientMessageId = NyxoMessageOrder.newClientMessageId();
            continue;
        }
        return { data, request, clientMessageId };
    }
}

// Запрос, чей исход неизвестен (таймаут, обрыв, 5xx после всех повторов): { key, request,
// clientMessageId, at }. key — чат, ответ и текст; пока пользователь не изменил ни одного из
// них, «Отправить» повторяет ЭТОТ запрос, и сервер по clientMessageId не создаст дубликат.
let unknownSend = null;

function unknownSendKey(chatId, roomId, text, replyToId) {
    return JSON.stringify([chatId, roomId || null, text, replyToId || null]);
}

// Sender Key, которым зашифрован конверт запроса (null — не конверт комнаты).
function requestSenderKeyId(request) {
    try {
        const envelope = JSON.parse(request && request.text);
        return envelope && typeof envelope.senderKeyId === 'string' ? envelope.senderKeyId : null;
    } catch {
        return null;
    }
}

// Текст для пользователя по отказу сервера. client-outdated — просьба обновить
// страницу; bad-message-id — ошибка клиента, подробности только в консоль.
function sendFailureText(data, fallback) {
    if (data.code === 'client-outdated') return data.message || 'Обновите страницу: эта версия приложения устарела';
    if (data.code === 'bad-message-id') {
        console.error('Сервер отклонил идентификатор сообщения (bad-message-id)');
        return fallback;
    }
    if (data.code === 'id-conflict') return 'Не удалось отправить сообщение: идентификатор занят, попробуйте ещё раз';
    // Исход неизвестен: сервер мог успеть принять сообщение. Повтор безопасен — уходит тот же
    // запрос с тем же clientMessageId (unknownSend), второго сообщения не будет.
    if (data.timedOut) return 'Сервер не отвечает — не удалось подтвердить отправку. Нажмите «Отправить» ещё раз: дубликата не будет';
    if (data.networkError) return 'Нет соединения с сервером — сообщение не отправлено';
    return data.message || fallback;
}

// Отправляет уже готовый текст в ЯВНО указанный чат: в комнате шифрует всегда
// (открытым текстом уходит только сообщение в чат с ботом), шлёт на сервер и
// сразу показывает сообщение в ленте.
// Поле ввода не читает и не очищает — это дело вызывающего, поэтому тем же
// путём можно отправить текст из другого источника, не трогая черновик.
//
// Чат и ответ передаются явно и фиксируются в момент вызова: пока шифруем и
// ждём ответ сервера, пользователь может уйти в другой чат или отменить
// ответ. Замок `sending` здесь не берётся — его держит вызывающий.
//
// Возвращает true, если сообщение ушло. false — отправка прервана, причину
// пользователю уже показали тостом; поле ввода в этом случае не очищают.
async function sendText(text, { chatId, roomId, replyToId } = {}) {
    // Чат обязателен: без него запрос ушёл бы с пустым chatId, а не в открытый чат.
    if (!chatId) throw new Error('sendText: не указан чат');
    let client;
    try {
        client = await prepareOutgoing(chatId, roomId);
    } catch (err) {
        if (!(err instanceof E2eeBlockedError)) throw err;
        reportBlockedSend(err, chatId, roomId);
        return false;
    }
    // Id сообщения комнаты выбирает клиент ДО шифрования и кладёт его внутрь
    // конверта (mid): сервер не сможет выдать конверт за другое сообщение. Чат с
    // ботом id не присылает. Исходы отправки — sendWithOutcomes (раздел 6.5).
    const encrypted = Boolean(client);
    let encryptFailed = false;
    const key = unknownSendKey(chatId, roomId, text, replyToId);
    let reuse = unknownSend && unknownSend.key === key && Date.now() - unknownSend.at < UNKNOWN_SEND_TTL_MS ? unknownSend : null;
    unknownSend = null;
    // Свой ключ комнаты сменился с момента шифрования (ротация — например, исключили участника): старый конверт не
    // повторяется. Если первая попытка не дошла, его под прежним ключом мог бы прочитать исключённый (повторное ревью
    // W7, RR-9); цена — возможный дубликат, если она всё же дошла, о чём и сказано.
    if (reuse && reuse.senderKeyId && client && typeof client.currentSenderKeyId === 'function'
        && (await client.currentSenderKeyId(roomId)) !== reuse.senderKeyId) {
        reuse = null;
        showToast('Ключ группы сменился: сообщение зашифровано заново. Если первая попытка всё же дошла, оно может появиться дважды', 'info', 6000);
    }
    const deadline = Date.now() + SEND_TOTAL_MS;
    const outcome = await sendWithOutcomes({
        roomId,
        reuse,
        shouldStop: () => Date.now() >= deadline,
        buildRequest: async (clientMessageId) => {
            let outgoingText = text;
            if (client) {
                try {
                    // Ответ уходит и внутри шифротекста (replyTo): сервер хранит reply_to_id открыто, и получатели
                    // принимают цитату, только если её id совпал с подписанным (З3).
                    outgoingText = await encryptForRoom(client, chatId, roomId, text, { messageId: clientMessageId, replyTo: replyToId || null });
                } catch (err) {
                    console.error('E2EE: encryptOutgoing failed:', err);
                    encryptFailed = true;
                    return null;
                }
            }
            const payload = { chatId, text: outgoingText, encrypted, proto: PROTO_VERSION };
            if (clientMessageId) payload.clientMessageId = clientMessageId;
            if (replyToId) payload.replyToId = replyToId;
            return payload;
        },
        post: (payload) => api('/api/messages', {
            method: 'POST',
            body: JSON.stringify(payload),
            timeoutMs: Math.max(5000, Math.min(SEND_TIMEOUT_MS, deadline - Date.now())),
        }),
    });
    if (isUnknownSendOutcome(outcome.data) && outcome.request) {
        unknownSend = {
            key, request: outcome.request, clientMessageId: outcome.clientMessageId, at: Date.now(),
            senderKeyId: roomId ? requestSenderKeyId(outcome.request) : null,
        };
    }
    if (encryptFailed) {
        showToast('Не удалось зашифровать сообщение — попробуйте ещё раз', 'error');
        return false;
    }
    const data = outcome.data;
    if (!data.success) {
        showToast(sendFailureText(data, 'Не удалось отправить сообщение'), 'error');
        return false;
    }
    clearRoomBlock(chatId);
    checkRoomKeyRotation(chatId, roomId);
    // Показываем сразу из ответа — не зависим от того, успел ли
    // прийти (и пришёл ли вообще) newMessage по сокету.
    if (chatId === currentChatId && data.message) {
        const message = { ...data.message, text };
        // Цитата в ответе сервера должна быть той, на которую отвечали мы (З3).
        if (roomId && message.reply_to && String(message.reply_to.id) !== String(replyToId || '')) message.reply_to = null;
        const reply = message.reply_to;
        if (reply && reply.encrypted && !reply.deleted) {
            const replyRes = await decryptEnvelope(roomId, null, reply.text, reply.id);
            reply.text = decryptedSummary(replyRes);
            reply._author = replyRes.ok ? roomAuthorLabel(roomId, replyRes.senderId) : '';
        }
        if (chatId === currentChatId) {
            if (appendMessage(message, true)) scrollToBottom();
            updateChatListOnMessage(message, true);
        }
    }
    return true;
}

// Поле сообщения — textarea: растёт по тексту до max-height из CSS (шесть строк), дальше
// прокручивается. Высоту надо пересчитывать при любом изменении значения, в том числе из
// кода (setMessageInputValue), и при смене ширины окна (меняются переносы строк).
function autoResizeMessageInput() {
    const input = elements.messageInput;
    input.style.height = 'auto';
    if (input.offsetParent === null) {          // поле скрыто (чат не открыт): высоту посчитать нельзя
        input.style.height = '';
        return;
    }
    const max = parseFloat(getComputedStyle(input).maxHeight);
    const wanted = input.scrollHeight + (input.offsetHeight - input.clientHeight);
    const limit = Number.isFinite(max) ? max : wanted;
    input.style.height = `${Math.min(wanted, limit)}px`;
    input.style.overflowY = wanted > limit ? 'auto' : 'hidden';
}

function setMessageInputValue(text) {
    elements.messageInput.value = text;
    autoResizeMessageInput();
}

// Отправка из поля ввода: новое сообщение (через sendText) или сохранение
// правки. Поле и ответ очищаются только после успеха — и только если
// пользователь остался в том же чате.
async function sendMessage() {
    const text = elements.messageInput.value.trim();
    if (!text || sending) return;
    if (!currentChatId) {
        showToast('Выберите чат', 'error');
        return;
    }
    // Чат фиксируется в начале: пока шифруем/отправляем, пользователь может
    // переключиться — конверт комнаты A не должен уйти в чат B.
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const replyAtStart = replyToMessageId;
    // После сохранённой правки в поле возвращается черновик, набранный до «Изменить» (после нового сообщения — пусто).
    let restoreDraft = '';

    setSending(true); // двойной Enter/клик не отправляет сообщение дважды
    try {
        if (editingMessageId) {
            // Правка в комнате шифруется всегда: сервер принимает в комнату только
            // конверт правильной формы. Правка сообщения в чате с ботом — открытый текст.
            const messageId = editingMessageId;
            const encryptEdit = Boolean(roomId);
            let outgoingText = text;
            if (!encryptEdit && !plaintextAllowedForChat(chatId, roomId)) {
                showToast('Правка не отправлена: открытый текст разрешён только в чате с ботом', 'error');
                return;
            }
            if (encryptEdit) {
                const client = await getReadyE2eeClient();
                if (!client) { showToast('Не удалось зашифровать правку: сквозное шифрование недоступно', 'error'); return; }
                // mid правки — id редактируемого сообщения (строка), edit:true поднимает ts
                // выше известной версии: правка при отстающих часах не выглядит старой.
                // Правка несёт тот же ответ, что и исходное сообщение (replyTo): после перезагрузки истории показывается
                // именно текст правки, и без replyTo цитата не прошла бы сверку (З3).
                const original = findMessageEl(messageId);
                const originalReply = original && original._message && original._message.reply_to ? String(original._message.reply_to.id) : null;
                try { outgoingText = await encryptForRoom(client, chatId, roomId, text, { messageId: String(messageId), edit: true, replyTo: originalReply }); }
                catch { showToast('Не удалось зашифровать правку', 'error'); return; }
            }
            const data = await api(`/api/messages/${messageId}`, {
                method: 'PUT',
                body: JSON.stringify({ text: outgoingText, proto: PROTO_VERSION }),
            });
            if (!data.success) {
                showToast(sendFailureText(data, 'Не удалось изменить сообщение'), 'error');
                return; // поле не очищаем — пользователь не теряет набранный текст
            }
            showToast('Сообщение изменено', 'success');
            // в бабле — то, что реально набрано, открытым текстом
            if (chatId === currentChatId) applyMessageEdit(messageId, encryptEdit ? text : (data.text || text));
            if (String(editingMessageId) === String(messageId)) {
                const draft = draftBeforeEdit;
                finishEditing();
                restoreDraft = draft;
            }
        } else {
            const sent = await sendText(text, { chatId, roomId, replyToId: replyAtStart });
            if (!sent) return;
        }
    } finally {
        setSending(false);
    }

    // Если пользователь успел уйти в другой чат, там в поле может быть уже
    // новый черновик — его не трогаем. В том же чате поле очищается, только если там
    // всё ещё отправленный текст: за время отправки (до 60 с при плохой связи) человек
    // мог набирать следующее сообщение, и стирать его нельзя. То же с ответом: если он
    // успел выбрать другое сообщение для ответа, выбор остаётся.
    if (chatId === currentChatId) {
        if (elements.messageInput.value.trim() === text) setMessageInputValue(restoreDraft);
        if (replyToMessageId === replyAtStart) clearReply();
    }
}
