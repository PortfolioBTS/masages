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
//                                    нарастающей паузой. Повтор идемпотентен;
//   409 id-conflict                  новый id, содержимое шифруется заново (новый
//                                    mid и итерация цепочки; старая итерация
//                                    остаётся пропуском, получатели его терпят),
//                                    не больше трёх конфликтов подряд;
//   400 client-outdated              «Обновите страницу», не повторять;
//   400 bad-message-id               ошибка клиента: не повторять, в консоль.
const SEND_RETRY_DELAYS_MS = [500, 1500, 4000];
const MAX_ID_CONFLICTS = 3;

function isUnknownSendOutcome(data) {
    return !data.success && (data.networkError === true || (Number(data.httpStatus) >= 500));
}

// buildRequest(clientMessageId) → запрос (шифрует содержимое под этим id) или
// null, если собрать нельзя; post(запрос) → тело ответа. clientMessageId —
// только для комнаты, у чата с ботом он null. shouldStop() — отмена между
// повторами. Возвращает { data }; data.success === false с кодом из тела — отказ.
async function sendWithOutcomes({ roomId, buildRequest, post, shouldStop = () => false }) {
    let conflicts = 0;
    let clientMessageId = roomId ? NyxoMessageOrder.newClientMessageId() : null;
    for (;;) {
        const request = await buildRequest(clientMessageId);
        if (request === null) return { data: { success: false, message: '' } };
        let data = await post(request);
        for (let retry = 0; isUnknownSendOutcome(data) && retry < SEND_RETRY_DELAYS_MS.length; retry++) {
            if (shouldStop()) return { data };
            await delay(SEND_RETRY_DELAYS_MS[retry]);
            data = await post(request);
        }
        if (data.success) return { data };
        if (roomId && data.httpStatus === 409 && data.code === 'id-conflict' && ++conflicts < MAX_ID_CONFLICTS) {
            clientMessageId = NyxoMessageOrder.newClientMessageId();
            continue;
        }
        return { data };
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
    const outcome = await sendWithOutcomes({
        roomId,
        buildRequest: async (clientMessageId) => {
            let outgoingText = text;
            if (client) {
                try {
                    outgoingText = await encryptForRoom(client, chatId, roomId, text, { messageId: clientMessageId });
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
        post: (payload) => api('/api/messages', { method: 'POST', body: JSON.stringify(payload) }),
    });
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
                try { outgoingText = await encryptForRoom(client, chatId, roomId, text, { messageId: String(messageId), edit: true }); }
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
            if (String(editingMessageId) === String(messageId)) finishEditing();
        } else {
            const sent = await sendText(text, { chatId, roomId, replyToId: replyToMessageId });
            if (!sent) return;
        }
    } finally {
        setSending(false);
    }

    // Если пользователь успел уйти в другой чат, там в поле может быть уже
    // новый черновик — его не трогаем.
    if (chatId === currentChatId) {
        elements.messageInput.value = '';
        clearReply();
    }
}
