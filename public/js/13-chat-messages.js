// public/js/13-chat-messages.js — открытый чат: история, отрисовка сообщений, отметки о прочтении, реакции.
// Вынесено из public/script.js (строки 5395–5987 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Открытый чат ====================

// avatar из списка чатов больше не используется: аватар в монохроме —
// буква или иконка бота (renderAvatar). Параметр оставлен ради вызовов.
async function openChat(chatId, roomId, name, avatar, online, isBot) {
    const seq = ++openChatSeq;
    // Ушли из комнаты с режимом «Не хранить историю» — стираем её ключи на устройстве.
    if (currentRoomId && Number(currentRoomId) !== Number(roomId)) forgetRoomIfNoHistory(currentRoomId);
    releaseChatResources();
    hideChatItemMenu();
    currentChatId = chatId;
    currentRoomId = roomId || null;
    const room = currentRoomId;
    oldestSeq = null;
    hasMoreHistory = false;
    loadingHistory = false;
    lastSeenSeq = 0;
    cancelEditing();
    clearReply();
    const bot = Boolean(Number(isBot));
    currentChatExtra = { id: chatId, room_id: room, name, is_bot: isBot, online, expiry_seconds: 0, pinned: false, muted: false, archived: false };

    elements.chatName.textContent = name;
    renderChatStatus();
    renderAvatar(elements.chatAvatar, name, bot);
    elements.chatHeader.classList.remove('hidden');
    elements.messageInputContainer.classList.remove('hidden');
    elements.emptyState.classList.add('hidden');
    elements.chatMessages.replaceChildren();
    elements.sidebar.classList.add('hidden-mobile');
    setActiveChatItem(chatId, room);
    updateComposerForChat();
    updateChatIndicators();
    if (room) loadJoinRequestsCount();

    // История запрашивается параллельно с синхронизацией E2EE-ключей, а не
    // после неё. Расшифровка всё равно ждёт ключи: только что полученные
    // Sender Key других участников должны быть известны локально. Зависший
    // сервер ключей не должен навсегда оставлять чат пустым — ждём не
    // дольше 15 секунд.
    const messagesPromise = api(`/api/messages/${chatId}`);
    // Автор сообщения комнаты известен только клиенту: список участников и карта имён
    // нужны к моменту показа (подпись над чужим сообщением).
    const authorsPromise = room ? loadRoomAuthorDirectory(chatId, room) : null;
    if (room) {
        await withTimeout(syncE2eeKeyShares(chatId, room), 15000, null);
        // Сессия комнаты (свой ключ новым участникам, ротация после ухода)
        // — в фоне: для показа истории она не нужна, а отправка её дождётся.
        if (seq === openChatSeq) ensureE2eeRoomSession(chatId, room, { answerKeyRequests: true });
        // Срок исчезающих сообщений — хранилищу ключей этого устройства.
        const roomMeta = findChatMeta(chatId, room);
        syncRoomKeyPolicy(room, roomMeta ? roomMeta.expiry_seconds : 0);
        // Режим «Не хранить историю»: значок в шапке и переключатель в меню.
        loadRoomHistoryMode(room).then(() => {
            if (seq !== openChatSeq) return;
            updateChatIndicators();
            if (!elements.chatMenuModal.classList.contains('hidden')) renderChatMenu();
        });
    }
    const data = await messagesPromise;
    if (seq !== openChatSeq) return; // пользователь уже открыл другой чат
    if (!data.success) {
        showToast(data.message || 'Не удалось загрузить сообщения', 'error');
        flushSystemNotices();
        return;
    }
    if (authorsPromise) await withTimeout(authorsPromise, 5000, null);
    if (seq !== openChatSeq) return;

    await decryptMessagesInPlace(data.messages, room);
    if (seq !== openChatSeq) return;
    renderMessages(data.messages, 'replace');
    // Подсказки бота — до прокрутки вниз: они занимают место над полем ввода,
    // и лента ужмётся.
    if (bot) renderBotSuggestions(chatId, data.chat && data.chat.quickReplies);
    hasMoreHistory = Boolean(data.hasMore);
    lastSeenSeq = data.messages.length ? Number(data.messages[data.messages.length - 1].seq) : 0;
    flushSystemNotices();
    scrollToBottom();
    // Подписку на чат делает сервер: при подключении сокета на все чаты и при создании
    // чата или входе в комнату. Событие joinChat убрано (R1 п.2): его обработчик
    // ходил в БД на каждое событие, а теперь сервер любые события клиента отбрасывает.
}

async function loadOlderMessages() {
    if (!hasMoreHistory || loadingHistory || !currentChatId || oldestSeq === null) return;
    loadingHistory = true;
    const seq = openChatSeq;
    const roomId = currentRoomId;
    try {
        const data = await api(`/api/messages/${currentChatId}?beforeSeq=${oldestSeq}`);
        if (seq !== openChatSeq || !data.success) return;
        await decryptMessagesInPlace(data.messages, roomId);
        if (seq !== openChatSeq) return;
        const container = elements.chatMessages;
        const previousHeight = container.scrollHeight;
        renderMessages(data.messages, 'prepend');
        container.scrollTop += container.scrollHeight - previousHeight; // экран не "прыгает"
        hasMoreHistory = Boolean(data.hasMore);
    } finally {
        if (seq === openChatSeq) loadingHistory = false;
    }
}

// Догружает то, что пришло, пока сокет был отключён, и убирает то, что за
// это время удалили (удаление физическое — в свежей странице такого id нет).
async function refreshCurrentChat() {
    const seq = openChatSeq;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    if (roomId) await syncE2eeKeyShares(chatId, roomId);
    const data = await api(`/api/messages/${chatId}`);
    if (seq !== openChatSeq || !data.success) return;
    if (roomId) ensureE2eeRoomSession(chatId, roomId);

    // Убираем то, что за время обрыва удалили: на экране сообщение, чей seq
    // лежит внутри диапазона свежей страницы, а самого id в странице нет.
    // Сравнение seq — только внутри этого чата; id — строки.
    if (data.messages.length > 0) {
        const pageIds = new Set(data.messages.map(m => String(m.id)));
        const minSeq = data.hasMore ? Number(data.messages[0].seq) : 0;
        const maxSeq = Number(data.messages[data.messages.length - 1].seq);
        elements.chatMessages.querySelectorAll('.message[data-message-id][data-seq]').forEach((el) => {
            const elSeq = Number(el.dataset.seq);
            if (elSeq >= minSeq && elSeq <= maxSeq && !pageIds.has(el.dataset.messageId)) removeMessageElement(el.dataset.messageId);
        });
    }

    // Новые для ленты — по id; расхождение seq у уже показанного id
    // игнорируется (раздел 12, строка 18 контракта), в консоль — для отладки.
    const shown = new Set([...elements.chatMessages.querySelectorAll('.message[data-message-id]')].map(el => el.dataset.messageId));
    const fresh = NyxoMessageOrder.dedupById(data.messages, shown);
    for (const m of data.messages) {
        const el = findMessageEl(m.id);
        if (el && el.dataset.seq !== undefined && Number(el.dataset.seq) !== Number(m.seq)) {
            console.warn('Порядок сообщений: seq известного сообщения изменился, игнорируем');
        }
    }
    if (fresh.length === 0) return;
    await decryptMessagesInPlace(fresh, roomId);
    if (seq !== openChatSeq) return;
    const stick = isNearBottom();
    fresh.forEach(m => appendMessage(m, false));
    if (stick) scrollToBottom();
    else fresh.forEach((m) => { if (!isOwnMessage(m)) bumpJumpDown(); });
    lastSeenSeq = Math.max(lastSeenSeq, ...fresh.map(m => Number(m.seq)));
}

function renderMessages(messages, mode) {
    const fragment = document.createDocumentFragment();
    const items = messages.map(msg => createMessageElement(msg, false));
    collapseHistoryGaps(items);
    items.forEach(item => fragment.appendChild(item));
    if (mode === 'prepend') elements.chatMessages.prepend(fragment);
    else elements.chatMessages.replaceChildren(fragment);
    if (messages.length > 0 && (mode !== 'prepend' || oldestSeq === null || Number(messages[0].seq) < oldestSeq)) {
        oldestSeq = Number(messages[0].seq);
    }
}

// Возвращает false, если сообщение уже на экране (например, пришло и в
// ответе POST, и по сокету).
// Лента упорядочена по seq, а не по порядку прихода: сообщение по сокету
// может прийти переставленным, и placeMessageElement ставит его на своё место.
// Серия из двух и более сообщений «недоступно на этом устройстве» подряд: первое
// превращается в служебную строку, остальные скрываются (остаются в ленте ради порядка,
// поиска по id и удаления).
function collapseHistoryGaps(items) {
    for (const run of historyGapRuns(items.map(el => el._message))) {
        const first = items[run[0]];
        first.classList.add('history-gap');
        const textEl = first.querySelector('.message-text');
        if (textEl) textEl.replaceChildren(icon('eye-off', { size: 'sm' }), document.createTextNode('Более ранние сообщения не хранятся на этом устройстве'));
        run.slice(1).forEach(index => items[index].classList.add('hidden'));
    }
}

function appendMessage(message, animate) {
    if (findMessageEl(message.id)) return false;
    placeMessageElement(createMessageElement(message, animate));
    if (oldestSeq === null || Number(message.seq) < oldestSeq) oldestSeq = Number(message.seq);
    markChatSearchStale();
    return true;
}

// Элемент сообщения по id. id — строка из цифр, но через CSS.escape: в
// селектор не должно попасть ничего лишнего, что бы ни пришло с сервера.
function findMessageEl(id) {
    return elements.chatMessages.querySelector(`[data-message-id="${CSS.escape(String(id))}"]`);
}

// Ставит элемент сообщения на место по seq (двоичный поиск); служебные строки
// без data-seq пропускаются. Сообщение с наибольшим seq (обычный случай) уходит
// в конец ленты, как и раньше.
function placeMessageElement(el) {
    const container = elements.chatMessages;
    const items = [...container.children].filter(child => child.dataset && child.dataset.seq !== undefined);
    const seqs = items.map(child => Number(child.dataset.seq));
    const index = NyxoMessageOrder.insertionIndex(seqs, Number(el.dataset.seq));
    if (index >= items.length) container.appendChild(el);
    else container.insertBefore(el, items[index]);
}

function formatReplyQuote(reply) {
    if (reply.deleted) return 'Сообщение удалено';
    // В комнате автора цитаты сервер не называет: подпись собрана при расшифровке.
    const author = reply._author !== undefined ? reply._author : (reply.sender_username || 'Неизвестно');
    const text = (reply.text || '').substring(0, 60);
    return author ? `${author}: ${text}` : text;
}

// Обновляет цитаты на сообщение messageId в других сообщениях ленты.
function updateReplyQuotes(messageId, update) {
    elements.chatMessages.querySelectorAll('.message').forEach((el) => {
        const m = el._message;
        if (!m || !m.reply_to || String(m.reply_to.id) !== String(messageId)) return;
        update(m.reply_to);
        const small = el.querySelector('.reply-to small');
        if (small) small.textContent = formatReplyQuote(m.reply_to);
    });
}

function removeMessageElement(messageId) {
    const el = findMessageEl(messageId);
    if (el) {
        const box = el.querySelector('.encrypted-attachment');
        if (box && attachmentObserver) attachmentObserver.unobserve(box);
        el.remove();
    }
    revokeObjectUrl(messageId);
    if (replyToMessageId != null && String(replyToMessageId) === String(messageId)) clearReply();
    if (editingMessageId != null && String(editingMessageId) === String(messageId)) cancelEditing();
    if (menuMessage && String(menuMessage.id) === String(messageId)) {
        hideMessageMenu();
        menuMessage = null;
    }
    updateReplyQuotes(messageId, (reply) => { reply.deleted = true; reply.text = ''; });
    markChatSearchStale();
}

function applyMessageEdit(messageId, displayText, failed = false) {
    const bubble = findMessageEl(messageId);
    if (bubble) {
        if (bubble._message) {
            bubble._message.text = displayText; // чтобы меню "Ответить/Изменить" видело новый текст
            bubble._message._e2eeFailed = failed;
            // У правленого сообщения показывается created_at (раздел 9.5): ts в конверте
            // правки — время правки, а не создания. Метка edited_at нужна только для этого.
            delete bubble._message._ts;
            bubble._message.edited_at = bubble._message.edited_at || true;
            const timeEl = bubble.querySelector('.message-time');
            if (timeEl) {
                timeEl.textContent = formatMessageTime(bubble._message);
                timeEl.removeAttribute('title');
            }
        }
        const textEl = bubble.querySelector('.message-text');
        if (textEl) setMessageText(textEl, displayText, failed);
        if (!bubble.querySelector('.edited-label')) {
            const contentEl = bubble.querySelector('.message-content');
            if (contentEl) {
                const label = document.createElement('div');
                label.className = 'edited-label';
                label.textContent = 'изменено';
                contentEl.appendChild(label);
            }
        }
    }
    updateReplyQuotes(messageId, (reply) => { reply.text = displayText; });
    markChatSearchStale();
}

// ---- Отметки о прочтении ----

// Статус своего сообщения: check — отправлено, check-check — прочитано. При
// выключенных у себя отметках о прочтении «прочитано» не показываем
// (взаимность, как в Signal): не сообщаешь сам — не видишь чужие.
function renderMessageStatus(el) {
    const status = el.querySelector('.message-status');
    if (!status) return;
    const read = readReceiptsEnabled() && Boolean(el._message) && el._message.status === 'read';
    if (status.dataset.state === (read ? 'read' : 'sent')) return;
    status.dataset.state = read ? 'read' : 'sent';
    const label = read ? 'Прочитано' : 'Отправлено';
    status.replaceChildren(icon(read ? 'check-check' : 'check', { size: 'sm', label }));
    status.title = label;
}

// Текст пузыря. Нерасшифрованное — с иконкой перед текстом (сам текст
// остаётся чистым: он же уходит в цитаты и превью).
function setMessageText(textEl, text, failed) {
    textEl.classList.toggle('e2ee-failed', Boolean(failed));
    if (failed) textEl.replaceChildren(icon('lock', { size: 'sm' }), document.createTextNode(text || ''));
    else textEl.textContent = text || '';
}

function refreshOwnMessageStatuses() {
    elements.chatMessages.querySelectorAll('.message.sent').forEach(renderMessageStatus);
}

// Последнее показанное сообщение: { id, seq } (служебные строки пропускаются)
// или null. Лента упорядочена по seq, поэтому последнее в DOM — самое новое.
function lastRenderedMessage() {
    let el = elements.chatMessages.lastElementChild;
    while (el && el.dataset.seq === undefined) el = el.previousElementSibling;
    return el ? { id: el.dataset.messageId, seq: Number(el.dataset.seq) } : null;
}

// Отмечаем прочитанным то, что пользователь реально видит: вкладка
// активна, чат прокручен к концу. Запрос — не чаще раза в секунду.
let markReadTimer = null;
function markVisibleMessagesRead() {
    if (!currentChatId || document.visibilityState !== 'visible' || !isNearBottom()) return;
    const last = lastRenderedMessage();
    if (!last || !last.seq || last.seq <= lastSeenSeq) return;
    lastSeenSeq = last.seq;
    const chatId = currentChatId;
    clearTimeout(markReadTimer);
    markReadTimer = setTimeout(() => {
        api(`/api/chats/${chatId}/read`, { method: 'POST', body: JSON.stringify({ upToSeq: last.seq }) });
    }, 1000);
}

// ---- Отрисовка сообщения ----

// Элементы с файлом (img/video/a) собираются через DOM API, а не через
// шаблонную строку с сырым message.file_url — см. п.2 аудита. file_url сейчас
// всегда безопасен (имя генерируется сервером из Date.now()+random), но даже
// если бы в нём оказались произвольные символы, .src/.href — это присвоение
// свойства, а не вставка HTML-текста, так что вырваться из атрибута нельзя.
// Заодно клик по картинке навешан через addEventListener, а не инлайновый
// onclick, который CSP (script-src без 'unsafe-inline') всё равно блокирует.
function createFileAttachmentElement(message) {
    const { file_url, file_name, message_type } = message;
    if (message_type === 'image') {
        const img = document.createElement('img');
        img.src = file_url;
        img.className = 'message-image';
        img.loading = 'lazy';
        img.decoding = 'async';
        img.alt = file_name || 'Изображение';
        img.addEventListener('click', () => window.open(file_url, '_blank', 'noopener'));
        return img;
    }
    if (message_type === 'video') {
        const video = document.createElement('video');
        video.src = file_url;
        video.controls = true;
        video.preload = 'metadata'; // не качать весь ролик при открытии чата
        video.className = 'message-video';
        return video;
    }
    // Всё остальное (PDF, TXT и любой неизвестный тип) — ссылка на скачивание.
    return createDocumentLink(file_url, file_name || 'Файл', String(message.file_type || ''), { newTab: true });
}

function createAttachmentElement(message) {
    if (!message.encrypted) return message.file_url ? createFileAttachmentElement(message) : null;
    // Зашифрованное вложение: ключ файла — внутри E2EE-конверта. Если сам
    // конверт не расшифровался, текст сообщения уже говорит об этом, а
    // ссылка на шифротекст (.bin) пользователю ни к чему.
    return message._file ? createEncryptedAttachmentElement(message) : null;
}

// Время показывается в часовом поясе пользователя (created_at, до минуты),
// а не сервера: колонки time (HH:MM по часам сервера) больше нет.
// Что именно показывать — решает NyxoMessageOrder.displayTimeMs (раздел 9.5): у
// неправленого сообщения ts отправителя из конверта, если он в пределах 10
// минут от created_at; у правленого и без пригодного ts — created_at.
function formatMessageTime(message) {
    const ms = NyxoMessageOrder.displayTimeMs(message, message._ts);
    if (ms === null) return '';
    const date = new Date(ms);
    const hhmm = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    if (date.toDateString() === new Date().toDateString()) return hhmm;
    return `${date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' })} ${hhmm}`;
}

// Точное время для всплывающей подсказки: только если оно пришло внутри
// конверта (секунды в базе не хранятся) и показано вместо created_at.
function formatMessageTimeTitle(message) {
    if (!Number.isSafeInteger(message._ts)) return '';
    const ms = NyxoMessageOrder.displayTimeMs(message, message._ts);
    if (ms !== message._ts) return '';
    return new Date(ms).toLocaleString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function createMessageElement(message, animate) {
    const isMine = isOwnMessage(message);
    const div = document.createElement('div');
    div.className = `message ${isMine ? 'sent' : 'received'}${animate ? ' message-new' : ''}`;
    div.dataset.messageId = String(message.id);
    if (message.seq !== undefined && message.seq !== null) div.dataset.seq = String(message.seq);
    div._message = message;

    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';

    if (!isMine && message.room_id) {
        // Имя автора - из списка участников по senderId расшифровки (9.1).
        const authorDiv = document.createElement('div');
        authorDiv.className = 'message-author';
        authorDiv.textContent = roomAuthorLabel(message.room_id, message._senderId);
        if (message._unverified) {
            authorDiv.classList.add('unverified');
            authorDiv.appendChild(iconText('span', 'message-author-flag', 'shield-alert', 'не подтверждён', { size: 'sm' }));
        }
        contentDiv.appendChild(authorDiv);
    }
    if (message.reply_to) {
        const replyDiv = document.createElement('div');
        replyDiv.className = 'reply-to';
        const small = document.createElement('small');
        small.textContent = formatReplyQuote(message.reply_to);
        replyDiv.append(icon('reply', { size: 'sm' }), small);
        contentDiv.appendChild(replyDiv);
    }
    const attachment = createAttachmentElement(message);
    if (attachment) contentDiv.appendChild(attachment);
    const textDiv = document.createElement('div');
    textDiv.className = 'message-text';
    setMessageText(textDiv, message.text, message._e2eeFailed);
    contentDiv.appendChild(textDiv);

    if (message.edited_at) {
        const editedDiv = document.createElement('div');
        editedDiv.className = 'edited-label';
        editedDiv.textContent = 'изменено';
        contentDiv.appendChild(editedDiv);
    }
    const reactionsDiv = document.createElement('div');
    reactionsDiv.className = 'reactions';
    contentDiv.appendChild(reactionsDiv);
    renderReactions(reactionsDiv, message);

    const metaDiv = document.createElement('div');
    metaDiv.className = 'message-meta';
    if (message.encrypted) {
        const lockSpan = document.createElement('span');
        lockSpan.className = 'message-lock';
        lockSpan.title = 'Сквозное шифрование';
        lockSpan.appendChild(icon('lock', { size: 'sm', label: 'Сквозное шифрование' }));
        metaDiv.appendChild(lockSpan);
    }
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = formatMessageTime(message);
    const timeTitle = formatMessageTimeTitle(message);
    if (timeTitle) timeSpan.title = timeTitle;
    metaDiv.appendChild(timeSpan);
    if (isMine) {
        const statusSpan = document.createElement('span');
        statusSpan.className = 'message-status';
        metaDiv.appendChild(statusSpan);
    }

    div.appendChild(contentDiv);
    div.appendChild(metaDiv);
    if (isMine) renderMessageStatus(div);

    div.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        e.stopPropagation();
        showMessageMenu(e.clientX, e.clientY, message);
    });
    attachLongPress(div, (x, y) => showMessageMenu(x, y, message));

    return div;
}

function showMessageMenu(x, y, message) {
    hideChatItemMenu();
    menuMessage = message;
    const isMine = isOwnMessage(message);
    // Файлы не редактируются; нерасшифрованное — тоже (в поле ввода попал
    // бы текст "Не удалось расшифровать", а не само сообщение).
    elements.editMessageBtn.classList.toggle('hidden', !(isMine && !message.file_url && !message._e2eeFailed));
    elements.deleteMessageBtn.classList.toggle('hidden', !isMine);
    elements.copyMessageBtn.classList.toggle('hidden', !message.text || Boolean(message._e2eeFailed));
    updateReactionPicker(message);
    const menu = elements.messageMenu;
    menu.classList.remove('hidden');
    const rect = menu.getBoundingClientRect();
    menu.style.left = Math.max(8, Math.min(x, window.innerWidth - rect.width - 8)) + 'px';
    menu.style.top = Math.max(8, Math.min(y, window.innerHeight - rect.height - 8)) + 'px';
}

function hideMessageMenu() {
    elements.messageMenu.classList.add('hidden');
}

// ---- Реакции ----
// Сервер хранит эмодзи и отдаёт по сообщению список различных реакций
// (без счётчиков и без «чья»). Свои реакции этой сессии помним локально,
// чтобы повторный выбор в пикере снимал реакцию.
const myReactions = new Map();   // messageId -> Set(emoji)

function renderReactions(container, message) {
    const list = Array.isArray(message.reactions) ? message.reactions : [];
    const mine = myReactions.get(String(message.id)) || new Set();
    const items = [];
    REACTIONS.forEach((r) => {
        const entry = list.find(x => (x && typeof x === 'object' ? x.emoji : x) === r.emoji);
        if (!entry) return;
        const count = entry && typeof entry === 'object' ? Number(entry.count) || 0 : 0;
        const el = document.createElement('span');
        el.className = 'reaction' + (mine.has(r.emoji) ? ' is-active' : '');
        el.title = r.label;
        el.appendChild(icon(r.icon, { size: 'sm', className: 'icon-fill', label: r.label }));
        if (count > 1) {
            const n = document.createElement('span');
            n.textContent = String(count);
            el.appendChild(n);
        }
        items.push(el);
    });
    container.replaceChildren(...items);
    container.classList.toggle('hidden', items.length === 0);
}

function buildReactionPicker() {
    elements.reactionPicker.replaceChildren(...REACTIONS.map((r) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'reaction-option';
        btn.dataset.index = String(REACTIONS.indexOf(r));
        btn.title = r.label;
        btn.setAttribute('aria-label', r.label);
        btn.setAttribute('aria-pressed', 'false');
        btn.appendChild(icon(r.icon, { className: 'icon-fill' }));
        btn.addEventListener('click', () => {
            const message = menuMessage;
            hideMessageMenu();
            if (message) toggleReaction(message, r.emoji);
        });
        return btn;
    }));
}

function updateReactionPicker(message) {
    const mine = myReactions.get(String(message.id)) || new Set();
    elements.reactionPicker.querySelectorAll('.reaction-option').forEach((btn) => {
        const r = REACTIONS[Number(btn.dataset.index)];
        const on = Boolean(r) && mine.has(r.emoji);
        btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        btn.classList.toggle('is-active', on);
    });
}

async function toggleReaction(message, emoji) {
    const key = String(message.id);
    const mine = myReactions.get(key) || new Set();
    const removing = mine.has(emoji);
    const data = removing
        ? await api(`/api/reactions/${encodeURIComponent(message.id)}/${encodeURIComponent(emoji)}`, { method: 'DELETE' })
        : await api('/api/reactions', { method: 'POST', body: JSON.stringify({ messageId: message.id, emoji }) });
    if (!data.success) {
        showToast(data.message || 'Не удалось сохранить реакцию', 'error');
        return;
    }
    const list = Array.isArray(message.reactions) ? message.reactions.slice() : [];
    const has = list.some(x => (x && typeof x === 'object' ? x.emoji : x) === emoji);
    if (removing) {
        mine.delete(emoji);
        // Реакция, которой не было в ответе сервера, — только наша: убираем.
        // Пришедшую с сервером могли поставить и другие — оставляем до
        // следующей загрузки истории.
        if (!message._serverReactions || !message._serverReactions.has(emoji)) {
            message.reactions = list.filter(x => (x && typeof x === 'object' ? x.emoji : x) !== emoji);
        }
    } else {
        mine.add(emoji);
        if (!message._serverReactions) message._serverReactions = new Set(list.map(x => (x && typeof x === 'object' ? x.emoji : x)));
        if (!has) message.reactions = [...list, emoji];
    }
    myReactions.set(key, mine);
    const bubble = elements.chatMessages.querySelector(`[data-message-id="${CSS.escape(key)}"]`);
    const container = bubble && bubble.querySelector('.reactions');
    if (container) renderReactions(container, bubble._message || message);
}

function clearReply() {
    replyToMessageId = null;
    elements.replyPreview.classList.add('hidden');
    elements.replyPreviewText.textContent = '';
}

function cancelEditing() {
    if (editingMessageId) elements.messageInput.value = '';
    editingMessageId = null;
}
