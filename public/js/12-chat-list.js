// public/js/12-chat-list.js — список чатов: кэш, личные флаги, строки списка, контекстные меню.
// Вынесено из public/script.js (строки 4834–5394 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Раздел «Список чатов» (в начале — небольшие функции сообщений, которыми пользуется список).
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Список чатов ====================

function isOwnMessage(message) {
    if (!currentUser) return false;
    if (message.room_id) {
        // Сообщение комнаты: в строке автора нет. Главное - результат расшифровки
        // (senderId из индекса отправителей); подсказка mine с сервера (ответ на
        // отправку, копия события на user:<id>) - только косметика для сообщения,
        // которое расшифровать не удалось, иначе оно «чужое» (sealed-sender.md, 9.4).
        if (Number.isSafeInteger(message._senderId)) return message._senderId === currentUser.id;
        return message.mine === true;
    }
    // Ответы бота хранятся с user_id владельца чата и sent = 0 — раньше
    // они отображались как собственные сообщения пользователя.
    return message.user_id === currentUser.id && Number(message.sent) !== 0;
}

// Сообщение относится к открытому чату? Групповые — по room_id, личный
// чат с ботом — по chat_id. Раньше сравнение шло через "==", и при
// открытом чате без комнаты (null == null) в него попадали чужие сообщения.
function belongsToCurrentChat(chatId, roomId) {
    if (currentChatId === null) return false;
    if (currentRoomId) return roomId != null && Number(roomId) === Number(currentRoomId);
    return roomId == null && Number(chatId) === Number(currentChatId);
}

// Подпись последнего сообщения: { icon, text } — замок для E2EE,
// скрепка для файла (иконка отдельным элементом, не символом в тексте).
function messagePreview(message) {
    if (message.encrypted || message.room_id) return { icon: 'lock', text: 'Зашифрованное сообщение' };
    const text = message.text || message.last_message || '';
    return message.file_url ? { icon: 'paperclip', text: text || 'Файл' } : { icon: null, text };
}

function chatLastPreview(chat) {
    if (chat.last_message_encrypted || (chat.room_id && chat.last_message_id)) return { icon: 'lock', text: 'Зашифрованное сообщение' };
    if (!chat.last_message_id) return { icon: null, text: 'Нет сообщений' };
    const isFile = Boolean(chat.last_message_type) && chat.last_message_type !== 'text';
    return { icon: isFile ? 'paperclip' : null, text: chat.last_message || (isFile ? 'Файл' : '') };
}

// Короткое описание сообщения для превью ответа.
function messageSummary(message) {
    if (message._file) return `Файл: ${message.text || safeDisplayName(message._file.name)}`;
    if (message.file_url) return message.text ? `Файл: ${message.text}` : 'Файл';
    return message.text || '';
}

function setChatBadge(item, count) {
    let badge = item.querySelector('.chat-badge');
    if (!count) {
        if (badge) badge.remove();
        return;
    }
    if (!badge) {
        badge = document.createElement('div');
        badge.className = 'chat-badge badge';
        item.appendChild(badge);
    }
    badge.dataset.count = String(count);
    // Скринридеру — «3 непрочитанных сообщения» после названия чата, а не голая цифра; на экране — число.
    const shown = document.createElement('span');
    shown.setAttribute('aria-hidden', 'true');
    shown.textContent = count > 99 ? '99+' : String(count);
    const spoken = document.createElement('span');
    spoken.className = 'visually-hidden';
    spoken.textContent = `${count} ${plural(count, ['непрочитанное сообщение', 'непрочитанных сообщения', 'непрочитанных сообщений'])}`;
    badge.replaceChildren(shown, spoken);
}

// ---- Кэш списка и личные флаги чатов ----

let chatListData = [];          // последний GET /api/chats (порядок сервера + локальные сдвиги)
const chatsById = new Map();    // chatId -> объект из chatListData
let currentChatExtra = {};      // флаги открытого чата, если его ещё нет в списке
let archiveExpanded = false;

function normalizeExpiry(value) {
    const n = Math.floor(Number(value) || 0);
    return n > 0 ? n : 0;
}

function expiryLabel(seconds) {
    if (EXPIRY_LABELS[seconds]) return EXPIRY_LABELS[seconds];
    if (seconds < 3600) return `${Math.round(seconds / 60)} мин`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} ч`;
    return `${Math.round(seconds / 86400)} д`;
}

function expiryShort(seconds) {
    return EXPIRY_SHORT[seconds] || expiryLabel(seconds);
}

function findChatMeta(chatId, roomId) {
    if (roomId != null) return chatListData.find(c => c.room_id != null && Number(c.room_id) === Number(roomId)) || null;
    return chatsById.get(Number(chatId)) || null;
}

function getCurrentChatMeta() {
    return chatsById.get(Number(currentChatId)) || currentChatExtra;
}

function openChatFromMeta(meta) {
    openChat(meta.id, meta.room_id, meta.name, meta.avatar, meta.online, meta.is_bot);
}

function createChatItemFlags(chat) {
    const flags = document.createElement('span');
    flags.className = 'chat-item-flags';
    if (chat.pinned) flags.appendChild(icon('pin', { size: 'sm', label: 'Закреплён' }));
    if (chat.muted) flags.appendChild(icon('bell-off', { size: 'sm', label: 'Без звука' }));
    const expiry = normalizeExpiry(chat.expiry_seconds);
    if (expiry) flags.appendChild(icon('timer', { size: 'sm', label: `Исчезающие сообщения: ${expiryLabel(expiry)}` }));
    return flags.childNodes.length > 0 ? flags : null;
}

// Долгое нажатие на телефоне. После него браузер прислал бы click — он не
// должен открывать чат или сразу закрывать только что открытое меню:
// preventDefault на touchend отменяет синтетический click, а отметка
// времени — страховка для браузеров, которые его всё равно присылают.
let longPressAt = 0;
function recentLongPress() {
    return Date.now() - longPressAt < 400;
}

function attachLongPress(el, onLongPress) {
    let timer = null;
    let fired = false;
    el.addEventListener('touchstart', (e) => {
        clearTimeout(timer);
        fired = false;
        const touch = e.touches[0];
        timer = setTimeout(() => {
            fired = true;
            onLongPress(touch.clientX, touch.clientY);
        }, 600);
    }, { passive: true });
    el.addEventListener('touchend', (e) => {
        clearTimeout(timer);
        if (!fired) return;
        fired = false;
        longPressAt = Date.now();
        if (e.cancelable) e.preventDefault();
    });
    const cancel = () => clearTimeout(timer);
    el.addEventListener('touchmove', cancel, { passive: true });
    el.addEventListener('touchcancel', cancel);
    el.addEventListener('contextmenu', cancel);
}

function createChatItem({ id, roomId, name, isBot, preview, unread, onClick, meta, nameRanges }) {
    const div = document.createElement('div');
    div.className = 'chat-item';
    div.dataset.id = id;
    div.dataset.roomId = roomId || '';
    div.tabIndex = 0;
    div.setAttribute('role', 'button');
    if (Number(id) === Number(currentChatId)) {
        div.classList.add('active', 'is-active');
        div.setAttribute('aria-current', 'true');
    }
    if (meta) {
        div.classList.toggle('is-pinned', Boolean(meta.pinned));
        div.classList.toggle('is-muted', Boolean(meta.muted));
        div.classList.toggle('is-archived', Boolean(meta.archived));
    }

    const avatarEl = document.createElement('div');
    avatarEl.className = 'chat-avatar-small';
    avatarEl.setAttribute('aria-hidden', 'true');
    renderAvatar(avatarEl, name, isBot);

    const info = document.createElement('div');
    info.className = 'chat-info';
    const nameEl = document.createElement('div');
    nameEl.className = 'chat-name';
    setHighlightedText(nameEl, name, nameRanges);
    if (nameRanges && meta && meta.archived) {
        // В общем списке фильтра архивный чат отличается только классом: для скринридера — слово.
        const hint = document.createElement('span');
        hint.className = 'visually-hidden';
        hint.textContent = ', в архиве';
        nameEl.appendChild(hint);
    }
    const lastEl = document.createElement('div');
    lastEl.className = 'chat-last';
    setChatLast(lastEl, preview);
    info.append(nameEl, lastEl);

    div.append(avatarEl, info);
    const flags = meta ? createChatItemFlags(meta) : null;
    if (flags) div.appendChild(flags);
    setChatBadge(div, unread);
    div.addEventListener('click', () => {
        if (recentLongPress()) return;
        onClick();
    });
    div.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onClick();
        } else if (meta && (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10'))) {
            e.preventDefault();
            const rect = div.getBoundingClientRect();
            showChatItemMenu(rect.left + 24, rect.bottom - 8, meta, div);
        }
    });
    if (meta) {
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            e.stopPropagation();
            showChatItemMenu(e.clientX, e.clientY, meta, div);
        });
        attachLongPress(div, (x, y) => showChatItemMenu(x, y, meta, div));
    }
    return div;
}

function setChatLast(el, preview) {
    const text = preview && typeof preview === 'object' ? preview.text : String(preview || '');
    const iconName = preview && typeof preview === 'object' ? preview.icon : null;
    if (iconName) el.replaceChildren(icon(iconName, { size: 'sm' }), document.createTextNode(text));
    else el.textContent = text;
}

function createChatItemFromMeta(chat, nameRanges) {
    return createChatItem({
        nameRanges,
        id: chat.id,
        roomId: chat.room_id,
        name: chat.name,
        isBot: Boolean(Number(chat.is_bot)),
        preview: chatLastPreview(chat),
        unread: Number(chat.id) === Number(currentChatId) ? 0 : Number(chat.unread) || 0,
        onClick: () => openChatFromMeta(chat),
        meta: chat,
    });
}

// Закреплённые — сверху, внутри групп сохраняется порядок сервера (по
// последнему сообщению). Сервер сортирует так же, но после локальной смены
// флага порядок поправляем сразу, не дожидаясь нового списка.
function sortedChats(list) {
    return list
        .map((chat, index) => ({ chat, index }))
        .sort((a, b) => (Number(Boolean(b.chat.pinned)) - Number(Boolean(a.chat.pinned))) || (a.index - b.index))
        .map(x => x.chat);
}

let focusArchiveToggle = false;
function renderChatList() {
    const focused = document.activeElement && document.activeElement.closest
        ? document.activeElement.closest('#chats-list .chat-item') : null;
    const focusedId = focused ? focused.dataset.id : null;

    // Фильтр по названию (R6): совпадения из того же списка, закреплённые сверху,
    // архивные — наравне с остальными (переключатель архива в это время не нужен).
    const filtered = NyxoTextSearch.filterChats(chatListData, chatFilter);
    if (filtered !== null) {
        elements.chatsEmpty.classList.toggle('hidden', filtered.length > 0);
        elements.chatsList.replaceChildren(...filtered.map(({ chat, ranges }) => createChatItemFromMeta(chat, ranges)));
        if (focusedId) {
            const again = elements.chatsList.querySelector(`.chat-item[data-id="${CSS.escape(focusedId)}"]`);
            if (again) again.focus({ preventScroll: true });
        }
        return;
    }
    elements.chatsEmpty.classList.add('hidden');

    const active = sortedChats(chatListData.filter(c => !c.archived));
    const archived = sortedChats(chatListData.filter(c => c.archived));
    const fragment = document.createDocumentFragment();
    active.forEach(chat => fragment.appendChild(createChatItemFromMeta(chat)));
    let toggle = null;
    if (archived.length > 0) {
        toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'archive-toggle';
        toggle.setAttribute('aria-expanded', archiveExpanded ? 'true' : 'false');
        const label = document.createElement('span');
        label.textContent = `Архив (${archived.length})`;
        toggle.append(icon('archive'), label);
        const unread = archived.reduce((sum, c) => sum + (c.muted ? 0 : Number(c.unread) || 0), 0);
        if (unread > 0) {
            const badge = document.createElement('span');
            badge.className = 'badge';
            badge.textContent = unread > 99 ? '99+' : String(unread);
            toggle.appendChild(badge);
        }
        toggle.addEventListener('click', () => {
            archiveExpanded = !archiveExpanded;
            focusArchiveToggle = true;
            renderChatList();
        });
        fragment.appendChild(toggle);
        if (archiveExpanded) archived.forEach(chat => fragment.appendChild(createChatItemFromMeta(chat)));
    }
    elements.chatsList.replaceChildren(fragment);
    if (focusArchiveToggle && toggle) toggle.focus({ preventScroll: true });
    focusArchiveToggle = false;
    if (focusedId) {
        const again = elements.chatsList.querySelector(`.chat-item[data-id="${CSS.escape(focusedId)}"]`);
        if (again) again.focus({ preventScroll: true });
    }
}

let loadChatsSeq = 0;
async function loadChats() {
    const seq = ++loadChatsSeq;
    const data = await api('/api/chats');
    if (!data.success || seq !== loadChatsSeq || !currentUser) return;
    chatListData = Array.isArray(data.chats) ? data.chats : [];
    chatsById.clear();
    chatListData.forEach((chat) => {
        chat.expiry_seconds = normalizeExpiry(chat.expiry_seconds);
        chat.pinned = Boolean(chat.pinned);
        chat.muted = Boolean(chat.muted);
        chat.archived = Boolean(chat.archived);
        if (Number(chat.id) === Number(currentChatId)) chat.unread = 0;
        chatsById.set(Number(chat.id), chat);
    });
    renderChatList();
    updateChatIndicators();
}

// Список чатов перезапрашивается не чаще раза в полсекунды — раньше КАЖДОЕ
// входящее сообщение в любом неоткрытом чате вызывало GET /api/chats (самый
// тяжёлый запрос сервера) и быстро упиралось в rate limit.
let loadChatsTimer = null;
function scheduleLoadChats() {
    if (!currentUser) return;
    clearTimeout(loadChatsTimer);
    loadChatsTimer = setTimeout(loadChats, 500);
}

function findChatItem(chatId, roomId) {
    const items = elements.chatsList.querySelectorAll('.chat-item');
    for (const item of items) {
        if (roomId != null ? item.dataset.roomId === String(roomId) : (item.dataset.roomId === '' && item.dataset.id === String(chatId))) {
            return item;
        }
    }
    return null;
}

// Новое сообщение обновляет кэш списка (превью, счётчик, порядок) и
// перерисовывает список без запроса к серверу.
function updateChatListOnMessage(message, isCurrent) {
    const meta = findChatMeta(message.chat_id, message.room_id);
    if (!meta) return scheduleLoadChats(); // новый для нас чат
    meta.last_message_id = message.id;
    meta.last_message_encrypted = Boolean(message.encrypted);
    meta.last_message = message.encrypted || message.room_id ? null : (message.text || '');
    meta.last_message_type = message.file_url ? (message.message_type || 'file') : 'text';
    if (!isCurrent && !isOwnMessage(message)) meta.unread = (Number(meta.unread) || 0) + 1;
    const index = chatListData.indexOf(meta);
    if (index > 0) {
        chatListData.splice(index, 1);
        chatListData.unshift(meta);
    }
    // Архивный чат без звука остаётся в архиве, иначе сервер его
    // разархивирует — узнаем из свежего списка.
    if (meta.archived && !meta.muted) scheduleLoadChats();
    renderChatList();
}

function setActiveChatItem(chatId, roomId) {
    elements.chatsList.querySelectorAll('.chat-item.active, .chat-item.is-active').forEach((el) => {
        el.classList.remove('active', 'is-active');
        el.removeAttribute('aria-current');
    });
    if (chatId == null) return;
    const meta = chatsById.get(Number(chatId));
    if (meta) meta.unread = 0;
    const item = findChatItem(chatId, roomId);
    if (item) {
        item.classList.add('active', 'is-active');
        item.setAttribute('aria-current', 'true');
        setChatBadge(item, 0);
    }
}

// ---- Клавиатура во всплывающих меню (сообщения и строки чата) ----

function popupMenuItems(menu) {
    return Array.from(menu.querySelectorAll('button')).filter((btn) => !btn.disabled && btn.offsetParent !== null);
}

// Стрелки двигают фокус по кругу, Home/End — в начало и конец; Esc и Tab закрывают
// меню (hide сам возвращает фокус туда, откуда меню открыли).
function onPopupMenuKeydown(e, menu, hide) {
    if (e.key === 'Escape' || e.key === 'Tab') {
        e.preventDefault();
        hide();
        return;
    }
    const items = popupMenuItems(menu);
    if (items.length === 0) return;
    const index = items.indexOf(document.activeElement);
    let target = null;
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') target = items[(index + 1) % items.length];
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') target = index < 0 ? items[items.length - 1] : items[(index - 1 + items.length) % items.length];
    else if (e.key === 'Home') target = items[0];
    else if (e.key === 'End') target = items[items.length - 1];
    if (!target) return;
    e.preventDefault();
    target.focus({ preventScroll: true });
}

// ---- Контекстное меню строки чата и меню чата ----

let chatItemMenuChat = null;
let chatItemMenuReturnFocus = null;   // строка чата, с которой открыли меню: сюда вернётся фокус

// opener — строка чата, из которой открыто меню (клавиатура, правый клик, долгое нажатие).
function showChatItemMenu(x, y, chat, opener = null) {
    hideMessageMenu();
    chatItemMenuChat = chat;
    chatItemMenuReturnFocus = opener || document.activeElement;
    setIconLabel(elements.ctxPinBtn, chat.pinned ? 'pin-off' : 'pin', chat.pinned ? 'Открепить' : 'Закрепить');
    setIconLabel(elements.ctxMuteBtn, chat.muted ? 'bell' : 'bell-off', chat.muted ? 'Включить звук' : 'Без звука');
    setIconLabel(elements.ctxArchiveBtn, chat.archived ? 'archive-restore' : 'archive', chat.archived ? 'Вернуть из архива' : 'В архив');
    const menu = elements.chatItemMenu;
    menu.classList.remove('hidden');
    const rect = menu.getBoundingClientRect();
    menu.style.left = Math.max(8, Math.min(x, window.innerWidth - rect.width - 8)) + 'px';
    menu.style.top = Math.max(8, Math.min(y, window.innerHeight - rect.height - 8)) + 'px';
    elements.ctxPinBtn.focus({ preventScroll: true });
}

// Закрывая меню, возвращает фокус на строку чата — но только если фокус был в самом меню
// (после Escape он иначе уходил на body); клик в другое место фокус не отбирает. Список
// чатов мог перерисоваться, пока меню было открыто: тогда строка ищется заново по чату.
function hideChatItemMenu() {
    const menu = elements.chatItemMenu;
    if (menu.classList.contains('hidden')) return;
    const hadFocus = menu.contains(document.activeElement);
    menu.classList.add('hidden');
    let target = chatItemMenuReturnFocus;
    chatItemMenuReturnFocus = null;
    if (!hadFocus) return;
    if ((!target || !target.isConnected) && chatItemMenuChat) target = findChatItem(chatItemMenuChat.id, chatItemMenuChat.room_id);
    if (target && target.isConnected) target.focus({ preventScroll: true });
}

// Клик вне меню закрывает его — кроме click, который браузер прислал
// сразу после долгого нажатия, открывшего это меню.
function onDocumentClickForMenus() {
    if (recentLongPress()) return;
    hideMessageMenu();
    hideChatItemMenu();
}

function onChatItemMenuAction(key) {
    const chat = chatItemMenuChat;
    hideChatItemMenu();
    chatItemMenuChat = null;
    if (chat) toggleChatPref(chat.id, key);
}

const PREF_TOASTS = {
    pinned: { true: 'Чат закреплён', false: 'Чат откреплён' },
    muted: { true: 'Чат без звука: уведомлений не будет', false: 'Звук чата включён' },
    archived: { true: 'Чат перенесён в архив', false: 'Чат возвращён из архива' },
};

async function toggleChatPref(chatId, key) {
    const meta = chatsById.get(Number(chatId));
    if (!chatId || !meta) return;
    const value = !meta[key];
    const data = await api(`/api/chats/${chatId}/prefs`, { method: 'POST', body: JSON.stringify({ [key]: value }) });
    if (!data.success) {
        showToast(data.message || 'Не удалось сохранить настройку', 'error');
        return;
    }
    ['pinned', 'muted', 'archived'].forEach((k) => {
        if (typeof data[k] === 'boolean') meta[k] = data[k];
    });
    if (typeof data[key] !== 'boolean') meta[key] = value;
    renderChatList();
    if (Number(chatId) === Number(currentChatId)) {
        updateChatIndicators();
        renderChatMenu();
    }
    showToast(PREF_TOASTS[key][String(meta[key])], 'success');
    scheduleLoadChats();
}

function openChatMenu() {
    if (!currentChatId) return;
    renderChatMenu();
    openModal(elements.chatMenuModal);
}

function renderChatMenu() {
    if (!currentChatId) return;
    const meta = getCurrentChatMeta();
    const known = chatsById.has(Number(currentChatId));
    setIconLabel(elements.pinChatBtn, meta.pinned ? 'pin-off' : 'pin', meta.pinned ? 'Открепить' : 'Закрепить');
    setIconLabel(elements.muteChatBtn, meta.muted ? 'bell' : 'bell-off', meta.muted ? 'Включить звук' : 'Без звука');
    setIconLabel(elements.archiveChatBtn, meta.archived ? 'archive-restore' : 'archive', meta.archived ? 'Вернуть из архива' : 'В архив');
    [elements.pinChatBtn, elements.muteChatBtn, elements.archiveChatBtn].forEach((b) => { b.disabled = !known; });
    // Из группы выходят (и решают судьбу своих сообщений), чат с ботом удаляют.
    setIconLabel(elements.deleteChatBtn, 'trash', currentRoomId ? 'Выйти из группы' : 'Удалить чат с ботом');
    elements.expiryHint.textContent = currentRoomId
        ? 'Срок действует для новых сообщений всех участников группы. Уже отправленные сообщения не изменятся.'
        : 'Срок действует для новых сообщений этого чата. Уже отправленные сообщения не изменятся.';
    syncExpiryRadios();
    // «На этом устройстве» — только для групп: у чата с ботом нет ключей комнаты.
    elements.deviceSettings.classList.toggle('hidden', !currentRoomId);
    elements.noHistoryToggle.checked = roomHistoryMode(currentRoomId) === 'none';
}

// Включение «Не хранить историю» необратимо для уже прочитанного, поэтому требует
// подтверждения; выключение — без него. Что именно меняется и чего это не делает,
// сказано в окне (раздел 6 плана криптографии).
const NO_HISTORY_CONFIRM = 'Ключи к прочитанным сообщениям этой группы будут стираться из браузера, когда вы закроете чат или вкладку. '
    + 'Более ранние сообщения здесь больше не откроются, вернуть их нельзя.\n\n'
    + 'Это касается только этого устройства: у других участников и на сервере сообщения остаются, '
    + 'а чтобы они исчезли у всех, включите исчезающие сообщения. Другие участники об этой настройке не узнают.\n\n'
    + 'Браузер не гарантирует, что данные сразу будут затёрты на диске.';
const NO_HISTORY_CONFIRM_TITLE = 'Включить «Не хранить историю на этом устройстве»?';

async function onNoHistoryToggle() {
    const roomId = currentRoomId;
    const toggle = elements.noHistoryToggle;
    if (!roomId) return;
    const wantNone = toggle.checked;
    if (wantNone && !(await confirmAction(NO_HISTORY_CONFIRM, { title: NO_HISTORY_CONFIRM_TITLE, confirmLabel: 'Включить', danger: true }))) {
        toggle.checked = false;
        return;
    }
    if (roomId !== currentRoomId) return;   // пока отвечали, открыли другой чат
    toggle.disabled = true;
    try {
        await applyRoomHistoryMode(roomId, wantNone ? 'none' : 'keep');
        showToast(wantNone
            ? 'История не хранится на этом устройстве'
            : 'История снова хранится на этом устройстве. Стёртое не возвращается', 'success');
    } catch (err) {
        console.error('E2EE: не удалось изменить режим хранения истории:', err);
        toggle.checked = !wantNone;
        showToast('Не удалось изменить настройку', 'error');
    } finally {
        toggle.disabled = false;
        if (roomId === currentRoomId) updateChatIndicators();
    }
}

function syncExpiryRadios() {
    const value = normalizeExpiry(getCurrentChatMeta().expiry_seconds);
    elements.expiryFieldset.querySelectorAll('input[name="chat-expiry"]').forEach((radio) => {
        radio.checked = Number(radio.value) === value;
    });
}

function setExpiryRadiosDisabled(disabled) {
    elements.expiryFieldset.querySelectorAll('input[name="chat-expiry"]').forEach((radio) => { radio.disabled = disabled; });
}

async function setChatExpiry(seconds) {
    if (!currentChatId || !EXPIRY_OPTIONS.includes(seconds)) return;
    const chatId = currentChatId;
    const meta = getCurrentChatMeta();
    if (normalizeExpiry(meta.expiry_seconds) === seconds) return;
    setExpiryRadiosDisabled(true);
    const data = await api(`/api/chats/${chatId}/expiry`, { method: 'POST', body: JSON.stringify({ seconds }) });
    setExpiryRadiosDisabled(false);
    if (!data.success) {
        showToast(data.message || 'Не удалось изменить срок', 'error');
        if (chatId === currentChatId) syncExpiryRadios();
        return;
    }
    const value = normalizeExpiry(data.seconds !== undefined ? data.seconds : seconds);
    meta.expiry_seconds = value;
    if (currentRoomId && chatId === currentChatId) syncRoomKeyPolicy(currentRoomId, value);
    renderChatList();
    if (chatId === currentChatId) {
        updateChatIndicators();
        syncExpiryRadios();
    }
    showToast(value ? `Исчезающие сообщения: ${expiryLabel(value)}` : 'Исчезающие сообщения выключены', 'success');
}

// Подпись под названием чата: у группы — число участников (из списка
// чатов), у бота — «Бот · без сквозного шифрования» (с ним переписка идёт
// открытым текстом, и это видно сразу), иначе — в сети / не в сети.
function renderChatStatus() {
    if (!currentChatId) return;
    const meta = getCurrentChatMeta();
    const members = Number(meta.member_count);
    if (currentRoomId && members > 0) {
        elements.chatStatus.textContent = `${members} ${plural(members, ['участник', 'участника', 'участников'])}`;
        elements.chatStatus.className = 'status';
        return;
    }
    const online = Boolean(Number(meta.online !== undefined ? meta.online : currentChatExtra.online));
    elements.chatStatus.textContent = Number(meta.is_bot) ? 'Бот · без сквозного шифрования' : (currentRoomId ? 'Группа' : (online ? 'В сети' : 'Не в сети'));
    elements.chatStatus.className = 'status ' + (online ? 'online' : 'offline');
}

// Индикаторы в шапке открытого чата: таймер исчезающих сообщений и «без звука».
function updateChatIndicators() {
    if (!currentChatId) return;
    renderChatStatus();
    const meta = getCurrentChatMeta();
    const expiry = normalizeExpiry(meta.expiry_seconds);
    elements.expiryIndicator.classList.toggle('hidden', !expiry);
    elements.expiryIndicatorText.textContent = expiry ? expiryShort(expiry) : '';
    const title = expiry ? `Исчезающие сообщения: ${expiryLabel(expiry)}` : '';
    elements.expiryIndicator.title = title;
    if (title) elements.expiryIndicator.setAttribute('aria-label', title);
    else elements.expiryIndicator.removeAttribute('aria-label');
    elements.mutedIndicator.classList.toggle('hidden', !meta.muted);
    elements.noHistoryIndicator.classList.toggle('hidden', !(currentRoomId && roomHistoryMode(currentRoomId) === 'none'));
}
