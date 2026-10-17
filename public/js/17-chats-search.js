// public/js/17-chats-search.js — создание, вход и удаление чатов, поиск, прокрутка ленты.
// Вынесено из public/script.js (строки 6642–6985 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Разделы «Чаты: создание, вход, удаление» и «Поиск», затем функции прокрутки (isNearBottom, scrollToBottom).
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Чаты: создание, вход, удаление ====================

async function createChat() {
    const name = document.getElementById('new-chat-name').value.trim();
    if (!name) return showToast('Введите название', 'error');
    const data = await api('/api/chats', {
        method: 'POST',
        body: JSON.stringify({ name }),
    });
    if (data.success) {
        document.getElementById('new-chat-name').value = '';
        // Создатель: V = {я}, how = creator, bootstrapDone записываются сразу (signed-membership.md, 5.1).
        if (data.chat.room_id) {
            const client = await getReadyE2eeClient();
            if (client) {
                try { await client.noteRoomCreated(data.chat.room_id, currentUser.username); } catch (err) { console.warn('E2EE: состав новой группы не записан:', err); }
            }
        }
        showToast('Чат создан', 'success');
        closeModal(elements.newChatModal);
        loadChats();
        openChat(data.chat.id, data.chat.room_id, data.chat.name, data.chat.avatar, 0, 0);
    } else {
        showToast(data.message, 'error');
    }
}

async function deleteChat() {
    if (!currentChatId) return;
    const roomId = currentRoomId;
    if (!confirm(roomId ? 'Выйти из группы?' : 'Удалить чат?')) return;
    // Сообщения комнаты хранятся без автора и удаляются вместе с аккаунтом (sealed-sender.md,
    // 12.1): выходящий решает, убрать ли свои сразу. По умолчанию (Отмена) - оставить.
    let removeMine = false;
    if (roomId) {
        removeMine = confirm('Удалить ваши сообщения в этой группе?\n\nОК - удалить сейчас.\nОтмена - оставить: они удалятся вместе с аккаунтом, но не раньше.');
    }
    const data = await api(`/api/chats/${currentChatId}${removeMine ? '?deleteMessages=1' : ''}`, { method: 'DELETE' });
    if (data.success) {
        if (roomId) await forgetLeftRoom(roomId);
        showToast(roomId ? 'Вы вышли из группы' : 'Чат удалён', 'success');
        closeModal(elements.chatMenuModal);
        resetChatView();
        loadChats();
    } else {
        showToast(data.message, 'error');
    }
}

// Локальная очистка комнаты после выхода: ключи, индекс отправителей (вместе с
// надгробиями), архив, имена участников. Сбой не мешает выходу.
async function forgetLeftRoom(roomId) {
    roomParticipants.delete(Number(roomId));
    roomMemberNames.delete(Number(roomId));
    try {
        const client = await getReadyE2eeClient();
        if (client) await client.forgetRoom(roomId);
    } catch (err) {
        console.warn('E2EE: локальные данные комнаты не очищены:', err);
    }
}

// ==================== Поиск ====================
// Серверного поиска нет (R6): список чатов фильтруется по названию, а в открытом
// чате ищется по уже загруженным и расшифрованным сообщениям. Запросов на сервер
// при поиске нет (кнопка «Искать в более ранних» догружает обычные страницы
// истории), открытый текст нигде не сохраняется — ни в localStorage, ни в
// IndexedDB: свёртка текста m._fold живёт в памяти вкладки вместе с самим
// сообщением. Сравнение и индексы — public/lib/text-search.js (NyxoTextSearch).

let chatFilter = '';

// Текст с выделением совпадений через <mark>: узлы строятся из textContent,
// innerHTML не используется (название чата — данные).
function setHighlightedText(el, text, ranges) {
    if (!ranges || ranges.length === 0) {
        el.textContent = text;
        return;
    }
    el.replaceChildren(...NyxoTextSearch.splitSegments(text, ranges).map((part) => {
        if (!part.match) return document.createTextNode(part.text);
        const mark = document.createElement('mark');
        mark.textContent = part.text;
        return mark;
    }));
}

// Фильтр списка чатов: перерисовка на следующем кадре после ввода.
function applyChatFilter() {
    chatFilter = elements.searchInput.value;
    renderChatList();
}

// ---- Поиск в открытом чате ----

const CHAT_SEARCH_DEBOUNCE_MS = 150;
const CHAT_SEARCH_OLDER_PAGES = 3;          // «Искать в более ранних»: до 3 страниц за нажатие
const HIGHLIGHT_ALL = 'nyxo-search';
const HIGHLIGHT_CURRENT = 'nyxo-search-current';

const chatSearch = {
    open: false,
    matches: [],        // [{ key: элемент сообщения, start, end }] в порядке ленты
    current: -1,
    capped: false,      // совпадений больше предела
    timer: 0,
    pending: false,     // введён запрос, пауза до пересчёта ещё не прошла
    loadingOlder: false,
};

// CSS Custom Highlight API: подсветка без изменения DOM. Где её нет, подсвечивается
// только сообщение с текущим совпадением (рамка).
function supportsCustomHighlights() {
    return typeof CSS !== 'undefined' && Boolean(CSS.highlights) && typeof Highlight === 'function';
}

function clearCurrentSearchMark() {
    if (supportsCustomHighlights()) CSS.highlights.delete(HIGHLIGHT_CURRENT);
    elements.chatMessages.querySelectorAll('.message.is-search-current').forEach(el => el.classList.remove('is-search-current'));
}

function clearSearchHighlights() {
    if (supportsCustomHighlights()) CSS.highlights.delete(HIGHLIGHT_ALL);
    clearCurrentSearchMark();
}

// Ищется только то, что расшифровано и лежит в пузыре одним текстовым узлом, равным
// тексту сообщения: нерасшифрованные (_e2eeFailed) и сообщения без текста пропускаются.
function searchableText(el) {
    const message = el && el._message;
    if (!message || message._e2eeFailed || typeof message.text !== 'string' || message.text === '') return null;
    const textEl = el.querySelector('.message-text');
    const node = textEl && textEl.firstChild;
    return node && node.nodeType === Node.TEXT_NODE && node.data === message.text ? { message, node } : null;
}

function collectSearchEntries() {
    const entries = [];
    elements.chatMessages.querySelectorAll('.message').forEach((el) => {
        const found = searchableText(el);
        if (!found) return;
        const { message } = found;
        // Свёртка считается один раз на текст; правка сообщения меняет text — свёртка пересчитывается.
        if (!message._fold || message._fold.source !== message.text) message._fold = NyxoTextSearch.foldText(message.text);
        entries.push({ key: el, folded: message._fold });
    });
    return entries;
}

function matchRange(match) {
    const found = searchableText(match.key);
    if (!found) return null;
    const range = new Range();
    range.setStart(found.node, match.start);
    range.setEnd(found.node, match.end);
    return range;
}

function paintSearchHighlights() {
    if (!supportsCustomHighlights()) return;
    const all = new Highlight();
    for (const match of chatSearch.matches) {
        const range = matchRange(match);
        if (range) all.add(range);
    }
    CSS.highlights.set(HIGHLIGHT_ALL, all);
}

function renderChatSearchCounter() {
    const query = elements.chatSearchInput.value.trim();
    elements.chatSearchCounter.textContent = query
        ? NyxoTextSearch.formatCounter(chatSearch.current, chatSearch.matches.length, chatSearch.capped)
        : '';
}

function updateChatSearchButtons() {
    const none = chatSearch.matches.length === 0;
    elements.chatSearchPrev.disabled = none;
    elements.chatSearchNext.disabled = none;
    elements.chatSearchOlder.disabled = !hasMoreHistory || chatSearch.loadingOlder;
}

function goToSearchMatch(index, { scroll = true } = {}) {
    chatSearch.current = index;
    clearCurrentSearchMark();
    const match = chatSearch.matches[index];
    if (match) {
        match.key.classList.add('is-search-current');
        if (supportsCustomHighlights()) {
            const range = matchRange(match);
            if (range) CSS.highlights.set(HIGHLIGHT_CURRENT, new Highlight(range));
        }
        if (scroll) match.key.scrollIntoView({ block: 'center', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    }
    renderChatSearchCounter();
    updateChatSearchButtons();
}

// Пересчёт совпадений. keep — после догрузки или правки: остаться на том же
// совпадении, если оно ещё есть, и не прокручивать ленту. Без keep выбирается самое
// новое совпадение (нижнее в ленте) — оно же чаще всего нужно.
function runChatSearch({ keep = false } = {}) {
    clearTimeout(chatSearch.timer);
    chatSearch.pending = false;
    const query = elements.chatSearchInput.value.trim();
    const previous = keep && chatSearch.current >= 0 ? chatSearch.matches[chatSearch.current] : null;
    const { matches, capped } = NyxoTextSearch.collectMatches(collectSearchEntries(), query);
    chatSearch.matches = matches;
    chatSearch.capped = capped;
    clearSearchHighlights();
    if (matches.length === 0) {
        chatSearch.current = -1;
        renderChatSearchCounter();
        updateChatSearchButtons();
        return;
    }
    paintSearchHighlights();
    let index = matches.length - 1;
    if (previous) {
        const same = matches.findIndex(m => m.key === previous.key && m.start === previous.start);
        if (same >= 0) index = same;
    }
    goToSearchMatch(index, { scroll: !previous });
}

// Новое, исправленное или удалённое сообщение сделало результаты устаревшими:
// пересчёт через короткую паузу, без прокрутки.
function markChatSearchStale() {
    if (!chatSearch.open || !elements.chatSearchInput.value.trim()) return;
    clearTimeout(chatSearch.timer);
    chatSearch.timer = setTimeout(() => runChatSearch({ keep: true }), CHAT_SEARCH_DEBOUNCE_MS);
}

function stepChatSearch(dir) {
    if (chatSearch.matches.length === 0) return;
    // Сообщение из результатов могло исчезнуть (удаление, смена чата): пересчёт.
    if (chatSearch.matches.some(m => !m.key.isConnected)) {
        runChatSearch({ keep: true });
        if (chatSearch.matches.length === 0) return;
    }
    goToSearchMatch(NyxoTextSearch.stepIndex(chatSearch.current, chatSearch.matches.length, dir));
}

function openChatSearch() {
    if (!currentChatId) return;
    chatSearch.open = true;
    elements.chatSearch.classList.remove('hidden');
    elements.chatSearchBtn.setAttribute('aria-expanded', 'true');
    updateChatSearchButtons();
    elements.chatSearchInput.focus({ preventScroll: true });
    if (elements.chatSearchInput.value.trim()) runChatSearch();
}

function closeChatSearch({ focusButton = false } = {}) {
    clearTimeout(chatSearch.timer);
    chatSearch.pending = false;
    const wasOpen = chatSearch.open;
    chatSearch.open = false;
    chatSearch.matches = [];
    chatSearch.current = -1;
    chatSearch.capped = false;
    chatSearch.loadingOlder = false;
    clearSearchHighlights();
    elements.chatSearch.classList.add('hidden');
    elements.chatSearchBtn.setAttribute('aria-expanded', 'false');
    elements.chatSearchInput.value = '';
    elements.chatSearchCounter.textContent = '';
    if (wasOpen && focusButton) elements.chatSearchBtn.focus({ preventScroll: true });
}

// «Искать в более ранних»: за одно нажатие догружает до трёх страниц истории тем же
// путём, что прокрутка вверх (loadOlderMessages), и показывает ход. Смена чата
// прерывает загрузку.
async function searchOlderMessages() {
    if (!chatSearch.open || chatSearch.loadingOlder || !hasMoreHistory) return;
    const seq = openChatSeq;
    chatSearch.loadingOlder = true;
    updateChatSearchButtons();
    try {
        for (let page = 1; page <= CHAT_SEARCH_OLDER_PAGES && hasMoreHistory; page++) {
            elements.chatSearchCounter.textContent = `Загружаем ранние сообщения: ${page} из ${CHAT_SEARCH_OLDER_PAGES}`;
            await loadOlderMessages();
            if (seq !== openChatSeq) return;
        }
    } finally {
        if (seq === openChatSeq) {
            chatSearch.loadingOlder = false;
            if (chatSearch.open) runChatSearch({ keep: true });
        }
    }
}

function setupChatSearchListeners() {
    elements.chatSearchBtn.addEventListener('click', () => {
        if (chatSearch.open) closeChatSearch({ focusButton: true });
        else openChatSearch();
    });
    elements.chatSearchInput.addEventListener('input', () => {
        clearTimeout(chatSearch.timer);
        chatSearch.pending = true;
        chatSearch.timer = setTimeout(() => runChatSearch(), CHAT_SEARCH_DEBOUNCE_MS);
    });
    elements.chatSearchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            // Ввод ещё не обработан (пауза не прошла): сначала пересчёт.
            if (chatSearch.pending) runChatSearch();
            else stepChatSearch(e.shiftKey ? -1 : 1);
        } else if (e.key === 'Escape') {
            e.preventDefault();
            closeChatSearch({ focusButton: true });
        }
    });
    elements.chatSearchPrev.addEventListener('click', () => stepChatSearch(-1));
    elements.chatSearchNext.addEventListener('click', () => stepChatSearch(1));
    elements.chatSearchOlder.addEventListener('click', searchOlderMessages);
    elements.chatSearchClose.addEventListener('click', () => closeChatSearch({ focusButton: true }));
}

function isNearBottom() {
    const el = elements.chatMessages;
    return el.scrollHeight - el.scrollTop - el.clientHeight < 120;
}

function prefersReducedMotion() {
    try {
        return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {
        return false;
    }
}

// smooth — плавная прокрутка по кнопке «вниз»; обычная — мгновенная.
function scrollToBottom(smooth = false) {
    const el = elements.chatMessages;
    if (smooth === true && typeof el.scrollTo === 'function' && !prefersReducedMotion()) {
        el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
    } else {
        el.scrollTop = el.scrollHeight;
        resetJumpDown();
    }
    markVisibleMessagesRead();
}
