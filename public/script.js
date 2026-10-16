// Сокет подключается только после входа. Раньше io() вызывался сразу при
// загрузке страницы: неавторизованное соединение сервер закрывал, клиент
// socket.io после такого отключения сам не переподключается — и после
// входа в аккаунт сообщения в реальном времени не приходили до F5.
const socket = io({ autoConnect: false });
let currentChatId = null;
let currentRoomId = null;
let currentUser = null;
let replyToMessageId = null;
let editingMessageId = null;
let menuMessage = null;              // сообщение, для которого открыто контекстное меню

// Состояние открытого чата: история грузится страницами с конца.
let openChatSeq = 0;          // защита от гонок при быстром переключении чатов (счётчик открытий чата, а не seq сообщений)
let oldestSeq = null;         // seq самого старого загруженного сообщения — курсор для ?beforeSeq=
let hasMoreHistory = false;
let loadingHistory = false;
let lastSeenSeq = 0;          // до какого seq пользователь уже видел открытый чат (seq сравнивается только внутри чата)
let membersChangedTimer = null; // debounce событий roomMembersChanged

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const MAX_FILES_PER_BATCH = 10;
const POW_TIMEOUT_MS = 60 * 1000;
const ANON_IDS_KEY = 'nyxo-anon-ids';
const FLASH_NOTICE_KEY = 'nyxo-notice';
const NOTIFY_PREF_PREFIX = 'nyxo-notify:';
const BOT_CHAT_PREFIX = 'nyxo-bot-chat:';
// Выключатель шифрования удалён (R7): флаги прежних версий стираются при старте.
const LEGACY_E2EE_PREF_PREFIX = 'e2ee-enabled:';
const E2EE_DB_PREFIX = 'nyxo-e2ee-';
const SESSION_CHANNEL = 'nyxo-session';

// Keepalive (контракт этапа 1, §5): GET /api/auth раз в 4 минуты, а также
// при возвращении во вкладку (если запроса не было дольше минуты), при
// появлении сети и после обрыва сокета.
const KEEPALIVE_MS = 4 * 60 * 1000;
const KEEPALIVE_VISIBLE_GAP_MS = 60 * 1000;

// Срок исчезающих сообщений: только эти значения принимает сервер (К2).
const EXPIRY_OPTIONS = [0, 300, 3600, 86400, 604800];
const EXPIRY_LABELS = { 300: '5 минут', 3600: '1 час', 86400: '1 день', 604800: '7 дней' };
const EXPIRY_SHORT = { 300: '5 мин', 3600: '1 ч', 86400: '1 д', 604800: '7 д' };

// Реакции: в API и в БД остаются эмодзи (совместимость со старыми данными),
// в интерфейсе — иконки. Эмодзи записаны escape-последовательностями: это
// ключи соответствия, а не текст интерфейса; '\u2764\uFE0F' — именно с
// вариантным селектором, как в белом списке сервера.
const REACTIONS = [
    { emoji: '\u{1F44D}', icon: 'thumbs-up', label: 'Нравится' },
    { emoji: '\u2764\uFE0F', icon: 'heart', label: 'Сердце' },
    { emoji: '\u{1F602}', icon: 'laugh', label: 'Смешно' },
    { emoji: '\u{1F622}', icon: 'frown', label: 'Грустно' },
    { emoji: '\u{1F525}', icon: 'flame', label: 'Огонь' },
];
const REACTION_BY_EMOJI = new Map(REACTIONS.map(r => [r.emoji, r]));

const elements = {
    // ---- Каркас приложения ----
    app: document.getElementById('app'),
    mainContent: document.querySelector('.main-content'),
    emptyState: document.getElementById('empty-state'),
    toast: document.getElementById('toast'),
    overlay: document.getElementById('overlay'),
    connectionStatus: document.getElementById('connection-status'),
    connectionStatusIcon: document.getElementById('connection-status-icon'),
    connectionStatusText: document.getElementById('connection-status-text'),

    // ---- Экран входа ----
    authScreen: document.getElementById('auth-screen'),
    authThemeBtn: document.getElementById('auth-theme-btn'),
    authNotice: document.getElementById('auth-notice'),
    authInvite: document.getElementById('auth-invite'),
    authInviteInput: document.getElementById('auth-invite-input'),
    authInviteError: document.getElementById('auth-invite-error'),
    authLifetime: document.getElementById('auth-lifetime'),
    authLifetimeDetail: document.getElementById('auth-lifetime-detail'),
    authInviteAdvice: document.getElementById('auth-invite-advice'),
    authProgress: document.getElementById('auth-progress'),
    anonStartBtn: document.getElementById('anon-start-btn'),
    inviteToggleBtn: document.getElementById('invite-toggle-btn'),
    aboutOpenBtn: document.getElementById('about-open-btn'),
    authLinksSep: document.getElementById('auth-links-sep'),
    onionOpenBtn: document.getElementById('onion-open-btn'),

    // ---- Окно «Как это работает» ----
    aboutModal: document.getElementById('about-modal'),
    aboutTor: document.getElementById('about-tor'),
    aboutOnion: document.getElementById('about-onion'),
    aboutOnionAddress: document.getElementById('about-onion-address'),
    aboutOnionCopyBtn: document.getElementById('about-onion-copy-btn'),
    aboutOnionLink: document.getElementById('about-onion-link'),
    aboutOnionMissing: document.getElementById('about-onion-missing'),
    aboutOnionCurrent: document.getElementById('about-onion-current'),

    // ---- Сайдбар ----
    sidebar: document.querySelector('.sidebar'),
    themeToggleBtn: document.getElementById('theme-toggle-btn'),
    newChatBtn: document.getElementById('new-chat-btn'),
    anonNote: document.getElementById('anon-note'),
    anonNoteText: document.getElementById('anon-note-text'),
    searchInput: document.getElementById('search-input'),
    chatsEmpty: document.getElementById('chats-empty'),
    chatsList: document.getElementById('chats-list'),
    profileBtn: document.getElementById('profile-btn'),
    logoutBtn: document.getElementById('logout-btn'),

    // ---- Шапка чата ----
    chatHeader: document.getElementById('chat-header'),
    backBtn: document.getElementById('back-btn'),
    chatAvatar: document.getElementById('chat-avatar'),
    chatName: document.getElementById('chat-name'),
    chatStatus: document.getElementById('chat-status'),
    expiryIndicator: document.getElementById('expiry-indicator'),
    expiryIndicatorText: document.getElementById('expiry-indicator-text'),
    mutedIndicator: document.getElementById('muted-indicator'),
    noHistoryIndicator: document.getElementById('no-history-indicator'),
    deviceSettings: document.getElementById('device-settings'),
    noHistoryToggle: document.getElementById('no-history-toggle'),
    getChatCodeBtn: document.getElementById('get-chat-code-btn'),
    chatMenuBtn: document.getElementById('chat-menu-btn'),
    chatSearchBtn: document.getElementById('chat-search-btn'),
    chatSearch: document.getElementById('chat-search'),
    chatSearchInput: document.getElementById('chat-search-input'),
    chatSearchCounter: document.getElementById('chat-search-counter'),
    chatSearchPrev: document.getElementById('chat-search-prev'),
    chatSearchNext: document.getElementById('chat-search-next'),
    chatSearchOlder: document.getElementById('chat-search-older'),
    chatSearchClose: document.getElementById('chat-search-close'),

    // ---- Сквозное шифрование: значок в шапке и баннер ----
    e2eeIndicator: document.getElementById('e2ee-indicator'),
    e2eeBanner: document.getElementById('e2ee-banner'),
    e2eeBannerText: document.getElementById('e2ee-banner-text'),
    e2eeBannerBtn: document.getElementById('e2ee-banner-btn'),

    // ---- Участники и ключи ----
    membersKeysBtn: document.getElementById('members-keys-btn'),
    membersModal: document.getElementById('members-modal'),
    membersList: document.getElementById('members-list'),
    membersNote: document.getElementById('members-note'),
    ktBanner: document.getElementById('kt-banner'),
    ktBannerText: document.getElementById('kt-banner-text'),
    ktBannerBtn: document.getElementById('kt-banner-btn'),
    ktModal: document.getElementById('kt-modal'),
    ktAlertList: document.getElementById('kt-alert-list'),

    // ---- Заявки на вступление: плашка и окно ----
    requestsBar: document.getElementById('requests-bar'),
    requestsBarText: document.getElementById('requests-bar-text'),
    requestsBarBtn: document.getElementById('requests-bar-btn'),
    requestsModal: document.getElementById('requests-modal'),
    requestsList: document.getElementById('requests-list'),

    // ---- Лента ----
    chatMessages: document.getElementById('chat-messages'),
    jumpDown: document.getElementById('jump-down'),
    jumpDownBadge: document.getElementById('jump-down-badge'),

    // ---- Поле ввода ----
    messageInputContainer: document.getElementById('message-input-container'),
    replyPreview: document.getElementById('reply-preview'),
    replyPreviewText: document.getElementById('reply-preview-text'),
    cancelReplyBtn: document.getElementById('cancel-reply-btn'),
    attachBtn: document.getElementById('attach-btn'),
    messageInput: document.getElementById('message-input'),
    sendBtn: document.getElementById('send-btn'),
    composerStatus: document.getElementById('composer-status'),
    composerStatusIcon: document.getElementById('composer-status-icon'),
    composerStatusText: document.getElementById('composer-status-text'),
    composerStatusRetry: document.getElementById('composer-status-retry'),
    fileInput: document.getElementById('file-input'),

    // ---- Подсказки в чате с ботом ----
    botSuggestions: document.getElementById('bot-suggestions'),

    // ---- Файлы: перетаскивание, загрузка, окно отправки ----
    dropZone: document.getElementById('drop-zone'),
    uploadStatus: document.getElementById('upload-status'),
    uploadStatusText: document.getElementById('upload-status-text'),
    uploadProgress: document.getElementById('upload-progress'),
    uploadProgressBar: document.getElementById('upload-progress-bar'),
    uploadCancelBtn: document.getElementById('upload-cancel-btn'),
    sendFilesModal: document.getElementById('send-files-modal'),
    sendFilesTitle: document.getElementById('send-files-title'),
    sendFilesList: document.getElementById('send-files-list'),
    sendFilesBtn: document.getElementById('send-files-btn'),

    // ---- Меню сообщения ----
    messageMenu: document.getElementById('message-menu'),
    reactionPicker: document.getElementById('reaction-picker'),
    replyMessageBtn: document.getElementById('reply-message-btn'),
    copyMessageBtn: document.getElementById('copy-message-btn'),
    editMessageBtn: document.getElementById('edit-message-btn'),
    deleteMessageBtn: document.getElementById('delete-message-btn'),

    // ---- Меню чата ----
    chatMenuModal: document.getElementById('chat-menu-modal'),
    pinChatBtn: document.getElementById('pin-chat-btn'),
    muteChatBtn: document.getElementById('mute-chat-btn'),
    archiveChatBtn: document.getElementById('archive-chat-btn'),
    expiryFieldset: document.getElementById('expiry-fieldset'),
    expiryHint: document.getElementById('expiry-hint'),
    deleteChatBtn: document.getElementById('delete-chat-btn'),

    // ---- Контекстное меню элемента списка чатов ----
    chatItemMenu: document.getElementById('chat-item-menu'),
    ctxPinBtn: document.getElementById('ctx-pin-btn'),
    ctxMuteBtn: document.getElementById('ctx-mute-btn'),
    ctxArchiveBtn: document.getElementById('ctx-archive-btn'),

    // ---- Новый чат и вступление по коду ----
    newChatModal: document.getElementById('new-chat-modal'),
    createChatBtn: document.getElementById('create-chat-btn'),
    joinChatBtn: document.getElementById('join-chat-btn'),
    joinChatCode: document.getElementById('join-chat-code'),
    joinPreview: document.getElementById('join-preview'),
    joinPreviewName: document.getElementById('join-preview-name'),
    joinPreviewMeta: document.getElementById('join-preview-meta'),
    joinPreviewApproval: document.getElementById('join-preview-approval'),
    newChatTitle: document.getElementById('new-chat-title'),
    newChatCreate: document.getElementById('new-chat-create'),
    joinError: document.getElementById('join-error'),
    joinStatus: document.getElementById('join-status'),
    joinConfirmBtn: document.getElementById('join-confirm-btn'),
    joinCancelBtn: document.getElementById('join-cancel-btn'),
    myRequests: document.getElementById('my-requests'),
    myRequestsList: document.getElementById('my-requests-list'),

    // ---- Приглашения ----
    inviteModal: document.getElementById('invite-modal'),
    inviteStatus: document.getElementById('invite-status'),
    inviteCodeContainer: document.getElementById('invite-code-container'),
    inviteCodeDisplay: document.getElementById('invite-code-display'),
    copyInviteBtn: document.getElementById('copy-invite-btn'),
    inviteQr: document.getElementById('invite-qr'),
    inviteQrCanvas: document.getElementById('invite-qr-canvas'),
    copyInviteLinkBtn: document.getElementById('copy-invite-link-btn'),
    inviteTtl: document.getElementById('invite-ttl'),
    inviteMax: document.getElementById('invite-max'),
    inviteApproval: document.getElementById('invite-approval'),
    rotateInviteBtn: document.getElementById('rotate-invite-btn'),
    disableInviteBtn: document.getElementById('disable-invite-btn'),

    // ---- Профиль ----
    profileModal: document.getElementById('profile-modal'),
    profileAvatar: document.getElementById('profile-avatar'),
    profileUsername: document.getElementById('profile-username'),
    profileLifetime: document.getElementById('profile-lifetime'),
    profileLifetimeStatus: document.getElementById('profile-lifetime-status'),
    profileThemeBtn: document.getElementById('profile-theme-btn'),
    readReceiptsToggle: document.getElementById('read-receipts-toggle'),
    notifyToggle: document.getElementById('notify-toggle'),
    profileAboutBtn: document.getElementById('profile-about-btn'),

    // ---- «Удалить и выйти» ----
    deleteAccountBtn: document.getElementById('delete-account-btn'),
    deleteAccountModal: document.getElementById('delete-account-modal'),
    deleteAccountAlt: document.getElementById('delete-account-alt'),
    deleteAccountError: document.getElementById('delete-account-error'),
    confirmDeleteAccountBtn: document.getElementById('confirm-delete-account-btn'),
};

// ==================== Иконки ====================
// SVG-спрайт и Icons.icon() — из public/icons.js (подключён в <head>). Если
// он почему-то не загрузился, собираем ту же разметку сами: <use> на
// отсутствующий символ просто ничего не рисует, а подписи (aria-label,
// текст рядом) остаются — интерфейс не ломается.

function icon(name, options = {}) {
    if (window.Icons && typeof window.Icons.icon === 'function') {
        try {
            return window.Icons.icon(name, options);
        } catch { /* ниже — запасной вариант */ }
    }
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    const size = ['sm', 'md', 'lg', 'xl'].includes(options.size) ? options.size : 'md';
    svg.setAttribute('class', `icon icon-${size}${options.className ? ' ' + options.className : ''}`);
    if (options.label) {
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', options.label);
    } else {
        svg.setAttribute('aria-hidden', 'true');
    }
    const use = document.createElementNS(NS, 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.appendChild(use);
    return svg;
}

// Кнопка/пункт меню «иконка + подпись»: содержимое пересобирается целиком.
function setIconLabel(el, iconName, text, options = {}) {
    const span = document.createElement('span');
    span.textContent = text;
    el.replaceChildren(icon(iconName, options), span);
}

// Строка «иконка + текст» для служебных элементов (статусы, подписи).
function iconText(tag, className, iconName, text, options = {}) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    setIconLabel(el, iconName, text, options);
    return el;
}

// ==================== Мелкие утилиты ====================

// Не отменяет сам promise — только перестаёт его ждать. Нужна там, где
// зависший сетевой запрос не должен навсегда блокировать интерфейс.
function withTimeout(promise, ms, fallback) {
    let timer;
    return Promise.race([
        promise,
        new Promise(resolve => { timer = setTimeout(() => resolve(fallback), ms); }),
    ]).finally(() => clearTimeout(timer));
}

function formatShortDateTime(date) {
    const day = date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' });
    const time = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    return `${day} ${time}`;
}

function joinNames(members) {
    return members.map(m => m.username || `участник #${m.id}`).join(', ');
}

// Русские формы множественного числа: plural(5, ['файл', 'файла', 'файлов']).
function plural(n, forms) {
    const abs = Math.abs(n) % 100;
    const last = abs % 10;
    if (abs > 10 && abs < 20) return forms[2];
    if (last > 1 && last < 5) return forms[1];
    if (last === 1) return forms[0];
    return forms[2];
}

function parseDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

// «только что», «5 минут назад», «вчера»; старше недели — дата и время.
function formatRelativeTime(value) {
    const date = parseDate(value);
    if (!date) return '';
    const diffSec = Math.round((date.getTime() - Date.now()) / 1000);
    const abs = Math.abs(diffSec);
    if (abs < 45) return 'только что';
    if (abs >= 7 * 86400) return formatShortDateTime(date);
    let rtf = null;
    try {
        rtf = new Intl.RelativeTimeFormat('ru', { numeric: 'auto' });
    } catch { /* старый браузер — ниже запасной вариант */ }
    const [amount, unit, short] = abs < 3600 ? [Math.round(diffSec / 60), 'minute', 'мин']
        : abs < 86400 ? [Math.round(diffSec / 3600), 'hour', 'ч']
            : [Math.round(diffSec / 86400), 'day', 'дн.'];
    if (rtf) return rtf.format(amount, unit);
    return amount < 0 ? `${-amount} ${short} назад` : `через ${amount} ${short}`;
}

function formatFileSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return `${n} Б`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0).replace('.', ',')} КБ`;
    return `${(n / 1024 / 1024).toFixed(1).replace('.', ',')} МБ`;
}

// ==================== Следы на устройстве ====================
// Всё, что клиент хранит локально: ключи E2EE (IndexedDB nyxo-e2ee-<id>,
// удаляется через E2EE.deleteLocalData) и флаги пользователя в localStorage.
// Все аккаунты временные, поэтому при выходе (он же удаление) и после
// удаления аккаунта по сроку это должно исчезать вместе с сессией.
// Хранилище браузера может быть недоступно (окно инкогнито, запрет
// cookies) — отсюда try/catch вокруг каждого обращения: интерфейс должен
// работать и без него.

function readAnonIds() {
    try {
        const list = JSON.parse(localStorage.getItem(ANON_IDS_KEY) || '[]');
        return Array.isArray(list) ? list.map(Number).filter(id => Number.isInteger(id) && id > 0) : [];
    } catch {
        return [];
    }
}

function writeAnonIds(ids) {
    try {
        const unique = Array.from(new Set(ids));
        if (unique.length > 0) localStorage.setItem(ANON_IDS_KEY, JSON.stringify(unique));
        else localStorage.removeItem(ANON_IDS_KEY);
    } catch { /* хранилище недоступно — стирать будет нечего */ }
}

// Список "чьи локальные данные стереть, как только этот пользователь не
// текущая сессия". Туда попадает каждый аккаунт при входе (вкладку могли
// просто закрыть, а сервер удалит аккаунт сам по сроку без входа) и
// удалённые аккаунты, чью базу ключей не удалось стереть сразу.
function rememberIdForWipe(userId) {
    writeAnonIds([...readAnonIds(), Number(userId)]);
}

function forgetIdForWipe(userId) {
    writeAnonIds(readAnonIds().filter(id => id !== Number(userId)));
}

// Локальные флаги пользователя: согласие на уведомления и id чата с ботом.
// Тема оформления — настройка устройства, а не аккаунта, её не трогаем.
function removeLocalUserPrefs(userId) {
    try {
        localStorage.removeItem(NOTIFY_PREF_PREFIX + userId);
        localStorage.removeItem(BOT_CHAT_PREFIX + userId);
    } catch { /* хранилище недоступно */ }
}

// Флаги e2ee-enabled:<пользователь>:<чат> остались от выключателя шифрования,
// которого больше нет: они ничего не значат и никому не нужны. Стираются все,
// любых пользователей, один раз при старте страницы.
function sweepLegacyPrefs() {
    try {
        const doomed = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(LEGACY_E2EE_PREF_PREFIX)) doomed.push(key);
        }
        doomed.forEach(key => localStorage.removeItem(key));
    } catch { /* хранилище недоступно — стирать нечего */ }
}

// id чата с ботом (приходит в ответе регистрации) нужен клиенту волны 2;
// хранится на устройстве рядом с остальными локальными данными аккаунта.
function rememberBotChatId(userId, botChatId) {
    const id = Number(botChatId);
    if (!Number.isInteger(id) || id <= 0 || !Number.isInteger(Number(userId))) return;
    try { localStorage.setItem(BOT_CHAT_PREFIX + userId, String(id)); } catch { /* хранилище недоступно */ }
}

// Стирает локальные данные пользователя. Резолвится true, если база
// ключей точно удалена. Удаление IndexedDB ждёт, пока закроются открытые
// к ней соединения, поэтому ждём не дольше timeoutMs: id остаётся в
// списке на стирание и будет дочищен позже (при следующем старте), а
// если удаление всё же завершится — вычеркнется из списка само.
function wipeLocalUserData(userId, timeoutMs = 3000) {
    removeLocalUserPrefs(userId);
    if (typeof E2EE === 'undefined' || typeof E2EE.deleteLocalData !== 'function') {
        return Promise.resolve(false);
    }
    const deletion = Promise.resolve()
        .then(() => E2EE.deleteLocalData(userId))
        .then(() => { forgetIdForWipe(userId); return true; })
        .catch((err) => {
            console.warn('Не удалось удалить локальные ключи E2EE:', err);
            return false;
        });
    return withTimeout(deletion, timeoutMs, false);
}

// Чьи следы лежат на устройстве: id из списка на стирание, из ключей
// localStorage (уведомления, чат с ботом) и из имён баз
// IndexedDB nyxo-e2ee-<id>. Список баз знает indexedDB.databases(); где его
// нет (старый Firefox), остаётся список nyxo-anon-ids.
async function listLocalUserIds() {
    const ids = new Set(readAnonIds());
    try {
        // Ключ вида <префикс><id>.
        const prefixes = [NOTIFY_PREF_PREFIX, BOT_CHAT_PREFIX];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const prefix = key && prefixes.find(p => key.startsWith(p));
            if (!prefix) continue;
            const digits = key.slice(prefix.length).split(':')[0];
            if (/^[0-9]+$/.test(digits)) ids.add(Number(digits));
        }
    } catch { /* хранилище недоступно */ }
    try {
        if (typeof indexedDB !== 'undefined' && indexedDB && typeof indexedDB.databases === 'function') {
            const dbs = await withTimeout(indexedDB.databases(), 3000, []);
            for (const db of dbs || []) {
                if (!db || typeof db.name !== 'string' || !db.name.startsWith(E2EE_DB_PREFIX)) continue;
                const digits = db.name.slice(E2EE_DB_PREFIX.length);
                if (/^[0-9]+$/.test(digits)) ids.add(Number(digits));
            }
        }
    } catch { /* список баз недоступен — остаётся nyxo-anon-ids */ }
    return Array.from(ids).filter(id => Number.isSafeInteger(id) && id > 0);
}

// На одном origin живёт один аккаунт (кука сессии общая): всё, что осталось
// от других, — следы удалённых аккаунтов, их стираем. Порядок важен: СНАЧАЛА
// список следов, ПОТОМ свежий GET /api/auth. Если наоборот, аккаунт,
// созданный в соседней вкладке между запросом и чтением списка, попал бы
// под стирание. Оставляем аккаунт из ответа сервера и текущий. Сервер
// недоступен — не стираем ничего: сессия могла и не истечь.
let purgingForeign = null;
function purgeForeignLocalData() {
    if (purgingForeign) return purgingForeign;
    purgingForeign = (async () => {
        const known = await listLocalUserIds();
        if (known.length === 0) return;
        const state = await fetchAuthState();
        if (!state) return;
        const keep = new Set();
        if (state.authenticated && state.user) keep.add(Number(state.user.id));
        if (currentUser) keep.add(Number(currentUser.id));
        known.filter(id => !keep.has(id)).forEach((id) => { wipeLocalUserData(id); });
    })().catch((err) => {
        console.warn('Не удалось почистить чужие локальные данные:', err);
    }).finally(() => { purgingForeign = null; });
    return purgingForeign;
}

// Полная перезагрузка после выхода и удаления аккаунта: закрывает
// соединения с IndexedDB (иначе удаление базы ключей ждёт их закрытия) и
// выбрасывает из памяти расшифрованную переписку. Уведомление переживает
// перезагрузку через sessionStorage и показывается на экране входа.
function reloadWithNotice(text) {
    try {
        if (text) sessionStorage.setItem(FLASH_NOTICE_KEY, text);
    } catch { /* без уведомления — не страшно */ }
    location.reload();
}

// Уведомление, оставленное перед перезагрузкой; читается один раз.
function takeFlashNotice() {
    let text = null;
    try {
        text = sessionStorage.getItem(FLASH_NOTICE_KEY);
        sessionStorage.removeItem(FLASH_NOTICE_KEY);
    } catch { /* нет sessionStorage */ }
    return text || '';
}

// ==================== E2EE (X3DH + Sender Keys) ====================
// Ключи устройства хранятся в IndexedDB, отдельная база на каждого
// currentUser.id — это исключает утечку ключевого материала между
// разными аккаунтами на одном браузере (общий компьютер, тест-логины).
// Подробности протокола и честные ограничения — см. public/e2ee.js.
//
// Шифрование в комнатах обязательно, выключателя нет (R7): сервер всё равно
// принимает в комнату только конверт правильной формы. Если ключи устройства
// не удалось подготовить, поле ввода комнаты отключается, а под ним — причина
// по коду E2eeError и «Повторить» (плюс автоповтор, пока комната открыта).
// Открытым текстом уходят только сообщения в чат с ботом, номер которого
// запомнен при регистрации (NyxoE2eePolicy.plaintextAllowed), а не любой чат,
// который сервер назвал ботом. Что показать в каждом состоянии, решает чистая
// функция NyxoE2eePolicy.composerView (public/lib/e2ee-policy.js).

let e2eeClient = null;
let e2eeClientUserId = null;
let e2eeInitPromise = null;       // Promise<boolean>: true — ключи устройства готовы
let e2eeState = 'off';            // 'off' | 'pending' | 'ready' | 'unavailable'
let e2eeInitError = null;         // ошибка последней неудачной инициализации (E2eeError с code)
let e2eeUnavailableWarned = false;
let e2eeRetryTimer = null;        // автоповтор инициализации
let e2eeRetryStep = 0;            // сколько автоповторов уже было
let roomBlock = null;             // { chatId, text } — почему отправка в комнату только что отклонена

// Паузы автоповтора после неудачной инициализации (сеть или сервер ключей):
// 10 с, 30 с, 2 мин. Дальше — только кнопка «Повторить».
const E2EE_AUTO_RETRY_MS = [10 * 1000, 30 * 1000, 2 * 60 * 1000];

function getE2eeClient() {
    if (!currentUser || typeof E2EE === 'undefined') return null;
    if (!e2eeClient || e2eeClientUserId !== currentUser.id) {
        try {
            e2eeClient = E2EE.createClient({
                userId: currentUser.id,
                storage: E2EE.makeIndexedDbStorage('nyxo-e2ee-' + currentUser.id),
                // Две вкладки одного аккаунта делят IndexedDB с ключами: Web Locks не дают им
                // выдать одну итерацию Sender Key двум сообщениям (message-ordering.md, 9.7).
                // Без Web Locks lock = null — работает внутренняя очередь клиента, в консоли предупреждение.
                lock: NyxoE2eeLock.makeLock(typeof navigator !== 'undefined' ? navigator.locks : null, currentUser.id,
                    (message) => console.warn(message)),
                // Прозрачность ключей: новая тревога журнала сразу попадает в баннер боковой панели.
                onTransparencyAlert: (alert) => {
                    // stale — не тревога, а предупреждение: журнал давно не обновлялся (не блокирует работу).
                    if (alert && alert.kind === 'stale') showToast('Журнал ключей на сервере давно не обновлялся: проверка ключей собеседников может запаздывать', 'info', 8000);
                    refreshTransparencyBanner();
                },
            });
            e2eeClientUserId = currentUser.id;
        } catch (err) {
            console.error('E2EE: не удалось создать клиент:', err);
            e2eeClient = null;
            e2eeClientUserId = null;
        }
    }
    return e2eeClient;
}

// Один тост на вход: потом то же самое видно под полем ввода комнаты.
function warnE2eeUnavailable(err) {
    if (e2eeUnavailableWarned) return;
    e2eeUnavailableWarned = true;
    showToast(`Сквозное шифрование недоступно: ${NyxoE2eePolicy.initErrorReason(err)}. В группы сообщения не отправляются, пока оно не заработает`, 'error', 8000);
}

function initE2eeForCurrentUser() {
    const userId = currentUser ? currentUser.id : null;
    const client = getE2eeClient();
    if (!client) {
        // Нет модуля шифрования или клиент не создался: повторять нечего.
        e2eeInitError = { code: 'unsupported' };
        e2eeState = 'unavailable';
        e2eeInitPromise = Promise.resolve(false);
        warnE2eeUnavailable(e2eeInitError);
        refreshE2eeUi();
        return e2eeInitPromise;
    }
    e2eeState = 'pending';
    e2eeInitError = null;
    refreshE2eeUi();
    // Показ приложения генерацией/загрузкой ключей не блокируется: кому
    // нужны ключи (отправка, расшифровка), тот дожидается этого promise.
    e2eeInitPromise = Promise.resolve()
        .then(() => client.init())
        .then(() => {
            if (!currentUser || currentUser.id !== userId) return false;
            e2eeState = 'ready';
            e2eeRetryStep = 0;
            clearTimeout(e2eeRetryTimer);
            refreshE2eeUi();
            // Журнал ключей: плановые проверки раз в час и первая проверка (самомониторинг) сразу после входа.
            if (typeof client.startTransparency === 'function') {
                client.startTransparency();
                client.runKtChecks().then(refreshTransparencyBanner, (err) => console.warn('E2EE: проверка журнала ключей не удалась:', err));
            }
            return true;
        }, (err) => {
            console.error('E2EE: инициализация ключей устройства не удалась:', err);
            if (!currentUser || currentUser.id !== userId) return false;
            e2eeState = 'unavailable';
            e2eeInitError = err;
            warnE2eeUnavailable(err);
            refreshE2eeUi();
            scheduleE2eeAutoRetry();
            return false;
        });
    return e2eeInitPromise;
}

// Клиент, у которого init() завершился успешно, или null.
async function getReadyE2eeClient() {
    if (!currentUser || !e2eeInitPromise) return null;
    const ok = await e2eeInitPromise;
    return ok && e2eeState === 'ready' ? getE2eeClient() : null;
}

// Клиент после завершения init() (даже неудачного): расшифровка истории
// работает на локальных ключах и может получиться, даже если сервер
// ключей сейчас недоступен.
async function getSettledE2eeClient() {
    if (!currentUser || !e2eeInitPromise) return null;
    await e2eeInitPromise;
    return getE2eeClient();
}

// Автоповтор: пока причина может пройти сама (сеть, сервер ключей), комната
// открыта и вкладка видна — новая попытка через 10 с, 30 с, 2 мин. Если условия
// не выполнены, проверка повторяется через ту же паузу, а счётчик не растёт.
function scheduleE2eeAutoRetry() {
    clearTimeout(e2eeRetryTimer);
    if (e2eeState !== 'unavailable' || !NyxoE2eePolicy.initErrorRetryable(e2eeInitError)) return;
    if (e2eeRetryStep >= E2EE_AUTO_RETRY_MS.length) return;
    e2eeRetryTimer = setTimeout(() => {
        if (!currentUser || e2eeState !== 'unavailable') return;
        if (!currentRoomId || document.visibilityState !== 'visible') {
            scheduleE2eeAutoRetry();
            return;
        }
        e2eeRetryStep++;
        retryE2ee({ silent: true });
    }, E2EE_AUTO_RETRY_MS[e2eeRetryStep]);
}

// Номер чата с ботом, запомненный при регистрации (ответ botChatId).
function readRememberedBotChatId(userId) {
    try {
        return localStorage.getItem(BOT_CHAT_PREFIX + userId);
    } catch {
        return null;
    }
}

// Открытый текст можно отправить только в чат с ботом, номер которого запомнен
// на этом устройстве; признак is_bot от сервера для этого не используется.
function plaintextAllowedForChat(chatId, roomId) {
    return Boolean(currentUser) && NyxoE2eePolicy.plaintextAllowed(readRememberedBotChatId(currentUser.id), chatId, roomId);
}

function currentRoomBlock() {
    return roomBlock && roomBlock.chatId === currentChatId ? roomBlock : null;
}

// Причина по тексту: отправка отклонена, пока ключ комнаты не дошёл до участников.
function setRoomBlock(chatId, text) {
    roomBlock = { chatId, text };
    if (chatId === currentChatId) updateComposerForChat();
}

function clearRoomBlock(chatId) {
    if (!roomBlock || (chatId !== undefined && roomBlock.chatId !== chatId)) return;
    roomBlock = null;
    updateComposerForChat();
}

// Причина, по которой поле ввода сейчас отключено (пусто — доступно): ею же
// отвечают перетаскивание файлов и подсказки кнопок.
let composerDisabledReason = '';

function setComposerDisabled(disabled, reason) {
    composerDisabledReason = disabled ? reason : '';
    elements.messageInput.disabled = disabled;
    elements.sendBtn.disabled = disabled;
    elements.attachBtn.disabled = disabled || Boolean(uploadQueue);
    elements.sendBtn.title = disabled ? reason : 'Отправить';
    elements.attachBtn.title = disabled ? reason : 'Прикрепить файлы';
}

// Шапка и поле ввода открытого чата: значок шифрования, строка состояния под
// полем, подсказка в поле, доступность отправки и вложений.
function updateComposerForChat() {
    if (!currentChatId) return;
    const inRoom = Boolean(currentRoomId);
    const block = currentRoomBlock();
    const view = NyxoE2eePolicy.composerView({
        inRoom,
        plaintextOk: plaintextAllowedForChat(currentChatId, currentRoomId),
        e2ee: e2eeState,
        initError: e2eeInitError,
        block,
    });
    elements.membersKeysBtn.classList.toggle('hidden', !inRoom);
    elements.getChatCodeBtn.classList.toggle('hidden', !inRoom);

    const indicator = elements.e2eeIndicator;
    indicator.classList.toggle('hidden', !view.indicator.show);
    indicator.classList.toggle('is-on', view.indicator.ok);
    if (view.indicator.show) {
        setIconLabel(indicator, view.indicator.ok ? 'lock' : 'alert-triangle', view.indicator.text, { size: 'sm' });
        indicator.title = view.indicator.title;
        indicator.setAttribute('aria-label', view.indicator.title);
    }

    const status = elements.composerStatus;
    status.classList.toggle('is-problem', view.kind === 'unavailable' || view.kind === 'blocked' || view.kind === 'unknown');
    // Недоступность объявляется как alert (один раз при появлении), остальное — вежливо.
    status.setAttribute('role', view.kind === 'unavailable' ? 'alert' : 'status');
    elements.composerStatusIcon.replaceChildren(icon(view.icon, view.spin ? { size: 'sm', className: 'spin' } : { size: 'sm' }));
    elements.composerStatusText.textContent = view.text;
    elements.composerStatusRetry.classList.toggle('hidden', !view.retry);

    elements.messageInput.placeholder = view.placeholder;
    setComposerDisabled(view.disabled, view.text);
}

function refreshE2eeUi() {
    if (!currentChatId) return;
    updateComposerForChat();
}

// «Повторить»: заново подготовить ключи устройства (если они недоступны) и ключ
// открытой комнаты. silent — автоповтор: об отказе молчим, видно и так.
async function retryE2ee({ silent = false } = {}) {
    if (!currentUser) return;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    clearTimeout(e2eeRetryTimer);
    if (!silent) e2eeRetryStep = 0;
    const wasBlocked = Boolean(currentRoomBlock());
    const retryBtn = elements.composerStatusRetry;
    retryBtn.disabled = true;
    try {
        if (e2eeState === 'unavailable') {
            const ok = await initE2eeForCurrentUser();
            if (!ok) {
                if (!silent) showToast(`Сквозное шифрование по-прежнему недоступно: ${NyxoE2eePolicy.initErrorReason(e2eeInitError)}`, 'error');
                return;
            }
            showToast('Сквозное шифрование снова доступно', 'success');
        }
        roomBlock = null;
        if (chatId && roomId && chatId === currentChatId) {
            await syncE2eeKeyShares(chatId, roomId);
            const session = await ensureE2eeRoomSession(chatId, roomId);
            if (chatId !== currentChatId) return;
            const block = NyxoE2eePolicy.sessionBlock(session);
            if (block) {
                setRoomBlock(chatId, block.text);
                if (!silent) showToast(block.text, 'error', 6000);
            } else if (wasBlocked) {
                showToast('Ключ шифрования передан, можно отправлять', 'success');
            }
        }
    } finally {
        retryBtn.disabled = false;
        updateComposerForChat();
    }
}

// ---- Участники комнаты, ключи, служебные строки ----

const roomParticipants = new Map();          // roomId -> [{id, username}] (последний известный состав)
const pendingIdentityChanges = new Map();    // userId -> username (для баннера открытой комнаты)
const pendingLogMismatches = new Map();      // userId -> username: ключа нет в журнале ключей (там же)
const notedLogMismatches = new Set();        // 'комната:участник': о чём уже писали в ленту
const warnedRooms = new Set();               // о каких комнатах уже предупреждали, что не все получили ключ
const pendingUnconfirmed = new Map();        // userId -> username: неподтверждённые участники открытой комнаты (баннер)
const notedMembership = new Set();           // 'комната:вид:...': о чём про состав группы уже писали в ленту

function rememberRoomParticipants(roomId, participants) {
    roomParticipants.set(Number(roomId), Array.isArray(participants) ? participants : []);
}

// Карты имён бывших и текущих участников из хранилища ключей устройства
// (memberNames:<комната>, sealed-sender.md, 9.5): сообщение вышедшего участника
// подписывается его последним известным именем.
const roomMemberNames = new Map();           // roomId -> { <id>: <имя> }

// Подпись автора сообщения комнаты. Сервер автора не называет: senderId приходит из
// результата расшифровки (индекс отправителей), имя - из списка участников. Не
// расшифрованное сообщение - «Участник группы»; вышедший - с пометкой; без имени -
// «Бывший участник». Пока список участников не загружен, назвать некого.
function roomAuthorLabel(roomId, senderId) {
    if (!Number.isSafeInteger(senderId)) return 'Участник группы';
    const list = roomParticipants.get(Number(roomId));
    if (!list) return 'Участник группы';
    const current = list.find(p => Number(p.id) === senderId);
    if (current && current.username) return current.username;
    const former = (roomMemberNames.get(Number(roomId)) || {})[senderId];
    return former ? `${former} (вышел(ла))` : 'Бывший участник';
}

// Список участников и карта имён - до показа истории: автор сообщения известен только
// клиенту. Сбой не мешает показать историю (подписи будут «Участник группы»).
async function loadRoomAuthorDirectory(chatId, roomId) {
    try {
        const [part, client] = await Promise.all([api(`/api/chats/${chatId}/participants`), getReadyE2eeClient()]);
        if (part && part.success && Array.isArray(part.participants)) rememberRoomParticipants(roomId, part.participants);
        if (client) roomMemberNames.set(Number(roomId), await client.getRoomMemberNames(roomId));
    } catch (err) {
        console.warn('E2EE: имена участников не загружены:', err);
    }
}

function participantName(roomId, userId) {
    const list = roomParticipants.get(Number(roomId)) || [];
    const found = list.find(p => Number(p.id) === Number(userId));
    return found && found.username ? found.username : `участник #${userId}`;
}

// Служебные строки (вход/выход участников, смена ключей) — локальные, не
// сообщения сервера. Пока история чата не отрисована, копятся в очереди:
// иначе renderMessages('replace') стёр бы их.
let noticesReady = false;
let pendingNotices = [];

// Служебная строка в ленте открытого чата (иконка + текст).
function appendChatNotice(text, iconName = 'info') {
    if (!currentChatId) return;
    if (!noticesReady) {
        pendingNotices.push({ text, iconName });
        return;
    }
    const stick = isNearBottom();
    const el = iconText('div', 'system-notice', iconName, text, { size: 'sm' });
    el.setAttribute('role', 'status');
    elements.chatMessages.appendChild(el);
    if (stick) scrollToBottom();
}

function appendSystemNotice(roomId, text, iconName = 'key') {
    if (Number(roomId) !== Number(currentRoomId)) return;
    appendChatNotice(text, iconName);
}

function flushSystemNotices() {
    noticesReady = true;
    const queued = pendingNotices;
    pendingNotices = [];
    queued.forEach(n => appendChatNotice(n.text, n.iconName));
}

function renderIdentityBanner() {
    const names = Array.from(pendingIdentityChanges.values());
    const mismatched = Array.from(pendingLogMismatches.values());
    const unconfirmed = Array.from(pendingUnconfirmed.values());
    if (!currentRoomId || (names.length === 0 && mismatched.length === 0 && unconfirmed.length === 0)) {
        elements.e2eeBanner.classList.add('hidden');
        elements.e2eeBannerText.textContent = '';
        return;
    }
    const parts = [];
    if (names.length > 0) {
        parts.push(names.length === 1
            ? `У участника ${names[0]} сменился ключ шифрования. Сообщения ему не отправляются, пока вы не проверите код безопасности`
            : `У участников ${names.join(', ')} сменились ключи шифрования. Сообщения им не отправляются, пока вы не проверите коды безопасности`);
    }
    if (mismatched.length > 0) {
        parts.push(`Сервер показывает для ${mismatched.join(', ')} ключ, которого нет в журнале ключей (или журнал у участников разный). Возможна подмена. Сверьте код безопасности лично. Ключ комнаты ${mismatched.length === 1 ? 'этому участнику' : 'этим участникам'} не отправляется`);
    }
    // Подписанный состав группы (signed-membership.md, 10): сервер добавил участника, за которого никто не поручился.
    if (unconfirmed.length > 0) {
        parts.push(`В группе есть неподтверждённые участники: ${unconfirmed.join(', ')}. Сообщения им не отправляются`);
    }
    elements.e2eeBannerText.textContent = parts.join('. ');
    elements.e2eeBanner.classList.remove('hidden');
}

function addIdentityChanges(roomId, changes) {
    if (Number(roomId) !== Number(currentRoomId) || !Array.isArray(changes)) return;
    changes.forEach((change) => {
        const userId = Number(typeof change === 'object' && change !== null ? change.userId : change);
        if (!userId) return;
        const username = (change && change.username) || participantName(roomId, userId);
        pendingIdentityChanges.set(userId, username);
    });
    renderIdentityBanner();
}

// Статус identity пира — getPeerIdentityStatus может быть и синхронным, и
// асинхронным; ошибка = "неизвестно".
async function peerIdentityStatus(client, userId) {
    try {
        return await Promise.resolve(client.getPeerIdentityStatus(userId));
    } catch {
        return null;
    }
}

// Баннер показывает тех, у кого identity сейчас в состоянии 'changed':
// и найденных только что (ensureRoomSession), и оставшихся с прошлых раз
// (ключ сменился, а пользователь его ещё не проверил).
async function refreshIdentityChanges(client, roomId, participants, reported) {
    const changed = new Map();
    (reported || []).forEach((c) => {
        const userId = Number(c.userId);
        if (userId) changed.set(userId, c.username || participantName(roomId, userId));
    });
    const others = (participants || []).filter(p => currentUser && Number(p.id) !== Number(currentUser.id));
    const mismatched = new Map();
    let statusesKnown = true;
    for (const peer of others) {
        const status = await peerIdentityStatus(client, peer.id);
        if (status === null) statusesKnown = false;
        if (status === 'changed') changed.set(Number(peer.id), peer.username || participantName(roomId, peer.id));
        if (status === 'log-mismatch') mismatched.set(Number(peer.id), peer.username || participantName(roomId, peer.id));
    }
    if (Number(roomId) !== Number(currentRoomId)) return;
    // Если статусы узнать не удалось, ничего из баннера не убираем.
    if (statusesKnown) {
        pendingIdentityChanges.clear();
        pendingLogMismatches.clear();
    }
    changed.forEach((name, userId) => pendingIdentityChanges.set(userId, name));
    mismatched.forEach((name, userId) => pendingLogMismatches.set(userId, name));
    renderIdentityBanner();
}

// Имя участника для строк о составе: текущий участник или бывший (последнее известное имя).
function memberLabel(roomId, userId) {
    if (userId == null) return 'участник';
    const list = roomParticipants.get(Number(roomId)) || [];
    const current = list.find(p => Number(p.id) === Number(userId));
    if (current && current.username) return current.username;
    const former = (roomMemberNames.get(Number(roomId)) || {})[userId];
    return former || `участник #${userId}`;
}

// Подпись под именем в окне участников и в ленте: кто и как подтвердил участника (signed-membership.md, 10).
function membershipHowLine(roomId, entry) {
    if (!entry) return '';
    const by = memberLabel(roomId, entry.by);
    if (entry.status === 'self') {
        if (entry.how === 'approved') return `Вас одобрил(а) ${by}`;
        if (entry.how === 'invite') return `Вы вошли по приглашению ${by}`;
        return entry.how === 'creator' ? 'Вы создали группу' : '';
    }
    if (entry.status === 'unconfirmed') {
        return entry.duplicateKeys
            ? 'Не подтверждён: ключи шифрования такие же, как у другого участника'
            : 'Не подтверждён: вошёл без подписи участника';
    }
    switch (entry.how) {
        case 'approved': return `Одобрил(а) ${by}`;
        case 'invite': return `По приглашению ${by}`;
        case 'vouched': return `Подтвердил(а) ${by}`;
        case 'revouched': return `Повторно подтверждён ${by} после выхода прежнего подписавшего`;
        case 'manual': return 'Подтверждён вами';
        default: return '';
    }
}

const ANCHOR_FAILURE_TEXT = {
    'no-certificate': 'Не удалось подтвердить состав группы: подписи участника для вас нет на сервере. Участники не подтверждены — подтвердите тех, кого знаете, вручную',
    'snap-bad': 'Приглашение повреждено: состав группы по нему не подтверждён',
    'snap-missing': 'Не получен список участников от пригласившего: состав группы не подтверждён',
    'inviter-key': 'Ключ пригласившего не совпал с подписью приглашения — возможна подмена. Состав группы не подтверждён, сверьте код безопасности лично',
    'inviter-substituted': 'Ключ пригласившего не совпал с подписью приглашения — возможна подмена. Состав группы не подтверждён, сверьте код безопасности лично',
    'duplicate-keys': 'У пригласившего и другого участника одинаковые ключи шифрования. Состав группы не подтверждён',
};

// Состав группы после проверки: баннер, строки ленты, предупреждения (signed-membership.md, 10).
function handleMembershipResult(roomId, result) {
    const unconfirmed = Array.isArray(result.unconfirmed) ? result.unconfirmed : [];
    const skip = new Set((result.identityChanges || []).concat(result.logMismatches || []).map(c => Number(c.userId)));
    pendingUnconfirmed.clear();
    unconfirmed.filter(u => !skip.has(Number(u.id))).forEach(u => pendingUnconfirmed.set(Number(u.id), u.username || `участник #${u.id}`));
    renderIdentityBanner();

    const once = (key) => {
        const full = `${roomId}:${key}`;
        if (notedMembership.has(full)) return false;
        notedMembership.add(full);
        return true;
    };
    if (result.anchor && result.anchor.ok === true && once('anchor-ok')) {
        appendSystemNotice(roomId, result.anchor.via === 'invite'
            ? 'Состав группы подтверждён по подписи приглашения'
            : 'Состав группы подтверждён по подписи одобрившего', 'shield-check');
    }
    if (result.anchor && result.anchor.ok === false && once('anchor-' + result.anchor.reason)) {
        appendSystemNotice(roomId, ANCHOR_FAILURE_TEXT[result.anchor.reason] || 'Не удалось подтвердить состав группы по приглашению', 'shield-alert');
    }
    (Array.isArray(result.duplicateKeys) ? result.duplicateKeys : []).forEach((group) => {
        if (!once('dup:' + group.ids.join(','))) return;
        const names = group.ids.map(id => memberLabel(roomId, id)).join(', ');
        appendSystemNotice(roomId, `Ключи шифрования участников ${names} совпадают. Сверьте код безопасности`, 'shield-alert');
    });
}

function handleRoomSessionResult(roomId, result) {
    if (!result || Number(roomId) !== Number(currentRoomId)) return;
    handleMembershipResult(roomId, result);
    const warnings = Array.isArray(result.warnings) ? result.warnings : [];
    const unconfirmedIds = new Set((Array.isArray(result.unconfirmed) ? result.unconfirmed : []).map(u => Number(u.id)));
    const membersById = new Map((Array.isArray(result.members) ? result.members : []).map(member => [Number(member.id), member]));
    // Неподтверждённые и дубликаты ключей - не «не настроено шифрование»: о них говорят баннер и отдельная строка.
    const failedIds = new Set(warnings
        .filter(w => w && w.userId != null && w.reason !== 'unconfirmed-member' && w.reason !== 'duplicate-keys')
        .map(w => Number(w.userId)));
    // Участники со сменившимся ключом и с ключом, которого нет в журнале, тоже попадают в warnings, но о них
    // говорят баннер и отдельная строка — здесь они не «без шифрования».
    const changedIds = new Set((result.identityChanges || []).concat(result.logMismatches || []).map(c => Number(c.userId)));
    const newMembers = Array.isArray(result.newMembers) ? result.newMembers : [];
    const removedMembers = Array.isArray(result.removedMembers) ? result.removedMembers : [];

    // Участники со сменившимся ключом тоже попадают в warnings, но о них
    // говорит баннер — здесь они не "без шифрования".
    const delivered = newMembers.filter(member => !failedIds.has(Number(member.id)) && !changedIds.has(Number(member.id)) && !unconfirmedIds.has(Number(member.id)));
    const undelivered = newMembers.filter(member => failedIds.has(Number(member.id)) && !changedIds.has(Number(member.id)) && !unconfirmedIds.has(Number(member.id)));
    const unsigned = newMembers.filter(member => unconfirmedIds.has(Number(member.id)) && !changedIds.has(Number(member.id)));
    if (delivered.length > 0) {
        // «{имя} в группе — одобрил(а) {имя}»: кто и как подтвердил (подпись участника, а не слово сервера).
        const lines = delivered.map((member) => {
            const how = membershipHowLine(roomId, membersById.get(Number(member.id)));
            return how ? `${member.username || `участник #${member.id}`} в группе — ${how.charAt(0).toLowerCase()}${how.slice(1)}` : null;
        });
        const text = lines.every(Boolean)
            ? `${lines.join('; ')}. Ключ шифрования передан`
            : `В чат вошли: ${joinNames(delivered)}, им передан ключ шифрования`;
        appendSystemNotice(roomId, text, 'key');
        showToast(text, 'info');
    }
    if (unsigned.length > 0) {
        const verb = unsigned.length === 1 ? 'появился(ась)' : 'появились';
        const text = `${joinNames(unsigned)} ${verb} в группе без подписи участника. Ключ шифрования ${unsigned.length === 1 ? 'ему' : 'им'} не отправлен`;
        appendSystemNotice(roomId, text, 'shield-alert');
        showToast(text, 'info', 6000);
    }
    if (undelivered.length > 0) {
        appendSystemNotice(roomId, `В чат вошли: ${joinNames(undelivered)}, но ключ шифрования им передать не удалось — они пока не смогут читать зашифрованные сообщения`, 'alert-triangle');
    }
    // Ключа участника нет в журнале ключей: ключ комнаты ему не передан (один раз за сессию на участника).
    const fresh = (Array.isArray(result.logMismatches) ? result.logMismatches : [])
        .filter(m => !notedLogMismatches.has(`${roomId}:${m.userId}`));
    if (fresh.length > 0) {
        fresh.forEach(m => notedLogMismatches.add(`${roomId}:${m.userId}`));
        appendSystemNotice(roomId, `Ключа ${joinNames(fresh)} нет в журнале ключей: ключ шифрования ${fresh.length === 1 ? 'ему' : 'им'} не передан${result.rotated ? ', ключ комнаты обновлён' : ''}. Сверьте код безопасности лично`, 'alert-triangle');
    }
    if (removedMembers.length > 0) {
        const verb = removedMembers.length === 1 ? 'покинул(а)' : 'покинули';
        const text = `${joinNames(removedMembers)} ${verb} чат${result.rotated ? ' — ключ шифрования обновлён' : ''}`;
        appendSystemNotice(roomId, text, 'key');
        showToast(text, 'info');
    }

    const newIds = new Set(newMembers.map(member => Number(member.id)));
    const failedExisting = Array.from(failedIds).filter(id => !newIds.has(id) && !changedIds.has(id));
    const general = warnings.find(w => w && w.userId == null);
    if (general) {
        showToast(`Ключ шифрования не разослан: ${general.reason || 'ошибка сервера'} — собеседники могут не прочитать новые сообщения`, 'error', 6000);
    } else if (failedExisting.length > 0 && !warnedRooms.has(Number(roomId))) {
        warnedRooms.add(Number(roomId));
        showToast(`${failedExisting.length} участник(ов) пока не могут читать зашифрованные сообщения: у них не настроено шифрование`, 'info', 6000);
    }
}

// Забирает ожидающие key-share для комнаты (от других участников) — нужно
// делать ДО расшифровки входящих сообщений, иначе их Sender Key ещё не
// будет известен локально. Параллельные вызовы для той же комнаты
// склеиваются в один запрос.
let keySyncInFlight = null;   // { roomId, promise }
let lastKeySyncAt = 0;
function syncE2eeKeyShares(chatId, roomId) {
    if (!roomId) return Promise.resolve(null);
    if (keySyncInFlight && keySyncInFlight.roomId === roomId) return keySyncInFlight.promise;
    const promise = (async () => {
        const client = await getReadyE2eeClient();
        if (!client) return null;
        lastKeySyncAt = Date.now();
        try {
            const res = await client.syncKeyShares(chatId, roomId);
            if (res && Array.isArray(res.identityChanges) && res.identityChanges.length > 0) {
                addIdentityChanges(roomId, res.identityChanges);
            }
            // Сверка взглядов на состав и ключи (signed-membership.md, 9.6): информативная тревога, отправка не блокируется.
            if (res && res.viewMismatch) {
                showToast('Участники группы видят разные ключи шифрования (возможна подмена сервером). Сверьте коды безопасности', 'error', 8000);
            }
            if (res && res.viewIdsDiverged) {
                showToast('Состав группы у одного из участников отличается от вашего. Возможно, сервер показывает участникам разные списки', 'info', 8000);
            }
            return res;
        } catch (err) {
            console.error('E2EE: syncKeyShares failed:', err);
            return null;
        }
    })().finally(() => {
        if (keySyncInFlight && keySyncInFlight.promise === promise) keySyncInFlight = null;
    });
    keySyncInFlight = { roomId, promise };
    return promise;
}

// Готовит комнату к шифрованию (ensureRoomSession): создаёт свой Sender
// Key, досылает его новым участникам, ротирует после ухода участника.
// Вызовы выстраиваются в очередь: состав комнаты мог измениться, пока
// шёл предыдущий, и "склеивать" их, как syncKeyShares, нельзя.
let roomSessionChain = Promise.resolve();
let lastRoomSession = null;   // { roomId, promise } — последний запуск, его ждёт отправка

async function runRoomSession(chatId, roomId, { answerKeyRequests = false } = {}) {
    const client = await getReadyE2eeClient();
    if (!client) return null;
    const part = await api(`/api/chats/${chatId}/participants`);
    if (!part.success || !part.roomId || Number(part.roomId) !== Number(roomId)) return null;
    rememberRoomParticipants(roomId, part.participants);
    // Запросы ключа, накопившиеся, пока я была офлайн: снимаем отметки «разослано»
    // до ensureRoomSession, и тот переотправит мой текущий ключ.
    if (answerKeyRequests) {
        try { await client.answerKeyRequests(chatId, roomId); } catch (err) { console.warn('E2EE: запросы ключа не прочитаны:', err); }
    }
    let result;
    try {
        // Ответ участников целиком: свои сертификаты, снимки к ним и приглашение комнаты (проверка состава).
        result = await client.ensureRoomSession(chatId, roomId, part.participants, part);
    } catch (err) {
        console.error('E2EE: не удалось подготовить сессию комнаты:', err);
        return null;
    }
    scheduleRevouchTimer(chatId, roomId, client);
    if (result && Array.isArray(result.warnings) && result.warnings.length > 0) {
        console.warn('E2EE: не со всеми участниками установлен защищённый канал:', result.warnings);
    }
    handleRoomSessionResult(roomId, result);
    await refreshIdentityChanges(client, roomId, part.participants, result && result.identityChanges);
    refreshTransparencyBanner();
    return result;
}

// Повторный допуск после ухода подписавшего (signed-membership.md, 5.5): задача исполняется по сроку, и открытая вкладка
// сама перезапускает сессию комнаты, когда срок наступил.
let revouchTimer = null;
async function scheduleRevouchTimer(chatId, roomId, client) {
    clearTimeout(revouchTimer);
    let wait = null;
    try { wait = await client.nextRevouchDueMs(roomId); } catch { wait = null; }
    if (wait === null) return;
    revouchTimer = setTimeout(() => {
        if (currentUser && Number(roomId) === Number(currentRoomId)) ensureE2eeRoomSession(chatId, roomId);
    }, Math.min(Math.max(wait, 5000), 60 * 60 * 1000) + 1000);
}

function ensureE2eeRoomSession(chatId, roomId, options) {
    const run = () => runRoomSession(chatId, roomId, options).catch((err) => {
        console.error('E2EE: ensureRoomSession failed:', err);
        return null;
    });
    const promise = roomSessionChain.then(run);
    roomSessionChain = promise;
    lastRoomSession = { roomId, promise };
    return promise;
}

// Состав открытой комнаты изменился (вступление по коду, одобренная
// заявка, выход участника). Забираем новые key-share и пересобираем сессию:
// ensureRoomSession увидит новичка в newMembers и отправит ему наш Sender
// Key, а после ухода — ротирует ключ. Серия событий склеивается в один
// запуск. Комнату, открытую не сейчас, это догонит при её открытии
// (openChat тоже вызывает ensureRoomSession).
function scheduleRoomMembersRefresh(roomId) {
    if (!currentUser || !roomId || !currentChatId || Number(roomId) !== Number(currentRoomId)) return;
    const chatId = currentChatId;
    const room = currentRoomId;
    clearTimeout(membersChangedTimer);
    membersChangedTimer = setTimeout(async () => {
        if (chatId !== currentChatId) return;
        await syncE2eeKeyShares(chatId, room);
        if (chatId === currentChatId) ensureE2eeRoomSession(chatId, room);
    }, 300);
}

// Отправка прервана, и причина понятна пользователю. code:
//   'unavailable'        — ключи устройства не готовы (причина в e2eeInitError);
//   'session-failed',
//   'keys-not-delivered' — см. NyxoE2eePolicy.sessionBlock;
//   'not-bot'            — чат не комната и не запомненный чат с ботом.
class E2eeBlockedError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'E2eeBlockedError';
        this.code = code;
    }

    // Причина относится к ключу комнаты: её показывают под полем ввода с «Повторить».
    get showsRetry() {
        return this.code === 'session-failed' || this.code === 'keys-not-delivered';
    }
}

// Вызывается перед отправкой в чат. Возвращает клиент E2EE для комнаты и null
// ТОЛЬКО для чата с ботом (открытый текст разрешён по запомненному номеру). В
// комнате null не бывает: либо клиент, либо E2eeBlockedError с текстом для
// пользователя — тихо отправить комнате открытым текстом нельзя.
//
// Правило блокировки (план криптографии, раздел 3): если после подготовки
// сессии комнаты ключ не дошёл ни до одного участника, а другие участники есть,
// отправка прерывается. Если не дошёл лишь до части — отправляем, а о части
// один раз предупреждает handleRoomSessionResult.
async function prepareOutgoing(chatId, roomId) {
    if (!roomId) {
        if (plaintextAllowedForChat(chatId, roomId)) return null;
        throw new E2eeBlockedError('not-bot', 'Сообщение не отправлено: открытый текст разрешён только в чате с ботом, а этот чат им не подтверждён');
    }
    const client = await getReadyE2eeClient();
    if (!client) {
        throw new E2eeBlockedError('unavailable',
            `Сквозное шифрование недоступно: ${NyxoE2eePolicy.initErrorReason(e2eeInitError)}. Сообщение не отправлено`);
    }
    // Sender Key комнаты должен быть создан и разослан участникам до
    // первого конверта; если последний запуск не удался — пробуем снова.
    let session = null;
    if (lastRoomSession && lastRoomSession.roomId === roomId) session = await lastRoomSession.promise;
    if (!session || session.ok === false) session = await ensureE2eeRoomSession(chatId, roomId);
    const block = NyxoE2eePolicy.sessionBlock(session);
    if (block) throw new E2eeBlockedError(block.code, block.text);
    return client;
}

// Показывает причину отклонённой отправки: тост и, для ключа комнаты, строка
// под полем ввода с «Повторить».
function reportBlockedSend(err, chatId, roomId) {
    showToast(err.message, 'error', 6000);
    if (roomId && err.showsRetry) setRoomBlock(chatId, err.message);
}

// Общий признак версии клиента волны 4 (message-ordering.md, 14.1): все изменяющие
// запросы сообщений (отправка, файл, правка) несут proto. Значение должно равняться
// PROTO_CURRENT в lib/proto.js - это проверяет test/proto.test.js. Устаревшая вкладка
// без признака получает 400 client-outdated («Обновите страницу»).
const PROTO_VERSION = 4;

// Тексты для причин отказа decryptIncoming (res.reason из e2ee.js). Причина,
// которой здесь нет, получает общий текст. Новая причина — новая строка.
const E2EE_FAILURE_TEXTS = {
    // Автора сообщения комнаты определяет клиент по senderKeyId через индекс
    // отправителей (sealed-sender.md, 9.3): ключа в индексе ещё нет - он придёт
    // key-share'ом или по запросу ключа.
    'no-sender-key': 'Ключ автора ещё не получен на этом устройстве',
    'bad-signature': 'Подпись сообщения неверна (возможна подмена сервером)',
    replay: 'Повтор старого сообщения (возможна подмена сервером)',
    // Содержимое привязано к сообщению (message-ordering.md, раздел 9): внутри
    // шифротекста лежат id сообщения, автор версии и время правки.
    'id-mismatch': 'Сообщение выдано под чужим номером (возможна подмена сервером)',
    'sender-mismatch': 'У сообщения сменился автор (возможна подмена сервером)',
    'stale-edit': 'Старая версия сообщения вместо более новой (возможна подмена сервером)',
    'no-mid': 'Сообщение старого формата, показать его нельзя',
    // Ключ сообщения удалён на этом устройстве: по сроку исчезающих сообщений или бюджету
    // хранения (раздел 5 плана криптографии) либо режимом «Не хранить историю» (раздел 6).
    'key-expired': 'Недоступно на этом устройстве: ключ удалён по сроку хранения',
    'history-not-kept': 'Недоступно на этом устройстве: история не хранится',
    // Открытых сообщений в комнатах нет: сервер их не принимает. Пришло такое — его
    // прислал не клиент участника; показывать его текст как сообщение нельзя.
    'not-encrypted': 'Сообщение пришло без шифрования — так не должно быть (возможна подмена сервером), поэтому оно не показано',
};
const E2EE_FAILURE_DEFAULT_TEXT = 'Не удалось расшифровать';

function e2eeFailureText(reason) {
    // hasOwnProperty: причина — строка из кода, но имена вроде 'constructor'
    // не должны находиться в прототипе объекта.
    return Object.prototype.hasOwnProperty.call(E2EE_FAILURE_TEXTS, reason)
        ? E2EE_FAILURE_TEXTS[reason]
        : E2EE_FAILURE_DEFAULT_TEXT;
}

function safeDisplayName(name) {
    const clean = String(name || '')
        .split(/[\\/]/).pop()
        .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '')
        .trim()
        .slice(0, 200);
    return clean || 'file';
}

// Текст цитаты/превью для результата decryptIncoming.
function decryptedSummary(res) {
    if (!res.ok && res.reason === 'history-not-kept') return 'Сообщение недоступно на этом устройстве';
    if (!res.ok) return e2eeFailureText(res.reason);
    if (res.file) return `Файл: ${res.text || safeDisplayName(res.file.name)}`;
    return res.text;
}

// Расшифровывает сообщение "на месте" перед рендерингом — после этого
// вызова весь остальной код (createMessageElement, предпросмотр ответа,
// редактирование) работает с message.text как с обычным открытым
// текстом, будто шифрования и не было. messageId передаётся в
// decryptIncoming для защиты от повтора: сервер не может выдать старый
// конверт за новое сообщение.
async function decryptEnvelope(roomId, senderId, text, messageId) {
    const client = roomId ? await getSettledE2eeClient() : null;
    if (!client) return { ok: false, reason: 'unavailable' };
    const attempt = async () => {
        try {
            return await client.decryptIncoming(roomId, senderId, text, messageId);
        } catch (err) {
            console.warn('E2EE: decryptIncoming failed:', err);
            return { ok: false, reason: 'error' };
        }
    };
    let res = await attempt();
    // Sender Key отправителя мог прийти (e2eeKeyShare) буквально перед
    // самим сообщением — один раз досинхронизируем ключи и пробуем снова.
    if (!res.ok && (res.reason === 'no-sender-key' || res.reason === 'stale-sender-key')
        && currentChatId && Number(roomId) === Number(currentRoomId) && Date.now() - lastKeySyncAt > 3000) {
        await syncE2eeKeyShares(currentChatId, roomId);
        res = await attempt();
    }
    // Ключа всё ещё нет (key-share потерян или вытеснен из очереди): просим владельца
    // прислать его снова, не чаще раза в час на ключ.
    if (!res.ok && (res.reason === 'no-sender-key' || res.reason === 'stale-sender-key')) requestMissingRoomKey(roomId, text);
    return res;
}

async function decryptMessageInPlace(message, roomId) {
    if (roomId && !message.encrypted) {
        // Без метки «без шифрования» (её больше нет) подложенное сервером открытое
        // сообщение выглядело бы как настоящее сообщение участника.
        message.text = e2eeFailureText('not-encrypted');
        message._e2eeFailed = true;
        message.file_url = null;
        message.file_name = null;
    } else if (message.encrypted) {
        if (roomId) {
            // Подсказки сервера об авторе нет и быть не может: senderId = null, автора
            // находит клиент по индексу отправителей (sealed-sender.md, 9.3).
            const res = await decryptEnvelope(roomId, null, message.text, message.id);
            if (res.ok) {
                message.text = res.text || '';
                if (res.file) message._file = res.file;
                message._ts = res.ts; // время отправителя для показа (раздел 9.5)
                message._senderId = res.senderId; // автор - только из расшифровки (9.4)
                // Отправитель вне подтверждённого состава (signed-membership.md, 9.4): сообщение помечается.
                message._unverified = res.unverifiedSender === true;
            } else {
                message.text = e2eeFailureText(res.reason);
                message._e2eeFailed = true;
                // Серия таких сообщений сворачивается в одну служебную строку (renderMessages).
                if (res.reason === 'history-not-kept') message._historyNotKept = true;
            }
        } else {
            message.text = 'Зашифрованное сообщение';
            message._e2eeFailed = true;
        }
    }
    if (message.reply_to && !message.reply_to.deleted) {
        if (roomId && !message.reply_to.encrypted) {
            message.reply_to.text = e2eeFailureText('not-encrypted');
        } else if (message.reply_to.encrypted) {
            const replyRes = roomId
                ? await decryptEnvelope(roomId, null, message.reply_to.text, message.reply_to.id)
                : { ok: false };
            message.reply_to.text = decryptedSummary(replyRes);
            // Автор цитаты определяется так же, как у обычного сообщения; цитата без
            // расшифровки - «Сообщение недоступно» (sealed-sender.md, 9.6).
            if (roomId) {
                message.reply_to._author = replyRes.ok ? roomAuthorLabel(roomId, replyRes.senderId) : '';
                if (!replyRes.ok) message.reply_to.text = 'Сообщение недоступно';
            }
        }
    }
    return message;
}

async function decryptMessagesInPlace(messages, roomId) {
    for (const m of messages) await decryptMessageInPlace(m, roomId);
    return messages;
}

// >>> e2ee-room-keys
// Ключи комнат на устройстве (план криптографии, раздел 5): плановая ротация своего
// ключа после отправки, повтор шифрования после needs-room-session, запрос потерянного
// ключа и ответ владельца, срок исчезающих сообщений для хранилища ключей.
// Логика вынесена в отдельный блок, чтобы проверяться юнит-тестом
// (test/e2ee-room-keys-client.test.js) без браузера.

// Шифрует сообщение комнаты. Если ключ комнаты исчерпал жёсткий порог ротации
// (200 сообщений или 8 суток, E2eeError с кодом 'needs-room-session'), ждёт
// ensureRoomSession — он ротирует ключ и рассылает новый — и повторяет шифрование
// один раз. Любая другая ошибка и повторный отказ уходят вызывающему.
async function encryptForRoom(client, chatId, roomId, content, options) {
    try {
        return await client.encryptOutgoing(roomId, content, options);
    } catch (err) {
        if (!err || err.code !== 'needs-room-session') throw err;
        await ensureE2eeRoomSession(chatId, roomId);
        return client.encryptOutgoing(roomId, content, options);
    }
}

// После отправки: ключ комнаты мог дойти до мягкого порога ротации (100 сообщений
// или 7 суток). Проверка локальная и дешёвая; ротацию и рассылку нового ключа
// делает ensureRoomSession в фоне, и отправка её не ждёт.
async function checkRoomKeyRotation(chatId, roomId) {
    if (!roomId) return;
    try {
        const client = await getReadyE2eeClient();
        if (client && await client.roomKeyDue(roomId)) await ensureE2eeRoomSession(chatId, roomId);
    } catch (err) {
        console.warn('E2EE: плановая ротация ключа комнаты не удалась:', err);
    }
}

// Запрос потерянного ключа. Сообщение не расшифровалось из-за 'no-sender-key' или
// 'stale-sender-key', а синхронизация key-share ключа не принесла: просим владельца
// прислать его снова. Конверты открытой комнаты копятся и уходят одним запросом.
const KEY_REQUEST_DEBOUNCE_MS = 800;
const pendingKeyRequests = new Map();   // roomId → { chatId, envelopes: Set<string>, timer }

function requestMissingRoomKey(roomId, envelopeText) {
    if (!roomId || !currentChatId || Number(roomId) !== Number(currentRoomId) || typeof envelopeText !== 'string') return;
    let entry = pendingKeyRequests.get(roomId);
    if (!entry) {
        entry = { chatId: currentChatId, envelopes: new Set(), timer: null };
        pendingKeyRequests.set(roomId, entry);
    }
    entry.envelopes.add(envelopeText);
    clearTimeout(entry.timer);
    entry.timer = setTimeout(() => flushKeyRequest(roomId), KEY_REQUEST_DEBOUNCE_MS);
}

async function flushKeyRequest(roomId) {
    const entry = pendingKeyRequests.get(roomId);
    pendingKeyRequests.delete(roomId);
    if (!entry || !currentUser) return;
    try {
        const client = await getReadyE2eeClient();
        if (client) await client.requestRoomKeys(entry.chatId, roomId, Array.from(entry.envelopes));
    } catch (err) {
        console.warn('E2EE: запрос ключа не удался:', err);
    }
}

function clearPendingKeyRequests() {
    pendingKeyRequests.forEach(entry => clearTimeout(entry.timer));
    pendingKeyRequests.clear();
}

// Событие e2eeKeyRequest: участник просит ключ. Если это мой текущий ключ, клиент
// снимает отметку «разослано», и ensureRoomSession переотправляет его.
async function handleKeyRequestEvent(payload) {
    if (!currentUser || !payload) return;
    const roomId = Number(payload.roomId);
    const meta = roomId ? findChatMeta(null, roomId) : null;
    if (!meta) return;
    try {
        const client = await getReadyE2eeClient();
        if (!client) return;
        const answer = await client.answerKeyRequests(meta.id, roomId, [{ fromUserId: payload.fromUserId, senderKeyIds: payload.senderKeyIds }]);
        if (answer && Array.isArray(answer.resend) && answer.resend.length > 0) await ensureE2eeRoomSession(meta.id, roomId);
    } catch (err) {
        console.warn('E2EE: ответ на запрос ключа не удался:', err);
    }
}

// Срок исчезающих сообщений комнаты нужен хранилищу ключей на устройстве: ключи
// удаляются вместе с сообщениями, через срок и час запаса. Передаётся при открытии
// комнаты и при смене срока (список чатов, событие chatExpiryChanged).
async function syncRoomKeyPolicy(roomId, seconds) {
    if (!roomId) return;
    try {
        const client = await getReadyE2eeClient();
        if (client) await client.setRoomPolicy(roomId, { expirySeconds: normalizeExpiry(seconds) });
    } catch (err) {
        console.warn('E2EE: не удалось передать срок хранения ключам комнаты:', err);
    }
}

// Раз в час и при открытии комнаты: хранение ключей (срок, цепочки без prev.final, бюджет)
// по всем комнатам из списка чатов; для комнат со сроком заодно сверяется сам срок.
const ROOM_KEYS_MAINTENANCE_MS = 60 * 60 * 1000;
let roomKeysMaintenanceTimer = null;
let roomKeysFirstRunTimer = null;

async function maintainAllRoomKeys() {
    if (!currentUser || e2eeState !== 'ready') return;
    const client = getE2eeClient();
    if (!client) return;
    for (const chat of chatListData.slice()) {
        if (chat.room_id == null) continue;
        try {
            await client.setRoomPolicy(chat.room_id, { expirySeconds: normalizeExpiry(chat.expiry_seconds) });
            await client.maintainRoomKeys(chat.room_id);
        } catch (err) {
            console.warn('E2EE: обслуживание ключей комнаты не удалось:', err);
        }
    }
}

function startRoomKeysMaintenance() {
    stopRoomKeysMaintenance();
    roomKeysFirstRunTimer = setTimeout(maintainAllRoomKeys, 20 * 1000); // к этому времени список чатов уже загружен
    roomKeysMaintenanceTimer = setInterval(maintainAllRoomKeys, ROOM_KEYS_MAINTENANCE_MS);
}

function stopRoomKeysMaintenance() {
    clearTimeout(roomKeysFirstRunTimer);
    clearInterval(roomKeysMaintenanceTimer);
    roomKeysFirstRunTimer = null;
    roomKeysMaintenanceTimer = null;
    clearPendingKeyRequests();
}
// ---- «Не хранить историю на этом устройстве» (план криптографии, раздел 6) ----
//
// Настройка личная и живёт в хранилище ключей устройства. Пока она включена, ключи
// сообщений комнаты стираются, когда комнату перестают смотреть: уход в другой чат,
// закрытие или скрытие вкладки (дольше 5 минут). Страховка на случай упавшей вкладки —
// клиент забывает такие комнаты при первом init() следующего запуска.

const HISTORY_HIDDEN_FORGET_MS = 5 * 60 * 1000;
const roomHistoryModes = new Map();   // roomId → 'keep' | 'none' (что вкладка знает о комнатах)
let hiddenForgetTimer = null;

function roomHistoryMode(roomId) {
    return roomId ? (roomHistoryModes.get(Number(roomId)) || 'keep') : 'keep';
}

// Читает режим комнаты из хранилища ключей и запоминает его.
async function loadRoomHistoryMode(roomId) {
    if (!roomId) return 'keep';
    try {
        const client = await getSettledE2eeClient();
        if (client) roomHistoryModes.set(Number(roomId), await client.getRoomHistoryMode(roomId));
    } catch (err) {
        console.warn('E2EE: не удалось прочитать режим хранения истории:', err);
    }
    return roomHistoryMode(roomId);
}

// Включает или выключает режим. Включение забывает историю сразу (клиент), выключение
// удалённое не возвращает. Бросает ошибку, если сохранить настройку не удалось.
async function applyRoomHistoryMode(roomId, mode) {
    const client = await getSettledE2eeClient();
    if (!client) throw new Error('сквозное шифрование недоступно');
    const saved = await client.setRoomHistoryMode(roomId, mode);
    roomHistoryModes.set(Number(roomId), saved);
    return saved;
}

// Забывает историю комнаты на этом устройстве, если для неё включено «не хранить».
async function forgetRoomIfNoHistory(roomId) {
    if (!roomId || roomHistoryMode(roomId) !== 'none') return false;
    try {
        const client = await getSettledE2eeClient();
        if (!client) return false;
        await client.forgetRoomHistory(roomId);
        return true;
    } catch (err) {
        console.warn('E2EE: не удалось забыть историю комнаты:', err);
        return false;
    }
}

// Вкладка скрыта дольше 5 минут — забываем историю открытой комнаты; вернулись — отсчёт сброшен.
function onHistoryVisibilityChange(hidden) {
    clearTimeout(hiddenForgetTimer);
    hiddenForgetTimer = null;
    if (!hidden) return;
    hiddenForgetTimer = setTimeout(() => { forgetRoomIfNoHistory(currentRoomId); }, HISTORY_HIDDEN_FORGET_MS);
}

// Закрытие страницы (pagehide). Запись в IndexedDB на выгрузке не гарантирована, поэтому
// есть страховка: init() следующего запуска забывает такие комнаты.
function forgetOpenRoomOnPageHide() {
    forgetRoomIfNoHistory(currentRoomId);
}

// Подряд идущие сообщения с историей, которой нет на устройстве, сворачиваются в одну
// служебную строку вместо десятков серых пузырей: возвращает группы индексов (по две и
// более подряд). Одиночное сообщение остаётся обычным пузырём.
function historyGapRuns(messages) {
    const runs = [];
    let run = [];
    const close = () => { if (run.length >= 2) runs.push(run); run = []; };
    messages.forEach((message, index) => {
        if (message && message._historyNotKept) run.push(index);
        else close();
    });
    close();
    return runs;
}
// <<< e2ee-room-keys

// ==================== Файлы: белый список, очистка, шифрование ====================
// Какие типы можно отправлять, как их распознавать, называть и показывать —
// решает public/lib/mime-policy.js (MimePolicy): он подключён до этого
// файла и проверяется юнит-тестами. Здесь только то, что связывает политику
// с санитайзером.

// Отправить можно то, что и разрешено политикой, и умеет чистить санитайзер.
// Списки независимы: формат, которому санитайзер научился, сам по себе
// отправку не включит (его нет в политике), а тип из политики, который
// санитайзер чистить не умеет, в очередь не попадёт. Вторая страховка —
// sendOneFile: MediaSanitizer.sanitize бросает исключение на неизвестном типе.
function isSupportedMime(mime) {
    return MimePolicy.isAllowedUpload(mime)
        && typeof MediaSanitizer !== 'undefined' && Array.isArray(MediaSanitizer.SUPPORTED_TYPES)
        && MediaSanitizer.SUPPORTED_TYPES.includes(mime);
}

// Имя внутри E2EE-конверта: у фото и видео — обезличенное, у документов —
// исходное (без него документ не отличить от других), но сервер его не
// видит — только участники комнаты.
function encryptedFileName(file, mime) {
    return MimePolicy.isMediaMime(mime)
        ? MimePolicy.anonymousFileName(mime)
        : safeDisplayName(file.name || MimePolicy.anonymousFileName(mime));
}

// ---- Расшифровка вложений: лениво и не больше двух за раз ----

const MAX_PARALLEL_FILE_DECRYPTS = 2;
const objectUrls = new Map();   // messageId -> blob: URL (отзываются при удалении сообщения и смене чата)
const attachmentQueue = [];
let attachmentsActive = 0;
let attachmentObserver = null;

function registerObjectUrl(messageId, url) {
    revokeObjectUrl(messageId);
    objectUrls.set(String(messageId), url);
}

function revokeObjectUrl(messageId) {
    const url = objectUrls.get(String(messageId));
    if (url) {
        URL.revokeObjectURL(url);
        objectUrls.delete(String(messageId));
    }
}

function revokeAllObjectUrls() {
    objectUrls.forEach(url => URL.revokeObjectURL(url));
    objectUrls.clear();
}

function getAttachmentObserver() {
    if (attachmentObserver || typeof IntersectionObserver === 'undefined') return attachmentObserver;
    attachmentObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            attachmentObserver.unobserve(entry.target);
            enqueueAttachmentDecrypt(entry.target);
        });
    }, { root: elements.chatMessages, rootMargin: '300px 0px' });
    return attachmentObserver;
}

function enqueueAttachmentDecrypt(box) {
    attachmentQueue.push(box);
    pumpAttachmentQueue();
}

function pumpAttachmentQueue() {
    while (attachmentsActive < MAX_PARALLEL_FILE_DECRYPTS && attachmentQueue.length > 0) {
        const box = attachmentQueue.shift();
        if (!box.isConnected || !box._attachment || box._attachment.seq !== openChatSeq) continue;
        attachmentsActive++;
        decryptAttachment(box).finally(() => {
            attachmentsActive--;
            pumpAttachmentQueue();
        });
    }
}

function resetAttachmentDecrypts() {
    attachmentQueue.length = 0;
    if (attachmentObserver) attachmentObserver.disconnect();
    revokeAllObjectUrls();
}

function setAttachmentStatus(box, text, failed) {
    const span = failed
        ? iconText('span', 'attachment-status e2ee-failed', 'lock', text, { size: 'sm' })
        : iconText('span', 'attachment-status attachment-loading', 'loader', text, { size: 'sm', className: 'spin' });
    box.replaceChildren(span);
}

function createDocumentLink(url, name, mime, extra = {}) {
    const wrapper = document.createElement('div');
    wrapper.className = 'file-attachment';
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    if (extra.newTab) {
        a.target = '_blank';
        a.rel = 'noopener';
    }
    const label = document.createElement('span');
    label.textContent = name;
    a.append(icon(MimePolicy.fileIconName(mime)), label, icon('download', { size: 'sm' }));
    wrapper.appendChild(a);
    return wrapper;
}

function createMediaElement(mime, url, name) {
    if (mime.startsWith('image/')) {
        const img = document.createElement('img');
        img.src = url;
        img.className = 'message-image';
        img.decoding = 'async';
        img.alt = name || 'Изображение';
        img.addEventListener('click', () => window.open(url, '_blank', 'noopener'));
        return img;
    }
    if (mime.startsWith('video/')) {
        const video = document.createElement('video');
        video.src = url;
        video.controls = true;
        video.preload = 'metadata';
        video.className = 'message-video';
        return video;
    }
    // Документы только скачиваются (download), а не открываются во вкладке.
    return createDocumentLink(url, name, mime);
}

function showDecryptedAttachment(box, message, bytes) {
    const file = message._file;
    const mime = MimePolicy.safeBlobMime(file.mime);
    const name = safeDisplayName(file.name || MimePolicy.anonymousFileName(mime));
    const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
    registerObjectUrl(message.id, url);
    const stick = isNearBottom();
    const media = createMediaElement(mime, url, name);
    // Картинка меняет высоту ленты после загрузки — если пользователь был
    // внизу, остаёмся внизу.
    if (stick && media.tagName === 'IMG') media.addEventListener('load', () => scrollToBottom(), { once: true });
    box.replaceChildren(media);
    box.classList.add('decrypted');
}

async function decryptAttachment(box) {
    const { message, seq } = box._attachment;
    const file = message._file;
    try {
        const client = await getSettledE2eeClient();
        if (!client) throw new Error('E2EE-клиент недоступен');
        const res = await fetch(message.file_url, { credentials: 'same-origin' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const ciphertext = new Uint8Array(await res.arrayBuffer());
        const plain = await client.decryptFile(ciphertext, file.key, file.iv, file.size);
        if (seq !== openChatSeq || !box.isConnected) return; // чат уже сменили — object URL не создаём
        showDecryptedAttachment(box, message, plain);
    } catch (err) {
        console.warn('E2EE: не удалось расшифровать вложение:', err);
        if (seq === openChatSeq && box.isConnected) setAttachmentStatus(box, 'Не удалось расшифровать файл', true);
    }
}

function createEncryptedAttachmentElement(message) {
    const box = document.createElement('div');
    box.className = 'encrypted-attachment';
    if (!message.file_url) {
        setAttachmentStatus(box, 'Не удалось расшифровать файл', true);
        return box;
    }
    box._attachment = { message, seq: openChatSeq };
    if (message._localBytes) {
        // Своё только что отправленное вложение: исходные (уже очищенные)
        // байты есть в памяти — повторно скачивать и расшифровывать незачем.
        const bytes = message._localBytes;
        delete message._localBytes;
        showDecryptedAttachment(box, message, bytes);
        return box;
    }
    setAttachmentStatus(box, `Загрузка файла «${safeDisplayName(message._file.name)}»…`, false);
    const observer = getAttachmentObserver();
    if (observer) observer.observe(box);
    else setTimeout(() => enqueueAttachmentDecrypt(box), 0);
    return box;
}

// ==================== Proof-of-work для регистрации ====================
// Создание аккаунта требует решения PoW-задачи: это ограничивает массовое
// создание аккаунтов ботами без капчи и без сторонних сервисов. Считается
// в Web Worker, чтобы не вешать вкладку.

function runPowWorker(token, difficulty) {
    return new Promise((resolve, reject) => {
        let worker;
        try {
            worker = new Worker('pow-worker.js');
        } catch (err) {
            reject(new Error('Браузер не поддерживает проверку (Web Worker недоступен)'));
            return;
        }
        let timer = null;
        const finish = () => {
            clearTimeout(timer);
            worker.terminate();
        };
        timer = setTimeout(() => {
            finish();
            reject(new Error('Проверка заняла слишком много времени. Попробуйте ещё раз.'));
        }, POW_TIMEOUT_MS);
        worker.onmessage = (event) => {
            finish();
            const nonce = event.data && event.data.nonce;
            if (typeof nonce === 'string' && nonce) resolve(nonce);
            else reject(new Error('Не удалось пройти проверку'));
        };
        worker.onerror = () => {
            finish();
            reject(new Error('Не удалось пройти проверку'));
        };
        worker.postMessage({ token, difficulty });
    });
}

async function solvePow(purpose) {
    const challenge = await api(`/api/pow/challenge?purpose=${encodeURIComponent(purpose)}`);
    if (!challenge.success || typeof challenge.token !== 'string') {
        throw new Error(challenge.message || 'Не удалось получить задачу проверки');
    }
    const nonce = await runPowWorker(challenge.token, challenge.difficulty);
    return { token: challenge.token, nonce };
}

// POST с решённой PoW-задачей. Если сервер ответил powRequired (токен
// истёк, пока пользователь думал), — одна повторная попытка с новой задачей.
// isCancelled() проверяется перед отправкой: пока считалась задача, в
// соседней вкладке мог появиться аккаунт — второй тогда не создаётся.
async function postWithPow(url, body, purpose, btn, { isCancelled } = {}) {
    // Подпись кнопки — иконка + текст: сохраняем узлы целиком.
    const label = Array.from(btn.childNodes);
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    setIconLabel(btn, 'loader', 'Проверка…', { className: 'spin' });
    try {
        let data = null;
        for (let attempt = 0; attempt < 2; attempt++) {
            const pow = await solvePow(purpose);
            if (typeof isCancelled === 'function' && isCancelled()) return { success: false, cancelled: true };
            data = await api(url, { method: 'POST', body: JSON.stringify({ ...body, pow }) });
            if (!(data && data.success === false && data.powRequired)) break;
        }
        return data;
    } catch (err) {
        return { success: false, message: err.message || 'Не удалось пройти проверку' };
    } finally {
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        btn.replaceChildren(...label);
    }
}

// ==================== Сессия и сокет ====================

function init() {
    sweepLegacyPrefs();
    // До проверки входа: фрагмент #join=… стирается из адресной строки
    // сразу, даже если пользователь ещё не вошёл (см. consumeJoinFragment).
    consumeJoinFragment();
    openSessionChannel();
    checkAuth();
    try {
        setupEventListeners();
    } catch (e) {
        console.error('setupEventListeners() failed — some UI controls may not respond:', e);
    }
    setupThemeControls();
}

// ---- Ссылка-приглашение: <origin>/#join=<КОД>[.<СЕКРЕТ>] ----
// Код едет во фрагменте: браузер не отправляет фрагмент на сервер, он не
// попадает в логи прокси и в Referer. Сразу после чтения фрагмент стирается
// (history.replaceState), чтобы код не остался в истории и закладках, а
// сам код живёт только в памяти вкладки до входа в аккаунт. Секрет ссылки
// (подписанный состав группы, этап 5.4) пока не используется, но
// сохраняется рядом с кодом и на сервер не отправляется.
let pendingJoin = null;          // { code, secret } — открыть после входа
let pendingJoinBroken = false;   // ссылка была, но повреждена — сказать после входа

const INVITE_BROKEN_LINK = 'Ссылка-приглашение повреждена — попросите новую.';

// Значение для поля приглашения: код группами по 5 и секрет через точку —
// parseInviteInput разберёт его обратно без потерь.
function inviteFieldValue(invite) {
    return NyxoInvite.formatInviteCode(invite.code) + (invite.secret ? `.${invite.secret}` : '');
}

function consumeJoinFragment() {
    const hash = String(location.hash || '');
    if (!/^#(?:[^&]*&)*join=/i.test(hash)) return;
    try {
        history.replaceState(null, '', location.pathname + location.search);
    } catch { /* без History API фрагмент останется, но код всё равно не уйдёт на сервер */ }
    const parsed = NyxoInvite.parseInviteInput(hash);
    if (!parsed.ok) {
        pendingJoin = null;
        if (currentUser) {
            showToast(INVITE_BROKEN_LINK, 'error', 6000);
            return;
        }
        pendingJoinBroken = true;
        setInviteMode(true, { value: '', error: INVITE_BROKEN_LINK });
        return;
    }
    pendingJoin = { code: parsed.code, secret: parsed.secret };
    pendingJoinBroken = false;
    if (currentUser) openPendingJoin();
    else setInviteMode(true, { value: inviteFieldValue(pendingJoin) });
}

// Предпросмотр вступления по коду из ссылки — только после входа.
function openPendingJoin() {
    const invite = pendingJoin;
    pendingJoin = null;
    pendingJoinBroken = false;
    if (!invite || !currentUser) return;
    openNewChatModal({ invite: true });
    elements.joinChatCode.value = inviteFieldValue(invite);
    previewJoin();
}

async function checkAuth() {
    const data = await fetchAuthState();
    const notice = takeFlashNotice();
    if (data && data.authenticated && data.user) {
        enterApp(data.user);
        if (notice) showToast(notice, 'info', 5000);
        return;
    }
    showAuth();
    // expired — сессия была, но аккаунт уже удалён по сроку без входа (или
    // сессия недействительна).
    const expired = Boolean(data && (data.expired || data.reason === 'expired'));
    showAuthNotice(notice || (expired ? AUTH_NOTICES.expired : ''));
    // Сервер недоступен — локальные данные не трогаем: сессия могла и не истечь.
    if (data) purgeForeignLocalData();
}

function enterApp(user) {
    currentUser = user;
    // До всего остального: если вкладку просто закроют, данные этого
    // аккаунта будут стёрты, как только он перестанет быть текущим (см.
    // purgeForeignLocalData) — все аккаунты временные.
    rememberIdForWipe(user.id);
    purgeForeignLocalData();
    e2eeUnavailableWarned = false;
    e2eeRetryStep = 0;
    roomBlock = null;
    warnedRooms.clear();
    initE2eeForCurrentUser();
    showApp();
    // Новое соединение = новое рукопожатие с актуальной кукой сессии.
    if (socket.connected) socket.disconnect();
    socket.connect();
    startKeepalive();
    startE2eeMaintenance();
    startRoomKeysMaintenance();
    loadChats();
    updateAnonNote();
    // Ответ регистрации мог прийти без настроек и срока — их знает /api/auth.
    if (typeof user.readReceipts !== 'boolean' || !NyxoLifetime.isLifetime(user.anonLifetime)) pingSession();
    if (pendingJoin) {
        openPendingJoin();
    } else if (pendingJoinBroken) {
        pendingJoinBroken = false;
        showToast(INVITE_BROKEN_LINK, 'error', 6000);
    }
}

// ---- Состояние аккаунта с сервера ----
// GET /api/auth для вошедшего: продлевает сессию (сокет куку продлить не
// может — её ставит только HTTP-ответ) и приносит свежие срок, дату
// удаления и настройки. Параллельные вызовы склеиваются. Сетевая ошибка не
// разлогинивает никогда. authenticated:false без причины перепроверяется
// через 2 с: разовый сбой сервера не должен стирать ключи живого аккаунта.
const AUTH_RECHECK_MS = 2000;
let authPing = null;

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function isCurrentUser(userId) {
    return Boolean(currentUser) && currentUser.id === userId;
}

function pingSession() {
    if (!currentUser) return Promise.resolve(null);
    if (authPing) return authPing;
    const userId = currentUser.id;
    authPing = (async () => {
        let data = await fetchAuthState();
        if (!isCurrentUser(userId)) return null;
        if (data && !data.authenticated && !data.expired && !data.reason) {
            await delay(AUTH_RECHECK_MS);
            if (!isCurrentUser(userId)) return null;
            data = await fetchAuthState();
            if (!isCurrentUser(userId)) return null;
        }
        if (!data) return null;
        if (!data.authenticated) {
            // Аккаунт удаляем мы сами: сервер сначала закрывает сокет и снимает
            // сессию, потом отвечает. Выходом и уведомлением займётся
            // deleteAccountAndLeave, когда придёт ответ.
            if (deletingAccount) return data;
            leaveApp(data.expired || data.reason === 'expired' ? AUTH_NOTICES.expired : AUTH_NOTICES.sessionLost);
            return data;
        }
        if (!data.user) return data;
        // Кука принадлежит уже другому аккаунту (его создали в соседней
        // вкладке): этот из браузера недоступен, его ключи бесполезны.
        if (Number(data.user.id) !== Number(userId)) {
            leaveApp(AUTH_NOTICES.otherAccount);
            return data;
        }
        applyAuthUser(data.user);
        return data;
    })().finally(() => { authPing = null; });
    return authPing;
}

// ---- Keepalive ----
// Сессия продлевается HTTP-запросом (сокет куку не обновляет), а у вкладки
// без активности сервер снимает с аккаунта срок. Поэтому пока вкладка
// открыта, GET /api/auth уходит раз в KEEPALIVE_MS, а ещё когда вкладка
// снова видна (если запроса не было дольше минуты), при появлении сети и
// после обрыва сокета (см. обработчики сокета ниже). Фоновая вкладка может
// получать таймеры реже — для tab-аккаунта (30 минут) этого хватает.
let lastAuthAt = 0;
let keepaliveTimer = null;

function startKeepalive() {
    stopKeepalive();
    keepaliveTimer = setInterval(() => { pingSession(); }, KEEPALIVE_MS);
}

function stopKeepalive() {
    clearInterval(keepaliveTimer);
    keepaliveTimer = null;
}

function keepaliveOnVisible() {
    if (document.visibilityState !== 'visible' || !currentUser) return;
    if (Date.now() - lastAuthAt > KEEPALIVE_VISIBLE_GAP_MS) pingSession();
}

// >>> e2ee-maintenance
// Плановое обслуживание ключей устройства. init() идемпотентен и делает всё
// нужное: ротирует просроченные SPK и PQ-prekey, пополняет пулы одноразовых
// ключей, раз в 30 дней заменяет пул одноразовых PQ-prekey. Вкладка живёт
// днями, а запас одноразовых ключей тратится, пока собеседники открывают чаты
// с нами, — поэтому init() повторяется раз в 6 часов и при возвращении на
// вкладку, если прошло больше 6 часов (фоновые таймеры браузер замедляет).
// Сбой на состояние E2EE не влияет: ключи устройства остаются рабочими.
const E2EE_MAINTENANCE_MS = 6 * 60 * 60 * 1000;
const E2EE_MAINTENANCE_TICK_MS = 30 * 60 * 1000;
let e2eeMaintainedAt = 0;
let e2eeMaintaining = false;
let e2eeMaintenanceTimer = null;

function startE2eeMaintenance() {
    stopE2eeMaintenance();
    e2eeMaintainedAt = Date.now(); // первый init() делает initE2eeForCurrentUser
    e2eeMaintenanceTimer = setInterval(maintainE2eeKeys, E2EE_MAINTENANCE_TICK_MS);
}

function stopE2eeMaintenance() {
    clearInterval(e2eeMaintenanceTimer);
    e2eeMaintenanceTimer = null;
}

function maintainE2eeKeys() {
    if (!currentUser || e2eeState !== 'ready' || e2eeMaintaining) return;
    if (Date.now() - e2eeMaintainedAt < E2EE_MAINTENANCE_MS) return;
    const client = getE2eeClient();
    if (!client) return;
    e2eeMaintaining = true;
    Promise.resolve()
        .then(() => client.init())
        .then(() => { e2eeMaintainedAt = Date.now(); })
        .catch((err) => { console.warn('E2EE: плановое обслуживание ключей не удалось:', err); })
        .finally(() => { e2eeMaintaining = false; });
}
// <<< e2ee-maintenance

// Сервер сам закрыл сокет ('io server disconnect'): socket.io в этом случае
// не переподключается. Проверяем вход; если сессия жива — подключаемся
// заново, но не чаще раза в 5 секунд (иначе сервер, который по какой-то
// причине закрывает сокет каждый раз, получил бы цикл из запросов).
// Сервер закрывает сокеты и при удалении аккаунта — раньше, чем соседняя
// вкладка успеет об этом сообщить (account-deleted), поэтому с проверкой
// входа секунду ждём: иначе вместо «удалён в другой вкладке» человек
// увидел бы «потерян вход».
const SERVER_DISCONNECT_GRACE_MS = 1000;
let lastServerDisconnectAt = 0;
async function recoverFromServerDisconnect() {
    if (!currentUser) return;
    const userId = currentUser.id;
    const tooSoon = Date.now() - lastServerDisconnectAt < 5000;
    lastServerDisconnectAt = Date.now();
    await delay(SERVER_DISCONNECT_GRACE_MS);
    if (!isCurrentUser(userId)) return;
    const data = await pingSession();
    if (tooSoon || !isCurrentUser(userId) || !data || !data.authenticated) return;
    if (!socket.connected) socket.connect();
}

// ---- Несколько вкладок: BroadcastChannel nyxo-session ----
// Кука сессии общая для всех вкладок origin, поэтому вход, смена срока и
// удаление аккаунта в одной вкладке касаются всех. События:
//   session-started  { userId }               — в этом браузере создан/открыт аккаунт;
//   account-deleted  { userId }               — аккаунт удалён;
//   lifetime-changed { userId, anonLifetime } — сменился срок (сессия пересоздана).
// Автор события сам его не получает. Нет BroadcastChannel (старый Safari) —
// остаётся keepalive: другая вкладка узнает об изменении при ближайшем
// запросе /api/auth.
let sessionChannel = null;

function openSessionChannel() {
    if (typeof BroadcastChannel !== 'function') return;
    try {
        sessionChannel = new BroadcastChannel(SESSION_CHANNEL);
        sessionChannel.onmessage = (e) => onSessionEvent(e.data);
    } catch {
        sessionChannel = null;
    }
}

function postSessionEvent(event) {
    try {
        if (sessionChannel) sessionChannel.postMessage(event);
    } catch { /* канал закрыт — вкладки узнают через keepalive */ }
}

// Экран входа в этой вкладке уже не нужен: аккаунт есть, куку сессии видят
// все вкладки. Идущую здесь регистрацию отменяем — но только убедившись по
// /api/auth, что сессия действительно есть.
async function adoptSessionFromOtherTab() {
    const state = await fetchAuthState();
    if (currentUser || !state || !state.authenticated || !state.user) return;
    registrationCancelled = true;
    enterApp(state.user);
}

function onSessionEvent(event) {
    if (!event || typeof event !== 'object' || !Number.isInteger(event.userId)) return;
    if (event.type === 'session-started') {
        if (!currentUser) {
            adoptSessionFromOtherTab();
        } else if (currentUser.id !== event.userId) {
            // Кука теперь принадлежит другому аккаунту; pingSession сам
            // уведёт эту вкладку на экран входа и сотрёт её ключи.
            pingSession();
        }
    } else if (event.type === 'account-deleted') {
        if (isCurrentUser(event.userId)) leaveApp(AUTH_NOTICES.deletedElsewhere);
    } else if (event.type === 'lifetime-changed') {
        if (!isCurrentUser(event.userId)) return;
        if (NyxoLifetime.isLifetime(event.anonLifetime)) currentUser.anonLifetime = event.anonLifetime;
        // Сервер пересоздал сессию: старое рукопожатие сокета держится за прежнюю.
        reconnectSocket();
        onLifetimeChanged();
        pingSession();
    }
}

// Поля аккаунта из /api/auth; каждое проверяется: сервер другой версии
// может прислать не всё.
function applyAuthUser(user) {
    if (!currentUser || !user) return;
    const receiptsBefore = readReceiptsEnabled();
    if (typeof user.username === 'string' && user.username) currentUser.username = user.username;
    if (typeof user.readReceipts === 'boolean') currentUser.readReceipts = user.readReceipts;
    if (NyxoLifetime.isLifetime(user.anonLifetime)) currentUser.anonLifetime = user.anonLifetime;
    if ('anonExpiresAt' in user) currentUser.anonExpiresAt = user.anonExpiresAt;
    if (typeof user.anonInactivitySeconds === 'number') currentUser.anonInactivitySeconds = user.anonInactivitySeconds;
    if (readReceiptsEnabled() !== receiptsBefore) refreshOwnMessageStatuses();
    updateAnonNote();
    renderProfileLifetime();
}

// ---- Заметка о сроке хранения в сайдбаре ----
// Текст статичный («Удалится, если не заходить 1 день»): дата удаления
// сдвигается при каждом входе, её место — в профиле. Заметка — кнопка,
// открывающая профиль, где срок можно поменять.
function updateAnonNote() {
    const text = currentUser ? NyxoLifetime.lifetimeNote(currentUser.anonLifetime) : '';
    elements.anonNote.classList.toggle('hidden', !text);
    elements.anonNoteText.textContent = text;
    elements.anonNote.setAttribute('aria-label', text ? `Срок хранения аккаунта: ${text}. Открыть профиль` : 'Открыть профиль');
}

function resetChatView() {
    forgetRoomIfNoHistory(currentRoomId);
    currentChatId = null;
    currentRoomId = null;
    oldestSeq = null;
    hasMoreHistory = false;
    lastSeenSeq = 0;
    openChatSeq++;
    releaseChatResources();
    elements.chatHeader.classList.add('hidden');
    elements.messageInputContainer.classList.add('hidden');
    elements.emptyState.classList.remove('hidden');
    elements.chatMessages.replaceChildren();
    elements.sidebar.classList.remove('hidden-mobile');
    clearReply();
    editingMessageId = null;
    setActiveChatItem(null, null);
}

// Всё, что привязано к открытому чату и должно исчезнуть при его смене:
// расшифрованные вложения (object URL), очередь их расшифровки, баннер
// смены ключей, отложенные служебные строки, полоса заявок, кнопка «вниз»,
// подсказки бота (они рисуются заново после загрузки истории).
function releaseChatResources() {
    closeChatSearch();
    resetAttachmentDecrypts();
    clearBotSuggestions();
    pendingIdentityChanges.clear();
    pendingLogMismatches.clear();
    renderIdentityBanner();
    noticesReady = false;
    pendingNotices = [];
    clearTimeout(membersChangedTimer);
    hideMessageMenu();
    menuMessage = null;
    joinRequestsSeq++;
    renderRequestsBar(0);
    resetJumpDown();
    hideDropZone();
}

// Выход из приложения. Все аккаунты временные: локальные данные аккаунта
// (ключи E2EE, флаги) стираются всегда, а страница перезагружается — так
// закрываются соединения с IndexedDB и из памяти уходит расшифрованная
// переписка. message — уведомление на экране входа после перезагрузки.
// Повторный вызов (например, ответ «Не авторизован» на несколько запросов
// сразу) ничего не делает.
let leavingApp = false;
function leaveApp(message) {
    if (leavingApp) return;
    leavingApp = true;
    const user = currentUser;
    stopKeepalive();
    stopE2eeMaintenance();
    stopRoomKeysMaintenance();
    socket.disconnect();
    currentUser = null;
    e2eeClient = null;
    e2eeClientUserId = null;
    e2eeInitPromise = null;
    e2eeState = 'off';
    e2eeInitError = null;
    roomBlock = null;
    clearTimeout(e2eeRetryTimer);
    clearTimeout(markReadTimer);
    clearTimeout(loadChatsTimer);
    cancelUploadQueue();
    roomParticipants.clear();
    chatListData = [];
    chatsById.clear();
    myReactions.clear();
    resetChatView();
    closeAllModals();
    hideChatItemMenu();
    elements.chatsList.replaceChildren();
    updateAnonNote();
    setConnectionStatus(null);
    showAuth();
    if (!user) {
        reloadWithNotice(message);
        return;
    }
    rememberIdForWipe(user.id);
    wipeLocalUserData(user.id, 1500).finally(() => reloadWithNotice(message));
}

socket.on('connect_error', (err) => {
    // Сессия истекла (например, аккаунт удалён по сроку) — сервер отклоняет
    // рукопожатие. Перепроверяем вход: pingSession сам уведёт на экран входа.
    if (err && err.message === 'Не авторизован' && currentUser) pingSession();
});

socket.io.on('reconnect', () => {
    // После обрыва связи (или рестарта сервера) догружаем пропущенное и
    // продлеваем сессию: пока связи не было, HTTP-запросов тоже не было.
    if (!currentUser) return;
    loadChats();
    if (currentChatId) refreshCurrentChat();
    if (currentChatId && currentRoomId) loadJoinRequestsCount();
    pingSession();
});

// ---- Индикатор соединения ----
// Показывается только при обрыве уже установленной связи. Намеренное
// отключение (выход из аккаунта) — reason 'io client disconnect' — не в счёт.
// Сервер, разорвавший связь сам ('io server disconnect'), socket.io не
// переподключает — тогда индикатор так и остаётся «Нет соединения».
function setConnectionStatus(state) {
    const el = elements.connectionStatus;
    el.classList.remove('is-offline', 'is-reconnecting');
    if (!state || !currentUser) {
        el.classList.add('hidden');
        return;
    }
    const offline = state === 'offline';
    el.classList.add(offline ? 'is-offline' : 'is-reconnecting');
    elements.connectionStatusIcon.replaceChildren(offline
        ? icon('wifi-off', { size: 'sm' })
        : icon('loader', { size: 'sm', className: 'spin' }));
    elements.connectionStatusText.textContent = offline ? 'Нет соединения' : 'Переподключение…';
    el.classList.remove('hidden');
}

// Обрыв — «Нет соединения»; как только socket.io начинает попытку —
// «Переподключение…» (без сети браузер не даст подключиться — снова «нет»).
socket.on('connect', () => setConnectionStatus(null));
socket.on('disconnect', (reason) => {
    if (reason === 'io client disconnect') return;
    setConnectionStatus('offline');
    if (reason === 'io server disconnect') recoverFromServerDisconnect();
});
socket.io.on('reconnect_attempt', () => {
    setConnectionStatus(navigator.onLine === false ? 'offline' : 'reconnecting');
});
socket.io.on('reconnect_error', () => {
    if (navigator.onLine === false) setConnectionStatus('offline');
});
window.addEventListener('offline', () => {
    if (currentUser) setConnectionStatus('offline');
});
window.addEventListener('online', () => {
    if (!currentUser) return;
    if (!socket.connected) setConnectionStatus('reconnecting');
    pingSession();
});

socket.on('e2eeKeyRequest', (payload) => {
    // Участник просит прислать Sender Key: если это мой текущий ключ, переотправляем.
    handleKeyRequestEvent(payload);
});

socket.on('e2eeKeyShare', ({ roomId } = {}) => {
    // Кто-то прислал нам Sender Key. Если это открытый сейчас чат —
    // подхватываем сразу, иначе заберём при следующем открытии чата.
    if (roomId && Number(roomId) === Number(currentRoomId) && currentChatId) {
        syncE2eeKeyShares(currentChatId, currentRoomId);
    }
});

function showAuth() {
    elements.authScreen.classList.remove('hidden');
    elements.app.classList.add('hidden');
}

function showApp() {
    elements.authScreen.classList.add('hidden');
    elements.app.classList.remove('hidden');
}

let toastTimer = null;
const TOAST_ICONS = { success: 'check', error: 'alert-triangle', info: 'info' };
function showToast(message, type = 'info', duration = 3000) {
    const kind = TOAST_ICONS[type] ? type : 'info';
    const text = document.createElement('span');
    text.textContent = message || '';
    elements.toast.replaceChildren(icon(TOAST_ICONS[kind]), text);
    elements.toast.className = `toast toast-${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => elements.toast.classList.add('hidden'), duration);
}

function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
    return match ? match[1] : '';
}

// Ответ «Не авторизован» посреди работы: сессии может уже не быть (аккаунт
// удалён по сроку или в другой вкладке), а может, запрос просто ушёл со
// старой кукой, пока сервер пересоздавал сессию (смена срока). Решает
// свежий /api/auth (pingSession): сам ответ ключи не стирает.
function onUnauthorizedResponse(data) {
    if (currentUser && data && data.success === false && data.message === 'Не авторизован') pingSession();
}

// Любой ответ сервера приводится к { success, message, ... }. Раньше
// ответ не-JSON (502 от прокси, обрыв сети) бросал исключение прямо в
// обработчике клика, и кнопка просто "ничего не делала". networkError —
// запрос не дошёл до сервера (важно для «Удалить и выйти»: тогда аккаунт
// точно не удалён). skipAuthCheck — вызывающий сам разбирает «Не авторизован».
async function api(url, options = {}, retried = false) {
    const { skipAuthCheck = false, ...init } = options;
    let res;
    try {
        res = await fetch(url, {
            ...init,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
                ...init.headers,
            },
        });
    } catch {
        return { success: false, networkError: true, message: 'Нет соединения с сервером' };
    }
    let data;
    try {
        data = await res.json();
    } catch {
        return { success: false, httpStatus: res.status, message: `Ошибка сервера (HTTP ${res.status})` };
    }
    if (!data || typeof data !== 'object') return { success: false, httpStatus: res.status, message: `Ошибка сервера (HTTP ${res.status})` };
    // Статус нужен тем, кто различает исходы (повтор отправки после 5xx и 409,
    // sendText); тело при этом остаётся прежним.
    data.httpStatus = res.status;
    // Кука csrf_token живёт сутки; если она истекла, любой GET выдаст новую.
    if (res.status === 403 && !retried && /CSRF/i.test(data.message || '')) {
        await fetch('/api/auth').catch(() => {});
        return api(url, options, true);
    }
    if (!skipAuthCheck) onUnauthorizedResponse(data);
    return data;
}

// multipart-вариант api(): без Content-Type (его с границей ставит сам
// браузер), с той же обработкой ошибок и повтором при протухшем CSRF.
async function postFormData(url, formData, retried = false) {
    let res;
    try {
        res = await fetch(url, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
    } catch {
        return { success: false, networkError: true, message: 'Нет соединения с сервером' };
    }
    const data = await res.json().catch(() => ({ success: false, message: `Ошибка сервера (HTTP ${res.status})` }));
    if (data && typeof data === 'object') data.httpStatus = res.status;
    if (res.status === 403 && !retried && /CSRF/i.test(data.message || '')) {
        await fetch('/api/auth').catch(() => {});
        return postFormData(url, formData, true);
    }
    onUnauthorizedResponse(data);
    return data;
}

// Тот же multipart-запрос через XMLHttpRequest: у fetch нет событий
// прогресса отправки. Заголовок CSRF и куки — как у fetch (same-origin,
// withCredentials на всякий случай явно). options.onProgress(0..1),
// options.onXhr(xhr) — чтобы вызывающий мог отменить загрузку (abort).
// Отмена резолвится { success:false, aborted:true }.
function postFormDataWithProgress(url, formData, options = {}, retried = false) {
    return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', url);
        xhr.withCredentials = true;
        xhr.responseType = 'text';
        xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());
        if (typeof options.onXhr === 'function') options.onXhr(xhr);
        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable && typeof options.onProgress === 'function') options.onProgress(e.loaded / e.total);
        };
        xhr.onabort = () => resolve({ success: false, aborted: true, message: 'Загрузка отменена' });
        xhr.onerror = () => resolve({ success: false, networkError: true, message: 'Нет соединения с сервером' });
        xhr.onload = async () => {
            let data;
            try {
                data = JSON.parse(xhr.responseText);
            } catch {
                data = { success: false, message: `Ошибка сервера (HTTP ${xhr.status})` };
            }
            if (data && typeof data === 'object') data.httpStatus = xhr.status;
            if (xhr.status === 403 && !retried && /CSRF/i.test((data && data.message) || '')) {
                await fetch('/api/auth').catch(() => {});
                resolve(postFormDataWithProgress(url, formData, options, true));
                return;
            }
            onUnauthorizedResponse(data);
            resolve(data || { success: false });
        };
        xhr.send(formData);
    });
}

// Обработчики навешиваются по областям интерфейса, каждая — в своей функции
// ниже. Порядок вызовов повторяет прежний порядок регистрации, когда всё
// было одним длинным телом: он важен там, где на один и тот же элемент и
// событие вешается несколько обработчиков (например, два keydown на
// document). Новый обработчик добавляйте в функцию своей области; новая
// область — новая функция и одна строка в этом списке.
function setupEventListeners() {
    setupAuthListeners();        // экран входа, «Как это работает»
    setupLogoutListeners();      // выход из аккаунта
    setupSidebarListeners();     // «Новый чат», вступление по коду, «назад»
    setupChatMenuListeners();    // меню чата и личные настройки чатов
    setupE2eeListeners();        // шифрование в шапке чата, участники и ключи
    setupInviteListeners();      // приглашения и заявки
    setupProfileListeners();     // профиль, настройки, удаление аккаунта
    setupComposerListeners();    // поле ввода, вложения
    setupMessageMenuListeners(); // меню сообщения
    setupSearchListeners();      // поиск по чатам
    setupModalListeners();       // модальные окна
    setupFeedListeners();        // лента сообщений
    setupSocketListeners();      // события сокета
    setupMenuDismissListeners(); // закрытие всплывающих меню
}

// Экран входа: выбор срока, «Начать анонимно», поле приглашения, окно
// «Как это работает» и ссылка на onion-адрес.
function setupAuthListeners() {
    elements.authLifetime.addEventListener('change', updateAuthLifetimeDetail);
    elements.anonStartBtn.addEventListener('click', startAccount);
    elements.inviteToggleBtn.addEventListener('click', () => setInviteMode(!authInviteMode, { focus: true }));
    elements.authInviteInput.addEventListener('input', clearInviteError);
    elements.authInviteInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            startAccount();
        }
    });
    elements.aboutOpenBtn.addEventListener('click', () => openAboutModal());
    elements.onionOpenBtn.addEventListener('click', () => openAboutModal('tor'));
    elements.aboutOnionCopyBtn.addEventListener('click', () => {
        if (onionUrl) copyText(onionUrl, 'Адрес скопирован', 'Не удалось скопировать — выделите адрес вручную');
    });
    updateAuthLifetimeDetail();
    applyOnionUrl(onionUrl);
}

// «Удалить и выйти» в сайдбаре: аккаунт держится только на cookie этого
// браузера, поэтому выход и есть удаление — то же подтверждение, что и у
// кнопки в профиле.
function setupLogoutListeners() {
    elements.logoutBtn.addEventListener('click', openDeleteAccountModal);
    elements.confirmDeleteAccountBtn.addEventListener('click', deleteAccountAndLeave);
}

// Сайдбар и окно «Новый чат»: создание группы, вступление по коду
// приглашения; «назад» к списку чатов в мобильной раскладке.
function setupSidebarListeners() {
    elements.newChatBtn.addEventListener('click', () => openNewChatModal());
    elements.createChatBtn.addEventListener('click', createChat);
    document.getElementById('new-chat-name').addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            createChat();
        }
    });
    elements.joinChatBtn.addEventListener('click', previewJoin);
    elements.joinChatCode.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            previewJoin();
        }
    });
    elements.joinChatCode.addEventListener('input', () => {
        hideJoinPreview();
        clearJoinError();
    });
    elements.joinConfirmBtn.addEventListener('click', joinChat);
    elements.joinCancelBtn.addEventListener('click', onJoinCancel);

    if (elements.backBtn) {
        elements.backBtn.addEventListener('click', () => elements.sidebar.classList.remove('hidden-mobile'));
    }
}

// Меню чата и личные настройки чатов (закрепить, без звука, архив, срок
// исчезающих сообщений) — в окне меню и в контекстном меню списка.
function setupChatMenuListeners() {
    elements.chatMenuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        openChatMenu();
    });
    elements.deleteChatBtn.addEventListener('click', deleteChat);
    elements.pinChatBtn.addEventListener('click', () => toggleChatPref(currentChatId, 'pinned'));
    elements.muteChatBtn.addEventListener('click', () => toggleChatPref(currentChatId, 'muted'));
    elements.archiveChatBtn.addEventListener('click', () => toggleChatPref(currentChatId, 'archived'));
    elements.expiryFieldset.querySelectorAll('input[name="chat-expiry"]').forEach((radio) => {
        radio.addEventListener('change', () => {
            if (radio.checked) setChatExpiry(Number(radio.value));
        });
    });
    elements.ctxPinBtn.addEventListener('click', () => onChatItemMenuAction('pinned'));
    elements.ctxMuteBtn.addEventListener('click', () => onChatItemMenuAction('muted'));
    elements.ctxArchiveBtn.addEventListener('click', () => onChatItemMenuAction('archived'));
}

// Сквозное шифрование в шапке чата: значок шифрования и кнопка открывают окно
// «Участники и ключи», баннер о смене ключа собеседника; «Повторить» под полем
// ввода. Выключателя нет.
function setupE2eeListeners() {
    elements.e2eeIndicator.addEventListener('click', openMembersModal);
    elements.membersKeysBtn.addEventListener('click', openMembersModal);
    elements.noHistoryToggle.addEventListener('change', onNoHistoryToggle);
    elements.e2eeBannerBtn.addEventListener('click', openMembersModal);
    elements.ktBannerBtn.addEventListener('click', openTransparencyModal);
    elements.composerStatusRetry.addEventListener('click', () => retryE2ee());
}

// Приглашения в группу (код, ссылка, QR) и заявки на вступление.
function setupInviteListeners() {
    elements.getChatCodeBtn.addEventListener('click', openInviteModal);
    elements.rotateInviteBtn.addEventListener('click', rotateInviteCode);
    elements.disableInviteBtn.addEventListener('click', disableInviteCode);
    elements.copyInviteBtn.addEventListener('click', () => {
        const code = elements.inviteCodeDisplay.dataset.code || '';
        if (code) copyText(code, 'Код скопирован', 'Не удалось скопировать — выделите код вручную');
    });
    elements.copyInviteLinkBtn.addEventListener('click', () => {
        const code = elements.inviteCodeDisplay.dataset.code || '';
        const secret = elements.inviteCodeDisplay.dataset.secret || '';
        if (code) copyText(inviteLink(code, secret), secret ? 'Ссылка скопирована' : 'Ссылка без секрета скопирована: по ней можно только отправить заявку', 'Не удалось скопировать ссылку');
    });
    elements.requestsBarBtn.addEventListener('click', openRequestsModal);
}

// Профиль: срок хранения, отметки о прочтении, уведомления, «Как устроен
// Nyxo», «Удалить аккаунт и выйти». Заметка о сроке в сайдбаре тоже
// открывает профиль — там срок и меняется.
function setupProfileListeners() {
    elements.profileBtn.addEventListener('click', openProfile);
    elements.anonNote.addEventListener('click', openProfile);
    elements.profileLifetime.addEventListener('change', onProfileLifetimeChange);
    elements.readReceiptsToggle.addEventListener('change', onReadReceiptsToggle);
    elements.notifyToggle.addEventListener('change', onNotifyToggle);
    elements.profileAboutBtn.addEventListener('click', () => openAboutModal());
    elements.deleteAccountBtn.addEventListener('click', openDeleteAccountModal);
}

// Поле ввода: отправка по кнопке и Enter, Escape (отмена правки и ответа),
// вложения (скрепка, окно «Отправить файлы», перетаскивание), отмена ответа.
function setupComposerListeners() {
    elements.sendBtn.addEventListener('click', sendMessage);
    elements.messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            sendMessage();
        } else if (e.key === 'Escape' && (editingMessageId || replyToMessageId)) {
            cancelEditing();
            clearReply();
        }
    });

    elements.attachBtn.addEventListener('click', () => {
        if (uploadQueue) {
            showToast('Дождитесь окончания загрузки', 'info');
            return;
        }
        elements.fileInput.click();
    });
    elements.fileInput.addEventListener('change', () => {
        const files = Array.from(elements.fileInput.files || []);
        elements.fileInput.value = '';
        onFilesChosen(files);
    });
    elements.sendFilesBtn.addEventListener('click', sendChosenFiles);
    elements.uploadCancelBtn.addEventListener('click', () => cancelUploadQueue(true));
    setupDragAndDrop();
    elements.cancelReplyBtn.addEventListener('click', clearReply);
    elements.botSuggestions.addEventListener('click', onBotSuggestionClick);
}

// Меню сообщения: панель реакций, ответ, копирование, правка, удаление.
function setupMessageMenuListeners() {
    buildReactionPicker();

    elements.replyMessageBtn.addEventListener('click', () => {
        const message = menuMessage;
        hideMessageMenu();
        if (!message) return;
        replyToMessageId = message.id;
        elements.replyPreviewText.textContent = messageSummary(message).substring(0, 100);
        elements.replyPreview.classList.remove('hidden');
        elements.messageInput.focus();
    });

    elements.copyMessageBtn.addEventListener('click', () => {
        const message = menuMessage;
        hideMessageMenu();
        if (message && message.text) copyText(message.text, 'Текст скопирован', 'Не удалось скопировать текст');
    });

    elements.editMessageBtn.addEventListener('click', () => {
        const message = menuMessage;
        hideMessageMenu();
        if (!message) return;
        editingMessageId = message.id;
        elements.messageInput.value = message.text || '';
        elements.messageInput.focus();
    });

    elements.deleteMessageBtn.addEventListener('click', async () => {
        const message = menuMessage;
        hideMessageMenu();
        if (!message) return;
        const data = await api(`/api/messages/${message.id}`, { method: 'DELETE' });
        if (data.success) {
            showToast('Сообщение удалено', 'success');
            removeMessageElement(message.id);
        } else {
            showToast(data.message, 'error');
        }
    });
}

// Поиск по названиям чатов: фильтр на клиенте, без запросов; перерисовка — на
// следующем кадре после ввода. Escape очищает фильтр, стрелка вниз переводит фокус
// на первый чат, Enter открывает первый. Поиск по сообщениям открытого чата — в
// шапке (setupChatSearchListeners).
function setupSearchListeners() {
    let frame = 0;
    elements.searchInput.addEventListener('input', () => {
        if (frame) cancelAnimationFrame(frame);
        frame = requestAnimationFrame(() => {
            frame = 0;
            applyChatFilter();
        });
    });
    elements.searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && elements.searchInput.value) {
            e.preventDefault();
            elements.searchInput.value = '';
            applyChatFilter();
        } else if (e.key === 'ArrowDown' || e.key === 'Enter') {
            const first = elements.chatsList.querySelector('.chat-item');
            if (!first) return;
            e.preventDefault();
            if (e.key === 'Enter') first.click();
            else first.focus();
        }
    });
    setupChatSearchListeners();
}

// Модальные окна: закрытие по крестику и кнопкам «Отмена», по оверлею и
// Escape (а также удержание фокуса внутри окна — onModalKeydown).
function setupModalListeners() {
    document.querySelectorAll('.close-modal, [data-close-modal]').forEach(btn => {
        btn.addEventListener('click', closeAllModals);
    });

    elements.overlay.addEventListener('click', () => {
        closeAllModals();
        hideMessageMenu();
        hideChatItemMenu();
    });

    document.addEventListener('keydown', onModalKeydown);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideMessageMenu();
            hideChatItemMenu();
        }
    });
}

// Лента сообщений: подгрузка истории, отметка «прочитано», кнопка «вниз»,
// ссылка-приглашение, вставленная в уже открытую вкладку.
function setupFeedListeners() {
    // Подгрузка более старых сообщений при прокрутке к началу.
    elements.chatMessages.addEventListener('scroll', () => {
        if (elements.chatMessages.scrollTop < 200) loadOlderMessages();
        if (isNearBottom()) markVisibleMessagesRead();
        updateJumpDown();
    }, { passive: true });
    elements.jumpDown.addEventListener('click', () => scrollToBottom(true));

    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') markVisibleMessagesRead();
        keepaliveOnVisible();
        maintainE2eeKeys();
        onHistoryVisibilityChange(document.visibilityState === 'hidden');
    });
    window.addEventListener('pagehide', forgetOpenRoomOnPageHide);

    // Ссылка-приглашение, вставленная в уже открытую вкладку.
    window.addEventListener('hashchange', consumeJoinFragment);
}

// События сокета: новые, изменённые и удалённые сообщения, прочтение,
// состав комнаты, срок исчезающих сообщений, заявки, список чатов.
function setupSocketListeners() {
    socket.on('newMessage', async (message) => {
        if (!currentUser) return;
        const mine = isOwnMessage(message);
        if (!mine) maybeNotify(message);
        if (belongsToCurrentChat(message.chat_id, message.room_id)) {
            const roomId = currentRoomId;
            const seq = openChatSeq;
            const stickToBottom = mine || isNearBottom();
            await decryptMessageInPlace(message, roomId);
            if (seq !== openChatSeq) return; // пока расшифровывали, открыли другой чат
            if (appendMessage(message, true)) {
                if (stickToBottom) scrollToBottom();
                else if (!mine) bumpJumpDown();
            }
            updateChatListOnMessage(message, true);
            if (!mine) markVisibleMessagesRead();
        } else {
            updateChatListOnMessage(message, false);
        }
    });

    socket.on('messageEdited', async ({ id, text, chat_id, room_id, encrypted }) => {
        if (!belongsToCurrentChat(chat_id, room_id)) return;
        const roomId = currentRoomId;
        const seq = openChatSeq;
        let displayText = text;
        let failed = false;
        if (roomId && !encrypted) {
            // Правка без шифрования в комнате: так не бывает, текст не показываем.
            displayText = e2eeFailureText('not-encrypted');
            failed = true;
        } else if (encrypted) {
            const res = await decryptEnvelope(roomId, null, text, id);
            displayText = decryptedSummary(res);
            failed = !res.ok;
        }
        if (seq !== openChatSeq) return;
        applyMessageEdit(id, displayText, failed);
        scheduleLoadChats();
    });

    // Удаление теперь физическое (DELETE на сервере): элемент убирается
    // целиком, а цитаты на него в других сообщениях становятся "удалено".
    socket.on('messageDeleted', ({ id, chat_id, room_id }) => {
        if (belongsToCurrentChat(chat_id, room_id)) removeMessageElement(id);
        scheduleLoadChats();
    });

    // Сервер больше не сообщает, КТО прочитал (reader_id убран), — только
    // до какого сообщения; самому читателю событие не шлётся. Раньше
    // проверка reader_id !== currentUser.id отсекала своё же чтение — теперь
    // это делает сервер.
    socket.on('messagesRead', ({ chat_id, room_id, up_to_seq } = {}) => {
        if (!belongsToCurrentChat(chat_id, room_id)) return;
        const upTo = Number(up_to_seq);
        if (!upTo) return;
        elements.chatMessages.querySelectorAll('.message.sent').forEach((el) => {
            if (el.dataset.seq !== undefined && Number(el.dataset.seq) <= upTo) {
                if (el._message) el._message.status = 'read';
                renderMessageStatus(el);
            }
        });
    });

    // Состав комнаты изменился (вступление по коду, одобренная заявка,
    // выход): забираем новые key-share и пересобираем сессию — новому
    // участнику уходит наш Sender Key, после ухода свой ключ ротируется.
    socket.on('roomMembersChanged', ({ roomId, inviteRotated } = {}) => {
        if (!currentUser || !roomId) return;
        // Решение владельца (signed-membership.md, вопрос 17): при выходе любого участника подписанное приглашение
        // сервер обнуляет и выдаёт новый код; новую подписанную ссылку создаёт следующий, кто нажмёт «Пригласить».
        if (inviteRotated === true && Number(roomId) === Number(currentRoomId)) {
            appendSystemNotice(roomId, 'Ссылка-приглашение обновлена: участник вышел из группы', 'link');
            if (inviteState) inviteState = { ...inviteState, signed: false, linkSecret: null };
        }
        scheduleRoomMembersRefresh(roomId);
        scheduleLoadChats(); // число участников в списке и в шапке
    });

    // Таймер исчезающих сообщений общий на комнату: его мог сменить любой
    // участник — в ленте остаётся служебная строка, как в Signal.
    socket.on('chatExpiryChanged', ({ roomId, chatId, seconds } = {}) => {
        if (!currentUser) return;
        const value = normalizeExpiry(seconds);
        const meta = findChatMeta(chatId, roomId);
        if (meta) meta.expiry_seconds = value;
        if (roomId) syncRoomKeyPolicy(roomId, value);
        renderChatList();
        if (!belongsToCurrentChat(chatId, roomId)) return;
        if (!meta) currentChatExtra.expiry_seconds = value;
        updateChatIndicators();
        syncExpiryRadios();
        appendChatNotice(value ? `Исчезающие сообщения: ${EXPIRY_LABELS[value]}` : 'Исчезающие сообщения выключены', 'timer');
    });

    socket.on('joinRequestsChanged', ({ roomId } = {}) => {
        if (!currentUser || !roomId || Number(roomId) !== Number(currentRoomId)) return;
        loadJoinRequestsCount();
        if (!elements.requestsModal.classList.contains('hidden')) loadRequestsList();
    });

    // approved:false приходит не только при отказе, но и когда заявка
    // пропала сама (группу удалили, истёк срок заявки) — текст нейтральный.
    socket.on('joinRequestDecided', ({ requestId, approved, chat } = {}) => {
        if (!currentUser) return;
        const roomName = myRequestNames.get(String(requestId));
        myRequestNames.delete(String(requestId));
        if (!elements.newChatModal.classList.contains('hidden')) loadMyRequests();
        if (!approved) {
            showToast(`Заявку${roomName ? ` в «${roomName}»` : ''} не приняли: её отклонили или она больше не действует`, 'info', 6000);
            return;
        }
        const name = chat && chat.name ? `«${chat.name}»` : '';
        showToast(`Заявку одобрили — вы в группе ${name}`.trim(), 'success', 5000);
        loadChats();
        if (chat && chat.id) {
            closeModal(elements.newChatModal);
            openChat(chat.id, chat.room_id, chat.name, chat.avatar, chat.online, chat.is_bot);
        }
    });

    // Закрепление/архив/звук сменили в другой вкладке.
    socket.on('chatListChanged', () => {
        if (currentUser) scheduleLoadChats();
    });
}

// Всплывающие меню (сообщения и элемента списка чатов) закрываются кликом
// мимо, прокруткой и изменением размера окна.
function setupMenuDismissListeners() {
    document.addEventListener('click', onDocumentClickForMenus);
    document.addEventListener('scroll', () => {
        hideMessageMenu();
        hideChatItemMenu();
    }, true);
    window.addEventListener('resize', () => {
        hideMessageMenu();
        hideChatItemMenu();
    });
}

// ==================== Модальные окна ====================

let modalReturnFocus = null;

function isFocusable(el) {
    return !el.disabled && el.offsetParent !== null;
}

// Фокус при открытии окна: элемент с data-autofocus, иначе первое видимое
// текстовое поле, иначе первая кнопка окна, иначе "закрыть" (скрытые
// элементы пропускаются).
function initialFocusTarget(modal) {
    const groups = ['[data-autofocus]', '.modal-body input:not([type="checkbox"]):not([type="radio"]):not([type="number"])', '.modal-body button', '.close-modal'];
    for (const selector of groups) {
        const found = Array.from(modal.querySelectorAll(selector)).find(isFocusable);
        if (found) return found;
    }
    return null;
}

function openModal(modal) {
    if (!document.querySelector('.modal:not(.hidden)')) modalReturnFocus = document.activeElement;
    modal.classList.remove('hidden');
    elements.overlay.classList.remove('hidden');
    const focusTarget = initialFocusTarget(modal);
    if (focusTarget) focusTarget.focus({ preventScroll: true });
}

function closeModal(modal) {
    modal.classList.add('hidden');
    if (!document.querySelector('.modal:not(.hidden)')) {
        elements.overlay.classList.add('hidden');
        const target = modalReturnFocus;
        modalReturnFocus = null;
        if (target && target.isConnected && typeof target.focus === 'function') target.focus({ preventScroll: true });
    }
}

function closeAllModals() {
    document.querySelectorAll('.modal:not(.hidden)').forEach(m => closeModal(m));
}

// Escape закрывает окно, Tab не уводит фокус из открытого окна за оверлей.
function onModalKeydown(e) {
    const open = document.querySelectorAll('.modal:not(.hidden)');
    if (open.length === 0) return;
    const modal = open[open.length - 1];
    if (e.key === 'Escape') {
        e.preventDefault();
        closeAllModals();
        return;
    }
    if (e.key !== 'Tab') return;
    const focusables = Array.from(modal.querySelectorAll('button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])'))
        .filter(isFocusable);
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (!modal.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
    } else if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
    }
}

// ==================== Профиль, срок хранения, удаление аккаунта ====================

// Аватар в монохроме — буква на нейтральном фоне (цвет задаёт тема, не
// пользователь), у бота — иконка.
function renderAvatar(el, name, isBot) {
    if (isBot) {
        el.replaceChildren(icon('bot'));
        return;
    }
    el.textContent = (String(name || '').trim().charAt(0) || '?').toUpperCase();
}

// Профиль рисуется из currentUser — его держит свежим pingSession (ответ
// /api/auth), отдельный запрос за профилем не нужен. Открытие профиля —
// тоже повод сверить срок и дату удаления с сервером.
function openProfile() {
    if (!currentUser) return;
    elements.profileUsername.textContent = currentUser.username || '';
    renderAvatar(elements.profileAvatar, currentUser.username, false);
    renderProfileLifetime();
    elements.readReceiptsToggle.checked = readReceiptsEnabled();
    elements.notifyToggle.checked = isNotifyEnabled();
    refreshThemeButtons();
    openModal(elements.profileModal);
    pingSession();
}

// «Сколько хранить аккаунт» в профиле: выбранный срок и статус «удалится,
// если не заходить до …» (для tab — «через 30 минут после закрытия
// последней вкладки»).
function renderProfileLifetime() {
    if (!currentUser) return;
    const lifetime = lifetimeWanted || currentUser.anonLifetime;
    elements.profileLifetime.querySelectorAll('input[name="profile-lifetime"]').forEach((radio) => {
        radio.checked = radio.value === lifetime;
    });
    elements.profileLifetimeStatus.textContent = NyxoLifetime.lifetimeStatus(currentUser, new Date());
}

// «Пока открыта вкладка» → «пока открыта вкладка» для середины фразы.
function lifetimeLabelInline(lifetime) {
    const label = NyxoLifetime.LIFETIME_LABELS[lifetime] || '';
    return label.charAt(0).toLowerCase() + label.slice(1);
}

// Смена срока: POST /api/user/lifetime. Сервер пересоздаёт сессию (новый
// sid и кука с новым сроком), поэтому после успеха сокет переподключается —
// старое рукопожатие держится за прежнюю сессию. Без подтверждения, как у
// отметок о прочтении. Пока запрос в пути, выбор не блокируется (иначе
// клавиатурный фокус слетел бы с radio): последний выбор запоминается и
// отправляется следом. Ошибка откатывает выбор к тому, что знает сервер.
let lifetimeRequest = null;
let lifetimeWanted = null;

function changeLifetime(lifetime) {
    if (!currentUser || !NyxoLifetime.isLifetime(lifetime)) return Promise.resolve(false);
    lifetimeWanted = lifetime;
    if (lifetimeRequest) return lifetimeRequest;
    const userId = currentUser.id;
    elements.profileLifetime.setAttribute('aria-busy', 'true');
    lifetimeRequest = (async () => {
        let ok = true;
        while (isCurrentUser(userId) && lifetimeWanted && lifetimeWanted !== currentUser.anonLifetime) {
            const target = lifetimeWanted;
            const data = await api('/api/user/lifetime', { method: 'POST', body: JSON.stringify({ lifetime: target }) });
            if (!isCurrentUser(userId)) return false;
            if (!data.success) {
                ok = false;
                lifetimeWanted = null;
                showToast(data.message || 'Не удалось сменить срок хранения', 'error');
                break;
            }
            // Следующий круг — только если за время запроса выбрали другой срок.
            if (lifetimeWanted === target) lifetimeWanted = null;
            currentUser.anonLifetime = NyxoLifetime.isLifetime(data.anonLifetime) ? data.anonLifetime : target;
            if ('anonExpiresAt' in data) currentUser.anonExpiresAt = data.anonExpiresAt;
            if (typeof data.anonInactivitySeconds === 'number') currentUser.anonInactivitySeconds = data.anonInactivitySeconds;
            reconnectSocket();
            onLifetimeChanged();
            postSessionEvent({ type: 'lifetime-changed', userId, anonLifetime: currentUser.anonLifetime });
            showToast(`Срок хранения: ${lifetimeLabelInline(currentUser.anonLifetime)}`, 'success');
        }
        return ok;
    })().finally(() => {
        lifetimeRequest = null;
        lifetimeWanted = null;
        elements.profileLifetime.removeAttribute('aria-busy');
        renderProfileLifetime();
    });
    return lifetimeRequest;
}

// Срок поменялся (здесь или в соседней вкладке): заметка в сайдбаре,
// статус в профиле.
function onLifetimeChanged() {
    updateAnonNote();
    renderProfileLifetime();
    // Совет «не закрывайте вкладку» на карточках заявок зависит от срока.
    if (!elements.newChatModal.classList.contains('hidden')) loadMyRequests();
}

function onProfileLifetimeChange(e) {
    const radio = e.target;
    if (!radio || radio.name !== 'profile-lifetime' || !radio.checked) return;
    changeLifetime(radio.value);
}

// Новое рукопожатие сокета с актуальной кукой сессии.
function reconnectSocket() {
    if (!currentUser) return;
    if (socket.connected) socket.disconnect();
    socket.connect();
}

// ---- Уведомления ----
// Согласие хранится на устройстве (по умолчанию выключено). Уведомление
// никогда не содержит текста и имени отправителя: его видит ОС, центр
// уведомлений и всё, что с ним синхронизируется.

function notifyPrefKey() {
    return NOTIFY_PREF_PREFIX + (currentUser ? currentUser.id : '0');
}

function notificationsSupported() {
    return typeof window.Notification === 'function';
}

function isNotifyEnabled() {
    if (!notificationsSupported()) return false;
    try {
        return localStorage.getItem(notifyPrefKey()) === '1' && Notification.permission === 'granted';
    } catch {
        return false;
    }
}

function setNotifyPref(enabled) {
    try {
        if (enabled) localStorage.setItem(notifyPrefKey(), '1');
        else localStorage.removeItem(notifyPrefKey());
    } catch { /* хранилище недоступно — настройка не запомнится */ }
}

async function onNotifyToggle() {
    const toggle = elements.notifyToggle;
    if (!toggle.checked) {
        setNotifyPref(false);
        showToast('Уведомления выключены', 'info');
        return;
    }
    if (!notificationsSupported()) {
        toggle.checked = false;
        showToast('Этот браузер не поддерживает уведомления', 'error');
        return;
    }
    let permission = 'default';
    try {
        permission = Notification.permission;
        if (permission !== 'granted') permission = await Notification.requestPermission();
    } catch {
        permission = 'denied';
    }
    if (permission !== 'granted') {
        toggle.checked = false;
        setNotifyPref(false);
        showToast('Браузер не разрешил уведомления — разрешите их в настройках сайта', 'error', 5000);
        return;
    }
    setNotifyPref(true);
    showToast('Уведомления включены', 'success');
}

function maybeNotify(message) {
    if (document.visibilityState !== 'hidden' || !isNotifyEnabled()) return;
    const meta = findChatMeta(message.chat_id, message.room_id);
    if (meta && meta.muted) return;
    const tag = message.room_id ? `nyxo-room-${message.room_id}` : `nyxo-chat-${message.chat_id}`;
    try {
        // tag — одно уведомление на чат: новые заменяют старое, а не копятся.
        const notification = new Notification('Nyxo — новое сообщение', {
            tag,
            icon: 'icons/icon-192.png',
            badge: 'icons/icon-192.png',
        });
        notification.onclick = () => {
            try { window.focus(); } catch { /* окно могло закрыться */ }
            notification.close();
            if (meta) openChatFromMeta(meta);
        };
    } catch { /* например, мобильный Chrome без service worker — просто без уведомления */ }
}

// Отметки о прочтении по умолчанию выключены (4.2): включены, только если
// сервер прямо сказал readReceipts === true. Неизвестное значение (ответ
// без поля, сервер другой версии) — выключены.
function readReceiptsEnabled() {
    return Boolean(currentUser && currentUser.readReceipts === true);
}

async function onReadReceiptsToggle() {
    const toggle = elements.readReceiptsToggle;
    const desired = toggle.checked;
    toggle.disabled = true;
    const data = await api('/api/user/privacy', {
        method: 'POST',
        body: JSON.stringify({ readReceipts: desired }),
    });
    toggle.disabled = false;
    if (!data.success) {
        toggle.checked = !desired;
        showToast(data.message || 'Не удалось сохранить настройку', 'error');
        return;
    }
    const value = typeof data.readReceipts === 'boolean' ? data.readReceipts : desired;
    if (currentUser) currentUser.readReceipts = value;
    toggle.checked = value;
    refreshOwnMessageStatuses();
    showToast(value
        ? 'Отметки о прочтении включены'
        : 'Отметки о прочтении выключены — вы тоже не будете видеть, что ваши сообщения прочитаны', 'success', 5000);
}

// «Удалить и выйти» — одна кнопка в сайдбаре и «Удалить аккаунт и выйти»
// в профиле, одно подтверждение (alertdialog, фокус на «Отмена»). Подсказка
// под предупреждением — как уйти, НЕ удаляя аккаунт (зависит от срока).
function openDeleteAccountModal() {
    if (!currentUser) return;
    const alt = NyxoLifetime.leaveAlternative(currentUser.anonLifetime);
    elements.deleteAccountAlt.textContent = alt;
    elements.deleteAccountAlt.classList.toggle('hidden', !alt);
    showDeleteAccountError('');
    closeAllModals();
    openModal(elements.deleteAccountModal);
}

function showDeleteAccountError(text) {
    elements.deleteAccountError.textContent = text;
    elements.deleteAccountError.classList.toggle('hidden', !text);
}

// Аккаунт удалён — стираем локальные данные и перезагружаемся с
// уведомлением. Не удалён (нет сети, ошибка сервера) — локальные ключи НЕ
// трогаем: иначе живой аккаунт остался бы на сервере без ключей.
let deletingAccount = false;
async function deleteAccountAndLeave() {
    if (deletingAccount || !currentUser) return;
    deletingAccount = true;
    const userId = currentUser.id;
    const btn = elements.confirmDeleteAccountBtn;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    showDeleteAccountError('');
    let gone = false;
    let failure = '';
    const data = await api('/api/account/delete', { method: 'POST', body: '{}', skipAuthCheck: true });
    if (data.success) {
        gone = true;
    } else if (data.message === 'Не авторизован' || data.message === 'Пользователь не найден') {
        // Сессии уже нет — проверяем, что аккаунта действительно нет, а не
        // запрос ушёл со старой кукой (пока сервер пересоздавал сессию).
        const state = await fetchAuthState();
        if (state && !state.authenticated) gone = true;
        else failure = state ? 'Не удалось удалить аккаунт. Попробуйте ещё раз.' : 'Нет связи с сервером — аккаунт не удалён. Попробуйте ещё раз.';
    } else if (data.networkError) {
        failure = 'Нет связи с сервером — аккаунт не удалён. Попробуйте ещё раз.';
    } else {
        failure = `${String(data.message || 'Не удалось удалить аккаунт').replace(/[.!]+$/, '')}. Аккаунт не удалён — попробуйте ещё раз.`;
    }
    deletingAccount = false;
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    if (!isCurrentUser(userId)) return;
    if (gone) {
        postSessionEvent({ type: 'account-deleted', userId });
        leaveApp(AUTH_NOTICES.deleted);
        return;
    }
    showDeleteAccountError(failure);
}

// ==================== Экран входа и тема ====================
// Аккаунт только временный: без почты и номера телефона, с выбранным
// сроком хранения. Экран один: выбор срока, «Начать анонимно» и, если есть,
// приглашение в группу (ссылка или код). Формат приглашения проверяется ДО
// PoW: битый код не должен стоить человеку проверки и лишнего аккаунта.
// Ход проверки и ошибки остаются на экране (#auth-progress), а не только в
// тосте: тост исчезает, пока человек смотрит на кнопку.

// Почему человек снова видит экран входа (#auth-notice).
const AUTH_NOTICES = {
    deleted: 'Аккаунт удалён. Данные на этом устройстве стёрты.',
    deletedElsewhere: 'Аккаунт удалён в другой вкладке.',
    expired: 'Прежний аккаунт удалён: вы не заходили дольше выбранного срока.',
    sessionLost: 'Вход в аккаунт потерян: аккаунт удалён или сессия закончилась. Данные на этом устройстве стёрты.',
    otherAccount: 'В соседней вкладке открыт другой аккаунт. Данные прежнего на этом устройстве стёрты.',
    noCookies: 'Браузер не сохранил cookie — без неё аккаунт не работает. Разрешите cookie для этого сайта.',
};

const AUTH_POW_PROGRESS = 'Создаём аккаунт: проверка, что вы не бот. Обычно несколько секунд, в Tor Browser — дольше.';
const INVITE_FORMAT_ERROR = 'Не похоже на код приглашения. Нужна ссылка вида …/#join=… или 26 символов (буквы и цифры 2–9).';
const INVITE_EMPTY_ERROR = 'Вставьте ссылку-приглашение или код.';

let authBusy = false;
let authInviteMode = false;
let registrationCancelled = false;   // аккаунт появился в соседней вкладке, пока считался PoW

function selectedAuthLifetime() {
    const checked = elements.authLifetime.querySelector('input[name="auth-lifetime"]:checked');
    return checked && NyxoLifetime.isLifetime(checked.value) ? checked.value : NyxoLifetime.DEFAULT_LIFETIME;
}

function updateAuthLifetimeDetail() {
    elements.authLifetimeDetail.textContent = NyxoLifetime.lifetimeDetail(selectedAuthLifetime());
    updateAuthInviteAdvice();
}

// Совет для срока «Пока открыта вкладка» в режиме приглашения: заявка в
// группу удаляется вместе с аккаунтом, а одобрения можно ждать долго.
function updateAuthInviteAdvice() {
    const text = authInviteMode ? NyxoLifetime.inviteTabWarning(selectedAuthLifetime(), false) : '';
    elements.authInviteAdvice.textContent = text;
    elements.authInviteAdvice.classList.toggle('hidden', !text);
}

// Подпись кнопки — в её <span>: иконки рядом остаются на месте.
function setButtonText(btn, text) {
    const span = btn.querySelector('span');
    if (span) span.textContent = text;
    else btn.textContent = text;
}

// Режим «У меня есть приглашение»: поле ссылки или кода над выбором срока.
// value — подставить в поле (ссылка #join=), error — сразу показать ошибку.
function setInviteMode(on, { value = null, focus = false, error = null } = {}) {
    authInviteMode = Boolean(on);
    elements.authInvite.classList.toggle('hidden', !authInviteMode);
    elements.inviteToggleBtn.setAttribute('aria-expanded', authInviteMode ? 'true' : 'false');
    setButtonText(elements.inviteToggleBtn, authInviteMode ? 'Без приглашения' : 'У меня есть приглашение');
    setButtonText(elements.anonStartBtn, authInviteMode ? 'Создать аккаунт и открыть приглашение' : 'Начать анонимно');
    if (value !== null) elements.authInviteInput.value = value;
    if (error) showInviteError(error);
    else if (!authInviteMode || value !== null) clearInviteError();
    updateAuthInviteAdvice();
    if (focus && authInviteMode) elements.authInviteInput.focus();
}

function showInviteError(text) {
    elements.authInviteError.textContent = text;
    elements.authInviteError.classList.remove('hidden');
    elements.authInviteInput.setAttribute('aria-invalid', 'true');
}

function clearInviteError() {
    elements.authInviteError.textContent = '';
    elements.authInviteError.classList.add('hidden');
    elements.authInviteInput.removeAttribute('aria-invalid');
}

function setAuthProgress(text, { error = false } = {}) {
    const el = elements.authProgress;
    el.classList.toggle('is-error', Boolean(text) && error);
    if (!text) {
        el.replaceChildren();
        return;
    }
    const span = document.createElement('span');
    span.textContent = text;
    el.replaceChildren(error ? icon('alert-triangle', { size: 'sm' }) : icon('loader', { size: 'sm', className: 'spin' }), span);
}

function showAuthNotice(text) {
    elements.authNotice.textContent = text || '';
    elements.authNotice.classList.toggle('hidden', !text);
}

// Пока создаётся аккаунт, выбор срока и приглашение заблокированы: двойной
// клик и повторный Enter не запускают вторую проверку.
function setAuthBusy(busy) {
    authBusy = busy;
    elements.authLifetime.disabled = busy;
    elements.inviteToggleBtn.disabled = busy;
    elements.authInviteInput.readOnly = busy;
    elements.anonStartBtn.disabled = busy;
}

// GET /api/auth — единый источник состояния аккаунта (он же продлевает
// сессию). null — сервер недоступен или ответил не JSON: тогда ничего не
// решаем и ничего не стираем.
async function fetchAuthState() {
    let data;
    try {
        const res = await fetch('/api/auth', { cache: 'no-store' });
        data = await res.json();
    } catch {
        return null;
    }
    if (!data || typeof data !== 'object' || typeof data.authenticated !== 'boolean') return null;
    lastAuthAt = Date.now();
    if ('onionUrl' in data) applyOnionUrl(data.onionUrl);
    return data;
}

async function startAccount() {
    if (authBusy || currentUser) return;
    let invite = null;
    if (authInviteMode) {
        const parsed = NyxoInvite.parseInviteInput(elements.authInviteInput.value);
        if (!parsed.ok) {
            showInviteError(parsed.reason === 'empty' ? INVITE_EMPTY_ERROR : INVITE_FORMAT_ERROR);
            elements.authInviteInput.focus();
            return;
        }
        clearInviteError();
        invite = { code: parsed.code, secret: parsed.secret };
    }
    const lifetime = selectedAuthLifetime();
    const btn = elements.anonStartBtn;
    registrationCancelled = false;
    setAuthBusy(true);
    setAuthProgress('');
    let entered = false;
    const enter = (user) => {
        entered = true;
        pendingJoin = invite;
        pendingJoinBroken = false;
        enterApp(user);
        // Другие вкладки на экране входа подхватят аккаунт, остальные
        // сверят, не сменилась ли кука на чужой аккаунт.
        postSessionEvent({ type: 'session-started', userId: user.id });
    };
    try {
        // Аккаунт уже создан (в соседней вкладке или до перезагрузки) —
        // входим в него, второй не создаём.
        const before = await fetchAuthState();
        if (currentUser) return;
        if (before && before.authenticated && before.user) {
            enter(before.user);
            return;
        }

        setAuthProgress(AUTH_POW_PROGRESS);
        const data = await postWithPow('/api/register/anonymous', { lifetime }, 'register-anon', btn, {
            isCancelled: () => registrationCancelled || Boolean(currentUser),
        });
        // postWithPow разблокирует кнопку сам; держим её выключенной до конца.
        btn.disabled = true;
        if (registrationCancelled || currentUser || (data && data.cancelled)) return;

        if (data && data.code === 'already-authenticated') {
            // 409: живая сессия есть (её не было видно при первой проверке) — входим в неё.
            const state = await fetchAuthState();
            if (currentUser) return;
            if (state && state.authenticated && state.user) {
                enter(state.user);
                return;
            }
            setAuthProgress(data.message || 'Вы уже вошли в аккаунт. Обновите страницу.', { error: true });
            return;
        }
        if (!data || !data.success || !data.user) {
            setAuthProgress((data && data.message) || 'Не удалось создать аккаунт. Попробуйте ещё раз.', { error: true });
            return;
        }

        // Ответ регистрации поставил куку сессии. Если /api/auth её не видит,
        // браузер cookie не сохранил: аккаунт без неё недоступен, а уход на
        // экран входа зациклил бы попытки — просто объясняем, что случилось.
        const state = await fetchAuthState();
        if (currentUser) return;
        if (state && !state.authenticated) {
            setAuthProgress('');
            showAuthNotice(AUTH_NOTICES.noCookies);
            return;
        }
        const user = state && state.authenticated && state.user ? state.user : { anonLifetime: lifetime, ...data.user };
        rememberBotChatId(user.id, data.botChatId);
        enter(user);
    } finally {
        setAuthBusy(false);
        if (entered) setAuthProgress('');
    }
}

// Окно «Как это работает»: с экрана входа и из профиля. section 'tor' —
// сразу к разделу про IP и onion-адрес (ссылка «Открыть через Tor»).
function openAboutModal(section) {
    closeAllModals();
    openModal(elements.aboutModal);
    if (section === 'tor') {
        elements.aboutTor.focus({ preventScroll: true });
        elements.aboutTor.scrollIntoView({ block: 'start', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    }
}

// Onion-адрес приходит полем onionUrl в /api/auth: заголовок Onion-Location
// скрипт прочитать не может, а шаблонизировать index.html нельзя. Ссылка
// «Открыть через Tor» показывается только для проверенного v3-адреса (иначе
// её нет вовсе) и не ведёт прямо на onion: в обычном браузере такая ссылка
// не откроется — она открывает раздел про Tor с адресом и «Скопировать».
let onionUrl = null;

function applyOnionUrl(value) {
    onionUrl = NyxoInvite.parseOnionUrl(value);
    const onOnion = /\.onion$/i.test(location.hostname);
    const show = Boolean(onionUrl) && !onOnion;
    elements.onionOpenBtn.classList.toggle('hidden', !show);
    elements.authLinksSep.classList.toggle('hidden', !show);
    elements.aboutOnion.classList.toggle('hidden', !show);
    elements.aboutOnionMissing.classList.toggle('hidden', show || onOnion);
    elements.aboutOnionCurrent.classList.toggle('hidden', !onOnion);
    elements.aboutOnionAddress.textContent = show ? onionUrl : '';
    if (show) elements.aboutOnionLink.href = onionUrl;
    else elements.aboutOnionLink.removeAttribute('href');
}

// Тема — через window.NyxoTheme (public/theme.js). Кнопка показывает, КУДА
// переключит: в тёмной теме — солнце, в светлой — луна.
function currentTheme() {
    try {
        if (window.NyxoTheme && typeof window.NyxoTheme.get === 'function') return window.NyxoTheme.get();
    } catch { /* ниже — по атрибуту */ }
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function refreshThemeButtons() {
    const dark = currentTheme() !== 'light';
    const label = dark ? 'Светлая тема' : 'Тёмная тема';
    const iconName = dark ? 'sun' : 'moon';
    const hasApi = Boolean(window.NyxoTheme);
    // Кнопки-иконки: в сайдбаре и в углу экрана входа.
    for (const btn of [elements.themeToggleBtn, elements.authThemeBtn]) {
        btn.replaceChildren(icon(iconName));
        btn.title = `Включить: ${label.toLowerCase()}`;
        btn.setAttribute('aria-label', `Включить ${label.toLowerCase()}`);
        btn.classList.toggle('hidden', !hasApi);
    }
    setIconLabel(elements.profileThemeBtn, iconName, label);
    elements.profileThemeBtn.classList.toggle('hidden', !hasApi);
}

function toggleTheme() {
    try {
        if (window.NyxoTheme && typeof window.NyxoTheme.toggle === 'function') window.NyxoTheme.toggle();
    } catch (err) {
        console.warn('Не удалось сменить тему:', err);
    }
    refreshThemeButtons();
}

function setupThemeControls() {
    elements.themeToggleBtn.addEventListener('click', toggleTheme);
    elements.authThemeBtn.addEventListener('click', toggleTheme);
    elements.profileThemeBtn.addEventListener('click', toggleTheme);
    // Тему может сменить и сама система (если выбор не сохранён), и другая
    // вкладка — следим за атрибутом, а не за своими кликами.
    if (typeof MutationObserver === 'function') {
        new MutationObserver(refreshThemeButtons).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    }
    refreshThemeButtons();
}

// ==================== Приглашения ====================
// Код показывается группами по 5 символов (NyxoInvite.formatInviteCode) —
// его диктуют и переписывают вручную; сервер при вводе убирает пробелы и
// дефисы сам.

// Ссылка-приглашение: код во фрагменте — он не уходит на сервер ни при
// открытии ссылки, ни в Referer (см. consumeJoinFragment).
// С секретом (22 символа base64url, signed-membership.md, 5.3) ссылка впускает без одобрения; без него - только заявка.
function inviteLink(code, secret) {
    return `${location.origin}/#join=${encodeURIComponent(code)}${secret ? `.${secret}` : ''}`;
}

async function copyText(text, okMessage, failMessage) {
    try {
        await navigator.clipboard.writeText(text);
        showToast(okMessage, 'success');
    } catch {
        showToast(failMessage, 'error');
    }
}

// QR рисуется на <canvas> по модулям (qrcode-generator: getModuleCount/
// isDark) — без createSvgTag/createImgTag и innerHTML. Белый фон и чёрные
// модули в обеих темах: так его читает любой сканер. Тихая зона — 4
// модуля (минимум по стандарту), уровень коррекции M.
const QR_QUIET_ZONE = 4;
const QR_TARGET_PX = 240;

function drawInviteQr(text) {
    const canvas = elements.inviteQrCanvas;
    const ctx = canvas.getContext && canvas.getContext('2d');
    if (!ctx || typeof qrcode !== 'function' || !text) return false;
    let qr;
    try {
        qr = qrcode(0, 'M');
        qr.addData(text);
        qr.make();
    } catch (err) {
        console.warn('QR: не удалось построить код:', err);
        return false;
    }
    const count = qr.getModuleCount();
    const total = count + QR_QUIET_ZONE * 2;
    const dpr = Math.min(Math.max(window.devicePixelRatio || 1, 1), 3);
    const cell = Math.max(2, Math.floor((QR_TARGET_PX * dpr) / total));
    const size = total * cell;
    canvas.width = size;
    canvas.height = size;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';
    for (let row = 0; row < count; row++) {
        for (let col = 0; col < count; col++) {
            if (qr.isDark(row, col)) ctx.fillRect((col + QR_QUIET_ZONE) * cell, (row + QR_QUIET_ZONE) * cell, cell, cell);
        }
    }
    return true;
}

function clearInviteQr() {
    const canvas = elements.inviteQrCanvas;
    canvas.width = 0;
    canvas.height = 0;
}

let inviteState = null;   // последний ответ сервера по приглашению открытой комнаты

function inviteStatusLine(iconName, text) {
    return iconText('p', 'invite-status-line', iconName, text, { size: 'sm' });
}

function renderInvite(state) {
    inviteState = state;
    const rawCode = String(state.code || '').replace(/[\s-]+/g, '');
    const expiry = parseDate(state.expiresAt);
    const disabled = state.disabled === true || !rawCode;
    const expired = !disabled && (state.expired === true || Boolean(expiry && expiry.getTime() <= Date.now()));
    const usable = !disabled && !expired;

    elements.inviteCodeDisplay.textContent = disabled ? 'Приглашение выключено' : NyxoInvite.formatInviteCode(rawCode);
    elements.inviteCodeDisplay.dataset.code = usable ? rawCode : '';
    elements.inviteCodeContainer.classList.toggle('expired', !usable);
    elements.copyInviteBtn.disabled = !usable;
    elements.copyInviteLinkBtn.disabled = !usable;
    elements.disableInviteBtn.disabled = disabled;

    const linkSecret = usable && state.signed !== false ? (state.linkSecret || null) : null;
    elements.inviteCodeDisplay.dataset.secret = linkSecret || '';
    const shown = usable && drawInviteQr(inviteLink(rawCode, linkSecret));
    if (!shown) clearInviteQr();
    elements.inviteQr.classList.toggle('hidden', !shown);

    const lines = [];
    if (disabled) lines.push(inviteStatusLine('x', 'Приглашение выключено — создайте новый код, чтобы снова звать людей'));
    else if (expired) lines.push(inviteStatusLine('hourglass', 'Код истёк — создайте новый'));
    else if (expiry) lines.push(inviteStatusLine('clock', `Действует до ${formatShortDateTime(expiry)}`));
    const members = Number(state.memberCount);
    const max = Number(state.maxMembers);
    if (Number.isFinite(members) && members > 0) {
        lines.push(inviteStatusLine('users', max > 0 ? `Участников: ${members} из ${max}` : `Участников: ${members}`));
    }
    if (!disabled && state.requireApproval !== false) lines.push(inviteStatusLine('shield-check', 'Вступление — с одобрением участников'));
    else if (!disabled) {
        lines.push(inviteStatusLine('unlock', 'Ссылка с секретом впускает сразу; код без ссылки отправляет заявку'));
        if (state.inviter) lines.push(inviteStatusLine('shield-check', `Приглашение подписано участником ${state.inviter}`));
        else if (state.signed === false) lines.push(inviteStatusLine('alert-triangle', 'Подписанной ссылки нет: нажмите «Создать новый код», чтобы получить ссылку, которая впускает сразу'));
        else if (!linkSecret) lines.push(inviteStatusLine('alert-triangle', 'Секрет ссылки есть только на устройстве, где она создана: здесь ссылка и QR впускают лишь через заявку. Создайте новый код, чтобы получить свою ссылку'));
    }
    elements.inviteStatus.replaceChildren(...lines);
    elements.inviteStatus.classList.toggle('expired', !usable);

    // Настройки нового кода по умолчанию — как у текущего.
    elements.inviteApproval.checked = state.requireApproval !== false;
    elements.inviteMax.value = max > 0 ? String(max) : '';
}

async function openInviteModal() {
    if (!currentChatId || !currentRoomId) return;
    const chatId = currentChatId;
    const data = await api(`/api/chats/invite/${chatId}`);
    if (!data.success) {
        showToast(data.message, 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    elements.inviteTtl.value = '604800';
    const signing = await loadInviteSigning(chatId, currentRoomId);
    if (chatId !== currentChatId) return;
    renderInvite({ ...data, ...signing });
    openModal(elements.inviteModal);
}

// Подписанное приглашение комнаты (signed-membership.md, 9.3): кто его подписал (проверяется по подписям) и секрет ссылки, если он
// создан на этом устройстве и сертификат на сервере тот же. Сбой не мешает показать код.
async function loadInviteSigning(chatId, roomId) {
    const result = { linkSecret: null, inviter: null };
    try {
        const [part, client] = await Promise.all([api(`/api/chats/${chatId}/participants`), getReadyE2eeClient()]);
        if (!part.success) return result;
        rememberRoomParticipants(roomId, part.participants);
        if (client) result.linkSecret = await client.getInviteSecret(roomId, part.invite || null);
        if (part.invite) {
            const parsed = NyxoMembership.parseCert(NyxoMembership.fromB64(part.invite) || new Uint8Array(0));
            if (parsed.ok && parsed.cert.kind === NyxoMembership.KIND.invite && (await NyxoMembership.verifyCertSignatures(parsed.cert)).ok) {
                result.inviter = memberLabel(roomId, parsed.cert.actorId);
            }
        }
    } catch (err) {
        console.warn('E2EE: подпись приглашения не прочитана:', err);
    }
    return result;
}

// Лимит участников из поля: пусто — без лимита; иначе целое 2..1000.
function readInviteMaxMembers() {
    const raw = elements.inviteMax.value.trim();
    if (!raw) return { ok: true, value: null };
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 2 || n > 1000) return { ok: false };
    return { ok: true, value: n };
}

async function rotateInviteCode() {
    if (!currentChatId || elements.rotateInviteBtn.disabled) return;
    const max = readInviteMaxMembers();
    if (!max.ok) {
        showToast('Лимит участников — целое число от 2 до 1000 или пусто', 'error');
        elements.inviteMax.focus();
        return;
    }
    const hadCode = Boolean(inviteState && inviteState.code && !inviteState.disabled);
    if (hadCode && !confirm('Создать новый код? Старый код сразу перестанет действовать.')) return;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const body = {
        ttlSeconds: Number(elements.inviteTtl.value) || 604800,
        maxMembers: max.value,
        requireApproval: elements.inviteApproval.checked,
        proto: PROTO_VERSION,
    };
    elements.rotateInviteBtn.disabled = true;
    // Вход без одобрения - только по подписанному приглашению: сертификат и снимок подписывает клиент, секрет ссылки остаётся на устройстве.
    let signed = null;
    if (!body.requireApproval) {
        const client = await getReadyE2eeClient();
        if (!client) {
            elements.rotateInviteBtn.disabled = false;
            showToast('Шифрование недоступно: подписанную ссылку без одобрения создать нельзя', 'error');
            return;
        }
        try {
            signed = await client.signInvite(roomId, { ttlSeconds: body.ttlSeconds });
        } catch (err) {
            console.error('E2EE: signInvite failed:', err);
            elements.rotateInviteBtn.disabled = false;
            showToast('Не удалось подписать приглашение', 'error');
            return;
        }
        body.inviteCert = signed.cert;
        body.inviteSnap = signed.snap;
    }
    const data = await api(`/api/chats/${chatId}/invite/rotate`, { method: 'POST', body: JSON.stringify(body) });
    elements.rotateInviteBtn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось создать новый код', 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    if (!signed) {
        // Приглашение с одобрением подписанного сертификата не имеет: секрет прежней ссылки больше не нужен (9.3).
        const client = await getReadyE2eeClient();
        if (client) client.dropInviteSecret(roomId).catch(() => {});
    }
    const signing = signed ? await loadInviteSigning(chatId, roomId) : { linkSecret: null, inviter: null };
    renderInvite({
        ...(inviteState || {}),
        code: data.code,
        expiresAt: data.expiresAt,
        expired: false,
        disabled: false,
        maxMembers: data.maxMembers !== undefined ? data.maxMembers : body.maxMembers,
        requireApproval: data.requireApproval !== undefined ? data.requireApproval : body.requireApproval,
        signed: Boolean(signed),
        ...signing,
    });
    showToast(hadCode ? 'Создан новый код. Старый больше не действует' : 'Создан новый код', 'success', 5000);
}

async function disableInviteCode() {
    if (!currentChatId || elements.disableInviteBtn.disabled) return;
    if (!confirm('Отключить приглашение? Текущий код сразу перестанет действовать. Новый код можно создать в любой момент.')) return;
    const chatId = currentChatId;
    elements.disableInviteBtn.disabled = true;
    const data = await api(`/api/chats/${chatId}/invite/disable`, { method: 'POST', body: JSON.stringify({ proto: PROTO_VERSION }) });
    elements.disableInviteBtn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось отключить приглашение', 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    renderInvite({ ...(inviteState || {}), code: null, expiresAt: null, disabled: true, expired: false, signed: false, linkSecret: null, inviter: null });
    // Секрет прежней ссылки больше не нужен: приглашение выключено (signed-membership.md, 9.3).
    const client = await getReadyE2eeClient();
    if (client && currentRoomId) client.dropInviteSecret(currentRoomId).catch(() => {});
    showToast('Приглашение отключено', 'success');
}

// ==================== Вступление по коду ====================

// Окно «Новый чат» работает в двух режимах: обычном (создать группу или
// вступить по коду) и приглашения — после входа по ссылке #join= или с
// экрана входа «У меня есть приглашение»: заголовок «Приглашение в группу»,
// блока «Создать группу» нет, вместо «Отмена» — «Не сейчас».
let joinPreviewCode = null;
let joinPreviewSecret = null;  // секрет ссылки (signed-membership.md, 5.3): хранится в памяти, на сервер не уходит
let joinPreviewRoomId = null;       // комната и сертификат приглашения из предпросмотра: вход по ссылке подписывается ими
let joinPreviewInviteCert = null;
let joinPreviewDirect = false;      // true - вход без одобрения по ссылке с секретом, false - заявка
let joinInviteMode = false;
let joinBusy = false;

const JOIN_INVALID_TEXT = 'Код недействителен: он истёк, выключен или введён с ошибкой. Попросите новый.';
const JOIN_KEYS_STATUS = 'Готовим ключи шифрования…';
const JOIN_KEYS_WAIT_MS = 15000;

function openNewChatModal({ invite = false } = {}) {
    joinInviteMode = Boolean(invite);
    hideJoinPreview();
    clearJoinError();
    elements.newChatTitle.textContent = joinInviteMode ? 'Приглашение в группу' : 'Новый чат';
    elements.newChatCreate.classList.toggle('hidden', joinInviteMode);
    elements.joinCancelBtn.textContent = joinInviteMode ? 'Не сейчас' : 'Отмена';
    openModal(elements.newChatModal);
    loadMyRequests();
}

function hideJoinPreview() {
    joinPreviewCode = null;
    joinPreviewRoomId = null;
    joinPreviewInviteCert = null;
    joinPreviewDirect = false;
    elements.joinPreview.classList.add('hidden');
    setJoinStatus('');
}

function onJoinCancel() {
    hideJoinPreview();
    if (joinInviteMode) closeModal(elements.newChatModal);
}

function showJoinError(text) {
    elements.joinError.textContent = text;
    elements.joinError.classList.remove('hidden');
    elements.joinChatCode.setAttribute('aria-invalid', 'true');
}

function clearJoinError() {
    elements.joinError.textContent = '';
    elements.joinError.classList.add('hidden');
    elements.joinChatCode.removeAttribute('aria-invalid');
}

// Ход вступления («Готовим ключи шифрования…») — role="status".
function setJoinStatus(text) {
    elements.joinStatus.textContent = text;
    elements.joinStatus.classList.toggle('hidden', !text);
}

// Ответ сервера → текст под полем. «Код недействителен» сервер пишет
// коротко, подробность — на клиенте.
function joinFailureText(data, fallback) {
    if (data && data.networkError) return 'Нет связи с сервером. Попробуйте ещё раз.';
    const message = data && typeof data.message === 'string' ? data.message : '';
    if (/^Код недействителен/.test(message)) return JOIN_INVALID_TEXT;
    return message || fallback;
}

// Шаг 1: предпросмотр — название, число участников, нужно ли одобрение.
// Формат кода проверяется до запроса: в поле можно вставить и всю ссылку.
async function previewJoin() {
    const parsed = NyxoInvite.parseInviteInput(elements.joinChatCode.value);
    if (!parsed.ok) {
        hideJoinPreview();
        showJoinError(parsed.reason === 'empty' ? INVITE_EMPTY_ERROR : INVITE_FORMAT_ERROR);
        elements.joinChatCode.focus();
        return;
    }
    const code = parsed.code;
    const btn = elements.joinChatBtn;
    if (btn.disabled) return;
    clearJoinError();
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    const label = Array.from(btn.childNodes);
    setIconLabel(btn, 'loader', 'Проверяем…', { className: 'spin' });
    const data = await api('/api/chats/join/preview', { method: 'POST', body: JSON.stringify({ code }) });
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.replaceChildren(...label);
    if (!currentUser) return;
    if (!data.success) {
        hideJoinPreview();
        showJoinError(joinFailureText(data, 'Не удалось проверить код. Попробуйте ещё раз.'));
        elements.joinChatCode.focus();
        return;
    }
    joinPreviewCode = code;
    joinPreviewSecret = parsed.secret || null;
    joinPreviewRoomId = Number(data.roomId) || null;
    joinPreviewInviteCert = typeof data.inviteCert === 'string' ? data.inviteCert : null;
    // Без одобрения впускает только ссылка с секретом к подписанному приглашению; код без секрета - заявка (5.4).
    joinPreviewDirect = !data.requireApproval && Boolean(joinPreviewSecret && joinPreviewInviteCert && joinPreviewRoomId);
    elements.joinPreviewName.textContent = data.roomName || 'Группа';
    const count = Number(data.memberCount) || 0;
    elements.joinPreviewMeta.textContent = count > 0 ? `${count} ${plural(count, ['участник', 'участника', 'участников'])}` : '';
    elements.joinPreviewApproval.classList.toggle('hidden', joinPreviewDirect);
    setIconLabel(elements.joinConfirmBtn, joinPreviewDirect ? 'log-in' : 'send', joinPreviewDirect ? 'Вступить' : 'Отправить заявку');
    if (!data.requireApproval && !joinPreviewDirect) {
        setJoinStatus('Ссылка с секретом впускает сразу; код без ссылки отправляет заявку');
    }
    elements.joinPreview.classList.remove('hidden');
    elements.joinConfirmBtn.focus({ preventScroll: true });
}

// Перед вступлением без одобрения ключи устройства должны быть на сервере:
// иначе участники получат roomMembersChanged, пока identity новичка ещё
// не опубликована, запишут «у собеседника не настроен E2EE» и не отправят
// ему Sender Key. Ждём не дольше JOIN_KEYS_WAIT_MS: недоступное шифрование
// (e2eeInitPromise → false) вступление не блокирует: ключи устройства
// догонятся при повторе, а сообщения в группы до тех пор не отправляются.
async function waitForE2eeKeysBeforeJoin() {
    if (e2eeState !== 'pending' || !e2eeInitPromise) return;
    setJoinStatus(JOIN_KEYS_STATUS);
    await withTimeout(e2eeInitPromise, JOIN_KEYS_WAIT_MS, false);
    setJoinStatus('');
}

// Тексты ошибок проверки приглашения на устройстве (prepareJoin).
function joinPrepareFailureText(err) {
    switch (err && err.code) {
        case 'invalid-secret': return 'Ссылка повреждена: секрет не распознан. Попросите новую ссылку';
        case 'no-invite': return 'В этой группе нет приглашения по ссылке. Отправьте заявку';
        case 'secret-mismatch': return 'Секрет ссылки не подходит к приглашению. Попросите новую ссылку';
        case 'invalid-invite': return 'Приглашение повреждено или подписано неверно. Попросите новую ссылку';
        case 'expired': return 'Срок приглашения истёк. Попросите новую ссылку';
        case 'clock': return 'Часы на устройстве отстают: приглашение выдано «в будущем». Поправьте время и повторите';
        default: return 'Не удалось проверить приглашение. Попробуйте ещё раз';
    }
}

// Шаг 2: вступление (или заявка, если группе нужно одобрение).
async function joinChat() {
    const code = joinPreviewCode;
    if (!code || joinBusy) return;
    joinBusy = true;
    const btn = elements.joinConfirmBtn;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    clearJoinError();
    let data;
    const roomId = joinPreviewRoomId;
    let intentWritten = false;
    try {
        await waitForE2eeKeysBeforeJoin();
        const client = await getReadyE2eeClient();
        const body = { code, proto: PROTO_VERSION };
        if (client && roomId) {
            // Намерение входа создаёт только это действие пользователя (signed-membership.md, 9.2): по ссылке - после
            // проверки приглашения секретом, по заявке - при нажатии «Отправить заявку».
            try {
                const prepared = await client.prepareJoin(roomId, joinPreviewDirect
                    ? { secret: joinPreviewSecret, inviteCert: joinPreviewInviteCert }
                    : {});
                intentWritten = true;
                if (prepared.joinCert) body.joinCert = prepared.joinCert;
            } catch (err) {
                data = { success: false, message: joinPrepareFailureText(err) };
            }
        }
        if (!data) {
            data = await api('/api/chats/join', { method: 'POST', body: JSON.stringify(body) });
            if (data.success && data.inviteSnap && client && roomId) {
                const done = await client.completeJoin(roomId, data.inviteSnap).catch(() => ({ ok: false }));
                if (!done.ok) showToast('Приглашение повреждено: состав группы по нему не подтвердится', 'error', 8000);
            }
            if (!data.success && intentWritten && client) client.cancelJoinIntent(roomId).catch(() => {});
        }
    } finally {
        joinBusy = false;
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        setJoinStatus('');
    }
    if (!currentUser) return;
    if (!data.success) {
        showJoinError(joinFailureText(data, 'Не удалось вступить. Попробуйте ещё раз.'));
        return;
    }
    elements.joinChatCode.value = '';
    joinPreviewSecret = null;
    hideJoinPreview();
    if (data.pending) {
        if (data.requestId != null && data.roomName) myRequestNames.set(String(data.requestId), data.roomName);
        showToast('Запрос отправлен, ожидает одобрения', 'success', 5000);
        loadMyRequests(data.requestId);
        return;
    }
    showToast('Вы присоединились к чату', 'success');
    closeModal(elements.newChatModal);
    loadChats();
    openChat(data.chat.id, data.chat.room_id, data.chat.name, data.chat.avatar, 0, 0);
}

// Свои заявки — карточки «ожидает одобрения» с кнопкой «Отменить».
// Названия групп запоминаем: в joinRequestDecided есть только requestId.
const myRequestNames = new Map();   // requestId -> roomName
let myRequestsSeq = 0;
async function loadMyRequests(highlightId) {
    const seq = ++myRequestsSeq;
    const data = await api('/api/join-requests/mine');
    if (seq !== myRequestsSeq) return;
    const list = data.success && Array.isArray(data.requests) ? data.requests : [];
    list.forEach((req) => { if (req.roomName) myRequestNames.set(String(req.id), req.roomName); });
    elements.myRequests.classList.toggle('hidden', list.length === 0);
    elements.myRequestsList.replaceChildren(...list.map(req => createPendingCard(req, Number(req.id) === Number(highlightId))));
}

function createPendingCard(req, fresh) {
    const card = document.createElement('div');
    card.className = 'pending-card' + (fresh ? ' is-active' : '');
    const body = document.createElement('div');
    const title = document.createElement('h4');
    title.textContent = req.roomName || 'Группа';
    const status = document.createElement('p');
    status.className = 'muted';
    const when = formatRelativeTime(req.createdAt);
    status.textContent = `Запрос отправлен, ожидает одобрения${when ? ' · ' + when : ''}`;
    body.append(title, status);
    const cancel = document.createElement('button');
    cancel.className = 'btn btn-ghost btn-sm';
    cancel.type = 'button';
    setIconLabel(cancel, 'x', 'Отменить');
    cancel.addEventListener('click', () => cancelMyRequest(req.id, cancel));
    // Аккаунт «Пока открыта вкладка» удалится через 30 минут после закрытия
    // вкладки — вместе с заявкой, а одобрения можно ждать долго.
    const warning = currentUser ? NyxoLifetime.inviteTabWarning(currentUser.anonLifetime, true) : '';
    if (!warning) {
        card.append(icon('hourglass'), body, cancel);
        return card;
    }
    const hint = document.createElement('p');
    hint.className = 'field-hint';
    hint.textContent = warning;
    body.append(hint);
    const keep = document.createElement('button');
    keep.className = 'btn btn-secondary btn-sm';
    keep.type = 'button';
    keep.textContent = 'Хранить 1 день';
    keep.addEventListener('click', async () => {
        keep.disabled = true;
        const ok = await changeLifetime('day');
        if (!ok && keep.isConnected) keep.disabled = false;
    });
    const actions = document.createElement('div');
    actions.className = 'invite-actions';
    actions.append(keep, cancel);
    card.append(icon('hourglass'), body, actions);
    return card;
}

async function cancelMyRequest(requestId, btn) {
    btn.disabled = true;
    const data = await api(`/api/join-requests/${encodeURIComponent(requestId)}`, { method: 'DELETE' });
    if (!data.success) {
        btn.disabled = false;
        showToast(data.message || 'Не удалось отменить заявку', 'error');
        return;
    }
    showToast('Заявка отменена', 'success');
    loadMyRequests();
}

// ==================== Заявки на вступление (у участников) ====================

let joinRequestsSeq = 0;

function renderRequestsBar(count) {
    const n = Number(count) || 0;
    elements.requestsBar.classList.toggle('hidden', n === 0);
    elements.requestsBarText.textContent = n > 0 ? `Заявки на вступление: ${n}` : '';
}

async function fetchJoinRequests() {
    if (!currentChatId || !currentRoomId) return null;
    const chatId = currentChatId;
    const seq = ++joinRequestsSeq;
    const data = await api(`/api/chats/${chatId}/join-requests`);
    if (seq !== joinRequestsSeq || chatId !== currentChatId) return null;
    return data.success && Array.isArray(data.requests) ? data.requests : [];
}

async function loadJoinRequestsCount() {
    const list = await fetchJoinRequests();
    if (list) renderRequestsBar(list.length);
}

function openRequestsModal() {
    setRequestsPlaceholder('Загрузка…');
    openModal(elements.requestsModal);
    loadRequestsList();
}

function setRequestsPlaceholder(text) {
    const li = document.createElement('li');
    li.className = 'request-row muted';
    li.textContent = text;
    elements.requestsList.replaceChildren(li);
}

async function loadRequestsList() {
    const list = await fetchJoinRequests();
    if (!list) return;
    renderRequestsBar(list.length);
    if (list.length === 0) {
        setRequestsPlaceholder('Новых заявок нет');
        return;
    }
    elements.requestsList.replaceChildren(...list.map(createRequestRow));
}

function createRequestRow(req) {
    const li = document.createElement('li');
    li.className = 'request-row';
    const avatar = document.createElement('div');
    avatar.className = 'member-avatar';
    avatar.setAttribute('aria-hidden', 'true');
    renderAvatar(avatar, req.username, false);
    const info = document.createElement('div');
    info.className = 'member-info';
    const name = document.createElement('div');
    name.className = 'member-name';
    name.textContent = req.username || `участник #${req.userId}`;
    const when = document.createElement('small');
    when.className = 'muted';
    when.textContent = formatRelativeTime(req.createdAt);
    info.append(name, when);
    const actions = document.createElement('div');
    actions.className = 'member-actions';
    const approve = document.createElement('button');
    approve.className = 'btn btn-primary btn-sm';
    approve.type = 'button';
    setIconLabel(approve, 'check', 'Впустить');
    approve.setAttribute('aria-label', `Впустить ${name.textContent}`);
    const deny = document.createElement('button');
    deny.className = 'btn btn-secondary btn-sm';
    deny.type = 'button';
    setIconLabel(deny, 'x', 'Отклонить');
    deny.setAttribute('aria-label', `Отклонить заявку ${name.textContent}`);
    approve.addEventListener('click', () => decideJoinRequest(req, true, li, [approve, deny]));
    deny.addEventListener('click', () => decideJoinRequest(req, false, li, [approve, deny]));
    actions.append(approve, deny);
    li.append(avatar, info, actions);
    showApplicantKeyCheck(req, info);
    return li;
}

// Одобряющий поручается за ключ заявителя до вступления: ключ проверяется по журналу (ревью К12).
async function showApplicantKeyCheck(req, info) {
    if (!req || !req.identity || !req.identity.kt) return;
    const client = await getReadyE2eeClient();
    if (!client || typeof client.checkApplicantKey !== 'function') return;
    let result;
    try {
        result = await client.checkApplicantKey(req.userId, req.identity);
    } catch (err) {
        console.warn('E2EE: проверка ключа заявителя по журналу не удалась:', err);
        return;
    }
    const texts = {
        ok: 'ключ проверен по журналу',
        pending: KT_PEER_TEXT.pending,
        mismatch: 'Ключа заявителя нет в журнале ключей. Возможна подмена, сверьте код безопасности лично',
    };
    const text = result && texts[result.status];
    if (!text || !info.isConnected) return;
    const line = document.createElement('small');
    line.className = result.status === 'mismatch' ? 'member-kt' : 'member-kt';
    line.textContent = text;
    info.appendChild(line);
}

async function decideJoinRequest(req, approve, row, buttons) {
    buttons.forEach((b) => { b.disabled = true; });
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const body = { proto: PROTO_VERSION };
    if (approve) {
        // Одобрение подписывается (signed-membership.md, 5.2): сертификат допуска и снимок состава одобряющего.
        const client = await getReadyE2eeClient();
        if (!client || !req.identity) {
            buttons.forEach((b) => { b.disabled = false; });
            showToast(client ? 'Пользователь ещё не настроил шифрование: одобрить его пока нельзя' : 'Шифрование недоступно: одобрить заявку нельзя', 'error');
            return;
        }
        const approveBtn = buttons[0];
        const label = Array.from(approveBtn.childNodes);
        setIconLabel(approveBtn, 'loader', 'Подписываем…', { className: 'spin' });
        try {
            const signed = await client.signApproval(roomId, { userId: req.userId, signingKey: req.identity.signingKey, dhKey: req.identity.dhKey });
            body.cert = signed.cert;
            body.snap = signed.snap;
        } catch (err) {
            console.error('E2EE: signApproval failed:', err);
            approveBtn.replaceChildren(...label);
            buttons.forEach((b) => { b.disabled = false; });
            showToast('Не удалось подписать допуск', 'error');
            return;
        }
        approveBtn.replaceChildren(...label);
    }
    const data = await api(`/api/join-requests/${encodeURIComponent(req.id)}/${approve ? 'approve' : 'deny'}`, { method: 'POST', body: JSON.stringify(body) });
    if (!data.success) {
        buttons.forEach((b) => { b.disabled = false; });
        showToast(data.message || 'Не удалось обработать заявку', 'error');
        return;
    }
    row.remove();
    if (!elements.requestsList.querySelector('.request-row:not(.muted)')) setRequestsPlaceholder('Новых заявок нет');
    showToast(approve
        ? `${req.username || 'Участник'} в группе. Ключ шифрования будет передан автоматически`
        : 'Заявка отклонена', 'success', 5000);
    loadJoinRequestsCount();
    // Ключ новичку разошлёт тот же поток, что и при вступлении без
    // одобрения: сервер шлёт roomMembersChanged → syncKeyShares →
    // ensureRoomSession (newMembers → key-share). Запускаем его и сами —
    // на случай, если событие сокета потерялось; повтор склеит debounce.
    if (approve && chatId === currentChatId && roomId) scheduleRoomMembersRefresh(roomId);
}

// ==================== Участники и ключи ====================

// ==================== Журнал ключей ====================
//
// Прозрачность ключей (docs/security/key-transparency.md, 10): тревоги клиента попадают в баннер боковой
// панели, подробности и действия — в окне «Журнал ключей». Статусы участников — в окне «Участники и ключи».

const KT_BANNER_TEXT = {
    'self-foreign-entry': 'Сервер опубликовал для вашего аккаунта ключ, которого нет на этом устройстве.',
    'self-missing': 'Сервер не выполнил обещание включить ваш ключ в журнал ключей.',
    'key-split': 'Подпись журнала у вас и у собеседника не сходится. Возможна подмена журнала — сверьте коды безопасности лично.',
    'log-disabled': 'Журнал ключей на сервере перестал отвечать или отключён, хотя раньше работал. Новые и изменившиеся ключи собеседников не считаются проверенными — сверяйте коды безопасности.',
    inconsistent: 'Журнал ключей на сервере не прошёл проверку. Шифрование может быть небезопасным — сверяйте коды безопасности.',
};
// Какая тревога главная для баннера: сначала про мой аккаунт, потом про журнал.
const KT_BANNER_ORDER = ['self-foreign-entry', 'self-missing', 'key-split', 'log-disabled'];
const KT_INCONSISTENT_KINDS = ['log-fork', 'equivocation', 'bad-signature', 'key-changed'];

let ktAlertsSeq = 0;

function currentE2eeClientIfReady() {
    return currentUser && e2eeClient && e2eeClientUserId === currentUser.id ? e2eeClient : null;
}

async function readTransparencyAlerts() {
    const client = currentE2eeClientIfReady();
    if (!client || typeof client.getTransparencyAlerts !== 'function') return [];
    try {
        return await client.getTransparencyAlerts();
    } catch (err) {
        console.warn('E2EE: не удалось прочитать тревоги журнала ключей:', err);
        return [];
    }
}

async function refreshTransparencyBanner() {
    const seq = ++ktAlertsSeq;
    const alerts = await readTransparencyAlerts();
    if (seq !== ktAlertsSeq) return;
    let kind = KT_BANNER_ORDER.find(k => alerts.some(a => a.kind === k)) || null;
    if (!kind && alerts.some(a => KT_INCONSISTENT_KINDS.includes(a.kind))) kind = 'inconsistent';
    if (!kind) {
        elements.ktBanner.classList.add('hidden');
        elements.ktBannerText.textContent = '';
        return;
    }
    elements.ktBannerText.textContent = KT_BANNER_TEXT[kind];
    elements.ktBanner.classList.remove('hidden');
}

// Час эпохи (число часов от 1970-го) → «2026-10-11 14:00 UTC».
function ktEpochText(epoch) {
    if (!Number.isFinite(epoch)) return 'время неизвестно';
    return new Date(epoch * 3600 * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

const KT_FORK_TEXT = {
    rollback: 'Сервер показал более раннюю версию журнала, чем уже видело это устройство.',
    'chain-mismatch': 'История журнала переписана: новая цепочка не продолжает ту, что видело это устройство.',
    'genesis-changed': 'Начало поколения журнала изменилось.',
    'generation-length': 'Сервер нарушил длину поколения журнала.',
    'grace-violated': 'Сервер удалил прежнее поколение журнала раньше срока.',
    'prev-final-head': 'Новое поколение журнала не продолжает прежнее.',
    'self-proof': 'Сервер прислал для вашей метки доказательство, которое не сходится с журналом.',
};

// Описание тревоги для окна: заголовок, пояснения и действия (кнопки).
function ktAlertView(alert, pendingKey, client) {
    const lines = [];
    const actions = [];
    let title = KT_BANNER_TEXT[alert.kind] || 'Журнал ключей не прошёл проверку.';
    if (alert.kind === 'self-foreign-entry') {
        (alert.entries || []).forEach((entry) => lines.push(`Запись в журнале от ${ktEpochText(entry.epoch)}.`));
        if (Number.isFinite(alert.identityCreatedHour)) {
            lines.push(`Ключи этого устройства созданы ${ktEpochText(alert.identityCreatedHour)} (с точностью до часа).`);
        }
        lines.push('Записи старше создания ключей на этом устройстве — вероятно, прежние ключи вашего аккаунта (например, после очистки данных сайта без выхода). Записи новее подозрительны: сверьте коды безопасности с собеседниками лично.');
        actions.push({
            text: 'Это были мои прежние ключи',
            run: async () => { await client.ackSelfEntries(alert.entries || []); },
        });
    } else if (alert.kind === 'self-missing') {
        title = alert.reason === 'carry-over'
            ? 'Сервер не перенёс ваш ключ в новое поколение журнала.'
            : KT_BANNER_TEXT['self-missing'];
        lines.push(`Поколение ${alert.gen}, ${ktEpochText(alert.epoch)}. Подписанное обещание сервера сохранено на этом устройстве как доказательство.`);
    } else if (alert.kind === 'log-fork') {
        title = KT_FORK_TEXT[alert.reason] || 'Журнал ключей показывает несогласованную историю.';
        lines.push('Это доказательство того, что сервер ведёт журнал нечестно (или его базу восстановили без смены ключа журнала).');
    } else if (alert.kind === 'equivocation') {
        title = alert.reason === 'keychange'
            ? 'Сервер выдал два разных заявления о смене ключа журнала.'
            : 'Вы и собеседник видите разные подписанные версии журнала для одной эпохи.';
        lines.push('Подписанные версии сохранены на этом устройстве как доказательство.');
    } else if (alert.kind === 'bad-signature') {
        title = alert.reason === 'own-skt'
            ? 'Обещание сервера включить ваш ключ в журнал имеет неверную подпись.'
            : 'Подпись журнала ключей не проходит проверку.';
    } else if (alert.kind === 'key-changed') {
        title = 'Ключ подписи журнала изменился без заявления о смене.';
        lines.push('Принимайте новый ключ только после сверки отпечатка с опубликованным релизом.');
        if (pendingKey) {
            lines.push({ fingerprint: pendingKey.hex.match(/.{1,8}/g).join(' ') });
            actions.push({
                text: 'Принять новый ключ журнала',
                confirm: 'Отпечаток совпадает с опубликованным в релизе? Принятие сбросит сохранённые цепочки журнала на этом устройстве.',
                run: async () => {
                    // false — ключ не прошёл проверку (малый порядок и т.п.): принять его нельзя.
                    if (!(await client.acceptLogKey())) throw new Error('ключ журнала не принят');
                },
            });
        }
    }
    return { title, lines, actions };
}

async function openTransparencyModal() {
    const client = currentE2eeClientIfReady();
    if (!client) return;
    const alerts = await readTransparencyAlerts();
    let pendingKey = null;
    try { pendingKey = await client.getPendingLogKey(); } catch { pendingKey = null; }
    const items = alerts.map((alert) => {
        const view = ktAlertView(alert, pendingKey, client);
        const li = document.createElement('li');
        li.className = 'kt-alert';
        const title = document.createElement('div');
        title.className = 'kt-alert-title';
        title.textContent = view.title;
        li.appendChild(title);
        view.lines.forEach((line) => {
            const p = document.createElement('p');
            if (typeof line === 'object') {
                p.className = 'kt-fingerprint';
                p.textContent = line.fingerprint;
            } else {
                p.textContent = line;
            }
            li.appendChild(p);
        });
        if (view.actions.length > 0) {
            const row = document.createElement('div');
            row.className = 'member-actions';
            view.actions.forEach((action) => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-secondary btn-sm';
                btn.textContent = action.text;
                btn.addEventListener('click', async () => {
                    if (action.confirm && !confirm(action.confirm)) return;
                    btn.disabled = true;
                    try {
                        await action.run();
                    } catch (err) {
                        console.error('E2EE: действие над тревогой журнала не удалось:', err);
                        showToast('Не удалось выполнить действие', 'error');
                        btn.disabled = false;
                        return;
                    }
                    await refreshTransparencyBanner();
                    openTransparencyModal();
                });
                row.appendChild(btn);
            });
            li.appendChild(row);
        }
        return li;
    });
    if (items.length === 0) {
        const li = document.createElement('li');
        li.className = 'members-placeholder';
        li.textContent = 'Тревог нет.';
        items.push(li);
    }
    elements.ktAlertList.replaceChildren(...items);
    if (elements.ktModal.classList.contains('hidden')) openModal(elements.ktModal);
}

const IDENTITY_STATUS = {
    verified: { text: 'проверен', cls: 'verified', icon: 'shield-check' },
    unverified: { text: 'не проверен', cls: 'unverified', icon: 'shield' },
    changed: { text: 'ключ изменился', cls: 'changed', icon: 'alert-triangle' },
    // Ключа нет в журнале ключей: класс как у changed (раздел 10 key-transparency.md).
    'log-mismatch': { text: 'нет в журнале ключей', cls: 'changed', icon: 'alert-triangle' },
    unknown: { text: 'нет E2EE', cls: 'unknown', icon: 'unlock' },
};

// Журнал ключей рядом со статусом участника: неброская строка (pending, unavailable) и отметка ok.
const KT_PEER_TEXT = {
    ok: 'ключ проверен по журналу',
    pending: 'Ключ ждёт подтверждения журналом',
    unavailable: 'Проверка журнала ключей сейчас недоступна',
};

let membersModalSeq = 0;

function setMembersPlaceholder(text) {
    const li = document.createElement('li');
    li.className = 'members-placeholder';
    li.textContent = text;
    elements.membersList.replaceChildren(li);
}

function setMemberStatus(row, status) {
    const info = IDENTITY_STATUS[status] || IDENTITY_STATUS.unknown;
    row._status = status;
    setIconLabel(row._statusEl, info.icon, info.text, { size: 'sm' });
    row._statusEl.className = `member-status ${info.cls}`;
}

function renderSafetyNumber(container, safetyNumber) {
    if (!safetyNumber) {
        container.textContent = 'Код недоступен: у участника нет ключей шифрования';
        container.classList.add('unavailable');
        return;
    }
    container.classList.remove('unavailable');
    const groups = String(safetyNumber).trim().split(/\s+/);
    container.replaceChildren(...groups.map((group) => {
        const span = document.createElement('span');
        span.textContent = group;
        return span;
    }));
}

async function renderMemberDetails(row, peer, ctx) {
    const { details } = row;
    const status = row._status;
    details.replaceChildren();

    if (status === 'log-mismatch') {
        details.appendChild(iconText('p', 'member-warning', 'alert-triangle', `Сервер показывает для ${peer.username} ключ, которого нет в журнале ключей (или журнал у участников разный). Возможна подмена. Сверьте код безопасности лично. Ключ комнаты этому участнику не отправляется, пока вы не сверите код или не продолжите явно.`));
    }
    if (status === 'changed') {
        details.appendChild(iconText('p', 'member-warning', 'alert-triangle', 'Ключ шифрования этого участника изменился. Так бывает после переустановки браузера или входа с нового устройства — но так же выглядит и подмена ключа сервером. Сверьте код безопасности с участником лично, прежде чем принимать новый ключ.'));
    }

    const code = document.createElement('div');
    code.className = 'safety-number';
    code.setAttribute('aria-label', `Код безопасности с ${peer.username}`);
    code.textContent = 'Загрузка кода…';
    const hint = document.createElement('p');
    hint.className = 'safety-hint';
    hint.textContent = `${peer.username} видит у себя такой же код для вас. Сравните все 12 групп цифр.`;
    const actions = document.createElement('div');
    actions.className = 'member-actions';
    details.append(code, hint, actions);

    if (status === 'changed') {
        const accept = document.createElement('button');
        accept.className = 'btn btn-danger btn-sm';
        setIconLabel(accept, 'key', 'Принять новый ключ');
        accept.addEventListener('click', () => acceptIdentityChange(row, peer, ctx, accept));
        actions.appendChild(accept);
    } else if (status === 'unverified' || status === 'log-mismatch') {
        const mark = document.createElement('button');
        mark.className = 'btn btn-primary btn-sm';
        setIconLabel(mark, 'shield-check', 'Отметить как проверенный');
        mark.addEventListener('click', () => markVerified(row, peer, ctx, mark));
        actions.appendChild(mark);
        if (status === 'log-mismatch') {
            const proceed = document.createElement('button');
            proceed.className = 'btn btn-danger btn-sm';
            setIconLabel(proceed, 'key', 'Продолжить без проверки');
            proceed.addEventListener('click', () => overrideLogMismatch(row, peer, ctx, proceed));
            actions.appendChild(proceed);
        }
    } else if (status === 'verified') {
        actions.appendChild(iconText('p', 'safety-hint', 'check', 'Вы уже сверили этот код.', { size: 'sm' }));
    }

    try {
        renderSafetyNumber(code, await ctx.client.getSafetyNumber(peer.id));
    } catch (err) {
        console.warn('E2EE: getSafetyNumber failed:', err);
        renderSafetyNumber(code, null);
    }
}

async function markVerified(row, peer, ctx, btn) {
    btn.disabled = true;
    try {
        await ctx.client.markPeerVerified(peer.id);
    } catch (err) {
        console.error('E2EE: markPeerVerified failed:', err);
        btn.disabled = false;
        showToast('Не удалось сохранить отметку', 'error');
        return;
    }
    setMemberStatus(row, (await peerIdentityStatus(ctx.client, peer.id)) || 'verified');
    showToast(`${peer.username}: ключ отмечен как проверенный`, 'success');
    renderMemberDetails(row, peer, ctx);
}

// Пользователь явно продолжает общение с участником, чьего ключа нет в журнале: он снова адресат рассылки.
async function overrideLogMismatch(row, peer, ctx, btn) {
    if (!confirm(`Продолжить обмен ключами с ${peer.username} без проверки по журналу? Делайте это, только если уверены, что его ключ настоящий (код безопасности сверен лично).`)) return;
    btn.disabled = true;
    try {
        await ctx.client.overrideLogMismatch(peer.id);
    } catch (err) {
        console.error('E2EE: overrideLogMismatch failed:', err);
        btn.disabled = false;
        showToast('Не удалось продолжить', 'error');
        return;
    }
    setMemberStatus(row, (await peerIdentityStatus(ctx.client, peer.id)) || 'unverified');
    if (Number(ctx.roomId) === Number(currentRoomId)) {
        pendingLogMismatches.delete(Number(peer.id));
        renderIdentityBanner();
        ensureE2eeRoomSession(ctx.chatId, ctx.roomId);
    }
    renderMemberDetails(row, peer, ctx);
}

async function acceptIdentityChange(row, peer, ctx, btn) {
    if (!confirm(`Принять новый ключ участника ${peer.username}? Делайте это, только если код безопасности совпал с кодом на его устройстве.`)) return;
    btn.disabled = true;
    try {
        await ctx.client.acceptPeerIdentityChange(peer.id);
    } catch (err) {
        console.error('E2EE: acceptPeerIdentityChange failed:', err);
        btn.disabled = false;
        showToast('Не удалось принять новый ключ', 'error');
        return;
    }
    setMemberStatus(row, (await peerIdentityStatus(ctx.client, peer.id)) || 'unverified');
    if (Number(ctx.roomId) === Number(currentRoomId)) {
        pendingIdentityChanges.delete(Number(peer.id));
        renderIdentityBanner();
        // Ключ комнаты этому участнику до сих пор не отправлялся — досылаем.
        ensureE2eeRoomSession(ctx.chatId, ctx.roomId);
    }
    showToast(`Новый ключ ${peer.username} принят`, 'success');
    renderMemberDetails(row, peer, ctx);
}

// Подтверждение участника вручную (signed-membership.md, 9.7): локальное решение, сертификата не публикует.
async function trustUnconfirmedMember(peer, ctx, btn, duplicate) {
    const warning = `Сервер добавил ${peer.username} в группу, но никто из участников это не подписал. Доверяйте, только если знаете, кто это.`
        + (duplicate ? ' У этого участника такие же ключи шифрования, как у другого: возможно, это подделка.' : '');
    if (!confirm(warning)) return;
    btn.disabled = true;
    let res;
    try {
        res = await ctx.client.trustMember(ctx.roomId, peer.id);
    } catch (err) {
        console.error('E2EE: trustMember failed:', err);
        res = { ok: false };
    }
    if (!res || !res.ok) {
        btn.disabled = false;
        showToast(res && res.reason === 'changed' ? 'Ключ участника изменился: сначала проверьте код безопасности' : 'Не удалось подтвердить участника', 'error');
        return;
    }
    showToast(`${peer.username} подтверждён. Ключ шифрования будет передан автоматически`, 'success', 5000);
    if (res.cancelledIntent) showToast('Проверка по приглашению отменена: вы подтвердили участников вручную', 'info', 6000);
    if (Number(ctx.roomId) === Number(currentRoomId)) {
        pendingUnconfirmed.delete(Number(peer.id));
        renderIdentityBanner();
        ensureE2eeRoomSession(ctx.chatId, ctx.roomId);
    }
    openMembersModal();
}

// Явное поручительство (9.5): подписать допуск за участника, подтверждённого вручную. Остальные начнут отправлять ему ключи.
async function vouchForMember(peer, ctx, btn) {
    if (!confirm(`Вы подпишете, что знаете ${peer.username}. Остальные участники начнут отправлять ему ключи.`)) return;
    btn.disabled = true;
    let res;
    try {
        res = await ctx.client.vouchForMember(ctx.chatId, ctx.roomId, peer.id);
    } catch (err) {
        console.error('E2EE: vouchForMember failed:', err);
        res = { ok: false };
    }
    if (!res || !res.ok) {
        btn.disabled = false;
        showToast((res && res.message) || 'Не удалось поручиться за участника', 'error');
        return;
    }
    showToast(`Вы поручились за ${peer.username}`, 'success', 5000);
    openMembersModal();
}

// Строка о составе под именем участника и действие над ним.
function appendMembershipInfo(li, info, peer, ctx) {
    const entry = ctx.member;
    if (!entry) return;
    const text = membershipHowLine(ctx.roomId, entry);
    if (text) {
        const line = document.createElement('small');
        line.className = 'member-how' + (entry.status === 'unconfirmed' ? ' unconfirmed' : '');
        line.textContent = text;
        info.appendChild(line);
    }
    if (entry.duplicateKeys && entry.status !== 'unconfirmed') {
        const warn = document.createElement('small');
        warn.className = 'member-how unconfirmed';
        warn.textContent = 'Ключи шифрования такие же, как у другого участника. Сверьте код безопасности';
        info.appendChild(warn);
    }
    if (ctx.isSelf || !ctx.client) return;
    if (entry.status === 'unconfirmed') {
        const trust = document.createElement('button');
        trust.className = 'btn btn-danger btn-sm';
        trust.type = 'button';
        setIconLabel(trust, 'user-check', 'Доверять участнику');
        trust.setAttribute('aria-label', `Доверять участнику ${peer.username}`);
        trust.addEventListener('click', () => trustUnconfirmedMember(peer, ctx, trust, Boolean(entry.duplicateKeys)));
        li.appendChild(trust);
    } else if (entry.status === 'confirmed' && entry.how === 'manual' && !entry.vouchedByMe) {
        const vouch = document.createElement('button');
        vouch.className = 'btn btn-secondary btn-sm';
        vouch.type = 'button';
        setIconLabel(vouch, 'shield-check', 'Поручиться за участника');
        vouch.setAttribute('aria-label', `Поручиться за участника ${peer.username}`);
        vouch.addEventListener('click', () => vouchForMember(peer, ctx, vouch));
        li.appendChild(vouch);
    }
}

function createMemberRow(peer, status, ctx) {
    const li = document.createElement('li');
    li.className = 'member-item';

    const head = document.createElement('div');
    head.className = 'member-head';
    const avatar = document.createElement('div');
    avatar.className = 'member-avatar';
    avatar.setAttribute('aria-hidden', 'true');
    renderAvatar(avatar, peer.username, false);
    const info = document.createElement('div');
    info.className = 'member-info';
    const name = document.createElement('div');
    name.className = 'member-name';
    name.textContent = ctx.isSelf ? `${peer.username} (вы)` : peer.username;
    info.appendChild(name);
    head.append(avatar, info);
    li.appendChild(head);
    if (ctx.isSelf) {
        appendMembershipInfo(li, info, peer, ctx);
        return li;
    }

    const statusEl = document.createElement('span');
    info.appendChild(statusEl);
    li._statusEl = statusEl;
    setMemberStatus(li, status);
    appendMembershipInfo(li, info, peer, ctx);
    const ktText = ctx.kt && KT_PEER_TEXT[ctx.kt];
    if (ktText) {
        const ktEl = document.createElement('small');
        ktEl.className = 'member-kt';
        ktEl.textContent = ktText;
        info.appendChild(ktEl);
    }
    if (!ctx.client || status === 'unknown') return li;

    const details = document.createElement('div');
    details.className = 'member-details hidden';
    details.id = `member-details-${peer.id}`;
    li.details = details;
    const toggle = document.createElement('button');
    toggle.className = 'member-code-btn';
    toggle.textContent = status === 'changed' || status === 'log-mismatch' ? 'Проверить' : 'Код';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-controls', details.id);
    toggle.setAttribute('aria-label', `Код безопасности с ${peer.username}`);
    toggle.addEventListener('click', () => {
        const opening = details.classList.contains('hidden');
        details.classList.toggle('hidden', !opening);
        toggle.setAttribute('aria-expanded', opening ? 'true' : 'false');
        if (opening) renderMemberDetails(li, peer, ctx);
    });
    head.appendChild(toggle);
    li.appendChild(details);
    // Сменившийся ключ сразу разворачиваем: ради этого окно и открыли.
    if (status === 'changed' || status === 'log-mismatch') toggle.click();
    return li;
}

async function openMembersModal() {
    if (!currentChatId || !currentRoomId || !currentUser) return;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const seq = ++membersModalSeq;
    elements.membersNote.classList.add('hidden');
    setMembersPlaceholder('Загрузка участников…');
    openModal(elements.membersModal);

    const part = await api(`/api/chats/${chatId}/participants`);
    if (seq !== membersModalSeq || !currentUser) return;
    if (!part.success || !Array.isArray(part.participants)) {
        setMembersPlaceholder(part.message || 'Не удалось загрузить участников');
        return;
    }
    rememberRoomParticipants(roomId, part.participants);
    const client = await getReadyE2eeClient();
    if (seq !== membersModalSeq || !currentUser) return;
    // Состав группы (signed-membership.md, 10): статусы и подписи «кто подтвердил» - из свежей проверки состава.
    const membership = new Map();
    if (client) {
        try {
            const roomResult = await client.ensureRoomSession(chatId, roomId, part.participants, part);
            (roomResult.members || []).forEach(member => membership.set(Number(member.id), member));
            (roomResult.unconfirmed || []).forEach((u) => {
                const entry = membership.get(Number(u.id));
                if (entry) entry.duplicateKeys = Boolean(u.duplicateKeys);
            });
        } catch (err) {
            console.warn('E2EE: состав группы не проверен:', err);
        }
        roomMemberNames.set(Number(roomId), await client.getRoomMemberNames(roomId).catch(() => ({})));
        if (seq !== membersModalSeq || !currentUser) return;
    }
    const others = part.participants.filter(p => Number(p.id) !== Number(currentUser.id));

    const statuses = new Map();
    const ktStatuses = new Map();
    if (client && others.length > 0) {
        try {
            const list = await client.checkPeerIdentities(others.map(p => p.id));
            (list || []).forEach((s) => {
                statuses.set(Number(s.userId), s.status);
                if (s.kt) ktStatuses.set(Number(s.userId), s.kt);
            });
        } catch (err) {
            console.warn('E2EE: checkPeerIdentities failed:', err);
        }
    }
    if (seq !== membersModalSeq) return;

    if (!client) {
        elements.membersNote.textContent = 'Сквозное шифрование недоступно на этом устройстве — проверить ключи сейчас нельзя.';
        elements.membersNote.classList.remove('hidden');
    }
    const ctx = { client, chatId, roomId };
    const me = part.participants.find(p => Number(p.id) === Number(currentUser.id))
        || { id: currentUser.id, username: currentUser.username };
    const fragment = document.createDocumentFragment();
    fragment.appendChild(createMemberRow(me, null, { ...ctx, isSelf: true, member: membership.get(Number(me.id)) }));
    const changed = [];
    others.forEach((peer) => {
        const status = client ? (statuses.get(Number(peer.id)) || 'unknown') : 'unknown';
        if (status === 'changed') changed.push({ userId: peer.id, username: peer.username });
        fragment.appendChild(createMemberRow(peer, status, { ...ctx, kt: ktStatuses.get(Number(peer.id)), member: membership.get(Number(peer.id)) }));
    });
    elements.membersList.replaceChildren(fragment);
    if (changed.length > 0) addIdentityChanges(roomId, changed);
}

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
    badge.textContent = count > 99 ? '99+' : String(count);
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
    if (Number(id) === Number(currentChatId)) div.classList.add('active', 'is-active');
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
            showChatItemMenu(rect.left + 24, rect.bottom - 8, meta);
        }
    });
    if (meta) {
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            e.stopPropagation();
            showChatItemMenu(e.clientX, e.clientY, meta);
        });
        attachLongPress(div, (x, y) => showChatItemMenu(x, y, meta));
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
    elements.chatsList.querySelectorAll('.chat-item.active, .chat-item.is-active').forEach(el => el.classList.remove('active', 'is-active'));
    if (chatId == null) return;
    const meta = chatsById.get(Number(chatId));
    if (meta) meta.unread = 0;
    const item = findChatItem(chatId, roomId);
    if (item) {
        item.classList.add('active', 'is-active');
        setChatBadge(item, 0);
    }
}

// ---- Контекстное меню строки чата и меню чата ----

let chatItemMenuChat = null;

function showChatItemMenu(x, y, chat) {
    hideMessageMenu();
    chatItemMenuChat = chat;
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

function hideChatItemMenu() {
    elements.chatItemMenu.classList.add('hidden');
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
    setIconLabel(elements.deleteChatBtn, 'trash', currentRoomId ? 'Выйти из группы' : 'Удалить чат');
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
const NO_HISTORY_CONFIRM = 'Включить «Не хранить историю на этом устройстве»?\n\n'
    + 'Расшифрованные сообщения этой группы будут стираться из браузера, когда вы закроете чат или вкладку. '
    + 'Более ранние сообщения здесь больше не откроются, вернуть их нельзя.\n\n'
    + 'Это касается только этого устройства: у других участников и на сервере сообщения остаются, '
    + 'а чтобы они исчезли у всех, включите исчезающие сообщения. Другие участники об этой настройке не узнают.\n\n'
    + 'Браузер не гарантирует, что данные сразу будут затёрты на диске.';

async function onNoHistoryToggle() {
    const roomId = currentRoomId;
    const toggle = elements.noHistoryToggle;
    if (!roomId) return;
    const wantNone = toggle.checked;
    if (wantNone && !confirm(NO_HISTORY_CONFIRM)) {
        toggle.checked = false;
        return;
    }
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

    // Сокет уже подписан на все чаты при подключении; это — страховка для
    // чата, созданного/добавленного до переподключения.
    socket.emit('joinChat', room ? `room:${room}` : `chat:${chatId}`);
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
            if (String(editingMessageId) === String(messageId)) {
                editingMessageId = null;
            }
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

// ==================== Подсказки в чате с ботом ====================
// Над полем ввода в чате с ботом — кнопки с темами («Гайд», «Шифрование», …).
// Нажатие — обычное сообщение с подписью кнопки, тем же путём (sendText), что и
// набранный текст: ответ бота приходит как на любое другое сообщение. Подписи
// отдаёт сервер (chat.quickReplies в ответе истории): это же ключевые слова
// бота (lib/bot-guide.js), и разойтись они не должны.

const MAX_BOT_SUGGESTIONS = 6;         // больше кнопок на экране не поместится
const MAX_BOT_SUGGESTION_LENGTH = 60;  // подпись длиннее — уже не подсказка

let botSuggestionsChatId = null;       // чат, для которого нарисованы кнопки: нажатие уходит только в него

function clearBotSuggestions() {
    botSuggestionsChatId = null;
    elements.botSuggestions.classList.add('hidden');
    elements.botSuggestions.replaceChildren();
}

// Пока идёт отправка, кнопки помечены aria-disabled, а не disabled: фокус
// остаётся на нажатой кнопке (клавиатура и скринридер не теряют место), а
// повторное нажатие всё равно ничего не делает.
function syncBotSuggestionsBusy() {
    elements.botSuggestions.querySelectorAll('button.suggestion').forEach((button) => {
        if (sending) button.setAttribute('aria-disabled', 'true');
        else button.removeAttribute('aria-disabled');
    });
}

// Единственное место, где меняется замок отправки: кнопки подсказок должны
// отражать его и тогда, когда сообщение уходит из поля ввода.
function setSending(value) {
    sending = value;
    syncBotSuggestionsBusy();
}

// labels — chat.quickReplies из ответа сервера. Рисуем только строки разумной
// длины и не больше MAX_BOT_SUGGESTIONS, через textContent, как любой текст,
// пришедший с сервера. chatId запоминается: нажатие отправит сообщение именно
// в этот чат, даже если к тому времени открыт другой.
function renderBotSuggestions(chatId, labels) {
    clearBotSuggestions();
    if (!Array.isArray(labels)) return;
    const shown = labels
        .filter(label => typeof label === 'string' && label.trim() !== '' && label.length <= MAX_BOT_SUGGESTION_LENGTH)
        .slice(0, MAX_BOT_SUGGESTIONS);
    if (shown.length === 0) return;
    const fragment = document.createDocumentFragment();
    shown.forEach((label) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'chip suggestion';
        button.textContent = label;
        fragment.appendChild(button);
    });
    elements.botSuggestions.appendChild(fragment);
    elements.botSuggestions.classList.remove('hidden');
    botSuggestionsChatId = chatId;
    syncBotSuggestionsBusy();
}

// Один обработчик на весь контейнер: кнопки пересоздаются при каждом открытии чата.
async function onBotSuggestionClick(event) {
    const button = event.target.closest('button.suggestion');
    if (!button || !elements.botSuggestions.contains(button)) return;
    const chatId = botSuggestionsChatId;
    if (!chatId || chatId !== currentChatId || sending) return;
    setSending(true);
    try {
        // Поле ввода не читаем и не очищаем: черновик пользователя остаётся как был.
        await sendText(button.textContent, { chatId });
    } finally {
        setSending(false);
    }
}

// ==================== Файлы: выбор, перетаскивание, очередь отправки ====================
// Каждое вложение: проверка типа по белому списку → удаление метаданных на
// клиенте (сервер при открытой отправке снимает их ещё раз, но исходные
// EXIF/GPS так до него вообще не доходят) → в E2EE-комнате шифрование
// файла, а ключ файла, MIME и имя — внутри E2EE-конверта сообщения →
// загрузка с прогрессом. Несколько файлов уходят строго по очереди: так
// порядок в ленте совпадает с порядком выбора, а память не забивается
// несколькими большими файлами сразу.

let chosenFiles = [];          // [{ file, mime, error }] — содержимое окна «Отправить N файлов»
let chosenFilesChat = null;    // { chatId, roomId } — для какого чата они выбраны
let uploadQueue = null;        // { chatId, roomId, xhr, cancelled } — идёт отправка

function describeFile(file) {
    const mime = MimePolicy.detectFileMime(file);
    let error = '';
    if (!isSupportedMime(mime)) error = 'такой тип файлов не поддерживается (можно фото, видео, PDF и TXT)';
    else if (file.size > MAX_UPLOAD_BYTES) error = 'больше 50 МБ';
    else if (file.size === 0) error = 'пустой файл';
    return { file, mime, error };
}

// Имя, под которым файл увидят собеседники: у фото и видео — всегда
// обезличенное; у документа в E2EE-комнате — исходное (оно внутри конверта,
// сервер его не видит), без E2EE сервер тоже получает обезличенное.
function outgoingFileName(file, mime, encrypted) {
    return encrypted ? encryptedFileName(file, mime) : MimePolicy.anonymousFileName(mime);
}

function onFilesChosen(files) {
    if (!currentChatId || files.length === 0) return;
    if (composerDisabledReason) {
        showToast(composerDisabledReason, 'error', 6000);
        return;
    }
    if (uploadQueue) {
        showToast('Дождитесь окончания загрузки', 'info');
        return;
    }
    let list = files;
    if (list.length > MAX_FILES_PER_BATCH) {
        showToast(`За один раз можно отправить до ${MAX_FILES_PER_BATCH} файлов — лишние не добавлены`, 'info', 5000);
        list = list.slice(0, MAX_FILES_PER_BATCH);
    }
    chosenFiles = list.map(describeFile);
    chosenFilesChat = { chatId: currentChatId, roomId: currentRoomId };
    renderSendFilesList();
    openModal(elements.sendFilesModal);
}

function renderSendFilesList() {
    const target = chosenFilesChat;
    const encrypted = Boolean(target && target.roomId);
    const valid = chosenFiles.filter(f => !f.error).length;
    elements.sendFilesTitle.textContent = valid > 0
        ? `Отправить ${valid} ${plural(valid, ['файл', 'файла', 'файлов'])}`
        : 'Нечего отправить';
    const rows = chosenFiles.map((item, index) => {
        const li = document.createElement('li');
        li.className = 'send-file-row' + (item.error ? ' muted' : '');
        const info = document.createElement('div');
        const name = document.createElement('div');
        // У отклонённого файла показываем исходное имя — иначе не понять,
        // какой именно не подошёл; оно никуда не отправляется.
        name.textContent = item.error ? safeDisplayName(item.file.name) : outgoingFileName(item.file, item.mime, encrypted);
        const meta = document.createElement('small');
        meta.className = item.error ? 'field-hint' : 'muted';
        meta.textContent = item.error
            ? `${formatFileSize(item.file.size)} · не будет отправлен: ${item.error}`
            : formatFileSize(item.file.size);
        info.append(name, meta);
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'icon-btn icon-btn-sm';
        remove.title = 'Убрать из списка';
        remove.setAttribute('aria-label', `Убрать ${name.textContent} из списка`);
        remove.appendChild(icon('x', { size: 'sm' }));
        remove.addEventListener('click', () => {
            chosenFiles.splice(index, 1);
            if (chosenFiles.length === 0) {
                chosenFilesChat = null;
                closeModal(elements.sendFilesModal);
                return;
            }
            renderSendFilesList();
            const next = elements.sendFilesList.querySelectorAll('.send-file-row .icon-btn')[Math.min(index, chosenFiles.length - 1)];
            (next || elements.sendFilesBtn).focus({ preventScroll: true });
        });
        li.append(icon(item.error ? 'alert-triangle' : MimePolicy.fileIconName(item.mime)), info, remove);
        return li;
    });
    elements.sendFilesList.replaceChildren(...rows);
    elements.sendFilesBtn.disabled = valid === 0;
    setIconLabel(elements.sendFilesBtn, 'send', valid > 1 ? `Отправить ${valid}` : 'Отправить');
}

function sendChosenFiles() {
    const items = chosenFiles.filter(f => !f.error);
    const target = chosenFilesChat;
    chosenFiles = [];
    chosenFilesChat = null;
    closeModal(elements.sendFilesModal);
    if (!target || items.length === 0) return;
    if (target.chatId !== currentChatId) {
        showToast('Чат сменился — выберите файлы заново', 'error');
        return;
    }
    runUploadQueue(target.chatId, target.roomId, items);
}

async function runUploadQueue(chatId, roomId, items) {
    const queue = { chatId, roomId, xhr: null, cancelled: false };
    uploadQueue = queue;
    elements.attachBtn.disabled = true;
    let sent = 0;
    const errors = [];
    try {
        for (let i = 0; i < items.length && !queue.cancelled; i++) {
            let result;
            try {
                result = await sendOneFile(queue, items[i], i, items.length);
            } catch (err) {
                console.error('File upload failed:', err);
                result = { ok: false, message: 'Не удалось отправить файл' };
            }
            if (queue.cancelled) break;
            if (result.ok) {
                sent++;
            } else {
                errors.push(result.message || 'Не удалось отправить файл');
                // Шифрование недоступно — остальным файлам будет то же самое.
                if (result.fatal) break;
            }
        }
    } finally {
        if (uploadQueue === queue) uploadQueue = null;
        updateComposerForChat();
        hideUploadStatus();
    }
    const total = items.length;
    if (queue.cancelled) {
        if (queue.silent) return;
        showToast(sent > 0 ? `Загрузка отменена. Отправлено: ${sent} из ${total}` : 'Загрузка отменена', 'info');
    } else if (errors.length > 0) {
        const head = total > 1 ? `Не отправлено файлов: ${total - sent} из ${total}. ` : '';
        showToast(head + errors[errors.length - 1], 'error', 6000);
    } else if (total > 1) {
        showToast(`Отправлено ${sent} ${plural(sent, ['файл', 'файла', 'файлов'])}`, 'success');
    }
}

async function sendOneFile(queue, item, index, total) {
    const { chatId, roomId } = queue;
    const prefix = total > 1 ? `Файл ${index + 1} из ${total}: ` : '';
    setUploadStatus(`${prefix}подготовка…`, null);
    let client;
    try {
        client = await prepareOutgoing(chatId, roomId);
    } catch (err) {
        if (!(err instanceof E2eeBlockedError)) throw err;
        if (roomId && err.showsRetry) setRoomBlock(chatId, err.message);
        return { ok: false, fatal: true, message: err.message };
    }
    if (queue.cancelled) return { ok: false };

    setUploadStatus(`${prefix}удаление метаданных…`, null);
    let clean;
    try {
        clean = MediaSanitizer.sanitize(new Uint8Array(await item.file.arrayBuffer()), item.mime);
    } catch (err) {
        console.warn('MediaSanitizer: файл отклонён:', err);
        // userFacing — отказ с понятной пользователю причиной и советом (например,
        // PDF со сжатыми метаданными: «Печать → Сохранить как PDF»).
        return { ok: false, message: err && err.userFacing ? err.message : 'Файл повреждён или его формат не поддерживается' };
    }
    if (queue.cancelled) return { ok: false };

    // Шифротекст вложения от id сообщения не зависит: при 409 заново
    // шифруется только конверт (с новым mid), тот же шифротекст загружается снова.
    let localFile = null;
    let enc = null;
    if (client) {
        setUploadStatus(`${prefix}шифрование…`, null);
        try {
            enc = await client.encryptFile(clean);
        } catch (err) {
            console.error('E2EE: не удалось зашифровать файл:', err);
            return { ok: false, message: 'Не удалось зашифровать файл' };
        }
        if (enc.ciphertext.byteLength > MAX_UPLOAD_BYTES) {
            return { ok: false, message: 'Файл слишком большой для отправки с шифрованием (макс. 50 МБ)' };
        }
        localFile = { mime: item.mime, name: encryptedFileName(item.file, item.mime), size: enc.size, key: enc.key, iv: enc.iv };
    }
    if (queue.cancelled) return { ok: false };

    let encryptFailed = false;
    const outcome = await sendWithOutcomes({
        roomId,
        shouldStop: () => queue.cancelled,
        buildRequest: async (clientMessageId) => {
            const formData = new FormData();
            // Порядок полей важен: сервер читает proto/chatId/encrypted/clientMessageId/
            // envelope ДО того, как начнёт принимать сам файл (fileFilter), и проверяет
            // их раньше, чем файл попадёт на диск. Поле после файла — 400 client-outdated.
            formData.append('proto', String(PROTO_VERSION)); // признак версии - первым, до файла (14.1)
            formData.append('chatId', String(chatId));
            if (client) formData.append('encrypted', 'true');
            if (clientMessageId) formData.append('clientMessageId', clientMessageId);
            if (client) {
                try {
                    const envelope = await encryptForRoom(client, chatId, roomId, { type: 'file', ...localFile, caption: '' }, { messageId: clientMessageId });
                    formData.append('envelope', envelope);
                } catch (err) {
                    console.error('E2EE: не удалось зашифровать файл:', err);
                    encryptFailed = true;
                    return null;
                }
                formData.append('file', new Blob([enc.ciphertext], { type: 'application/octet-stream' }), 'blob');
            } else {
                formData.append('file', new Blob([clean], { type: item.mime }), MimePolicy.anonymousFileName(item.mime));
            }
            return formData;
        },
        post: async (formData) => {
            setUploadStatus(`${prefix}загрузка…`, 0);
            const result = await postFormDataWithProgress('/api/messages/file', formData, {
                onXhr: (xhr) => { queue.xhr = xhr; },
                onProgress: (p) => {
                    if (!queue.cancelled) setUploadStatus(`${prefix}загрузка ${Math.round(p * 100)}%`, p);
                },
            });
            queue.xhr = null;
            return result;
        },
    });
    if (encryptFailed) return { ok: false, message: 'Не удалось зашифровать файл' };
    const data = outcome.data;
    if (data.aborted || queue.cancelled) return { ok: false };
    if (!data.success) return { ok: false, message: sendFailureText(data, 'Не удалось отправить файл') };
    checkRoomKeyRotation(chatId, roomId);
    if (chatId === currentChatId && data.message) {
        const message = localFile
            ? { ...data.message, text: '', _file: localFile, _localBytes: clean }
            : data.message;
        if (appendMessage(message, true)) scrollToBottom();
        updateChatListOnMessage(message, true);
    }
    return { ok: true };
}

function setUploadStatus(text, progress) {
    elements.uploadStatus.classList.remove('hidden');
    elements.uploadStatusText.textContent = text;
    const pct = progress == null ? 0 : Math.max(0, Math.min(100, Math.round(progress * 100)));
    elements.uploadProgressBar.style.width = `${pct}%`;
    elements.uploadProgress.setAttribute('aria-valuenow', String(pct));
    if (progress == null) elements.uploadProgress.removeAttribute('aria-valuenow');
}

function hideUploadStatus() {
    elements.uploadStatus.classList.add('hidden');
    elements.uploadStatusText.textContent = '';
    elements.uploadProgressBar.style.width = '0%';
}

// byUser — нажата «Отменить»: итог покажет runUploadQueue. Иначе (выход из
// аккаунта) — тихо.
function cancelUploadQueue(byUser) {
    const queue = uploadQueue;
    if (!queue) return;
    queue.cancelled = true;
    queue.silent = !byUser;
    if (queue.xhr) {
        try { queue.xhr.abort(); } catch { /* запрос уже завершён */ }
    }
}

// ---- Перетаскивание файлов в ленту ----

let dragDepth = 0;

function dragHasFiles(e) {
    const types = e.dataTransfer && e.dataTransfer.types;
    return Boolean(types) && Array.from(types).includes('Files');
}

function canDropFiles() {
    return Boolean(currentUser && currentChatId) && !document.querySelector('.modal:not(.hidden)');
}

function showDropZone() {
    elements.dropZone.classList.remove('hidden');
    elements.dropZone.classList.add('is-active');
}

function hideDropZone() {
    dragDepth = 0;
    elements.dropZone.classList.add('hidden');
    elements.dropZone.classList.remove('is-active');
}

function setupDragAndDrop() {
    const area = elements.mainContent;
    area.addEventListener('dragenter', (e) => {
        if (!dragHasFiles(e) || !canDropFiles()) return;
        e.preventDefault();
        dragDepth++;
        showDropZone();
    });
    area.addEventListener('dragover', (e) => {
        if (!dragHasFiles(e) || !canDropFiles()) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
    });
    area.addEventListener('dragleave', (e) => {
        if (!dragHasFiles(e)) return;
        dragDepth = Math.max(0, dragDepth - 1);
        if (dragDepth === 0) hideDropZone();
    });
    area.addEventListener('drop', (e) => {
        if (!dragHasFiles(e)) return;
        e.preventDefault();
        const files = Array.from((e.dataTransfer && e.dataTransfer.files) || []);
        hideDropZone();
        if (canDropFiles()) onFilesChosen(files);
    });
    // Файл, брошенный мимо ленты, браузер открыл бы вместо приложения.
    window.addEventListener('dragover', (e) => {
        if (!dragHasFiles(e)) return;
        e.preventDefault();
        if (!area.contains(e.target) || !canDropFiles()) e.dataTransfer.dropEffect = 'none';
    });
    window.addEventListener('drop', (e) => {
        if (!dragHasFiles(e)) return;
        e.preventDefault();
        hideDropZone();
    });
}

// ---- Кнопка «вниз» ----
// Видна, пока пользователь прокручен вверх; бейдж — сколько новых чужих
// сообщений пришло за это время.
let jumpDownCount = 0;

function renderJumpDownBadge() {
    const n = jumpDownCount;
    elements.jumpDownBadge.classList.toggle('hidden', n === 0);
    elements.jumpDownBadge.textContent = n > 99 ? '99+' : String(n);
    const label = n > 0 ? `К последним сообщениям, новых: ${n}` : 'К последним сообщениям';
    elements.jumpDown.title = label;
    elements.jumpDown.setAttribute('aria-label', label);
}

function updateJumpDown() {
    const show = Boolean(currentChatId) && !isNearBottom();
    if (!show) jumpDownCount = 0;
    elements.jumpDown.classList.toggle('hidden', !show);
    renderJumpDownBadge();
}

function bumpJumpDown() {
    jumpDownCount++;
    elements.jumpDown.classList.remove('hidden');
    renderJumpDownBadge();
}

function resetJumpDown() {
    jumpDownCount = 0;
    elements.jumpDown.classList.add('hidden');
    renderJumpDownBadge();
}

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

init();
