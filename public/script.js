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
let editingMessageEncrypted = false; // флаг ИСХОДНОГО сообщения — при правке шифруем/не шифруем так же, а не по текущему тумблеру чата
let menuMessage = null;              // сообщение, для которого открыто контекстное меню

// Состояние открытого чата: история грузится страницами с конца.
let openChatSeq = 0;          // защита от гонок при быстром переключении чатов
let oldestMessageId = null;   // самый старый загруженный — курсор для ?before=
let hasMoreHistory = false;
let loadingHistory = false;
let lastSeenMessageId = 0;    // до какого id пользователь уже видел открытый чат
let chatListMode = 'chats';   // 'chats' | 'search' — что сейчас показано в сайдбаре
let membersChangedTimer = null; // debounce событий roomMembersChanged

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const MAX_FILES_PER_BATCH = 10;
const POW_TIMEOUT_MS = 60 * 1000;
const ANON_IDS_KEY = 'nyxo-anon-ids';
const FLASH_NOTICE_KEY = 'nyxo-notice';
const NOTIFY_PREF_PREFIX = 'nyxo-notify:';
const BOT_CHAT_PREFIX = 'nyxo-bot-chat:';
const E2EE_PREF_PREFIX = 'e2ee-enabled:';
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
    getChatCodeBtn: document.getElementById('get-chat-code-btn'),
    chatMenuBtn: document.getElementById('chat-menu-btn'),

    // ---- Сквозное шифрование: выключатель и баннер ----
    e2eeToggleBtn: document.getElementById('e2ee-toggle-btn'),
    e2eeBanner: document.getElementById('e2ee-banner'),
    e2eeBannerText: document.getElementById('e2ee-banner-text'),
    e2eeBannerBtn: document.getElementById('e2ee-banner-btn'),

    // ---- Участники и ключи ----
    membersKeysBtn: document.getElementById('members-keys-btn'),
    membersModal: document.getElementById('members-modal'),
    membersList: document.getElementById('members-list'),
    membersNote: document.getElementById('members-note'),

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
    recordBtn: document.getElementById('record-btn'),
    fileInput: document.getElementById('file-input'),

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

// Локальные флаги пользователя: тумблеры шифрования по чатам, согласие на
// уведомления и id чата с ботом. Тема оформления — настройка устройства, а
// не аккаунта, её не трогаем.
function removeLocalUserPrefs(userId) {
    try {
        const prefix = `${E2EE_PREF_PREFIX}${userId}:`;
        const doomed = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(prefix)) doomed.push(key);
        }
        doomed.push(NOTIFY_PREF_PREFIX + userId, BOT_CHAT_PREFIX + userId);
        doomed.forEach(key => localStorage.removeItem(key));
    } catch { /* хранилище недоступно */ }
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
// localStorage (уведомления, чат с ботом, тумблеры шифрования) и из имён баз
// IndexedDB nyxo-e2ee-<id>. Список баз знает indexedDB.databases(); где его
// нет (старый Firefox), остаётся список nyxo-anon-ids.
async function listLocalUserIds() {
    const ids = new Set(readAnonIds());
    try {
        // Ключ вида <префикс><id> или <префикс><id>:<хвост> (тумблеры шифрования).
        const prefixes = [NOTIFY_PREF_PREFIX, BOT_CHAT_PREFIX, E2EE_PREF_PREFIX];
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
// В комнатах шифрование включено по умолчанию: выключить его можно только
// явно (в localStorage тогда '0'). Если ключи устройства не удалось
// инициализировать (например, сервер ключей ответил ошибкой),
// шифрование недоступно: пользователь один раз видит предупреждение,
// тумблер показывает "недоступно", сообщения уходят открыто. Чат с ботом
// (без комнаты) никогда не шифруется — там некому передать ключ.

let e2eeClient = null;
let e2eeClientUserId = null;
let e2eeInitPromise = null;       // Promise<boolean>: true — ключи устройства готовы
let e2eeState = 'off';            // 'off' | 'pending' | 'ready' | 'unavailable'
let e2eeUnavailableWarned = false;

function getE2eeClient() {
    if (!currentUser || typeof E2EE === 'undefined') return null;
    if (!e2eeClient || e2eeClientUserId !== currentUser.id) {
        try {
            e2eeClient = E2EE.createClient({
                userId: currentUser.id,
                storage: E2EE.makeIndexedDbStorage('nyxo-e2ee-' + currentUser.id),
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

// Причина — чтобы было понятно, что делать: обновить браузер, открыть
// Nyxo не в окне инкогнито или ждать, пока починят сервер.
function describeE2eeInitError(err) {
    const name = err && err.name;
    const message = String((err && err.message) || '');
    if (err && err.code === 'key-server') {
        return err.status === 503 || err.status === 404
            ? 'Сквозное шифрование не настроено на сервере'
            : 'Сервер ключей шифрования сейчас не отвечает';
    }
    if (name === 'NotSupportedError' || /X25519|Ed25519|ML-KEM|mlkem|not supported|Unrecognized/i.test(message)) {
        return 'Этот браузер не поддерживает нужные алгоритмы шифрования (X25519/Ed25519) — обновите его';
    }
    if (name === 'InvalidStateError' || name === 'QuotaExceededError' || name === 'UnknownError' || /indexedDB/i.test(message)) {
        return 'Браузер не разрешает сохранить ключи шифрования (окно инкогнито или запрет хранилища)';
    }
    if (err instanceof TypeError && /fetch|network/i.test(message)) {
        return 'Нет связи с сервером ключей шифрования';
    }
    return 'Не удалось подготовить ключи шифрования';
}

function warnE2eeUnavailable(err) {
    if (e2eeUnavailableWarned) return;
    e2eeUnavailableWarned = true;
    showToast(`Сквозное шифрование недоступно: ${describeE2eeInitError(err).replace(/^./, c => c.toLowerCase())}. Сообщения будут отправляться без него`, 'error', 8000);
}

function initE2eeForCurrentUser() {
    const userId = currentUser ? currentUser.id : null;
    const client = getE2eeClient();
    if (!client) {
        e2eeState = 'unavailable';
        e2eeInitPromise = Promise.resolve(false);
        warnE2eeUnavailable();
        refreshE2eeUi();
        return e2eeInitPromise;
    }
    e2eeState = 'pending';
    // Показ приложения генерацией/загрузкой ключей не блокируется: кому
    // нужны ключи (отправка, расшифровка), тот дожидается этого promise.
    e2eeInitPromise = Promise.resolve()
        .then(() => client.init())
        .then(() => {
            if (!currentUser || currentUser.id !== userId) return false;
            e2eeState = 'ready';
            refreshE2eeUi();
            return true;
        }, (err) => {
            console.error('E2EE: инициализация ключей устройства не удалась:', err);
            if (!currentUser || currentUser.id !== userId) return false;
            e2eeState = 'unavailable';
            warnE2eeUnavailable(err);
            refreshE2eeUi();
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

function e2eePrefKey(chatId) {
    return `${E2EE_PREF_PREFIX}${currentUser ? currentUser.id : '0'}:${chatId}`;
}

// Выбор пользователя: отсутствие ключа = "включено".
function isE2eePreferred(chatId) {
    try {
        return localStorage.getItem(e2eePrefKey(chatId)) !== '0';
    } catch {
        return true;
    }
}

function setE2eePreferred(chatId, enabled) {
    try {
        localStorage.setItem(e2eePrefKey(chatId), enabled ? '1' : '0');
    } catch { /* окно инкогнито без localStorage — выбор не запомнится */ }
}

// Фактическое состояние: выбрано и доступно на этом устройстве.
function isE2eeActiveForChat(chatId) {
    return e2eeState !== 'unavailable' && e2eeState !== 'off' && isE2eePreferred(chatId);
}

function updateE2eeToggleUI(chatId, roomId) {
    const btn = elements.e2eeToggleBtn;
    const inRoom = Boolean(roomId);
    // Боту/одиночному чату групповое E2EE не подходит — прячем тумблер,
    // чтобы не обещать шифрование там, где его некому подтвердить.
    btn.classList.toggle('hidden', !inRoom);
    elements.membersKeysBtn.classList.toggle('hidden', !inRoom);
    elements.getChatCodeBtn.classList.toggle('hidden', !inRoom);
    btn.classList.remove('e2ee-active', 'e2ee-unavailable', 'is-active');
    if (!inRoom) {
        elements.messageInput.placeholder = 'Сообщение...';
        return;
    }
    let label;
    if (e2eeState === 'unavailable') {
        btn.replaceChildren(icon('alert-triangle'));
        btn.classList.add('e2ee-unavailable');
        btn.setAttribute('aria-pressed', 'false');
        label = 'Сквозное шифрование недоступно — нажмите, чтобы повторить попытку';
        elements.messageInput.placeholder = 'Сообщение (без шифрования)...';
    } else {
        const enabled = isE2eePreferred(chatId);
        btn.replaceChildren(icon(enabled ? 'lock' : 'unlock'));
        btn.classList.toggle('e2ee-active', enabled);
        btn.classList.toggle('is-active', enabled);
        btn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
        label = enabled ? 'Сквозное шифрование включено — нажмите, чтобы выключить' : 'Сквозное шифрование выключено — нажмите, чтобы включить';
        elements.messageInput.placeholder = enabled ? 'Зашифрованное сообщение...' : 'Сообщение (без шифрования)...';
    }
    btn.title = label;
    btn.setAttribute('aria-label', label);
}

function refreshE2eeUi() {
    if (!currentChatId) return;
    updateE2eeToggleUI(currentChatId, currentRoomId);
    updatePlaintextMarkers();
}

// ---- Участники комнаты, ключи, служебные строки ----

const roomParticipants = new Map();          // roomId -> [{id, username}] (последний известный состав)
const pendingIdentityChanges = new Map();    // userId -> username (для баннера открытой комнаты)
const warnedRooms = new Set();               // о каких комнатах уже предупреждали, что не все получили ключ

function rememberRoomParticipants(roomId, participants) {
    roomParticipants.set(Number(roomId), Array.isArray(participants) ? participants : []);
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
    if (!currentRoomId || names.length === 0) {
        elements.e2eeBanner.classList.add('hidden');
        elements.e2eeBannerText.textContent = '';
        return;
    }
    elements.e2eeBannerText.textContent = names.length === 1
        ? `У участника ${names[0]} сменился ключ шифрования. Сообщения ему не отправляются, пока вы не проверите код безопасности`
        : `У участников ${names.join(', ')} сменились ключи шифрования. Сообщения им не отправляются, пока вы не проверите коды безопасности`;
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
    let statusesKnown = true;
    for (const peer of others) {
        const status = await peerIdentityStatus(client, peer.id);
        if (status === null) statusesKnown = false;
        if (status === 'changed') changed.set(Number(peer.id), peer.username || participantName(roomId, peer.id));
    }
    if (Number(roomId) !== Number(currentRoomId)) return;
    // Если статусы узнать не удалось, ничего из баннера не убираем.
    if (statusesKnown) pendingIdentityChanges.clear();
    changed.forEach((name, userId) => pendingIdentityChanges.set(userId, name));
    renderIdentityBanner();
}

function handleRoomSessionResult(roomId, result) {
    if (!result || Number(roomId) !== Number(currentRoomId)) return;
    const warnings = Array.isArray(result.warnings) ? result.warnings : [];
    const failedIds = new Set(warnings.filter(w => w && w.userId != null).map(w => Number(w.userId)));
    const changedIds = new Set((result.identityChanges || []).map(c => Number(c.userId)));
    const newMembers = Array.isArray(result.newMembers) ? result.newMembers : [];
    const removedMembers = Array.isArray(result.removedMembers) ? result.removedMembers : [];

    // Участники со сменившимся ключом тоже попадают в warnings, но о них
    // говорит баннер — здесь они не "без шифрования".
    const delivered = newMembers.filter(m => !failedIds.has(Number(m.id)) && !changedIds.has(Number(m.id)));
    const undelivered = newMembers.filter(m => failedIds.has(Number(m.id)) && !changedIds.has(Number(m.id)));
    if (delivered.length > 0) {
        const text = `В чат вошли: ${joinNames(delivered)}, им передан ключ шифрования`;
        appendSystemNotice(roomId, text, 'key');
        showToast(text, 'info');
    }
    if (undelivered.length > 0) {
        appendSystemNotice(roomId, `В чат вошли: ${joinNames(undelivered)}, но ключ шифрования им передать не удалось — они пока не смогут читать зашифрованные сообщения`, 'alert-triangle');
    }
    if (removedMembers.length > 0) {
        const verb = removedMembers.length === 1 ? 'покинул(а)' : 'покинули';
        const text = `${joinNames(removedMembers)} ${verb} чат${result.rotated ? ' — ключ шифрования обновлён' : ''}`;
        appendSystemNotice(roomId, text, 'key');
        showToast(text, 'info');
    }

    const newIds = new Set(newMembers.map(m => Number(m.id)));
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

async function runRoomSession(chatId, roomId) {
    const client = await getReadyE2eeClient();
    if (!client || !isE2eeActiveForChat(chatId)) return null;
    const part = await api(`/api/chats/${chatId}/participants`);
    if (!part.success || !part.roomId || Number(part.roomId) !== Number(roomId)) return null;
    rememberRoomParticipants(roomId, part.participants);
    let result;
    try {
        result = await client.ensureRoomSession(chatId, roomId, part.participants);
    } catch (err) {
        console.error('E2EE: не удалось подготовить сессию комнаты:', err);
        return null;
    }
    if (result && Array.isArray(result.warnings) && result.warnings.length > 0) {
        console.warn('E2EE: не со всеми участниками установлен защищённый канал:', result.warnings);
    }
    handleRoomSessionResult(roomId, result);
    await refreshIdentityChanges(client, roomId, part.participants, result && result.identityChanges);
    return result;
}

function ensureE2eeRoomSession(chatId, roomId) {
    const run = () => runRoomSession(chatId, roomId).catch((err) => {
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

// Вызывается перед отправкой. Возвращает клиент, если сообщение нужно
// шифровать, null — если отправлять открыто (чат без комнаты, шифрование
// выключено пользователем или недоступно на устройстве). Бросает Error с
// текстом для пользователя, если отправку нужно прервать.
async function prepareOutgoingE2ee(chatId, roomId) {
    if (!roomId || !isE2eePreferred(chatId) || e2eeState === 'unavailable') return null;
    const wasPending = e2eeState === 'pending';
    const client = await getReadyE2eeClient();
    if (!client) {
        // Пользователь набирал сообщение, рассчитывая на шифрование, а оно
        // только что оказалось недоступным. Молча отправлять открытым
        // текстом нельзя — пусть отправит ещё раз, уже зная об этом.
        if (wasPending) throw new Error('Сквозное шифрование недоступно — сообщение не отправлено. Отправьте ещё раз, чтобы отправить без шифрования');
        return null;
    }
    // Sender Key комнаты должен быть создан и разослан участникам до
    // первого конверта; если последний запуск не удался — пробуем снова.
    let session = null;
    if (lastRoomSession && lastRoomSession.roomId === roomId) session = await lastRoomSession.promise;
    if (!session || session.ok === false) await ensureE2eeRoomSession(chatId, roomId);
    return client;
}

// Тексты для причин отказа decryptIncoming (res.reason из e2ee.js). Причина,
// которой здесь нет, получает общий текст. Новая причина — новая строка.
const E2EE_FAILURE_TEXTS = {
    replay: 'Повтор старого сообщения (возможна подмена сервером)',
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
    return res;
}

async function decryptMessageInPlace(message, roomId) {
    if (message.encrypted) {
        if (roomId) {
            const res = await decryptEnvelope(roomId, message.user_id, message.text, message.id);
            if (res.ok) {
                message.text = res.text || '';
                if (res.file) message._file = res.file;
            } else {
                message.text = e2eeFailureText(res.reason);
                message._e2eeFailed = true;
            }
        } else {
            message.text = 'Зашифрованное сообщение';
            message._e2eeFailed = true;
        }
    }
    if (message.reply_to && message.reply_to.encrypted && !message.reply_to.deleted) {
        const replyRes = roomId
            ? await decryptEnvelope(roomId, message.reply_to.sender_id, message.reply_to.text, message.reply_to.id)
            : { ok: false };
        message.reply_to.text = decryptedSummary(replyRes);
    }
    return message;
}

async function decryptMessagesInPlace(messages, roomId) {
    for (const m of messages) await decryptMessageInPlace(m, roomId);
    return messages;
}

async function onE2eeToggleClick() {
    if (!currentChatId || !currentRoomId) return;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const btn = elements.e2eeToggleBtn;

    if (e2eeState === 'unavailable') {
        // Повторная попытка: сервер ключей мог просто перезапускаться.
        btn.disabled = true;
        btn.replaceChildren(icon('loader', { className: 'spin' }));
        const ok = await initE2eeForCurrentUser();
        btn.disabled = false;
        refreshE2eeUi();
        if (!ok) {
            showToast('Сквозное шифрование по-прежнему недоступно: сервер ключей не отвечает', 'error');
            return;
        }
        showToast('Сквозное шифрование снова доступно', 'success');
        if (chatId === currentChatId) {
            await syncE2eeKeyShares(chatId, roomId);
            ensureE2eeRoomSession(chatId, roomId);
        }
        return;
    }

    const enabling = !isE2eePreferred(chatId);
    if (!enabling) {
        setE2eePreferred(chatId, false);
        refreshE2eeUi();
        showToast('Шифрование выключено: новые сообщения этого чата будут видны серверу', 'info', 5000);
        return;
    }

    setE2eePreferred(chatId, true);
    btn.disabled = true;
    btn.replaceChildren(icon('loader', { className: 'spin' }));
    const result = await ensureE2eeRoomSession(chatId, roomId);
    btn.disabled = false;
    if (chatId !== currentChatId) return; // пользователь уже ушёл в другой чат
    if (!result || result.ok === false) {
        // Ключ не удалось даже создать/разослать — не обещаем шифрование,
        // которого собеседники не смогут прочитать.
        setE2eePreferred(chatId, false);
        refreshE2eeUi();
        showToast('Не удалось включить шифрование: не получилось подготовить ключи', 'error');
        return;
    }
    refreshE2eeUi();
    showToast('Шифрование включено для этого чата', 'success');
}

// ==================== Файлы: белый список, очистка, шифрование ====================

const MIME_ALIASES = {
    'image/jpg': 'image/jpeg',
    'image/pjpeg': 'image/jpeg',
    'audio/mp3': 'audio/mpeg',
    'audio/x-wav': 'audio/wav',
    'audio/wave': 'audio/wav',
    'audio/vnd.wave': 'audio/wav',
    'audio/x-pn-wav': 'audio/wav',
};

// Обезличенные имена — как у сервера для незашифрованных вложений (К6):
// исходное имя файла часто содержит имя человека, дату, номер телефона.
const ANONYMOUS_FILE_NAMES = {
    'image/jpeg': 'photo.jpg',
    'image/png': 'photo.png',
    'image/gif': 'photo.gif',
    'image/webp': 'photo.webp',
    'video/mp4': 'video.mp4',
    'video/quicktime': 'video.mov',
    'video/webm': 'video.webm',
    'audio/webm': 'audio.webm',
    'audio/ogg': 'audio.ogg',
    'audio/mpeg': 'audio.mp3',
    'audio/wav': 'audio.wav',
    'application/pdf': 'document.pdf',
    'text/plain': 'text.txt',
};

function detectFileMime(file) {
    let mime = String(file.type || '').toLowerCase().split(';')[0].trim();
    mime = MIME_ALIASES[mime] || mime;
    if (!mime) {
        const name = String(file.name || '').toLowerCase();
        if (name.endsWith('.txt')) mime = 'text/plain';
        else if (name.endsWith('.pdf')) mime = 'application/pdf';
    }
    return mime;
}

// Только точные MIME из белого списка К3 (синонимы вроде image/jpg
// приводятся к ним заранее, в detectFileMime).
function isSupportedMime(mime) {
    return typeof MediaSanitizer !== 'undefined' && Array.isArray(MediaSanitizer.SUPPORTED_TYPES)
        && MediaSanitizer.SUPPORTED_TYPES.includes(mime);
}

function isMediaMime(mime) {
    return /^(image|video|audio)\//.test(mime);
}

function anonymousFileName(mime) {
    return ANONYMOUS_FILE_NAMES[mime] || 'file';
}

// Имя внутри E2EE-конверта: у фото/видео/аудио — обезличенное, у
// документов — исходное (без него документ не отличить от других), но
// сервер его не видит — только участники комнаты.
function encryptedFileName(file, mime) {
    return isMediaMime(mime) ? anonymousFileName(mime) : safeDisplayName(file.name || anonymousFileName(mime));
}

// MIME из конверта задаёт отправитель, то есть любой участник комнаты.
// Всё вне белого списка отдаётся как octet-stream: blob: URL живёт в
// origin приложения, и, например, text/html в нём был бы готовой XSS.
function safeBlobMime(mime) {
    return isSupportedMime(mime) ? mime : 'application/octet-stream';
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

// Иконка по MIME: для списка отправляемых файлов и ссылок на документы.
function fileIconName(mime) {
    if (/^image\//.test(mime)) return 'image';
    if (/^video\//.test(mime)) return 'video';
    if (/^audio\//.test(mime)) return 'music';
    if (mime === 'text/plain' || mime === 'application/pdf') return 'file-text';
    return 'file';
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
    a.append(icon(fileIconName(mime)), label, icon('download', { size: 'sm' }));
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
    if (mime.startsWith('audio/')) {
        const audio = document.createElement('audio');
        audio.src = url;
        audio.controls = true;
        audio.preload = 'metadata';
        audio.className = 'message-audio';
        return audio;
    }
    // Документы только скачиваются (download), а не открываются во вкладке.
    return createDocumentLink(url, name, mime);
}

function showDecryptedAttachment(box, message, bytes) {
    const file = message._file;
    const mime = safeBlobMime(file.mime);
    const name = safeDisplayName(file.name || anonymousFileName(mime));
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
    openNewChatModal();
    elements.joinChatCode.value = NyxoInvite.formatInviteCode(invite.code);
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
    warnedRooms.clear();
    initE2eeForCurrentUser();
    showApp();
    // Новое соединение = новое рукопожатие с актуальной кукой сессии.
    if (socket.connected) socket.disconnect();
    socket.connect();
    startKeepalive();
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

// Сервер сам закрыл сокет ('io server disconnect'): socket.io в этом случае
// не переподключается. Проверяем вход; если сессия жива — подключаемся
// заново, но не чаще раза в 5 секунд (иначе сервер, который по какой-то
// причине закрывает сокет каждый раз, получил бы цикл из запросов).
let lastServerDisconnectAt = 0;
async function recoverFromServerDisconnect() {
    if (!currentUser) return;
    const userId = currentUser.id;
    const tooSoon = Date.now() - lastServerDisconnectAt < 5000;
    lastServerDisconnectAt = Date.now();
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
    currentChatId = null;
    currentRoomId = null;
    oldestMessageId = null;
    hasMoreHistory = false;
    lastSeenMessageId = 0;
    openChatSeq++;
    releaseChatResources();
    elements.chatHeader.classList.add('hidden');
    elements.messageInputContainer.classList.add('hidden');
    elements.emptyState.classList.remove('hidden');
    elements.chatMessages.replaceChildren();
    elements.sidebar.classList.remove('hidden-mobile');
    clearReply();
    editingMessageId = null;
    editingMessageEncrypted = false;
    setActiveChatItem(null, null);
}

// Всё, что привязано к открытому чату и должно исчезнуть при его смене:
// расшифрованные вложения (object URL), очередь их расшифровки, баннер
// смены ключей, отложенные служебные строки, полоса заявок, кнопка «вниз».
function releaseChatResources() {
    resetAttachmentDecrypts();
    pendingIdentityChanges.clear();
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
    socket.disconnect();
    currentUser = null;
    e2eeClient = null;
    e2eeClientUserId = null;
    e2eeInitPromise = null;
    e2eeState = 'off';
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
    if (chatListMode === 'chats') loadChats();
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
        return { success: false, message: `Ошибка сервера (HTTP ${res.status})` };
    }
    if (!data || typeof data !== 'object') return { success: false, message: `Ошибка сервера (HTTP ${res.status})` };
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
        return { success: false, message: 'Нет соединения с сервером' };
    }
    const data = await res.json().catch(() => ({ success: false, message: `Ошибка сервера (HTTP ${res.status})` }));
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
        xhr.onerror = () => resolve({ success: false, message: 'Нет соединения с сервером' });
        xhr.onload = async () => {
            let data;
            try {
                data = JSON.parse(xhr.responseText);
            } catch {
                data = { success: false, message: `Ошибка сервера (HTTP ${xhr.status})` };
            }
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
    elements.newChatBtn.addEventListener('click', openNewChatModal);
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
    elements.joinChatCode.addEventListener('input', hideJoinPreview);
    elements.joinConfirmBtn.addEventListener('click', joinChat);
    elements.joinCancelBtn.addEventListener('click', hideJoinPreview);

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

// Сквозное шифрование в шапке чата: выключатель, окно «Участники и ключи»,
// баннер о смене ключа собеседника.
function setupE2eeListeners() {
    elements.e2eeToggleBtn.addEventListener('click', onE2eeToggleClick);
    elements.membersKeysBtn.addEventListener('click', openMembersModal);
    elements.e2eeBannerBtn.addEventListener('click', openMembersModal);
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
        if (code) copyText(inviteLink(code), 'Ссылка скопирована', 'Не удалось скопировать ссылку');
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
        editingMessageEncrypted = Boolean(message.encrypted);
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

// Поиск по чатам и сообщениям: запрос уходит на сервер через 300 мс после
// последнего нажатия клавиши.
function setupSearchListeners() {
    let searchTimeout;
    elements.searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(performSearch, 300);
    });
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
    });

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

    socket.on('messageEdited', async ({ id, text, chat_id, room_id, encrypted, user_id }) => {
        if (!belongsToCurrentChat(chat_id, room_id)) return;
        const roomId = currentRoomId;
        const seq = openChatSeq;
        let displayText = text;
        let failed = false;
        if (encrypted) {
            const res = await decryptEnvelope(roomId, user_id, text, id);
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
    socket.on('messagesRead', ({ chat_id, room_id, up_to_id } = {}) => {
        if (!belongsToCurrentChat(chat_id, room_id)) return;
        const upTo = Number(up_to_id);
        if (!upTo) return;
        elements.chatMessages.querySelectorAll('.message.sent').forEach((el) => {
            if (Number(el.dataset.messageId) <= upTo) {
                if (el._message) el._message.status = 'read';
                renderMessageStatus(el);
            }
        });
    });

    // Состав комнаты изменился (вступление по коду, одобренная заявка,
    // выход): забираем новые key-share и пересобираем сессию — новому
    // участнику уходит наш Sender Key, после ухода свой ключ ротируется.
    socket.on('roomMembersChanged', ({ roomId } = {}) => {
        if (!currentUser || !roomId) return;
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
        if (chatListMode === 'chats') renderChatList();
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
function inviteLink(code) {
    return `${location.origin}/#join=${encodeURIComponent(code)}`;
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

    const shown = usable && drawInviteQr(inviteLink(rawCode));
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
    else if (!disabled) lines.push(inviteStatusLine('unlock', 'Вступление — без одобрения, сразу по коду'));
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
    renderInvite(data);
    openModal(elements.inviteModal);
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
    const body = {
        ttlSeconds: Number(elements.inviteTtl.value) || 604800,
        maxMembers: max.value,
        requireApproval: elements.inviteApproval.checked,
    };
    elements.rotateInviteBtn.disabled = true;
    const data = await api(`/api/chats/${chatId}/invite/rotate`, { method: 'POST', body: JSON.stringify(body) });
    elements.rotateInviteBtn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось создать новый код', 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    renderInvite({
        ...(inviteState || {}),
        code: data.code,
        expiresAt: data.expiresAt,
        expired: false,
        disabled: false,
        maxMembers: data.maxMembers !== undefined ? data.maxMembers : body.maxMembers,
        requireApproval: data.requireApproval !== undefined ? data.requireApproval : body.requireApproval,
    });
    showToast(hadCode ? 'Создан новый код. Старый больше не действует' : 'Создан новый код', 'success', 5000);
}

async function disableInviteCode() {
    if (!currentChatId || elements.disableInviteBtn.disabled) return;
    if (!confirm('Отключить приглашение? Текущий код сразу перестанет действовать. Новый код можно создать в любой момент.')) return;
    const chatId = currentChatId;
    elements.disableInviteBtn.disabled = true;
    const data = await api(`/api/chats/${chatId}/invite/disable`, { method: 'POST' });
    elements.disableInviteBtn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось отключить приглашение', 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    renderInvite({ ...(inviteState || {}), code: null, expiresAt: null, disabled: true, expired: false });
    showToast('Приглашение отключено', 'success');
}

// ==================== Вступление по коду ====================

let joinPreviewCode = null;

function openNewChatModal() {
    hideJoinPreview();
    openModal(elements.newChatModal);
    loadMyRequests();
}

function hideJoinPreview() {
    joinPreviewCode = null;
    elements.joinPreview.classList.add('hidden');
}

function readJoinCode() {
    return elements.joinChatCode.value.replace(/[\s-]+/g, '').toUpperCase();
}

// Шаг 1: предпросмотр — название, число участников, нужно ли одобрение.
async function previewJoin() {
    const code = readJoinCode();
    if (!code) return showToast('Введите код', 'error');
    const btn = elements.joinChatBtn;
    if (btn.disabled) return;
    btn.disabled = true;
    const data = await api('/api/chats/join/preview', { method: 'POST', body: JSON.stringify({ code }) });
    btn.disabled = false;
    if (!data.success) {
        hideJoinPreview();
        showToast(data.message || 'Код недействителен', 'error');
        return;
    }
    joinPreviewCode = code;
    elements.joinPreviewName.textContent = data.roomName || 'Группа';
    const count = Number(data.memberCount) || 0;
    elements.joinPreviewMeta.textContent = count > 0 ? `${count} ${plural(count, ['участник', 'участника', 'участников'])}` : '';
    elements.joinPreviewApproval.classList.toggle('hidden', !data.requireApproval);
    setIconLabel(elements.joinConfirmBtn, data.requireApproval ? 'send' : 'log-in', data.requireApproval ? 'Отправить заявку' : 'Вступить');
    elements.joinPreview.classList.remove('hidden');
    elements.joinConfirmBtn.focus({ preventScroll: true });
}

// Шаг 2: вступление (или заявка, если группе нужно одобрение).
async function joinChat() {
    const code = joinPreviewCode || readJoinCode();
    if (!code) return showToast('Введите код', 'error');
    const btn = elements.joinConfirmBtn;
    if (btn.disabled) return;
    btn.disabled = true;
    const data = await api('/api/chats/join', {
        method: 'POST',
        body: JSON.stringify({ code }),
    });
    btn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось вступить', 'error');
        return;
    }
    elements.joinChatCode.value = '';
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
    card.append(icon('hourglass'), body, cancel);
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
    return li;
}

async function decideJoinRequest(req, approve, row, buttons) {
    buttons.forEach((b) => { b.disabled = true; });
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const data = await api(`/api/join-requests/${encodeURIComponent(req.id)}/${approve ? 'approve' : 'deny'}`, { method: 'POST' });
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

const IDENTITY_STATUS = {
    verified: { text: 'проверен', cls: 'verified', icon: 'shield-check' },
    unverified: { text: 'не проверен', cls: 'unverified', icon: 'shield' },
    changed: { text: 'ключ изменился', cls: 'changed', icon: 'alert-triangle' },
    unknown: { text: 'нет E2EE', cls: 'unknown', icon: 'unlock' },
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
    } else if (status === 'unverified') {
        const mark = document.createElement('button');
        mark.className = 'btn btn-primary btn-sm';
        setIconLabel(mark, 'shield-check', 'Отметить как проверенный');
        mark.addEventListener('click', () => markVerified(row, peer, ctx, mark));
        actions.appendChild(mark);
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
    if (ctx.isSelf) return li;

    const statusEl = document.createElement('span');
    info.appendChild(statusEl);
    li._statusEl = statusEl;
    setMemberStatus(li, status);
    if (!ctx.client || status === 'unknown') return li;

    const details = document.createElement('div');
    details.className = 'member-details hidden';
    details.id = `member-details-${peer.id}`;
    li.details = details;
    const toggle = document.createElement('button');
    toggle.className = 'member-code-btn';
    toggle.textContent = status === 'changed' ? 'Проверить' : 'Код';
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
    if (status === 'changed') toggle.click();
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
    const others = part.participants.filter(p => Number(p.id) !== Number(currentUser.id));

    const statuses = new Map();
    if (client && others.length > 0) {
        try {
            const list = await client.checkPeerIdentities(others.map(p => p.id));
            (list || []).forEach(s => statuses.set(Number(s.userId), s.status));
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
    fragment.appendChild(createMemberRow(me, null, { ...ctx, isSelf: true }));
    const changed = [];
    others.forEach((peer) => {
        const status = client ? (statuses.get(Number(peer.id)) || 'unknown') : 'unknown';
        if (status === 'changed') changed.push({ userId: peer.id, username: peer.username });
        fragment.appendChild(createMemberRow(peer, status, ctx));
    });
    elements.membersList.replaceChildren(fragment);
    if (changed.length > 0) addIdentityChanges(roomId, changed);
}

// ==================== Список чатов ====================

function isOwnMessage(message) {
    // Ответы бота хранятся с user_id владельца чата и sent = 0 — раньше
    // они отображались как собственные сообщения пользователя.
    return Boolean(currentUser) && message.user_id === currentUser.id && Number(message.sent) !== 0;
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
    if (message.encrypted) return { icon: 'lock', text: 'Зашифрованное сообщение' };
    const text = message.text || message.last_message || '';
    return message.file_url ? { icon: 'paperclip', text: text || 'Файл' } : { icon: null, text };
}

function chatLastPreview(chat) {
    if (chat.last_message_encrypted) return { icon: 'lock', text: 'Зашифрованное сообщение' };
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

function createChatItem({ id, roomId, name, isBot, preview, unread, onClick, meta }) {
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
    nameEl.textContent = name;
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

function createChatItemFromMeta(chat) {
    return createChatItem({
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
    if (chatListMode !== 'chats') return;
    const focused = document.activeElement && document.activeElement.closest
        ? document.activeElement.closest('#chats-list .chat-item') : null;
    const focusedId = focused ? focused.dataset.id : null;

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
    meta.last_message = message.encrypted ? null : (message.text || '');
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
    elements.expiryHint.textContent = currentRoomId
        ? 'Срок действует для новых сообщений всех участников группы. Уже отправленные сообщения не изменятся.'
        : 'Срок действует для новых сообщений этого чата. Уже отправленные сообщения не изменятся.';
    syncExpiryRadios();
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
    renderChatList();
    if (chatId === currentChatId) {
        updateChatIndicators();
        syncExpiryRadios();
    }
    showToast(value ? `Исчезающие сообщения: ${expiryLabel(value)}` : 'Исчезающие сообщения выключены', 'success');
}

// Подпись под названием чата: у группы — число участников (из списка
// чатов), у бота — «Бот», иначе — в сети / не в сети.
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
    elements.chatStatus.textContent = Number(meta.is_bot) ? 'Бот' : (currentRoomId ? 'Группа' : (online ? 'В сети' : 'Не в сети'));
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
}

// ==================== Открытый чат ====================

// avatar из списка чатов больше не используется: аватар в монохроме —
// буква или иконка бота (renderAvatar). Параметр оставлен ради вызовов.
async function openChat(chatId, roomId, name, avatar, online, isBot) {
    const seq = ++openChatSeq;
    releaseChatResources();
    hideChatItemMenu();
    currentChatId = chatId;
    currentRoomId = roomId || null;
    const room = currentRoomId;
    oldestMessageId = null;
    hasMoreHistory = false;
    loadingHistory = false;
    lastSeenMessageId = 0;
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
    updateE2eeToggleUI(chatId, room);
    updateChatIndicators();
    if (room) loadJoinRequestsCount();

    // История запрашивается параллельно с синхронизацией E2EE-ключей, а не
    // после неё. Расшифровка всё равно ждёт ключи: только что полученные
    // Sender Key других участников должны быть известны локально. Зависший
    // сервер ключей не должен навсегда оставлять чат пустым — ждём не
    // дольше 15 секунд.
    const messagesPromise = api(`/api/messages/${chatId}`);
    if (room) {
        await withTimeout(syncE2eeKeyShares(chatId, room), 15000, null);
        // Сессия комнаты (свой ключ новым участникам, ротация после ухода)
        // — в фоне: для показа истории она не нужна, а отправка её дождётся.
        if (seq === openChatSeq) ensureE2eeRoomSession(chatId, room);
    }
    const data = await messagesPromise;
    if (seq !== openChatSeq) return; // пользователь уже открыл другой чат
    if (!data.success) {
        showToast(data.message || 'Не удалось загрузить сообщения', 'error');
        flushSystemNotices();
        return;
    }

    await decryptMessagesInPlace(data.messages, room);
    if (seq !== openChatSeq) return;
    renderMessages(data.messages, 'replace');
    hasMoreHistory = Boolean(data.hasMore);
    lastSeenMessageId = data.messages.length ? data.messages[data.messages.length - 1].id : 0;
    flushSystemNotices();
    scrollToBottom();

    // Сокет уже подписан на все чаты при подключении; это — страховка для
    // чата, созданного/добавленного до переподключения.
    socket.emit('joinChat', room ? `room:${room}` : `chat:${chatId}`);
}

async function loadOlderMessages() {
    if (!hasMoreHistory || loadingHistory || !currentChatId || !oldestMessageId) return;
    loadingHistory = true;
    const seq = openChatSeq;
    const roomId = currentRoomId;
    try {
        const data = await api(`/api/messages/${currentChatId}?before=${oldestMessageId}`);
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

    if (data.messages.length > 0) {
        const pageIds = new Set(data.messages.map(m => Number(m.id)));
        const minId = data.hasMore ? Number(data.messages[0].id) : 0;
        const maxId = Number(data.messages[data.messages.length - 1].id);
        elements.chatMessages.querySelectorAll('.message[data-message-id]').forEach((el) => {
            const id = Number(el.dataset.messageId);
            if (id >= minId && id <= maxId && !pageIds.has(id)) removeMessageElement(id);
        });
    }

    const fresh = data.messages.filter(m => !elements.chatMessages.querySelector(`[data-message-id="${m.id}"]`));
    if (fresh.length === 0) return;
    await decryptMessagesInPlace(fresh, roomId);
    if (seq !== openChatSeq) return;
    const stick = isNearBottom();
    fresh.forEach(m => appendMessage(m, false));
    if (stick) scrollToBottom();
    else fresh.forEach((m) => { if (!isOwnMessage(m)) bumpJumpDown(); });
    lastSeenMessageId = Math.max(lastSeenMessageId, ...fresh.map(m => m.id));
}

function renderMessages(messages, mode) {
    const fragment = document.createDocumentFragment();
    messages.forEach(msg => fragment.appendChild(createMessageElement(msg, false)));
    if (mode === 'prepend') elements.chatMessages.prepend(fragment);
    else elements.chatMessages.replaceChildren(fragment);
    if (messages.length > 0 && (mode !== 'prepend' || oldestMessageId === null || messages[0].id < oldestMessageId)) {
        oldestMessageId = messages[0].id;
    }
}

// Возвращает false, если сообщение уже на экране (например, пришло и в
// ответе POST, и по сокету).
function appendMessage(message, animate) {
    if (elements.chatMessages.querySelector(`[data-message-id="${message.id}"]`)) return false;
    elements.chatMessages.appendChild(createMessageElement(message, animate));
    if (oldestMessageId === null) oldestMessageId = message.id;
    return true;
}

function formatReplyQuote(reply) {
    if (reply.deleted) return 'Сообщение удалено';
    return `${reply.sender_username || 'Неизвестно'}: ${(reply.text || '').substring(0, 60)}`;
}

// Обновляет цитаты на сообщение messageId в других сообщениях ленты.
function updateReplyQuotes(messageId, update) {
    elements.chatMessages.querySelectorAll('.message').forEach((el) => {
        const m = el._message;
        if (!m || !m.reply_to || Number(m.reply_to.id) !== Number(messageId)) return;
        update(m.reply_to);
        const small = el.querySelector('.reply-to small');
        if (small) small.textContent = formatReplyQuote(m.reply_to);
    });
}

function removeMessageElement(messageId) {
    const el = elements.chatMessages.querySelector(`[data-message-id="${messageId}"]`);
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
}

function applyMessageEdit(messageId, displayText, failed = false) {
    const bubble = elements.chatMessages.querySelector(`[data-message-id="${messageId}"]`);
    if (bubble) {
        if (bubble._message) {
            bubble._message.text = displayText; // чтобы меню "Ответить/Изменить" видело новый текст
            bubble._message._e2eeFailed = failed;
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

function lastRenderedMessageId() {
    let el = elements.chatMessages.lastElementChild;
    while (el && !el.dataset.messageId) el = el.previousElementSibling; // служебные строки пропускаем
    return el ? Number(el.dataset.messageId) : 0;
}

// Отмечаем прочитанным то, что пользователь реально видит: вкладка
// активна, чат прокручен к концу. Запрос — не чаще раза в секунду.
let markReadTimer = null;
function markVisibleMessagesRead() {
    if (!currentChatId || document.visibilityState !== 'visible' || !isNearBottom()) return;
    const lastId = lastRenderedMessageId();
    if (!lastId || lastId <= lastSeenMessageId) return;
    lastSeenMessageId = lastId;
    const chatId = currentChatId;
    clearTimeout(markReadTimer);
    markReadTimer = setTimeout(() => {
        api(`/api/chats/${chatId}/read`, { method: 'POST', body: JSON.stringify({ upToId: lastId }) });
    }, 1000);
}

// ---- Отрисовка сообщения ----

// Элементы с файлом (img/video/audio/a) собираются через DOM API, а не через
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
    if (message_type === 'audio') {
        const audio = document.createElement('audio');
        audio.src = file_url;
        audio.controls = true;
        audio.preload = 'metadata';
        audio.className = 'message-audio';
        return audio;
    }
    return createDocumentLink(file_url, file_name || 'Файл', String(message.file_type || ''), { newTab: true });
}

function createAttachmentElement(message) {
    if (!message.encrypted) return message.file_url ? createFileAttachmentElement(message) : null;
    // Зашифрованное вложение: ключ файла — внутри E2EE-конверта. Если сам
    // конверт не расшифровался, текст сообщения уже говорит об этом, а
    // ссылка на шифротекст (.bin) пользователю ни к чему.
    return message._file ? createEncryptedAttachmentElement(message) : null;
}

function createPlaintextLabel() {
    const label = iconText('span', 'plaintext-label', 'unlock', 'без сквозного шифрования', { size: 'sm' });
    label.title = 'Это сообщение отправлено без сквозного шифрования — его содержимое видно серверу';
    return label;
}

// В комнате с включённым у меня E2EE чужие открытые сообщения помечаются:
// их содержимое видел сервер, и это не должно выглядеть как обычная переписка.
function shouldMarkPlaintext(message) {
    return Boolean(currentRoomId) && !message.encrypted && !isOwnMessage(message) && isE2eeActiveForChat(currentChatId);
}

function updatePlaintextMarkers() {
    elements.chatMessages.querySelectorAll('.message.received').forEach((el) => {
        if (!el._message) return;
        const need = shouldMarkPlaintext(el._message);
        const label = el.querySelector('.plaintext-label');
        if (need && !label) {
            const meta = el.querySelector('.message-meta');
            if (meta) meta.prepend(createPlaintextLabel());
        } else if (!need && label) {
            label.remove();
        }
    });
}

// Время показывается в часовом поясе пользователя (created_at), а не
// сервера. Для старых сообщений без created_at — прежнее поле time.
function formatMessageTime(message) {
    if (message.created_at) {
        const date = new Date(message.created_at);
        if (!Number.isNaN(date.getTime())) {
            const hhmm = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
            if (date.toDateString() === new Date().toDateString()) return hhmm;
            return `${date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' })} ${hhmm}`;
        }
    }
    return message.time || '';
}

function createMessageElement(message, animate) {
    const isMine = isOwnMessage(message);
    const div = document.createElement('div');
    div.className = `message ${isMine ? 'sent' : 'received'}${animate ? ' message-new' : ''}`;
    div.dataset.messageId = message.id;
    div._message = message;

    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';

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
    if (shouldMarkPlaintext(message)) metaDiv.appendChild(createPlaintextLabel());
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
    editingMessageEncrypted = false;
}

// ==================== Отправка ====================

// Замок отправки: пока идёт отправка или правка, повторный Enter/клик
// ничего не делает. Берёт его вызывающий (sendMessage), а не sendText.
let sending = false;

// Отправляет уже готовый текст в ЯВНО указанный чат: шифрует (если для чата
// включено шифрование), шлёт на сервер и сразу показывает сообщение в ленте.
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
        client = await prepareOutgoingE2ee(chatId, roomId);
    } catch (err) {
        showToast(err.message, 'error', 6000);
        return false;
    }
    let outgoingText = text;
    let encrypted = false;
    if (client) {
        try {
            outgoingText = await client.encryptOutgoing(roomId, text);
            encrypted = true;
        } catch (err) {
            console.error('E2EE: encryptOutgoing failed:', err);
            showToast('Не удалось зашифровать сообщение — попробуйте ещё раз или выключите шифрование', 'error');
            return false;
        }
    }
    const payload = { chatId, text: outgoingText, encrypted };
    if (replyToId) payload.replyToId = replyToId;
    const data = await api('/api/messages', {
        method: 'POST',
        body: JSON.stringify(payload),
    });
    if (!data.success) {
        showToast(data.message || 'Не удалось отправить сообщение', 'error');
        return false;
    }
    // Показываем сразу из ответа — не зависим от того, успел ли
    // прийти (и пришёл ли вообще) newMessage по сокету.
    if (chatId === currentChatId && data.message) {
        const message = { ...data.message, text };
        const reply = message.reply_to;
        if (reply && reply.encrypted && !reply.deleted) {
            reply.text = decryptedSummary(await decryptEnvelope(roomId, reply.sender_id, reply.text, reply.id));
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

    sending = true; // двойной Enter/клик не отправляет сообщение дважды
    try {
        if (editingMessageId) {
            // Шифруем правку так же, как было зашифровано исходное
            // сообщение — независимо от текущего состояния тумблера чата
            // (см. editingMessageEncrypted): сервер не принимает флаг
            // encrypted при редактировании, он фиксирован с момента
            // создания сообщения.
            const messageId = editingMessageId;
            const encryptEdit = editingMessageEncrypted;
            let outgoingText = text;
            if (encryptEdit) {
                const client = roomId ? await getReadyE2eeClient() : null;
                if (!client) { showToast('Не удалось зашифровать правку: сквозное шифрование недоступно', 'error'); return; }
                try { outgoingText = await client.encryptOutgoing(roomId, text); }
                catch { showToast('Не удалось зашифровать правку', 'error'); return; }
            }
            const data = await api(`/api/messages/${messageId}`, {
                method: 'PUT',
                body: JSON.stringify({ text: outgoingText }),
            });
            if (!data.success) {
                showToast(data.message || 'Не удалось изменить сообщение', 'error');
                return; // поле не очищаем — пользователь не теряет набранный текст
            }
            showToast('Сообщение изменено', 'success');
            // в бабле — то, что реально набрано, открытым текстом
            if (chatId === currentChatId) applyMessageEdit(messageId, encryptEdit ? text : (data.text || text));
            if (String(editingMessageId) === String(messageId)) {
                editingMessageId = null;
                editingMessageEncrypted = false;
            }
        } else {
            const sent = await sendText(text, { chatId, roomId, replyToId: replyToMessageId });
            if (!sent) return;
        }
    } finally {
        sending = false;
    }

    // Если пользователь успел уйти в другой чат, там в поле может быть уже
    // новый черновик — его не трогаем.
    if (chatId === currentChatId) {
        elements.messageInput.value = '';
        clearReply();
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
    const mime = detectFileMime(file);
    let error = '';
    if (!isSupportedMime(mime)) error = 'такой тип файлов не поддерживается';
    else if (file.size > MAX_UPLOAD_BYTES) error = 'больше 50 МБ';
    else if (file.size === 0) error = 'пустой файл';
    return { file, mime, error };
}

// Имя, под которым файл увидят собеседники: у фото/видео/аудио — всегда
// обезличенное; у документа в E2EE-комнате — исходное (оно внутри конверта,
// сервер его не видит), без E2EE сервер тоже получает обезличенное.
function outgoingFileName(file, mime, encrypted) {
    return encrypted ? encryptedFileName(file, mime) : anonymousFileName(mime);
}

function onFilesChosen(files) {
    if (!currentChatId || files.length === 0) return;
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
    const encrypted = Boolean(target && target.roomId) && isE2eeActiveForChat(target.chatId);
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
        li.append(icon(item.error ? 'alert-triangle' : fileIconName(item.mime)), info, remove);
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
        elements.attachBtn.disabled = false;
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
        client = await prepareOutgoingE2ee(chatId, roomId);
    } catch (err) {
        return { ok: false, fatal: true, message: err.message };
    }
    if (queue.cancelled) return { ok: false };

    setUploadStatus(`${prefix}удаление метаданных…`, null);
    let clean;
    try {
        clean = MediaSanitizer.sanitize(new Uint8Array(await item.file.arrayBuffer()), item.mime);
    } catch (err) {
        console.warn('MediaSanitizer: файл отклонён:', err);
        return { ok: false, message: 'Файл повреждён или его формат не поддерживается' };
    }
    if (queue.cancelled) return { ok: false };

    const formData = new FormData();
    formData.append('chatId', String(chatId));
    let localFile = null;
    if (client) {
        setUploadStatus(`${prefix}шифрование…`, null);
        try {
            const enc = await client.encryptFile(clean);
            if (enc.ciphertext.byteLength > MAX_UPLOAD_BYTES) {
                return { ok: false, message: 'Файл слишком большой для отправки с шифрованием (макс. 50 МБ)' };
            }
            localFile = { mime: item.mime, name: encryptedFileName(item.file, item.mime), size: enc.size, key: enc.key, iv: enc.iv };
            const envelope = await client.encryptOutgoing(roomId, { type: 'file', ...localFile, caption: '' });
            // Порядок полей важен: сервер читает chatId/encrypted/envelope
            // до того, как начнёт принимать сам файл.
            formData.append('encrypted', 'true');
            formData.append('envelope', envelope);
            formData.append('file', new Blob([enc.ciphertext], { type: 'application/octet-stream' }), 'blob');
        } catch (err) {
            console.error('E2EE: не удалось зашифровать файл:', err);
            return { ok: false, message: 'Не удалось зашифровать файл' };
        }
    } else {
        formData.append('file', new Blob([clean], { type: item.mime }), anonymousFileName(item.mime));
    }
    if (queue.cancelled) return { ok: false };

    setUploadStatus(`${prefix}загрузка…`, 0);
    const data = await postFormDataWithProgress('/api/messages/file', formData, {
        onXhr: (xhr) => { queue.xhr = xhr; },
        onProgress: (p) => {
            if (!queue.cancelled) setUploadStatus(`${prefix}загрузка ${Math.round(p * 100)}%`, p);
        },
    });
    queue.xhr = null;
    if (data.aborted || queue.cancelled) return { ok: false };
    if (!data.success) return { ok: false, message: data.message || 'Не удалось отправить файл' };
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
    if (!confirm('Удалить чат?')) return;
    const data = await api(`/api/chats/${currentChatId}`, { method: 'DELETE' });
    if (data.success) {
        showToast('Чат удалён', 'success');
        closeModal(elements.chatMenuModal);
        resetChatView();
        loadChats();
    } else {
        showToast(data.message, 'error');
    }
}

// ==================== Поиск ====================

function renderSearchSection(title) {
    const header = document.createElement('div');
    header.className = 'search-section-title chats-section-title';
    header.textContent = title;
    return header;
}

let searchSeq = 0;
async function performSearch() {
    const q = elements.searchInput.value.trim();
    const seq = ++searchSeq;
    if (!q) {
        chatListMode = 'chats';
        return loadChats();
    }
    const data = await api(`/api/search?q=${encodeURIComponent(q)}`);
    if (!data.success || seq !== searchSeq) return;
    chatListMode = 'search';
    hideChatItemMenu();

    const { chats = [], messages = [] } = data.results || {};
    const fragment = document.createDocumentFragment();
    if (chats.length > 0) {
        fragment.appendChild(renderSearchSection('Чаты'));
        chats.forEach(chat => {
            fragment.appendChild(createChatItem({
                id: chat.id, roomId: chat.room_id, name: chat.name, isBot: Boolean(Number(chat.is_bot)),
                preview: { icon: chat.room_id ? 'users' : null, text: chat.room_id ? 'Групповой чат' : 'Личный чат' }, unread: 0,
                onClick: () => openChat(chat.id, chat.room_id, chat.name, chat.avatar, chat.online, chat.is_bot),
            }));
        });
    }
    // Раньше найденные сообщения сервер возвращал, но они нигде не выводились.
    if (messages.length > 0) {
        fragment.appendChild(renderSearchSection('Сообщения'));
        messages.forEach(m => {
            fragment.appendChild(createChatItem({
                id: m.chat_id, roomId: m.room_id, name: m.chat_name, isBot: Boolean(Number(m.is_bot)),
                preview: { icon: 'search', text: m.text || '' }, unread: 0,
                onClick: () => openChat(m.chat_id, m.room_id, m.chat_name, m.avatar, m.online, m.is_bot),
            }));
        });
    }
    if (chats.length === 0 && messages.length === 0) {
        fragment.appendChild(renderSearchSection('Ничего не найдено'));
    }
    elements.chatsList.replaceChildren(fragment);
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
