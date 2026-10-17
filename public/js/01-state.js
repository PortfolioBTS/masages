// public/js/01-state.js — состояние приложения, константы и таблица элементов страницы (elements).
// Вынесено из public/script.js (строки 1–262 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Сокет (подключается после входа), переменные открытого чата, лимиты, ключи localStorage, сроки исчезающих сообщений, реакции.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

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
