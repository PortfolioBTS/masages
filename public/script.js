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
let longPressTimer = null;

// Состояние открытого чата: история грузится страницами с конца.
let openChatSeq = 0;          // защита от гонок при быстром переключении чатов
let oldestMessageId = null;   // самый старый загруженный — курсор для ?before=
let hasMoreHistory = false;
let loadingHistory = false;
let lastSeenMessageId = 0;    // до какого id пользователь уже видел открытый чат
let chatListMode = 'chats';   // 'chats' | 'search' — что сейчас показано в сайдбаре
let membersChangedTimer = null; // debounce событий roomMembersChanged

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const POW_TIMEOUT_MS = 60 * 1000;
const ANON_IDS_KEY = 'nyxo-anon-ids';
const FLASH_NOTICE_KEY = 'nyxo-notice';

const elements = {
    authScreen: document.getElementById('auth-screen'),
    app: document.getElementById('app'),
    sidebar: document.querySelector('.sidebar'),
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    loginBtn: document.getElementById('login-btn'),
    registerBtn: document.getElementById('register-btn'),
    anonymousLoginBtn: document.getElementById('anonymous-login-btn'),
    logoutBtn: document.getElementById('logout-btn'),
    chatsList: document.getElementById('chats-list'),
    chatMessages: document.getElementById('chat-messages'),
    messageInput: document.getElementById('message-input'),
    sendBtn: document.getElementById('send-btn'),
    attachBtn: document.getElementById('attach-btn'),
    fileInput: document.getElementById('file-input'),
    recordBtn: document.getElementById('record-btn'),
    newChatBtn: document.getElementById('new-chat-btn'),
    backBtn: document.getElementById('back-btn'),
    chatHeader: document.getElementById('chat-header'),
    chatName: document.getElementById('chat-name'),
    chatStatus: document.getElementById('chat-status'),
    chatAvatar: document.getElementById('chat-avatar'),
    emptyState: document.getElementById('empty-state'),
    messageInputContainer: document.getElementById('message-input-container'),
    searchInput: document.getElementById('search-input'),
    newChatModal: document.getElementById('new-chat-modal'),
    chatMenuModal: document.getElementById('chat-menu-modal'),
    profileModal: document.getElementById('profile-modal'),
    passwordModal: document.getElementById('password-modal'),
    inviteModal: document.getElementById('invite-modal'),
    membersModal: document.getElementById('members-modal'),
    deleteAccountModal: document.getElementById('delete-account-modal'),
    createChatBtn: document.getElementById('create-chat-btn'),
    joinChatBtn: document.getElementById('join-chat-btn'),
    deleteChatBtn: document.getElementById('delete-chat-btn'),
    getChatCodeBtn: document.getElementById('get-chat-code-btn'),
    chatMenuBtn: document.getElementById('chat-menu-btn'),
    membersKeysBtn: document.getElementById('members-keys-btn'),
    profileBtn: document.getElementById('profile-btn'),
    changePasswordBtn: document.getElementById('change-password-btn'),
    savePasswordBtn: document.getElementById('save-password-btn'),
    inviteCodeContainer: document.getElementById('invite-code-container'),
    inviteCodeDisplay: document.getElementById('invite-code-display'),
    inviteExpiry: document.getElementById('invite-expiry'),
    copyInviteBtn: document.getElementById('copy-invite-btn'),
    rotateInviteBtn: document.getElementById('rotate-invite-btn'),
    messageMenu: document.getElementById('message-menu'),
    replyMessageBtn: document.getElementById('reply-message-btn'),
    editMessageBtn: document.getElementById('edit-message-btn'),
    deleteMessageBtn: document.getElementById('delete-message-btn'),
    replyPreview: document.getElementById('reply-preview'),
    replyPreviewText: document.getElementById('reply-preview-text'),
    cancelReplyBtn: document.getElementById('cancel-reply-btn'),
    toast: document.getElementById('toast'),
    overlay: document.getElementById('overlay'),
    profileUsername: document.getElementById('profile-username'),
    profileEmail: document.getElementById('profile-email'),
    profileCode: document.getElementById('profile-code'),
    profileAvatar: document.getElementById('profile-avatar'),
    profileAnonBadge: document.getElementById('profile-anon-badge'),
    readReceiptsToggle: document.getElementById('read-receipts-toggle'),
    deleteAccountBtn: document.getElementById('delete-account-btn'),
    deleteAccountText: document.getElementById('delete-account-text'),
    deleteAccountPasswordGroup: document.getElementById('delete-account-password-group'),
    deleteAccountPassword: document.getElementById('delete-account-password'),
    confirmDeleteAccountBtn: document.getElementById('confirm-delete-account-btn'),
    e2eeToggleBtn: document.getElementById('e2ee-toggle-btn'),
    e2eeBanner: document.getElementById('e2ee-banner'),
    e2eeBannerText: document.getElementById('e2ee-banner-text'),
    e2eeBannerBtn: document.getElementById('e2ee-banner-btn'),
    membersList: document.getElementById('members-list'),
    membersNote: document.getElementById('members-note'),
};

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

// ==================== Следы на устройстве ====================
// Всё, что клиент хранит локально: ключи E2EE (IndexedDB nyxo-e2ee-<id>,
// удаляется через E2EE.deleteLocalData) и выбор тумблера шифрования по
// чатам (localStorage e2ee-enabled:<id>:<chatId>). Для анонимного режима
// ("данные удалятся при выходе") и после удаления аккаунта это должно
// исчезать вместе с сессией. Хранилище браузера может быть недоступно
// (приватный режим, запрет cookies) — отсюда try/catch вокруг каждого
// обращения: интерфейс должен работать и без него.

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
// текущая сессия". Туда попадают анонимные сессии (вкладку могли просто
// закрыть, а сервер удалит анонима сам через 4 часа) и удалённые аккаунты.
function rememberIdForWipe(userId) {
    writeAnonIds([...readAnonIds(), Number(userId)]);
}

function forgetIdForWipe(userId) {
    writeAnonIds(readAnonIds().filter(id => id !== Number(userId)));
}

function removeLocalE2eePrefs(userId) {
    try {
        const prefix = `e2ee-enabled:${userId}:`;
        const doomed = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(prefix)) doomed.push(key);
        }
        doomed.forEach(key => localStorage.removeItem(key));
    } catch { /* хранилище недоступно */ }
}

// Стирает локальные данные пользователя. Резолвится true, если база
// ключей точно удалена. Удаление IndexedDB ждёт, пока закроются открытые
// к ней соединения, поэтому ждём не дольше timeoutMs: id остаётся в
// списке на стирание и будет дочищен позже (при следующем старте), а
// если удаление всё же завершится — вычеркнется из списка само.
function wipeLocalUserData(userId, timeoutMs = 3000) {
    removeLocalE2eePrefs(userId);
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

function purgeStaleLocalData(activeUserId) {
    readAnonIds()
        .filter(id => id !== Number(activeUserId))
        .forEach(id => { wipeLocalUserData(id); });
}

// Полная перезагрузка после выхода из приватного режима и удаления
// аккаунта: закрывает соединения с IndexedDB (иначе удаление базы ключей
// ждёт их закрытия) и выбрасывает из памяти расшифрованную переписку.
// Уведомление переживает перезагрузку через sessionStorage.
function reloadWithNotice(text) {
    try {
        if (text) sessionStorage.setItem(FLASH_NOTICE_KEY, text);
    } catch { /* без уведомления — не страшно */ }
    location.reload();
}

function showFlashNotice() {
    let text = null;
    try {
        text = sessionStorage.getItem(FLASH_NOTICE_KEY);
        sessionStorage.removeItem(FLASH_NOTICE_KEY);
    } catch { /* нет sessionStorage */ }
    if (text) showToast(text, 'info', 5000);
}

// ==================== E2EE (X3DH + Sender Keys) ====================
// Ключи устройства хранятся в IndexedDB, отдельная база на каждого
// currentUser.id — это исключает утечку ключевого материала между
// разными аккаунтами на одном браузере (общий компьютер, тест-логины).
// Подробности протокола и честные ограничения — см. public/e2ee.js.
//
// В комнатах шифрование включено по умолчанию: выключить его можно только
// явно (в localStorage тогда '0'). Если ключи устройства не удалось
// инициализировать (например, не настроен e2ee-key-server → 503),
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

function warnE2eeUnavailable() {
    if (e2eeUnavailableWarned) return;
    e2eeUnavailableWarned = true;
    showToast('Сквозное шифрование недоступно: не удалось подготовить ключи. Сообщения будут отправляться без него', 'error', 7000);
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
            warnE2eeUnavailable();
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
    return `e2ee-enabled:${currentUser ? currentUser.id : '0'}:${chatId}`;
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
    } catch { /* приватный режим браузера без localStorage — выбор не запомнится */ }
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
    btn.classList.remove('e2ee-active', 'e2ee-unavailable');
    if (!inRoom) {
        elements.messageInput.placeholder = 'Сообщение...';
        return;
    }
    let label;
    if (e2eeState === 'unavailable') {
        btn.textContent = '⚠';
        btn.classList.add('e2ee-unavailable');
        btn.setAttribute('aria-pressed', 'false');
        label = 'Сквозное шифрование недоступно — нажмите, чтобы повторить попытку';
        elements.messageInput.placeholder = 'Сообщение (без шифрования)...';
    } else {
        const enabled = isE2eePreferred(chatId);
        btn.textContent = enabled ? '🔒' : '🔓';
        btn.classList.toggle('e2ee-active', enabled);
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

function appendSystemNotice(roomId, text) {
    if (Number(roomId) !== Number(currentRoomId)) return;
    if (!noticesReady) {
        pendingNotices.push(text);
        return;
    }
    const stick = isNearBottom();
    const el = document.createElement('div');
    el.className = 'system-notice';
    el.setAttribute('role', 'status');
    el.textContent = text;
    elements.chatMessages.appendChild(el);
    if (stick) scrollToBottom();
}

function flushSystemNotices() {
    noticesReady = true;
    const queued = pendingNotices;
    pendingNotices = [];
    queued.forEach(text => appendSystemNotice(currentRoomId, text));
}

function renderIdentityBanner() {
    const names = Array.from(pendingIdentityChanges.values());
    if (!currentRoomId || names.length === 0) {
        elements.e2eeBanner.classList.add('hidden');
        elements.e2eeBannerText.textContent = '';
        return;
    }
    elements.e2eeBannerText.textContent = names.length === 1
        ? `⚠ У участника ${names[0]} сменился ключ шифрования. Сообщения ему не отправляются, пока вы не проверите код безопасности`
        : `⚠ У участников ${names.join(', ')} сменились ключи шифрования. Сообщения им не отправляются, пока вы не проверите коды безопасности`;
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
        const text = `🔑 В чат вошли: ${joinNames(delivered)}, им передан ключ шифрования`;
        appendSystemNotice(roomId, text);
        showToast(text, 'info');
    }
    if (undelivered.length > 0) {
        appendSystemNotice(roomId, `⚠ В чат вошли: ${joinNames(undelivered)}, но ключ шифрования им передать не удалось — они пока не смогут читать зашифрованные сообщения`);
    }
    if (removedMembers.length > 0) {
        const verb = removedMembers.length === 1 ? 'покинул(а)' : 'покинули';
        const text = `🔑 ${joinNames(removedMembers)} ${verb} чат${result.rotated ? ' — ключ шифрования обновлён' : ''}`;
        appendSystemNotice(roomId, text);
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

function e2eeFailureText(reason) {
    if (reason === 'replay') return '⚠ Повтор старого сообщения (возможна подмена сервером)';
    return '🔒 Не удалось расшифровать';
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
    if (res.file) return `📎 ${res.text || safeDisplayName(res.file.name)}`;
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
            message.text = '🔒 Зашифрованное сообщение';
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
        btn.textContent = '⏳';
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
    btn.textContent = '⏳';
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
    const span = document.createElement('span');
    span.className = 'attachment-status' + (failed ? ' e2ee-failed' : '');
    span.textContent = text;
    box.replaceChildren(span);
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
    const wrapper = document.createElement('div');
    wrapper.className = 'file-attachment';
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.textContent = `📎 ${name}`;
    wrapper.appendChild(a);
    return wrapper;
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
        if (seq === openChatSeq && box.isConnected) setAttachmentStatus(box, '🔒 Не удалось расшифровать файл', true);
    }
}

function createEncryptedAttachmentElement(message) {
    const box = document.createElement('div');
    box.className = 'encrypted-attachment';
    if (!message.file_url) {
        setAttachmentStatus(box, '🔒 Не удалось расшифровать файл', true);
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
    setAttachmentStatus(box, `⏳ Загрузка файла «${safeDisplayName(message._file.name)}»…`, false);
    const observer = getAttachmentObserver();
    if (observer) observer.observe(box);
    else setTimeout(() => enqueueAttachmentDecrypt(box), 0);
    return box;
}

// ==================== Proof-of-work для регистрации ====================
// Регистрация (обычная и анонимная) требует решения PoW-задачи: это
// ограничивает массовое создание аккаунтов ботами без капчи и без
// сторонних сервисов. Считается в Web Worker, чтобы не вешать вкладку.

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
            reject(new Error('Проверка заняла слишком много времени. Попробуйте ещё раз'));
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
async function postWithPow(url, body, purpose, btn) {
    const label = btn.textContent;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.textContent = 'Проверка…';
    try {
        let data = null;
        for (let attempt = 0; attempt < 2; attempt++) {
            const pow = await solvePow(purpose);
            data = await api(url, { method: 'POST', body: JSON.stringify({ ...body, pow }) });
            if (!(data && data.success === false && data.powRequired)) break;
        }
        return data;
    } catch (err) {
        return { success: false, message: err.message || 'Не удалось пройти проверку' };
    } finally {
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        btn.textContent = label;
    }
}

// ==================== Сессия и сокет ====================

function init() {
    showFlashNotice();
    checkAuth();
    try {
        setupEventListeners();
    } catch (e) {
        console.error('setupEventListeners() failed — some UI controls may not respond:', e);
    }
}

async function checkAuth() {
    let data;
    try {
        const res = await fetch('/api/auth');
        data = await res.json();
    } catch (e) {
        // Сервер недоступен — локальные данные не трогаем: сессия могла и не истечь.
        showAuth();
        return;
    }
    if (data && data.authenticated && data.user) {
        enterApp(data.user);
    } else {
        purgeStaleLocalData(null);
        showAuth();
    }
}

function enterApp(user) {
    currentUser = user;
    // До всего остального: если вкладку просто закроют, при следующем
    // старте данные этой анонимной сессии будут стёрты (см. purgeStaleLocalData).
    if (user.isAnonymous) rememberIdForWipe(user.id);
    purgeStaleLocalData(user.id);
    e2eeUnavailableWarned = false;
    warnedRooms.clear();
    initE2eeForCurrentUser();
    showApp();
    // Новое соединение = новое рукопожатие с актуальной кукой сессии.
    if (socket.connected) socket.disconnect();
    socket.connect();
    loadChats();
    if (typeof user.readReceipts !== 'boolean') refreshAccountFlags();
}

// Ответ /api/login и /api/register не содержит настроек приватности —
// берём их из /api/auth.
async function refreshAccountFlags() {
    const userId = currentUser ? currentUser.id : null;
    try {
        const res = await fetch('/api/auth');
        const data = await res.json();
        if (!data.authenticated || !data.user || !currentUser || currentUser.id !== userId) return;
        if (typeof data.user.readReceipts === 'boolean') currentUser.readReceipts = data.user.readReceipts;
        if (typeof data.user.isAnonymous === 'boolean') currentUser.isAnonymous = data.user.isAnonymous;
        refreshOwnMessageStatuses();
    } catch { /* останется значение по умолчанию */ }
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
}

// Всё, что привязано к открытому чату и должно исчезнуть при его смене:
// расшифрованные вложения (object URL), очередь их расшифровки, баннер
// смены ключей, отложенные служебные строки.
function releaseChatResources() {
    resetAttachmentDecrypts();
    pendingIdentityChanges.clear();
    renderIdentityBanner();
    noticesReady = false;
    pendingNotices = [];
    clearTimeout(membersChangedTimer);
    hideMessageMenu();
    menuMessage = null;
}

// options.wipe — стереть локальные данные пользователя (ключи E2EE,
// настройки шифрования). Для анонимного режима — всегда.
function leaveApp(message, options = {}) {
    const user = currentUser;
    socket.disconnect();
    currentUser = null;
    e2eeClient = null; // ключи обычного аккаунта остаются в IndexedDB под его userId для следующего входа
    e2eeClientUserId = null;
    e2eeInitPromise = null;
    e2eeState = 'off';
    clearTimeout(markReadTimer);
    clearTimeout(loadChatsTimer);
    roomParticipants.clear();
    resetChatView();
    closeAllModals();
    elements.chatsList.replaceChildren();
    showAuth();
    if (user && (user.isAnonymous || options.wipe)) {
        rememberIdForWipe(user.id);
        wipeLocalUserData(user.id, 1500).finally(() => reloadWithNotice(message));
        return;
    }
    if (message) showToast(message, 'info');
}

let authRecheckPending = false;
socket.on('connect_error', (err) => {
    // Сессия истекла (например, 4 часа анонимного режима) — сервер
    // отклоняет рукопожатие. Перепроверяем вход и показываем экран входа.
    if (err && err.message === 'Не авторизован' && !authRecheckPending) {
        authRecheckPending = true;
        fetch('/api/auth').then(r => r.json()).then((data) => {
            if (!data.authenticated && currentUser) leaveApp('Сессия истекла, войдите снова');
        }).catch(() => {}).finally(() => { authRecheckPending = false; });
    }
});

socket.io.on('reconnect', () => {
    // После обрыва связи (или рестарта сервера) догружаем пропущенное.
    if (!currentUser) return;
    if (chatListMode === 'chats') loadChats();
    if (currentChatId) refreshCurrentChat();
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
function showToast(message, type = 'info', duration = 3000) {
    elements.toast.textContent = message || '';
    elements.toast.className = `toast ${type}`;
    elements.toast.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => elements.toast.classList.add('hidden'), duration);
}

function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
    return match ? match[1] : '';
}

// Любой ответ сервера приводится к { success, message, ... }. Раньше
// ответ не-JSON (502 от прокси, обрыв сети) бросал исключение прямо в
// обработчике клика, и кнопка просто "ничего не делала".
async function api(url, options = {}, retried = false) {
    let res;
    try {
        res = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
                ...options.headers,
            },
        });
    } catch {
        return { success: false, message: 'Нет соединения с сервером' };
    }
    let data;
    try {
        data = await res.json();
    } catch {
        return { success: false, message: `Ошибка сервера (HTTP ${res.status})` };
    }
    // Кука csrf_token живёт сутки; если она истекла, любой GET выдаст новую.
    if (res.status === 403 && !retried && /CSRF/i.test(data.message || '')) {
        await fetch('/api/auth').catch(() => {});
        return api(url, options, true);
    }
    if (currentUser && data && data.success === false && data.message === 'Не авторизован') {
        leaveApp('Сессия истекла, войдите снова');
    }
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
    if (currentUser && data && data.success === false && data.message === 'Не авторизован') {
        leaveApp('Сессия истекла, войдите снова');
    }
    return data;
}

function setupEventListeners() {
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.auth-tab').forEach((t) => {
                t.classList.remove('active');
                t.setAttribute('aria-selected', 'false');
            });
            tab.classList.add('active');
            tab.setAttribute('aria-selected', 'true');
            const target = tab.dataset.tab;
            if (target === 'login') {
                elements.loginForm.classList.add('active');
                elements.registerForm.classList.remove('active');
            } else {
                elements.loginForm.classList.remove('active');
                elements.registerForm.classList.add('active');
            }
        });
    });

    elements.loginBtn.addEventListener('click', async () => {
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const data = await api('/api/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
        });
        if (data.success) {
            document.getElementById('login-password').value = '';
            showToast('Вход выполнен!', 'success');
            enterApp(data.user);
        } else {
            showToast(data.message, 'error');
        }
    });

    elements.registerBtn.addEventListener('click', async () => {
        if (elements.registerBtn.disabled) return;
        const username = document.getElementById('register-username').value.trim();
        const email = document.getElementById('register-email').value.trim();
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        // Очевидные ошибки ловим до PoW, чтобы не заставлять ждать проверку зря.
        if (!username || !email || !password || !confirmPassword) return showToast('Заполните все поля', 'error');
        if (password.length < 8) return showToast('Пароль должен быть не менее 8 символов', 'error');
        if (password !== confirmPassword) return showToast('Пароли не совпадают', 'error');
        const data = await postWithPow('/api/register', { username, email, password, confirmPassword }, 'register', elements.registerBtn);
        if (data && data.success) {
            document.getElementById('register-password').value = '';
            document.getElementById('register-confirm-password').value = '';
            showToast('Регистрация успешна!', 'success');
            enterApp(data.user);
        } else {
            showToast((data && data.message) || 'Ошибка регистрации', 'error');
        }
    });

    elements.anonymousLoginBtn.addEventListener('click', async () => {
        if (elements.anonymousLoginBtn.disabled) return;
        const data = await postWithPow('/api/register/anonymous', {}, 'register-anon', elements.anonymousLoginBtn);
        if (data && data.success) {
            showToast('Приватный режим активирован!', 'success');
            enterApp({ ...data.user, isAnonymous: true });
        } else {
            showToast((data && data.message) || 'Не удалось войти в приватном режиме', 'error');
        }
    });

    elements.logoutBtn.addEventListener('click', async () => {
        const wasAnonymous = Boolean(currentUser && currentUser.isAnonymous);
        await api('/api/logout', { method: 'POST' });
        leaveApp(wasAnonymous ? 'Данные приватного режима удалены' : 'Вы вышли из аккаунта');
    });

    elements.newChatBtn.addEventListener('click', () => openModal(elements.newChatModal));
    elements.createChatBtn.addEventListener('click', createChat);
    elements.joinChatBtn.addEventListener('click', joinChat);

    if (elements.backBtn) {
        elements.backBtn.addEventListener('click', () => elements.sidebar.classList.remove('hidden-mobile'));
    }

    elements.chatMenuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        openModal(elements.chatMenuModal);
    });

    elements.deleteChatBtn.addEventListener('click', deleteChat);

    elements.e2eeToggleBtn.addEventListener('click', onE2eeToggleClick);
    elements.membersKeysBtn.addEventListener('click', openMembersModal);
    elements.e2eeBannerBtn.addEventListener('click', openMembersModal);

    elements.getChatCodeBtn.addEventListener('click', openInviteModal);
    elements.rotateInviteBtn.addEventListener('click', rotateInviteCode);

    elements.copyInviteBtn.addEventListener('click', async () => {
        const code = elements.inviteCodeDisplay.dataset.code || '';
        if (!code) return;
        try {
            await navigator.clipboard.writeText(code);
            showToast('Код скопирован!', 'success');
        } catch {
            showToast('Не удалось скопировать — выделите код вручную', 'error');
        }
    });

    elements.profileBtn.addEventListener('click', openProfile);

    elements.changePasswordBtn.addEventListener('click', () => {
        closeModal(elements.profileModal);
        openModal(elements.passwordModal);
    });

    elements.savePasswordBtn.addEventListener('click', async () => {
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-new-password').value;
        const data = await api('/api/change-password', {
            method: 'POST',
            body: JSON.stringify({ currentPassword, newPassword, confirmPassword }),
        });
        if (data.success) {
            showToast(data.message, 'success');
            closeModal(elements.passwordModal);
            ['current-password', 'new-password', 'confirm-new-password'].forEach(id => { document.getElementById(id).value = ''; });
            setTimeout(() => leaveApp(), 1500);
        } else {
            showToast(data.message, 'error');
        }
    });

    elements.readReceiptsToggle.addEventListener('change', onReadReceiptsToggle);
    elements.deleteAccountBtn.addEventListener('click', openDeleteAccountModal);
    elements.confirmDeleteAccountBtn.addEventListener('click', deleteAccount);
    elements.deleteAccountPassword.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            deleteAccount();
        }
    });

    document.querySelectorAll('.color-option').forEach(btn => {
        btn.addEventListener('click', async () => {
            const color = btn.dataset.color;
            const data = await api('/api/user/avatar-color', {
                method: 'POST',
                body: JSON.stringify({ avatarColor: color }),
            });
            if (data.success) {
                elements.profileAvatar.style.background = color;
                if (currentUser) currentUser.avatar = color;
                markActiveColor(color);
                showToast('Цвет обновлён', 'success');
            } else {
                showToast(data.message || 'Не удалось обновить цвет', 'error');
            }
        });
    });

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

    elements.attachBtn.addEventListener('click', () => elements.fileInput.click());
    elements.fileInput.addEventListener('change', handleFileUpload);
    elements.cancelReplyBtn.addEventListener('click', clearReply);

    elements.replyMessageBtn.addEventListener('click', () => {
        const message = menuMessage;
        hideMessageMenu();
        if (!message) return;
        replyToMessageId = message.id;
        elements.replyPreviewText.textContent = messageSummary(message).substring(0, 100);
        elements.replyPreview.classList.remove('hidden');
        elements.messageInput.focus();
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

    let searchTimeout;
    elements.searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(performSearch, 300);
    });

    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', closeAllModals);
    });

    elements.overlay.addEventListener('click', () => {
        closeAllModals();
        hideMessageMenu();
    });

    document.addEventListener('keydown', onModalKeydown);

    // Подгрузка более старых сообщений при прокрутке к началу.
    elements.chatMessages.addEventListener('scroll', () => {
        if (elements.chatMessages.scrollTop < 200) loadOlderMessages();
        if (isNearBottom()) markVisibleMessagesRead();
    }, { passive: true });

    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') markVisibleMessagesRead();
    });

    socket.on('newMessage', async (message) => {
        if (!currentUser) return;
        const mine = isOwnMessage(message);
        if (belongsToCurrentChat(message.chat_id, message.room_id)) {
            const roomId = currentRoomId;
            const seq = openChatSeq;
            const stickToBottom = mine || isNearBottom();
            await decryptMessageInPlace(message, roomId);
            if (seq !== openChatSeq) return; // пока расшифровывали, открыли другой чат
            if (appendMessage(message, true) && stickToBottom) scrollToBottom();
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

    // Состав комнаты изменился: забираем новые key-share и пересобираем
    // сессию (новым — отдать ключ, после ухода — ротировать свой).
    socket.on('roomMembersChanged', ({ roomId } = {}) => {
        if (!currentUser || !roomId || !currentChatId || Number(roomId) !== Number(currentRoomId)) return;
        const chatId = currentChatId;
        const room = currentRoomId;
        clearTimeout(membersChangedTimer);
        membersChangedTimer = setTimeout(async () => {
            if (chatId !== currentChatId) return;
            await syncE2eeKeyShares(chatId, room);
            if (chatId === currentChatId) ensureE2eeRoomSession(chatId, room);
        }, 300);
    });

    document.addEventListener('click', () => hideMessageMenu());
    document.addEventListener('scroll', () => hideMessageMenu(), true);
}

// ==================== Модальные окна ====================

let modalReturnFocus = null;

function isFocusable(el) {
    return !el.disabled && el.offsetParent !== null;
}

// Фокус при открытии окна: первое видимое поле ввода, иначе первая кнопка
// окна, иначе "закрыть" (скрытые элементы, например поле пароля у
// анонимного аккаунта, пропускаются).
function initialFocusTarget(modal) {
    const groups = ['.modal-body input:not([type="checkbox"])', '.modal-body button', '.close-modal'];
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
    const focusables = Array.from(modal.querySelectorAll('button, input, a[href], [tabindex]:not([tabindex="-1"])'))
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

// ==================== Профиль, приватность, удаление аккаунта ====================

let profileIsAnonymous = false;

function markActiveColor(color) {
    document.querySelectorAll('.color-option').forEach((btn) => {
        const active = String(btn.dataset.color).toLowerCase() === String(color || '').toLowerCase();
        btn.classList.toggle('active', active);
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
}

async function openProfile() {
    const data = await api('/api/user');
    if (!data.success) {
        showToast(data.message || 'Не удалось загрузить профиль', 'error');
        return;
    }
    elements.profileUsername.textContent = data.user.username;
    elements.profileEmail.textContent = data.user.email || 'Нет email (приватный режим)';
    elements.profileCode.textContent = `Код: ${data.user.uniqueCode}`;
    elements.profileAvatar.style.background = avatarBackground(data.user.avatar);
    elements.profileAvatar.textContent = data.user.username.charAt(0).toUpperCase();
    markActiveColor(data.user.avatar);
    profileIsAnonymous = data.user.email === null || data.user.email === undefined;
    elements.profileAnonBadge.classList.toggle('hidden', !profileIsAnonymous);
    elements.changePasswordBtn.classList.toggle('hidden', profileIsAnonymous);
    if (typeof data.user.readReceipts === 'boolean' && currentUser) currentUser.readReceipts = data.user.readReceipts;
    elements.readReceiptsToggle.checked = readReceiptsEnabled();
    openModal(elements.profileModal);
}

function readReceiptsEnabled() {
    return !currentUser || currentUser.readReceipts !== false;
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

function openDeleteAccountModal() {
    elements.deleteAccountText.textContent = profileIsAnonymous
        ? 'Все данные приватного режима — чаты, сообщения, файлы и ключи шифрования на этом устройстве — будут удалены безвозвратно.'
        : 'Аккаунт, все ваши чаты, сообщения и файлы будут удалены безвозвратно. Ключи шифрования на этом устройстве тоже будут стёрты. Введите пароль для подтверждения.';
    elements.deleteAccountPasswordGroup.classList.toggle('hidden', profileIsAnonymous);
    elements.deleteAccountPassword.value = '';
    closeModal(elements.profileModal);
    openModal(elements.deleteAccountModal);
}

async function deleteAccount() {
    const btn = elements.confirmDeleteAccountBtn;
    if (btn.disabled || !currentUser) return;
    const password = elements.deleteAccountPassword.value;
    if (!profileIsAnonymous && !password) {
        showToast('Введите пароль', 'error');
        elements.deleteAccountPassword.focus();
        return;
    }
    btn.disabled = true;
    const data = await api('/api/account/delete', {
        method: 'POST',
        body: JSON.stringify(profileIsAnonymous ? {} : { password }),
    });
    btn.disabled = false;
    elements.deleteAccountPassword.value = '';
    if (!data.success) {
        showToast(data.message || 'Не удалось удалить аккаунт', 'error');
        return;
    }
    leaveApp(data.message || 'Аккаунт удалён', { wipe: true });
}

// ==================== Приглашения ====================

// Код показывается группами по 5 символов — его диктуют и переписывают
// вручную; сервер при вводе убирает пробелы и дефисы сам.
function formatInviteCode(code) {
    return String(code || '').replace(/[\s-]+/g, '').replace(/(.{5})(?=.)/g, '$1 ');
}

function renderInvite({ code, expiresAt, expired }) {
    const rawCode = String(code || '').replace(/[\s-]+/g, '');
    elements.inviteCodeDisplay.textContent = formatInviteCode(rawCode);
    elements.inviteCodeDisplay.dataset.code = rawCode;
    const expiry = expiresAt ? new Date(expiresAt) : null;
    const validDate = expiry && !Number.isNaN(expiry.getTime());
    const isExpired = expired === true || Boolean(validDate && expiry.getTime() <= Date.now());
    elements.inviteExpiry.textContent = isExpired
        ? '⌛ Код истёк — создайте новый'
        : validDate ? `Действует до ${formatShortDateTime(expiry)}` : '';
    elements.inviteExpiry.classList.toggle('expired', isExpired);
    elements.inviteCodeContainer.classList.toggle('expired', isExpired);
    elements.copyInviteBtn.disabled = isExpired;
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
    renderInvite(data);
    openModal(elements.inviteModal);
}

async function rotateInviteCode() {
    if (!currentChatId || elements.rotateInviteBtn.disabled) return;
    if (!confirm('Создать новый код? Старый код сразу перестанет действовать.')) return;
    const chatId = currentChatId;
    elements.rotateInviteBtn.disabled = true;
    const data = await api(`/api/chats/${chatId}/invite/rotate`, { method: 'POST' });
    elements.rotateInviteBtn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось создать новый код', 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    renderInvite({ code: data.code, expiresAt: data.expiresAt, expired: false });
    showToast('Создан новый код. Старый больше не действует', 'success', 5000);
}

// ==================== Участники и ключи ====================

const IDENTITY_STATUS = {
    verified: { text: '✓ проверен', cls: 'verified' },
    unverified: { text: 'не проверен', cls: 'unverified' },
    changed: { text: '⚠ ключ изменился', cls: 'changed' },
    unknown: { text: 'нет E2EE', cls: 'unknown' },
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
    row._statusEl.textContent = info.text;
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
        const warn = document.createElement('p');
        warn.className = 'member-warning';
        warn.textContent = '⚠ Ключ шифрования этого участника изменился. Так бывает после переустановки браузера или входа с нового устройства — но так же выглядит и подмена ключа сервером. Сверьте код безопасности с участником лично, прежде чем принимать новый ключ.';
        details.appendChild(warn);
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
        accept.className = 'danger-btn';
        accept.textContent = 'Принять новый ключ';
        accept.addEventListener('click', () => acceptIdentityChange(row, peer, ctx, accept));
        actions.appendChild(accept);
    } else if (status === 'unverified') {
        const mark = document.createElement('button');
        mark.className = 'auth-btn';
        mark.textContent = 'Отметить как проверенный';
        mark.addEventListener('click', () => markVerified(row, peer, ctx, mark));
        actions.appendChild(mark);
    } else if (status === 'verified') {
        const done = document.createElement('p');
        done.className = 'safety-hint';
        done.textContent = '✓ Вы уже сверили этот код.';
        actions.appendChild(done);
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
    avatar.textContent = (peer.username || '?').charAt(0).toUpperCase();
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

function avatarBackground(avatar) {
    return avatar && /^#[0-9a-fA-F]{6}$/.test(avatar) ? avatar : '#667EEA';
}

function messagePreview(message) {
    if (message.encrypted) return '🔒 Зашифрованное сообщение';
    const text = message.text || message.last_message || '';
    return message.file_url ? `📎 ${text}` : text;
}

// Короткое описание сообщения для превью ответа.
function messageSummary(message) {
    if (message._file) return `📎 ${message.text || safeDisplayName(message._file.name)}`;
    if (message.file_url) return `📎 ${message.text || ''}`;
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
        badge.className = 'chat-badge';
        item.appendChild(badge);
    }
    badge.dataset.count = String(count);
    badge.textContent = count > 99 ? '99+' : String(count);
}

function createChatItem({ id, roomId, name, avatar, lastText, unread, onClick }) {
    const div = document.createElement('div');
    div.className = 'chat-item';
    div.dataset.id = id;
    div.dataset.roomId = roomId || '';
    div.tabIndex = 0;
    div.setAttribute('role', 'button');
    if (Number(id) === Number(currentChatId)) div.classList.add('active');

    const avatarEl = document.createElement('div');
    avatarEl.className = 'chat-avatar-small';
    avatarEl.style.background = avatarBackground(avatar);
    avatarEl.textContent = (name || '?').charAt(0).toUpperCase();

    const info = document.createElement('div');
    info.className = 'chat-info';
    const nameEl = document.createElement('div');
    nameEl.className = 'chat-name';
    nameEl.textContent = name;
    const lastEl = document.createElement('div');
    lastEl.className = 'chat-last';
    lastEl.textContent = lastText;
    info.append(nameEl, lastEl);

    div.append(avatarEl, info);
    setChatBadge(div, unread);
    div.addEventListener('click', onClick);
    div.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onClick();
        }
    });
    return div;
}

let loadChatsSeq = 0;
async function loadChats() {
    const seq = ++loadChatsSeq;
    const data = await api('/api/chats');
    if (!data.success || seq !== loadChatsSeq || chatListMode !== 'chats') return;
    const fragment = document.createDocumentFragment();
    data.chats.forEach(chat => {
        const lastText = chat.last_message_encrypted
            ? '🔒 Зашифрованное сообщение'
            : chat.last_message_id
                ? `${chat.last_message_type && chat.last_message_type !== 'text' ? '📎 ' : ''}${chat.last_message || ''}`
                : 'Нет сообщений';
        fragment.appendChild(createChatItem({
            id: chat.id,
            roomId: chat.room_id,
            name: chat.name,
            avatar: chat.avatar,
            lastText,
            unread: Number(chat.id) === Number(currentChatId) ? 0 : chat.unread,
            onClick: () => openChat(chat.id, chat.room_id, chat.name, chat.avatar, chat.online, chat.is_bot),
        }));
    });
    elements.chatsList.replaceChildren(fragment);
}

// Список чатов перезапрашивается не чаще раза в полсекунды — раньше КАЖДОЕ
// входящее сообщение в любом неоткрытом чате вызывало GET /api/chats (самый
// тяжёлый запрос сервера) и быстро упиралось в rate limit.
let loadChatsTimer = null;
function scheduleLoadChats() {
    if (chatListMode !== 'chats' || !currentUser) return;
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

// Новое сообщение обновляет список чатов на месте (превью, бейдж, порядок)
// без запроса к серверу.
function updateChatListOnMessage(message, isCurrent) {
    if (chatListMode !== 'chats') return;
    const item = findChatItem(message.chat_id, message.room_id);
    if (!item) return scheduleLoadChats(); // новый для нас чат
    const lastEl = item.querySelector('.chat-last');
    if (lastEl) lastEl.textContent = messagePreview(message);
    if (!isCurrent && !isOwnMessage(message)) {
        const badge = item.querySelector('.chat-badge');
        setChatBadge(item, (badge ? Number(badge.dataset.count) || 0 : 0) + 1);
    }
    if (elements.chatsList.firstElementChild !== item) elements.chatsList.prepend(item);
}

function setActiveChatItem(chatId, roomId) {
    elements.chatsList.querySelectorAll('.chat-item.active').forEach(el => el.classList.remove('active'));
    const item = findChatItem(chatId, roomId);
    if (item) {
        item.classList.add('active');
        setChatBadge(item, 0);
    }
}

// ==================== Открытый чат ====================

async function openChat(chatId, roomId, name, avatar, online, isBot) {
    const seq = ++openChatSeq;
    releaseChatResources();
    currentChatId = chatId;
    currentRoomId = roomId || null;
    const room = currentRoomId;
    oldestMessageId = null;
    hasMoreHistory = false;
    loadingHistory = false;
    lastSeenMessageId = 0;
    cancelEditing();
    clearReply();

    elements.chatName.textContent = name;
    elements.chatStatus.textContent = isBot ? 'Бот' : (online ? 'В сети' : 'Не в сети');
    elements.chatStatus.className = 'status ' + (online ? 'online' : 'offline');
    elements.chatAvatar.textContent = (name || '?').charAt(0).toUpperCase();
    elements.chatAvatar.style.background = avatarBackground(avatar);
    elements.chatHeader.classList.remove('hidden');
    elements.messageInputContainer.classList.remove('hidden');
    elements.emptyState.classList.add('hidden');
    elements.chatMessages.replaceChildren();
    elements.sidebar.classList.add('hidden-mobile');
    setActiveChatItem(chatId, room);
    updateE2eeToggleUI(chatId, room);

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
    if (reply.deleted) return '↩️ Сообщение удалено';
    return `↩️ ${reply.sender_username || 'Неизвестно'}: ${(reply.text || '').substring(0, 60)}`;
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
        if (textEl) {
            textEl.textContent = displayText;
            textEl.classList.toggle('e2ee-failed', failed);
        }
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

// Статус своего сообщения. При выключенных у себя отметках о прочтении ✓✓
// не показываем (взаимность, как в Signal): не сообщаешь сам — не видишь чужие.
function renderMessageStatus(el) {
    const status = el.querySelector('.message-status');
    if (!status) return;
    const read = readReceiptsEnabled() && Boolean(el._message) && el._message.status === 'read';
    status.textContent = read ? '✓✓' : '✓';
    status.title = read ? 'Прочитано' : 'Отправлено';
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
    const wrapper = document.createElement('div');
    wrapper.className = 'file-attachment';
    const a = document.createElement('a');
    a.href = file_url;
    a.target = '_blank';
    a.rel = 'noopener';
    a.download = file_name || 'file';
    a.textContent = `📎 ${file_name || 'Файл'}`;
    wrapper.appendChild(a);
    return wrapper;
}

function createAttachmentElement(message) {
    if (!message.encrypted) return message.file_url ? createFileAttachmentElement(message) : null;
    // Зашифрованное вложение: ключ файла — внутри E2EE-конверта. Если сам
    // конверт не расшифровался, текст сообщения уже говорит об этом, а
    // ссылка на шифротекст (.bin) пользователю ни к чему.
    return message._file ? createEncryptedAttachmentElement(message) : null;
}

function createPlaintextLabel() {
    const label = document.createElement('span');
    label.className = 'plaintext-label';
    label.textContent = '🔓 без сквозного шифрования';
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
        replyDiv.appendChild(small);
        contentDiv.appendChild(replyDiv);
    }
    const attachment = createAttachmentElement(message);
    if (attachment) contentDiv.appendChild(attachment);
    const textDiv = document.createElement('div');
    textDiv.className = 'message-text' + (message._e2eeFailed ? ' e2ee-failed' : '');
    textDiv.textContent = message.text || '';
    contentDiv.appendChild(textDiv);

    if (message.edited_at) {
        const editedDiv = document.createElement('div');
        editedDiv.className = 'edited-label';
        editedDiv.textContent = 'изменено';
        contentDiv.appendChild(editedDiv);
    }
    if (message.reactions && message.reactions.length > 0) {
        const reactionsDiv = document.createElement('div');
        reactionsDiv.className = 'reactions';
        message.reactions.forEach(r => {
            const span = document.createElement('span');
            span.className = 'reaction';
            span.textContent = r;
            reactionsDiv.appendChild(span);
        });
        contentDiv.appendChild(reactionsDiv);
    }

    const metaDiv = document.createElement('div');
    metaDiv.className = 'message-meta';
    if (shouldMarkPlaintext(message)) metaDiv.appendChild(createPlaintextLabel());
    if (message.encrypted) {
        const lockSpan = document.createElement('span');
        lockSpan.className = 'message-lock';
        lockSpan.textContent = '🔒';
        lockSpan.title = 'Сквозное шифрование';
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
        showMessageMenu(e.clientX, e.clientY, message);
    });

    div.addEventListener('touchstart', (e) => {
        clearTimeout(longPressTimer);
        longPressTimer = setTimeout(() => {
            const touch = e.touches[0];
            showMessageMenu(touch.clientX, touch.clientY, message);
        }, 600);
    }, { passive: true });

    div.addEventListener('touchend', () => clearTimeout(longPressTimer));
    div.addEventListener('touchmove', () => clearTimeout(longPressTimer));

    return div;
}

function showMessageMenu(x, y, message) {
    menuMessage = message;
    elements.messageMenu.style.left = Math.min(x, window.innerWidth - 200) + 'px';
    elements.messageMenu.style.top = Math.min(y, window.innerHeight - 150) + 'px';
    elements.messageMenu.classList.remove('hidden');
    const isMine = isOwnMessage(message);
    // Файлы не редактируются; нерасшифрованное — тоже (в поле ввода попал
    // бы текст "Не удалось расшифровать", а не само сообщение).
    elements.editMessageBtn.classList.toggle('hidden', !(isMine && !message.file_url && !message._e2eeFailed));
    elements.deleteMessageBtn.classList.toggle('hidden', !isMine);
}

function hideMessageMenu() {
    elements.messageMenu.classList.add('hidden');
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

let sending = false;
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
            let client;
            try {
                client = await prepareOutgoingE2ee(chatId, roomId);
            } catch (err) {
                showToast(err.message, 'error', 6000);
                return;
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
                    return;
                }
            }
            const payload = { chatId, text: outgoingText, encrypted };
            if (replyToMessageId) payload.replyToId = replyToMessageId;
            const data = await api('/api/messages', {
                method: 'POST',
                body: JSON.stringify(payload),
            });
            if (!data.success) {
                showToast(data.message || 'Не удалось отправить сообщение', 'error');
                return;
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

// Вложение: проверка типа по белому списку → удаление метаданных на
// клиенте (сервер при открытой отправке снимает их ещё раз, но исходные
// EXIF/GPS так до него вообще не доходят) → в E2EE-комнате шифрование
// файла, а ключ файла, MIME и имя — внутри E2EE-конверта сообщения.
let uploadingFile = false;
async function handleFileUpload() {
    const file = elements.fileInput.files[0];
    elements.fileInput.value = '';
    if (!file || !currentChatId || uploadingFile) return;
    if (file.size > MAX_UPLOAD_BYTES) {
        showToast('Файл слишком большой (макс. 50 МБ)', 'error');
        return;
    }
    const mime = detectFileMime(file);
    if (!isSupportedMime(mime)) {
        showToast('Этот тип файлов не поддерживается: можно отправлять фото, видео, аудио, PDF и TXT', 'error', 5000);
        return;
    }

    const chatId = currentChatId;
    const roomId = currentRoomId;
    uploadingFile = true;
    elements.attachBtn.disabled = true;
    try {
        let client;
        try {
            client = await prepareOutgoingE2ee(chatId, roomId);
        } catch (err) {
            showToast(err.message, 'error', 6000);
            return;
        }

        showToast('Удаление метаданных…', 'info');
        let clean;
        try {
            clean = MediaSanitizer.sanitize(new Uint8Array(await file.arrayBuffer()), mime);
        } catch (err) {
            console.warn('MediaSanitizer: файл отклонён:', err);
            showToast('Не удалось обработать файл: он повреждён или его формат не поддерживается', 'error', 5000);
            return;
        }

        const formData = new FormData();
        formData.append('chatId', String(chatId));
        let localFile = null;
        if (client) {
            showToast('Шифрование файла…', 'info');
            let envelope;
            let enc;
            try {
                enc = await client.encryptFile(clean);
                if (enc.ciphertext.byteLength > MAX_UPLOAD_BYTES) {
                    showToast('Файл слишком большой для отправки с шифрованием (макс. 50 МБ)', 'error');
                    return;
                }
                localFile = { mime, name: encryptedFileName(file, mime), size: enc.size, key: enc.key, iv: enc.iv };
                envelope = await client.encryptOutgoing(roomId, { type: 'file', ...localFile, caption: '' });
            } catch (err) {
                console.error('E2EE: не удалось зашифровать файл:', err);
                showToast('Не удалось зашифровать файл', 'error');
                return;
            }
            // Порядок полей важен: сервер читает chatId/encrypted/envelope
            // до того, как начнёт принимать сам файл.
            formData.append('encrypted', 'true');
            formData.append('envelope', envelope);
            formData.append('file', new Blob([enc.ciphertext], { type: 'application/octet-stream' }), 'blob');
        } else {
            formData.append('file', new Blob([clean], { type: mime }), anonymousFileName(mime));
        }

        showToast('Загрузка файла…', 'info');
        const data = await postFormData('/api/messages/file', formData);
        if (!data.success) {
            showToast(data.message || 'Не удалось отправить файл', 'error');
            return;
        }
        elements.toast.classList.add('hidden');
        if (chatId === currentChatId && data.message) {
            const message = localFile
                ? { ...data.message, text: '', _file: localFile, _localBytes: clean }
                : data.message;
            if (appendMessage(message, true)) scrollToBottom();
            updateChatListOnMessage(message, true);
        }
    } catch (err) {
        console.error('File upload failed:', err);
        showToast('Не удалось отправить файл', 'error');
    } finally {
        uploadingFile = false;
        elements.attachBtn.disabled = false;
    }
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

async function joinChat() {
    // Код показывается группами через пробел — убираем пробелы и дефисы
    // здесь же (сервер делает то же самое).
    const code = document.getElementById('join-chat-code').value.replace(/[\s-]+/g, '').toUpperCase();
    if (!code) return showToast('Введите код', 'error');
    const data = await api('/api/chats/join', {
        method: 'POST',
        body: JSON.stringify({ code }),
    });
    if (data.success) {
        document.getElementById('join-chat-code').value = '';
        showToast('Вы присоединились к чату', 'success');
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
    header.className = 'search-section-title';
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

    const { chats = [], messages = [] } = data.results || {};
    const fragment = document.createDocumentFragment();
    if (chats.length > 0) {
        fragment.appendChild(renderSearchSection('Чаты'));
        chats.forEach(chat => {
            fragment.appendChild(createChatItem({
                id: chat.id, roomId: chat.room_id, name: chat.name, avatar: chat.avatar,
                lastText: chat.room_id ? 'Групповой чат' : 'Личный чат', unread: 0,
                onClick: () => openChat(chat.id, chat.room_id, chat.name, chat.avatar, chat.online, chat.is_bot),
            }));
        });
    }
    // Раньше найденные сообщения сервер возвращал, но они нигде не выводились.
    if (messages.length > 0) {
        fragment.appendChild(renderSearchSection('Сообщения'));
        messages.forEach(m => {
            fragment.appendChild(createChatItem({
                id: m.chat_id, roomId: m.room_id, name: m.chat_name, avatar: m.avatar,
                lastText: m.text, unread: 0,
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

function scrollToBottom() {
    elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
    markVisibleMessagesRead();
}

init();
