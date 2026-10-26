// public/js/06-session-socket.js — proof-of-work регистрации, сессия и сокет.
// Вынесено из public/script.js (строки 1823–2395 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Вход и keepalive, плановое обслуживание ключей, несколько вкладок (BroadcastChannel), индикатор соединения.
// Здесь же на верхнем уровне навешиваются обработчики socket.on(...) — они срабатывают позже, при событиях сокета.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

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
// (подписанный состав группы, signed-membership.md) хранится рядом с кодом и на
// сервер не отправляется: по нему клиент подписывает вход без одобрения.
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
    finishEditing();
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
    unknownSend = null;
    chatListData = [];
    chatsById.clear();
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
