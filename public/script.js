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
let longPressTimer = null;
let e2eeClient = null; // см. секцию "E2EE" ниже — создаётся лениво под currentUser.id

// Состояние открытого чата: история грузится страницами с конца.
let openChatSeq = 0;          // защита от гонок при быстром переключении чатов
let oldestMessageId = null;   // самый старый загруженный — курсор для ?before=
let hasMoreHistory = false;
let loadingHistory = false;
let lastSeenMessageId = 0;    // до какого id пользователь уже видел открытый чат
let chatListMode = 'chats';   // 'chats' | 'search' — что сейчас показано в сайдбаре

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
    createChatBtn: document.getElementById('create-chat-btn'),
    joinChatBtn: document.getElementById('join-chat-btn'),
    deleteChatBtn: document.getElementById('delete-chat-btn'),
    getChatCodeBtn: document.getElementById('get-chat-code-btn'),
    chatMenuBtn: document.getElementById('chat-menu-btn'),
    profileBtn: document.getElementById('profile-btn'),
    changePasswordBtn: document.getElementById('change-password-btn'),
    savePasswordBtn: document.getElementById('save-password-btn'),
    inviteCodeDisplay: document.getElementById('invite-code-display'),
    copyInviteBtn: document.getElementById('copy-invite-btn'),
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
    e2eeToggleBtn: document.getElementById('e2ee-toggle-btn'),
};

// ==================== E2EE (X3DH + Sender Keys) ====================
// Ключи устройства хранятся в IndexedDB, отдельная база на каждого
// currentUser.id — это исключает утечку ключевого материала между
// разными аккаунтами на одном браузере (общий компьютер, тест-логины).
// Подробности протокола и честные ограничения — см. public/e2ee.js.

function getE2eeClient() {
    if (!currentUser) return null;
    if (!e2eeClient || e2eeClient.forUserId !== currentUser.id) {
        e2eeClient = E2EE.createClient({
            userId: currentUser.id,
            storage: E2EE.makeIndexedDbStorage('nyxo-e2ee-' + currentUser.id),
        });
        e2eeClient.forUserId = currentUser.id;
    }
    return e2eeClient;
}

function initE2eeForCurrentUser() {
    const client = getE2eeClient();
    if (!client) return;
    // Не блокируем показ приложения генерацией/загрузкой ключей.
    client.init().catch(err => console.error('E2EE: инициализация ключей устройства не удалась:', err));
}

function e2eeStorageKey(chatId) {
    return `e2ee-enabled:${currentUser ? currentUser.id : '0'}:${chatId}`;
}

function isE2eeEnabledForChat(chatId) {
    try {
        return localStorage.getItem(e2eeStorageKey(chatId)) === '1';
    } catch {
        return false;
    }
}

function updateE2eeToggleUI(chatId, roomId) {
    if (!elements.e2eeToggleBtn) return;
    if (!roomId) {
        // Боту/одиночному чату групповое E2EE не подходит — прячем тумблер,
        // чтобы не обещать шифрование там, где его некому подтвердить.
        elements.e2eeToggleBtn.classList.add('hidden');
        elements.messageInput.placeholder = 'Сообщение...';
        return;
    }
    elements.e2eeToggleBtn.classList.remove('hidden');
    const enabled = isE2eeEnabledForChat(chatId);
    elements.e2eeToggleBtn.textContent = enabled ? '🔒' : '🔓';
    elements.e2eeToggleBtn.classList.toggle('e2ee-active', enabled);
    elements.e2eeToggleBtn.title = enabled ? 'Сквозное шифрование включено' : 'Включить сквозное шифрование';
    elements.messageInput.placeholder = enabled ? 'Зашифрованное сообщение...' : 'Сообщение...';
}

// Готовит комнату к шифрованию: создаёт (если ещё нет) свой Sender Key и
// досылает его участникам, кому текущая версия ключа ещё не отправлена.
// Идемпотентна — безопасно звать при каждом открытии чата, в том числе
// чтобы со временем подхватить участников, добавленных позже.
// Возвращает { others, failed, serverRejected } или null при ошибке.
async function ensureE2eeRoomReady(chatId, roomId) {
    const client = getE2eeClient();
    if (!client || !roomId) return null;
    try {
        const partRes = await api(`/api/chats/${chatId}/participants`);
        if (!partRes.success || !partRes.roomId) return null;
        const result = await client.ensureRoomSession(chatId, partRes.roomId, partRes.participants);
        if (result.warnings && result.warnings.length > 0) {
            console.warn('E2EE: не со всеми участниками установлен защищённый канал:', result.warnings);
        }
        const warnings = result.warnings || [];
        return {
            others: partRes.participants.filter(p => Number(p.id) !== Number(currentUser.id)).length,
            failed: new Set(warnings.filter(w => w.userId != null).map(w => Number(w.userId))).size,
            serverRejected: warnings.some(w => w.userId == null),
        };
    } catch (err) {
        console.error('E2EE: не удалось подготовить сессию комнаты:', err);
        return null;
    }
}

// Забирает ожидающие key-share для этого чата (от других участников,
// включивших у себя шифрование) — нужно делать ДО расшифровки входящих
// сообщений, иначе их Sender Key ещё не будет известен локально.
let keySyncInFlight = null;
let lastKeySyncAt = 0;
function syncE2eeKeyShares(chatId, roomId) {
    const client = getE2eeClient();
    if (!client || !roomId) return Promise.resolve();
    if (keySyncInFlight) return keySyncInFlight;
    lastKeySyncAt = Date.now();
    keySyncInFlight = client.syncKeyShares(chatId, roomId)
        .catch(err => console.error('E2EE: syncKeyShares failed:', err))
        .finally(() => { keySyncInFlight = null; });
    return keySyncInFlight;
}

// Расшифровывает сообщение "на месте" перед рендерингом — после этого
// вызова весь остальной код (createMessageElement, предпросмотр ответа,
// редактирование) работает с message.text как с обычным открытым
// текстом, будто шифрования и не было.
async function decryptEnvelope(roomId, senderId, text) {
    const client = getE2eeClient();
    if (!client || !roomId) return { ok: false };
    let res = await client.decryptIncoming(roomId, senderId, text);
    // Sender Key отправителя мог прийти (e2eeKeyShare) буквально перед
    // самим сообщением — один раз досинхронизируем ключи и пробуем снова.
    if (!res.ok && (res.reason === 'no-sender-key' || res.reason === 'stale-sender-key')
        && currentChatId && Date.now() - lastKeySyncAt > 3000) {
        await syncE2eeKeyShares(currentChatId, roomId);
        res = await client.decryptIncoming(roomId, senderId, text);
    }
    return res;
}

async function decryptMessageInPlace(message, roomId) {
    if (message.encrypted) {
        if (roomId) {
            const res = await decryptEnvelope(roomId, message.user_id, message.text);
            message.text = res.ok ? res.text : '🔒 Не удалось расшифровать';
            message._e2eeFailed = !res.ok;
        } else {
            message.text = '🔒 Зашифрованное сообщение';
            message._e2eeFailed = true;
        }
    }
    if (message.reply_to && message.reply_to.encrypted && !message.reply_to.deleted) {
        const replyRes = roomId ? await decryptEnvelope(roomId, message.reply_to.sender_id, message.reply_to.text) : { ok: false };
        message.reply_to.text = replyRes.ok ? replyRes.text : '🔒 Не удалось расшифровать';
    }
    return message;
}

async function decryptMessagesInPlace(messages, roomId) {
    for (const m of messages) await decryptMessageInPlace(m, roomId);
    return messages;
}

if (elements.e2eeToggleBtn) {
    elements.e2eeToggleBtn.addEventListener('click', async () => {
        if (!currentChatId || !currentRoomId) return;
        const chatId = currentChatId;
        const roomId = currentRoomId;
        const enabling = !isE2eeEnabledForChat(chatId);
        if (enabling) {
            elements.e2eeToggleBtn.disabled = true;
            elements.e2eeToggleBtn.textContent = '⏳';
            const status = await ensureE2eeRoomReady(chatId, roomId);
            elements.e2eeToggleBtn.disabled = false;
            // Раньше шифрование включалось даже когда ключ не получил НИ
            // ОДИН собеседник (например, не настроен e2ee-key-server) — и все
            // дальнейшие сообщения у остальных показывались как "Не удалось
            // расшифровать".
            if (!status || status.serverRejected || (status.others > 0 && status.failed === status.others)) {
                updateE2eeToggleUI(chatId, roomId);
                showToast('Не удалось включить шифрование: собеседники не смогут прочитать сообщения', 'error');
                return;
            }
            if (status.failed > 0) {
                showToast(`Шифрование включено, но ${status.failed} участник(ов) пока не смогут читать сообщения`, 'info');
            }
        }
        try {
            localStorage.setItem(e2eeStorageKey(chatId), enabling ? '1' : '0');
        } catch { /* приватный режим браузера без localStorage */ }
        if (chatId !== currentChatId) return; // пользователь уже ушёл в другой чат
        updateE2eeToggleUI(chatId, roomId);
        showToast(enabling ? 'Шифрование включено для этого чата' : 'Шифрование выключено для этого чата', 'success');
    });
}

socket.on('e2eeKeyShare', ({ roomId }) => {
    // Кто-то прислал нам Sender Key. Если это открытый сейчас чат —
    // подхватываем сразу, иначе заберём при следующем открытии чата.
    if (roomId && roomId === currentRoomId && currentChatId) {
        syncE2eeKeyShares(currentChatId, currentRoomId);
    }
});

// ==================== Сессия и сокет ====================

function init() {
    checkAuth();
    try {
        setupEventListeners();
    } catch (e) {
        console.error('setupEventListeners() failed — some UI controls may not respond:', e);
    }
}

async function checkAuth() {
    try {
        const res = await fetch('/api/auth');
        const data = await res.json();
        if (data.authenticated) {
            enterApp(data.user);
        } else {
            showAuth();
        }
    } catch (e) {
        showAuth();
    }
}

function enterApp(user) {
    currentUser = user;
    initE2eeForCurrentUser();
    showApp();
    // Новое соединение = новое рукопожатие с актуальной кукой сессии.
    if (socket.connected) socket.disconnect();
    socket.connect();
    loadChats();
}

function resetChatView() {
    currentChatId = null;
    currentRoomId = null;
    oldestMessageId = null;
    hasMoreHistory = false;
    lastSeenMessageId = 0;
    openChatSeq++;
    elements.chatHeader.classList.add('hidden');
    elements.messageInputContainer.classList.add('hidden');
    elements.emptyState.classList.remove('hidden');
    elements.chatMessages.replaceChildren();
    elements.sidebar.classList.remove('hidden-mobile');
    clearReply();
    editingMessageId = null;
}

function leaveApp(message) {
    socket.disconnect();
    currentUser = null;
    e2eeClient = null; // ключи устройства остаются в IndexedDB под старым userId для следующего входа
    resetChatView();
    elements.chatsList.replaceChildren();
    if (message) showToast(message, 'info');
    showAuth();
}

let authRecheckPending = false;
socket.on('connect_error', (err) => {
    // Сессия истекла (например, 4 часа анонимного режима) — сервер
    // отклоняет рукопожатие. Перепроверяем вход и показываем экран входа.
    if (err && err.message === 'Не авторизован' && !authRecheckPending) {
        authRecheckPending = true;
        fetch('/api/auth').then(r => r.json()).then((data) => {
            if (!data.authenticated) leaveApp('Сессия истекла, войдите снова');
        }).catch(() => {}).finally(() => { authRecheckPending = false; });
    }
});

socket.io.on('reconnect', () => {
    // После обрыва связи (или рестарта сервера) догружаем пропущенное.
    if (!currentUser) return;
    if (chatListMode === 'chats') loadChats();
    if (currentChatId) refreshCurrentChat();
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
function showToast(message, type = 'info') {
    elements.toast.textContent = message || '';
    elements.toast.className = `toast ${type}`;
    elements.toast.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => elements.toast.classList.add('hidden'), 3000);
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

function setupEventListeners() {
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
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
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        const data = await api('/api/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password, confirmPassword }),
        });
        if (data.success) {
            document.getElementById('register-password').value = '';
            document.getElementById('register-confirm-password').value = '';
            showToast('Регистрация успешна!', 'success');
            enterApp(data.user);
        } else {
            showToast(data.message, 'error');
        }
    });

    elements.anonymousLoginBtn.addEventListener('click', async () => {
        const data = await api('/api/register/anonymous', { method: 'POST' });
        if (data.success) {
            showToast('Приватный режим активирован!', 'success');
            enterApp(data.user);
        } else {
            showToast(data.message, 'error');
        }
    });

    elements.logoutBtn.addEventListener('click', async () => {
        await api('/api/logout', { method: 'POST' });
        leaveApp('Вы вышли из аккаунта');
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

    elements.getChatCodeBtn.addEventListener('click', async () => {
        if (!currentChatId) return;
        const data = await api(`/api/chats/invite/${currentChatId}`);
        if (data.success) {
            elements.inviteCodeDisplay.textContent = data.code;
            openModal(elements.inviteModal);
        } else {
            showToast(data.message, 'error');
        }
    });

    elements.copyInviteBtn.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(elements.inviteCodeDisplay.textContent);
            showToast('Код скопирован!', 'success');
        } catch {
            showToast('Не удалось скопировать — выделите код вручную', 'error');
        }
    });

    elements.profileBtn.addEventListener('click', async () => {
        const data = await api('/api/user');
        if (data.success) {
            elements.profileUsername.textContent = data.user.username;
            elements.profileEmail.textContent = data.user.email || 'Нет email (приватный режим)';
            elements.profileCode.textContent = `Код: ${data.user.uniqueCode}`;
            elements.profileAvatar.style.background = data.user.avatar || '#667EEA';
            elements.profileAvatar.textContent = data.user.username.charAt(0).toUpperCase();
            if (data.user.email === null || data.user.email === undefined) {
                elements.profileAnonBadge.classList.remove('hidden');
                elements.changePasswordBtn.classList.add('hidden');
            } else {
                elements.profileAnonBadge.classList.add('hidden');
                elements.changePasswordBtn.classList.remove('hidden');
            }
            openModal(elements.profileModal);
        } else {
            showToast(data.message || 'Не удалось загрузить профиль', 'error');
        }
    });

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
        replyToMessageId = elements.messageMenu.dataset.messageId;
        const text = elements.messageMenu.dataset.messageText;
        elements.replyPreviewText.textContent = text.substring(0, 100);
        elements.replyPreview.classList.remove('hidden');
        hideMessageMenu();
        elements.messageInput.focus();
    });

    elements.editMessageBtn.addEventListener('click', () => {
        editingMessageId = elements.messageMenu.dataset.messageId;
        editingMessageEncrypted = elements.messageMenu.dataset.encrypted === '1';
        const text = elements.messageMenu.dataset.messageText;
        elements.messageInput.value = text;
        elements.messageInput.focus();
        hideMessageMenu();
    });

    elements.deleteMessageBtn.addEventListener('click', async () => {
        const messageId = elements.messageMenu.dataset.messageId;
        hideMessageMenu();
        const data = await api(`/api/messages/${messageId}`, { method: 'DELETE' });
        if (data.success) {
            showToast('Сообщение удалено', 'success');
            removeMessageElement(messageId);
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
        btn.addEventListener('click', () => {
            document.querySelectorAll('.modal').forEach(m => closeModal(m));
        });
    });

    elements.overlay.addEventListener('click', () => {
        document.querySelectorAll('.modal').forEach(m => closeModal(m));
        hideMessageMenu();
    });

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
        let displayText = text;
        if (encrypted) {
            const res = await decryptEnvelope(currentRoomId, user_id, text);
            displayText = res.ok ? res.text : '🔒 Не удалось расшифровать';
        }
        applyMessageEdit(id, displayText);
        scheduleLoadChats();
    });

    socket.on('messageDeleted', ({ id, chat_id, room_id }) => {
        if (belongsToCurrentChat(chat_id, room_id)) removeMessageElement(id);
        scheduleLoadChats();
    });

    socket.on('messagesRead', ({ chat_id, room_id, up_to_id, reader_id }) => {
        if (!belongsToCurrentChat(chat_id, room_id) || (currentUser && reader_id === currentUser.id)) return;
        elements.chatMessages.querySelectorAll('.message.sent').forEach((el) => {
            if (Number(el.dataset.messageId) <= up_to_id) {
                const status = el.querySelector('.message-status');
                if (status) status.textContent = '✓✓';
            }
        });
    });

    document.addEventListener('click', () => hideMessageMenu());
    document.addEventListener('scroll', () => hideMessageMenu(), true);
}

function openModal(modal) {
    modal.classList.remove('hidden');
    elements.overlay.classList.remove('hidden');
}

function closeModal(modal) {
    modal.classList.add('hidden');
    if (!document.querySelector('.modal:not(.hidden)')) {
        elements.overlay.classList.add('hidden');
    }
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
    if (chatListMode !== 'chats') return;
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
    currentChatId = chatId;
    currentRoomId = roomId || null;
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
    setActiveChatItem(chatId, currentRoomId);
    updateE2eeToggleUI(chatId, currentRoomId);

    // История запрашивается параллельно с синхронизацией E2EE-ключей, а не
    // после неё (раньше было 2–3 последовательных запроса до первого
    // сообщения на экране). Расшифровка всё равно ждёт ключи: только что
    // полученные Sender Key других участников должны быть известны локально.
    const messagesPromise = api(`/api/messages/${chatId}`);
    if (currentRoomId) {
        await syncE2eeKeyShares(chatId, currentRoomId);
        // Досылаем свой Sender Key участникам, добавленным позже, — в фоне:
        // для показа истории это не нужно.
        if (isE2eeEnabledForChat(chatId)) ensureE2eeRoomReady(chatId, currentRoomId);
    }
    const data = await messagesPromise;
    if (seq !== openChatSeq) return; // пользователь уже открыл другой чат
    if (!data.success) {
        showToast(data.message || 'Не удалось загрузить сообщения', 'error');
        return;
    }

    await decryptMessagesInPlace(data.messages, currentRoomId);
    if (seq !== openChatSeq) return;
    renderMessages(data.messages, 'replace');
    hasMoreHistory = Boolean(data.hasMore);
    lastSeenMessageId = data.messages.length ? data.messages[data.messages.length - 1].id : 0;
    scrollToBottom();

    // Сокет уже подписан на все чаты при подключении; это — страховка для
    // чата, созданного/добавленного до переподключения.
    socket.emit('joinChat', currentRoomId ? `room:${currentRoomId}` : `chat:${chatId}`);
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

// Догружает то, что пришло, пока сокет был отключён.
async function refreshCurrentChat() {
    const seq = openChatSeq;
    const roomId = currentRoomId;
    const data = await api(`/api/messages/${currentChatId}`);
    if (seq !== openChatSeq || !data.success) return;
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

function removeMessageElement(messageId) {
    const el = elements.chatMessages.querySelector(`[data-message-id="${messageId}"]`);
    if (el) el.remove();
}

function applyMessageEdit(messageId, displayText) {
    const bubble = elements.chatMessages.querySelector(`[data-message-id="${messageId}"]`);
    if (!bubble) return;
    if (bubble._message) bubble._message.text = displayText; // чтобы меню "Ответить/Изменить" видело новый текст
    const textEl = bubble.querySelector('.message-text');
    if (textEl) textEl.textContent = displayText;
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

// Отмечаем прочитанным то, что пользователь реально видит: вкладка
// активна, чат прокручен к концу. Запрос — не чаще раза в секунду.
let markReadTimer = null;
function markVisibleMessagesRead() {
    if (!currentChatId || document.visibilityState !== 'visible' || !isNearBottom()) return;
    const last = elements.chatMessages.lastElementChild;
    const lastId = last ? Number(last.dataset.messageId) : 0;
    if (!lastId || lastId <= lastSeenMessageId) return;
    lastSeenMessageId = lastId;
    const chatId = currentChatId;
    clearTimeout(markReadTimer);
    markReadTimer = setTimeout(() => {
        api(`/api/chats/${chatId}/read`, { method: 'POST', body: JSON.stringify({ upToId: lastId }) });
    }, 1000);
}

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

    if (message.deleted) {
        const em = document.createElement('em');
        em.textContent = 'Сообщение удалено';
        contentDiv.appendChild(em);
    } else {
        if (message.reply_to) {
            const replyDiv = document.createElement('div');
            replyDiv.className = 'reply-to';
            const small = document.createElement('small');
            small.textContent = message.reply_to.deleted
                ? '↩️ Сообщение удалено'
                : `↩️ ${message.reply_to.sender_username || 'Неизвестно'}: ${(message.reply_to.text || '').substring(0, 60)}`;
            replyDiv.appendChild(small);
            contentDiv.appendChild(replyDiv);
        }
        if (message.file_url) {
            contentDiv.appendChild(createFileAttachmentElement(message));
        }
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
    }

    const metaDiv = document.createElement('div');
    metaDiv.className = 'message-meta';
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
        statusSpan.textContent = message.status === 'read' ? '✓✓' : '✓';
        statusSpan.title = message.status === 'read' ? 'Прочитано' : 'Отправлено';
        metaDiv.appendChild(statusSpan);
    }

    div.appendChild(contentDiv);
    div.appendChild(metaDiv);

    div.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        if (message.deleted) return;
        showMessageMenu(e.clientX, e.clientY, message);
    });

    div.addEventListener('touchstart', (e) => {
        clearTimeout(longPressTimer);
        longPressTimer = setTimeout(() => {
            const touch = e.touches[0];
            if (!message.deleted) showMessageMenu(touch.clientX, touch.clientY, message);
        }, 600);
    }, { passive: true });

    div.addEventListener('touchend', () => clearTimeout(longPressTimer));
    div.addEventListener('touchmove', () => clearTimeout(longPressTimer));

    return div;
}

function showMessageMenu(x, y, message) {
    elements.messageMenu.style.left = Math.min(x, window.innerWidth - 200) + 'px';
    elements.messageMenu.style.top = Math.min(y, window.innerHeight - 150) + 'px';
    elements.messageMenu.classList.remove('hidden');
    elements.messageMenu.dataset.messageId = message.id;
    elements.messageMenu.dataset.messageText = message.text || '';
    elements.messageMenu.dataset.encrypted = message.encrypted ? '1' : '0';
    const isMine = isOwnMessage(message);
    elements.editMessageBtn.style.display = isMine && !message.file_url ? 'block' : 'none';
    elements.deleteMessageBtn.style.display = isMine ? 'block' : 'none';
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

let sending = false;
async function sendMessage() {
    const text = elements.messageInput.value.trim();
    if (!text || sending) return;
    if (!currentChatId) {
        showToast('Выберите чат', 'error');
        return;
    }

    sending = true; // двойной Enter/клик не отправляет сообщение дважды
    try {
        if (editingMessageId) {
            // Шифруем правку так же, как было зашифровано исходное
            // сообщение — независимо от текущего состояния тумблера чата
            // (см. editingMessageEncrypted): сервер не принимает флаг
            // encrypted при редактировании, он фиксирован с момента
            // создания сообщения.
            let outgoingText = text;
            if (editingMessageEncrypted) {
                const client = getE2eeClient();
                if (!client || !currentRoomId) { showToast('Не удалось зашифровать правку', 'error'); return; }
                try { outgoingText = await client.encryptOutgoing(currentRoomId, text); }
                catch { showToast('Не удалось зашифровать правку', 'error'); return; }
            }
            const messageId = editingMessageId;
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
            applyMessageEdit(messageId, editingMessageEncrypted ? text : (data.text || text));
            editingMessageId = null;
            editingMessageEncrypted = false;
        } else {
            const e2eeOn = currentRoomId && isE2eeEnabledForChat(currentChatId);
            let outgoingText = text;
            let encrypted = false;
            if (e2eeOn) {
                const client = getE2eeClient();
                try {
                    outgoingText = await client.encryptOutgoing(currentRoomId, text);
                    encrypted = true;
                } catch (err) {
                    showToast('Не удалось зашифровать сообщение — попробуйте переключить шифрование', 'error');
                    return;
                }
            }
            const chatId = currentChatId;
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
                    const res = await decryptEnvelope(currentRoomId, reply.sender_id, reply.text);
                    reply.text = res.ok ? res.text : '🔒 Не удалось расшифровать';
                }
                if (appendMessage(message, true)) scrollToBottom();
                updateChatListOnMessage(message, true);
            }
        }
    } finally {
        sending = false;
    }

    elements.messageInput.value = '';
    clearReply();
}

async function handleFileUpload() {
    const file = elements.fileInput.files[0];
    elements.fileInput.value = '';
    if (!file || !currentChatId) return;
    if (file.size > 50 * 1024 * 1024) {
        showToast('Файл слишком большой (макс. 50 МБ)', 'error');
        return;
    }

    const chatId = currentChatId;
    const formData = new FormData();
    formData.append('chatId', chatId);
    formData.append('file', file);

    elements.attachBtn.disabled = true;
    showToast('Загрузка файла...', 'info');
    try {
        const res = await fetch('/api/messages/file', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json().catch(() => ({ success: false, message: `Ошибка сервера (HTTP ${res.status})` }));
        if (!data.success) {
            showToast(data.message, 'error');
            return;
        }
        elements.toast.classList.add('hidden');
        if (chatId === currentChatId && data.message) {
            if (appendMessage(data.message, true)) scrollToBottom();
            updateChatListOnMessage(data.message, true);
        }
    } catch {
        showToast('Нет соединения с сервером', 'error');
    } finally {
        elements.attachBtn.disabled = false;
    }
}

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
    const code = document.getElementById('join-chat-code').value.trim();
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
