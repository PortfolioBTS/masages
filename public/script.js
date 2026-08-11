const socket = io();
let currentChatId = null;
let currentRoomId = null;
let currentUser = null;
let replyToMessageId = null;
let editingMessageId = null;
let longPressTimer = null;

const elements = {
    authScreen: document.getElementById('auth-screen'),
    app: document.getElementById('app'),
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
};

function init() {
    checkAuth();
    setupEventListeners();
}

async function checkAuth() {
    try {
        const res = await fetch('/api/auth');
        const data = await res.json();
        if (data.authenticated) {
            currentUser = data.user;
            showApp();
            loadChats();
        } else {
            showAuth();
        }
    } catch (e) {
        showAuth();
    }
}

function showAuth() {
    elements.authScreen.classList.remove('hidden');
    elements.app.classList.add('hidden');
}

function showApp() {
    elements.authScreen.classList.add('hidden');
    elements.app.classList.remove('hidden');
}

function showToast(message, type = 'info') {
    elements.toast.textContent = message;
    elements.toast.className = `toast ${type}`;
    elements.toast.classList.remove('hidden');
    setTimeout(() => elements.toast.classList.add('hidden'), 3000);
}

function getCsrfToken() {
    const match = document.cookie.match(/csrf_token=([^;]+)/);
    return match ? match[1] : '';
}

async function api(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken(),
        ...options.headers,
    };
    const res = await fetch(url, { ...options, headers });
    return res.json();
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
            currentUser = data.user;
            showToast('Вход выполнен!', 'success');
            showApp();
            loadChats();
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
            currentUser = data.user;
            showToast('Регистрация успешна!', 'success');
            showApp();
            loadChats();
        } else {
            showToast(data.message, 'error');
        }
    });

    elements.anonymousLoginBtn.addEventListener('click', async () => {
        const data = await api('/api/register/anonymous', { method: 'POST' });
        if (data.success) {
            currentUser = data.user;
            showToast('Приватный режим активирован!', 'success');
            showApp();
            loadChats();
        } else {
            showToast(data.message, 'error');
        }
    });

    elements.logoutBtn.addEventListener('click', async () => {
        await api('/api/logout', { method: 'POST' });
        currentUser = null;
        currentChatId = null;
        currentRoomId = null;
        showToast('Вы вышли из аккаунта', 'info');
        showAuth();
    });

    elements.newChatBtn.addEventListener('click', () => openModal(elements.newChatModal));
    elements.createChatBtn.addEventListener('click', createChat);
    elements.joinChatBtn.addEventListener('click', joinChat);

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

    elements.copyInviteBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(elements.inviteCodeDisplay.textContent);
        showToast('Код скопирован!', 'success');
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
            setTimeout(() => {
                currentUser = null;
                showAuth();
            }, 1500);
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
            }
        });
    });

    elements.sendBtn.addEventListener('click', sendMessage);
    elements.messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
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
    });

    elements.editMessageBtn.addEventListener('click', () => {
        editingMessageId = elements.messageMenu.dataset.messageId;
        const text = elements.messageMenu.dataset.messageText;
        elements.messageInput.value = text;
        elements.messageInput.focus();
        hideMessageMenu();
    });

    elements.deleteMessageBtn.addEventListener('click', async () => {
        const messageId = elements.messageMenu.dataset.messageId;
        const data = await api(`/api/messages/${messageId}`, { method: 'DELETE' });
        if (data.success) {
            showToast('Сообщение удалено', 'success');
            const el = document.querySelector(`[data-message-id="${messageId}"]`);
            if (el) el.remove();
        } else {
            showToast(data.message, 'error');
        }
        hideMessageMenu();
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

    socket.on('newMessage', (message) => {
        if (message.chat_id == currentChatId || message.room_id == currentRoomId) {
            appendMessage(message);
            scrollToBottom();
        } else {
            loadChats();
        }
    });

    socket.on('messageEdited', ({ id, text, chat_id, room_id }) => {
        if (chat_id == currentChatId || room_id == currentRoomId) {
            const bubble = document.querySelector(`[data-message-id="${id}"]`);
            if (!bubble) return;
            const textEl = bubble.querySelector('.message-text');
            if (textEl) textEl.textContent = text;
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
    });

    socket.on('messageDeleted', ({ id, chat_id, room_id }) => {
        if (chat_id == currentChatId || room_id == currentRoomId) {
            const bubble = document.querySelector(`[data-message-id="${id}"]`);
            if (bubble) bubble.remove();
        }
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

async function loadChats() {
    const data = await api('/api/chats');
    if (!data.success) return;
    elements.chatsList.innerHTML = '';
    data.chats.forEach(chat => {
        const div = document.createElement('div');
        div.className = 'chat-item';
        div.dataset.id = chat.id;
        div.dataset.roomId = chat.room_id || '';
        div.innerHTML = `
            <div class="chat-avatar-small" style="background:${chat.avatar && chat.avatar.startsWith('#') ? chat.avatar : '#667EEA'}">${chat.name.charAt(0).toUpperCase()}</div>
            <div class="chat-info">
                <div class="chat-name">${escapeHtml(chat.name)}</div>
                <div class="chat-last">${chat.last_message ? escapeHtml(chat.last_message.substring(0, 30)) : 'Нет сообщений'}</div>
            </div>
            ${chat.unread > 0 ? `<div class="chat-badge">${chat.unread}</div>` : ''}
        `;
        div.addEventListener('click', () => openChat(chat.id, chat.room_id, chat.name, chat.avatar, chat.online, chat.is_bot));
        elements.chatsList.appendChild(div);
    });
}

async function openChat(chatId, roomId, name, avatar, online, isBot) {
    currentChatId = chatId;
    currentRoomId = roomId;
    elements.chatName.textContent = name;
    elements.chatStatus.textContent = isBot ? 'Бот' : (online ? 'В сети' : 'Не в сети');
    elements.chatStatus.className = 'status ' + (online ? 'online' : 'offline');
    elements.chatAvatar.textContent = name.charAt(0).toUpperCase();
    elements.chatAvatar.style.background = (avatar && avatar.startsWith('#')) ? avatar : '#667EEA';
    elements.chatHeader.classList.remove('hidden');
    elements.messageInputContainer.classList.remove('hidden');
    elements.emptyState.classList.add('hidden');
    elements.chatMessages.innerHTML = '';

    const data = await api(`/api/messages/${chatId}`);
    if (!data.success) return;

    if (data.messages) {
        data.messages.forEach(msg => appendMessage(msg));
        scrollToBottom();
    }

    const roomKey = roomId ? `room:${roomId}` : `chat:${chatId}`;
    socket.emit('joinChat', roomKey);
}

function appendMessage(message) {
    const el = createMessageElement(message);
    elements.chatMessages.appendChild(el);
}

function createMessageElement(message) {
    const isMine = message.user_id === (currentUser ? currentUser.id : 0);
    const div = document.createElement('div');
    div.className = `message ${isMine ? 'sent' : 'received'}`;
    div.dataset.messageId = message.id;

    let content = '';
    if (message.deleted) {
        content = '<em>Сообщение удалено</em>';
    } else {
        if (message.reply_to) {
            content += `<div class="reply-to"><small>↩️ ${escapeHtml(message.reply_to.sender_username || 'Неизвестно')}: ${escapeHtml(message.reply_to.text || '').substring(0, 60)}</small></div>`;
        }
        if (message.file_url) {
            if (message.message_type === 'image') {
                content += `<img src="${message.file_url}" class="message-image" loading="lazy" onclick="window.open('${message.file_url}', '_blank')">`;
            } else if (message.message_type === 'video') {
                content += `<video src="${message.file_url}" controls class="message-video"></video>`;
            } else if (message.message_type === 'audio') {
                content += `<audio src="${message.file_url}" controls class="message-audio"></audio>`;
            } else {
                content += `<div class="file-attachment"><a href="${message.file_url}" target="_blank" download="${escapeHtml(message.file_name || 'file')}">📎 ${escapeHtml(message.file_name || 'Файл')}</a></div>`;
            }
        }
        content += `<div class="message-text">${escapeHtml(message.text || '')}</div>`;
        if (message.edited_at) {
            content += `<div class="edited-label">изменено</div>`;
        }
        if (message.reactions && message.reactions.length > 0) {
            content += `<div class="reactions">${message.reactions.map(r => `<span class="reaction">${escapeHtml(r)}</span>`).join('')}</div>`;
        }
    }

    const time = message.time || '';
    div.innerHTML = `
        <div class="message-content">${content}</div>
        <div class="message-meta">
            <span class="message-time">${time}</span>
            ${isMine ? `<span class="message-status">${message.status === 'read' ? '✓✓' : (message.status === 'delivered' ? '✓' : '○')}</span>` : ''}
        </div>
    `;

    div.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        if (message.deleted) return;
        showMessageMenu(e.pageX, e.pageY, message);
    });

    div.addEventListener('touchstart', (e) => {
        longPressTimer = setTimeout(() => {
            const touch = e.touches[0];
            showMessageMenu(touch.pageX, touch.pageY, message);
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
    const isMine = message.user_id === (currentUser ? currentUser.id : 0);
    elements.editMessageBtn.style.display = isMine ? 'block' : 'none';
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

async function sendMessage() {
    const text = elements.messageInput.value.trim();
    if (!text) return;
    if (!currentChatId) {
        showToast('Выберите чат', 'error');
        return;
    }
    const payload = { chatId: currentChatId, text };
    if (replyToMessageId) payload.replyToId = replyToMessageId;

    if (editingMessageId) {
        const data = await api(`/api/messages/${editingMessageId}`, {
            method: 'PUT',
            body: JSON.stringify({ text }),
        });
        if (data.success) {
            showToast('Сообщение изменено', 'success');
            const el = document.querySelector(`[data-message-id="${editingMessageId}"] .message-text`);
            if (el) el.textContent = text;
        }
        editingMessageId = null;
    } else {
        await api('/api/messages', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
    }

    elements.messageInput.value = '';
    clearReply();
}

async function handleFileUpload() {
    const file = elements.fileInput.files[0];
    if (!file || !currentChatId) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('chatId', currentChatId);

    const res = await fetch('/api/messages/file', {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();
    if (!data.success) {
        showToast(data.message, 'error');
    }
    elements.fileInput.value = '';
}

async function createChat() {
    const name = document.getElementById('new-chat-name').value.trim();
    if (!name) return showToast('Введите название', 'error');
    const data = await api('/api/chats', {
        method: 'POST',
        body: JSON.stringify({ name }),
    });
    if (data.success) {
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
        currentChatId = null;
        currentRoomId = null;
        elements.chatHeader.classList.add('hidden');
        elements.messageInputContainer.classList.add('hidden');
        elements.emptyState.classList.remove('hidden');
        elements.chatMessages.innerHTML = '';
        loadChats();
    } else {
        showToast(data.message, 'error');
    }
}

async function performSearch() {
    const q = elements.searchInput.value.trim();
    if (!q) return loadChats();
    const data = await api(`/api/search?q=${encodeURIComponent(q)}`);
    if (!data.success) return;
    elements.chatsList.innerHTML = '';
    if (data.results.chats) {
        data.results.chats.forEach(chat => {
            const div = document.createElement('div');
            div.className = 'chat-item';
            div.innerHTML = `<div class="chat-name">${escapeHtml(chat.name)}</div>`;
            div.addEventListener('click', () => openChat(chat.id, null, chat.name, chat.avatar, 0, 0));
            elements.chatsList.appendChild(div);
        });
    }
}

function scrollToBottom() {
    elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

init();
