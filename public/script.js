// State
let currentChatId = null;
let currentUser = null;
let chats = [];
let lastMessages = [];
let mediaRecorder = null;
let audioChunks = [];
let isRecordingAudio = false;
let messagePollInterval = null;
let isPollingMessages = false;
let replyToMessage = null; // Track reply mode
const MESSAGE_POLL_INTERVAL = 3000;
const RELOAD_DEBOUNCE_MS = 180;
const socket = io();
let chatsReloadTimer = null;
let messagesReloadTimer = null;
let chatsRequestId = 0;
let messagesRequestId = 0;

// DOM Elements
const authModal = document.getElementById('authModal');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const loginError = document.getElementById('loginError');
const registerError = document.getElementById('registerError');
const userInfo = document.getElementById('userInfo');
const displayUsername = document.getElementById('displayUsername');
const displayCode = document.getElementById('displayCode');
const logoutBtn = document.getElementById('logoutBtn');
const chatList = document.getElementById('chatList');
const messagesContainer = document.getElementById('messages');
const messageInput = document.getElementById('messageInput');
const emojiButton = document.getElementById('emojiButton');
const fileButton = document.getElementById('fileButton');
const voiceButton = document.getElementById('voiceButton');
const fileInput = document.getElementById('fileInput');
const recordIndicator = document.getElementById('recordIndicator');
const emojiPicker = document.getElementById('emojiPicker');
const sendBtn = document.getElementById('sendBtn');
const currentChatName = document.getElementById('currentChatName');
const currentChatStatus = document.getElementById('currentChatStatus');
const currentAvatar = document.getElementById('currentAvatar');
const settingsBtn = document.getElementById('settingsBtn');
const settingsModal = document.getElementById('settingsModal');
const closeSettings = document.getElementById('closeSettings');
const themeSelect = document.getElementById('themeSelect');
const usernameInput = document.getElementById('usernameInput');
const avatarColorInput = document.getElementById('avatarColorInput');
const avatarColorValue = document.getElementById('avatarColorValue');
const avatarColorPreview = document.getElementById('avatarColorPreview');
const settingsSaveBtn = document.getElementById('settingsSaveBtn');
const notificationsToggle = document.getElementById('notificationsToggle');
const newChatBtn = document.getElementById('newChatBtn');
const getChatCodeBtn = document.getElementById('getChatCodeBtn');
const joinCodeInput = document.getElementById('joinCodeInput');
const joinChatBtn = document.getElementById('joinChatBtn');
const inviteCodePreview = document.getElementById('inviteCodePreview');
const chatSearchBox = document.getElementById('chatSearchBox');
const replyPreview = document.getElementById('replyPreview');
const replyPreviewText = document.getElementById('replyPreviewText');
const cancelReplyBtn = document.getElementById('cancelReplyBtn');

let currentMessageSearchQuery = '';

// Initialize
async function init() {
    setupEventListeners();
    await checkAuth();
    loadSettings();
}

// Check authentication
async function checkAuth() {
    try {
        const response = await fetch('/api/auth');
        const data = await response.json();
        
        if (data.authenticated) {
            currentUser = data.user;
            showApp();
        } else {
            showAuth();
        }
    } catch (error) {
        console.error('Auth check error:', error);
        showAuth();
    }
}

// Show auth modal
function showAuth() {
    stopMessagePolling();
    clearReloadTimers();
    currentChatId = null;
    authModal.classList.remove('hidden');
    document.querySelector('.app').style.display = 'none';
}

// Show main app
function showApp() {
    authModal.classList.add('hidden');
    document.querySelector('.app').style.display = 'flex';
    displayUsername.textContent = currentUser.username;
    displayCode.textContent = currentUser.uniqueCode;
    syncAvatarColorControls();
    getChatCodeBtn.disabled = false;
    showInviteCode('');
    loadChats();
}

// Load chats from server
async function loadChats() {
    const requestId = ++chatsRequestId;
    try {
        const response = await fetch('/api/chats');
        const data = await response.json();
        if (requestId !== chatsRequestId) return;
        
        if (data.success) {
            chats = data.chats;
            renderChatList();
        }
    } catch (error) {
        console.error('Load chats error:', error);
    }
}

function normalizeAvatarColor(value) {
    const color = String(value || '').trim();
    return /^#[0-9a-fA-F]{6}$/.test(color) ? color.toUpperCase() : '#667EEA';
}

function getAvatarInitial(source) {
    const text = String(source || '').trim();
    return text ? escapeHtml(text.charAt(0).toUpperCase()) : '?';
}

function formatAvatarHtml(value) {
    const initial = getAvatarInitial(value);
    return `<span style="background:#667EEA;color:#fff;width:100%;height:100%;display:grid;place-items:center;border-radius:50%;">${initial}</span>`;
}

function formatUserAvatarHtml(colorValue, fallbackName) {
    const color = normalizeAvatarColor(colorValue);
    const initial = getAvatarInitial(fallbackName);
    return `<span style="background:${escapeHtml(color)};color:#fff;width:100%;height:100%;display:grid;place-items:center;border-radius:50%;">${initial}</span>`;
}

function updateAvatarColorPreview() {
    if (!avatarColorInput || !avatarColorPreview) return;
    const color = normalizeAvatarColor(avatarColorInput.value);
    avatarColorInput.value = color;
    if (avatarColorValue) {
        avatarColorValue.textContent = color;
    }
    const name = (usernameInput && usernameInput.value) || (currentUser && currentUser.username) || 'П';
    avatarColorPreview.style.background = color;
    avatarColorPreview.textContent = String(name).trim().charAt(0).toUpperCase() || 'П';
}

function syncAvatarColorControls() {
    if (!avatarColorInput) return;
    const color = normalizeAvatarColor(currentUser && currentUser.avatar);
    avatarColorInput.value = color;
    updateAvatarColorPreview();
}

// Render chat list
function renderChatList() {
    chatList.innerHTML = '';
    
    chats.forEach(chat => {
        const chatItem = document.createElement('div');
        chatItem.className = `chat-item ${chat.id === currentChatId ? 'active' : ''}`;
        chatItem.dataset.id = chat.id;
        
        const avatarHtml = formatAvatarHtml(chat.avatar || chat.name);
        
        chatItem.innerHTML = `
            <div class="avatar">${avatarHtml}</div>
            <div class="chat-item-info">
                <div class="chat-item-header">
                    <span class="chat-item-name">${chat.name}</span>
                    <span class="chat-item-time">${chat.last_time || ''}</span>
                </div>
                <div class="chat-item-preview">
                    ${chat.last_message || 'Нет сообщений'}
                    ${chat.invite_code ? `<span class="chat-code">Код: ${chat.invite_code}</span>` : ''}
                    ${chat.unread > 0 ? `<span class="unread-badge">${chat.unread}</span>` : ''}
                </div>
            </div>
            <button class="delete-chat-btn" title="Удалить чат">🗑</button>
        `;
        
        chatItem.addEventListener('click', (e) => {
            if (e.target.closest('.delete-chat-btn')) return;
            selectChat(chat.id);
        });

        const deleteBtn = chatItem.querySelector('.delete-chat-btn');
        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            deleteChat(chat.id, chat.name);
        });

        chatList.appendChild(chatItem);
    });
}

// Get status icon
function getStatusIcon(status) {
    switch(status) {
        case 'sent': return '✓';
        case 'delivered': return '✓✓';
        case 'read': return '✓✓';
        default: return '';
    }
}

function getChatSocketRoomKey(chat) {
    if (!chat) return null;
    return chat.room_id ? `room:${chat.room_id}` : `chat:${chat.id}`;
}

// Select chat
async function selectChat(chatId) {
    currentChatId = chatId;
    const chat = chats.find(c => c.id === chatId);
    const roomKey = getChatSocketRoomKey(chat);
    if (roomKey) {
        socket.emit('joinChat', roomKey);
    }
    
    if (chat) {
        // Update header
        currentChatName.textContent = chat.name;
        currentAvatar.innerHTML = formatAvatarHtml(chat.avatar || chat.name);
        currentChatStatus.textContent = chat.online ? 'онлайн' : 'был(а) недавно';
        currentChatStatus.className = `chat-status ${chat.online ? '' : 'offline'}`;
        
        // Invite code button for shared chats
        getChatCodeBtn.disabled = false;
        if (!chat.room_id) {
            showInviteCode('');
        }
        
        // Reset reply preview when switching chats
        clearReplyMode();

        // Enable input
        messageInput.disabled = false;
        sendBtn.disabled = false;
        messageInput.focus();
        
        // Load messages
        await loadMessages(chatId);
        renderChatList();
        startMessagePolling();



        // Мобильная навигация — показать чат
        if (window.innerWidth <= 768) {
            document.querySelector('.sidebar').classList.add('hidden-mobile');
            document.querySelector('.chat-area').classList.add('active-mobile');
        }
    }
}

// Load messages for chat
async function loadMessages(chatId) {
    if (!chatId) return;
    const requestId = ++messagesRequestId;
    try {
        const response = await fetch(`/api/messages/${chatId}`);
        const data = await response.json();
        if (requestId !== messagesRequestId || chatId !== currentChatId) return;
        
        if (data.success) {
            renderMessages(data.messages, currentMessageSearchQuery);
        }
    } catch (error) {
        console.error('Load messages error:', error);
    }
}

function clearReloadTimers() {
    if (chatsReloadTimer) {
        clearTimeout(chatsReloadTimer);
        chatsReloadTimer = null;
    }
    if (messagesReloadTimer) {
        clearTimeout(messagesReloadTimer);
        messagesReloadTimer = null;
    }
}

function scheduleChatsReload(delay = RELOAD_DEBOUNCE_MS) {
    if (chatsReloadTimer) {
        clearTimeout(chatsReloadTimer);
    }
    chatsReloadTimer = setTimeout(() => {
        chatsReloadTimer = null;
        loadChats();
    }, delay);
}

function scheduleCurrentChatReload(delay = RELOAD_DEBOUNCE_MS) {
    if (!currentChatId) return;
    if (messagesReloadTimer) {
        clearTimeout(messagesReloadTimer);
    }
    messagesReloadTimer = setTimeout(() => {
        messagesReloadTimer = null;
        if (currentChatId) {
            loadMessages(currentChatId);
        }
    }, delay);
}

function startMessagePolling() {
    stopMessagePolling();
    if (!currentChatId) return;

    messagePollInterval = setInterval(async () => {
        if (isPollingMessages || !currentChatId) return;
        isPollingMessages = true;
        try {
            await loadMessages(currentChatId);
        } finally {
            isPollingMessages = false;
        }
    }, MESSAGE_POLL_INTERVAL);
}

function stopMessagePolling() {
    if (messagePollInterval) {
        clearInterval(messagePollInterval);
        messagePollInterval = null;
    }
}

// Render a single message element
function createMessageElement(msg, highlightQuery = '') {
    const isCurrentUser = currentUser && msg.user_id === currentUser.id;
    const userColor = getUserColor(msg.sender_username || '');
    const bubbleColor = isCurrentUser ? '#667eea' : userColor;
    const textColor = isDarkThemeActive() ? '#ffffff' : getReadableTextColor(bubbleColor);
    
    // Получаем аватарку из сообщения или из текущего пользователя
    const messageEl = document.createElement('div');
    messageEl.className = `message-row ${isCurrentUser ? 'sent' : 'received'}`;

    const avatarColor = isCurrentUser
        ? normalizeAvatarColor(currentUser && currentUser.avatar)
        : normalizeAvatarColor(msg.sender_avatar);
    const avatarHtml = formatUserAvatarHtml(avatarColor, msg.sender_username || 'U');

    const statusIcon = isCurrentUser ? getStatusIcon(msg.status) : '';
    const attachmentHtml = msg.file_url
        ? (msg.message_type === 'image'
            ? `<img class="message-attachment" src="${escapeHtml(msg.file_url)}" alt="${escapeHtml(msg.file_name || 'image')}" loading="lazy" />`
            : msg.message_type === 'video'
                ? `<video class="message-attachment" controls src="${escapeHtml(msg.file_url)}"></video>`
                : msg.message_type === 'audio'
                    ? `<audio class="message-attachment" controls src="${escapeHtml(msg.file_url)}"></audio>`
                    : `<a class="message-file" href="${escapeHtml(msg.file_url)}" download="${escapeHtml(msg.file_name || '')}">${escapeHtml(msg.file_name || 'Файл')}</a>`)
        : '';
    const messageText = msg.text && msg.message_type === 'text'
        ? `<div class="message-text">${highlightText(msg.text, highlightQuery)}</div>`
        : '';

    // Build reply quote if message is a reply
    let replyQuoteHtml = '';
    if (msg.reply_to && msg.reply_to.sender_username) {
        const quotedText = msg.reply_to.text ? msg.reply_to.text.substring(0, 100) : '[Медиа-файл]';
        replyQuoteHtml = `
            <div class="message-reply-quote">
                <div class="reply-to-name">${escapeHtml(msg.reply_to.sender_username)}</div>
                <div class="reply-to-text">${escapeHtml(quotedText)}</div>
            </div>
        `;
    }

    messageEl.innerHTML = `
        <div class="message-avatar" title="${escapeHtml(msg.sender_username || '')}">${avatarHtml}</div>
        <div class="message-bubble" style="background: ${bubbleColor}; color: ${textColor};">
            ${replyQuoteHtml}
            ${messageText}
            ${attachmentHtml}
            <div class="message-time">
                ${escapeHtml(msg.time)}
                ${isCurrentUser ? `<span class="message-status-icon">${statusIcon}</span>` : ''}
            </div>
        </div>
    `;

    // Add context menu
    messageEl.addEventListener('contextmenu', (e) => {
        showMessageContextMenu(msg.id, e, isCurrentUser, msg);
    });

    return messageEl;
}

function messagesAreEqual(msgA, msgB) {
    return msgA.id === msgB.id
        && msgA.text === msgB.text
        && msgA.file_url === msgB.file_url
        && msgA.message_type === msgB.message_type
        && msgA.status === msgB.status
        && msgA.time === msgB.time
        && msgA.edited_at === msgB.edited_at
        && msgA.deleted === msgB.deleted
        && JSON.stringify(msgA.reactions || []) === JSON.stringify(msgB.reactions || []);
}

// Render messages
function renderMessages(messages, highlightQuery = '') {
    if (!messages || messages.length === 0) {
        lastMessages = [];
        messagesContainer.innerHTML = '<div class="no-chat-selected"><p>Нет сообщений</p></div>';
        return;
    }

    const sameLength = messages.length === lastMessages.length;
    const sameContent = sameLength && messages.every((msg, index) => messagesAreEqual(msg, lastMessages[index])) && highlightQuery === currentMessageSearchQuery;
    if (sameContent) {
        return;
    }

    const isAtBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop <= messagesContainer.clientHeight + 20;
    const prefixMatches = lastMessages.length > 0 && messages.length > lastMessages.length
        && lastMessages.every((msg, index) => messagesAreEqual(msg, lastMessages[index]));

    if (prefixMatches) {
        const newMessages = messages.slice(lastMessages.length);
        newMessages.forEach(msg => messagesContainer.appendChild(createMessageElement(msg, highlightQuery)));
        lastMessages = messages.slice();
        if (isAtBottom) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
        return;
    }

    messagesContainer.innerHTML = '';
    messages.forEach(msg => messagesContainer.appendChild(createMessageElement(msg, highlightQuery)));
    lastMessages = messages.slice();
    if (isAtBottom) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

function getUserColor(name) {
    const palette = ['#00B894', '#0984E3', '#FD79A8', '#E17055', '#00CEC9', '#6C5CE7', '#FFB142', '#55EFC4'];
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
        hash = (hash * 31 + name.charCodeAt(i)) % palette.length;
    }
    return palette[Math.abs(hash) % palette.length];
}

function isDarkThemeActive() {
    return document.body.classList.contains('theme-night');
}

function getReadableTextColor(hexColor) {
    const normalized = hexColor.replace('#', '');
    const full = normalized.length === 3
        ? normalized.split('').map(ch => ch + ch).join('')
        : normalized;
    const r = parseInt(full.slice(0, 2), 16);
    const g = parseInt(full.slice(2, 4), 16);
    const b = parseInt(full.slice(4, 6), 16);

    const brightness = (r * 299 + g * 587 + b * 114) / 1000;
    return brightness > 160 ? '#1f2937' : '#ffffff';
}

function isImageUrl(value) {
    return typeof value === 'string' && /^(https?:\/\/|\.\/|\/).+\.(jpg|jpeg|png|gif|svg|webp)$/i.test(value);
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

async function handleSettingsSave() {
    await saveUserAvatarColor();

    saveSettings();

    if (currentUser) {
        currentUser.username = usernameInput.value;
        displayUsername.textContent = currentUser.username;
    }

    if (currentChatId) {
        const chat = chats.find(c => c.id === currentChatId);
        if (chat) {
            currentAvatar.innerHTML = formatAvatarHtml(chat.avatar || chat.name);
        }
    }

    renderChatList();
    if (settingsModal) {
        settingsModal.classList.remove('active');
    }
}

async function saveUserAvatarColor() {
    if (!currentUser || !avatarColorInput) return;
    const avatarColor = normalizeAvatarColor(avatarColorInput.value);

    try {
        const response = await fetch('/api/user/avatar-color', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ avatarColor })
        });
        const rawText = await response.text();
        let data = null;
        try {
            data = rawText ? JSON.parse(rawText) : null;
        } catch (_parseErr) {
            throw new Error('SERVER_NON_JSON_RESPONSE');
        }

        if (!response.ok || !data) {
            throw new Error('SERVER_BAD_RESPONSE');
        }
        if (data.success) {
            currentUser.avatar = normalizeAvatarColor(data.avatar || avatarColor);
            syncAvatarColorControls();
            // Перезагружаем сообщения, чтобы отобразить новую аватарку
            if (currentChatId) {
                scheduleCurrentChatReload();
            }
            // Перезагружаем список чатов
            scheduleChatsReload();
        } else {
            console.error('Save avatar color error:', data && data.message);
            alert('Ошибка сохранения цвета аватара: ' + (data.message || 'Неизвестная ошибка'));
        }
    } catch (error) {
        console.error('Save avatar color error:', error);
        alert('Не удалось сохранить цвет аватара. Перезапусти сервер и попробуй снова.');
    }
}
async function deleteChat(chatId, chatName) {
    if (!confirm(`Удалить чат «${chatName}»? Это действие нельзя отменить.`)) return;

    try {
        const response = await fetch(`/api/chats/${chatId}`, { method: 'DELETE' });
        const data = await response.json();

        if (data.success) {
            if (currentChatId === chatId) {
                currentChatId = null;
                stopMessagePolling();
                lastMessages = [];
                messagesContainer.innerHTML = '<div class="no-chat-selected"><p>Выберите чат из списка</p></div>';
                currentChatName.textContent = 'Выберите чат';
                currentChatStatus.textContent = '';
                currentAvatar.innerHTML = 'Б';
                messageInput.disabled = true;
                sendBtn.disabled = true;
            }
            scheduleChatsReload();
        } else {
            alert(data.message || 'Ошибка удаления чата');
        }
    } catch (error) {
        console.error('Delete chat error:', error);
    }
}
// Send message
async function sendMessage() {
    const text = messageInput.value.trim();
    
    if (!text || !currentChatId) return;
    
    try {
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chatId: currentChatId, text, replyToId: replyToMessage ? replyToMessage.id : null })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Clear input and reply mode
            messageInput.value = '';
            clearReplyMode();
            
            // Debounced reload collapses with socket updates
            scheduleCurrentChatReload();
            scheduleChatsReload();
        }
    } catch (error) {
        console.error('Send message error:', error);
    }
}

async function uploadFileMessage(file) {
    if (!currentChatId || !file) return;

    try {
        const formData = new FormData();
        formData.append('chatId', currentChatId);
        formData.append('file', file);

        const response = await fetch('/api/messages/file', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            scheduleCurrentChatReload();
            scheduleChatsReload();
        } else {
            console.error('Upload file error:', data.message);
        }
    } catch (error) {
        console.error('Upload file error:', error);
    }
}

async function uploadAudioMessage(blob) {
    if (!currentChatId || !blob) return;

    try {
        const audioFile = new File([blob], `voice-${Date.now()}.webm`, { type: blob.type || 'audio/webm' });
        const formData = new FormData();
        formData.append('chatId', currentChatId);
        formData.append('file', audioFile);

        const response = await fetch('/api/messages/file', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            scheduleCurrentChatReload();
            scheduleChatsReload();
        } else {
            console.error('Upload audio error:', data.message);
        }
    } catch (error) {
        console.error('Upload audio error:', error);
    }
}

async function toggleVoiceRecording() {
    if (isRecordingAudio) {
        if (mediaRecorder) {
            mediaRecorder.stop();
        }
        return;
    }

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert('Ваш браузер не поддерживает запись голоса.');
        return;
    }

    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        audioChunks = [];
        mediaRecorder = new MediaRecorder(stream);

        mediaRecorder.ondataavailable = (event) => {
            if (event.data && event.data.size > 0) {
                audioChunks.push(event.data);
            }
        };

        mediaRecorder.onstop = async () => {
            stream.getTracks().forEach(track => track.stop());
            isRecordingAudio = false;
            updateVoiceRecordingState();

            const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
            await uploadAudioMessage(audioBlob);
        };

        mediaRecorder.start();
        isRecordingAudio = true;
        updateVoiceRecordingState();
    } catch (error) {
        console.error('Voice recording error:', error);
        alert('Не удалось включить микрофон. Проверьте разрешения.');
    }
}

function updateVoiceRecordingState() {
    if (voiceButton) {
        voiceButton.classList.toggle('recording', isRecordingAudio);
    }
    if (recordIndicator) {
        recordIndicator.classList.toggle('hidden', !isRecordingAudio);
    }
}

// Create new chat
async function createNewChat() {
    showNewChatModal(async (name) => {
        if (!name) return;
        try {
            const response = await fetch('/api/chats', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await response.json();
            if (data.success) {
                await loadChats();
                if (data.chat && data.chat.id) await selectChat(data.chat.id);
                if (data.chat && data.chat.invite_code) showInviteCode(data.chat.invite_code);
            } else {
                alert(data.message || 'Ошибка создания чата');
            }
        } catch (error) {
            console.error('Create chat error:', error);
        }
    });
}

async function fetchInviteCodeForChat(chatId) {
    if (!chatId) return null;

    try {
        const response = await fetch(`/api/chats/invite/${chatId}`);
        const data = await response.json();

        if (data.success) {
            return data.code;
        }

        console.error('Get invite code error:', data.message);
    } catch (error) {
        console.error('Get invite code error:', error);
    }

    return null;
}

async function handleGetCodeClick() {
    const selectedChat = chats.find(c => c.id === currentChatId);

    if (selectedChat && selectedChat.room_id) {
        const code = await fetchInviteCodeForChat(currentChatId);
        if (!code) {
            return alert('Не удалось получить код приглашения для этого чата');
        }

        await sendCodeMessage(currentChatId, code);
        return showInviteCode(code);
    }

    showNewChatModal(async (name) => {
    if (!name) return;
    await createChatWithCode(name);
});

    await createChatWithCode(name);
}

async function getInviteCode() {
    if (!currentChatId) {
        return alert('Выберите чат, чтобы получить код');
    }

    const code = await fetchInviteCodeForChat(currentChatId);
    if (code) {
        showInviteCode(code);
    } else {
        alert('Ошибка получения кода');
    }
}

async function sendCodeMessage(chatId, code) {
    try {
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chatId, text: `Код: ${code}` })
        });

        const data = await response.json();

        if (data.success) {
            if (chatId === currentChatId) {
                scheduleCurrentChatReload();
            }
            scheduleChatsReload();
        } else {
            console.error('Send code message failed:', data.message);
        }
    } catch (error) {
        console.error('Send code message error:', error);
    }
}

async function createChatWithCode(name) {
    try {
        const response = await fetch('/api/chats', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        });

        const data = await response.json();

        if (data.success) {
            await loadChats();
            if (data.chat && data.chat.id) {
                await selectChat(data.chat.id);
                if (data.chat.invite_code) {
                    await sendCodeMessage(data.chat.id, data.chat.invite_code);
                    showInviteCode(data.chat.invite_code);
                } else {
                    await getInviteCode();
                }
            }
        } else {
            alert(data.message || 'Ошибка создания чата с кодом');
        }
    } catch (error) {
        console.error('Create chat with code error:', error);
    }
}

async function joinChatByCode() {
    const code = joinCodeInput.value.trim();
    if (!code) {
        return alert('Введите код приглашения');
    }

    try {
        const response = await fetch('/api/chats/join', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });

        const data = await response.json();

        if (data.success) {
            if (data.chat && data.chat.id) {
                await loadChats();
                selectChat(data.chat.id);
                joinCodeInput.value = '';
                showInviteCode('');
            } else {
                alert('Вы уже добавлены в этот чат');
            }
        } else {
            alert(data.message || 'Ошибка при подключении к чату');
        }
    } catch (error) {
        console.error('Join chat error:', error);
        alert('Ошибка соединения');
    }
}

function showInviteCode(code) {
    if (!code) {
        inviteCodePreview.textContent = '';
        return;
    }
    inviteCodePreview.textContent = `Код чата: ${code}`;
}

// Setup event listeners
function setupEventListeners() {
    const logoutSidebarBtn = document.getElementById('logoutSidebarBtn');
if (logoutSidebarBtn) {
    logoutSidebarBtn.addEventListener('click', async () => {
        try {
            await fetch('/api/logout', { method: 'POST' });
            stopMessagePolling();
            currentUser = null;
            currentChatId = null;
            chats = [];
            showAuth();
        } catch (error) {
            console.error('Logout error:', error);
        }
    });
}
    // Auth tabs
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            if (tab.dataset.tab === 'login') {
                loginForm.classList.remove('hidden');
                registerForm.classList.add('hidden');
                userInfo.classList.add('hidden');
            } else {
                loginForm.classList.add('hidden');
                registerForm.classList.remove('hidden');
                userInfo.classList.add('hidden');
            }
        });
    });
    
    // Login form
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.textContent = '';
        
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (data.success) {
                currentUser = data.user;
                showApp();
            } else {
                loginError.textContent = data.message;
            }
        } catch (error) {
            loginError.textContent = 'Ошибка соединения';
        }
    });
    
    // Register form
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        registerError.textContent = '';
        
        const username = document.getElementById('regUsername').value;
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;
        const confirmPassword = document.getElementById('regConfirmPassword').value;
        
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password, confirmPassword })
            });
            
            const data = await response.json();
            
            if (data.success) {
                currentUser = data.user;
                showApp();
            } else {
                registerError.textContent = data.message;
            }
        } catch (error) {
            registerError.textContent = 'Ошибка соединения';
        }
    });
    
    // Logout
    logoutBtn.addEventListener('click', async () => {
        try {
            await fetch('/api/logout', { method: 'POST' });
            stopMessagePolling();
            currentUser = null;
            currentChatId = null;
            chats = [];
            showAuth();
        } catch (error) {
            console.error('Logout error:', error);
        }
    });
    
    // Send button
    sendBtn.addEventListener('click', sendMessage);
    
    // Emoji picker button
    if (emojiButton && emojiPicker) {
        emojiButton.addEventListener('click', (e) => {
            e.stopPropagation();
            emojiPicker.classList.toggle('hidden');
        });

        emojiPicker.addEventListener('click', (e) => {
            e.stopPropagation();
            if (e.target.classList.contains('emoji-item')) {
                insertEmoji(e.target.textContent);
            }
        });

        document.addEventListener('click', () => {
            if (!emojiPicker.classList.contains('hidden')) {
                emojiPicker.classList.add('hidden');
            }
        });
    }

    if (fileButton && fileInput) {
        fileButton.addEventListener('click', () => {
            fileInput.click();
        });

        fileInput.addEventListener('change', async () => {
            if (fileInput.files.length === 0 || !currentChatId) return;
            await uploadFileMessage(fileInput.files[0]);
            fileInput.value = '';
        });
    }

    if (voiceButton) {
        voiceButton.addEventListener('click', () => {
            if (!currentChatId) return;
            toggleVoiceRecording();
        });
    }
    
    // Enter key
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    
    // New chat button
    newChatBtn.addEventListener('click', createNewChat);
    
    // Invite code button
    getChatCodeBtn.addEventListener('click', handleGetCodeClick);
    joinChatBtn.addEventListener('click', joinChatByCode);

    if (chatSearchBox) {
    const chatSearchBtn = document.getElementById('chatSearchBtn');
    const chatSearchClear = document.getElementById('chatSearchClear');
    const searchCounter = document.getElementById('searchCounter');
    const searchPrev = document.getElementById('searchPrev');
    const searchNext = document.getElementById('searchNext');

    let searchMatches = [];
    let searchIndex = 0;

    function updateSearchCounter() {
        if (!searchCounter) return;
        if (searchMatches.length === 0) {
            searchCounter.textContent = currentMessageSearchQuery ? 'Не найдено' : '';
        } else {
            searchCounter.textContent = `${searchIndex + 1} / ${searchMatches.length}`;
        }
    }

    function scrollToMatch(index) {
        if (searchMatches.length === 0) return;
        // Снимаем активную подсветку со всех
        searchMatches.forEach(el => el.classList.remove('message-highlight-active'));
        // Ставим активную на текущий
        searchMatches[index].classList.add('message-highlight-active');
        searchMatches[index].scrollIntoView({ behavior: 'smooth', block: 'center' });
        updateSearchCounter();
    }

    function doMessageSearch() {
    const query = chatSearchBox.value.trim();
    searchMatches = [];
    searchIndex = 0;

    // Сбрасываем чтобы renderMessages не пропустил перерисовку
    currentMessageSearchQuery = '';

    if (currentChatId && lastMessages.length > 0) {
        renderMessages(lastMessages, query);
    }

    // Устанавливаем после рендера
    currentMessageSearchQuery = query;

        if (currentMessageSearchQuery) {
            // Собираем все найденные span-элементы подсветки
            searchMatches = Array.from(messagesContainer.querySelectorAll('.message-highlight'));
            if (searchMatches.length > 0) {
                scrollToMatch(0);
            }
        }

        updateSearchCounter();

        if (chatSearchClear) {
            chatSearchClear.style.display = currentMessageSearchQuery ? 'inline-block' : 'none';
        }
        if (searchPrev) searchPrev.style.display = currentMessageSearchQuery ? 'inline-flex' : 'none';
        if (searchNext) searchNext.style.display = currentMessageSearchQuery ? 'inline-flex' : 'none';
        if (searchCounter) searchCounter.style.display = currentMessageSearchQuery ? 'inline-block' : 'none';
    }

    if (chatSearchBtn) {
        chatSearchBtn.addEventListener('click', doMessageSearch);
    }

    chatSearchBox.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') doMessageSearch();
    });

    if (searchNext) {
        searchNext.addEventListener('click', () => {
            if (searchMatches.length === 0) return;
            searchIndex = (searchIndex + 1) % searchMatches.length;
            scrollToMatch(searchIndex);
        });
    }

    if (searchPrev) {
        searchPrev.addEventListener('click', () => {
            if (searchMatches.length === 0) return;
            searchIndex = (searchIndex - 1 + searchMatches.length) % searchMatches.length;
            scrollToMatch(searchIndex);
        });
    }

    if (chatSearchClear) {
        chatSearchClear.addEventListener('click', () => {
            chatSearchBox.value = '';
            currentMessageSearchQuery = '';
            searchMatches = [];
            searchIndex = 0;
            chatSearchClear.style.display = 'none';
            if (searchPrev) searchPrev.style.display = 'none';
            if (searchNext) searchNext.style.display = 'none';
            if (searchCounter) { searchCounter.textContent = ''; searchCounter.style.display = 'none'; }
            if (currentChatId && lastMessages.length > 0) {
                renderMessages(lastMessages, '');
            }
        });
    }
}

    if (cancelReplyBtn) {
        cancelReplyBtn.addEventListener('click', clearReplyMode);
    }

    // Settings modal
    settingsBtn.addEventListener('click', () => {
        settingsModal.classList.add('active');
    });
    
    closeSettings.addEventListener('click', () => {
        settingsModal.classList.remove('active');
    });
    
    settingsModal.addEventListener('click', (e) => {
        if (e.target === settingsModal) {
            settingsModal.classList.remove('active');
        }
    });
    
    // Theme
   themeSelect.addEventListener('change', (e) => {
    applyTheme(e.target.value);
    saveSettings();
});
    
    // Username
    usernameInput.addEventListener('change', (e) => {
        saveSettings();
    });

    // Avatar
    if (avatarColorInput) {
        avatarColorInput.addEventListener('input', updateAvatarColorPreview);
    }
    usernameInput.addEventListener('input', updateAvatarColorPreview);

    if (settingsSaveBtn) {
        settingsSaveBtn.addEventListener('click', async () => {
            await handleSettingsSave();
        });
    }
    
    // Notifications
    notificationsToggle.addEventListener('change', saveSettings);
    
    // Search
    setupSearch();
} // Привязка кнопок профиля и смены пароля
const profileBtn = document.getElementById('profileBtn');
const changePasswordBtn = document.getElementById('changePasswordBtn');
if (profileBtn) profileBtn.addEventListener('click', showUserProfile);
if (changePasswordBtn) changePasswordBtn.addEventListener('click', changePassword);

// Save settings
function saveSettings() {
    const settings = {
        theme: themeSelect.value,
        username: usernameInput.value,
        notifications: notificationsToggle.checked,
        avatarColor: avatarColorInput ? normalizeAvatarColor(avatarColorInput.value) : '#667EEA'
    };
    localStorage.setItem('messengerSettings', JSON.stringify(settings));
    if (currentUser) {
        currentUser.username = usernameInput.value;
        displayUsername.textContent = currentUser.username;
    }
}function applyTheme(theme) {
    document.body.classList.remove(
        'theme-night', 'theme-warm', 'theme-forest', 'theme-mono'
    );
    if (theme === 'night')  document.body.classList.add('theme-night');
    if (theme === 'warm')   document.body.classList.add('theme-warm');
    if (theme === 'forest') document.body.classList.add('theme-forest');
    if (theme === 'mono')   document.body.classList.add('theme-mono');
}

// Load settings
function insertEmoji(emoji) {
    const start = messageInput.selectionStart || 0;
    const end = messageInput.selectionEnd || 0;
    const text = messageInput.value;
    messageInput.value = text.slice(0, start) + emoji + text.slice(end);
    messageInput.focus();
    const cursorPosition = start + emoji.length;
    messageInput.setSelectionRange(cursorPosition, cursorPosition);
}

function loadSettings() {
    const settings = JSON.parse(localStorage.getItem('messengerSettings'));
    
    if (settings) {
        themeSelect.value = settings.theme || 'light';
        usernameInput.value = settings.username || 'Пользователь';
        notificationsToggle.checked = settings.notifications !== false;
        if (avatarColorInput && settings.avatarColor) {
            avatarColorInput.value = normalizeAvatarColor(settings.avatarColor);
        }
        
        if (settings.theme) {
    applyTheme(settings.theme);
}

        if (settings.username && currentUser) {
            currentUser.username = settings.username;
            displayUsername.textContent = settings.username;
        }
    }
    syncAvatarColorControls();
}

function setReplyMode(message) {
    if (!message) return;
    replyToMessage = message;
    const senderName = message.sender_username || 'Собеседник';
    const previewText = message.text ? message.text.trim().slice(0, 80) : 'Медиа-сообщение';
    if (replyPreview && replyPreviewText) {
        replyPreviewText.textContent = `Ответ ${senderName}: ${previewText}`;
        replyPreview.classList.remove('hidden');
    }
    if (messageInput) {
        messageInput.placeholder = `Ответ ${senderName}...`;
        messageInput.focus();
    }
}

function clearReplyMode() {
    replyToMessage = null;
    if (replyPreview && replyPreviewText) {
        replyPreviewText.textContent = '';
        replyPreview.classList.add('hidden');
    }
    if (messageInput) {
        messageInput.placeholder = 'Введите сообщение...';
    }
}

function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function highlightText(text, query) {
    const safeText = escapeHtml(text || '');
    if (!query) return safeText;
    const safeQuery = escapeRegExp(query.trim());
    if (!safeQuery) return safeText;
    const regex = new RegExp(`(${safeQuery})`, 'gi');
    return safeText.replace(regex, '<span class="message-highlight">$1</span>');
}


function showNewChatModal(callback) {
    const modal = document.getElementById('newChatModal');
    const input = document.getElementById('newChatNameInput');
    const error = document.getElementById('newChatError');
    const confirmBtn = document.getElementById('newChatConfirmBtn');
    const cancelBtn = document.getElementById('newChatCancelBtn');

    input.value = '';
    error.textContent = '';
    modal.classList.add('active');
    setTimeout(() => input.focus(), 50);

    function confirm() {
        const name = input.value.trim();
        if (!name) { error.textContent = 'Введите название чата'; return; }
        if (name.length > 64) { error.textContent = 'Максимум 64 символа'; return; }
        modal.classList.remove('active');
        cleanup();
        callback(name);
    }

    function cancel() {
        modal.classList.remove('active');
        cleanup();
        callback(null);
    }

    function onKey(e) {
        if (e.key === 'Enter') confirm();
        if (e.key === 'Escape') cancel();
    }

    function cleanup() {
        confirmBtn.removeEventListener('click', confirm);
        cancelBtn.removeEventListener('click', cancel);
        input.removeEventListener('keydown', onKey);
    }

    confirmBtn.addEventListener('click', confirm);
    cancelBtn.addEventListener('click', cancel);
    input.addEventListener('keydown', onKey);
}
// Initialize app
init();

// ===== NEW FEATURES =====

// Request notification permission
async function requestNotificationPermission() {
    if (!('Notification' in window)) {
        console.log('Browser does not support notifications');
        return;
    }

    if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
        await Notification.requestPermission();
    }
}

// Show browser notification
function showNotification(title, options = {}) {
    if (Notification.permission === 'granted' && document.hidden) {
        new Notification(title, { icon: '/favicon.ico', ...options });
    }
}

// Edit message
async function editMessage(messageId, text) {
    if (!text || text.trim() === '') {
        alert('Текст не может быть пустым');
        return;
    }

    try {
        const response = await fetch(`/api/messages/${messageId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });

        const data = await response.json();
        if (data.success) {
            scheduleCurrentChatReload();
            scheduleChatsReload();
        } else {
            alert(data.message || 'Ошибка редактирования');
        }
    } catch (error) {
        console.error('Edit message error:', error);
    }
}

// Delete message
async function deleteMessage(messageId) {
    if (!confirm('Удалить это сообщение?')) return;

    try {
        const response = await fetch(`/api/messages/${messageId}`, {
            method: 'DELETE'
        });

        const data = await response.json();
        if (data.success) {
            scheduleCurrentChatReload();
            scheduleChatsReload();
        } else {
            alert(data.message || 'Ошибка удаления');
        }
    } catch (error) {
        console.error('Delete message error:', error);
    }
}

// Add reaction
async function addReaction(messageId, emoji) {
    try {
        await fetch('/api/reactions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ messageId, emoji })
        });
        scheduleCurrentChatReload();
        scheduleChatsReload();
    } catch (error) {
        console.error('Add reaction error:', error);
    }
}

// Remove reaction
async function removeReaction(messageId, emoji) {
    try {
        await fetch(`/api/reactions/${messageId}/${emoji}`, {
            method: 'DELETE'
        });
        scheduleCurrentChatReload();
        scheduleChatsReload();
    } catch (error) {
        console.error('Remove reaction error:', error);
    }
}

// Search chats and messages
async function searchMessages(query) {
    if (!query || query.length < 1) {
        renderChatList();
        return;
    }

    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();

        if (data.success && data.results) {
            const filteredChats = data.results.chats || [];
            chatList.innerHTML = '';

            if (filteredChats.length === 0) {
                chatList.innerHTML = '<div style="padding: 10px; color: #999;">Ничего не найдено</div>';
                return;
            }

            filteredChats.forEach(chat => {
                const chatItem = document.createElement('div');
                chatItem.className = `chat-item ${chat.id === currentChatId ? 'active' : ''}`;
                chatItem.dataset.id = chat.id;

                const avatarHtml = formatAvatarHtml(chat.avatar || chat.name);

                chatItem.innerHTML = `
                    <div class="avatar">${avatarHtml}</div>
                    <div class="chat-item-info">
                        <div class="chat-item-header">
                            <span class="chat-item-name">${escapeHtml(chat.name)}</span>
                        </div>
                    </div>
                `;

                chatItem.addEventListener('click', () => selectChat(chat.id));
                chatList.appendChild(chatItem);
            });
        }
    } catch (error) {
        console.error('Search error:', error);
    }
}

// Show message context menu
function showMessageContextMenu(messageId, event, isCurrentUser, msg) {
    event.preventDefault();

    const existing = document.querySelector('.message-context-menu');
    if (existing) {
        existing.remove();
    }

    const menu = document.createElement('div');
    menu.className = 'message-context-menu';
    menu.style.position = 'absolute';
    menu.style.left = event.clientX + 'px';
    menu.style.top = event.clientY + 'px';
    menu.style.zIndex = '1000';
    menu.style.backgroundColor = '#fff';
    menu.style.border = '1px solid #ddd';
    menu.style.borderRadius = '4px';
    menu.style.boxShadow = '0 2px 10px rgba(0,0,0,0.1)';
    menu.style.minWidth = '150px';

    const items = [];

    // Reply button
    const replyBtn = document.createElement('button');
    replyBtn.textContent = '↩️ Ответить';
    replyBtn.style.display = 'block';
    replyBtn.style.width = '100%';
    replyBtn.style.padding = '8px';
    replyBtn.style.border = 'none';
    replyBtn.style.background = 'none';
    replyBtn.style.textAlign = 'left';
    replyBtn.style.cursor = 'pointer';
    replyBtn.style.fontSize = '14px';
    replyBtn.style.borderBottom = '1px solid #eee';
    replyBtn.addEventListener('click', () => {
        setReplyMode(msg);
        menu.remove();
    });
    menu.appendChild(replyBtn);

    // Emoji reactions
    const emojiReactions = ['👍', '❤️', '😂', '😢', '🔥'];
    const reactionsDiv = document.createElement('div');
    reactionsDiv.style.display = 'flex';
    reactionsDiv.style.gap = '5px';
    reactionsDiv.style.padding = '8px';
    reactionsDiv.style.borderBottom = '1px solid #eee';

    emojiReactions.forEach(emoji => {
        const btn = document.createElement('button');
        btn.textContent = emoji;
        btn.style.background = 'none';
        btn.style.border = 'none';
        btn.style.cursor = 'pointer';
        btn.style.fontSize = '18px';
        btn.addEventListener('click', () => {
            addReaction(messageId, emoji);
            menu.remove();
        });
        reactionsDiv.appendChild(btn);
    });

    menu.appendChild(reactionsDiv);

    // Edit (only for current user)
    if (isCurrentUser) {
        const editBtn = document.createElement('button');
        editBtn.textContent = '✏️ Редактировать';
        editBtn.style.display = 'block';
        editBtn.style.width = '100%';
        editBtn.style.padding = '8px';
        editBtn.style.border = 'none';
        editBtn.style.background = 'none';
        editBtn.style.textAlign = 'left';
        editBtn.style.cursor = 'pointer';
        editBtn.style.fontSize = '14px';
        editBtn.addEventListener('click', () => {
            const message = lastMessages.find(m => m.id === messageId);
            if (message) {
                const newText = prompt('Отредактировать сообщение:', message.text);
                if (newText !== null) {
                    editMessage(messageId, newText);
                }
            }
            menu.remove();
        });
        menu.appendChild(editBtn);

        // Delete
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = '🗑️ Удалить';
        deleteBtn.style.display = 'block';
        deleteBtn.style.width = '100%';
        deleteBtn.style.padding = '8px';
        deleteBtn.style.border = 'none';
        deleteBtn.style.background = 'none';
        deleteBtn.style.textAlign = 'left';
        deleteBtn.style.cursor = 'pointer';
        deleteBtn.style.fontSize = '14px';
        deleteBtn.style.borderTop = '1px solid #eee';
        deleteBtn.style.color = '#e74c3c';
        deleteBtn.addEventListener('click', () => {
            deleteMessage(messageId);
            menu.remove();
        });
        menu.appendChild(deleteBtn);
    }

    document.body.appendChild(menu);

    // Close menu on click outside
    setTimeout(() => {
        document.addEventListener('click', function closeMenu() {
            menu.remove();
            document.removeEventListener('click', closeMenu);
        });
    }, 0);
}

// Update createMessageElement to support context menu and reactions
const originalCreateMessageElement = window.createMessageElement;
window.createMessageElement = function(msg, highlightQuery = '') {
    const isCurrentUser = currentUser && msg.user_id === currentUser.id;
    const userColor = getUserColor(msg.sender_username || '');
    const bubbleColor = isCurrentUser ? '#667eea' : userColor;
    const textColor = isDarkThemeActive() ? '#ffffff' : getReadableTextColor(bubbleColor);

    const messageEl = document.createElement('div');
    messageEl.className = `message-row ${isCurrentUser ? 'sent' : 'received'}`;

    const avatarColor = isCurrentUser
        ? normalizeAvatarColor(currentUser && currentUser.avatar)
        : normalizeAvatarColor(msg.sender_avatar);
    const avatarHtml = formatUserAvatarHtml(avatarColor, msg.sender_username || 'U');

    const statusIcon = isCurrentUser ? getStatusIcon(msg.status) : '';
    const attachmentHtml = msg.file_url
        ? (msg.message_type === 'image'
            ? `<img class="message-attachment" src="${escapeHtml(msg.file_url)}" alt="${escapeHtml(msg.file_name || 'image')}" loading="lazy" />`
            : msg.message_type === 'video'
                ? `<video class="message-attachment" controls src="${escapeHtml(msg.file_url)}"></video>`
                : msg.message_type === 'audio'
                    ? `<audio class="message-attachment" controls src="${escapeHtml(msg.file_url)}"></audio>`
                    : `<a class="message-file" href="${escapeHtml(msg.file_url)}" download="${escapeHtml(msg.file_name || '')}">${escapeHtml(msg.file_name || 'Файл')}</a>`)
        : '';
    const messageText = msg.text && msg.message_type === 'text'
        ? `<div class="message-text">${highlightText(msg.text, highlightQuery || currentMessageSearchQuery)}</div>`
        : '';
    const editedHtml = msg.edited_at ? `<span class="message-edited">(отредактировано)</span>` : '';
    const reactionsHtml = msg.reactions && msg.reactions.length > 0
        ? `<div class="message-reactions">${msg.reactions.map(emoji => `<span class="reaction-item">${emoji}</span>`).join('')}</div>`
        : '';

    let replyQuoteHtml = '';
    if (msg.reply_to && msg.reply_to.sender_username) {
        const quotedText = msg.reply_to.text ? msg.reply_to.text.substring(0, 100) : '[Медиа-файл]';
        replyQuoteHtml = `
            <div class="message-reply-quote">
                <div class="reply-to-name">${escapeHtml(msg.reply_to.sender_username)}</div>
                <div class="reply-to-text">${escapeHtml(quotedText)}</div>
            </div>
        `;
    }

    messageEl.innerHTML = `
        <div class="message-avatar" title="${escapeHtml(msg.sender_username || '')}">${avatarHtml}</div>
        <div class="message-content">
            <div class="message-bubble" style="background: ${bubbleColor}; color: ${textColor};">
                ${replyQuoteHtml}
                ${messageText}
                ${editedHtml}
                ${attachmentHtml}
                <div class="message-time">
                    ${escapeHtml(msg.time)}
                    ${isCurrentUser ? `<span class="message-status-icon">${statusIcon}</span>` : ''}
                </div>
            </div>
            ${reactionsHtml}
        </div>
    `;

    messageEl.addEventListener('contextmenu', (e) => {
        showMessageContextMenu(msg.id, e, isCurrentUser, msg);
    });

    // Long touch for mobile
    let touchTimer;
    messageEl.addEventListener('touchstart', (e) => {
        touchTimer = setTimeout(() => {
            const touch = e.touches[0];
            showMessageContextMenu(msg.id, {
                clientX: touch.clientX,
                clientY: touch.clientY,
                preventDefault: () => {}
            }, isCurrentUser, msg);
        }, 500);
    });

    messageEl.addEventListener('touchend', () => {
        clearTimeout(touchTimer);
    });

    return messageEl;
};

// Change password
async function changePassword() {
    document.getElementById('changePasswordModal').classList.add('active');
    document.getElementById('cpError').textContent = '';

    document.getElementById('cpSaveBtn').onclick = async () => {
        const currentPassword = document.getElementById('cpCurrent').value;
        const newPassword = document.getElementById('cpNew').value;
        const confirmPassword = document.getElementById('cpConfirm').value;
        const errorEl = document.getElementById('cpError');

        if (!currentPassword || !newPassword || !confirmPassword) {
            errorEl.textContent = 'Заполните все поля';
            return;
        }

        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentPassword, newPassword, confirmPassword })
    });
        const data = await response.json();

        if (data.success) {
            document.getElementById('changePasswordModal').classList.remove('active');
            alert('Пароль изменён. Войдите заново.');
            showAuthModal();
        } else {
            errorEl.textContent = data.message || 'Ошибка';
        }
    };

    document.getElementById('closeChangePassword').onclick = () => {
        document.getElementById('changePasswordModal').classList.remove('active');
    };
}

// Show user profile modal
async function showUserProfile() {
    try {
        const response = await fetch('/api/user');
        const data = await response.json();

        if (data.success) {
            const user = data.user;
            alert(`Профиль:\n\nИмя: ${user.username}\nКод: ${user.uniqueCode}\nEmail: ${user.email}\nРегистрация: ${new Date(user.createdAt).toLocaleDateString('ru-RU')}`);
        }
    } catch (error) {
        console.error('Get profile error:', error);
    }
}

// Add search box listener
function setupSearch() {
    const searchBox = document.querySelector('.search-box');
    if (searchBox) {
        searchBox.addEventListener('input', (e) => {
            searchMessages(e.target.value);
        });
    }
}

// Request notifications on app load
window.addEventListener('load', () => {
    requestNotificationPermission();
});

// ========== ANTI-COPY PROTECTION ==========

// Disable right-click context menu
document.addEventListener('contextmenu', (e) => {
    // Разрешаем контекстное меню на сообщениях
    if (e.target.closest('.message-row')) return;
    e.preventDefault();
    return false;
});

// Disable text selection
document.addEventListener('selectstart', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    e.preventDefault();
    return false;
});

// Disable drag and drop
document.addEventListener('dragstart', (e) => {
    e.preventDefault();
    return false;
});

document.addEventListener('drop', (e) => {
    e.preventDefault();
    return false;
});

// Disable copy, cut, paste
document.addEventListener('copy', (e) => {
    e.preventDefault();
    return false;
});

document.addEventListener('cut', (e) => {
    e.preventDefault();
    return false;
});

document.addEventListener('paste', (e) => {
    // Разрешаем вставку в поля ввода
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    e.preventDefault();
    return false;
});

// Disable developer tools shortcuts
document.addEventListener('keydown', (e) => {
    // Disable F12
    if (e.key === 'F12') {
        e.preventDefault();
        return false;
    }
    // Disable Ctrl+Shift+I
    if (e.ctrlKey && e.shiftKey && e.key === 'I') {
        e.preventDefault();
        return false;
    }
    // Disable Ctrl+Shift+J
    if (e.ctrlKey && e.shiftKey && e.key === 'J') {
        e.preventDefault();
        return false;
    }
    // Disable Ctrl+Shift+C
    if (e.ctrlKey && e.shiftKey && e.key === 'C') {
        e.preventDefault();
        return false;
    }
});

// Disable CSS styling that allows text selection
const style = document.createElement('style');
style.textContent = `
    * {
        user-select: none;
        -webkit-user-select: none;
        -moz-user-select: none;
        -ms-user-select: none;
        -webkit-user-drag: none;
        -webkit-touch-callout: none;
    }
    input, textarea {
        user-select: text;
        -webkit-user-select: text;
    }
`;
document.head.appendChild(style);

// Detect if developer tools are open
//setInterval(() => {
    //const devtools = { open: false, orientation: null };
    //const threshold = 160;
    
    //devtools.open = window.outerHeight - window.innerHeight > threshold || window.outerWidth - window.innerWidth > threshold;
    
   // if (devtools.open) {
        // Alert user that dev tools are detected
//console.clear();
   //     console.log('%cWARNING!', 'color: red; font-size: 20px; font-weight: bold;');
    //    console.log('%cOpening developer tools is not allowed on this site!', 'color: red; font-size: 14px;');
   // }
//}, 200);


// ========== МОБИЛЬНАЯ НАВИГАЦИЯ ==========
const backBtn = document.getElementById('backBtn');

function updateBackBtn() {
    if (backBtn) {
        backBtn.style.display = window.innerWidth <= 768 ? 'flex' : 'none';
    }
}

if (backBtn) {
    backBtn.addEventListener('click', () => {
        document.querySelector('.sidebar').classList.remove('hidden-mobile');
        document.querySelector('.chat-area').classList.remove('active-mobile');
    });
}

window.addEventListener('resize', updateBackBtn);
updateBackBtn();

socket.on('newMessage', (message) => {
    const selectedChat = chats.find(c => c.id === currentChatId);
    if (!selectedChat) return;

    const isSelectedPrivateChat = !selectedChat.room_id && message.chat_id === selectedChat.id;
    const isSelectedSharedChat = Boolean(selectedChat.room_id) && message.room_id === selectedChat.room_id;
    if (!isSelectedPrivateChat && !isSelectedSharedChat) return;

    scheduleCurrentChatReload();
    scheduleChatsReload();
});