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
const MESSAGE_POLL_INTERVAL = 3000;

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
const avatarSelectButton = document.getElementById('avatarSelectButton');
const avatarInput = document.getElementById('avatarInput');
const avatarFileName = document.getElementById('avatarFileName');
const settingsSaveBtn = document.getElementById('settingsSaveBtn');
const notificationsToggle = document.getElementById('notificationsToggle');
const newChatBtn = document.getElementById('newChatBtn');
const getChatCodeBtn = document.getElementById('getChatCodeBtn');
const joinCodeInput = document.getElementById('joinCodeInput');
const joinChatBtn = document.getElementById('joinChatBtn');
const inviteCodePreview = document.getElementById('inviteCodePreview');

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
    if (avatarInput) {
        avatarInput.value = '';
    }
    if (avatarFileName) {
        avatarFileName.textContent = 'Файл не выбран';
    }
    getChatCodeBtn.disabled = false;
    showInviteCode('');
    loadChats();
}

// Load chats from server
async function loadChats() {
    try {
        const response = await fetch('/api/chats');
        const data = await response.json();
        
        if (data.success) {
            chats = data.chats;
            renderChatList();
        }
    } catch (error) {
        console.error('Load chats error:', error);
    }
}

function formatAvatarHtml(value) {
    const avatarValue = String(value || '').trim();
    if (isImageUrl(avatarValue)) {
        return `<img src="${escapeHtml(avatarValue)}" alt="avatar" />`;
    }
    const firstChar = avatarValue ? escapeHtml(avatarValue.charAt(0).toUpperCase()) : '?';
    return `<span>${firstChar}</span>`;
}

// Render chat list
function renderChatList() {
    chatList.innerHTML = '';
    
    chats.forEach(chat => {
        const chatItem = document.createElement('div');
        chatItem.className = `chat-item ${chat.id === currentChatId ? 'active' : ''}`;
        chatItem.dataset.id = chat.id;
        
        const statusIcon = getStatusIcon(chat.messages?.[chat.messages.length - 1]?.status);
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
        `;
        
        chatItem.addEventListener('click', () => selectChat(chat.id));
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

// Select chat
async function selectChat(chatId) {
    currentChatId = chatId;
    const chat = chats.find(c => c.id === chatId);
    
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
        
        // Enable input
        messageInput.disabled = false;
        sendBtn.disabled = false;
        messageInput.focus();
        
        // Load messages
        await loadMessages(chatId);
        renderChatList();
        startMessagePolling();
    }
}

// Load messages for chat
async function loadMessages(chatId) {
    if (!chatId) return;
    try {
        const response = await fetch(`/api/messages/${chatId}`);
        const data = await response.json();
        
        if (data.success) {
            renderMessages(data.messages);
        }
    } catch (error) {
        console.error('Load messages error:', error);
    }
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
function createMessageElement(msg) {
    const isCurrentUser = currentUser && msg.user_id === currentUser.id;
    const userColor = getUserColor(msg.sender_username || '');
    const bubbleColor = isCurrentUser ? '#6C5CE7' : userColor;
    const textColor = '#ffffff';
    const avatarValue = msg.sender_avatar || (msg.sender_username ? msg.sender_username.charAt(0).toUpperCase() : '?');

    const messageEl = document.createElement('div');
    messageEl.className = `message-row ${isCurrentUser ? 'sent' : 'received'}`;

    const avatarHtml = isImageUrl(avatarValue)
        ? `<img src="${escapeHtml(avatarValue)}" alt="${escapeHtml(msg.sender_username || '')}" />`
        : `<span>${escapeHtml(String(avatarValue).charAt(0).toUpperCase())}</span>`;

    const statusIcon = isCurrentUser ? getStatusIcon(msg.status) : '';
    const attachmentHtml = msg.file_url
        ? (msg.message_type === 'image'
            ? `<img class="message-attachment" src="${escapeHtml(msg.file_url)}" alt="${escapeHtml(msg.file_name || 'image')}" />`
            : msg.message_type === 'video'
                ? `<video class="message-attachment" controls src="${escapeHtml(msg.file_url)}"></video>`
                : msg.message_type === 'audio'
                    ? `<audio class="message-attachment" controls src="${escapeHtml(msg.file_url)}"></audio>`
                    : `<a class="message-file" href="${escapeHtml(msg.file_url)}" download="${escapeHtml(msg.file_name || '')}">${escapeHtml(msg.file_name || 'Файл')}</a>`)
        : '';
    const messageText = msg.text && msg.message_type === 'text' ? `<div class="message-text">${escapeHtml(msg.text)}</div>` : '';

    messageEl.innerHTML = `
        <div class="message-avatar">${avatarHtml}</div>
        <div class="message-bubble" style="background: ${bubbleColor}; color: ${textColor};">
            ${messageText}
            ${attachmentHtml}
            <div class="message-time">
                ${escapeHtml(msg.time)}
                ${isCurrentUser ? `<span class="message-status-icon">${statusIcon}</span>` : ''}
            </div>
        </div>
    `;

    return messageEl;
}

function messagesAreEqual(msgA, msgB) {
    return msgA.id === msgB.id
        && msgA.text === msgB.text
        && msgA.file_url === msgB.file_url
        && msgA.message_type === msgB.message_type
        && msgA.status === msgB.status
        && msgA.time === msgB.time;
}

// Render messages
function renderMessages(messages) {
    if (!messages || messages.length === 0) {
        lastMessages = [];
        messagesContainer.innerHTML = '<div class="no-chat-selected"><p>Нет сообщений</p></div>';
        return;
    }

    const sameLength = messages.length === lastMessages.length;
    const sameContent = sameLength && messages.every((msg, index) => messagesAreEqual(msg, lastMessages[index]));
    if (sameContent) {
        return;
    }

    const isAtBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop <= messagesContainer.clientHeight + 20;
    const prefixMatches = lastMessages.length > 0 && messages.length > lastMessages.length
        && lastMessages.every((msg, index) => messagesAreEqual(msg, lastMessages[index]));

    if (prefixMatches) {
        const newMessages = messages.slice(lastMessages.length);
        newMessages.forEach(msg => messagesContainer.appendChild(createMessageElement(msg)));
        lastMessages = messages.slice();
        if (isAtBottom) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
        return;
    }

    messagesContainer.innerHTML = '';
    messages.forEach(msg => messagesContainer.appendChild(createMessageElement(msg)));
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
    if (avatarInput && avatarInput.files && avatarInput.files.length > 0) {
        await saveUserAvatar();
    }

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

async function saveUserAvatar() {
    if (!currentUser || !avatarInput || !avatarInput.files || avatarInput.files.length === 0) return;

    const file = avatarInput.files[0];
    const formData = new FormData();
    formData.append('avatar', file);

    try {
        const response = await fetch('/api/user/avatar', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        if (data.success) {
            currentUser.avatar = data.avatar || '';
            avatarInput.value = '';
            if (avatarFileName) {
                avatarFileName.textContent = 'Файл не выбран';
            }
            if (currentChatId) {
                await loadMessages(currentChatId);
            }
        } else {
            console.error('Save avatar error:', data.message);
        }
    } catch (error) {
        console.error('Save avatar error:', error);
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
            body: JSON.stringify({ chatId: currentChatId, text })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Clear input
            messageInput.value = '';
            
            // Reload messages
            await loadMessages(currentChatId);
            await loadChats();
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
            await loadMessages(currentChatId);
            await loadChats();
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
            await loadMessages(currentChatId);
            await loadChats();
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
    const name = prompt('Введите имя нового чата:');
    
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
            if (data.chat && data.chat.id) {
                await selectChat(data.chat.id);
            }
            if (data.chat && data.chat.invite_code) {
                showInviteCode(data.chat.invite_code);
            }
        } else {
            alert(data.message || 'Ошибка создания чата');
        }
    } catch (error) {
        console.error('Create chat error:', error);
    }
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

    const name = selectedChat ? selectedChat.name : prompt('Введите название нового чата для создания кода:');
    if (!name) return;

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
                await loadMessages(chatId);
            }
            await loadChats();
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
        if (e.target.value === 'dark') {
            document.body.classList.add('dark-theme');
        } else {
            document.body.classList.remove('dark-theme');
        }
        saveSettings();
    });
    
    // Username
    usernameInput.addEventListener('change', (e) => {
        saveSettings();
    });

    // Avatar
    if (avatarSelectButton && avatarInput) {
        avatarSelectButton.addEventListener('click', () => {
            avatarInput.click();
        });
    }

    if (avatarInput) {
        avatarInput.addEventListener('change', () => {
            if (!avatarInput.files || avatarInput.files.length === 0) {
                if (avatarFileName) {
                    avatarFileName.textContent = 'Файл не выбран';
                }
                return;
            }

            const file = avatarInput.files[0];
            if (avatarFileName) {
                avatarFileName.textContent = file.name;
            }
        });
    }

    if (settingsSaveBtn) {
        settingsSaveBtn.addEventListener('click', async () => {
            await handleSettingsSave();
        });
    }
    
    // Notifications
    notificationsToggle.addEventListener('change', saveSettings);
} 

// Save settings
function saveSettings() {
    const settings = {
        theme: themeSelect.value,
        username: usernameInput.value,
        notifications: notificationsToggle.checked
    };
    localStorage.setItem('messengerSettings', JSON.stringify(settings));
    if (currentUser) {
        currentUser.username = usernameInput.value;
        displayUsername.textContent = currentUser.username;
    }
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
        
        if (settings.theme === 'dark') {
            document.body.classList.add('dark-theme');
        }

        if (settings.username && currentUser) {
            currentUser.username = settings.username;
            displayUsername.textContent = settings.username;
        }
    }
}

// Initialize app
init();