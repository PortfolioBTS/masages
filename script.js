// State
let currentChatId = null;
let currentUser = null;
let chats = [];

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
const sendBtn = document.getElementById('sendBtn');
const currentChatName = document.getElementById('currentChatName');
const currentChatStatus = document.getElementById('currentChatStatus');
const currentAvatar = document.getElementById('currentAvatar');
const settingsBtn = document.getElementById('settingsBtn');
const settingsModal = document.getElementById('settingsModal');
const closeSettings = document.getElementById('closeSettings');
const themeSelect = document.getElementById('themeSelect');
const usernameInput = document.getElementById('usernameInput');
const notificationsToggle = document.getElementById('notificationsToggle');
const newChatBtn = document.getElementById('newChatBtn');

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
    authModal.classList.remove('hidden');
    document.querySelector('.app').style.display = 'none';
}

// Show main app
function showApp() {
    authModal.classList.add('hidden');
    document.querySelector('.app').style.display = 'flex';
    displayUsername.textContent = currentUser.username;
    displayCode.textContent = currentUser.uniqueCode;
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

// Render chat list
function renderChatList() {
    chatList.innerHTML = '';
    
    chats.forEach(chat => {
        const chatItem = document.createElement('div');
        chatItem.className = `chat-item ${chat.id === currentChatId ? 'active' : ''}`;
        chatItem.dataset.id = chat.id;
        
        const statusIcon = getStatusIcon(chat.messages?.[chat.messages.length - 1]?.status);
        
        chatItem.innerHTML = `
            <div class="avatar">${chat.avatar}</div>
            <div class="chat-item-info">
                <div class="chat-item-header">
                    <span class="chat-item-name">${chat.name}</span>
                    <span class="chat-item-time">${chat.last_time || ''}</span>
                </div>
                <div class="chat-item-preview">
                    ${chat.last_message || 'Нет сообщений'}
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
        currentAvatar.textContent = chat.avatar;
        currentChatStatus.textContent = chat.online ? 'онлайн' : 'был(а) недавно';
        currentChatStatus.className = `chat-status ${chat.online ? '' : 'offline'}`;
        
        // Enable input
        messageInput.disabled = false;
        sendBtn.disabled = false;
        messageInput.focus();
        
        // Load messages
        await loadMessages(chatId);
        renderChatList();
    }
}

// Load messages for chat
async function loadMessages(chatId) {
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

// Render messages
function renderMessages(messages) {
    messagesContainer.innerHTML = '';
    
    if (!messages || messages.length === 0) {
        messagesContainer.innerHTML = '<div class="no-chat-selected"><p>Нет сообщений</p></div>';
        return;
    }
    
    messages.forEach(msg => {
        const messageEl = document.createElement('div');
        messageEl.className = `message ${msg.sent ? 'sent' : 'received'}`;
        
        const statusIcon = msg.sent ? getStatusIcon(msg.status) : '';
        
        messageEl.innerHTML = `
            <div class="message-content">${msg.text}</div>
            <div class="message-time">
                ${msg.time}
                ${msg.sent ? `<span class="message-status-icon">${statusIcon}</span>` : ''}
            </div>
        `;
        
        messagesContainer.appendChild(messageEl);
    });
    
    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
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
        } else {
            alert(data.message || 'Ошибка создания чата');
        }
    } catch (error) {
        console.error('Create chat error:', error);
    }
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
    
    // Enter key
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    
    // New chat button
    newChatBtn.addEventListener('click', createNewChat);
    
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
}

// Load settings
function loadSettings() {
    const settings = JSON.parse(localStorage.getItem('messengerSettings'));
    
    if (settings) {
        themeSelect.value = settings.theme || 'light';
        usernameInput.value = settings.username || 'Пользователь';
        notificationsToggle.checked = settings.notifications !== false;
        
        if (settings.theme === 'dark') {
            document.body.classList.add('dark-theme');
        }
    }
}

// Initialize app
init();