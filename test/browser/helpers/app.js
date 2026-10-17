'use strict';
// Действия человека в интерфейсе Nyxo: вход, группы, приглашения, сообщения,
// файлы, удаление аккаунта. Всё — через настоящие клики и ввод (helpers/page.js).
//
// Селекторы — по id и классам из public/index.html и script.js, а не по тексту
// кнопок: тексты интерфейса правятся чаще, чем разметка. Тексты проверяются
// только там, где сам текст и есть проверяемое (надпись о подписи приглашения,
// «Аккаунт удалён в другой вкладке»); они собраны в TEXT, чтобы при
// переименовании править одно место.

const APP_TIMEOUT_MS = 30000;

// Тексты, которые тесты проверяют именно как тексты.
const TEXT = {
    membershipByInvite: /Состав группы подтверждён по подписи приглашения/,
    deletedElsewhere: /Аккаунт удалён в другой вкладке/,
    deleted: /Аккаунт удалён/,
};

// ---- Вход ----

async function waitForApp(page, { timeoutMs = APP_TIMEOUT_MS } = {}) {
    await page.waitForSelector('#app:not(.hidden)', { timeoutMs });
    // Список чатов загрузился: у только что созданного аккаунта в нём уже есть чат с ботом.
    await page.waitForSelector('#chats-list .chat-item', { timeoutMs });
}

// Открыть адрес и нажать «Начать анонимно». Срок хранения по умолчанию — «пока
// открыта вкладка»; lifetime: 'day' | 'week' выбирает другой.
async function startAnonymously(page, url, { lifetime = null } = {}) {
    await page.goto(url);
    await page.waitForSelector('#anon-start-btn');
    if (lifetime && lifetime !== 'tab') {
        await page.click(`label.segmented-option:has(input[name="auth-lifetime"][value="${lifetime}"])`);
    }
    await page.click('#anon-start-btn');
    await waitForApp(page);
}

// Имя аккаунта — как его видит человек в профиле.
async function username(page) {
    await page.click('#profile-btn');
    await page.waitForSelector('#profile-modal:not(.hidden)');
    const name = (await page.text('#profile-username')).trim();
    await closeModal(page, 'profile-modal');
    return name;
}

async function closeModal(page, modalId) {
    await page.click(`#${modalId} .close-modal`);
    await page.waitForGone(`#${modalId}:not(.hidden)`);
}

// ---- Чаты ----

// Элемент списка чатов по названию: ждёт, пока он появится, и возвращает селектор по id чата.
async function chatItem(page, name) {
    const id = await page.waitFor((wanted) => {
        const item = Array.from(document.querySelectorAll('#chats-list .chat-item'))
            .find(el => (el.querySelector('.chat-name') || {}).textContent.trim() === wanted);
        return item ? item.dataset.id : null;
    }, { args: [name], what: `чат «${name}» в списке чатов` });
    return `#chats-list .chat-item[data-id="${id}"]`;
}

async function openChat(page, name) {
    await page.click(await chatItem(page, name));
    await page.waitForText('#chat-name', name);
    await page.waitForSelector('#message-input-container');
}

async function createGroup(page, name) {
    await page.click('#new-chat-btn');
    await page.type('#new-chat-name', name);
    await page.click('#create-chat-btn');
    await page.waitForText('#chat-name', name);
    await page.waitForSelector('#message-input-container');
    await page.waitForGone('#new-chat-modal:not(.hidden)');
}

// ---- Приглашения ----

async function openInvite(page) {
    await page.click('#get-chat-code-btn');
    await page.waitForSelector('#invite-modal:not(.hidden)');
    await page.waitFor(() => document.getElementById('invite-code-display').dataset.code, { what: 'код приглашения в окне' });
}

async function closeInvite(page) {
    await closeModal(page, 'invite-modal');
}

// Код и секрет ссылки из открытого окна приглашения (секрет есть только у подписанной ссылки).
function readInvite(page) {
    return page.evaluate(() => {
        const data = document.getElementById('invite-code-display').dataset;
        return { code: data.code, secret: data.secret || null };
    });
}

// В открытом окне приглашения: выключить «Впускать после одобрения» и создать
// новый код. Подтверждение window.confirm принимает обработчик диалогов вкладки.
async function rotateToSignedInvite(page) {
    await page.click('label[for="invite-approval"]');
    if (await page.evaluate(() => document.getElementById('invite-approval').checked)) {
        throw new Error('переключатель «Впускать после одобрения» не выключился');
    }
    await page.click('#rotate-invite-btn');
    await page.waitFor(() => document.getElementById('invite-code-display').dataset.secret, { what: 'секрет подписанной ссылки в окне приглашения', timeoutMs: 30000 });
    return readInvite(page);
}

// «Скопировать ссылку» и чтение системного буфера: проверяет и кнопку, и то, что в ссылке.
async function copyInviteLink(page, profile, origin) {
    await profile.connection.send('Browser.grantPermissions', { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'], origin });
    await page.click('#copy-invite-link-btn');
    return page.waitFor(async () => {
        try {
            const text = await navigator.clipboard.readText();
            return text || false;
        } catch {
            return false;
        }
    }, { what: 'ссылка-приглашение в буфере обмена' });
}

// Новый человек открывает ссылку: поле приглашения заполнено, аккаунт создаётся,
// показывается предпросмотр группы. Вступление подтверждает confirmJoin.
async function openInviteAsNewcomer(page, link) {
    await page.goto(link);
    await page.waitForSelector('#auth-invite:not(.hidden)');
    await page.click('#anon-start-btn');
    await page.waitForSelector('#join-preview:not(.hidden)', { timeoutMs: APP_TIMEOUT_MS });
}

// Код вводится в поле «У меня есть приглашение» (без секрета — как диктуют по телефону).
async function openCodeAsNewcomer(page, url, code) {
    await page.goto(url);
    await page.waitForSelector('#anon-start-btn');
    await page.click('#invite-toggle-btn');
    await page.waitForSelector('#auth-invite:not(.hidden)');
    await page.type('#auth-invite-input', code);
    await page.click('#anon-start-btn');
    await page.waitForSelector('#join-preview:not(.hidden)', { timeoutMs: APP_TIMEOUT_MS });
}

// Кнопка в предпросмотре («Вступить» или «Отправить заявку») и ожидание результата.
async function confirmJoin(page) {
    await page.click('#join-confirm-btn');
}

// Группа владельца и второй человек в ней по подписанной ссылке без одобрения:
// общая подготовка сценариев, которым группа с двумя участниками нужна как
// исходное состояние. Оба должны быть открыты на пустой вкладке и не иметь аккаунта.
async function groupWithMember({ baseUrl, name, owner, ownerPage, memberPage }) {
    await startAnonymously(ownerPage, `${baseUrl}/`);
    await createGroup(ownerPage, name);
    await openInvite(ownerPage);
    await rotateToSignedInvite(ownerPage);
    const link = await copyInviteLink(ownerPage, owner, baseUrl);
    await closeInvite(ownerPage);
    await openInviteAsNewcomer(memberPage, link);
    await confirmJoin(memberPage);
    await memberPage.waitForText('#chat-name', name, { timeoutMs: APP_TIMEOUT_MS });
    await waitForNotice(memberPage, TEXT.membershipByInvite);
}

// Участник открывает заявки, одобряет первую и закрывает окно.
async function approveFirstRequest(page) {
    await page.waitForSelector('#requests-bar:not(.hidden)', { timeoutMs: APP_TIMEOUT_MS });
    await page.click('#requests-bar-btn');
    await page.waitForSelector('#requests-modal:not(.hidden)');
    // Строка-заглушка («Загрузка…», «Новых заявок нет») тоже .request-row, но с классом muted.
    await page.click('#requests-list .request-row:not(.muted) .btn-primary');
    await page.waitForGone('#requests-list .request-row:not(.muted)');
    await closeModal(page, 'requests-modal');
}

// Список участников из окна «Участники и ключи».
async function readMembers(page, { expected }) {
    await page.click('#members-keys-btn');
    await page.waitForSelector('#members-modal:not(.hidden)');
    await page.waitFor((count) => document.querySelectorAll('#members-list .member-item').length >= count,
        { args: [expected], what: `в окне участников ${expected} чел.`, timeoutMs: APP_TIMEOUT_MS });
    const members = await page.evaluate(() => Array.from(document.querySelectorAll('#members-list .member-item'), (li) => ({
        name: (li.querySelector('.member-name') || {}).textContent || '',
        status: ((li.querySelector('.member-status') || {}).className || '').replace('member-status', '').trim() || null,
        how: Array.from(li.querySelectorAll('.member-how'), el => el.textContent.trim()),
        unconfirmed: Boolean(li.querySelector('.member-how.unconfirmed')),
    })));
    return members;
}

// ---- Сообщения ----

function waitForMessage(page, text, { sent = null, timeoutMs = APP_TIMEOUT_MS } = {}) {
    return page.waitFor((wanted, mine) => Array.from(document.querySelectorAll('#chat-messages .message')).some((el) => {
        const body = el.querySelector('.message-text');
        return body && body.textContent === wanted && (mine === null || el.classList.contains('sent') === mine);
    }), { args: [text, sent], what: `сообщение «${text}»${sent === null ? '' : sent ? ' (своё)' : ' (чужое)'}`, timeoutMs });
}

async function sendMessage(page, text) {
    await page.type('#message-input', text);
    await page.click('#send-btn');
    await waitForMessage(page, text, { sent: true });
}

// Лента открытого чата: сообщения и системные строки по порядку.
function readChat(page) {
    return page.evaluate(() => Array.from(document.querySelectorAll('#chat-messages .message, #chat-messages .system-notice'), (el) => {
        if (el.classList.contains('system-notice')) return { notice: el.textContent.trim() };
        const author = el.querySelector('.message-author');
        return {
            sent: el.classList.contains('sent'),
            author: author ? author.firstChild.textContent.trim() : null,
            text: (el.querySelector('.message-text') || {}).textContent || '',
            image: Boolean(el.querySelector('img.message-image')),
        };
    }));
}

function waitForNotice(page, pattern, { timeoutMs = APP_TIMEOUT_MS } = {}) {
    return page.waitForText('#chat-messages .system-notice', pattern, { timeoutMs });
}

// ---- Аккаунт ----

async function deleteAccount(page) {
    await page.click('#logout-btn');
    await page.waitForSelector('#delete-account-modal:not(.hidden)');
    await page.click('#confirm-delete-account-btn');
    await page.waitForSelector('#auth-screen:not(.hidden)', { timeoutMs: APP_TIMEOUT_MS });
}

// Что осталось на устройстве: ключи localStorage/sessionStorage и имена баз IndexedDB.
function readLocalData(page) {
    return page.evaluate(async () => {
        const databases = typeof indexedDB.databases === 'function' ? await indexedDB.databases() : [];
        return {
            local: Object.keys(localStorage).sort(),
            session: Object.keys(sessionStorage).sort(),
            indexedDb: databases.map(db => db.name).sort(),
        };
    });
}

module.exports = {
    TEXT,
    APP_TIMEOUT_MS,
    waitForApp,
    startAnonymously,
    username,
    closeModal,
    chatItem,
    openChat,
    createGroup,
    openInvite,
    closeInvite,
    readInvite,
    rotateToSignedInvite,
    copyInviteLink,
    openInviteAsNewcomer,
    openCodeAsNewcomer,
    confirmJoin,
    groupWithMember,
    approveFirstRequest,
    readMembers,
    waitForMessage,
    sendMessage,
    readChat,
    waitForNotice,
    deleteAccount,
    readLocalData,
};
