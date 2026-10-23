// public/js/08-modals-profile.js — модальные окна, профиль, срок хранения, уведомления и удаление аккаунта.
// Вынесено из public/script.js (строки 2971–3320 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

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
    if (modal === elements.confirmModal) onConfirmClosed();
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

// Затемнение вокруг окна — сам видимый .modal; клик по его содержимому сюда не относится
// (target — элемент внутри .modal-content).
function backdropModalOf(target) {
    const hit = target && target.classList && target.classList.contains('modal') && !target.classList.contains('hidden');
    return hit ? target : null;
}

// Окно, на затемнении которого нажали мышью/пальцем. Закрываем только если и нажатие, и
// отпускание пришлись на затемнение: протянутое из текста окна выделение, закончившееся
// снаружи, даёт click на общем предке — .modal, и окно закрывать не должно.
let backdropPress = null;

function rememberBackdropPress(e) {
    backdropPress = backdropModalOf(e.target);
}

// alertdialog (подтверждение, удаление аккаунта, предупреждение о коде) мимокликом не
// закрывается: на такой вопрос надо ответить явно.
function closeOnBackdropClick(e) {
    const modal = backdropModalOf(e.target);
    const pressed = backdropPress;
    backdropPress = null;
    if (!modal || modal !== pressed) return;
    if (modal.getAttribute('role') === 'alertdialog') return;
    closeAllModals();
}

// Escape закрывает окно, Tab не уводит фокус из открытого окна за оверлей.
function onModalKeydown(e) {
    const open = document.querySelectorAll('.modal:not(.hidden)');
    if (open.length === 0) return;
    const modal = open[open.length - 1];
    if (e.key === 'Escape') {
        e.preventDefault();
        // Подтверждение поверх другого окна закрывается одно: нижнее окно остаётся.
        if (modal === elements.confirmModal) closeModal(modal);
        else closeAllModals();
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

// ==================== Окно подтверждения ====================
// Своё окно вместо window.confirm: у родного диалога нельзя подписать кнопки («Выйти и
// удалить сообщения»), его нельзя оформить под тему, а когда браузер отключает диалоги
// страницы, confirm() молча возвращает false — действие не выполнялось и без объяснений.
//
// confirmDialog({ title, paragraphs, actions: [{ id, label, style }], cancelLabel }) →
// Promise<id нажатой кнопки | null>. null — закрыто крестиком, Escape, «Отмена» или
// закрытием всех окон (выход из аккаунта): висящих обещаний не остаётся. Фокус сначала на
// «Отмене»; после закрытия возвращается туда, где был (в нижнем окне — на кнопку-источник).
let confirmResolve = null;
let confirmChoice = null;
let confirmReturnFocus = null;

function confirmDialog({ title, paragraphs = [], actions = [], cancelLabel = 'Отмена' }) {
    if (confirmResolve) closeModal(elements.confirmModal);   // прежний вопрос ещё висел: считаем отменённым
    elements.confirmTitle.textContent = title;
    elements.confirmBody.replaceChildren(...paragraphs.map((text) => {
        const p = document.createElement('p');
        p.textContent = text;
        return p;
    }));
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'btn btn-ghost';
    cancel.dataset.autofocus = '';
    cancel.dataset.cancel = '';
    cancel.textContent = cancelLabel;
    cancel.addEventListener('click', () => closeModal(elements.confirmModal));
    const buttons = actions.map((action) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `btn ${action.style === 'danger' ? 'btn-danger' : action.style === 'secondary' ? 'btn-secondary' : 'btn-primary'}`;
        btn.dataset.action = action.id;
        btn.textContent = action.label;
        btn.addEventListener('click', () => {
            confirmChoice = action.id;
            closeModal(elements.confirmModal);
        });
        return btn;
    });
    elements.confirmActions.replaceChildren(cancel, ...buttons);
    confirmChoice = null;
    confirmReturnFocus = document.activeElement;
    return new Promise((resolve) => {
        confirmResolve = resolve;
        openModal(elements.confirmModal);
    });
}

// Окно закрыли (любым путём): отдать выбор ждущему и вернуть фокус.
function onConfirmClosed() {
    const resolve = confirmResolve;
    const choice = confirmChoice;
    const target = confirmReturnFocus;
    confirmResolve = null;
    confirmChoice = null;
    confirmReturnFocus = null;
    if (target && target.isConnected && typeof target.focus === 'function') target.focus({ preventScroll: true });
    if (resolve) resolve(choice);
}

// Вопрос с одним «да»: true — подтверждено. text — абзацы через пустую строку.
async function confirmAction(text, { title = 'Подтвердите действие', confirmLabel = 'Продолжить', danger = false } = {}) {
    const choice = await confirmDialog({
        title,
        paragraphs: String(text).split(/\n\s*\n/),
        actions: [{ id: 'ok', label: confirmLabel, style: danger ? 'danger' : 'primary' }],
    });
    return choice === 'ok';
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
    // Совет «не закрывайте вкладку» на карточках заявок зависит от срока.
    if (!elements.newChatModal.classList.contains('hidden')) loadMyRequests();
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
