// public/js/07-api-listeners.js — экраны входа/приложения, всплывающие сообщения, api() и навешивание обработчиков событий.
// Вынесено из public/script.js (строки 2396–2970 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// showAuth/showApp/showToast, api/postFormData*, setupEventListeners и все setup*Listeners.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

function showAuth() {
    elements.authScreen.classList.remove('hidden');
    elements.app.classList.add('hidden');
}

function showApp() {
    elements.authScreen.classList.add('hidden');
    elements.app.classList.remove('hidden');
}

let toastTimer = null;
const TOAST_ICONS = { success: 'check', error: 'alert-triangle', info: 'info' };
function showToast(message, type = 'info', duration = 3000) {
    const kind = TOAST_ICONS[type] ? type : 'info';
    const text = document.createElement('span');
    text.textContent = message || '';
    elements.toast.replaceChildren(icon(TOAST_ICONS[kind]), text);
    elements.toast.className = `toast toast-${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => elements.toast.classList.add('hidden'), duration);
}

function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
    return match ? match[1] : '';
}

// Ответ «Не авторизован» посреди работы: сессии может уже не быть (аккаунт
// удалён по сроку или в другой вкладке), а может, запрос просто ушёл со
// старой кукой, пока сервер пересоздавал сессию (смена срока). Решает
// свежий /api/auth (pingSession): сам ответ ключи не стирает.
function onUnauthorizedResponse(data) {
    if (currentUser && data && data.success === false && data.message === 'Не авторизован') pingSession();
}

// Любой ответ сервера приводится к { success, message, ... }. Раньше
// ответ не-JSON (502 от прокси, обрыв сети) бросал исключение прямо в
// обработчике клика, и кнопка просто "ничего не делала". networkError —
// запрос не дошёл до сервера (важно для «Удалить и выйти»: тогда аккаунт
// точно не удалён). skipAuthCheck — вызывающий сам разбирает «Не авторизован».
async function api(url, options = {}, retried = false) {
    const { skipAuthCheck = false, ...init } = options;
    let res;
    try {
        res = await fetch(url, {
            ...init,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
                ...init.headers,
            },
        });
    } catch {
        return { success: false, networkError: true, message: 'Нет соединения с сервером' };
    }
    let data;
    try {
        data = await res.json();
    } catch {
        return { success: false, httpStatus: res.status, message: `Ошибка сервера (HTTP ${res.status})` };
    }
    if (!data || typeof data !== 'object') return { success: false, httpStatus: res.status, message: `Ошибка сервера (HTTP ${res.status})` };
    // Статус нужен тем, кто различает исходы (повтор отправки после 5xx и 409,
    // sendText); тело при этом остаётся прежним.
    data.httpStatus = res.status;
    // Кука csrf_token живёт сутки; если она истекла, любой GET выдаст новую.
    if (res.status === 403 && !retried && /CSRF/i.test(data.message || '')) {
        await fetch('/api/auth').catch(() => {});
        return api(url, options, true);
    }
    if (!skipAuthCheck) onUnauthorizedResponse(data);
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
        return { success: false, networkError: true, message: 'Нет соединения с сервером' };
    }
    const data = await res.json().catch(() => ({ success: false, message: `Ошибка сервера (HTTP ${res.status})` }));
    if (data && typeof data === 'object') data.httpStatus = res.status;
    if (res.status === 403 && !retried && /CSRF/i.test(data.message || '')) {
        await fetch('/api/auth').catch(() => {});
        return postFormData(url, formData, true);
    }
    onUnauthorizedResponse(data);
    return data;
}

// Тот же multipart-запрос через XMLHttpRequest: у fetch нет событий
// прогресса отправки. Заголовок CSRF и куки — как у fetch (same-origin,
// withCredentials на всякий случай явно). options.onProgress(0..1),
// options.onXhr(xhr) — чтобы вызывающий мог отменить загрузку (abort).
// Отмена резолвится { success:false, aborted:true }.
function postFormDataWithProgress(url, formData, options = {}, retried = false) {
    return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', url);
        xhr.withCredentials = true;
        xhr.responseType = 'text';
        xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());
        if (typeof options.onXhr === 'function') options.onXhr(xhr);
        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable && typeof options.onProgress === 'function') options.onProgress(e.loaded / e.total);
        };
        xhr.onabort = () => resolve({ success: false, aborted: true, message: 'Загрузка отменена' });
        xhr.onerror = () => resolve({ success: false, networkError: true, message: 'Нет соединения с сервером' });
        xhr.onload = async () => {
            let data;
            try {
                data = JSON.parse(xhr.responseText);
            } catch {
                data = { success: false, message: `Ошибка сервера (HTTP ${xhr.status})` };
            }
            if (data && typeof data === 'object') data.httpStatus = xhr.status;
            if (xhr.status === 403 && !retried && /CSRF/i.test((data && data.message) || '')) {
                await fetch('/api/auth').catch(() => {});
                resolve(postFormDataWithProgress(url, formData, options, true));
                return;
            }
            onUnauthorizedResponse(data);
            resolve(data || { success: false });
        };
        xhr.send(formData);
    });
}

// Обработчики навешиваются по областям интерфейса, каждая — в своей функции
// ниже. Порядок вызовов повторяет прежний порядок регистрации, когда всё
// было одним длинным телом: он важен там, где на один и тот же элемент и
// событие вешается несколько обработчиков (например, два keydown на
// document). Новый обработчик добавляйте в функцию своей области; новая
// область — новая функция и одна строка в этом списке.
function setupEventListeners() {
    setupAuthListeners();        // экран входа, «Как это работает»
    setupLogoutListeners();      // выход из аккаунта
    setupSidebarListeners();     // «Новый чат», вступление по коду, «назад»
    setupChatMenuListeners();    // меню чата и личные настройки чатов
    setupE2eeListeners();        // шифрование в шапке чата, участники и ключи
    setupInviteListeners();      // приглашения и заявки
    setupProfileListeners();     // профиль, настройки, удаление аккаунта
    setupComposerListeners();    // поле ввода, вложения
    setupMessageMenuListeners(); // меню сообщения
    setupSearchListeners();      // поиск по чатам
    setupModalListeners();       // модальные окна
    setupFeedListeners();        // лента сообщений
    setupSocketListeners();      // события сокета
    setupMenuDismissListeners(); // закрытие всплывающих меню
}

// Экран входа: выбор срока, «Начать анонимно», поле приглашения, окно
// «Как это работает» и ссылка на onion-адрес.
function setupAuthListeners() {
    elements.authLifetime.addEventListener('change', updateAuthLifetimeDetail);
    elements.anonStartBtn.addEventListener('click', startAccount);
    elements.inviteToggleBtn.addEventListener('click', () => setInviteMode(!authInviteMode, { focus: true }));
    elements.authInviteInput.addEventListener('input', clearInviteError);
    elements.authInviteInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            startAccount();
        }
    });
    elements.aboutOpenBtn.addEventListener('click', () => openAboutModal());
    elements.onionOpenBtn.addEventListener('click', () => openAboutModal('tor'));
    elements.aboutOnionCopyBtn.addEventListener('click', () => {
        if (onionUrl) copyText(onionUrl, 'Адрес скопирован', 'Не удалось скопировать — выделите адрес вручную');
    });
    updateAuthLifetimeDetail();
    applyOnionUrl(onionUrl);
}

// «Удалить и выйти» в сайдбаре: аккаунт держится только на cookie этого
// браузера, поэтому выход и есть удаление — то же подтверждение, что и у
// кнопки в профиле.
function setupLogoutListeners() {
    elements.logoutBtn.addEventListener('click', openDeleteAccountModal);
    elements.confirmDeleteAccountBtn.addEventListener('click', deleteAccountAndLeave);
}

// Сайдбар и окно «Новый чат»: создание группы, вступление по коду
// приглашения; «назад» к списку чатов в мобильной раскладке.
function setupSidebarListeners() {
    elements.newChatBtn.addEventListener('click', () => openNewChatModal());
    elements.createChatBtn.addEventListener('click', createChat);
    document.getElementById('new-chat-name').addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            createChat();
        }
    });
    elements.joinChatBtn.addEventListener('click', previewJoin);
    elements.joinChatCode.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.isComposing) {
            e.preventDefault();
            previewJoin();
        }
    });
    elements.joinChatCode.addEventListener('input', () => {
        hideJoinPreview();
        clearJoinError();
    });
    elements.joinConfirmBtn.addEventListener('click', joinChat);
    elements.joinCancelBtn.addEventListener('click', onJoinCancel);

    if (elements.backBtn) {
        elements.backBtn.addEventListener('click', () => elements.sidebar.classList.remove('hidden-mobile'));
    }
}

// Меню чата и личные настройки чатов (закрепить, без звука, архив, срок
// исчезающих сообщений) — в окне меню и в контекстном меню списка.
function setupChatMenuListeners() {
    elements.chatMenuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        openChatMenu();
    });
    elements.deleteChatBtn.addEventListener('click', deleteChat);
    elements.pinChatBtn.addEventListener('click', () => toggleChatPref(currentChatId, 'pinned'));
    elements.muteChatBtn.addEventListener('click', () => toggleChatPref(currentChatId, 'muted'));
    elements.archiveChatBtn.addEventListener('click', () => toggleChatPref(currentChatId, 'archived'));
    elements.expiryFieldset.querySelectorAll('input[name="chat-expiry"]').forEach((radio) => {
        radio.addEventListener('change', () => {
            if (radio.checked) setChatExpiry(Number(radio.value));
        });
    });
    elements.ctxPinBtn.addEventListener('click', () => onChatItemMenuAction('pinned'));
    elements.ctxMuteBtn.addEventListener('click', () => onChatItemMenuAction('muted'));
    elements.ctxArchiveBtn.addEventListener('click', () => onChatItemMenuAction('archived'));
}

// Сквозное шифрование в шапке чата: значок шифрования и кнопка открывают окно
// «Участники и ключи», баннер о смене ключа собеседника; «Повторить» под полем
// ввода. Выключателя нет.
function setupE2eeListeners() {
    elements.e2eeIndicator.addEventListener('click', openMembersModal);
    elements.membersKeysBtn.addEventListener('click', openMembersModal);
    elements.noHistoryToggle.addEventListener('change', onNoHistoryToggle);
    elements.e2eeBannerBtn.addEventListener('click', openMembersModal);
    elements.ktBannerBtn.addEventListener('click', openTransparencyModal);
    elements.composerStatusRetry.addEventListener('click', () => retryE2ee());
}

// Приглашения в группу (код, ссылка, QR) и заявки на вступление.
function setupInviteListeners() {
    elements.getChatCodeBtn.addEventListener('click', openInviteModal);
    elements.rotateInviteBtn.addEventListener('click', rotateInviteCode);
    elements.disableInviteBtn.addEventListener('click', disableInviteCode);
    elements.copyInviteBtn.addEventListener('click', () => {
        const code = elements.inviteCodeDisplay.dataset.code || '';
        if (code) copyText(code, 'Код скопирован', 'Не удалось скопировать — выделите код вручную');
    });
    elements.copyInviteLinkBtn.addEventListener('click', () => {
        const code = elements.inviteCodeDisplay.dataset.code || '';
        const secret = elements.inviteCodeDisplay.dataset.secret || '';
        if (code) copyText(inviteLink(code, secret), secret ? 'Ссылка скопирована' : 'Ссылка без секрета скопирована: по ней можно только отправить заявку', 'Не удалось скопировать ссылку');
    });
    elements.requestsBarBtn.addEventListener('click', openRequestsModal);
}

// Профиль: срок хранения, отметки о прочтении, уведомления, «Как устроен
// Nyxo», «Удалить аккаунт и выйти». Заметка о сроке в сайдбаре тоже
// открывает профиль — там срок и меняется.
function setupProfileListeners() {
    elements.profileBtn.addEventListener('click', openProfile);
    elements.anonNote.addEventListener('click', openProfile);
    elements.profileLifetime.addEventListener('change', onProfileLifetimeChange);
    elements.readReceiptsToggle.addEventListener('change', onReadReceiptsToggle);
    elements.notifyToggle.addEventListener('change', onNotifyToggle);
    elements.profileAboutBtn.addEventListener('click', () => openAboutModal());
    elements.deleteAccountBtn.addEventListener('click', openDeleteAccountModal);
}

// Поле ввода: отправка по кнопке и Enter, Escape (отмена правки и ответа),
// вложения (скрепка, окно «Отправить файлы», перетаскивание), отмена ответа.
function setupComposerListeners() {
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
    // Поле очищено вручную — правка отменяется (плашка пропадает): иначе
    // следующий набранный текст тихо ушёл бы как правка старого сообщения.
    elements.messageInput.addEventListener('input', () => {
        if (editingMessageId && !elements.messageInput.value.trim()) cancelEditing();
    });

    elements.attachBtn.addEventListener('click', () => {
        if (uploadQueue) {
            showToast('Дождитесь окончания загрузки', 'info');
            return;
        }
        elements.fileInput.click();
    });
    elements.fileInput.addEventListener('change', () => {
        const files = Array.from(elements.fileInput.files || []);
        elements.fileInput.value = '';
        onFilesChosen(files);
    });
    elements.sendFilesBtn.addEventListener('click', sendChosenFiles);
    elements.uploadCancelBtn.addEventListener('click', () => cancelUploadQueue(true));
    setupDragAndDrop();
    elements.cancelReplyBtn.addEventListener('click', clearReply);
    elements.cancelEditBtn.addEventListener('click', () => {
        cancelEditing();
        elements.messageInput.focus();
    });
    elements.botSuggestions.addEventListener('click', onBotSuggestionClick);
}

// Меню сообщения: панель реакций, ответ, копирование, правка, удаление.
function setupMessageMenuListeners() {
    buildReactionPicker();
    elements.messageMenu.addEventListener('keydown', (e) => onPopupMenuKeydown(e, elements.messageMenu, hideMessageMenu));

    elements.replyMessageBtn.addEventListener('click', () => {
        const message = menuMessage;
        hideMessageMenu();
        if (message) startReply(message);
    });

    elements.copyMessageBtn.addEventListener('click', () => {
        const message = menuMessage;
        hideMessageMenu();
        if (message && message.text) copyText(message.text, 'Текст скопирован', 'Не удалось скопировать текст');
    });

    elements.editMessageBtn.addEventListener('click', () => {
        const message = menuMessage;
        hideMessageMenu();
        if (message) startEditing(message);
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
}

// Поиск по названиям чатов: фильтр на клиенте, без запросов; перерисовка — на
// следующем кадре после ввода. Escape очищает фильтр, стрелка вниз переводит фокус
// на первый чат, Enter открывает первый. Поиск по сообщениям открытого чата — в
// шапке (setupChatSearchListeners).
function setupSearchListeners() {
    let frame = 0;
    elements.searchInput.addEventListener('input', () => {
        if (frame) cancelAnimationFrame(frame);
        frame = requestAnimationFrame(() => {
            frame = 0;
            applyChatFilter();
        });
    });
    elements.searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && elements.searchInput.value) {
            e.preventDefault();
            elements.searchInput.value = '';
            applyChatFilter();
        } else if (e.key === 'ArrowDown' || e.key === 'Enter') {
            const first = elements.chatsList.querySelector('.chat-item');
            if (!first) return;
            e.preventDefault();
            if (e.key === 'Enter') first.click();
            else first.focus();
        }
    });
    setupChatSearchListeners();
}

// Модальные окна: закрытие по крестику и кнопкам «Отмена», по оверлею и
// Escape (а также удержание фокуса внутри окна — onModalKeydown).
function setupModalListeners() {
    document.querySelectorAll('.close-modal, [data-close-modal]').forEach(btn => {
        btn.addEventListener('click', closeAllModals);
    });

    elements.overlay.addEventListener('click', () => {
        closeAllModals();
        hideMessageMenu();
        hideChatItemMenu();
    });

    document.addEventListener('keydown', onModalKeydown);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideMessageMenu();
            hideChatItemMenu();
        }
    });
}

// Лента сообщений: подгрузка истории, отметка «прочитано», кнопка «вниз»,
// ссылка-приглашение, вставленная в уже открытую вкладку.
function setupFeedListeners() {
    // Подгрузка более старых сообщений при прокрутке к началу.
    elements.chatMessages.addEventListener('scroll', () => {
        if (elements.chatMessages.scrollTop < 200) loadOlderMessages();
        if (isNearBottom()) markVisibleMessagesRead();
        updateJumpDown();
    }, { passive: true });
    elements.jumpDown.addEventListener('click', () => scrollToBottom(true));

    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') markVisibleMessagesRead();
        keepaliveOnVisible();
        maintainE2eeKeys();
        onHistoryVisibilityChange(document.visibilityState === 'hidden');
    });
    window.addEventListener('pagehide', forgetOpenRoomOnPageHide);

    // Ссылка-приглашение, вставленная в уже открытую вкладку.
    window.addEventListener('hashchange', consumeJoinFragment);
}

// События сокета: новые, изменённые и удалённые сообщения, прочтение,
// состав комнаты, срок исчезающих сообщений, заявки, список чатов.
function setupSocketListeners() {
    socket.on('newMessage', async (message) => {
        if (!currentUser) return;
        const mine = isOwnMessage(message);
        if (!mine) maybeNotify(message);
        if (belongsToCurrentChat(message.chat_id, message.room_id)) {
            const roomId = currentRoomId;
            const seq = openChatSeq;
            const stickToBottom = mine || isNearBottom();
            await decryptMessageInPlace(message, roomId);
            if (seq !== openChatSeq) return; // пока расшифровывали, открыли другой чат
            if (appendMessage(message, true)) {
                if (stickToBottom) scrollToBottom();
                else if (!mine) bumpJumpDown();
            }
            updateChatListOnMessage(message, true);
            if (!mine) markVisibleMessagesRead();
        } else {
            updateChatListOnMessage(message, false);
        }
    });

    socket.on('messageEdited', async ({ id, text, chat_id, room_id, encrypted }) => {
        if (!belongsToCurrentChat(chat_id, room_id)) return;
        const roomId = currentRoomId;
        const seq = openChatSeq;
        let displayText = text;
        let failed = false;
        if (roomId && !encrypted) {
            // Правка без шифрования в комнате: так не бывает, текст не показываем.
            displayText = e2eeFailureText('not-encrypted');
            failed = true;
        } else if (encrypted) {
            const res = await decryptEnvelope(roomId, null, text, id);
            displayText = decryptedSummary(res);
            failed = !res.ok;
        }
        if (seq !== openChatSeq) return;
        applyMessageEdit(id, displayText, failed);
        scheduleLoadChats();
    });

    // Реакцию поставил или снял другой участник (или другая вкладка этого же аккаунта):
    // сервер присылает итог по эмодзи, mine — только вкладкам автора реакции.
    socket.on('reactionChanged', ({ id, emoji, count, mine, chat_id, room_id } = {}) => {
        if (!currentUser || id === undefined || typeof emoji !== 'string') return;
        if (!belongsToCurrentChat(chat_id, room_id)) return;
        applyReactionChange(id, emoji, count, typeof mine === 'boolean' ? mine : undefined);
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
    socket.on('messagesRead', ({ chat_id, room_id, up_to_seq } = {}) => {
        if (!belongsToCurrentChat(chat_id, room_id)) return;
        const upTo = Number(up_to_seq);
        if (!upTo) return;
        elements.chatMessages.querySelectorAll('.message.sent').forEach((el) => {
            if (el.dataset.seq !== undefined && Number(el.dataset.seq) <= upTo) {
                if (el._message) el._message.status = 'read';
                renderMessageStatus(el);
            }
        });
    });

    // Состав комнаты изменился (вступление по коду, одобренная заявка,
    // выход): забираем новые key-share и пересобираем сессию — новому
    // участнику уходит наш Sender Key, после ухода свой ключ ротируется.
    socket.on('roomMembersChanged', ({ roomId, inviteRotated } = {}) => {
        if (!currentUser || !roomId) return;
        // Решение владельца (signed-membership.md, вопрос 17): при выходе любого участника подписанное приглашение
        // сервер обнуляет и выдаёт новый код; новую подписанную ссылку создаёт следующий, кто нажмёт «Пригласить».
        if (inviteRotated === true && Number(roomId) === Number(currentRoomId)) {
            appendSystemNotice(roomId, 'Ссылка-приглашение обновлена: участник вышел из группы', 'link');
            if (inviteState) inviteState = { ...inviteState, signed: false, linkSecret: null };
        }
        scheduleRoomMembersRefresh(roomId);
        scheduleLoadChats(); // число участников в списке и в шапке
    });

    // Таймер исчезающих сообщений общий на комнату: его мог сменить любой
    // участник — в ленте остаётся служебная строка, как в Signal.
    socket.on('chatExpiryChanged', ({ roomId, chatId, seconds } = {}) => {
        if (!currentUser) return;
        const value = normalizeExpiry(seconds);
        const meta = findChatMeta(chatId, roomId);
        if (meta) meta.expiry_seconds = value;
        if (roomId) syncRoomKeyPolicy(roomId, value);
        renderChatList();
        if (!belongsToCurrentChat(chatId, roomId)) return;
        if (!meta) currentChatExtra.expiry_seconds = value;
        updateChatIndicators();
        syncExpiryRadios();
        appendChatNotice(value ? `Исчезающие сообщения: ${EXPIRY_LABELS[value]}` : 'Исчезающие сообщения выключены', 'timer');
    });

    socket.on('joinRequestsChanged', ({ roomId } = {}) => {
        if (!currentUser || !roomId || Number(roomId) !== Number(currentRoomId)) return;
        loadJoinRequestsCount();
        if (!elements.requestsModal.classList.contains('hidden')) loadRequestsList();
    });

    // approved:false приходит не только при отказе, но и когда заявка
    // пропала сама (группу удалили, истёк срок заявки) — текст нейтральный.
    socket.on('joinRequestDecided', ({ requestId, approved, chat } = {}) => {
        if (!currentUser) return;
        const roomName = myRequestNames.get(String(requestId));
        myRequestNames.delete(String(requestId));
        if (!elements.newChatModal.classList.contains('hidden')) loadMyRequests();
        if (!approved) {
            showToast(`Заявку${roomName ? ` в «${roomName}»` : ''} не приняли: её отклонили или она больше не действует`, 'info', 6000);
            return;
        }
        const name = chat && chat.name ? `«${chat.name}»` : '';
        showToast(`Заявку одобрили — вы в группе ${name}`.trim(), 'success', 5000);
        loadChats();
        if (chat && chat.id) {
            closeModal(elements.newChatModal);
            openChat(chat.id, chat.room_id, chat.name, chat.avatar, chat.online, chat.is_bot);
        }
    });

    // Закрепление/архив/звук сменили в другой вкладке.
    socket.on('chatListChanged', () => {
        if (currentUser) scheduleLoadChats();
    });
}

// Всплывающие меню (сообщения и элемента списка чатов) закрываются кликом
// мимо, прокруткой и изменением размера окна.
function setupMenuDismissListeners() {
    document.addEventListener('click', onDocumentClickForMenus);
    document.addEventListener('scroll', () => {
        hideMessageMenu();
        hideChatItemMenu();
    }, true);
    window.addEventListener('resize', () => {
        hideMessageMenu();
        hideChatItemMenu();
    });
}
