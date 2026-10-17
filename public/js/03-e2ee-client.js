// public/js/03-e2ee-client.js — E2EE: клиент шифрования (X3DH + Sender Keys), его состояние и блокировка поля ввода.
// Вынесено из public/script.js (строки 534–804 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Начало раздела «E2EE (X3DH + Sender Keys)»: getE2eeClient/initE2eeForCurrentUser, автоповтор, блокировка комнаты и композера.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== E2EE (X3DH + Sender Keys) ====================
// Ключи устройства хранятся в IndexedDB, отдельная база на каждого
// currentUser.id — это исключает утечку ключевого материала между
// разными аккаунтами на одном браузере (общий компьютер, тест-логины).
// Подробности протокола и честные ограничения — см. public/e2ee.js.
//
// Шифрование в комнатах обязательно, выключателя нет (R7): сервер всё равно
// принимает в комнату только конверт правильной формы. Если ключи устройства
// не удалось подготовить, поле ввода комнаты отключается, а под ним — причина
// по коду E2eeError и «Повторить» (плюс автоповтор, пока комната открыта).
// Открытым текстом уходят только сообщения в чат с ботом, номер которого
// запомнен при регистрации (NyxoE2eePolicy.plaintextAllowed), а не любой чат,
// который сервер назвал ботом. Что показать в каждом состоянии, решает чистая
// функция NyxoE2eePolicy.composerView (public/lib/e2ee-policy.js).

let e2eeClient = null;
let e2eeClientUserId = null;
let e2eeInitPromise = null;       // Promise<boolean>: true — ключи устройства готовы
let e2eeState = 'off';            // 'off' | 'pending' | 'ready' | 'unavailable'
let e2eeInitError = null;         // ошибка последней неудачной инициализации (E2eeError с code)
let e2eeUnavailableWarned = false;
let e2eeRetryTimer = null;        // автоповтор инициализации
let e2eeRetryStep = 0;            // сколько автоповторов уже было
let roomBlock = null;             // { chatId, text } — почему отправка в комнату только что отклонена

// Паузы автоповтора после неудачной инициализации (сеть или сервер ключей):
// 10 с, 30 с, 2 мин. Дальше — только кнопка «Повторить».
const E2EE_AUTO_RETRY_MS = [10 * 1000, 30 * 1000, 2 * 60 * 1000];

function getE2eeClient() {
    if (!currentUser || typeof E2EE === 'undefined') return null;
    if (!e2eeClient || e2eeClientUserId !== currentUser.id) {
        try {
            e2eeClient = E2EE.createClient({
                userId: currentUser.id,
                storage: E2EE.makeIndexedDbStorage('nyxo-e2ee-' + currentUser.id),
                // Две вкладки одного аккаунта делят IndexedDB с ключами: Web Locks не дают им
                // выдать одну итерацию Sender Key двум сообщениям (message-ordering.md, 9.7).
                // Без Web Locks lock = null — работает внутренняя очередь клиента, в консоли предупреждение.
                lock: NyxoE2eeLock.makeLock(typeof navigator !== 'undefined' ? navigator.locks : null, currentUser.id,
                    (message) => console.warn(message)),
                // Ключ журнала ключей из манифеста релиза (keys.kt в /client-manifest.json): клиент сверяет с ним ключ при
                // первом закреплении, несовпадение — тревога «ключ журнала изменился». Нет манифеста или ключа в нём — null.
                ktManifestKey: () => (typeof NyxoKtClient !== 'undefined' ? NyxoKtClient.fetchManifestKey() : null),
                // Прозрачность ключей: новая тревога журнала сразу попадает в баннер боковой панели.
                onTransparencyAlert: (alert) => {
                    // stale — не тревога, а предупреждение: журнал давно не обновлялся (не блокирует работу).
                    if (alert && alert.kind === 'stale') showToast('Журнал ключей на сервере давно не обновлялся: проверка ключей собеседников может запаздывать', 'info', 8000);
                    refreshTransparencyBanner();
                },
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

// Один тост на вход: потом то же самое видно под полем ввода комнаты.
function warnE2eeUnavailable(err) {
    if (e2eeUnavailableWarned) return;
    e2eeUnavailableWarned = true;
    showToast(`Сквозное шифрование недоступно: ${NyxoE2eePolicy.initErrorReason(err)}. В группы сообщения не отправляются, пока оно не заработает`, 'error', 8000);
}

function initE2eeForCurrentUser() {
    const userId = currentUser ? currentUser.id : null;
    const client = getE2eeClient();
    if (!client) {
        // Нет модуля шифрования или клиент не создался: повторять нечего.
        e2eeInitError = { code: 'unsupported' };
        e2eeState = 'unavailable';
        e2eeInitPromise = Promise.resolve(false);
        warnE2eeUnavailable(e2eeInitError);
        refreshE2eeUi();
        return e2eeInitPromise;
    }
    e2eeState = 'pending';
    e2eeInitError = null;
    refreshE2eeUi();
    // Показ приложения генерацией/загрузкой ключей не блокируется: кому
    // нужны ключи (отправка, расшифровка), тот дожидается этого promise.
    e2eeInitPromise = Promise.resolve()
        .then(() => client.init())
        .then(() => {
            if (!currentUser || currentUser.id !== userId) return false;
            e2eeState = 'ready';
            e2eeRetryStep = 0;
            clearTimeout(e2eeRetryTimer);
            refreshE2eeUi();
            // Журнал ключей: плановые проверки раз в час и первая проверка (самомониторинг) сразу после входа.
            if (typeof client.startTransparency === 'function') {
                client.startTransparency();
                client.runKtChecks().then(refreshTransparencyBanner, (err) => console.warn('E2EE: проверка журнала ключей не удалась:', err));
            }
            return true;
        }, (err) => {
            console.error('E2EE: инициализация ключей устройства не удалась:', err);
            if (!currentUser || currentUser.id !== userId) return false;
            e2eeState = 'unavailable';
            e2eeInitError = err;
            warnE2eeUnavailable(err);
            refreshE2eeUi();
            scheduleE2eeAutoRetry();
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

// Автоповтор: пока причина может пройти сама (сеть, сервер ключей), комната
// открыта и вкладка видна — новая попытка через 10 с, 30 с, 2 мин. Если условия
// не выполнены, проверка повторяется через ту же паузу, а счётчик не растёт.
function scheduleE2eeAutoRetry() {
    clearTimeout(e2eeRetryTimer);
    if (e2eeState !== 'unavailable' || !NyxoE2eePolicy.initErrorRetryable(e2eeInitError)) return;
    if (e2eeRetryStep >= E2EE_AUTO_RETRY_MS.length) return;
    e2eeRetryTimer = setTimeout(() => {
        if (!currentUser || e2eeState !== 'unavailable') return;
        if (!currentRoomId || document.visibilityState !== 'visible') {
            scheduleE2eeAutoRetry();
            return;
        }
        e2eeRetryStep++;
        retryE2ee({ silent: true });
    }, E2EE_AUTO_RETRY_MS[e2eeRetryStep]);
}

// Номер чата с ботом, запомненный при регистрации (ответ botChatId).
function readRememberedBotChatId(userId) {
    try {
        return localStorage.getItem(BOT_CHAT_PREFIX + userId);
    } catch {
        return null;
    }
}

// Открытый текст можно отправить только в чат с ботом, номер которого запомнен
// на этом устройстве; признак is_bot от сервера для этого не используется.
function plaintextAllowedForChat(chatId, roomId) {
    return Boolean(currentUser) && NyxoE2eePolicy.plaintextAllowed(readRememberedBotChatId(currentUser.id), chatId, roomId);
}

function currentRoomBlock() {
    return roomBlock && roomBlock.chatId === currentChatId ? roomBlock : null;
}

// Причина по тексту: отправка отклонена, пока ключ комнаты не дошёл до участников.
function setRoomBlock(chatId, text) {
    roomBlock = { chatId, text };
    if (chatId === currentChatId) updateComposerForChat();
}

function clearRoomBlock(chatId) {
    if (!roomBlock || (chatId !== undefined && roomBlock.chatId !== chatId)) return;
    roomBlock = null;
    updateComposerForChat();
}

// Причина, по которой поле ввода сейчас отключено (пусто — доступно): ею же
// отвечают перетаскивание файлов и подсказки кнопок.
let composerDisabledReason = '';

function setComposerDisabled(disabled, reason) {
    composerDisabledReason = disabled ? reason : '';
    elements.messageInput.disabled = disabled;
    elements.sendBtn.disabled = disabled;
    elements.attachBtn.disabled = disabled || Boolean(uploadQueue);
    elements.sendBtn.title = disabled ? reason : 'Отправить';
    elements.attachBtn.title = disabled ? reason : 'Прикрепить файлы';
}

// Шапка и поле ввода открытого чата: значок шифрования, строка состояния под
// полем, подсказка в поле, доступность отправки и вложений.
function updateComposerForChat() {
    if (!currentChatId) return;
    const inRoom = Boolean(currentRoomId);
    const block = currentRoomBlock();
    const view = NyxoE2eePolicy.composerView({
        inRoom,
        plaintextOk: plaintextAllowedForChat(currentChatId, currentRoomId),
        e2ee: e2eeState,
        initError: e2eeInitError,
        block,
    });
    elements.membersKeysBtn.classList.toggle('hidden', !inRoom);
    elements.getChatCodeBtn.classList.toggle('hidden', !inRoom);

    const indicator = elements.e2eeIndicator;
    indicator.classList.toggle('hidden', !view.indicator.show);
    indicator.classList.toggle('is-on', view.indicator.ok);
    if (view.indicator.show) {
        setIconLabel(indicator, view.indicator.ok ? 'lock' : 'alert-triangle', view.indicator.text, { size: 'sm' });
        indicator.title = view.indicator.title;
        indicator.setAttribute('aria-label', view.indicator.title);
    }

    const status = elements.composerStatus;
    status.classList.toggle('is-problem', view.kind === 'unavailable' || view.kind === 'blocked' || view.kind === 'unknown');
    // Недоступность объявляется как alert (один раз при появлении), остальное — вежливо.
    status.setAttribute('role', view.kind === 'unavailable' ? 'alert' : 'status');
    elements.composerStatusIcon.replaceChildren(icon(view.icon, view.spin ? { size: 'sm', className: 'spin' } : { size: 'sm' }));
    elements.composerStatusText.textContent = view.text;
    elements.composerStatusRetry.classList.toggle('hidden', !view.retry);

    elements.messageInput.placeholder = view.placeholder;
    setComposerDisabled(view.disabled, view.text);
}

function refreshE2eeUi() {
    if (!currentChatId) return;
    updateComposerForChat();
}

// «Повторить»: заново подготовить ключи устройства (если они недоступны) и ключ
// открытой комнаты. silent — автоповтор: об отказе молчим, видно и так.
async function retryE2ee({ silent = false } = {}) {
    if (!currentUser) return;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    clearTimeout(e2eeRetryTimer);
    if (!silent) e2eeRetryStep = 0;
    const wasBlocked = Boolean(currentRoomBlock());
    const retryBtn = elements.composerStatusRetry;
    retryBtn.disabled = true;
    try {
        if (e2eeState === 'unavailable') {
            const ok = await initE2eeForCurrentUser();
            if (!ok) {
                if (!silent) showToast(`Сквозное шифрование по-прежнему недоступно: ${NyxoE2eePolicy.initErrorReason(e2eeInitError)}`, 'error');
                return;
            }
            showToast('Сквозное шифрование снова доступно', 'success');
        }
        roomBlock = null;
        if (chatId && roomId && chatId === currentChatId) {
            await syncE2eeKeyShares(chatId, roomId);
            const session = await ensureE2eeRoomSession(chatId, roomId);
            if (chatId !== currentChatId) return;
            const block = NyxoE2eePolicy.sessionBlock(session);
            if (block) {
                setRoomBlock(chatId, block.text);
                if (!silent) showToast(block.text, 'error', 6000);
            } else if (wasBlocked) {
                showToast('Ключ шифрования передан, можно отправлять', 'success');
            }
        }
    } finally {
        retryBtn.disabled = false;
        updateComposerForChat();
    }
}
