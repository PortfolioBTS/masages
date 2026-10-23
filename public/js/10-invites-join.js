// public/js/10-invites-join.js — приглашения, вступление по коду и заявки на вступление.
// Вынесено из public/script.js (строки 3602–4280 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Разделы «Приглашения», «Вступление по коду», «Заявки на вступление (у участников)».
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Приглашения ====================
// Код показывается группами по 5 символов (NyxoInvite.formatInviteCode) —
// его диктуют и переписывают вручную; сервер при вводе убирает пробелы и
// дефисы сам.

// Ссылка-приглашение: код во фрагменте — он не уходит на сервер ни при
// открытии ссылки, ни в Referer (см. consumeJoinFragment).
// С секретом (22 символа base64url, signed-membership.md, 5.3) ссылка впускает без одобрения; без него - только заявка.
function inviteLink(code, secret) {
    return `${location.origin}/#join=${encodeURIComponent(code)}${secret ? `.${secret}` : ''}`;
}

async function copyText(text, okMessage, failMessage) {
    try {
        await navigator.clipboard.writeText(text);
        showToast(okMessage, 'success');
    } catch {
        showToast(failMessage, 'error');
    }
}

// QR рисуется на <canvas> по модулям (qrcode-generator: getModuleCount/
// isDark) — без createSvgTag/createImgTag и innerHTML. Белый фон и чёрные
// модули в обеих темах: так его читает любой сканер. Тихая зона — 4
// модуля (минимум по стандарту), уровень коррекции M.
const QR_QUIET_ZONE = 4;
const QR_TARGET_PX = 240;

function drawInviteQr(text) {
    const canvas = elements.inviteQrCanvas;
    const ctx = canvas.getContext && canvas.getContext('2d');
    if (!ctx || typeof qrcode !== 'function' || !text) return false;
    let qr;
    try {
        qr = qrcode(0, 'M');
        qr.addData(text);
        qr.make();
    } catch (err) {
        console.warn('QR: не удалось построить код:', err);
        return false;
    }
    const count = qr.getModuleCount();
    const total = count + QR_QUIET_ZONE * 2;
    const dpr = Math.min(Math.max(window.devicePixelRatio || 1, 1), 3);
    const cell = Math.max(2, Math.floor((QR_TARGET_PX * dpr) / total));
    const size = total * cell;
    canvas.width = size;
    canvas.height = size;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';
    for (let row = 0; row < count; row++) {
        for (let col = 0; col < count; col++) {
            if (qr.isDark(row, col)) ctx.fillRect((col + QR_QUIET_ZONE) * cell, (row + QR_QUIET_ZONE) * cell, cell, cell);
        }
    }
    return true;
}

function clearInviteQr() {
    const canvas = elements.inviteQrCanvas;
    canvas.width = 0;
    canvas.height = 0;
}

let inviteState = null;   // последний ответ сервера по приглашению открытой комнаты

function inviteStatusLine(iconName, text) {
    return iconText('p', 'invite-status-line', iconName, text, { size: 'sm' });
}

function renderInvite(state) {
    inviteState = state;
    const rawCode = String(state.code || '').replace(/[\s-]+/g, '');
    const expiry = parseDate(state.expiresAt);
    const disabled = state.disabled === true || !rawCode;
    const expired = !disabled && (state.expired === true || Boolean(expiry && expiry.getTime() <= Date.now()));
    const usable = !disabled && !expired;

    elements.inviteCodeDisplay.textContent = disabled ? 'Приглашение выключено' : NyxoInvite.formatInviteCode(rawCode);
    elements.inviteCodeDisplay.dataset.code = usable ? rawCode : '';
    elements.inviteCodeContainer.classList.toggle('expired', !usable);
    elements.copyInviteBtn.disabled = !usable;
    elements.copyInviteLinkBtn.disabled = !usable;
    elements.disableInviteBtn.disabled = disabled;

    const linkSecret = usable && state.signed !== false ? (state.linkSecret || null) : null;
    elements.inviteCodeDisplay.dataset.secret = linkSecret || '';
    const shown = usable && drawInviteQr(inviteLink(rawCode, linkSecret));
    if (!shown) clearInviteQr();
    elements.inviteQr.classList.toggle('hidden', !shown);

    const lines = [];
    if (disabled) lines.push(inviteStatusLine('x', 'Приглашение выключено — создайте новый код, чтобы снова звать людей'));
    else if (expired) lines.push(inviteStatusLine('hourglass', 'Код истёк — создайте новый'));
    else if (expiry) lines.push(inviteStatusLine('clock', `Действует до ${formatShortDateTime(expiry)}`));
    const members = Number(state.memberCount);
    const max = Number(state.maxMembers);
    if (Number.isFinite(members) && members > 0) {
        lines.push(inviteStatusLine('users', max > 0 ? `Участников: ${members} из ${max}` : `Участников: ${members}`));
    }
    if (!disabled && state.requireApproval !== false) lines.push(inviteStatusLine('shield-check', 'Вступление — с одобрением участников'));
    else if (!disabled) {
        lines.push(inviteStatusLine('unlock', 'Ссылка с секретом впускает сразу; код без ссылки отправляет заявку'));
        if (state.inviter) lines.push(inviteStatusLine('shield-check', `Приглашение подписано участником ${state.inviter}`));
        else if (state.signed === false) lines.push(inviteStatusLine('alert-triangle', 'Подписанной ссылки нет: нажмите «Создать новый код», чтобы получить ссылку, которая впускает сразу'));
        else if (!linkSecret) lines.push(inviteStatusLine('alert-triangle', 'Секрет ссылки есть только на устройстве, где она создана: здесь ссылка и QR впускают лишь через заявку. Создайте новый код, чтобы получить свою ссылку'));
    }
    elements.inviteStatus.replaceChildren(...lines);
    elements.inviteStatus.classList.toggle('expired', !usable);

    // Настройки нового кода по умолчанию — как у текущего.
    elements.inviteApproval.checked = state.requireApproval !== false;
    elements.inviteMax.value = max > 0 ? String(max) : '';
}

async function openInviteModal() {
    if (!currentChatId || !currentRoomId) return;
    const chatId = currentChatId;
    const data = await api(`/api/chats/invite/${chatId}`);
    if (!data.success) {
        showToast(data.message, 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    elements.inviteTtl.value = '604800';
    const signing = await loadInviteSigning(chatId, currentRoomId);
    if (chatId !== currentChatId) return;
    renderInvite({ ...data, ...signing });
    openModal(elements.inviteModal);
}

// Подписанное приглашение комнаты (signed-membership.md, 9.3): кто его подписал (проверяется по подписям) и секрет ссылки, если он
// создан на этом устройстве и сертификат на сервере тот же. Сбой не мешает показать код.
async function loadInviteSigning(chatId, roomId) {
    const result = { linkSecret: null, inviter: null };
    try {
        const [part, client] = await Promise.all([api(`/api/chats/${chatId}/participants`), getReadyE2eeClient()]);
        if (!part.success) return result;
        rememberRoomParticipants(roomId, part.participants);
        if (client) result.linkSecret = await client.getInviteSecret(roomId, part.invite || null);
        if (part.invite) {
            const parsed = NyxoMembership.parseCert(NyxoMembership.fromB64(part.invite) || new Uint8Array(0));
            if (parsed.ok && parsed.cert.kind === NyxoMembership.KIND.invite && (await NyxoMembership.verifyCertSignatures(parsed.cert)).ok) {
                result.inviter = memberLabel(roomId, parsed.cert.actorId);
            }
        }
    } catch (err) {
        console.warn('E2EE: подпись приглашения не прочитана:', err);
    }
    return result;
}

// Лимит участников из поля: пусто — без лимита; иначе целое 2..1000.
function readInviteMaxMembers() {
    const raw = elements.inviteMax.value.trim();
    if (!raw) return { ok: true, value: null };
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 2 || n > 1000) return { ok: false };
    return { ok: true, value: n };
}

async function rotateInviteCode() {
    if (!currentChatId || elements.rotateInviteBtn.disabled) return;
    const max = readInviteMaxMembers();
    if (!max.ok) {
        showToast('Лимит участников — целое число от 2 до 1000 или пусто', 'error');
        elements.inviteMax.focus();
        return;
    }
    const hadCode = Boolean(inviteState && inviteState.code && !inviteState.disabled);
    if (hadCode && !confirm('Создать новый код? Старый код сразу перестанет действовать.')) return;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const body = {
        ttlSeconds: Number(elements.inviteTtl.value) || 604800,
        maxMembers: max.value,
        requireApproval: elements.inviteApproval.checked,
        proto: PROTO_VERSION,
    };
    elements.rotateInviteBtn.disabled = true;
    // Вход без одобрения - только по подписанному приглашению: сертификат и снимок подписывает клиент, секрет ссылки остаётся на устройстве.
    let signed = null;
    if (!body.requireApproval) {
        const client = await getReadyE2eeClient();
        if (!client) {
            elements.rotateInviteBtn.disabled = false;
            showToast('Шифрование недоступно: подписанную ссылку без одобрения создать нельзя', 'error');
            return;
        }
        try {
            signed = await client.signInvite(roomId, { ttlSeconds: body.ttlSeconds });
        } catch (err) {
            console.error('E2EE: signInvite failed:', err);
            elements.rotateInviteBtn.disabled = false;
            showToast('Не удалось подписать приглашение', 'error');
            return;
        }
        body.inviteCert = signed.cert;
        body.inviteSnap = signed.snap;
    }
    const data = await api(`/api/chats/${chatId}/invite/rotate`, { method: 'POST', body: JSON.stringify(body) });
    elements.rotateInviteBtn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось создать новый код', 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    if (!signed) {
        // Приглашение с одобрением подписанного сертификата не имеет: секрет прежней ссылки больше не нужен (9.3).
        const client = await getReadyE2eeClient();
        if (client) client.dropInviteSecret(roomId).catch(() => {});
    }
    const signing = signed ? await loadInviteSigning(chatId, roomId) : { linkSecret: null, inviter: null };
    renderInvite({
        ...(inviteState || {}),
        code: data.code,
        expiresAt: data.expiresAt,
        expired: false,
        disabled: false,
        maxMembers: data.maxMembers !== undefined ? data.maxMembers : body.maxMembers,
        requireApproval: data.requireApproval !== undefined ? data.requireApproval : body.requireApproval,
        signed: Boolean(signed),
        ...signing,
    });
    showToast(hadCode ? 'Создан новый код. Старый больше не действует' : 'Создан новый код', 'success', 5000);
}

async function disableInviteCode() {
    if (!currentChatId || elements.disableInviteBtn.disabled) return;
    if (!confirm('Отключить приглашение? Текущий код сразу перестанет действовать. Новый код можно создать в любой момент.')) return;
    const chatId = currentChatId;
    elements.disableInviteBtn.disabled = true;
    const data = await api(`/api/chats/${chatId}/invite/disable`, { method: 'POST', body: JSON.stringify({ proto: PROTO_VERSION }) });
    elements.disableInviteBtn.disabled = false;
    if (!data.success) {
        showToast(data.message || 'Не удалось отключить приглашение', 'error');
        return;
    }
    if (chatId !== currentChatId) return;
    renderInvite({ ...(inviteState || {}), code: null, expiresAt: null, disabled: true, expired: false, signed: false, linkSecret: null, inviter: null });
    // Секрет прежней ссылки больше не нужен: приглашение выключено (signed-membership.md, 9.3).
    const client = await getReadyE2eeClient();
    if (client && currentRoomId) client.dropInviteSecret(currentRoomId).catch(() => {});
    showToast('Приглашение отключено', 'success');
}

// ==================== Вступление по коду ====================

// Окно «Новый чат» работает в двух режимах: обычном (создать группу или
// вступить по коду) и приглашения — после входа по ссылке #join= или с
// экрана входа «У меня есть приглашение»: заголовок «Приглашение в группу»,
// блока «Создать группу» нет, вместо «Отмена» — «Не сейчас».
let joinPreviewCode = null;
let joinPreviewSecret = null;  // секрет ссылки (signed-membership.md, 5.3): хранится в памяти, на сервер не уходит
let joinPreviewRoomId = null;       // комната и сертификат приглашения из предпросмотра: вход по ссылке подписывается ими
let joinPreviewInviteCert = null;
let joinPreviewDirect = false;      // true - вход без одобрения по ссылке с секретом, false - заявка
let joinInviteMode = false;
let joinBusy = false;

const JOIN_INVALID_TEXT = 'Код недействителен: он истёк, выключен или введён с ошибкой. Попросите новый.';
const JOIN_KEYS_STATUS = 'Готовим ключи шифрования…';
const JOIN_KEYS_WAIT_MS = 15000;

function openNewChatModal({ invite = false } = {}) {
    joinInviteMode = Boolean(invite);
    hideJoinPreview();
    clearJoinError();
    elements.newChatTitle.textContent = joinInviteMode ? 'Приглашение в группу' : 'Новый чат';
    elements.newChatCreate.classList.toggle('hidden', joinInviteMode);
    elements.joinCancelBtn.textContent = joinInviteMode ? 'Не сейчас' : 'Отмена';
    openModal(elements.newChatModal);
    loadMyRequests();
}

function hideJoinPreview() {
    joinPreviewCode = null;
    joinPreviewRoomId = null;
    joinPreviewInviteCert = null;
    joinPreviewDirect = false;
    elements.joinPreview.classList.add('hidden');
    setJoinStatus('');
}

function onJoinCancel() {
    hideJoinPreview();
    if (joinInviteMode) closeModal(elements.newChatModal);
}

function showJoinError(text) {
    elements.joinError.textContent = text;
    elements.joinError.classList.remove('hidden');
    elements.joinChatCode.setAttribute('aria-invalid', 'true');
}

function clearJoinError() {
    elements.joinError.textContent = '';
    elements.joinError.classList.add('hidden');
    elements.joinChatCode.removeAttribute('aria-invalid');
}

// Ход вступления («Готовим ключи шифрования…») — role="status".
function setJoinStatus(text) {
    elements.joinStatus.textContent = text;
    elements.joinStatus.classList.toggle('hidden', !text);
}

// Ответ сервера → текст под полем. «Код недействителен» сервер пишет
// коротко, подробность — на клиенте.
function joinFailureText(data, fallback) {
    if (data && data.networkError) return 'Нет связи с сервером. Попробуйте ещё раз.';
    if (data && data.timedOut) return 'Сервер не отвечает. Попробуйте ещё раз.';
    const message = data && typeof data.message === 'string' ? data.message : '';
    if (/^Код недействителен/.test(message)) return JOIN_INVALID_TEXT;
    return message || fallback;
}

// Шаг 1: предпросмотр — название, число участников, нужно ли одобрение.
// Формат кода проверяется до запроса: в поле можно вставить и всю ссылку.
async function previewJoin() {
    const parsed = NyxoInvite.parseInviteInput(elements.joinChatCode.value);
    if (!parsed.ok) {
        hideJoinPreview();
        showJoinError(parsed.reason === 'empty' ? INVITE_EMPTY_ERROR : INVITE_FORMAT_ERROR);
        elements.joinChatCode.focus();
        return;
    }
    const code = parsed.code;
    const btn = elements.joinChatBtn;
    if (btn.disabled) return;
    clearJoinError();
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    const label = Array.from(btn.childNodes);
    setIconLabel(btn, 'loader', 'Проверяем…', { className: 'spin' });
    const data = await api('/api/chats/join/preview', { method: 'POST', body: JSON.stringify({ code }) });
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.replaceChildren(...label);
    if (!currentUser) return;
    if (!data.success) {
        hideJoinPreview();
        showJoinError(joinFailureText(data, 'Не удалось проверить код. Попробуйте ещё раз.'));
        elements.joinChatCode.focus();
        return;
    }
    joinPreviewCode = code;
    joinPreviewSecret = parsed.secret || null;
    joinPreviewRoomId = Number(data.roomId) || null;
    joinPreviewInviteCert = typeof data.inviteCert === 'string' ? data.inviteCert : null;
    // Без одобрения впускает только ссылка с секретом к подписанному приглашению; код без секрета - заявка (5.4).
    joinPreviewDirect = !data.requireApproval && Boolean(joinPreviewSecret && joinPreviewInviteCert && joinPreviewRoomId);
    elements.joinPreviewName.textContent = data.roomName || 'Группа';
    const count = Number(data.memberCount) || 0;
    elements.joinPreviewMeta.textContent = count > 0 ? `${count} ${plural(count, ['участник', 'участника', 'участников'])}` : '';
    elements.joinPreviewApproval.classList.toggle('hidden', joinPreviewDirect);
    setIconLabel(elements.joinConfirmBtn, joinPreviewDirect ? 'log-in' : 'send', joinPreviewDirect ? 'Вступить' : 'Отправить заявку');
    if (!data.requireApproval && !joinPreviewDirect) {
        setJoinStatus('Ссылка с секретом впускает сразу; код без ссылки отправляет заявку');
    }
    elements.joinPreview.classList.remove('hidden');
    elements.joinConfirmBtn.focus({ preventScroll: true });
}

// Перед вступлением без одобрения ключи устройства должны быть на сервере:
// иначе участники получат roomMembersChanged, пока identity новичка ещё
// не опубликована, запишут «у собеседника не настроен E2EE» и не отправят
// ему Sender Key. Ждём не дольше JOIN_KEYS_WAIT_MS: недоступное шифрование
// (e2eeInitPromise → false) вступление не блокирует: ключи устройства
// догонятся при повторе, а сообщения в группы до тех пор не отправляются.
async function waitForE2eeKeysBeforeJoin() {
    if (e2eeState !== 'pending' || !e2eeInitPromise) return;
    setJoinStatus(JOIN_KEYS_STATUS);
    await withTimeout(e2eeInitPromise, JOIN_KEYS_WAIT_MS, false);
    setJoinStatus('');
}

// Тексты ошибок проверки приглашения на устройстве (prepareJoin).
function joinPrepareFailureText(err) {
    switch (err && err.code) {
        case 'invalid-secret': return 'Ссылка повреждена: секрет не распознан. Попросите новую ссылку';
        case 'no-invite': return 'В этой группе нет приглашения по ссылке. Отправьте заявку';
        case 'secret-mismatch': return 'Секрет ссылки не подходит к приглашению. Попросите новую ссылку';
        case 'invalid-invite': return 'Приглашение повреждено или подписано неверно. Попросите новую ссылку';
        case 'expired': return 'Срок приглашения истёк. Попросите новую ссылку';
        case 'clock': return 'Часы на устройстве отстают: приглашение выдано «в будущем». Поправьте время и повторите';
        default: return 'Не удалось проверить приглашение. Попробуйте ещё раз';
    }
}

// Шаг 2: вступление (или заявка, если группе нужно одобрение).
async function joinChat() {
    const code = joinPreviewCode;
    if (!code || joinBusy) return;
    joinBusy = true;
    const btn = elements.joinConfirmBtn;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    clearJoinError();
    let data;
    const roomId = joinPreviewRoomId;
    let intentWritten = false;
    try {
        await waitForE2eeKeysBeforeJoin();
        const client = await getReadyE2eeClient();
        const body = { code, proto: PROTO_VERSION };
        if (client && roomId) {
            // Намерение входа создаёт только это действие пользователя (signed-membership.md, 9.2): по ссылке - после
            // проверки приглашения секретом, по заявке - при нажатии «Отправить заявку».
            try {
                const prepared = await client.prepareJoin(roomId, joinPreviewDirect
                    ? { secret: joinPreviewSecret, inviteCert: joinPreviewInviteCert }
                    : {});
                intentWritten = true;
                if (prepared.joinCert) body.joinCert = prepared.joinCert;
            } catch (err) {
                data = { success: false, message: joinPrepareFailureText(err) };
            }
        }
        if (!data) {
            data = await api('/api/chats/join', { method: 'POST', body: JSON.stringify(body) });
            if (data.success && data.inviteSnap && client && roomId) {
                const done = await client.completeJoin(roomId, data.inviteSnap).catch(() => ({ ok: false }));
                if (!done.ok) showToast('Приглашение повреждено: состав группы по нему не подтвердится', 'error', 8000);
            }
            if (!data.success && intentWritten && client) client.cancelJoinIntent(roomId).catch(() => {});
        }
    } finally {
        joinBusy = false;
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        setJoinStatus('');
    }
    if (!currentUser) return;
    if (!data.success) {
        showJoinError(joinFailureText(data, 'Не удалось вступить. Попробуйте ещё раз.'));
        return;
    }
    elements.joinChatCode.value = '';
    joinPreviewSecret = null;
    hideJoinPreview();
    if (data.pending) {
        if (data.requestId != null && data.roomName) myRequestNames.set(String(data.requestId), data.roomName);
        showToast('Запрос отправлен, ожидает одобрения', 'success', 5000);
        loadMyRequests(data.requestId);
        return;
    }
    showToast('Вы присоединились к чату', 'success');
    closeModal(elements.newChatModal);
    loadChats();
    openChat(data.chat.id, data.chat.room_id, data.chat.name, data.chat.avatar, 0, 0);
}

// Свои заявки — карточки «ожидает одобрения» с кнопкой «Отменить».
// Названия групп запоминаем: в joinRequestDecided есть только requestId.
const myRequestNames = new Map();   // requestId -> roomName
let myRequestsSeq = 0;
async function loadMyRequests(highlightId) {
    const seq = ++myRequestsSeq;
    const data = await api('/api/join-requests/mine');
    if (seq !== myRequestsSeq) return;
    const list = data.success && Array.isArray(data.requests) ? data.requests : [];
    list.forEach((req) => { if (req.roomName) myRequestNames.set(String(req.id), req.roomName); });
    elements.myRequests.classList.toggle('hidden', list.length === 0);
    elements.myRequestsList.replaceChildren(...list.map(req => createPendingCard(req, Number(req.id) === Number(highlightId))));
}

function createPendingCard(req, fresh) {
    const card = document.createElement('div');
    card.className = 'pending-card' + (fresh ? ' is-active' : '');
    const body = document.createElement('div');
    const title = document.createElement('h4');
    title.textContent = req.roomName || 'Группа';
    const status = document.createElement('p');
    status.className = 'muted';
    const when = formatRelativeTime(req.createdAt);
    status.textContent = `Запрос отправлен, ожидает одобрения${when ? ' · ' + when : ''}`;
    body.append(title, status);
    const cancel = document.createElement('button');
    cancel.className = 'btn btn-ghost btn-sm';
    cancel.type = 'button';
    setIconLabel(cancel, 'x', 'Отменить');
    cancel.addEventListener('click', () => cancelMyRequest(req.id, cancel));
    // Аккаунт «Пока открыта вкладка» удалится через 30 минут после закрытия
    // вкладки — вместе с заявкой, а одобрения можно ждать долго.
    const warning = currentUser ? NyxoLifetime.inviteTabWarning(currentUser.anonLifetime, true) : '';
    if (!warning) {
        card.append(icon('hourglass'), body, cancel);
        return card;
    }
    const hint = document.createElement('p');
    hint.className = 'field-hint';
    hint.textContent = warning;
    body.append(hint);
    const keep = document.createElement('button');
    keep.className = 'btn btn-secondary btn-sm';
    keep.type = 'button';
    keep.textContent = 'Хранить 1 день';
    keep.addEventListener('click', async () => {
        keep.disabled = true;
        const ok = await changeLifetime('day');
        if (!ok && keep.isConnected) keep.disabled = false;
    });
    const actions = document.createElement('div');
    actions.className = 'invite-actions';
    actions.append(keep, cancel);
    card.append(icon('hourglass'), body, actions);
    return card;
}

async function cancelMyRequest(requestId, btn) {
    btn.disabled = true;
    const data = await api(`/api/join-requests/${encodeURIComponent(requestId)}`, { method: 'DELETE' });
    if (!data.success) {
        btn.disabled = false;
        showToast(data.message || 'Не удалось отменить заявку', 'error');
        return;
    }
    showToast('Заявка отменена', 'success');
    loadMyRequests();
}

// ==================== Заявки на вступление (у участников) ====================

let joinRequestsSeq = 0;

function renderRequestsBar(count) {
    const n = Number(count) || 0;
    elements.requestsBar.classList.toggle('hidden', n === 0);
    elements.requestsBarText.textContent = n > 0 ? `Заявки на вступление: ${n}` : '';
}

async function fetchJoinRequests() {
    if (!currentChatId || !currentRoomId) return null;
    const chatId = currentChatId;
    const seq = ++joinRequestsSeq;
    const data = await api(`/api/chats/${chatId}/join-requests`);
    if (seq !== joinRequestsSeq || chatId !== currentChatId) return null;
    return data.success && Array.isArray(data.requests) ? data.requests : [];
}

async function loadJoinRequestsCount() {
    const list = await fetchJoinRequests();
    if (list) renderRequestsBar(list.length);
}

function openRequestsModal() {
    setRequestsPlaceholder('Загрузка…');
    openModal(elements.requestsModal);
    loadRequestsList();
}

function setRequestsPlaceholder(text) {
    const li = document.createElement('li');
    li.className = 'request-row muted';
    li.textContent = text;
    elements.requestsList.replaceChildren(li);
}

async function loadRequestsList() {
    const list = await fetchJoinRequests();
    if (!list) return;
    renderRequestsBar(list.length);
    if (list.length === 0) {
        setRequestsPlaceholder('Новых заявок нет');
        return;
    }
    elements.requestsList.replaceChildren(...list.map(createRequestRow));
}

function createRequestRow(req) {
    const li = document.createElement('li');
    li.className = 'request-row';
    const avatar = document.createElement('div');
    avatar.className = 'member-avatar';
    avatar.setAttribute('aria-hidden', 'true');
    renderAvatar(avatar, req.username, false);
    const info = document.createElement('div');
    info.className = 'member-info';
    const name = document.createElement('div');
    name.className = 'member-name';
    name.textContent = req.username || `участник #${req.userId}`;
    const when = document.createElement('small');
    when.className = 'muted';
    when.textContent = formatRelativeTime(req.createdAt);
    info.append(name, when);
    const actions = document.createElement('div');
    actions.className = 'member-actions';
    const approve = document.createElement('button');
    approve.className = 'btn btn-primary btn-sm';
    approve.type = 'button';
    setIconLabel(approve, 'check', 'Впустить');
    approve.setAttribute('aria-label', `Впустить ${name.textContent}`);
    const deny = document.createElement('button');
    deny.className = 'btn btn-secondary btn-sm';
    deny.type = 'button';
    setIconLabel(deny, 'x', 'Отклонить');
    deny.setAttribute('aria-label', `Отклонить заявку ${name.textContent}`);
    approve.addEventListener('click', () => decideJoinRequest(req, true, li, [approve, deny]));
    deny.addEventListener('click', () => decideJoinRequest(req, false, li, [approve, deny]));
    actions.append(approve, deny);
    li.append(avatar, info, actions);
    showApplicantKeyCheck(req, info);
    return li;
}

// Одобряющий поручается за ключ заявителя до вступления: ключ проверяется по журналу (ревью К12).
async function showApplicantKeyCheck(req, info) {
    if (!req || !req.identity || !req.identity.kt) return;
    const client = await getReadyE2eeClient();
    if (!client || typeof client.checkApplicantKey !== 'function') return;
    let result;
    try {
        result = await client.checkApplicantKey(req.userId, req.identity);
    } catch (err) {
        console.warn('E2EE: проверка ключа заявителя по журналу не удалась:', err);
        return;
    }
    const texts = {
        ok: 'ключ проверен по журналу',
        pending: KT_PEER_TEXT.pending,
        mismatch: 'Ключа заявителя нет в журнале ключей. Возможна подмена, сверьте код безопасности лично',
    };
    const text = result && texts[result.status];
    if (!text || !info.isConnected) return;
    const line = document.createElement('small');
    line.className = result.status === 'mismatch' ? 'member-kt' : 'member-kt';
    line.textContent = text;
    info.appendChild(line);
}

async function decideJoinRequest(req, approve, row, buttons) {
    buttons.forEach((b) => { b.disabled = true; });
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const body = { proto: PROTO_VERSION };
    if (approve) {
        // Одобрение подписывается (signed-membership.md, 5.2): сертификат допуска и снимок состава одобряющего.
        const client = await getReadyE2eeClient();
        if (!client || !req.identity) {
            buttons.forEach((b) => { b.disabled = false; });
            showToast(client ? 'Пользователь ещё не настроил шифрование: одобрить его пока нельзя' : 'Шифрование недоступно: одобрить заявку нельзя', 'error');
            return;
        }
        const approveBtn = buttons[0];
        const label = Array.from(approveBtn.childNodes);
        setIconLabel(approveBtn, 'loader', 'Подписываем…', { className: 'spin' });
        try {
            const signed = await client.signApproval(roomId, { userId: req.userId, signingKey: req.identity.signingKey, dhKey: req.identity.dhKey });
            body.cert = signed.cert;
            body.snap = signed.snap;
        } catch (err) {
            console.error('E2EE: signApproval failed:', err);
            approveBtn.replaceChildren(...label);
            buttons.forEach((b) => { b.disabled = false; });
            showToast('Не удалось подписать допуск', 'error');
            return;
        }
        approveBtn.replaceChildren(...label);
    }
    const data = await api(`/api/join-requests/${encodeURIComponent(req.id)}/${approve ? 'approve' : 'deny'}`, { method: 'POST', body: JSON.stringify(body) });
    if (!data.success) {
        buttons.forEach((b) => { b.disabled = false; });
        showToast(data.message || 'Не удалось обработать заявку', 'error');
        return;
    }
    row.remove();
    if (!elements.requestsList.querySelector('.request-row:not(.muted)')) setRequestsPlaceholder('Новых заявок нет');
    showToast(approve
        ? `${req.username || 'Участник'} в группе. Ключ шифрования будет передан автоматически`
        : 'Заявка отклонена', 'success', 5000);
    loadJoinRequestsCount();
    // Ключ новичку разошлёт тот же поток, что и при вступлении без
    // одобрения: сервер шлёт roomMembersChanged → syncKeyShares →
    // ensureRoomSession (newMembers → key-share). Запускаем его и сами —
    // на случай, если событие сокета потерялось; повтор склеит debounce.
    if (approve && chatId === currentChatId && roomId) scheduleRoomMembersRefresh(roomId);
}
