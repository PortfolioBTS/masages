// public/js/11-key-log-members.js — участники и ключи, журнал ключей (прозрачность).
// Вынесено из public/script.js (строки 4281–4833 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Разделы «Участники и ключи» и «Журнал ключей»: баннер расхождений журнала, окно участников, проверка номеров безопасности.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Участники и ключи ====================

// ==================== Журнал ключей ====================
//
// Прозрачность ключей (docs/security/key-transparency.md, 10): тревоги клиента попадают в баннер боковой
// панели, подробности и действия — в окне «Журнал ключей». Статусы участников — в окне «Участники и ключи».

const KT_BANNER_TEXT = {
    'self-foreign-entry': 'Сервер опубликовал для вашего аккаунта ключ, которого нет на этом устройстве.',
    'self-missing': 'Сервер не выполнил обещание включить ваш ключ в журнал ключей.',
    'key-split': 'Подпись журнала у вас и у собеседника не сходится. Возможна подмена журнала — сверьте коды безопасности лично.',
    'log-disabled': 'Журнал ключей на сервере перестал отвечать или отключён, хотя раньше работал. Новые и изменившиеся ключи собеседников не считаются проверенными — сверяйте коды безопасности.',
    inconsistent: 'Журнал ключей на сервере не прошёл проверку. Шифрование может быть небезопасным — сверяйте коды безопасности.',
};
// Какая тревога главная для баннера: сначала про мой аккаунт, потом про журнал.
const KT_BANNER_ORDER = ['self-foreign-entry', 'self-missing', 'key-split', 'log-disabled'];
const KT_INCONSISTENT_KINDS = ['log-fork', 'equivocation', 'bad-signature', 'key-changed'];

let ktAlertsSeq = 0;

function currentE2eeClientIfReady() {
    return currentUser && e2eeClient && e2eeClientUserId === currentUser.id ? e2eeClient : null;
}

async function readTransparencyAlerts() {
    const client = currentE2eeClientIfReady();
    if (!client || typeof client.getTransparencyAlerts !== 'function') return [];
    try {
        return await client.getTransparencyAlerts();
    } catch (err) {
        console.warn('E2EE: не удалось прочитать тревоги журнала ключей:', err);
        return [];
    }
}

async function refreshTransparencyBanner() {
    const seq = ++ktAlertsSeq;
    const alerts = await readTransparencyAlerts();
    if (seq !== ktAlertsSeq) return;
    let kind = KT_BANNER_ORDER.find(k => alerts.some(a => a.kind === k)) || null;
    if (!kind && alerts.some(a => KT_INCONSISTENT_KINDS.includes(a.kind))) kind = 'inconsistent';
    if (!kind) {
        elements.ktBanner.classList.add('hidden');
        elements.ktBannerText.textContent = '';
        return;
    }
    elements.ktBannerText.textContent = KT_BANNER_TEXT[kind];
    elements.ktBanner.classList.remove('hidden');
}

// Час эпохи (число часов от 1970-го) → «2026-10-11 14:00 UTC».
function ktEpochText(epoch) {
    if (!Number.isFinite(epoch)) return 'время неизвестно';
    return new Date(epoch * 3600 * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

const KT_FORK_TEXT = {
    rollback: 'Сервер показал более раннюю версию журнала, чем уже видело это устройство.',
    'chain-mismatch': 'История журнала переписана: новая цепочка не продолжает ту, что видело это устройство.',
    'genesis-changed': 'Начало поколения журнала изменилось.',
    'generation-length': 'Сервер нарушил длину поколения журнала.',
    'grace-violated': 'Сервер удалил прежнее поколение журнала раньше срока.',
    'prev-final-head': 'Новое поколение журнала не продолжает прежнее.',
    'self-proof': 'Сервер прислал для вашей метки доказательство, которое не сходится с журналом.',
};

// Описание тревоги для окна: заголовок, пояснения и действия (кнопки).
function ktAlertView(alert, pendingKey, client) {
    const lines = [];
    const actions = [];
    let title = KT_BANNER_TEXT[alert.kind] || 'Журнал ключей не прошёл проверку.';
    if (alert.kind === 'self-foreign-entry') {
        (alert.entries || []).forEach((entry) => lines.push(`Запись в журнале от ${ktEpochText(entry.epoch)}.`));
        if (Number.isFinite(alert.identityCreatedHour)) {
            lines.push(`Ключи этого устройства созданы ${ktEpochText(alert.identityCreatedHour)} (с точностью до часа).`);
        }
        lines.push('Записи старше создания ключей на этом устройстве — вероятно, прежние ключи вашего аккаунта (например, после очистки данных сайта без выхода). Записи новее подозрительны: сверьте коды безопасности с собеседниками лично.');
        actions.push({
            text: 'Это были мои прежние ключи',
            run: async () => { await client.ackSelfEntries(alert.entries || []); },
        });
    } else if (alert.kind === 'self-missing') {
        title = alert.reason === 'carry-over'
            ? 'Сервер не перенёс ваш ключ в новое поколение журнала.'
            : KT_BANNER_TEXT['self-missing'];
        lines.push(`Поколение ${alert.gen}, ${ktEpochText(alert.epoch)}. Подписанное обещание сервера сохранено на этом устройстве как доказательство.`);
    } else if (alert.kind === 'log-fork') {
        title = KT_FORK_TEXT[alert.reason] || 'Журнал ключей показывает несогласованную историю.';
        lines.push('Это доказательство того, что сервер ведёт журнал нечестно (или его базу восстановили без смены ключа журнала).');
    } else if (alert.kind === 'equivocation') {
        title = alert.reason === 'keychange'
            ? 'Сервер выдал два разных заявления о смене ключа журнала.'
            : 'Вы и собеседник видите разные подписанные версии журнала для одной эпохи.';
        lines.push('Подписанные версии сохранены на этом устройстве как доказательство.');
    } else if (alert.kind === 'bad-signature') {
        title = alert.reason === 'own-skt'
            ? 'Обещание сервера включить ваш ключ в журнал имеет неверную подпись.'
            : 'Подпись журнала ключей не проходит проверку.';
    } else if (alert.kind === 'key-changed') {
        title = 'Ключ подписи журнала изменился без заявления о смене.';
        lines.push('Принимайте новый ключ только после сверки отпечатка с опубликованным релизом.');
        if (pendingKey) {
            lines.push({ fingerprint: pendingKey.hex.match(/.{1,8}/g).join(' ') });
            actions.push({
                text: 'Принять новый ключ журнала',
                confirm: 'Отпечаток совпадает с опубликованным в релизе? Принятие сбросит сохранённые цепочки журнала на этом устройстве.',
                run: async () => {
                    // false — ключ не прошёл проверку (малый порядок и т.п.): принять его нельзя.
                    if (!(await client.acceptLogKey())) throw new Error('ключ журнала не принят');
                },
            });
        }
    }
    return { title, lines, actions };
}

async function openTransparencyModal() {
    const client = currentE2eeClientIfReady();
    if (!client) return;
    const alerts = await readTransparencyAlerts();
    let pendingKey = null;
    try { pendingKey = await client.getPendingLogKey(); } catch { pendingKey = null; }
    const items = alerts.map((alert) => {
        const view = ktAlertView(alert, pendingKey, client);
        const li = document.createElement('li');
        li.className = 'kt-alert';
        const title = document.createElement('div');
        title.className = 'kt-alert-title';
        title.textContent = view.title;
        li.appendChild(title);
        view.lines.forEach((line) => {
            const p = document.createElement('p');
            if (typeof line === 'object') {
                p.className = 'kt-fingerprint';
                p.textContent = line.fingerprint;
            } else {
                p.textContent = line;
            }
            li.appendChild(p);
        });
        if (view.actions.length > 0) {
            const row = document.createElement('div');
            row.className = 'member-actions';
            view.actions.forEach((action) => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-secondary btn-sm';
                btn.textContent = action.text;
                btn.addEventListener('click', async () => {
                    if (action.confirm && !confirm(action.confirm)) return;
                    btn.disabled = true;
                    try {
                        await action.run();
                    } catch (err) {
                        console.error('E2EE: действие над тревогой журнала не удалось:', err);
                        showToast('Не удалось выполнить действие', 'error');
                        btn.disabled = false;
                        return;
                    }
                    await refreshTransparencyBanner();
                    openTransparencyModal();
                });
                row.appendChild(btn);
            });
            li.appendChild(row);
        }
        return li;
    });
    if (items.length === 0) {
        const li = document.createElement('li');
        li.className = 'members-placeholder';
        li.textContent = 'Тревог нет.';
        items.push(li);
    }
    elements.ktAlertList.replaceChildren(...items);
    if (elements.ktModal.classList.contains('hidden')) openModal(elements.ktModal);
}

const IDENTITY_STATUS = {
    verified: { text: 'проверен', cls: 'verified', icon: 'shield-check' },
    unverified: { text: 'не проверен', cls: 'unverified', icon: 'shield' },
    changed: { text: 'ключ изменился', cls: 'changed', icon: 'alert-triangle' },
    // Ключа нет в журнале ключей: класс как у changed (раздел 10 key-transparency.md).
    'log-mismatch': { text: 'нет в журнале ключей', cls: 'changed', icon: 'alert-triangle' },
    unknown: { text: 'нет E2EE', cls: 'unknown', icon: 'unlock' },
};

// Журнал ключей рядом со статусом участника: неброская строка (pending, unavailable) и отметка ok.
const KT_PEER_TEXT = {
    ok: 'ключ проверен по журналу',
    pending: 'Ключ ждёт подтверждения журналом',
    unavailable: 'Проверка журнала ключей сейчас недоступна',
};

let membersModalSeq = 0;

function setMembersPlaceholder(text) {
    const li = document.createElement('li');
    li.className = 'members-placeholder';
    li.textContent = text;
    elements.membersList.replaceChildren(li);
}

function setMemberStatus(row, status) {
    const info = IDENTITY_STATUS[status] || IDENTITY_STATUS.unknown;
    row._status = status;
    setIconLabel(row._statusEl, info.icon, info.text, { size: 'sm' });
    row._statusEl.className = `member-status ${info.cls}`;
}

function renderSafetyNumber(container, safetyNumber) {
    if (!safetyNumber) {
        container.textContent = 'Код недоступен: у участника нет ключей шифрования';
        container.classList.add('unavailable');
        return;
    }
    container.classList.remove('unavailable');
    const groups = String(safetyNumber).trim().split(/\s+/);
    container.replaceChildren(...groups.map((group) => {
        const span = document.createElement('span');
        span.textContent = group;
        return span;
    }));
}

async function renderMemberDetails(row, peer, ctx) {
    const { details } = row;
    const status = row._status;
    details.replaceChildren();

    if (status === 'log-mismatch') {
        details.appendChild(iconText('p', 'member-warning', 'alert-triangle', `Сервер показывает для ${peer.username} ключ, которого нет в журнале ключей (или журнал у участников разный). Возможна подмена. Сверьте код безопасности лично. Ключ комнаты этому участнику не отправляется, пока вы не сверите код или не продолжите явно.`));
    }
    if (status === 'changed') {
        details.appendChild(iconText('p', 'member-warning', 'alert-triangle', 'Ключ шифрования этого участника изменился. Так бывает после переустановки браузера или входа с нового устройства — но так же выглядит и подмена ключа сервером. Сверьте код безопасности с участником лично, прежде чем принимать новый ключ.'));
    }

    const code = document.createElement('div');
    code.className = 'safety-number';
    code.setAttribute('aria-label', `Код безопасности с ${peer.username}`);
    code.textContent = 'Загрузка кода…';
    const hint = document.createElement('p');
    hint.className = 'safety-hint';
    hint.textContent = `${peer.username} видит у себя такой же код для вас. Сравните все 12 групп цифр.`;
    const actions = document.createElement('div');
    actions.className = 'member-actions';
    details.append(code, hint, actions);

    if (status === 'changed') {
        const accept = document.createElement('button');
        accept.className = 'btn btn-danger btn-sm';
        setIconLabel(accept, 'key', 'Принять новый ключ');
        accept.addEventListener('click', () => acceptIdentityChange(row, peer, ctx, accept));
        actions.appendChild(accept);
    } else if (status === 'unverified' || status === 'log-mismatch') {
        const mark = document.createElement('button');
        mark.className = 'btn btn-primary btn-sm';
        setIconLabel(mark, 'shield-check', 'Отметить как проверенный');
        mark.addEventListener('click', () => markVerified(row, peer, ctx, mark));
        actions.appendChild(mark);
        if (status === 'log-mismatch') {
            const proceed = document.createElement('button');
            proceed.className = 'btn btn-danger btn-sm';
            setIconLabel(proceed, 'key', 'Продолжить без проверки');
            proceed.addEventListener('click', () => overrideLogMismatch(row, peer, ctx, proceed));
            actions.appendChild(proceed);
        }
    } else if (status === 'verified') {
        actions.appendChild(iconText('p', 'safety-hint', 'check', 'Вы уже сверили этот код.', { size: 'sm' }));
    }

    try {
        renderSafetyNumber(code, await ctx.client.getSafetyNumber(peer.id));
    } catch (err) {
        console.warn('E2EE: getSafetyNumber failed:', err);
        renderSafetyNumber(code, null);
    }
}

async function markVerified(row, peer, ctx, btn) {
    btn.disabled = true;
    try {
        await ctx.client.markPeerVerified(peer.id);
    } catch (err) {
        console.error('E2EE: markPeerVerified failed:', err);
        btn.disabled = false;
        showToast('Не удалось сохранить отметку', 'error');
        return;
    }
    setMemberStatus(row, (await peerIdentityStatus(ctx.client, peer.id)) || 'verified');
    showToast(`${peer.username}: ключ отмечен как проверенный`, 'success');
    renderMemberDetails(row, peer, ctx);
}

// Пользователь явно продолжает общение с участником, чьего ключа нет в журнале: он снова адресат рассылки.
async function overrideLogMismatch(row, peer, ctx, btn) {
    if (!confirm(`Продолжить обмен ключами с ${peer.username} без проверки по журналу? Делайте это, только если уверены, что его ключ настоящий (код безопасности сверен лично).`)) return;
    btn.disabled = true;
    try {
        await ctx.client.overrideLogMismatch(peer.id);
    } catch (err) {
        console.error('E2EE: overrideLogMismatch failed:', err);
        btn.disabled = false;
        showToast('Не удалось продолжить', 'error');
        return;
    }
    setMemberStatus(row, (await peerIdentityStatus(ctx.client, peer.id)) || 'unverified');
    if (Number(ctx.roomId) === Number(currentRoomId)) {
        pendingLogMismatches.delete(Number(peer.id));
        renderIdentityBanner();
        ensureE2eeRoomSession(ctx.chatId, ctx.roomId);
    }
    renderMemberDetails(row, peer, ctx);
}

async function acceptIdentityChange(row, peer, ctx, btn) {
    if (!confirm(`Принять новый ключ участника ${peer.username}? Делайте это, только если код безопасности совпал с кодом на его устройстве.`)) return;
    btn.disabled = true;
    try {
        await ctx.client.acceptPeerIdentityChange(peer.id);
    } catch (err) {
        console.error('E2EE: acceptPeerIdentityChange failed:', err);
        btn.disabled = false;
        showToast('Не удалось принять новый ключ', 'error');
        return;
    }
    setMemberStatus(row, (await peerIdentityStatus(ctx.client, peer.id)) || 'unverified');
    if (Number(ctx.roomId) === Number(currentRoomId)) {
        pendingIdentityChanges.delete(Number(peer.id));
        renderIdentityBanner();
        // Ключ комнаты этому участнику до сих пор не отправлялся — досылаем.
        ensureE2eeRoomSession(ctx.chatId, ctx.roomId);
    }
    showToast(`Новый ключ ${peer.username} принят`, 'success');
    renderMemberDetails(row, peer, ctx);
}

// Подтверждение участника вручную (signed-membership.md, 9.7): локальное решение, сертификата не публикует.
async function trustUnconfirmedMember(peer, ctx, btn, duplicate) {
    const warning = `Сервер добавил ${peer.username} в группу, но никто из участников это не подписал. Доверяйте, только если знаете, кто это.`
        + (duplicate ? ' У этого участника такие же ключи шифрования, как у другого: возможно, это подделка.' : '');
    if (!confirm(warning)) return;
    btn.disabled = true;
    let res;
    try {
        res = await ctx.client.trustMember(ctx.roomId, peer.id);
    } catch (err) {
        console.error('E2EE: trustMember failed:', err);
        res = { ok: false };
    }
    if (!res || !res.ok) {
        btn.disabled = false;
        showToast(res && res.reason === 'changed' ? 'Ключ участника изменился: сначала проверьте код безопасности' : 'Не удалось подтвердить участника', 'error');
        return;
    }
    showToast(`${peer.username} подтверждён. Ключ шифрования будет передан автоматически`, 'success', 5000);
    if (res.cancelledIntent) showToast('Проверка по приглашению отменена: вы подтвердили участников вручную', 'info', 6000);
    if (Number(ctx.roomId) === Number(currentRoomId)) {
        pendingUnconfirmed.delete(Number(peer.id));
        renderIdentityBanner();
        ensureE2eeRoomSession(ctx.chatId, ctx.roomId);
    }
    openMembersModal();
}

// Явное поручительство (9.5): подписать допуск за участника, подтверждённого вручную. Остальные начнут отправлять ему ключи.
async function vouchForMember(peer, ctx, btn) {
    if (!confirm(`Вы подпишете, что знаете ${peer.username}. Остальные участники начнут отправлять ему ключи.`)) return;
    btn.disabled = true;
    let res;
    try {
        res = await ctx.client.vouchForMember(ctx.chatId, ctx.roomId, peer.id);
    } catch (err) {
        console.error('E2EE: vouchForMember failed:', err);
        res = { ok: false };
    }
    if (!res || !res.ok) {
        btn.disabled = false;
        showToast((res && res.message) || 'Не удалось поручиться за участника', 'error');
        return;
    }
    showToast(`Вы поручились за ${peer.username}`, 'success', 5000);
    openMembersModal();
}

// Строка о составе под именем участника и действие над ним.
function appendMembershipInfo(li, info, peer, ctx) {
    const entry = ctx.member;
    if (!entry) return;
    const text = membershipHowLine(ctx.roomId, entry);
    if (text) {
        const line = document.createElement('small');
        line.className = 'member-how' + (entry.status === 'unconfirmed' ? ' unconfirmed' : '');
        line.textContent = text;
        info.appendChild(line);
    }
    if (entry.duplicateKeys && entry.status !== 'unconfirmed') {
        const warn = document.createElement('small');
        warn.className = 'member-how unconfirmed';
        warn.textContent = 'Ключи шифрования такие же, как у другого участника. Сверьте код безопасности';
        info.appendChild(warn);
    }
    if (ctx.isSelf || !ctx.client) return;
    if (entry.status === 'unconfirmed') {
        const trust = document.createElement('button');
        trust.className = 'btn btn-danger btn-sm';
        trust.type = 'button';
        setIconLabel(trust, 'user-check', 'Доверять участнику');
        trust.setAttribute('aria-label', `Доверять участнику ${peer.username}`);
        trust.addEventListener('click', () => trustUnconfirmedMember(peer, ctx, trust, Boolean(entry.duplicateKeys)));
        li.appendChild(trust);
    } else if (entry.status === 'confirmed' && entry.how === 'manual' && !entry.vouchedByMe) {
        const vouch = document.createElement('button');
        vouch.className = 'btn btn-secondary btn-sm';
        vouch.type = 'button';
        setIconLabel(vouch, 'shield-check', 'Поручиться за участника');
        vouch.setAttribute('aria-label', `Поручиться за участника ${peer.username}`);
        vouch.addEventListener('click', () => vouchForMember(peer, ctx, vouch));
        li.appendChild(vouch);
    }
}

function createMemberRow(peer, status, ctx) {
    const li = document.createElement('li');
    li.className = 'member-item';

    const head = document.createElement('div');
    head.className = 'member-head';
    const avatar = document.createElement('div');
    avatar.className = 'member-avatar';
    avatar.setAttribute('aria-hidden', 'true');
    renderAvatar(avatar, peer.username, false);
    const info = document.createElement('div');
    info.className = 'member-info';
    const name = document.createElement('div');
    name.className = 'member-name';
    name.textContent = ctx.isSelf ? `${peer.username} (вы)` : peer.username;
    info.appendChild(name);
    head.append(avatar, info);
    li.appendChild(head);
    if (ctx.isSelf) {
        appendMembershipInfo(li, info, peer, ctx);
        return li;
    }

    const statusEl = document.createElement('span');
    info.appendChild(statusEl);
    li._statusEl = statusEl;
    setMemberStatus(li, status);
    appendMembershipInfo(li, info, peer, ctx);
    const ktText = ctx.kt && KT_PEER_TEXT[ctx.kt];
    if (ktText) {
        const ktEl = document.createElement('small');
        ktEl.className = 'member-kt';
        ktEl.textContent = ktText;
        info.appendChild(ktEl);
    }
    if (!ctx.client || status === 'unknown') return li;

    const details = document.createElement('div');
    details.className = 'member-details hidden';
    details.id = `member-details-${peer.id}`;
    li.details = details;
    const toggle = document.createElement('button');
    toggle.className = 'member-code-btn';
    toggle.textContent = status === 'changed' || status === 'log-mismatch' ? 'Проверить' : 'Код';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-controls', details.id);
    toggle.setAttribute('aria-label', `Код безопасности с ${peer.username}`);
    toggle.addEventListener('click', () => {
        const opening = details.classList.contains('hidden');
        details.classList.toggle('hidden', !opening);
        toggle.setAttribute('aria-expanded', opening ? 'true' : 'false');
        if (opening) renderMemberDetails(li, peer, ctx);
    });
    head.appendChild(toggle);
    li.appendChild(details);
    // Сменившийся ключ сразу разворачиваем: ради этого окно и открыли.
    if (status === 'changed' || status === 'log-mismatch') toggle.click();
    return li;
}

async function openMembersModal() {
    if (!currentChatId || !currentRoomId || !currentUser) return;
    const chatId = currentChatId;
    const roomId = currentRoomId;
    const seq = ++membersModalSeq;
    elements.membersNote.classList.add('hidden');
    setMembersPlaceholder('Загрузка участников…');
    openModal(elements.membersModal);

    const part = await api(`/api/chats/${chatId}/participants`);
    if (seq !== membersModalSeq || !currentUser) return;
    if (!part.success || !Array.isArray(part.participants)) {
        setMembersPlaceholder(part.message || 'Не удалось загрузить участников');
        return;
    }
    rememberRoomParticipants(roomId, part.participants);
    const client = await getReadyE2eeClient();
    if (seq !== membersModalSeq || !currentUser) return;
    // Состав группы (signed-membership.md, 10): статусы и подписи «кто подтвердил» - из свежей проверки состава.
    const membership = new Map();
    if (client) {
        try {
            // Через общую очередь сессий комнаты: баннер и лента обновляются тем же проходом.
            const roomResult = (await ensureE2eeRoomSession(chatId, roomId)) || { members: [], unconfirmed: [] };
            (roomResult.members || []).forEach(member => membership.set(Number(member.id), member));
            (roomResult.unconfirmed || []).forEach((u) => {
                const entry = membership.get(Number(u.id));
                if (entry) entry.duplicateKeys = Boolean(u.duplicateKeys);
            });
        } catch (err) {
            console.warn('E2EE: состав группы не проверен:', err);
        }
        roomMemberNames.set(Number(roomId), await client.getRoomMemberNames(roomId).catch(() => ({})));
        if (seq !== membersModalSeq || !currentUser) return;
    }
    const others = part.participants.filter(p => Number(p.id) !== Number(currentUser.id));

    const statuses = new Map();
    const ktStatuses = new Map();
    if (client && others.length > 0) {
        try {
            const list = await client.checkPeerIdentities(others.map(p => p.id));
            (list || []).forEach((s) => {
                statuses.set(Number(s.userId), s.status);
                if (s.kt) ktStatuses.set(Number(s.userId), s.kt);
            });
        } catch (err) {
            console.warn('E2EE: checkPeerIdentities failed:', err);
        }
    }
    if (seq !== membersModalSeq) return;

    if (!client) {
        elements.membersNote.textContent = 'Сквозное шифрование недоступно на этом устройстве — проверить ключи сейчас нельзя.';
        elements.membersNote.classList.remove('hidden');
    }
    const ctx = { client, chatId, roomId };
    const me = part.participants.find(p => Number(p.id) === Number(currentUser.id))
        || { id: currentUser.id, username: currentUser.username };
    const fragment = document.createDocumentFragment();
    fragment.appendChild(createMemberRow(me, null, { ...ctx, isSelf: true, member: membership.get(Number(me.id)) }));
    const changed = [];
    others.forEach((peer) => {
        const status = client ? (statuses.get(Number(peer.id)) || 'unknown') : 'unknown';
        if (status === 'changed') changed.push({ userId: peer.id, username: peer.username });
        fragment.appendChild(createMemberRow(peer, status, { ...ctx, kt: ktStatuses.get(Number(peer.id)), member: membership.get(Number(peer.id)) }));
    });
    elements.membersList.replaceChildren(fragment);
    if (changed.length > 0) addIdentityChanges(roomId, changed);
}
