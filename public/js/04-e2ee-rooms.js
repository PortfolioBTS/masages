// public/js/04-e2ee-rooms.js — E2EE: участники комнаты, ключи, служебные строки, сессии комнат, шифрование и расшифровка.
// Вынесено из public/script.js (строки 805–1633 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Продолжение раздела «E2EE»: баннеры смены ключей, итоги подписанного состава, сессия комнаты, шифрование/расшифровка сообщений,
// запросы ключей, обслуживание ключей комнат и режим «не хранить историю на этом устройстве».
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ---- Участники комнаты, ключи, служебные строки ----

const roomParticipants = new Map();          // roomId -> [{id, username}] (последний известный состав)
const pendingIdentityChanges = new Map();    // userId -> username (для баннера открытой комнаты)
const pendingLogMismatches = new Map();      // userId -> username: ключа нет в журнале ключей (там же)
const notedLogMismatches = new Set();        // 'комната:участник': о чём уже писали в ленту
const warnedRooms = new Set();               // о каких комнатах уже предупреждали, что не все получили ключ
const pendingUnconfirmed = new Map();        // userId -> username: неподтверждённые участники открытой комнаты (баннер)
const pendingSuspended = new Map();          // userId -> username: подтверждённые ранее, у которых сменился ключ (баннер)
const notedMembership = new Set();           // 'комната:вид:...': о чём про состав группы уже писали в ленту

function rememberRoomParticipants(roomId, participants) {
    roomParticipants.set(Number(roomId), Array.isArray(participants) ? participants : []);
}

// Карты имён бывших и текущих участников из хранилища ключей устройства
// (memberNames:<комната>, sealed-sender.md, 9.5): сообщение вышедшего участника
// подписывается его последним известным именем.
const roomMemberNames = new Map();           // roomId -> { <id>: <имя> }

// Подпись автора сообщения комнаты. Сервер автора не называет: senderId приходит из
// результата расшифровки (индекс отправителей), имя - из списка участников. Не
// расшифрованное сообщение - «Участник группы»; вышедший - с пометкой; без имени -
// «Бывший участник». Пока список участников не загружен, назвать некого.
function roomAuthorLabel(roomId, senderId) {
    if (!Number.isSafeInteger(senderId)) return 'Участник группы';
    const list = roomParticipants.get(Number(roomId));
    if (!list) return 'Участник группы';
    const current = list.find(p => Number(p.id) === senderId);
    if (current && current.username) return current.username;
    const former = (roomMemberNames.get(Number(roomId)) || {})[senderId];
    return former ? `${former} (вышел(ла))` : 'Бывший участник';
}

// Список участников и карта имён - до показа истории: автор сообщения известен только
// клиенту. Сбой не мешает показать историю (подписи будут «Участник группы»).
async function loadRoomAuthorDirectory(chatId, roomId) {
    try {
        const [part, client] = await Promise.all([api(`/api/chats/${chatId}/participants`), getReadyE2eeClient()]);
        if (part && part.success && Array.isArray(part.participants)) rememberRoomParticipants(roomId, part.participants);
        if (client) roomMemberNames.set(Number(roomId), await client.getRoomMemberNames(roomId));
    } catch (err) {
        console.warn('E2EE: имена участников не загружены:', err);
    }
}

function participantName(roomId, userId) {
    const list = roomParticipants.get(Number(roomId)) || [];
    const found = list.find(p => Number(p.id) === Number(userId));
    return found && found.username ? found.username : `участник #${userId}`;
}

// Служебные строки (вход/выход участников, смена ключей) — локальные, не
// сообщения сервера. Пока история чата не отрисована, копятся в очереди:
// иначе renderMessages('replace') стёр бы их.
let noticesReady = false;
let pendingNotices = [];

// Служебная строка в ленте открытого чата (иконка + текст).
function appendChatNotice(text, iconName = 'info') {
    if (!currentChatId) return;
    if (!noticesReady) {
        pendingNotices.push({ text, iconName });
        return;
    }
    const stick = isNearBottom();
    const el = iconText('div', 'system-notice', iconName, text, { size: 'sm' });
    el.setAttribute('role', 'status');
    elements.chatMessages.appendChild(el);
    if (stick) scrollToBottom();
}

function appendSystemNotice(roomId, text, iconName = 'key') {
    if (Number(roomId) !== Number(currentRoomId)) return;
    appendChatNotice(text, iconName);
}

function flushSystemNotices() {
    noticesReady = true;
    const queued = pendingNotices;
    pendingNotices = [];
    queued.forEach(n => appendChatNotice(n.text, n.iconName));
}

function renderIdentityBanner() {
    const names = Array.from(pendingIdentityChanges.values());
    const mismatched = Array.from(pendingLogMismatches.values());
    const unconfirmed = Array.from(pendingUnconfirmed.values());
    const suspended = Array.from(pendingSuspended.values());
    if (!currentRoomId || (names.length === 0 && mismatched.length === 0 && unconfirmed.length === 0 && suspended.length === 0)) {
        elements.e2eeBanner.classList.add('hidden');
        elements.e2eeBannerText.textContent = '';
        return;
    }
    const parts = [];
    if (names.length > 0) {
        // Отправка в группу не блокируется: остальные получают сообщения как обычно. Участнику со сменившимся ключом не
        // передаётся ключ группы — новые сообщения он не прочитает, пока вы не проверите код безопасности.
        parts.push(names.length === 1
            ? `У участника ${names[0]} сменился ключ шифрования. Ключ группы ему не передаётся, и новые сообщения он не прочитает, пока вы не проверите код безопасности`
            : `У участников ${names.join(', ')} сменились ключи шифрования. Ключ группы им не передаётся, и новые сообщения они не прочитают, пока вы не проверите коды безопасности`);
    }
    if (mismatched.length > 0) {
        parts.push(`Сервер показывает для ${mismatched.join(', ')} ключ, которого нет в журнале ключей (или журнал у участников разный). Возможна подмена. Сверьте код безопасности лично. Ключ комнаты ${mismatched.length === 1 ? 'этому участнику' : 'этим участникам'} не отправляется`);
    }
    // Подписанный состав группы (signed-membership.md, 10): сервер добавил участника, за которого никто не поручился.
    if (unconfirmed.length > 0) {
        parts.push(`В группе есть неподтверждённые участники: ${unconfirmed.join(', ')}. Ключ группы ${unconfirmed.length === 1 ? 'ему' : 'им'} не передаётся, пока вы не подтвердите ${unconfirmed.length === 1 ? 'его' : 'их'}`);
    }
    // Подтверждённые вами участники, у которых потом сменился ключ (suspended): не «вошли без подписи».
    if (suspended.length > 0) {
        parts.push(`${suspended.join(', ')}: ключ изменился после подтверждения. Ключ группы ${suspended.length === 1 ? 'ему' : 'им'} не передаётся, пока вы не проверите код безопасности`);
    }
    elements.e2eeBannerText.textContent = parts.join('. ');
    elements.e2eeBanner.classList.remove('hidden');
}

function addIdentityChanges(roomId, changes) {
    if (Number(roomId) !== Number(currentRoomId) || !Array.isArray(changes)) return;
    changes.forEach((change) => {
        const userId = Number(typeof change === 'object' && change !== null ? change.userId : change);
        if (!userId) return;
        const username = (change && change.username) || participantName(roomId, userId);
        pendingIdentityChanges.set(userId, username);
    });
    renderIdentityBanner();
}

// Статус identity пира — getPeerIdentityStatus может быть и синхронным, и
// асинхронным; ошибка = "неизвестно".
async function peerIdentityStatus(client, userId) {
    try {
        return await Promise.resolve(client.getPeerIdentityStatus(userId));
    } catch {
        return null;
    }
}

// Баннер показывает тех, у кого identity сейчас в состоянии 'changed':
// и найденных только что (ensureRoomSession), и оставшихся с прошлых раз
// (ключ сменился, а пользователь его ещё не проверил).
async function refreshIdentityChanges(client, roomId, participants, reported) {
    const changed = new Map();
    (reported || []).forEach((c) => {
        const userId = Number(c.userId);
        if (userId) changed.set(userId, c.username || participantName(roomId, userId));
    });
    const others = (participants || []).filter(p => currentUser && Number(p.id) !== Number(currentUser.id));
    const mismatched = new Map();
    let statusesKnown = true;
    for (const peer of others) {
        const status = await peerIdentityStatus(client, peer.id);
        if (status === null) statusesKnown = false;
        if (status === 'changed') changed.set(Number(peer.id), peer.username || participantName(roomId, peer.id));
        if (status === 'log-mismatch') mismatched.set(Number(peer.id), peer.username || participantName(roomId, peer.id));
    }
    if (Number(roomId) !== Number(currentRoomId)) return;
    // Если статусы узнать не удалось, ничего из баннера не убираем.
    if (statusesKnown) {
        pendingIdentityChanges.clear();
        pendingLogMismatches.clear();
    }
    changed.forEach((name, userId) => pendingIdentityChanges.set(userId, name));
    mismatched.forEach((name, userId) => pendingLogMismatches.set(userId, name));
    renderIdentityBanner();
}

// Имя участника для строк о составе: текущий участник или бывший (последнее известное имя).
function memberLabel(roomId, userId) {
    if (userId == null) return 'участник';
    const list = roomParticipants.get(Number(roomId)) || [];
    const current = list.find(p => Number(p.id) === Number(userId));
    if (current && current.username) return current.username;
    const former = (roomMemberNames.get(Number(roomId)) || {})[userId];
    return former || `участник #${userId}`;
}

// Подпись под именем в окне участников и в ленте: кто и как подтвердил участника (signed-membership.md, 10).
function membershipHowLine(roomId, entry) {
    if (!entry) return '';
    const by = memberLabel(roomId, entry.by);
    if (entry.status === 'self') {
        if (entry.how === 'approved') return `Вас одобрил(а) ${by}`;
        if (entry.how === 'invite') return `Вы вошли по приглашению ${by}`;
        if (entry.how === 'creator') return 'Вы создали группу';
        return entry.how === 'unknown' ? 'Способ входа в группу неизвестен' : '';
    }
    if (entry.status === 'unconfirmed') {
        if (entry.duplicateKeys) return 'Не подтверждён: ключи шифрования такие же, как у другого участника';
        // Подтверждали, но ключ с тех пор изменился (suspended): это не «вошёл без подписи».
        if (entry.suspended) return 'Не подтверждён: ключ изменился после подтверждения';
        return 'Не подтверждён: вошёл без подписи участника';
    }
    switch (entry.how) {
        case 'approved': return `Одобрил(а) ${by}`;
        case 'invite': return `По приглашению ${by}`;
        case 'vouched': return `Подтвердил(а) ${by}`;
        case 'revouched': return `Повторно подтверждён ${by} после выхода прежнего подписавшего`;
        case 'manual': return 'Подтверждён вами';
        default: return '';
    }
}

const ANCHOR_FAILURE_TEXT = {
    'no-certificate': 'Не удалось подтвердить состав группы: подписи участника для вас нет на сервере. Участники не подтверждены — подтвердите тех, кого знаете, вручную',
    'snap-bad': 'Приглашение повреждено: состав группы по нему не подтверждён',
    'snap-missing': 'Не получен список участников от пригласившего: состав группы не подтверждён',
    'inviter-key': 'Ключ пригласившего не совпал с подписью приглашения — возможна подмена. Состав группы не подтверждён, сверьте код безопасности лично',
    'inviter-substituted': 'Ключ пригласившего не совпал с подписью приглашения — возможна подмена. Состав группы не подтверждён, сверьте код безопасности лично',
    'duplicate-keys': 'У пригласившего и другого участника одинаковые ключи шифрования. Состав группы не подтверждён',
};

// Состав группы после проверки: баннер, строки ленты, предупреждения (signed-membership.md, 10).
function handleMembershipResult(roomId, result) {
    const unconfirmed = Array.isArray(result.unconfirmed) ? result.unconfirmed : [];
    const skip = new Set((result.identityChanges || []).concat(result.logMismatches || []).map(c => Number(c.userId)));
    pendingUnconfirmed.clear();
    pendingSuspended.clear();
    unconfirmed.filter(u => !skip.has(Number(u.id))).forEach(u => (u.suspended ? pendingSuspended : pendingUnconfirmed).set(Number(u.id), u.username || `участник #${u.id}`));
    renderIdentityBanner();

    const once = (key) => {
        const full = `${roomId}:${key}`;
        if (notedMembership.has(full)) return false;
        notedMembership.add(full);
        return true;
    };
    if (result.anchor && result.anchor.ok === true && once('anchor-ok')) {
        appendSystemNotice(roomId, result.anchor.via === 'invite'
            ? 'Состав группы подтверждён по подписи приглашения'
            : 'Состав группы подтверждён по подписи одобрившего', 'shield-check');
    }
    if (result.anchor && result.anchor.ok === false && once('anchor-' + result.anchor.reason)) {
        appendSystemNotice(roomId, ANCHOR_FAILURE_TEXT[result.anchor.reason] || 'Не удалось подтвердить состав группы по приглашению', 'shield-alert');
    }
    (Array.isArray(result.duplicateKeys) ? result.duplicateKeys : []).forEach((group) => {
        if (!once('dup:' + group.ids.join(','))) return;
        const names = group.ids.map(id => memberLabel(roomId, id)).join(', ');
        appendSystemNotice(roomId, `Ключи шифрования участников ${names} совпадают. Сверьте код безопасности`, 'shield-alert');
    });
}

function handleRoomSessionResult(roomId, result) {
    if (!result || Number(roomId) !== Number(currentRoomId)) return;
    handleMembershipResult(roomId, result);
    const warnings = Array.isArray(result.warnings) ? result.warnings : [];
    const unconfirmedIds = new Set((Array.isArray(result.unconfirmed) ? result.unconfirmed : []).map(u => Number(u.id)));
    const membersById = new Map((Array.isArray(result.members) ? result.members : []).map(member => [Number(member.id), member]));
    // Неподтверждённые и дубликаты ключей - не «не настроено шифрование»: о них говорят баннер и отдельная строка.
    const failedIds = new Set(warnings
        .filter(w => w && w.userId != null && w.reason !== 'unconfirmed-member' && w.reason !== 'duplicate-keys')
        .map(w => Number(w.userId)));
    // Участники со сменившимся ключом и с ключом, которого нет в журнале, тоже попадают в warnings, но о них
    // говорят баннер и отдельная строка — здесь они не «без шифрования».
    const changedIds = new Set((result.identityChanges || []).concat(result.logMismatches || []).map(c => Number(c.userId)));
    const newMembers = Array.isArray(result.newMembers) ? result.newMembers : [];
    const removedMembers = Array.isArray(result.removedMembers) ? result.removedMembers : [];

    // Участники со сменившимся ключом тоже попадают в warnings, но о них
    // говорит баннер — здесь они не "без шифрования".
    const delivered = newMembers.filter(member => !failedIds.has(Number(member.id)) && !changedIds.has(Number(member.id)) && !unconfirmedIds.has(Number(member.id)));
    const undelivered = newMembers.filter(member => failedIds.has(Number(member.id)) && !changedIds.has(Number(member.id)) && !unconfirmedIds.has(Number(member.id)));
    const unsigned = newMembers.filter(member => unconfirmedIds.has(Number(member.id)) && !changedIds.has(Number(member.id)));
    if (delivered.length > 0) {
        // «{имя} в группе — одобрил(а) {имя}»: кто и как подтвердил (подпись участника, а не слово сервера).
        const lines = delivered.map((member) => {
            const entry = membersById.get(Number(member.id));
            const name = member.username || `участник #${member.id}`;
            if (!entry || entry.status !== 'confirmed') return null;
            // Допуск заявки, подписанный участником, выглядит для остальных как поручительство: в ленте это «одобрил(а)».
            if (entry.how === 'vouched' || entry.how === 'approved') return `${name} в группе — одобрил(а) ${memberLabel(roomId, entry.by)}`;
            if (entry.how === 'invite') return `${name} в группе — по приглашению ${memberLabel(roomId, entry.by)}`;
            const how = membershipHowLine(roomId, entry);
            return how ? `${name} в группе — ${how.charAt(0).toLowerCase()}${how.slice(1)}` : null;
        });
        const text = lines.every(Boolean)
            ? `${lines.join('; ')}. Ключ шифрования передан`
            : `В чат вошли: ${joinNames(delivered)}, им передан ключ шифрования`;
        appendSystemNotice(roomId, text, 'key');
        showToast(text, 'info');
    }
    if (unsigned.length > 0) {
        const verb = unsigned.length === 1 ? 'появился(ась)' : 'появились';
        const text = `${joinNames(unsigned)} ${verb} в группе без подписи участника. Ключ шифрования ${unsigned.length === 1 ? 'ему' : 'им'} не отправлен`;
        appendSystemNotice(roomId, text, 'shield-alert');
        showToast(text, 'info', 6000);
    }
    if (undelivered.length > 0) {
        appendSystemNotice(roomId, `В чат вошли: ${joinNames(undelivered)}, но ключ шифрования им передать не удалось — они пока не смогут читать зашифрованные сообщения`, 'alert-triangle');
    }
    // Ключа участника нет в журнале ключей: ключ комнаты ему не передан (один раз за сессию на участника).
    const fresh = (Array.isArray(result.logMismatches) ? result.logMismatches : [])
        .filter(m => !notedLogMismatches.has(`${roomId}:${m.userId}`));
    if (fresh.length > 0) {
        fresh.forEach(m => notedLogMismatches.add(`${roomId}:${m.userId}`));
        appendSystemNotice(roomId, `Ключа ${joinNames(fresh)} нет в журнале ключей: ключ шифрования ${fresh.length === 1 ? 'ему' : 'им'} не передан${result.rotated ? ', ключ комнаты обновлён' : ''}. Сверьте код безопасности лично`, 'alert-triangle');
    }
    if (removedMembers.length > 0) {
        const verb = removedMembers.length === 1 ? 'покинул(а)' : 'покинули';
        const text = `${joinNames(removedMembers)} ${verb} чат${result.rotated ? ' — ключ шифрования обновлён' : ''}`;
        appendSystemNotice(roomId, text, 'key');
        showToast(text, 'info');
    }

    const newIds = new Set(newMembers.map(member => Number(member.id)));
    const failedExisting = Array.from(failedIds).filter(id => !newIds.has(id) && !changedIds.has(id));
    const general = warnings.find(w => w && w.userId == null);
    if (general) {
        showToast(`Ключ шифрования не разослан: ${general.reason || 'ошибка сервера'} — собеседники могут не прочитать новые сообщения`, 'error', 6000);
    } else if (failedExisting.length > 0 && !warnedRooms.has(Number(roomId))) {
        warnedRooms.add(Number(roomId));
        showToast(`${failedExisting.length} участник(ов) пока не могут читать зашифрованные сообщения: у них не настроено шифрование`, 'info', 6000);
    }
}

// Забирает ожидающие key-share для комнаты (от других участников) — нужно
// делать ДО расшифровки входящих сообщений, иначе их Sender Key ещё не
// будет известен локально. Параллельные вызовы для той же комнаты
// склеиваются в один запрос.
let keySyncInFlight = null;   // { roomId, promise }
let lastKeySyncAt = 0;
function syncE2eeKeyShares(chatId, roomId) {
    if (!roomId) return Promise.resolve(null);
    if (keySyncInFlight && keySyncInFlight.roomId === roomId) return keySyncInFlight.promise;
    const promise = (async () => {
        const client = await getReadyE2eeClient();
        if (!client) return null;
        lastKeySyncAt = Date.now();
        try {
            const res = await client.syncKeyShares(chatId, roomId);
            if (res && Array.isArray(res.identityChanges) && res.identityChanges.length > 0) {
                addIdentityChanges(roomId, res.identityChanges);
            }
            // Сверка взглядов на состав и ключи (signed-membership.md, 9.6): информативная тревога, отправка не блокируется.
            if (res && res.viewMismatch) {
                showToast('Участники группы видят разные ключи шифрования (возможна подмена сервером). Сверьте коды безопасности', 'error', 8000);
            }
            if (res && res.viewIdsDiverged) {
                showToast('Состав группы у одного из участников отличается от вашего. Возможно, сервер показывает участникам разные списки', 'info', 8000);
            }
            return res;
        } catch (err) {
            console.error('E2EE: syncKeyShares failed:', err);
            return null;
        }
    })().finally(() => {
        if (keySyncInFlight && keySyncInFlight.promise === promise) keySyncInFlight = null;
    });
    keySyncInFlight = { roomId, promise };
    return promise;
}

// Готовит комнату к шифрованию (ensureRoomSession): создаёт свой Sender
// Key, досылает его новым участникам, ротирует после ухода участника.
// Вызовы выстраиваются в очередь: состав комнаты мог измениться, пока
// шёл предыдущий, и "склеивать" их, как syncKeyShares, нельзя.
let roomSessionChain = Promise.resolve();
let lastRoomSession = null;   // { roomId, promise } — последний запуск, его ждёт отправка

async function runRoomSession(chatId, roomId, { answerKeyRequests = false } = {}) {
    const client = await getReadyE2eeClient();
    if (!client) return null;
    const part = await api(`/api/chats/${chatId}/participants`);
    if (!part.success || !part.roomId || Number(part.roomId) !== Number(roomId)) return null;
    rememberRoomParticipants(roomId, part.participants);
    // Запросы ключа, накопившиеся, пока я была офлайн: снимаем отметки «разослано»
    // до ensureRoomSession, и тот переотправит мой текущий ключ.
    if (answerKeyRequests) {
        try { await client.answerKeyRequests(chatId, roomId); } catch (err) { console.warn('E2EE: запросы ключа не прочитаны:', err); }
    }
    let result;
    try {
        // Ответ участников целиком: свои сертификаты, снимки к ним и приглашение комнаты (проверка состава).
        result = await client.ensureRoomSession(chatId, roomId, part.participants, part);
    } catch (err) {
        console.error('E2EE: не удалось подготовить сессию комнаты:', err);
        return null;
    }
    scheduleRevouchTimer(chatId, roomId, client);
    if (result && Array.isArray(result.warnings) && result.warnings.length > 0) {
        console.warn('E2EE: не со всеми участниками установлен защищённый канал:', result.warnings);
    }
    handleRoomSessionResult(roomId, result);
    // Причина отказа в отправке снимается, как только ключ комнаты получил хоть кто-то (например, после подтверждения участника).
    if (result && !NyxoE2eePolicy.sessionBlock(result)) clearRoomBlock(chatId);
    await refreshIdentityChanges(client, roomId, part.participants, result && result.identityChanges);
    refreshTransparencyBanner();
    return result;
}

// Повторный допуск после ухода подписавшего (signed-membership.md, 5.5): задача исполняется по сроку, и открытая вкладка
// сама перезапускает сессию комнаты, когда срок наступил.
let revouchTimer = null;
async function scheduleRevouchTimer(chatId, roomId, client) {
    clearTimeout(revouchTimer);
    let wait = null;
    try { wait = await client.nextRevouchDueMs(roomId); } catch { wait = null; }
    if (wait === null) return;
    revouchTimer = setTimeout(() => {
        if (currentUser && Number(roomId) === Number(currentRoomId)) ensureE2eeRoomSession(chatId, roomId);
    }, Math.min(Math.max(wait, 5000), 60 * 60 * 1000) + 1000);
}

function ensureE2eeRoomSession(chatId, roomId, options) {
    const run = () => runRoomSession(chatId, roomId, options).catch((err) => {
        console.error('E2EE: ensureRoomSession failed:', err);
        return null;
    });
    const promise = roomSessionChain.then(run);
    roomSessionChain = promise;
    lastRoomSession = { roomId, promise };
    return promise;
}

// Состав открытой комнаты изменился (вступление по коду, одобренная
// заявка, выход участника). Забираем новые key-share и пересобираем сессию:
// ensureRoomSession увидит новичка в newMembers и отправит ему наш Sender
// Key, а после ухода — ротирует ключ. Серия событий склеивается в один
// запуск. Комнату, открытую не сейчас, это догонит при её открытии
// (openChat тоже вызывает ensureRoomSession).
function scheduleRoomMembersRefresh(roomId) {
    if (!currentUser || !roomId || !currentChatId || Number(roomId) !== Number(currentRoomId)) return;
    const chatId = currentChatId;
    const room = currentRoomId;
    clearTimeout(membersChangedTimer);
    membersChangedTimer = setTimeout(async () => {
        if (chatId !== currentChatId) return;
        await syncE2eeKeyShares(chatId, room);
        if (chatId === currentChatId) ensureE2eeRoomSession(chatId, room);
    }, 300);
}

// Отправка прервана, и причина понятна пользователю. code:
//   'unavailable'        — ключи устройства не готовы (причина в e2eeInitError);
//   'session-failed',
//   'keys-not-delivered',
//   'keys-withheld'      — см. NyxoE2eePolicy.sessionBlock;
//   'not-bot'            — чат не комната и не запомненный чат с ботом.
class E2eeBlockedError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'E2eeBlockedError';
        this.code = code;
    }

    // Причина относится к ключу комнаты: её показывают под полем ввода с «Повторить».
    get showsRetry() {
        return this.code === 'session-failed' || this.code === 'keys-not-delivered' || this.code === 'keys-withheld';
    }
}

// Вызывается перед отправкой в чат. Возвращает клиент E2EE для комнаты и null
// ТОЛЬКО для чата с ботом (открытый текст разрешён по запомненному номеру). В
// комнате null не бывает: либо клиент, либо E2eeBlockedError с текстом для
// пользователя — тихо отправить комнате открытым текстом нельзя.
//
// Правило блокировки (план криптографии, раздел 3): если после подготовки
// сессии комнаты ключ не дошёл ни до одного участника, а другие участники есть,
// отправка прерывается. Если не дошёл лишь до части — отправляем, а о части
// один раз предупреждает handleRoomSessionResult.
async function prepareOutgoing(chatId, roomId) {
    if (!roomId) {
        if (plaintextAllowedForChat(chatId, roomId)) return null;
        throw new E2eeBlockedError('not-bot', 'Сообщение не отправлено: открытый текст разрешён только в чате с ботом, а этот чат им не подтверждён');
    }
    const client = await getReadyE2eeClient();
    if (!client) {
        throw new E2eeBlockedError('unavailable',
            `Сквозное шифрование недоступно: ${NyxoE2eePolicy.initErrorReason(e2eeInitError)}. Сообщение не отправлено`);
    }
    // Sender Key комнаты должен быть создан и разослан участникам до
    // первого конверта; если последний запуск не удался — пробуем снова.
    let session = null;
    if (lastRoomSession && lastRoomSession.roomId === roomId) session = await lastRoomSession.promise;
    if (!session || session.ok === false) session = await ensureE2eeRoomSession(chatId, roomId);
    const block = NyxoE2eePolicy.sessionBlock(session);
    if (block) throw new E2eeBlockedError(block.code, block.text);
    return client;
}

// Показывает причину отклонённой отправки: тост и, для ключа комнаты, строка
// под полем ввода с «Повторить».
function reportBlockedSend(err, chatId, roomId) {
    showToast(err.message, 'error', 6000);
    if (roomId && err.showsRetry) setRoomBlock(chatId, err.message);
}

// Общий признак версии клиента волны 4 (message-ordering.md, 14.1): все изменяющие
// запросы сообщений (отправка, файл, правка) несут proto. Значение должно равняться
// PROTO_CURRENT в lib/proto.js - это проверяет test/proto.test.js. Устаревшая вкладка
// без признака получает 400 client-outdated («Обновите страницу»).
const PROTO_VERSION = 4;

// Тексты для причин отказа decryptIncoming (res.reason из e2ee.js). Причина,
// которой здесь нет, получает общий текст. Новая причина — новая строка.
const E2EE_FAILURE_TEXTS = {
    // Автора сообщения комнаты определяет клиент по senderKeyId через индекс
    // отправителей (sealed-sender.md, 9.3): ключа в индексе ещё нет - он придёт
    // key-share'ом или по запросу ключа.
    'no-sender-key': 'Ключ автора ещё не получен на этом устройстве',
    'bad-signature': 'Подпись сообщения неверна (возможна подмена сервером)',
    replay: 'Повтор старого сообщения (возможна подмена сервером)',
    // Содержимое привязано к сообщению (message-ordering.md, раздел 9): внутри
    // шифротекста лежат id сообщения, автор версии и время правки.
    'id-mismatch': 'Сообщение выдано под чужим номером (возможна подмена сервером)',
    'sender-mismatch': 'У сообщения сменился автор (возможна подмена сервером)',
    'stale-edit': 'Старая версия сообщения вместо более новой (возможна подмена сервером)',
    'no-mid': 'Сообщение старого формата, показать его нельзя',
    // Ключ сообщения удалён на этом устройстве: по сроку исчезающих сообщений или бюджету
    // хранения (раздел 5 плана криптографии) либо режимом «Не хранить историю» (раздел 6).
    'key-expired': 'Недоступно на этом устройстве: ключ удалён по сроку хранения',
    'history-not-kept': 'Недоступно на этом устройстве: история не хранится',
    // Открытых сообщений в комнатах нет: сервер их не принимает. Пришло такое — его
    // прислал не клиент участника; показывать его текст как сообщение нельзя.
    'not-encrypted': 'Сообщение пришло без шифрования — так не должно быть (возможна подмена сервером), поэтому оно не показано',
};
const E2EE_FAILURE_DEFAULT_TEXT = 'Не удалось расшифровать';

function e2eeFailureText(reason) {
    // hasOwnProperty: причина — строка из кода, но имена вроде 'constructor'
    // не должны находиться в прототипе объекта.
    return Object.prototype.hasOwnProperty.call(E2EE_FAILURE_TEXTS, reason)
        ? E2EE_FAILURE_TEXTS[reason]
        : E2EE_FAILURE_DEFAULT_TEXT;
}

function safeDisplayName(name) {
    const clean = String(name || '')
        .split(/[\\/]/).pop()
        .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '')
        .trim()
        .slice(0, 200);
    return clean || 'file';
}

// Текст цитаты/превью для результата decryptIncoming.
function decryptedSummary(res) {
    if (!res.ok && res.reason === 'history-not-kept') return 'Сообщение недоступно на этом устройстве';
    if (!res.ok) return e2eeFailureText(res.reason);
    if (res.file) return `Файл: ${res.text || safeDisplayName(res.file.name)}`;
    return res.text;
}

// Расшифровывает сообщение "на месте" перед рендерингом — после этого
// вызова весь остальной код (createMessageElement, предпросмотр ответа,
// редактирование) работает с message.text как с обычным открытым
// текстом, будто шифрования и не было. messageId передаётся в
// decryptIncoming для защиты от повтора: сервер не может выдать старый
// конверт за новое сообщение.
async function decryptEnvelope(roomId, senderId, text, messageId) {
    const client = roomId ? await getSettledE2eeClient() : null;
    if (!client) return { ok: false, reason: 'unavailable' };
    const attempt = async () => {
        try {
            return await client.decryptIncoming(roomId, senderId, text, messageId);
        } catch (err) {
            console.warn('E2EE: decryptIncoming failed:', err);
            return { ok: false, reason: 'error' };
        }
    };
    let res = await attempt();
    // Sender Key отправителя мог прийти (e2eeKeyShare) буквально перед
    // самим сообщением — один раз досинхронизируем ключи и пробуем снова.
    if (!res.ok && (res.reason === 'no-sender-key' || res.reason === 'stale-sender-key')
        && currentChatId && Number(roomId) === Number(currentRoomId) && Date.now() - lastKeySyncAt > 3000) {
        await syncE2eeKeyShares(currentChatId, roomId);
        res = await attempt();
    }
    // Ключа всё ещё нет (key-share потерян или вытеснен из очереди): просим владельца
    // прислать его снова, не чаще раза в час на ключ.
    if (!res.ok && (res.reason === 'no-sender-key' || res.reason === 'stale-sender-key')) requestMissingRoomKey(roomId, text);
    return res;
}

async function decryptMessageInPlace(message, roomId) {
    let decryptedForReply = null;   // результат расшифровки самого сообщения: из него берётся подписанный id ответа
    if (roomId && !message.encrypted) {
        // Без метки «без шифрования» (её больше нет) подложенное сервером открытое
        // сообщение выглядело бы как настоящее сообщение участника.
        message.text = e2eeFailureText('not-encrypted');
        message._e2eeFailed = true;
        message.file_url = null;
        message.file_name = null;
    } else if (message.encrypted) {
        if (roomId) {
            // Подсказки сервера об авторе нет и быть не может: senderId = null, автора
            // находит клиент по индексу отправителей (sealed-sender.md, 9.3).
            const res = await decryptEnvelope(roomId, null, message.text, message.id);
            decryptedForReply = res;
            if (res.ok) {
                message.text = res.text || '';
                if (res.file) message._file = res.file;
                message._ts = res.ts; // время отправителя для показа (раздел 9.5)
                message._senderId = res.senderId; // автор - только из расшифровки (9.4)
                // Отправитель вне подтверждённого состава (signed-membership.md, 9.4): сообщение помечается.
                message._unverified = res.unverifiedSender === true;
            } else {
                message.text = e2eeFailureText(res.reason);
                message._e2eeFailed = true;
                // Серия таких сообщений сворачивается в одну служебную строку (renderMessages).
                if (res.reason === 'history-not-kept') message._historyNotKept = true;
            }
        } else {
            message.text = 'Зашифрованное сообщение';
            message._e2eeFailed = true;
        }
    }
    // Цитата в комнате показывается, только если её id совпал с id ответа внутри подписанного шифротекста (З3):
    // reply_to_id сервер хранит открыто и мог бы приписать сообщению любую цитату.
    if (roomId && message.reply_to && !NyxoE2eePolicy.replyQuoteTrusted(message.reply_to, decryptedForReply)) {
        message.reply_to = null;
    }
    if (message.reply_to && !message.reply_to.deleted) {
        if (roomId && !message.reply_to.encrypted) {
            message.reply_to.text = e2eeFailureText('not-encrypted');
        } else if (message.reply_to.encrypted) {
            const replyRes = roomId
                ? await decryptEnvelope(roomId, null, message.reply_to.text, message.reply_to.id)
                : { ok: false };
            message.reply_to.text = decryptedSummary(replyRes);
            // Автор цитаты определяется так же, как у обычного сообщения; цитата без
            // расшифровки - «Сообщение недоступно» (sealed-sender.md, 9.6).
            if (roomId) {
                message.reply_to._author = replyRes.ok ? roomAuthorLabel(roomId, replyRes.senderId) : '';
                if (!replyRes.ok) message.reply_to.text = 'Сообщение недоступно';
            }
        }
    }
    return message;
}

async function decryptMessagesInPlace(messages, roomId) {
    for (const m of messages) await decryptMessageInPlace(m, roomId);
    return messages;
}

// >>> e2ee-room-keys
// Ключи комнат на устройстве (план криптографии, раздел 5): плановая ротация своего
// ключа после отправки, повтор шифрования после needs-room-session, запрос потерянного
// ключа и ответ владельца, срок исчезающих сообщений для хранилища ключей.
// Логика вынесена в отдельный блок, чтобы проверяться юнит-тестом
// (test/e2ee-room-keys-client.test.js) без браузера.

// Шифрует сообщение комнаты. Если ключ комнаты исчерпал жёсткий порог ротации
// (200 сообщений или 8 суток, E2eeError с кодом 'needs-room-session'), ждёт
// ensureRoomSession — он ротирует ключ и рассылает новый — и повторяет шифрование
// один раз. Любая другая ошибка и повторный отказ уходят вызывающему.
async function encryptForRoom(client, chatId, roomId, content, options) {
    try {
        return await client.encryptOutgoing(roomId, content, options);
    } catch (err) {
        if (!err || err.code !== 'needs-room-session') throw err;
        await ensureE2eeRoomSession(chatId, roomId);
        return client.encryptOutgoing(roomId, content, options);
    }
}

// После отправки: ключ комнаты мог дойти до мягкого порога ротации (100 сообщений
// или 7 суток). Проверка локальная и дешёвая; ротацию и рассылку нового ключа
// делает ensureRoomSession в фоне, и отправка её не ждёт.
async function checkRoomKeyRotation(chatId, roomId) {
    if (!roomId) return;
    try {
        const client = await getReadyE2eeClient();
        if (client && await client.roomKeyDue(roomId)) await ensureE2eeRoomSession(chatId, roomId);
    } catch (err) {
        console.warn('E2EE: плановая ротация ключа комнаты не удалась:', err);
    }
}

// Запрос потерянного ключа. Сообщение не расшифровалось из-за 'no-sender-key' или
// 'stale-sender-key', а синхронизация key-share ключа не принесла: просим владельца
// прислать его снова. Конверты открытой комнаты копятся и уходят одним запросом.
const KEY_REQUEST_DEBOUNCE_MS = 800;
const pendingKeyRequests = new Map();   // roomId → { chatId, envelopes: Set<string>, timer }

function requestMissingRoomKey(roomId, envelopeText) {
    if (!roomId || !currentChatId || Number(roomId) !== Number(currentRoomId) || typeof envelopeText !== 'string') return;
    let entry = pendingKeyRequests.get(roomId);
    if (!entry) {
        entry = { chatId: currentChatId, envelopes: new Set(), timer: null };
        pendingKeyRequests.set(roomId, entry);
    }
    entry.envelopes.add(envelopeText);
    clearTimeout(entry.timer);
    entry.timer = setTimeout(() => flushKeyRequest(roomId), KEY_REQUEST_DEBOUNCE_MS);
}

async function flushKeyRequest(roomId) {
    const entry = pendingKeyRequests.get(roomId);
    pendingKeyRequests.delete(roomId);
    if (!entry || !currentUser) return;
    try {
        const client = await getReadyE2eeClient();
        if (client) await client.requestRoomKeys(entry.chatId, roomId, Array.from(entry.envelopes));
    } catch (err) {
        console.warn('E2EE: запрос ключа не удался:', err);
    }
}

function clearPendingKeyRequests() {
    pendingKeyRequests.forEach(entry => clearTimeout(entry.timer));
    pendingKeyRequests.clear();
}

// Событие e2eeKeyRequest: участник просит ключ. Если это мой текущий ключ, клиент
// снимает отметку «разослано», и ensureRoomSession переотправляет его.
async function handleKeyRequestEvent(payload) {
    if (!currentUser || !payload) return;
    const roomId = Number(payload.roomId);
    const meta = roomId ? findChatMeta(null, roomId) : null;
    if (!meta) return;
    try {
        const client = await getReadyE2eeClient();
        if (!client) return;
        const answer = await client.answerKeyRequests(meta.id, roomId, [{ fromUserId: payload.fromUserId, senderKeyIds: payload.senderKeyIds }]);
        if (answer && Array.isArray(answer.resend) && answer.resend.length > 0) await ensureE2eeRoomSession(meta.id, roomId);
    } catch (err) {
        console.warn('E2EE: ответ на запрос ключа не удался:', err);
    }
}

// Срок исчезающих сообщений комнаты нужен хранилищу ключей на устройстве: ключи
// удаляются вместе с сообщениями, через срок и час запаса. Передаётся при открытии
// комнаты и при смене срока (список чатов, событие chatExpiryChanged).
async function syncRoomKeyPolicy(roomId, seconds) {
    if (!roomId) return;
    try {
        const client = await getReadyE2eeClient();
        if (client) await client.setRoomPolicy(roomId, { expirySeconds: normalizeExpiry(seconds) });
    } catch (err) {
        console.warn('E2EE: не удалось передать срок хранения ключам комнаты:', err);
    }
}

// Раз в час и при открытии комнаты: хранение ключей (срок, цепочки без prev.final, бюджет)
// по всем комнатам из списка чатов; для комнат со сроком заодно сверяется сам срок.
const ROOM_KEYS_MAINTENANCE_MS = 60 * 60 * 1000;
let roomKeysMaintenanceTimer = null;
let roomKeysFirstRunTimer = null;

async function maintainAllRoomKeys() {
    if (!currentUser || e2eeState !== 'ready') return;
    const client = getE2eeClient();
    if (!client) return;
    for (const chat of chatListData.slice()) {
        if (chat.room_id == null) continue;
        try {
            await client.setRoomPolicy(chat.room_id, { expirySeconds: normalizeExpiry(chat.expiry_seconds) });
            await client.maintainRoomKeys(chat.room_id);
        } catch (err) {
            console.warn('E2EE: обслуживание ключей комнаты не удалось:', err);
        }
    }
}

function startRoomKeysMaintenance() {
    stopRoomKeysMaintenance();
    roomKeysFirstRunTimer = setTimeout(maintainAllRoomKeys, 20 * 1000); // к этому времени список чатов уже загружен
    roomKeysMaintenanceTimer = setInterval(maintainAllRoomKeys, ROOM_KEYS_MAINTENANCE_MS);
}

function stopRoomKeysMaintenance() {
    clearTimeout(roomKeysFirstRunTimer);
    clearInterval(roomKeysMaintenanceTimer);
    roomKeysFirstRunTimer = null;
    roomKeysMaintenanceTimer = null;
    clearPendingKeyRequests();
}
// ---- «Не хранить историю на этом устройстве» (план криптографии, раздел 6) ----
//
// Настройка личная и живёт в хранилище ключей устройства. Пока она включена, ключи
// сообщений комнаты стираются, когда комнату перестают смотреть: уход в другой чат,
// закрытие или скрытие вкладки (дольше 5 минут). Страховка на случай упавшей вкладки —
// клиент забывает такие комнаты при первом init() следующего запуска.

const HISTORY_HIDDEN_FORGET_MS = 5 * 60 * 1000;
const roomHistoryModes = new Map();   // roomId → 'keep' | 'none' (что вкладка знает о комнатах)
let hiddenForgetTimer = null;

function roomHistoryMode(roomId) {
    return roomId ? (roomHistoryModes.get(Number(roomId)) || 'keep') : 'keep';
}

// Читает режим комнаты из хранилища ключей и запоминает его.
async function loadRoomHistoryMode(roomId) {
    if (!roomId) return 'keep';
    try {
        const client = await getSettledE2eeClient();
        if (client) roomHistoryModes.set(Number(roomId), await client.getRoomHistoryMode(roomId));
    } catch (err) {
        console.warn('E2EE: не удалось прочитать режим хранения истории:', err);
    }
    return roomHistoryMode(roomId);
}

// Включает или выключает режим. Включение забывает историю сразу (клиент), выключение
// удалённое не возвращает. Бросает ошибку, если сохранить настройку не удалось.
async function applyRoomHistoryMode(roomId, mode) {
    const client = await getSettledE2eeClient();
    if (!client) throw new Error('сквозное шифрование недоступно');
    const saved = await client.setRoomHistoryMode(roomId, mode);
    roomHistoryModes.set(Number(roomId), saved);
    return saved;
}

// Забывает историю комнаты на этом устройстве, если для неё включено «не хранить».
async function forgetRoomIfNoHistory(roomId) {
    if (!roomId || roomHistoryMode(roomId) !== 'none') return false;
    try {
        const client = await getSettledE2eeClient();
        if (!client) return false;
        await client.forgetRoomHistory(roomId);
        return true;
    } catch (err) {
        console.warn('E2EE: не удалось забыть историю комнаты:', err);
        return false;
    }
}

// Вкладка скрыта дольше 5 минут — забываем историю открытой комнаты; вернулись — отсчёт сброшен.
function onHistoryVisibilityChange(hidden) {
    clearTimeout(hiddenForgetTimer);
    hiddenForgetTimer = null;
    if (!hidden) return;
    hiddenForgetTimer = setTimeout(() => { forgetRoomIfNoHistory(currentRoomId); }, HISTORY_HIDDEN_FORGET_MS);
}

// Закрытие страницы (pagehide). Запись в IndexedDB на выгрузке не гарантирована, поэтому
// есть страховка: init() следующего запуска забывает такие комнаты.
function forgetOpenRoomOnPageHide() {
    forgetRoomIfNoHistory(currentRoomId);
}

// Подряд идущие сообщения с историей, которой нет на устройстве, сворачиваются в одну
// служебную строку вместо десятков серых пузырей: возвращает группы индексов (по две и
// более подряд). Одиночное сообщение остаётся обычным пузырём.
function historyGapRuns(messages) {
    const runs = [];
    let run = [];
    const close = () => { if (run.length >= 2) runs.push(run); run = []; };
    messages.forEach((message, index) => {
        if (message && message._historyNotKept) run.push(index);
        else close();
    });
    close();
    return runs;
}
// <<< e2ee-room-keys
