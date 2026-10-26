// public/js/16-files-composer.js — файлы: выбор, перетаскивание, очередь отправки; кнопка «вниз».
// Вынесено из public/script.js (строки 6269–6641 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Файлы: выбор, перетаскивание, очередь отправки ====================
// Каждое вложение: проверка типа по белому списку → удаление метаданных на
// клиенте (сервер при открытой отправке снимает их ещё раз, но исходные
// EXIF/GPS так до него вообще не доходят) → в E2EE-комнате шифрование
// файла, а ключ файла, MIME и имя — внутри E2EE-конверта сообщения →
// загрузка с прогрессом. Несколько файлов уходят строго по очереди: так
// порядок в ленте совпадает с порядком выбора, а память не забивается
// несколькими большими файлами сразу.

let chosenFiles = [];          // [{ file, mime, error }] — содержимое окна «Отправить N файлов»
let chosenFilesChat = null;    // { chatId, roomId } — для какого чата они выбраны
let uploadQueue = null;        // { chatId, roomId, xhr, cancelled } — идёт отправка

function describeFile(file) {
    const mime = MimePolicy.detectFileMime(file);
    let error = '';
    if (!isSupportedMime(mime)) error = 'такой тип файлов не поддерживается (можно фото, видео, PDF и TXT)';
    else if (file.size > MAX_UPLOAD_BYTES) error = 'больше 50 МБ';
    else if (file.size === 0) error = 'пустой файл';
    return { file, mime, error };
}

// Имя, под которым файл увидят собеседники: у фото и видео — всегда
// обезличенное; у документа в E2EE-комнате — исходное (оно внутри конверта,
// сервер его не видит), без E2EE сервер тоже получает обезличенное.
function outgoingFileName(file, mime, encrypted) {
    return encrypted ? encryptedFileName(file, mime) : MimePolicy.anonymousFileName(mime);
}

function onFilesChosen(files) {
    if (!currentChatId || files.length === 0) return;
    if (composerDisabledReason) {
        showToast(composerDisabledReason, 'error', 6000);
        return;
    }
    if (uploadQueue) {
        showToast('Дождитесь окончания загрузки', 'info');
        return;
    }
    let list = files;
    if (list.length > MAX_FILES_PER_BATCH) {
        showToast(`За один раз можно отправить до ${MAX_FILES_PER_BATCH} файлов — лишние не добавлены`, 'info', 5000);
        list = list.slice(0, MAX_FILES_PER_BATCH);
    }
    chosenFiles = list.map(describeFile);
    chosenFilesChat = { chatId: currentChatId, roomId: currentRoomId };
    renderSendFilesList();
    openModal(elements.sendFilesModal);
}

function renderSendFilesList() {
    const target = chosenFilesChat;
    const encrypted = Boolean(target && target.roomId);
    const valid = chosenFiles.filter(f => !f.error).length;
    elements.sendFilesTitle.textContent = valid > 0
        ? `Отправить ${valid} ${plural(valid, ['файл', 'файла', 'файлов'])}`
        : 'Нечего отправить';
    const rows = chosenFiles.map((item, index) => {
        const li = document.createElement('li');
        li.className = 'send-file-row' + (item.error ? ' muted' : '');
        const info = document.createElement('div');
        const name = document.createElement('div');
        // У отклонённого файла показываем исходное имя — иначе не понять,
        // какой именно не подошёл; оно никуда не отправляется.
        name.textContent = item.error ? safeDisplayName(item.file.name) : outgoingFileName(item.file, item.mime, encrypted);
        const meta = document.createElement('small');
        meta.className = item.error ? 'field-hint' : 'muted';
        meta.textContent = item.error
            ? `${formatFileSize(item.file.size)} · не будет отправлен: ${item.error}`
            : formatFileSize(item.file.size);
        info.append(name, meta);
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'icon-btn icon-btn-sm';
        remove.title = 'Убрать из списка';
        remove.setAttribute('aria-label', `Убрать ${name.textContent} из списка`);
        remove.appendChild(icon('x', { size: 'sm' }));
        remove.addEventListener('click', () => {
            chosenFiles.splice(index, 1);
            if (chosenFiles.length === 0) {
                chosenFilesChat = null;
                closeModal(elements.sendFilesModal);
                return;
            }
            renderSendFilesList();
            const next = elements.sendFilesList.querySelectorAll('.send-file-row .icon-btn')[Math.min(index, chosenFiles.length - 1)];
            (next || elements.sendFilesBtn).focus({ preventScroll: true });
        });
        li.append(icon(item.error ? 'alert-triangle' : MimePolicy.fileIconName(item.mime)), info, remove);
        return li;
    });
    elements.sendFilesList.replaceChildren(...rows);
    elements.sendFilesBtn.disabled = valid === 0;
    setIconLabel(elements.sendFilesBtn, 'send', valid > 1 ? `Отправить ${valid}` : 'Отправить');
}

function sendChosenFiles() {
    const items = chosenFiles.filter(f => !f.error);
    const target = chosenFilesChat;
    chosenFiles = [];
    chosenFilesChat = null;
    closeModal(elements.sendFilesModal);
    if (!target || items.length === 0) return;
    if (target.chatId !== currentChatId) {
        showToast('Чат сменился — выберите файлы заново', 'error');
        return;
    }
    runUploadQueue(target.chatId, target.roomId, items);
}

async function runUploadQueue(chatId, roomId, items) {
    const queue = { chatId, roomId, xhr: null, cancelled: false };
    uploadQueue = queue;
    elements.attachBtn.disabled = true;
    let sent = 0;
    const errors = [];
    try {
        for (let i = 0; i < items.length && !queue.cancelled; i++) {
            let result;
            try {
                result = await sendOneFile(queue, items[i], i, items.length);
            } catch (err) {
                console.error('File upload failed:', err);
                result = { ok: false, message: 'Не удалось отправить файл' };
            }
            if (queue.cancelled) break;
            if (result.ok) {
                sent++;
            } else {
                errors.push(result.message || 'Не удалось отправить файл');
                // Шифрование недоступно — остальным файлам будет то же самое.
                if (result.fatal) break;
            }
        }
    } finally {
        if (uploadQueue === queue) uploadQueue = null;
        updateComposerForChat();
        hideUploadStatus();
    }
    const total = items.length;
    if (queue.cancelled) {
        if (queue.silent) return;
        showToast(sent > 0 ? `Загрузка отменена. Отправлено: ${sent} из ${total}` : 'Загрузка отменена', 'info');
    } else if (errors.length > 0) {
        const head = total > 1 ? `Не отправлено файлов: ${total - sent} из ${total}. ` : '';
        showToast(head + errors[errors.length - 1], 'error', 6000);
    } else if (total > 1) {
        showToast(`Отправлено ${sent} ${plural(sent, ['файл', 'файла', 'файлов'])}`, 'success');
    }
}

// Отказ при отправке файла. Таймаут — исход неизвестен, но в отличие от текста (unknownSend) запрос файла не
// запоминается: повтор шифрует файл заново под новым clientMessageId, и если первый дошёл, будет второе сообщение.
// Поэтому обещания «дубликата не будет» здесь нет (повторное ревью W7, RR-4).
function fileSendFailureText(data) {
    if (data.timedOut) return 'Сервер не ответил — файл мог быть отправлен. Проверьте ленту, прежде чем отправлять его снова';
    return sendFailureText(data, 'Не удалось отправить файл');
}

async function sendOneFile(queue, item, index, total) {
    const { chatId, roomId } = queue;
    const prefix = total > 1 ? `Файл ${index + 1} из ${total}: ` : '';
    setUploadStatus(`${prefix}подготовка…`, null);
    let client;
    try {
        client = await prepareOutgoing(chatId, roomId);
    } catch (err) {
        if (!(err instanceof E2eeBlockedError)) throw err;
        if (roomId && err.showsRetry) setRoomBlock(chatId, err.message);
        return { ok: false, fatal: true, message: err.message };
    }
    if (queue.cancelled) return { ok: false };

    setUploadStatus(`${prefix}удаление метаданных…`, null);
    let clean;
    try {
        clean = MediaSanitizer.sanitize(new Uint8Array(await item.file.arrayBuffer()), item.mime);
    } catch (err) {
        console.warn('MediaSanitizer: файл отклонён:', err);
        // userFacing — отказ с понятной пользователю причиной и советом (например,
        // PDF со сжатыми метаданными: «Печать → Сохранить как PDF»).
        return { ok: false, message: err && err.userFacing ? err.message : 'Файл повреждён или его формат не поддерживается' };
    }
    if (queue.cancelled) return { ok: false };

    // Шифротекст вложения от id сообщения не зависит: при 409 заново
    // шифруется только конверт (с новым mid), тот же шифротекст загружается снова.
    let localFile = null;
    let enc = null;
    if (client) {
        setUploadStatus(`${prefix}шифрование…`, null);
        try {
            enc = await client.encryptFile(clean);
        } catch (err) {
            console.error('E2EE: не удалось зашифровать файл:', err);
            return { ok: false, message: 'Не удалось зашифровать файл' };
        }
        if (enc.ciphertext.byteLength > MAX_UPLOAD_BYTES) {
            return { ok: false, message: 'Файл слишком большой для отправки с шифрованием (макс. 50 МБ)' };
        }
        localFile = { mime: item.mime, name: encryptedFileName(item.file, item.mime), size: enc.size, key: enc.key, iv: enc.iv };
    }
    if (queue.cancelled) return { ok: false };

    let encryptFailed = false;
    const outcome = await sendWithOutcomes({
        roomId,
        shouldStop: () => queue.cancelled,
        buildRequest: async (clientMessageId) => {
            const formData = new FormData();
            // Порядок полей важен: сервер читает proto/chatId/encrypted/clientMessageId/
            // envelope ДО того, как начнёт принимать сам файл (fileFilter), и проверяет
            // их раньше, чем файл попадёт на диск. Поле после файла — 400 client-outdated.
            formData.append('proto', String(PROTO_VERSION)); // признак версии - первым, до файла (14.1)
            formData.append('chatId', String(chatId));
            if (client) formData.append('encrypted', 'true');
            if (clientMessageId) formData.append('clientMessageId', clientMessageId);
            if (client) {
                try {
                    const envelope = await encryptForRoom(client, chatId, roomId, { type: 'file', ...localFile, caption: '' }, { messageId: clientMessageId });
                    formData.append('envelope', envelope);
                } catch (err) {
                    console.error('E2EE: не удалось зашифровать файл:', err);
                    encryptFailed = true;
                    return null;
                }
                formData.append('file', new Blob([enc.ciphertext], { type: 'application/octet-stream' }), 'blob');
            } else {
                formData.append('file', new Blob([clean], { type: item.mime }), MimePolicy.anonymousFileName(item.mime));
            }
            return formData;
        },
        post: async (formData) => {
            setUploadStatus(`${prefix}загрузка…`, 0);
            const result = await postFormDataWithProgress('/api/messages/file', formData, {
                onXhr: (xhr) => { queue.xhr = xhr; },
                onProgress: (p) => {
                    if (!queue.cancelled) setUploadStatus(`${prefix}загрузка ${Math.round(p * 100)}%`, p);
                },
            });
            queue.xhr = null;
            return result;
        },
    });
    if (encryptFailed) return { ok: false, message: 'Не удалось зашифровать файл' };
    const data = outcome.data;
    if (data.aborted || queue.cancelled) return { ok: false };
    if (!data.success) return { ok: false, message: fileSendFailureText(data) };
    checkRoomKeyRotation(chatId, roomId);
    if (chatId === currentChatId && data.message) {
        const message = localFile
            ? { ...data.message, text: '', _file: localFile, _localBytes: clean }
            : data.message;
        if (appendMessage(message, true)) scrollToBottom();
        updateChatListOnMessage(message, true);
    }
    return { ok: true };
}

function setUploadStatus(text, progress) {
    elements.uploadStatus.classList.remove('hidden');
    elements.uploadStatusText.textContent = text;
    const pct = progress == null ? 0 : Math.max(0, Math.min(100, Math.round(progress * 100)));
    elements.uploadProgressBar.style.width = `${pct}%`;
    elements.uploadProgress.setAttribute('aria-valuenow', String(pct));
    if (progress == null) elements.uploadProgress.removeAttribute('aria-valuenow');
}

function hideUploadStatus() {
    elements.uploadStatus.classList.add('hidden');
    elements.uploadStatusText.textContent = '';
    elements.uploadProgressBar.style.width = '0%';
}

// byUser — нажата «Отменить»: итог покажет runUploadQueue. Иначе (выход из
// аккаунта) — тихо.
function cancelUploadQueue(byUser) {
    const queue = uploadQueue;
    if (!queue) return;
    queue.cancelled = true;
    queue.silent = !byUser;
    if (queue.xhr) {
        try { queue.xhr.abort(); } catch { /* запрос уже завершён */ }
    }
}

// ---- Перетаскивание файлов в ленту ----

let dragDepth = 0;

function dragHasFiles(e) {
    const types = e.dataTransfer && e.dataTransfer.types;
    return Boolean(types) && Array.from(types).includes('Files');
}

function canDropFiles() {
    return Boolean(currentUser && currentChatId) && !document.querySelector('.modal:not(.hidden)');
}

function showDropZone() {
    elements.dropZone.classList.remove('hidden');
    elements.dropZone.classList.add('is-active');
}

function hideDropZone() {
    dragDepth = 0;
    elements.dropZone.classList.add('hidden');
    elements.dropZone.classList.remove('is-active');
}

function setupDragAndDrop() {
    const area = elements.mainContent;
    area.addEventListener('dragenter', (e) => {
        if (!dragHasFiles(e) || !canDropFiles()) return;
        e.preventDefault();
        dragDepth++;
        showDropZone();
    });
    area.addEventListener('dragover', (e) => {
        if (!dragHasFiles(e) || !canDropFiles()) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
    });
    area.addEventListener('dragleave', (e) => {
        if (!dragHasFiles(e)) return;
        dragDepth = Math.max(0, dragDepth - 1);
        if (dragDepth === 0) hideDropZone();
    });
    area.addEventListener('drop', (e) => {
        if (!dragHasFiles(e)) return;
        e.preventDefault();
        const files = Array.from((e.dataTransfer && e.dataTransfer.files) || []);
        hideDropZone();
        if (canDropFiles()) onFilesChosen(files);
    });
    // Файл, брошенный мимо ленты, браузер открыл бы вместо приложения.
    window.addEventListener('dragover', (e) => {
        if (!dragHasFiles(e)) return;
        e.preventDefault();
        if (!area.contains(e.target) || !canDropFiles()) e.dataTransfer.dropEffect = 'none';
    });
    window.addEventListener('drop', (e) => {
        if (!dragHasFiles(e)) return;
        e.preventDefault();
        hideDropZone();
    });
}

// ---- Кнопка «вниз» ----
// Видна, пока пользователь прокручен вверх; бейдж — сколько новых чужих
// сообщений пришло за это время.
let jumpDownCount = 0;

function renderJumpDownBadge() {
    const n = jumpDownCount;
    elements.jumpDownBadge.classList.toggle('hidden', n === 0);
    elements.jumpDownBadge.textContent = n > 99 ? '99+' : String(n);
    const label = n > 0 ? `К последним сообщениям, новых: ${n}` : 'К последним сообщениям';
    elements.jumpDown.title = label;
    elements.jumpDown.setAttribute('aria-label', label);
}

function updateJumpDown() {
    const show = Boolean(currentChatId) && !isNearBottom();
    if (!show) jumpDownCount = 0;
    elements.jumpDown.classList.toggle('hidden', !show);
    renderJumpDownBadge();
}

function bumpJumpDown() {
    jumpDownCount++;
    elements.jumpDown.classList.remove('hidden');
    renderJumpDownBadge();
}

function resetJumpDown() {
    jumpDownCount = 0;
    elements.jumpDown.classList.add('hidden');
    renderJumpDownBadge();
}
