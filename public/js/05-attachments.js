// public/js/05-attachments.js — файлы: белый список, очистка, шифрование и ленивая расшифровка вложений.
// Вынесено из public/script.js (строки 1634–1822 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Файлы: белый список, очистка, шифрование ====================
// Какие типы можно отправлять, как их распознавать, называть и показывать —
// решает public/lib/mime-policy.js (MimePolicy): он подключён до этого
// файла и проверяется юнит-тестами. Здесь только то, что связывает политику
// с санитайзером.

// Отправить можно то, что и разрешено политикой, и умеет чистить санитайзер.
// Списки независимы: формат, которому санитайзер научился, сам по себе
// отправку не включит (его нет в политике), а тип из политики, который
// санитайзер чистить не умеет, в очередь не попадёт. Вторая страховка —
// sendOneFile: MediaSanitizer.sanitize бросает исключение на неизвестном типе.
function isSupportedMime(mime) {
    return MimePolicy.isAllowedUpload(mime)
        && typeof MediaSanitizer !== 'undefined' && Array.isArray(MediaSanitizer.SUPPORTED_TYPES)
        && MediaSanitizer.SUPPORTED_TYPES.includes(mime);
}

// Имя внутри E2EE-конверта: у фото и видео — обезличенное, у документов —
// исходное (без него документ не отличить от других), но сервер его не
// видит — только участники комнаты.
function encryptedFileName(file, mime) {
    return MimePolicy.isMediaMime(mime)
        ? MimePolicy.anonymousFileName(mime)
        : safeDisplayName(file.name || MimePolicy.anonymousFileName(mime));
}

// ---- Расшифровка вложений: лениво и не больше двух за раз ----

const MAX_PARALLEL_FILE_DECRYPTS = 2;
const objectUrls = new Map();   // messageId -> blob: URL (отзываются при удалении сообщения и смене чата)
const attachmentQueue = [];
let attachmentsActive = 0;
let attachmentObserver = null;

function registerObjectUrl(messageId, url) {
    revokeObjectUrl(messageId);
    objectUrls.set(String(messageId), url);
}

function revokeObjectUrl(messageId) {
    const url = objectUrls.get(String(messageId));
    if (url) {
        URL.revokeObjectURL(url);
        objectUrls.delete(String(messageId));
    }
}

function revokeAllObjectUrls() {
    objectUrls.forEach(url => URL.revokeObjectURL(url));
    objectUrls.clear();
}

function getAttachmentObserver() {
    if (attachmentObserver || typeof IntersectionObserver === 'undefined') return attachmentObserver;
    attachmentObserver = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (!entry.isIntersecting) return;
            attachmentObserver.unobserve(entry.target);
            enqueueAttachmentDecrypt(entry.target);
        });
    }, { root: elements.chatMessages, rootMargin: '300px 0px' });
    return attachmentObserver;
}

function enqueueAttachmentDecrypt(box) {
    attachmentQueue.push(box);
    pumpAttachmentQueue();
}

function pumpAttachmentQueue() {
    while (attachmentsActive < MAX_PARALLEL_FILE_DECRYPTS && attachmentQueue.length > 0) {
        const box = attachmentQueue.shift();
        if (!box.isConnected || !box._attachment || box._attachment.seq !== openChatSeq) continue;
        attachmentsActive++;
        decryptAttachment(box).finally(() => {
            attachmentsActive--;
            pumpAttachmentQueue();
        });
    }
}

function resetAttachmentDecrypts() {
    attachmentQueue.length = 0;
    if (attachmentObserver) attachmentObserver.disconnect();
    revokeAllObjectUrls();
}

function setAttachmentStatus(box, text, failed) {
    const span = failed
        ? iconText('span', 'attachment-status e2ee-failed', 'lock', text, { size: 'sm' })
        : iconText('span', 'attachment-status attachment-loading', 'loader', text, { size: 'sm', className: 'spin' });
    box.replaceChildren(span);
}

function createDocumentLink(url, name, mime, extra = {}) {
    const wrapper = document.createElement('div');
    wrapper.className = 'file-attachment';
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    if (extra.newTab) {
        a.target = '_blank';
        a.rel = 'noopener';
    }
    const label = document.createElement('span');
    label.textContent = name;
    a.append(icon(MimePolicy.fileIconName(mime)), label, icon('download', { size: 'sm' }));
    wrapper.appendChild(a);
    return wrapper;
}

function createMediaElement(mime, url, name) {
    if (mime.startsWith('image/')) {
        const img = document.createElement('img');
        img.src = url;
        img.className = 'message-image';
        img.decoding = 'async';
        img.alt = name || 'Изображение';
        img.addEventListener('click', () => window.open(url, '_blank', 'noopener'));
        return img;
    }
    if (mime.startsWith('video/')) {
        const video = document.createElement('video');
        video.src = url;
        video.controls = true;
        video.preload = 'metadata';
        video.className = 'message-video';
        return video;
    }
    // Документы только скачиваются (download), а не открываются во вкладке.
    return createDocumentLink(url, name, mime);
}

function showDecryptedAttachment(box, message, bytes) {
    const file = message._file;
    const mime = MimePolicy.safeBlobMime(file.mime);
    const name = safeDisplayName(file.name || MimePolicy.anonymousFileName(mime));
    const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
    registerObjectUrl(message.id, url);
    const stick = isNearBottom();
    const media = createMediaElement(mime, url, name);
    // Картинка меняет высоту ленты после загрузки — если пользователь был
    // внизу, остаёмся внизу.
    if (stick && media.tagName === 'IMG') media.addEventListener('load', () => scrollToBottom(), { once: true });
    box.replaceChildren(media);
    box.classList.add('decrypted');
}

async function decryptAttachment(box) {
    const { message, seq } = box._attachment;
    const file = message._file;
    try {
        const client = await getSettledE2eeClient();
        if (!client) throw new Error('E2EE-клиент недоступен');
        const res = await fetch(message.file_url, { credentials: 'same-origin' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const ciphertext = new Uint8Array(await res.arrayBuffer());
        const plain = await client.decryptFile(ciphertext, file.key, file.iv, file.size);
        if (seq !== openChatSeq || !box.isConnected) return; // чат уже сменили — object URL не создаём
        showDecryptedAttachment(box, message, plain);
    } catch (err) {
        console.warn('E2EE: не удалось расшифровать вложение:', err);
        if (seq === openChatSeq && box.isConnected) setAttachmentStatus(box, 'Не удалось расшифровать файл', true);
    }
}

function createEncryptedAttachmentElement(message) {
    const box = document.createElement('div');
    box.className = 'encrypted-attachment';
    if (!message.file_url) {
        setAttachmentStatus(box, 'Не удалось расшифровать файл', true);
        return box;
    }
    box._attachment = { message, seq: openChatSeq };
    if (message._localBytes) {
        // Своё только что отправленное вложение: исходные (уже очищенные)
        // байты есть в памяти — повторно скачивать и расшифровывать незачем.
        const bytes = message._localBytes;
        delete message._localBytes;
        showDecryptedAttachment(box, message, bytes);
        return box;
    }
    setAttachmentStatus(box, `Загрузка файла «${safeDisplayName(message._file.name)}»…`, false);
    const observer = getAttachmentObserver();
    if (observer) observer.observe(box);
    else setTimeout(() => enqueueAttachmentDecrypt(box), 0);
    return box;
}
