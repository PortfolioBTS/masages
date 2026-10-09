// Политика типов вложений на клиенте: чистые функции без DOM, одинаково
// работающие в браузере и в Node. Поэтому их проверяют юнит-тесты
// (test/mime-policy.test.js), а script.js, который в Node не запускается,
// только вызывает их.
//
// Свой список, а не SUPPORTED_TYPES санитайзера: санитайзер отвечает на
// вопрос «умею ли я чистить этот формат», а здесь — «можно ли такое
// отправлять». Если в санитайзер когда-нибудь добавят ещё один формат,
// отправка его не включится сама: тип нужно сознательно дописать сюда и в
// серверный ALLOWED_MIME_TYPES (lib/security-utils.js). Списки обязаны
// совпадать — это проверяет тест.
//
// Звук мессенджер не принимает вовсе: ни вложений, ни плеера, ни записи.
// В E2EE-комнате сервер видит только шифротекст (application/octet-stream)
// и тип проверить не может, так что для зашифрованных вложений этот список —
// единственная преграда, и ставит её отправитель. Получатель типу из
// конверта не доверяет (safeBlobMime): его задаёт любой участник комнаты.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MimePolicy = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Только фото, видео, PDF и TXT. Порядок — как в ALLOWED_MIME_TYPES сервера.
    const ALLOWED_UPLOAD_MIMES = Object.freeze([
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'video/mp4', 'video/webm', 'video/quicktime',
        'application/pdf', 'text/plain',
    ]);
    const ALLOWED_SET = new Set(ALLOWED_UPLOAD_MIMES);

    // Браузеры и ОС называют один формат по-разному (File.type у JPEG бывает
    // image/jpeg, image/jpg и image/pjpeg). Синоним приводится к каноническому
    // типу сразу при определении типа файла, а дальше везде сравнивается
    // только точная строка из списка.
    const MIME_ALIASES = Object.freeze({
        'image/jpg': 'image/jpeg',
        'image/pjpeg': 'image/jpeg',
    });

    // Обезличенные имена — те же, что у сервера для незашифрованных вложений
    // (ANONYMIZED_FILE_NAMES в lib/security-utils.js): исходное имя файла
    // часто содержит имя человека, дату, номер телефона.
    const ANONYMOUS_FILE_NAMES = Object.freeze({
        'image/jpeg': 'photo.jpg',
        'image/png': 'photo.png',
        'image/gif': 'photo.gif',
        'image/webp': 'photo.webp',
        'video/mp4': 'video.mp4',
        'video/webm': 'video.webm',
        'video/quicktime': 'video.mov',
        'application/pdf': 'document.pdf',
        'text/plain': 'text.txt',
    });
    const FALLBACK_FILE_NAME = 'file';

    // Тип «непонятных байтов»: браузер не станет ни показывать, ни исполнять
    // такой blob.
    const OPAQUE_BLOB_MIME = 'application/octet-stream';

    function hasOwn(object, key) {
        return Object.prototype.hasOwnProperty.call(object, key);
    }

    // 'Image/JPG; x=1' → 'image/jpeg': регистр, параметры, синонимы. Это ещё
    // не разрешение — разрешает только isAllowedUpload.
    function normalizeMime(mime) {
        if (typeof mime !== 'string') return '';
        const base = mime.split(';')[0].trim().toLowerCase();
        return hasOwn(MIME_ALIASES, base) ? MIME_ALIASES[base] : base;
    }

    // Тип выбранного или перетащенного файла (объект с полями type и name).
    // Пустой File.type бывает у .txt и .pdf на части систем — его добираем
    // по расширению. У остального пустой тип так и остаётся пустым, то есть
    // вне списка: по расширению других типов не угадываем.
    function detectFileMime(file) {
        let mime = normalizeMime(file && file.type);
        if (!mime) {
            const name = String((file && file.name) || '').toLowerCase();
            if (name.endsWith('.txt')) mime = 'text/plain';
            else if (name.endsWith('.pdf')) mime = 'application/pdf';
        }
        return mime;
    }

    // Строгое сравнение: регистр, параметры и синонимы не прощаются. Тот, кто
    // получил тип не из detectFileMime, приводит его к каноническому виду
    // сам (normalizeMime) или не доверяет ему вовсе (safeBlobMime).
    function isAllowedUpload(mime) {
        return typeof mime === 'string' && ALLOWED_SET.has(mime);
    }

    // Фото и видео показываются в ленте прямо в сообщении, документы —
    // ссылкой на скачивание. Только они получают обезличенное имя даже
    // внутри E2EE-конверта.
    function isMediaMime(mime) {
        return typeof mime === 'string' && /^(image|video)\//.test(mime);
    }

    function anonymousFileName(mime) {
        return typeof mime === 'string' && hasOwn(ANONYMOUS_FILE_NAMES, mime)
            ? ANONYMOUS_FILE_NAMES[mime]
            : FALLBACK_FILE_NAME;
    }

    // Тип для blob: URL расшифрованного вложения. blob: живёт в origin
    // приложения, и, например, text/html в нём был бы готовой XSS, поэтому
    // всё вне списка отдаётся как непрозрачные байты.
    function safeBlobMime(mime) {
        return isAllowedUpload(mime) ? mime : OPAQUE_BLOB_MIME;
    }

    // Имя иконки из public/icons.js: для списка отправляемых файлов и ссылок
    // на документы. Всё, чего нет в списке ниже, — обычный «файл».
    function fileIconName(mime) {
        if (typeof mime !== 'string') return 'file';
        if (mime.startsWith('image/')) return 'image';
        if (mime.startsWith('video/')) return 'video';
        if (mime === 'text/plain' || mime === 'application/pdf') return 'file-text';
        return 'file';
    }

    return {
        ALLOWED_UPLOAD_MIMES,
        MIME_ALIASES,
        ANONYMOUS_FILE_NAMES,
        normalizeMime,
        detectFileMime,
        isAllowedUpload,
        isMediaMime,
        anonymousFileName,
        safeBlobMime,
        fileIconName,
    };
});
