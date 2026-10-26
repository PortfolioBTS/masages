// Приглашение в группу: разбор того, что человек вставил в поле «Ссылка или
// код приглашения», и вид кода для показа. Плюс проверка onion-адреса,
// который сервер отдаёт для ссылки «Открыть через Tor».
//
// Чистые функции без DOM и сети: файл исполняется и в браузере
// (window.NyxoInvite), и в Node (test/client-lib.test.js).
//
// Что принимает поле приглашения (контракт волны 1, docs/dev/contracts/stage-1.md, §5):
//   - полную ссылку с любого origin: https://…/#join=КОД или #join=КОД.СЕКРЕТ
//     (у фрагмента могут быть и другие параметры через &);
//   - «join=КОД» — часть ссылки;
//   - сам КОД: 26 символов алфавита ABCDEFGHJKLMNPQRSTUVWXYZ23456789. Пробелы,
//     дефисы и тире игнорируются, регистр не важен — ровно так нормализует код
//     и сервер (normalizeInviteCode в lib/security-utils.js).
// СЕКРЕТ — 22 символа base64url. Он нужен подписанному составу группы
// (docs/security/signed-membership.md): по нему клиент подписывает вход без
// одобрения. Разбор лишь сохраняет его и возвращает как есть. На сервер секрет не
// отправляется — он подтверждает приглашение участникам группы, а не серверу.
//
// Формат проверяется ДО создания аккаунта: битый код не должен стоить
// человеку PoW-проверки и лишнего аккаунта.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoInvite = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const CODE_LENGTH = 26;
    const SECRET_LENGTH = 22;

    const CODE_RE = new RegExp(`^[${CODE_ALPHABET}]{${CODE_LENGTH}}$`);
    const SECRET_RE = new RegExp(`^[A-Za-z0-9_-]{${SECRET_LENGTH}}$`);

    // Разделители, которыми код делят на группы при показе и диктовке: те же,
    // что выбрасывает сервер (пробельные символы, дефис, тире U+2010–U+2015).
    const CODE_SEPARATORS_RE = /[\s\-‐-―]+/g;

    // Знаки, которые прилипают к ссылке, скопированной из конца фразы («вот
    // ссылка: …#join=КОД.»). В коде и секрете их не бывает.
    const TRAILING_PUNCTUATION_RE = /[\s.,;:!?)\]}»"'’”…]+$/;

    // Ссылка с секретом короче 200 символов на любом разумном домене; длинная
    // строка — точно не приглашение, разбирать её незачем.
    const MAX_INPUT_LENGTH = 2048;

    function fail(reason) {
        return { ok: false, reason };
    }

    // Значение параметра join из фрагмента или строки «join=…»; null — такого
    // параметра нет. Параметры фрагмента разделены &, имя — без учёта регистра.
    function joinParam(text) {
        for (const part of text.split('&')) {
            const eq = part.indexOf('=');
            if (eq < 0) continue;
            if (part.slice(0, eq).trim().toLowerCase() === 'join') return part.slice(eq + 1);
        }
        return null;
    }

    function decode(value) {
        try {
            return decodeURIComponent(value);
        } catch {
            return null; // битая %-последовательность
        }
    }

    // parseInviteInput(raw) → { ok: true, code, secret } | { ok: false, reason }.
    // code — 26 символов без разделителей, в верхнем регистре; secret — строка
    // из 22 символов или null. reason: 'empty' — поле пустое; 'format' — это
    // не приглашение (или ссылка повреждена).
    function parseInviteInput(raw) {
        const text = typeof raw === 'string' ? raw.trim() : '';
        if (!text) return fail('empty');
        if (text.length > MAX_INPUT_LENGTH) return fail('format');
        const value = text.replace(TRAILING_PUNCTUATION_RE, '');

        let candidate;
        const hash = value.indexOf('#');
        if (hash >= 0) {
            // Ссылка: всё до # (origin, путь, query) не важно — приглашение
            // живёт только во фрагменте, который браузер не шлёт на сервер.
            candidate = joinParam(value.slice(hash + 1));
        } else if (/^join=/i.test(value)) {
            candidate = joinParam(value);
        } else {
            candidate = value;
        }
        if (candidate === null) return fail('format');
        candidate = decode(candidate);
        if (candidate === null) return fail('format');

        const dot = candidate.indexOf('.');
        const codePart = dot >= 0 ? candidate.slice(0, dot) : candidate;
        // В секрете (base64url) дефис — значащий символ, выбрасываем только
        // пробельные: они появляются, когда длинную ссылку переносят по строкам.
        const secretPart = dot >= 0 ? candidate.slice(dot + 1).replace(/\s+/g, '') : '';

        const code = codePart.replace(CODE_SEPARATORS_RE, '').toUpperCase();
        if (!CODE_RE.test(code)) return fail('format');
        if (secretPart && !SECRET_RE.test(secretPart)) return fail('format');
        return { ok: true, code, secret: secretPart || null };
    }

    // Код группами по 5 символов: его диктуют и переписывают вручную, а сервер
    // и parseInviteInput пробелы между группами выбрасывают сами.
    function formatInviteCode(code) {
        return String(code || '').replace(CODE_SEPARATORS_RE, '').replace(/(.{5})(?=.)/g, '$1 ');
    }

    // Onion-адрес сервера из поля onionUrl ответа /api/auth (заголовок
    // Onion-Location скрипт прочитать не может). Принимается только v3-адрес
    // (56 символов base32); ссылка собирается заново из протокола и хоста —
    // всё прочее (путь, порт, учётные данные в URL) отбрасывается. null — адреса
    // нет или он не похож на onion-адрес: ссылку тогда не показываем.
    const ONION_HOST_RE = /^[a-z2-7]{56}\.onion$/;

    function parseOnionUrl(value) {
        if (typeof value !== 'string' || !value || value.length > 300) return null;
        let url;
        try {
            url = new URL(value);
        } catch {
            return null;
        }
        if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
        if (!ONION_HOST_RE.test(url.hostname)) return null;
        return `${url.protocol}//${url.hostname}/`;
    }

    return {
        CODE_ALPHABET,
        CODE_LENGTH,
        SECRET_LENGTH,
        parseInviteInput,
        formatInviteCode,
        parseOnionUrl,
    };
});
