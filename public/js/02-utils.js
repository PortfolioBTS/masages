// public/js/02-utils.js — иконки, мелкие утилиты и следы на устройстве.
// Вынесено из public/script.js (строки 263–533 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Разделы «Иконки», «Мелкие утилиты», «Следы на устройстве» (стирание локальных данных пользователя).
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Иконки ====================
// SVG-спрайт и Icons.icon() — из public/icons.js (подключён в <head>). Если
// он почему-то не загрузился, собираем ту же разметку сами: <use> на
// отсутствующий символ просто ничего не рисует, а подписи (aria-label,
// текст рядом) остаются — интерфейс не ломается.

function icon(name, options = {}) {
    if (window.Icons && typeof window.Icons.icon === 'function') {
        try {
            return window.Icons.icon(name, options);
        } catch { /* ниже — запасной вариант */ }
    }
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    const size = ['sm', 'md', 'lg', 'xl'].includes(options.size) ? options.size : 'md';
    svg.setAttribute('class', `icon icon-${size}${options.className ? ' ' + options.className : ''}`);
    if (options.label) {
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', options.label);
    } else {
        svg.setAttribute('aria-hidden', 'true');
    }
    const use = document.createElementNS(NS, 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.appendChild(use);
    return svg;
}

// Кнопка/пункт меню «иконка + подпись»: содержимое пересобирается целиком.
function setIconLabel(el, iconName, text, options = {}) {
    const span = document.createElement('span');
    span.textContent = text;
    el.replaceChildren(icon(iconName, options), span);
}

// Строка «иконка + текст» для служебных элементов (статусы, подписи).
function iconText(tag, className, iconName, text, options = {}) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    setIconLabel(el, iconName, text, options);
    return el;
}

// ==================== Мелкие утилиты ====================

// Не отменяет сам promise — только перестаёт его ждать. Нужна там, где
// зависший сетевой запрос не должен навсегда блокировать интерфейс.
function withTimeout(promise, ms, fallback) {
    let timer;
    return Promise.race([
        promise,
        new Promise(resolve => { timer = setTimeout(() => resolve(fallback), ms); }),
    ]).finally(() => clearTimeout(timer));
}

function formatShortDateTime(date) {
    const day = date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' });
    const time = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    return `${day} ${time}`;
}

function joinNames(members) {
    return members.map(m => m.username || `участник #${m.id}`).join(', ');
}

// Русские формы множественного числа: plural(5, ['файл', 'файла', 'файлов']).
function plural(n, forms) {
    const abs = Math.abs(n) % 100;
    const last = abs % 10;
    if (abs > 10 && abs < 20) return forms[2];
    if (last > 1 && last < 5) return forms[1];
    if (last === 1) return forms[0];
    return forms[2];
}

function parseDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

// «только что», «5 минут назад», «вчера»; старше недели — дата и время.
function formatRelativeTime(value) {
    const date = parseDate(value);
    if (!date) return '';
    const diffSec = Math.round((date.getTime() - Date.now()) / 1000);
    const abs = Math.abs(diffSec);
    if (abs < 45) return 'только что';
    if (abs >= 7 * 86400) return formatShortDateTime(date);
    let rtf = null;
    try {
        rtf = new Intl.RelativeTimeFormat('ru', { numeric: 'auto' });
    } catch { /* старый браузер — ниже запасной вариант */ }
    const [amount, unit, short] = abs < 3600 ? [Math.round(diffSec / 60), 'minute', 'мин']
        : abs < 86400 ? [Math.round(diffSec / 3600), 'hour', 'ч']
            : [Math.round(diffSec / 86400), 'day', 'дн.'];
    if (rtf) return rtf.format(amount, unit);
    return amount < 0 ? `${-amount} ${short} назад` : `через ${amount} ${short}`;
}

function formatFileSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return `${n} Б`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0).replace('.', ',')} КБ`;
    return `${(n / 1024 / 1024).toFixed(1).replace('.', ',')} МБ`;
}

// ==================== Следы на устройстве ====================
// Всё, что клиент хранит локально: ключи E2EE (IndexedDB nyxo-e2ee-<id>,
// удаляется через E2EE.deleteLocalData) и флаги пользователя в localStorage.
// Все аккаунты временные, поэтому при выходе (он же удаление) и после
// удаления аккаунта по сроку это должно исчезать вместе с сессией.
// Хранилище браузера может быть недоступно (окно инкогнито, запрет
// cookies) — отсюда try/catch вокруг каждого обращения: интерфейс должен
// работать и без него.

function readAnonIds() {
    try {
        const list = JSON.parse(localStorage.getItem(ANON_IDS_KEY) || '[]');
        return Array.isArray(list) ? list.map(Number).filter(id => Number.isInteger(id) && id > 0) : [];
    } catch {
        return [];
    }
}

function writeAnonIds(ids) {
    try {
        const unique = Array.from(new Set(ids));
        if (unique.length > 0) localStorage.setItem(ANON_IDS_KEY, JSON.stringify(unique));
        else localStorage.removeItem(ANON_IDS_KEY);
    } catch { /* хранилище недоступно — стирать будет нечего */ }
}

// Список "чьи локальные данные стереть, как только этот пользователь не
// текущая сессия". Туда попадает каждый аккаунт при входе (вкладку могли
// просто закрыть, а сервер удалит аккаунт сам по сроку без входа) и
// удалённые аккаунты, чью базу ключей не удалось стереть сразу.
function rememberIdForWipe(userId) {
    writeAnonIds([...readAnonIds(), Number(userId)]);
}

function forgetIdForWipe(userId) {
    writeAnonIds(readAnonIds().filter(id => id !== Number(userId)));
}

// Локальные флаги пользователя: согласие на уведомления и id чата с ботом.
// Тема оформления — настройка устройства, а не аккаунта, её не трогаем.
function removeLocalUserPrefs(userId) {
    try {
        localStorage.removeItem(NOTIFY_PREF_PREFIX + userId);
        localStorage.removeItem(BOT_CHAT_PREFIX + userId);
    } catch { /* хранилище недоступно */ }
}

// Флаги e2ee-enabled:<пользователь>:<чат> остались от выключателя шифрования,
// которого больше нет: они ничего не значат и никому не нужны. Стираются все,
// любых пользователей, один раз при старте страницы.
function sweepLegacyPrefs() {
    try {
        const doomed = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(LEGACY_E2EE_PREF_PREFIX)) doomed.push(key);
        }
        doomed.forEach(key => localStorage.removeItem(key));
    } catch { /* хранилище недоступно — стирать нечего */ }
}

// id чата с ботом (приходит в ответе регистрации) нужен клиенту волны 2;
// хранится на устройстве рядом с остальными локальными данными аккаунта.
function rememberBotChatId(userId, botChatId) {
    const id = Number(botChatId);
    if (!Number.isInteger(id) || id <= 0 || !Number.isInteger(Number(userId))) return;
    try { localStorage.setItem(BOT_CHAT_PREFIX + userId, String(id)); } catch { /* хранилище недоступно */ }
}

// Стирает локальные данные пользователя. Резолвится true, если база
// ключей точно удалена. Удаление IndexedDB ждёт, пока закроются открытые
// к ней соединения, поэтому ждём не дольше timeoutMs: id остаётся в
// списке на стирание и будет дочищен позже (при следующем старте), а
// если удаление всё же завершится — вычеркнется из списка само.
function wipeLocalUserData(userId, timeoutMs = 3000) {
    removeLocalUserPrefs(userId);
    if (typeof E2EE === 'undefined' || typeof E2EE.deleteLocalData !== 'function') {
        return Promise.resolve(false);
    }
    const deletion = Promise.resolve()
        .then(() => E2EE.deleteLocalData(userId))
        .then(() => { forgetIdForWipe(userId); return true; })
        .catch((err) => {
            console.warn('Не удалось удалить локальные ключи E2EE:', err);
            return false;
        });
    return withTimeout(deletion, timeoutMs, false);
}

// Чьи следы лежат на устройстве: id из списка на стирание, из ключей
// localStorage (уведомления, чат с ботом) и из имён баз
// IndexedDB nyxo-e2ee-<id>. Список баз знает indexedDB.databases(); где его
// нет (старый Firefox), остаётся список nyxo-anon-ids.
async function listLocalUserIds() {
    const ids = new Set(readAnonIds());
    try {
        // Ключ вида <префикс><id>.
        const prefixes = [NOTIFY_PREF_PREFIX, BOT_CHAT_PREFIX];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const prefix = key && prefixes.find(p => key.startsWith(p));
            if (!prefix) continue;
            const digits = key.slice(prefix.length).split(':')[0];
            if (/^[0-9]+$/.test(digits)) ids.add(Number(digits));
        }
    } catch { /* хранилище недоступно */ }
    try {
        if (typeof indexedDB !== 'undefined' && indexedDB && typeof indexedDB.databases === 'function') {
            const dbs = await withTimeout(indexedDB.databases(), 3000, []);
            for (const db of dbs || []) {
                if (!db || typeof db.name !== 'string' || !db.name.startsWith(E2EE_DB_PREFIX)) continue;
                const digits = db.name.slice(E2EE_DB_PREFIX.length);
                if (/^[0-9]+$/.test(digits)) ids.add(Number(digits));
            }
        }
    } catch { /* список баз недоступен — остаётся nyxo-anon-ids */ }
    return Array.from(ids).filter(id => Number.isSafeInteger(id) && id > 0);
}

// На одном origin живёт один аккаунт (кука сессии общая): всё, что осталось
// от других, — следы удалённых аккаунтов, их стираем. Порядок важен: СНАЧАЛА
// список следов, ПОТОМ свежий GET /api/auth. Если наоборот, аккаунт,
// созданный в соседней вкладке между запросом и чтением списка, попал бы
// под стирание. Оставляем аккаунт из ответа сервера и текущий. Сервер
// недоступен — не стираем ничего: сессия могла и не истечь.
let purgingForeign = null;
function purgeForeignLocalData() {
    if (purgingForeign) return purgingForeign;
    purgingForeign = (async () => {
        const known = await listLocalUserIds();
        if (known.length === 0) return;
        const state = await fetchAuthState();
        if (!state) return;
        const keep = new Set();
        if (state.authenticated && state.user) keep.add(Number(state.user.id));
        if (currentUser) keep.add(Number(currentUser.id));
        known.filter(id => !keep.has(id)).forEach((id) => { wipeLocalUserData(id); });
    })().catch((err) => {
        console.warn('Не удалось почистить чужие локальные данные:', err);
    }).finally(() => { purgingForeign = null; });
    return purgingForeign;
}

// Полная перезагрузка после выхода и удаления аккаунта: закрывает
// соединения с IndexedDB (иначе удаление базы ключей ждёт их закрытия) и
// выбрасывает из памяти расшифрованную переписку. Уведомление переживает
// перезагрузку через sessionStorage и показывается на экране входа.
function reloadWithNotice(text) {
    try {
        if (text) sessionStorage.setItem(FLASH_NOTICE_KEY, text);
    } catch { /* без уведомления — не страшно */ }
    location.reload();
}

// Уведомление, оставленное перед перезагрузкой; читается один раз.
function takeFlashNotice() {
    let text = null;
    try {
        text = sessionStorage.getItem(FLASH_NOTICE_KEY);
        sessionStorage.removeItem(FLASH_NOTICE_KEY);
    } catch { /* нет sessionStorage */ }
    return text || '';
}
