'use strict';
// Хранилище кук одного «браузера» сквозного теста (RFC 6265, без доменов:
// у тестового клиента один хост).
//
// Учитывает Path, Max-Age (главнее Expires), Expires, удаление пустой или
// просроченной кукой и Secure: Secure-куки уходят только при
// secureContext: true (имитация https). Часы внедряются (now), чтобы
// проверять сроки кук без ожидания.

function defaultPath(requestPath) {
    const pathname = String(requestPath || '/').split('?')[0];
    if (!pathname.startsWith('/')) return '/';
    const last = pathname.lastIndexOf('/');
    return last <= 0 ? '/' : pathname.slice(0, last);
}

function pathMatches(cookiePath, requestPath) {
    const pathname = String(requestPath || '/').split('?')[0] || '/';
    if (pathname === cookiePath) return true;
    if (!pathname.startsWith(cookiePath)) return false;
    return cookiePath.endsWith('/') || pathname[cookiePath.length] === '/';
}

// Разбор одной строки Set-Cookie.
function parseSetCookie(header, requestPath, now) {
    const [pair, ...attrs] = String(header).split(';');
    const eq = pair.indexOf('=');
    if (eq <= 0) return null;
    const cookie = {
        name: pair.slice(0, eq).trim(),
        value: pair.slice(eq + 1).trim(),
        path: defaultPath(requestPath),
        expiresAt: null,
        secure: false,
        httpOnly: false,
        sameSite: null,
    };
    let maxAge = null;
    for (const attr of attrs) {
        const i = attr.indexOf('=');
        const key = (i === -1 ? attr : attr.slice(0, i)).trim().toLowerCase();
        const val = i === -1 ? '' : attr.slice(i + 1).trim();
        if (key === 'path' && val.startsWith('/')) cookie.path = val;
        else if (key === 'max-age' && /^-?\d+$/.test(val)) maxAge = Number(val);
        else if (key === 'expires') {
            const t = Date.parse(val);
            if (!Number.isNaN(t)) cookie.expiresAt = t;
        } else if (key === 'secure') cookie.secure = true;
        else if (key === 'httponly') cookie.httpOnly = true;
        else if (key === 'samesite') cookie.sameSite = val.toLowerCase();
    }
    if (maxAge !== null) cookie.expiresAt = maxAge <= 0 ? 0 : now + maxAge * 1000;
    return cookie;
}

class CookieJar {
    constructor({ now = () => Date.now(), secureContext = false } = {}) {
        this.now = now;
        this.secureContext = secureContext;
        this.cookies = new Map(); // `${name}\n${path}` -> cookie
    }

    // Все Set-Cookie ответа (Headers#getSetCookie — каждая кука отдельно).
    setFromResponse(response, requestPath = '/') {
        const list = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
        for (const header of list) this.setCookieString(header, requestPath);
    }

    setCookieString(header, requestPath = '/') {
        const cookie = parseSetCookie(header, requestPath, this.now());
        if (!cookie) return;
        if (cookie.secure && !this.secureContext) return; // браузер по http Secure-куку не примет
        const key = `${cookie.name}\n${cookie.path}`;
        if (cookie.expiresAt !== null && cookie.expiresAt <= this.now()) this.cookies.delete(key);
        else this.cookies.set(key, cookie);
    }

    // Подставить куку вручную (например, для негативной проверки).
    set(name, value, { path = '/', expiresAt = null, secure = false, httpOnly = false } = {}) {
        this.cookies.set(`${name}\n${path}`, { name, value: String(value), path, expiresAt, secure, httpOnly, sameSite: null });
    }

    delete(name) {
        for (const [key, cookie] of this.cookies) if (cookie.name === name) this.cookies.delete(key);
    }

    clear() { this.cookies.clear(); }

    // Живые куки для пути запроса: длинный Path раньше (как в браузере).
    list(requestPath = '/') {
        const now = this.now();
        const out = [];
        for (const [key, cookie] of this.cookies) {
            if (cookie.expiresAt !== null && cookie.expiresAt <= now) {
                this.cookies.delete(key);
                continue;
            }
            if (cookie.secure && !this.secureContext) continue;
            if (pathMatches(cookie.path, requestPath)) out.push(cookie);
        }
        return out.sort((a, b) => b.path.length - a.path.length);
    }

    get(name, requestPath = '/') {
        const cookie = this.list(requestPath).find(c => c.name === name);
        return cookie ? cookie.value : undefined;
    }

    header(requestPath = '/') {
        return this.list(requestPath).map(c => `${c.name}=${c.value}`).join('; ');
    }
}

module.exports = { CookieJar, parseSetCookie, pathMatches, defaultPath };
