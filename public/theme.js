// Тема оформления Nyxo: тёмная или светлая, <html data-theme="dark|light">.
//
// Подключается синхронно в <head> до style.css: атрибут выставляется до
// первой отрисовки, поэтому страница не мигает «не той» темой.
// Выбор пользователя хранится в localStorage['nyxo-theme']; пока выбора нет,
// тема следует за системной (prefers-color-scheme) и меняется вместе с ней.
// Хранилище может быть недоступно (приватный режим, запрет cookies) — все
// обращения к нему в try/catch, без него тема просто не запоминается.
(function () {
    'use strict';

    const STORAGE_KEY = 'nyxo-theme';
    const THEMES = ['dark', 'light'];
    // Совпадает с --bg в style.css: цвет системной строки/заголовка окна PWA.
    const THEME_COLOR = { dark: '#0a0a0a', light: '#ffffff' };
    const root = document.documentElement;
    const media = typeof window.matchMedia === 'function'
        ? window.matchMedia('(prefers-color-scheme: light)')
        : null;

    function isTheme(value) {
        return THEMES.includes(value);
    }

    function readStored() {
        try {
            const value = localStorage.getItem(STORAGE_KEY);
            return isTheme(value) ? value : null;
        } catch {
            return null;
        }
    }

    function writeStored(value) {
        try {
            if (value) localStorage.setItem(STORAGE_KEY, value);
            else localStorage.removeItem(STORAGE_KEY);
        } catch { /* хранилище недоступно — выбор действует до перезагрузки */ }
    }

    function systemTheme() {
        return media && media.matches ? 'light' : 'dark';
    }

    // Один <meta name="theme-color"> без media: вариант с двумя meta под
    // prefers-color-scheme показывал бы системную тему, а не выбранную.
    function updateThemeColor(theme) {
        const head = document.head;
        if (!head) return;
        const metas = Array.from(head.querySelectorAll('meta[name="theme-color"]'));
        let meta = metas.find(m => !m.hasAttribute('media')) || metas[0] || null;
        metas.forEach((m) => { if (m !== meta) m.remove(); });
        if (!meta) {
            meta = document.createElement('meta');
            meta.setAttribute('name', 'theme-color');
            head.appendChild(meta);
        }
        meta.removeAttribute('media');
        meta.setAttribute('content', THEME_COLOR[theme]);
    }

    // При переключении отключаем transition на один кадр: иначе часть
    // элементов плавно перекрашивается, а часть — мгновенно, и смена темы
    // выглядит «рваной».
    let unfreezeFrame = 0;
    function freezeTransitions() {
        if (typeof window.requestAnimationFrame !== 'function') return;
        root.classList.add('theme-switching');
        cancelAnimationFrame(unfreezeFrame);
        unfreezeFrame = requestAnimationFrame(() => {
            unfreezeFrame = requestAnimationFrame(() => root.classList.remove('theme-switching'));
        });
    }

    let current = null;
    function apply(theme, animate) {
        const next = isTheme(theme) ? theme : 'dark';
        if (next === current && root.getAttribute('data-theme') === next) return;
        if (animate && current) freezeTransitions();
        current = next;
        root.setAttribute('data-theme', next);
        updateThemeColor(next);
        try {
            document.dispatchEvent(new CustomEvent('nyxo:themechange', { detail: { theme: next } }));
        } catch { /* очень старый движок без CustomEvent — событие не критично */ }
    }

    function get() {
        return current || 'dark';
    }

    // set('dark' | 'light') запоминает выбор; set(null) или set('system')
    // забывает его и возвращает тему системы.
    function set(theme) {
        if (theme === null || theme === undefined || theme === 'system') {
            writeStored(null);
            apply(systemTheme(), true);
            return get();
        }
        if (!isTheme(theme)) throw new TypeError(`NyxoTheme: неизвестная тема «${theme}»`);
        writeStored(theme);
        apply(theme, true);
        return get();
    }

    function toggle() {
        return set(get() === 'dark' ? 'light' : 'dark');
    }

    // true, если пользователь не выбирал тему и она следует за системой.
    function isSystem() {
        return readStored() === null;
    }

    apply(readStored() || systemTheme(), false);

    if (media) {
        const onSystemChange = () => {
            if (readStored() === null) apply(systemTheme(), true);
        };
        if (typeof media.addEventListener === 'function') media.addEventListener('change', onSystemChange);
        else if (typeof media.addListener === 'function') media.addListener(onSystemChange);
    }

    // Выбор, сделанный в другой вкладке, применяется и здесь.
    window.addEventListener('storage', (e) => {
        if (e.key !== null && e.key !== STORAGE_KEY) return;
        apply(readStored() || systemTheme(), true);
    });

    // <meta name="theme-color"> может стоять в разметке ниже этого скрипта.
    document.addEventListener('DOMContentLoaded', () => updateThemeColor(get()), { once: true });

    window.NyxoTheme = Object.freeze({ get, set, toggle, isSystem });
})();
