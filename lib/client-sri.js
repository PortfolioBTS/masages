'use strict';
// Атрибуты integrity (SRI) у <script src> и <link rel="stylesheet"> в index.html
// (6.1, roadmap R10). Здесь только разбор и расчёт; запись файла — в
// scripts/update-sri.js, проверка актуальности — в test/client-sri.test.js.
//
// SRI ВКЛЮЧЁН (волна 6): атрибуты integrity у всех своих скриптов и стилей стоят в index.html.
// Корень доверия к странице - хэш самого index.html (он в манифесте клиента), а хэши скриптов и
// стилей зашиты в него. После любой правки JS/CSS клиента атрибуты обновляет
// scripts/update-sri.js; test/client-sri.test.js проверяет их актуальность.
//
// Что покрывается: относительные и корневые адреса своих файлов. Чужие адреса
// (http:, https:, //), data: и blob: не трогаются. pow-worker.js — не <script>,
// а Worker, у Worker нет integrity (docs/threat-model.md); его хэш проверяется
// только манифестом.

const { sriOf } = require('./client-manifest');

const TAG_RE = /<(script|link)\b([^>]*)>/gi;

// Атрибут как он записан в тексте: значение в двойных или одинарных кавычках.
function findAttr(attrs, name) {
    const re = new RegExp(String.raw`(\s)${name}\s*=\s*(?:"([^"]*)"|'([^']*)')`, 'i');
    const match = re.exec(attrs);
    if (!match) return null;
    return {
        index: match.index,
        length: match[0].length,
        value: match[2] !== undefined ? match[2] : match[3],
    };
}

// Адрес файла от корня сайта или null, если это не наш файл.
function localUrlPath(url) {
    if (!url || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(url)) return null;
    const clean = url.split(/[?#]/)[0];
    return clean.startsWith('/') ? clean : '/' + clean;
}

// Теги, на которые нужен integrity: [{ start, end, attrs, tagName, urlAttr, urlPath }].
function findSriTags(html) {
    const found = [];
    for (const match of html.matchAll(TAG_RE)) {
        const tagName = match[1].toLowerCase();
        const attrs = match[2];
        let urlAttrName = null;
        if (tagName === 'script') urlAttrName = 'src';
        else if (/\bstylesheet\b/i.test((findAttr(attrs, 'rel') || {}).value || '')) urlAttrName = 'href';
        if (!urlAttrName) continue;
        const urlAttr = findAttr(attrs, urlAttrName);
        if (!urlAttr) continue;
        const urlPath = localUrlPath(urlAttr.value);
        if (!urlPath) continue;
        found.push({ start: match.index, end: match.index + match[0].length, tagName, attrs, urlAttrName, urlAttr, urlPath });
    }
    return found;
}

// Обработка страницы.
//   readBytes(urlPath) -> Buffer | null  (null — файла нет)
//   remove: true — убрать все integrity у найденных тегов
// Возвращает { html, tags: [{ url, tag, expected, actual, status }] }, где
// status: 'ok' | 'stale' | 'missing' | 'no-file'. html — страница с исправленными атрибутами.
function applySri(html, readBytes, { remove = false } = {}) {
    const tags = [];
    let out = '';
    let cursor = 0;
    for (const tag of findSriTags(html)) {
        const bytes = readBytes(tag.urlPath);
        const existing = findAttr(tag.attrs, 'integrity');
        const actual = existing ? existing.value : null;
        const expected = bytes ? sriOf(bytes) : null;
        let status;
        if (!bytes) status = 'no-file';
        else if (actual === null) status = 'missing';
        else status = actual === expected ? 'ok' : 'stale';
        tags.push({ url: tag.urlPath, tag: tag.tagName, expected, actual, status });

        let attrs = tag.attrs;
        if (remove) {
            if (existing) attrs = attrs.slice(0, existing.index) + attrs.slice(existing.index + existing.length);
        } else if (bytes) {
            if (existing) {
                attrs = attrs.slice(0, existing.index) + ` integrity="${expected}"` + attrs.slice(existing.index + existing.length);
            } else {
                const at = tag.urlAttr.index + tag.urlAttr.length;
                attrs = attrs.slice(0, at) + ` integrity="${expected}"` + attrs.slice(at);
            }
        }
        // Имя тега берём из текста как есть (регистр не меняем).
        out += html.slice(cursor, tag.start) + '<' + html.substr(tag.start + 1, tag.tagName.length) + attrs + '>';
        cursor = tag.end;
    }
    return { html: out + html.slice(cursor), tags };
}

// Есть ли в странице хоть один integrity у наших тегов (для охранного теста «SRI ещё не включён»).
function hasAnyIntegrity(html) {
    return findSriTags(html).some((tag) => findAttr(tag.attrs, 'integrity'));
}

module.exports = { applySri, findSriTags, hasAnyIntegrity, localUrlPath };
