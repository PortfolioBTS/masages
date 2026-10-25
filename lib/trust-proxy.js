'use strict';
// Сколько обратных прокси стоит перед приложением и чему из заголовков, которые они добавляют
// (X-Forwarded-For/-Host/-Proto), можно верить (W7 R1 п.10).
//
// TRUST_PROXY - число доверенных хопов, поддержаны 1 и 0. По умолчанию 1: Railway (или Cloudflare ->
// Railway) ставит заголовки сам, и приложение берёт значение, добавленное ближайшим к нему прокси (вся
// остальная логика - IP клиента, CF-Connecting-IP - рассчитана на один хоп). 0 (или false/no/off) - прокси
// нет, приложение торчит наружу напрямую: заголовки X-Forwarded-* игнорируются, хостом считается Host,
// клиентом - адрес сокета. Любое другое значение - ошибка настройки: действует умолчание, а
// lib/env-check.js предупреждает оператора.

const DEFAULT_HOPS = 1;
const MAX_HOPS = 1;

function parseTrustProxy(raw) {
    if (raw === undefined || raw === null || String(raw).trim() === '') return { hops: DEFAULT_HOPS, valid: true };
    const text = String(raw).trim().toLowerCase();
    if (['0', 'false', 'no', 'off'].includes(text)) return { hops: 0, valid: true };
    if (text === '1') return { hops: MAX_HOPS, valid: true };
    return { hops: DEFAULT_HOPS, valid: false };
}

function resolveTrustProxy(env = process.env) {
    return parseTrustProxy(env.TRUST_PROXY).hops;
}

// Значение заголовка, добавленное ближайшим доверенным прокси: список через запятую читается с КОНЦА
// (каждый прокси дописывает своё в конец; начало списка прислал сам клиент). Прокси нет (hops = 0) или
// заголовка нет - null.
function proxyHeaderValue(value, hops) {
    if (hops <= 0) return null;
    if (Array.isArray(value)) value = value.join(',');
    if (typeof value !== 'string') return null;
    const parts = value.split(',').map(part => part.trim()).filter(Boolean);
    if (parts.length === 0) return null;
    return parts[Math.max(0, parts.length - hops)];
}

module.exports = { parseTrustProxy, resolveTrustProxy, proxyHeaderValue, DEFAULT_HOPS, MAX_HOPS };
