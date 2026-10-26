// Проверка переменных окружения и секретов — без вывода самих значений.
//
// Запускается при старте сервера (результат — в логах деплоя) и отдельно:
// `npm run check-env` (на Railway: `railway run npm run check-env`).
// Ошибки не останавливают сервер (кроме тех, без которых он и так не
// стартует), но пишутся громко: неверный секрет обычно не ломает запуск, а
// тихо ломает функцию — как когда-то оставшиеся от отдельного сервиса ключей
// INTERNAL_KEY_SERVER_SECRET и KEY_SERVER_URL на 127.0.0.1: из-за них не
// работало сквозное шифрование.

const crypto = require('crypto');
const { parseContacts, parsePublicOrigin, resolveExpires, ROLLING_DAYS } = require('./security-txt');
const { loadSigningKey, TEST_KNOBS: KT_TEST_KNOBS } = require('./kt-log');
const { createOnionAllowList } = require('./onion-access');
const { parseTrustProxy } = require('./trust-proxy');
const { NUMERIC_KNOBS, parseKnob } = require('./numeric-knobs');

// SHA-256 значений из .env, попавшего в ПУБЛИЧНУЮ историю git (коммит
// d5cd834 от 15.07.2026, «Add files via upload»). Сами значения здесь не
// хранятся — только хэши, чтобы узнать их, если они всё ещё используются.
const KNOWN_LEAKED_SHA256 = {
    SESSION_SECRET: ['4c59afde926948e1687643298353fe8efc0e040a3ac2979362fca2da00f906db'],
    INTERNAL_KEY_SERVER_SECRET: ['a62cf1ca5a4004dbc5e5fe85dfe93604337bc1059455d2a566486a59740acdc4'],
    DATABASE_PASSWORD: ['12529561e844df2059d91f959710dc8b75f83a78bc83c21d6b88b6d77ca4cf73'],
};
const LEAK_NOTE = 'значение совпадает с утёкшим в публичную историю git (коммит d5cd834) — его нужно сменить';

// Переменные удалённых функций ничего не делают, но не должны оставаться в
// окружении молча: по ним можно решить, что функция всё ещё включена.
//   * E2EE_KEY_STORE, KEY_SERVER_URL, INTERNAL_KEY_SERVER_SECRET,
//     ANON_SERVICE_URL, ANON_SERVICE_SECRET — отдельные сервисы
//     e2ee-key-server и anon-service: ключи теперь во встроенном хранилище,
//     имена генерирует сам сервер;
//   * PASSWORD_PEPPER, HIBP_CHECK — постоянные аккаунты со входом по паролю:
//     остались только временные анонимные аккаунты.
const UNUSED_VARS = [
    'E2EE_KEY_STORE', 'KEY_SERVER_URL', 'INTERNAL_KEY_SERVER_SECRET',
    'ANON_SERVICE_URL', 'ANON_SERVICE_SECRET',
    'PASSWORD_PEPPER', 'HIBP_CHECK',
];

// Числовые настройки лимитов сервера (T7.2): таблица и разбор — lib/numeric-knobs.js, общие с сервером (Н2).
// Негодное значение — предупреждение с тем умолчанием, которое сервер действительно возьмёт.

const PLACEHOLDER_RE = /your_|change_?me|changeme|example|placeholder|secret_here|generate|another_|strong_secret|random_secret|^(test|secret|password|admin)$/i;

const sha256 = (value) => crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');

function checkEnv(env = process.env, { leaked = KNOWN_LEAKED_SHA256 } = {}) {
    const errors = [];
    const warnings = [];
    const info = [];
    const err = (name, message) => errors.push({ name, message });
    const warn = (name, message) => warnings.push({ name, message });
    const note = (name, message) => info.push({ name, message });
    const get = (name) => (typeof env[name] === 'string' ? env[name].trim() : '');
    const isLeaked = (kind, value) => Boolean(value) && (leaked[kind] || []).includes(sha256(value));

    const onRailway = Boolean(env.RAILWAY_ENVIRONMENT || env.RAILWAY_ENVIRONMENT_NAME || env.RAILWAY_PROJECT_ID);
    const production = get('NODE_ENV') === 'production';
    if (onRailway && !production) {
        err('NODE_ENV', 'на Railway должен быть "production" — иначе cookie без Secure, без HSTS и с отладочными настройками');
    }

    // Общая проверка секрета: задан, длина, не заглушка, не утёк.
    function checkSecret(name, { required, minLength = 32, leakKind = name } = {}) {
        const value = get(name);
        if (!value) {
            if (required) err(name, 'не задан');
            return '';
        }
        if (PLACEHOLDER_RE.test(value)) err(name, 'похоже на заглушку из примера — задайте случайное значение');
        else if (value.length < minLength) err(name, `слишком короткий (нужно не меньше ${minLength} символов)`);
        else if (new Set(value).size < 12) warn(name, 'мало разных символов — похоже не на случайное значение');
        if (isLeaked(leakKind, value)) err(name, LEAK_NOTE);
        return value;
    }

    const sessionSecret = checkSecret('SESSION_SECRET', { required: true });
    // Токен GET /metrics (7.6): необязателен — без него эндпоинт отключён. Он
    // идёт в заголовке Authorization: Bearer, поэтому без пробелов и кавычек.
    const metricsToken = checkSecret('METRICS_TOKEN', { required: false });
    if (metricsToken && !/^[A-Za-z0-9._~+/=-]+$/.test(metricsToken)) {
        err('METRICS_TOKEN', 'допустимы только буквы, цифры и символы . _ ~ + / = - (токен передаётся в заголовке Authorization: Bearer)');
    }

    // Ключ журнала ключей (docs/security/key-transparency.md, 6.6): base64 PKCS#8 Ed25519.
    // Необязателен: без него журнал выключен, клиенты работают как раньше. Значение в отчёт не попадает.
    const ktKey = get('KT_SIGNING_KEY');
    if (ktKey) {
        try { loadSigningKey(ktKey); } catch (e) { err('KT_SIGNING_KEY', `${e.message} (генерация: node -e "console.log(require('crypto').generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'der'}).toString('base64'))")`); }
    } else if (production) {
        warn('KT_SIGNING_KEY', 'не задан — журнал ключей выключен: подмену ключа собеседника сервером журнал не выявит. Ключ нужно хранить отдельно от остальных секретов, резервная копия обязательна');
    }
    const ktPrevious = get('KT_SIGNING_KEY_PREVIOUS');
    if (ktPrevious) {
        try { loadSigningKey(ktPrevious); } catch (e) { err('KT_SIGNING_KEY_PREVIOUS', e.message); }
        if (!ktKey) warn('KT_SIGNING_KEY_PREVIOUS', 'задан без KT_SIGNING_KEY — не используется');
        else if (ktPrevious === ktKey) warn('KT_SIGNING_KEY_PREVIOUS', 'совпадает с текущим ключом — смены ключа нет, переменную можно убрать');
    }

    // Ключ шифрования сообщений: base64 ровно 32 байта (иначе сервер не стартует).
    function checkMessageKey(name, raw) {
        const key = Buffer.from(raw, 'base64');
        if (key.length !== 32 || key.toString('base64').replace(/=+$/, '') !== raw.replace(/=+$/, '')) {
            err(name, 'должен быть base64 ровно 32 байт (генерация: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))")');
            return;
        }
        if (new Set(key).size < 8) err(name, 'ключ не выглядит случайным');
    }
    const messageKey = get('MESSAGE_ENCRYPTION_KEY');
    if (!messageKey) err('MESSAGE_ENCRYPTION_KEY', 'не задан — сервер не запустится');
    else checkMessageKey('MESSAGE_ENCRYPTION_KEY', messageKey);
    for (const prev of get('MESSAGE_ENCRYPTION_KEY_PREVIOUS').split(',').map(s => s.trim()).filter(Boolean)) {
        checkMessageKey('MESSAGE_ENCRYPTION_KEY_PREVIOUS', prev);
        if (prev === messageKey) warn('MESSAGE_ENCRYPTION_KEY_PREVIOUS', 'совпадает с текущим ключом — можно убрать');
    }

    // База данных.
    const dbUrl = get('DATABASE_URL');
    let dbHost = '';
    if (!dbUrl) {
        err('DATABASE_URL', 'не задан');
    } else {
        let url = null;
        try { url = new URL(dbUrl); } catch { err('DATABASE_URL', 'не разбирается как URL'); }
        if (url) {
            dbHost = url.hostname;
            if (!/^postgres(ql)?:$/.test(url.protocol)) err('DATABASE_URL', 'ожидается postgresql://…');
            const password = decodeURIComponent(url.password || '');
            if (!password) warn('DATABASE_URL', 'без пароля');
            else {
                if (isLeaked('DATABASE_PASSWORD', password)) {
                    err('DATABASE_URL', 'пароль базы совпадает с утёкшим в публичную историю git (коммит d5cd834) — его нужно сменить');
                }
                else if (password.length < 16) warn('DATABASE_URL', 'короткий пароль базы');
            }
        }
    }
    if (production) {
        const caCert = get('DB_CA_CERT');
        if (caCert && !/-----BEGIN CERTIFICATE-----/.test(caCert)) err('DB_CA_CERT', 'не похоже на PEM-сертификат');
        if (!caCert && !dbHost.endsWith('.railway.internal') && get('DB_TLS_INSECURE') !== 'true') {
            err('DB_CA_CERT', 'в production нужен CA базы (или приватный хост *.railway.internal, или осознанно DB_TLS_INSECURE=true) — иначе сервер не стартует');
        }
    }

    // Переменные удалённых функций — одним предупреждением со списком
    // заданных, чтобы окружение почистили за один раз.
    const staleVars = UNUSED_VARS.filter(get);
    if (staleVars.length > 0) {
        warn(staleVars.join(', '), 'не используется (функция удалена) — удалите из окружения');
    }
    // Утёкшее значение остаётся ошибкой, даже когда переменная не нужна: оно
    // лежит в публичной истории git и могло быть повторно использовано где-то ещё.
    if (isLeaked('INTERNAL_KEY_SERVER_SECRET', get('INTERNAL_KEY_SERVER_SECRET'))) {
        err('INTERNAL_KEY_SERVER_SECRET', LEAK_NOTE + ' (или просто удалить переменную)');
    }

    // Один и тот же секрет в двух местах — утечка одного раскрывает другой.
    const secrets = [
        ['SESSION_SECRET', sessionSecret], ['MESSAGE_ENCRYPTION_KEY', messageKey], ['METRICS_TOKEN', metricsToken],
        ['INTERNAL_KEY_SERVER_SECRET', get('INTERNAL_KEY_SERVER_SECRET')], ['KT_SIGNING_KEY', ktKey],
    ].filter(([, v]) => v);
    for (let i = 0; i < secrets.length; i++) {
        for (let j = i + 1; j < secrets.length; j++) {
            if (secrets[i][1] === secrets[j][1]) err(`${secrets[i][0]} / ${secrets[j][0]}`, 'одинаковые значения — у каждого секрета должно быть своё');
        }
    }

    // Onion и прочее.
    const onionPort = get('ONION_PORT');
    if (get('ONION_ADDRESS') && !onionPort) warn('ONION_PORT', 'ONION_ADDRESS задан без ONION_PORT — onion-режим выключен');
    if (onionPort && onionPort === (get('PORT') || '3000')) err('ONION_PORT', 'совпадает с PORT — нужен отдельный внутренний порт');
    // Доверенный прокси (lib/trust-proxy.js): 1 (по умолчанию) или 0.
    if (get('TRUST_PROXY')) {
        const trust = parseTrustProxy(get('TRUST_PROXY'));
        if (!trust.valid) warn('TRUST_PROXY', 'допустимо 1 (по умолчанию) или 0/false; будет использовано 1');
        else if (trust.hops === 0 && onRailway) {
            warn('TRUST_PROXY', 'на Railway перед приложением стоит прокси: при 0 адрес клиента — адрес прокси, лимиты по IP станут общими на всех, а X-Forwarded-Proto/-Host игнорируются');
        }
    }
    // Кому можно подключаться к ONION_PORT (lib/onion-access.js): по умолчанию частные и loopback-адреса.
    const onionCidr = get('ONION_ALLOWED_CIDR');
    if (onionCidr) {
        const allow = createOnionAllowList(onionCidr);
        if (allow.invalid.length > 0) {
            warn('ONION_ALLOWED_CIDR', `некорректных записей: ${allow.invalid.length} (нужны адрес или CIDR через запятую, например 10.8.0.0/16, fd00:1::/32)${allow.custom ? '' : '; корректных нет — действует список по умолчанию (частные адреса)'}`);
        }
        // Запись вне частных сетей открывает порт onion-режима (без IP-лимитов) кому-то снаружи.
        const privateOnly = createOnionAllowList('');
        const publicEntries = onionCidr.split(',').map(s => s.trim()).filter(Boolean)
            .filter(entry => !allow.invalid.includes(entry) && !privateOnly.allows(entry.split('/')[0]));
        if (publicEntries.length > 0) {
            warn('ONION_ALLOWED_CIDR', 'в списке есть адреса вне частных сетей: к ONION_PORT смогут подключаться оттуда, и такой клиент получит режим onion без лимитов по IP. Допустимо только если порт закрыт брандмауэром');
        }
    } else if (onionPort) {
        note('ONION_ALLOWED_CIDR', 'не задан: к ONION_PORT принимаются только частные и loopback-адреса (private network, docker-сеть)');
    }
    if (onRailway && !get('UPLOADS_DIR') && !get('RAILWAY_VOLUME_MOUNT_PATH')) {
        warn('UPLOADS_DIR', 'нет volume для вложений — файлы пропадут при следующем деплое');
    }
    // HSTS preload (8.3): флаг осознанный, и последствия у него долгие.
    const hstsPreload = get('HSTS_PRELOAD');
    if (hstsPreload && hstsPreload !== 'yes' && hstsPreload !== 'no') {
        warn('HSTS_PRELOAD', 'допустимо только "yes" — любое другое значение оставляет preload выключенным');
    }
    if (hstsPreload === 'yes') {
        if (!production) warn('HSTS_PRELOAD', 'заголовок отправляется только при NODE_ENV=production и по https — сейчас preload не действует');
        warn('HSTS_PRELOAD', 'включён HSTS preload (2 года, includeSubDomains, preload). Это заявка в список браузеров: убрать из него домен можно только через месяцы, ' +
            'а includeSubDomains требует https на ВСЕХ поддоменах. Нужен свой домен (на *.up.railway.app preload не подать); ' +
            'сначала проверьте домен на hstspreload.org и убедитесь, что редирект http → https работает у хостинга или Cloudflare');
    }

    // Аварийное снятие service worker (6.2, lib/sw-kill-switch.js): включённый переключатель оператору виден в отчёте.
    const swKill = get('SW_KILL_SWITCH');
    if (swKill && swKill !== 'yes' && swKill !== 'no') {
        warn('SW_KILL_SWITCH', 'допустимо только "yes" — любое другое значение оставляет переключатель выключенным');
    }
    if (swKill === 'yes') {
        warn('SW_KILL_SWITCH', 'включён: /sw.js снимает service worker у клиентов, закрепление кода не работает. Уберите переменную, когда причина устранена');
    }

    // security.txt (8.4): адреса связи, срок и публичный адрес для Canonical.
    if (get('SECURITY_CONTACT')) {
        const { invalid, usingDefault } = parseContacts(get('SECURITY_CONTACT'));
        if (invalid.length > 0) {
            warn('SECURITY_CONTACT', `пропущено некорректных адресов: ${invalid.length} (допустимы https://…, mailto:…, tel:+…)${usingDefault ? ' — используется адрес по умолчанию (GitHub Security Advisories)' : ''}`);
        }
    }
    if (get('SECURITY_TXT_EXPIRES')) {
        const expires = resolveExpires(get('SECURITY_TXT_EXPIRES'));
        if (expires.problem) warn('SECURITY_TXT_EXPIRES', `${expires.problem} — используется скользящий срок (+${ROLLING_DAYS} дней)`);
        else if (expires.expiresSoon) warn('SECURITY_TXT_EXPIRES', 'срок security.txt истекает меньше чем через 30 дней — продлите его (устаревший файл считается недействительным)');
    }
    if (get('PUBLIC_ORIGIN') && !parsePublicOrigin(get('PUBLIC_ORIGIN'))) {
        warn('PUBLIC_ORIGIN', 'ожидается https://домен без пути — Canonical в security.txt не будет выведен');
    }
    const pow = get('POW_DIFFICULTY');
    if (pow && !(/^\d+$/.test(pow) && Number(pow) >= 8 && Number(pow) <= 28)) warn('POW_DIFFICULTY', 'допустимо 8..28, будет использовано 18');

    for (const knob of NUMERIC_KNOBS) {
        const raw = get(knob.name);
        if (!raw) continue;
        if (parseKnob(knob, raw) === null) {
            warn(knob.name, `допустимо ${knob.float ? 'число' : 'целое'} ${knob.min}..${knob.max} (${knob.note}); будет использовано ${knob.def}`);
        }
    }

    // Тестовые ручки сквозных тестов (NYXO_TEST_*, docs/dev/testing.md)
    // сервер учитывает только при NODE_ENV=test. В production такая
    // переменная значит, что окружение перепутано (например, скопировано из
    // тестового), — это ошибка, даже если сервер её и не применит.
    const testKnobs = Object.keys(env).filter(name => name.startsWith('NYXO_TEST_') && env[name] !== undefined).sort();
    if (testKnobs.length > 0) {
        if (production) err(testKnobs.join(', '), 'тестовые настройки недопустимы при NODE_ENV=production — удалите их');
        else if (get('NODE_ENV') !== 'test') warn(testKnobs.join(', '), 'действуют только при NODE_ENV=test — сейчас не применяются');
    }

    // Тестовые ручки журнала ключей (длина эпохи и поколения — константы протокола, не настройки).
    const ktKnobs = KT_TEST_KNOBS.filter(name => get(name));
    if (ktKnobs.length > 0) {
        if (production) err(ktKnobs.join(', '), 'тестовые настройки журнала ключей недопустимы при NODE_ENV=production — длина эпохи и поколения заданы протоколом, удалите их');
        else if (get('NODE_ENV') !== 'test') warn(ktKnobs.join(', '), 'действуют только при NODE_ENV=test — сейчас не применяются');
    }

    return { errors, warnings, info };
}

function formatEnvReport({ errors, warnings, info }) {
    const lines = [];
    for (const e of errors) lines.push(`  ОШИБКА  ${e.name}: ${e.message}`);
    for (const w of warnings) lines.push(`  ВНИМАНИЕ ${w.name}: ${w.message}`);
    for (const i of info) lines.push(`  инфо    ${i.name}: ${i.message}`);
    const head = errors.length === 0 && warnings.length === 0
        ? 'Проверка настроек: всё в порядке'
        : `Проверка настроек: ошибок ${errors.length}, предупреждений ${warnings.length}`;
    return [head, ...lines].join('\n');
}

module.exports = { checkEnv, formatEnvReport, KNOWN_LEAKED_SHA256, NUMERIC_KNOBS, _internal: { sha256 } };
