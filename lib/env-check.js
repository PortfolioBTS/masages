// Проверка переменных окружения и секретов — без вывода самих значений.
//
// Запускается при старте сервера (результат — в логах деплоя) и отдельно:
// `npm run check-env` (на Railway: `railway run npm run check-env`).
// Ошибки не останавливают сервер (кроме тех, без которых он и так не
// стартует), но пишутся громко: неверный секрет обычно не ломает запуск, а
// тихо ломает функцию — как INTERNAL_KEY_SERVER_SECRET с KEY_SERVER_URL на
// 127.0.0.1, из-за которых не работало сквозное шифрование.

const crypto = require('crypto');

// SHA-256 значений из .env, попавшего в ПУБЛИЧНУЮ историю git (коммит
// d5cd834 от 15.07.2026, «Add files via upload»). Сами значения здесь не
// хранятся — только хэши, чтобы узнать их, если они всё ещё используются.
const KNOWN_LEAKED_SHA256 = {
    SESSION_SECRET: ['4c59afde926948e1687643298353fe8efc0e040a3ac2979362fca2da00f906db'],
    INTERNAL_KEY_SERVER_SECRET: ['a62cf1ca5a4004dbc5e5fe85dfe93604337bc1059455d2a566486a59740acdc4'],
    DATABASE_PASSWORD: ['12529561e844df2059d91f959710dc8b75f83a78bc83c21d6b88b6d77ca4cf73'],
};
const LEAK_NOTE = 'значение совпадает с утёкшим в публичную историю git (коммит d5cd834) — его нужно сменить';

const PLACEHOLDER_RE = /your_|change_?me|changeme|example|placeholder|secret_here|generate|another_|strong_secret|random_secret|^(test|secret|password|admin)$/i;

const sha256 = (value) => crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');

function isLoopbackHost(host) {
    return /^(localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0)$/i.test(host);
}

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

    // Хранилище E2EE-ключей.
    const remoteKeys = get('E2EE_KEY_STORE').toLowerCase() === 'remote';
    if (remoteKeys) {
        checkSecret('INTERNAL_KEY_SERVER_SECRET', { required: true });
        const keyUrl = get('KEY_SERVER_URL');
        if (!keyUrl) err('KEY_SERVER_URL', 'не задан при E2EE_KEY_STORE=remote');
        else {
            let url = null;
            try { url = new URL(keyUrl); } catch { err('KEY_SERVER_URL', 'не разбирается как URL'); }
            if (url && onRailway && isLoopbackHost(url.hostname)) {
                err('KEY_SERVER_URL', 'указывает на этот же контейнер (localhost) — на Railway key-server работает отдельным сервисом: http://<сервис>.railway.internal:7420');
            }
        }
    } else {
        note('E2EE_KEY_STORE', 'ключи E2EE хранятся во встроенном хранилище (эта же база)');
        const leftovers = ['INTERNAL_KEY_SERVER_SECRET', 'KEY_SERVER_URL'].filter(get);
        if (leftovers.length > 0) {
            warn(leftovers.join(', '), 'не используются (нет E2EE_KEY_STORE=remote) — их можно удалить');
        }
        if (isLeaked('INTERNAL_KEY_SERVER_SECRET', get('INTERNAL_KEY_SERVER_SECRET'))) {
            err('INTERNAL_KEY_SERVER_SECRET', LEAK_NOTE + ' (или просто удалить переменную)');
        }
    }

    // Необязательные секреты.
    const pepper = checkSecret('PASSWORD_PEPPER', { required: false });
    if (pepper) note('PASSWORD_PEPPER', 'задан — его нельзя менять и терять: пароли перестанут сходиться');
    const anonSecret = checkSecret('ANON_SERVICE_SECRET', { required: false });
    if (get('ANON_SERVICE_URL') && !anonSecret) warn('ANON_SERVICE_SECRET', 'ANON_SERVICE_URL задан без общего секрета — anon-service открыт для всех в сети');

    // Один и тот же секрет в двух местах — утечка одного раскрывает другой.
    const secrets = [
        ['SESSION_SECRET', sessionSecret], ['MESSAGE_ENCRYPTION_KEY', messageKey],
        ['INTERNAL_KEY_SERVER_SECRET', get('INTERNAL_KEY_SERVER_SECRET')], ['PASSWORD_PEPPER', pepper],
        ['ANON_SERVICE_SECRET', anonSecret],
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
    if (onRailway && !get('UPLOADS_DIR') && !get('RAILWAY_VOLUME_MOUNT_PATH')) {
        warn('UPLOADS_DIR', 'нет volume для вложений — файлы пропадут при следующем деплое');
    }
    const pow = get('POW_DIFFICULTY');
    if (pow && !(/^\d+$/.test(pow) && Number(pow) >= 8 && Number(pow) <= 28)) warn('POW_DIFFICULTY', 'допустимо 8..28, будет использовано 18');

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

module.exports = { checkEnv, formatEnvReport, KNOWN_LEAKED_SHA256, _internal: { sha256, isLoopbackHost } };
