'use strict';
// Сброс старой схемы (версия 2.0.0) при первом старте новой версии: roadmap R0,
// контракт волны 1 §1.
//
// Реальных пользователей нет, все данные в базе тестовые, поэтому вместо
// переноса старых аккаунтов (email и пароль) база один раз очищается целиком, а
// initDatabase создаёт итоговую схему. Всё здесь вызывается под блокировкой
// миграций (lib/advisory-locks.js), до создания таблиц.
//
// * detectLegacySchema — признак старой схемы;
// * resetLegacySchema  — одна транзакция: посчитать данные, удалить таблицы и функцию;
// * deleteLegacyUploads — после COMMIT: файлы вложений по шаблону загрузок v2.0.0;
// * resetLegacyDatabase — всё вместе для initDatabase.
//
// В лог идут только числа — id и имена в нём не нужны (lib/log-error.js).

const fs = require('fs');
const path = require('path');

// Все таблицы приложения версии 2.0.0, дети раньше родителей. schema_meta
// сюда не входит: версия схемы пишется раннером миграций и переживает сброс.
const LEGACY_TABLES = Object.freeze([
    'reactions', 'message_expiry', 'chat_settings', 'room_settings', 'e2ee_key_shares', 'join_requests',
    'security_events', 'unread', 'room_participants', 'messages', 'chats', 'rooms', 'users',
    'identity_keys', 'signed_prekeys', 'one_time_prekeys', 'signed_pq_prekeys', 'session',
]);

// Имя загруженного файла в v2.0.0: `${Date.now()}-${24 hex}${расширение по MIME}`.
// Шаблон зафиксирован как историческая константа, а не берётся у кода загрузки:
// тот в следующих волнах меняет имена, а сброс обязан узнавать именно старые.
const LEGACY_UPLOAD_NAME_RE = /^\d{13}-[0-9a-f]{24}(\.[a-z0-9]{2,5})?$/;
// Временная копия при очистке метаданных (lib/metadata-stripper.js, TEMP_MARKER).
// Файл с таким маркером в имени cleanupStaleTempFiles и так считает брошенным и
// удаляет каждый час, так что правило здесь не шире прежнего.
const LEGACY_TEMP_MARKER = '-cleaned-';

// Сколько файлов удаляется одновременно: на большой папке по одному долго, а
// тысячи unlink разом упираются в лимит дескрипторов.
const DELETE_CONCURRENCY = 32;

function isLegacyUploadName(name) {
    if (typeof name !== 'string') return false;
    return LEGACY_UPLOAD_NAME_RE.test(name) || name.includes(LEGACY_TEMP_MARKER);
}

// Чистое решение по фактам о базе. Старая схема, если у users есть колонка
// email или password. Либо если users есть, а schema_meta нет: версий схемы до
// T0.1 не существовало, поэтому users без schema_meta — схема, которую новый код
// не создавал. Если schema_meta есть и колонок нет, сброс не выполняется никогда.
function isLegacySchema({ hasUsers, hasSchemaMeta, hasLegacyColumns }) {
    return Boolean(hasLegacyColumns) || (Boolean(hasUsers) && !hasSchemaMeta);
}

// Схема — current_schema(), как в initDatabase и раннере миграций. Колонки
// берутся из pg_attribute, а не из information_schema: та показывает только
// таблицы, на которые у роли есть права, и для чужой роли старая схема
// «исчезла» бы из проверки.
const FACTS_SQL = `
    SELECT to_regclass(quote_ident(current_schema()) || '.users') IS NOT NULL AS has_users,
           to_regclass(quote_ident(current_schema()) || '.schema_meta') IS NOT NULL AS has_schema_meta,
           EXISTS (
               SELECT 1 FROM pg_attribute
               WHERE attrelid = to_regclass(quote_ident(current_schema()) || '.users')
                 AND attname IN ('email', 'password') AND attnum > 0 AND NOT attisdropped
           ) AS has_legacy_columns
`;

async function detectLegacySchema(client) {
    const result = await client.query(FACTS_SQL);
    const row = result.rows[0] || {};
    return isLegacySchema({
        hasUsers: row.has_users,
        hasSchemaMeta: row.has_schema_meta,
        hasLegacyColumns: row.has_legacy_columns,
    });
}

// Строк в таблице; 0, если таблицы нет: старая схема могла быть создана не до
// конца (сервер упал посреди initDatabase), и сброс не должен падать на этом.
// Имя таблицы — только из констант этого файла.
async function countRows(client, table) {
    const exists = await client.query('SELECT to_regclass($1) IS NOT NULL AS present', [table]);
    if (!exists.rows[0] || !exists.rows[0].present) return 0;
    const result = await client.query(`SELECT count(*) AS n FROM ${table}`);
    return Number(result.rows[0].n);
}

// Одна транзакция: числа → DROP всех таблиц → DROP функции случайных id. Функция
// удаляется после таблиц: их DEFAULT'ы ссылаются на неё. Строка лога — после
// COMMIT: если DDL не дождался блокировки (lock_timeout) и initDatabase
// повторяется, строка не продублируется.
async function resetLegacySchema(client, { log = console.log } = {}) {
    let counts;
    await client.query('BEGIN');
    try {
        counts = {
            users: await countRows(client, 'users'),
            messages: await countRows(client, 'messages'),
        };
        for (const table of LEGACY_TABLES) {
            await client.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
        }
        await client.query('DROP FUNCTION IF EXISTS nyxo_random_id(regclass)');
        await client.query('COMMIT');
    } catch (err) {
        // Исходная ошибка важнее: сбой самого ROLLBACK её не затирает.
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    }
    log(`[Reset] Обнаружена старая схема: удаляются тестовые данные (пользователей: ${counts.users}, сообщений: ${counts.messages})`);
    return counts;
}

// Удаляет из папки вложений только обычные файлы со старыми именами. Папки
// (lost+found на volume), ссылки и всё остальное не трогаются. Возвращает число
// удалённых. Сбой чтения папки или удаления файла не останавливает старт: база
// уже сброшена, а осиротевший файл — лишь место на диске. В сообщении об ошибке
// только число и коды: имена файлов в лог не идут.
async function deleteLegacyUploads(uploadsDir, { log = console.log, error = console.error, fsApi = fs.promises } = {}) {
    let entries = [];
    try {
        entries = await fsApi.readdir(uploadsDir, { withFileTypes: true });
    } catch (err) {
        // Папки ещё нет — удалять нечего (сервер создаёт её при старте сам).
        if (err.code !== 'ENOENT') error(`[Reset] Не удалось прочитать папку вложений (код ошибки: ${err.code || 'unknown'})`);
    }
    const names = entries.filter(entry => entry.isFile() && isLegacyUploadName(entry.name)).map(entry => entry.name);

    let removed = 0;
    let failed = 0;
    const failureCodes = new Set();
    for (let i = 0; i < names.length; i += DELETE_CONCURRENCY) {
        await Promise.all(names.slice(i, i + DELETE_CONCURRENCY).map(async (name) => {
            try {
                await fsApi.unlink(path.join(uploadsDir, name));
                removed++;
            } catch (err) {
                // Файл уже удалён параллельно — цель достигнута.
                if (err.code === 'ENOENT') return;
                failed++;
                failureCodes.add(err.code || 'unknown');
            }
        }));
    }
    log(`[Reset] Удалено файлов вложений: ${removed}`);
    if (failed > 0) error(`[Reset] Не удалось удалить файлов вложений: ${failed} (коды ошибок: ${[...failureCodes].sort().join(', ')})`);
    return removed;
}

// Для initDatabase: старая схема есть — сбросить базу, затем файлы. false —
// сброс не понадобился. Соединение берётся из переданного пула (во время
// миграций это пул с lock_timeout) и возвращается в него; после ошибки
// соединение закрывается, а не возвращается.
async function resetLegacyDatabase({ pool, uploadsDir, log = console.log, error = console.error, fsApi }) {
    const client = await pool.connect();
    let failure;
    try {
        if (!(await detectLegacySchema(client))) return false;
        await resetLegacySchema(client, { log });
    } catch (err) {
        failure = err;
        throw err;
    } finally {
        client.release(failure);
    }
    await deleteLegacyUploads(uploadsDir, { log, error, fsApi });
    return true;
}

module.exports = {
    LEGACY_TABLES,
    LEGACY_UPLOAD_NAME_RE,
    LEGACY_TEMP_MARKER,
    isLegacyUploadName,
    isLegacySchema,
    detectLegacySchema,
    resetLegacySchema,
    deleteLegacyUploads,
    resetLegacyDatabase,
};
