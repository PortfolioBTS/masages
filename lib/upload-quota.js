'use strict';
// Квота вложений под псевдонимом (docs/security/sealed-sender.md, раздел 13).
//
// UPLOAD_QUOTA_MB считает ОБЪЁМ ЗАГРУЗОК ЗА ОКНО В 30 ДНЕЙ, а не сумму размеров
// сообщений пользователя: у строки сообщения комнаты нет user_id. Строка квоты
// лежит в таблице upload_quota под qkey = HMAC(K_quota, u32be(user_id))[0..16]
// (lib/author-tag.js): в таблице нет ни user_id, ни внешних ключей — связать её с
// учётной записью без ключа сервера нельзя. Удаление сообщения квоту НЕ
// возвращает; откат транзакции вставки (409, ошибка) откатывает и резервирование.
//
// * initUploadQuotaSchema — таблица (initDatabase, вместе с остальной схемой);
// * reserveUploadQuota    — резервирование в транзакции вставки сообщения;
// * deleteQuotaRows       — удаление аккаунта (по qkey от текущего и прежних ключей);
// * jobs                  — суточная уборка окон старше 30 суток (lib/jobs).

const WINDOW_DAYS = 30;

async function initUploadQuotaSchema(pool) {
    // Внешних ключей нет намеренно (строку нельзя связать с users средствами БД).
    await pool.query(`
        CREATE TABLE IF NOT EXISTS upload_quota (
            qkey BYTEA PRIMARY KEY CHECK (octet_length(qkey) = 16),
            window_start DATE NOT NULL,
            bytes BIGINT NOT NULL CHECK (bytes >= 0)
        )
    `);
}

// Окно фиксированное: начинается с первой загрузки после истечения прежнего.
// Строка меняется только если после прибавления размера объём не превышает
// квоту; нет строки в RETURNING — квота исчерпана (413). На стыке окон возможен
// всплеск до двойной квоты (вопрос 8 документа, принято).
const RESERVE_SQL = `
    INSERT INTO upload_quota AS q (qkey, window_start, bytes)
    VALUES ($1::bytea, current_date, $2::bigint)
    ON CONFLICT (qkey) DO UPDATE SET
        window_start = CASE WHEN q.window_start <= current_date - ${WINDOW_DAYS} THEN current_date ELSE q.window_start END,
        bytes        = CASE WHEN q.window_start <= current_date - ${WINDOW_DAYS} THEN $2::bigint ELSE q.bytes + $2::bigint END
    WHERE (CASE WHEN q.window_start <= current_date - ${WINDOW_DAYS} THEN $2::bigint ELSE q.bytes + $2::bigint END) <= $3::bigint
    RETURNING 1
`;

// client — клиент транзакции вставки сообщения (users уже заблокирована
// FOR KEY SHARE, комната — FOR NO KEY UPDATE, членство проверено). Размер файла
// больше квоты отсеивается до транзакции. true — зарезервировано.
async function reserveUploadQuota(client, qkey, bytes, quotaBytes) {
    // Одиночная вставка с размером больше квоты не должна оставить строку: условие
    // WHERE ON CONFLICT к первой вставке не применяется, поэтому проверяется здесь.
    if (!(bytes <= quotaBytes)) return false;
    const result = await client.query(RESERVE_SQL, [qkey, bytes, quotaBytes]);
    return result.rows.length > 0;
}

// Сколько байт ещё можно загрузить. Нужен ДО тяжёлой обработки файла: резерв
// делается только в транзакции вставки сообщения, и без этой проверки аккаунт с
// исчерпанной квотой каждый раз гонял бы санитайзер впустую. Только подсказка:
// решающее слово остаётся за reserveUploadQuota (гонка двух загрузок возможна).
// db — объект с dbGet(sql, params) (как у контекста сервера).
async function remainingUploadQuota(db, qkey, quotaBytes) {
    const row = await db.dbGet(
        `SELECT CASE WHEN window_start <= current_date - ${WINDOW_DAYS} THEN 0 ELSE bytes END AS used
           FROM upload_quota WHERE qkey = $1::bytea`,
        [qkey]
    );
    const used = row ? Number(row.used) : 0;
    return Math.max(0, quotaBytes - (Number.isFinite(used) ? used : 0));
}

// Удаление аккаунта: окна, начатые под текущим и прежними ключами сообщений.
async function deleteQuotaRows(client, qkeys) {
    if (qkeys.length === 0) return 0;
    const result = await client.query('DELETE FROM upload_quota WHERE qkey = ANY($1::bytea[])', [qkeys]);
    return result.rowCount;
}

// Окно, истёкшее без новых загрузок, в дампе не остаётся.
async function purgeExpiredQuota(pool) {
    const result = await pool.query(`DELETE FROM upload_quota WHERE window_start <= current_date - ${WINDOW_DAYS}`);
    return result.rowCount;
}

// Задачи для реестра lib/jobs (JOB_MODULES): раз в сутки, под runExclusive.
function jobs(ctx) {
    return [{
        name: 'purgeUploadQuota',
        run: () => purgeExpiredQuota(ctx.pool),
        firstDelayMs: 5 * 60 * 1000,
        intervalMs: 24 * 60 * 60 * 1000,
        maintenance: true,
    }];
}

module.exports = {
    WINDOW_DAYS,
    RESERVE_SQL,
    initUploadQuotaSchema,
    reserveUploadQuota,
    remainingUploadQuota,
    deleteQuotaRows,
    purgeExpiredQuota,
    jobs,
};
