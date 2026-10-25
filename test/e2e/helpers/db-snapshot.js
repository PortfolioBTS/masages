'use strict';
// Снимок состояния базы набора для проверок «ничего не изменилось».
//
// Негативные тесты доступа (чужой chatId, чужая заявка, чужая реакция) недостаточно сверять по ответу
// сервера: отказ в ответе не доказывает, что запрос не успел что-то записать. Снимок берёт все строки
// таблиц, которых касаются маршруты чатов, комнат, заявок и реакций, и сравнивается до и после.
// Столбцы не перечисляются (to_jsonb): новый столбец попадёт в сравнение сам.
//
// users не входит: last_active_at и подобные поля меняются любым запросом и не про состояние чата.

const TABLES = [
    'chats', 'rooms', 'room_participants', 'room_member_certs', 'messages', 'message_expiry',
    'chat_settings', 'room_settings', 'join_requests', 'reactions', 'user_left_rooms',
    'e2ee_key_shares', 'e2ee_key_requests',
];

// { таблица: [строки в jsonb, по возрастанию текста] } - порядок строк не зависит от физического.
async function dbSnapshot(suite, tables = TABLES) {
    const snapshot = {};
    for (const table of tables) {
        const { rows } = await suite.query(
            `SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text), '[]'::jsonb) AS rows FROM ${table} t`
        );
        snapshot[table] = rows[0].rows;
    }
    return snapshot;
}

module.exports = { dbSnapshot, SNAPSHOT_TABLES: TABLES };
