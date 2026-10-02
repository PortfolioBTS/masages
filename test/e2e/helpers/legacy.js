'use strict';
// Легаси-фикстура: база версии 2.0.0 (аккаунты с email и паролем),
// test/e2e/fixtures/legacy-2.0.0.{sql,json}.
//
// Достаточно загрузить её в свежую базу: реальных пользователей нет, и
// новая версия при первом запуске на старой схеме один раз сбрасывает базу
// (это делает задача волны 1). Сдвиг времени и досев ключей, заявок и
// файлов не нужны.
//
// Дамп — pg_dump --column-inserts без psql-команд: выполняется одним
// запросом по простому протоколу. Соединение — отдельное и закрывается
// сразу: дамп меняет настройки сессии (search_path = '').

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
const { FIXTURES_DIR } = require('./env');

const FIXTURE = 'legacy-2.0.0';

function legacyMeta() {
    return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, `${FIXTURE}.json`), 'utf8'));
}

// Секреты, которыми зашифрованы сообщения и подписаны сессии фикстуры
// (тестовые значения, не секреты).
function legacyServerSecrets() {
    const { MESSAGE_ENCRYPTION_KEY, SESSION_SECRET } = legacyMeta().testOnlySecrets;
    return { MESSAGE_ENCRYPTION_KEY, SESSION_SECRET };
}

async function loadLegacyFixture(databaseUrl) {
    const meta = legacyMeta();
    const sql = fs.readFileSync(path.join(FIXTURES_DIR, meta.sql), 'utf8');
    const psqlCommand = sql.split('\n').find(line => line.startsWith('\\'));
    if (psqlCommand) throw new Error(`в ${meta.sql} команда psql «${psqlCommand.slice(0, 40)}» — node-postgres её не выполнит (см. fixtures/README.md)`);
    const client = new Client({ connectionString: databaseUrl });
    await client.connect();
    try {
        await client.query(sql);
    } finally {
        await client.end();
    }
    return meta;
}

module.exports = { loadLegacyFixture, legacyMeta, legacyServerSecrets, FIXTURE };
