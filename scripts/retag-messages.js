#!/usr/bin/env node
'use strict';
// Перетегирование сообщений комнат после смены MESSAGE_ENCRYPTION_KEY
// (docs/security/sealed-sender.md, 14.1; порядок действий оператора -
// docs/ops/message-key-rotation.md).
//
//   node scripts/retag-messages.js [--dry-run] [--verify] [--batch N] [--room ID] [--verbose]
//
//   (без флагов)  переписать все строки комнат, не лежащие под текущим ключом (kid и тег автора):
//                 новый тег автора и новое шифрование строки (K_enc3 нового ключа, AAD с новым
//                 тегом), пачками по 500 строк в одной транзакции каждая;
//   --dry-run     то же без записи: покажет, сколько строк будет переписано и что не удастся;
//   --verify      только чтение: нет строк со старым kid и нет тегов, не входящих в теги владельцев
//                 комнаты под НОВЫМ ключом. Прежний ключ убирают из MESSAGE_ENCRYPTION_KEY_PREVIOUS
//                 только после «проверка пройдена»;
//   --batch N     размер пачки (по умолчанию 500);
//   --room ID     только одна комната;
//   --verbose     печатать id проблемных строк (по умолчанию - только числа: id и тексты в отчёт
//                 не попадают).
//
// Окружение (как у сервера): DATABASE_URL; MESSAGE_ENCRYPTION_KEY - НОВЫЙ ключ;
// MESSAGE_ENCRYPTION_KEY_PREVIOUS - прежний (и все ещё нужные более старые); NODE_ENV=production,
// DB_CA_CERT / DB_TLS_INSECURE - TLS до Postgres, как у сервера. Скрипт идемпотентен и
// возобновляем: строка под новым kid пропускается. Код выхода: 0 - всё в порядке, 1 - ошибка,
// 2 - есть строки, которые перетегировать нельзя (отчёт выше), либо проверка не пройдена.

require('dotenv').config();
const { Pool } = require('pg');
const { logError } = require('../lib/log-error');

const USAGE = 'Использование: node scripts/retag-messages.js [--dry-run] [--verify] [--batch N] [--room ID] [--verbose]';

function parseArgs(argv) {
    const opts = { dryRun: false, verify: false, verbose: false, batchSize: undefined, roomId: undefined };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--dry-run') opts.dryRun = true;
        else if (arg === '--verify') opts.verify = true;
        else if (arg === '--verbose') opts.verbose = true;
        else if (arg === '--batch' || arg === '--room') {
            const value = Number(argv[++i]);
            if (!Number.isInteger(value) || value < 1) throw new Error(`${arg}: нужно целое число больше нуля`);
            if (arg === '--batch') opts.batchSize = value; else opts.roomId = value;
        } else throw new Error(`неизвестный параметр ${arg}\n${USAGE}`);
    }
    if (opts.verify && opts.dryRun) throw new Error('--verify и --dry-run несовместимы: проверка и так только читает');
    return opts;
}

function buildDeps() {
    // Модули читают и проверяют ключи при загрузке: без MESSAGE_ENCRYPTION_KEY - сразу ошибка.
    const messageCrypto = require('../lib/message-crypto');
    const { createAuthorTags } = require('../lib/author-tag');
    const ring = messageCrypto.messageKeyRing();
    const ikms = ring.map(entry => entry.ikm);
    return {
        authorTags: createAuthorTags(ikms),
        // Для проверки: только текущий ключ - после неё прежний убирают из …_PREVIOUS.
        currentKeyTags: createAuthorTags([ikms[0]]),
        crypto: {
            decryptRoomText: messageCrypto.decryptRoomText,
            encryptRoomText: messageCrypto.encryptRoomText,
            messageAadV3: messageCrypto.messageAadV3,
            DECRYPT_FAILED: messageCrypto.DECRYPT_FAILED,
        },
        currentKid: ring[0].kid,
        knownKids: new Set(ring.map(entry => entry.kid)),
        previousCount: ring.length - 1,
    };
}

function buildPool() {
    const { resolveDbTlsConfig } = require('../lib/security-utils');
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL не задан');
    const tls = resolveDbTlsConfig({
        nodeEnv: process.env.NODE_ENV,
        databaseUrl: process.env.DATABASE_URL,
        caCert: process.env.DB_CA_CERT,
        insecure: process.env.DB_TLS_INSECURE === 'true',
    });
    if (tls.error) throw new Error(tls.error);
    if (tls.warning) console.warn(tls.warning);
    return new Pool({ connectionString: process.env.DATABASE_URL, ssl: tls.ssl, max: 2, connectionTimeoutMillis: 10000 });
}

function printProblems(problems, verbose) {
    if (problems.length === 0) return;
    if (!verbose) {
        console.log('  (id проблемных строк не печатаются; --verbose покажет)');
        return;
    }
    for (const p of problems) console.log(`  комната ${p.roomId}, сообщение ${p.id}: ${p.status}${p.reason ? ` (${p.reason})` : ''}`);
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const { retagDatabase, verifyDatabase } = require('../lib/message-retag');
    const deps = buildDeps();
    const pool = buildPool();
    try {
        if (opts.verify) {
            const result = await verifyDatabase(pool, deps, opts);
            console.log(`Проверка: комнат ${result.rooms}; строк не под текущим kid: ${result.otherKid}; тегов вне тегов владельцев под новым ключом: ${result.unknownTag}; не enc:v3: ${result.notV3}`);
            printProblems(result.problems, opts.verbose);
            if (result.ok) console.log('Проверка пройдена: прежний ключ можно убирать из MESSAGE_ENCRYPTION_KEY_PREVIOUS.');
            else console.log('Проверка НЕ пройдена: прежний ключ из MESSAGE_ENCRYPTION_KEY_PREVIOUS убирать нельзя.');
            return result.ok ? 0 : 2;
        }
        if (deps.previousCount === 0) {
            console.log('MESSAGE_ENCRYPTION_KEY_PREVIOUS пуст: переписывать нечего (все строки читаются текущим ключом либо старого ключа уже нет).');
        }
        const totals = await retagDatabase(pool, deps, { ...opts, log: opts.verbose ? console.log : undefined });
        console.log(`${opts.dryRun ? 'Пробный прогон (ничего не записано)' : 'Готово'}: комнат ${totals.rooms}; просмотрено ${totals.scanned}; ${opts.dryRun ? 'будет переписано' : 'переписано'} ${totals.retagged}; ` +
            `не под enc:v3 текущей схемы ${totals.foreign}; не расшифровалось ${totals.undecryptable}; владелец тега не найден ${totals.orphan}`);
        printProblems(totals.problems, opts.verbose);
        return totals.foreign + totals.undecryptable + totals.orphan > 0 ? 2 : 0;
    } finally {
        await pool.end();
    }
}

if (require.main === module) {
    main().then((code) => { process.exitCode = code; }, (err) => {
        // Ошибки Postgres несут в detail значения строк: печатаются только
        // message и code (lib/log-error.js).
        logError('Ошибка', err);
        process.exitCode = 1;
    });
}

module.exports = { parseArgs };
