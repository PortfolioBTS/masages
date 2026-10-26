'use strict';
// Запуск процесса: страховочные обработчики, миграции, затем открытие портов и запуск фоновых
// задач. Вызывается только когда server.js запущен как программа (require.main === module).
// Вынесено из server.js.

const os = require('os');
// Onion-сервис (контейнер tor-service/)
const { ONION_ADDRESS, ONION_PORT, listenOnionPort } = require('../lib/tor-support');
// Несколько экземпляров сервера на одной базе (миграции и фоновые задачи
// под advisory-блокировками) и запись ошибок в лог без id из detail.
const { LOCK_NOT_AVAILABLE } = require('../lib/advisory-locks');
const { logError } = require('../lib/log-error');
// Штатная остановка по SIGTERM/SIGINT (ревью W7 R2.5).
const { createShutdown } = require('./shutdown');

function getLocalAddresses() {
    const nets = os.networkInterfaces();
    const addresses = [];
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                addresses.push(net.address);
            }
        }
    }
    return addresses;
}

function createLifecycle(ctx) {
    const { IS_PRODUCTION, PORT, HOST, readiness, server, io, pool, initDatabaseExclusive, jobs } = ctx;
    let onionListener = null;

    function onServerListening() {
        // Адреса сетевых интерфейсов нужны только при разработке (открыть сервер
        // с телефона); в production и в сквозных тестах IP в лог не пишутся.
        const addresses = IS_PRODUCTION || process.env.NODE_ENV === 'test' ? [] : getLocalAddresses();
        console.log(`\n${'='.repeat(60)}`);
        console.log(`Nyxo Messenger запущен на порту ${PORT}`);
        console.log(`${'='.repeat(60)}\n`);

        if (addresses.length > 0) {
            console.log('Доступен по адресам:');
            addresses.forEach(addr => console.log(`  → http://${addr}:${PORT}`));
            console.log('');
        }

        // Фоновые задачи (реестр — в src/jobs/index.js).
        jobs.start();

        // Только то, что действительно включено в этом запуске.
        console.log('Функции безопасности:');
        console.log('  + CSRF-токен и проверка Origin (HTTP и WebSocket)');
        console.log('  + Rate limiting (IP, аккаунт) и proof-of-work при регистрации');
        console.log('  + Очистка метаданных и обезличенные имена вложений');
        console.log('  + Исчезающие сообщения, физическое удаление');
        console.log('  + Шифрование текста сообщений в БД (AES-256-GCM с привязкой к комнате)');
        console.log('  + CSP без inline-кода, заголовки приватности' + (IS_PRODUCTION ? ', HSTS по https' : ''));
        console.log('  + E2EE: ключи во встроенном хранилище (эта же база)');
        if (ONION_ADDRESS && ONION_PORT) console.log(`  + Onion-сервис: http://${ONION_ADDRESS} (внутренний порт ${ONION_PORT})`);
        console.log(`\n${'='.repeat(60)}\n`);
    }

    function start() {
        // Страховка: ошибка в фоновой задаче (таймеры, сокеты) не должна ронять
        // весь сервер. Маршруты уже защищены wrapAsync. Причина — через logError:
        // объект целиком (console.error(reason)) печатает detail и where ошибок
        // Postgres со значениями строк.
        process.on('unhandledRejection', (reason) => {
            logError('[Process] Необработанный reject промиса', reason);
        });
        // Непойманное исключение по-прежнему завершает процесс (состояние после него
        // неизвестно, хостинг перезапустит), но без обработчика Node печатает ошибку
        // сам — вместе со стеком и полями вроде detail. Здесь пишется то же, что
        // и везде, и сразу выходит.
        process.on('uncaughtException', (err) => {
            logError('[Process] Необработанное исключение', err);
            process.exit(1);
        });
        // SIGTERM — деплой и перезапуск на хостинге, SIGINT — Ctrl+C при разработке.
        const shutdown = createShutdown({ server, io, pool, jobs, getOnionListener: () => onionListener });
        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));

        // Порт открывается только ПОСЛЕ миграций. Раньше listen() вызывался сразу,
        // параллельно с initDatabase(): первые запросы попадали на недомигрированную
        // БД и висели на блокировках ALTER TABLE.
        initDatabaseExclusive()
            .then(() => {
                readiness.migrated = true;
                server.listen(PORT, HOST, onServerListening);
                // Отдельный внутренний порт для tor-service: соединения с него
                // помечаются как onion (lib/tor-support.js). Наружу его не публиковать.
                onionListener = listenOnionPort(server, HOST, () => console.log(`[Tor] Onion-порт ${ONION_PORT} слушается`));
            })
            .catch((err) => {
                logError(err && err.code === LOCK_NOT_AVAILABLE
                    ? 'Ошибка инициализации БД: миграция не дождалась блокировки таблицы (идут долгие запросы), нужен перезапуск'
                    : 'Ошибка инициализации БД', err);
                process.exit(1);
            });
    }

    return { start };
}

module.exports = { createLifecycle };
