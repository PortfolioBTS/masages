require('dotenv').config();

// Отчёт о настройках и секретах — первым делом, до модулей, которые могут
// упасть на неверном значении: в логах деплоя будет видно, что именно не так
// (значения не печатаются). То же вручную: npm run check-env.
{
    const { checkEnv, formatEnvReport } = require('./lib/env-check');
    const envReport = checkEnv(process.env);
    (envReport.errors.length > 0 ? console.error : console.log)('[Env] ' + formatEnvReport(envReport));
}

// Точка входа. Весь код сервера — в src/ (карта: src/create-server.js): конфигурация
// (src/config.js), база (src/db/), HTTP (src/http/), сокеты (src/realtime/), предметная логика
// (src/services/), фоновые задачи (src/jobs/). Здесь только запуск.
const { loadConfig } = require('./src/config');
const { createServer } = require('./src/create-server');

// Порт открывается и миграции идут только когда файл запущен как программа (node server.js,
// npm start): тесты и скрипты могут подключить createServer, не поднимая сервер.
if (require.main === module) {
    createServer(loadConfig(__dirname)).start();
}

module.exports = { loadConfig, createServer };
