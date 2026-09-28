#!/usr/bin/env node
// Проверка переменных окружения и секретов без вывода значений.
// Локально: npm run check-env (читает .env).
// На Railway: railway run npm run check-env — или смотрите логи деплоя,
// сервер печатает тот же отчёт при каждом старте.
'use strict';
require('dotenv').config();
const { checkEnv, formatEnvReport } = require('../lib/env-check');

const result = checkEnv(process.env);
console.log(formatEnvReport(result));
process.exitCode = result.errors.length > 0 ? 1 : 0;
