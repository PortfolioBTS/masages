'use strict';
// Диагностика упавшего набора: причины сбоев и логи серверов — в
// test/e2e/.logs/ (в CI — артефакт).
//
// Зачем отдельно от логов серверов. Набор (файл *.e2e.test.js) может упасть
// не тестом, а целиком: исключение в before/after-хуке, сбой старта сервера,
// исключение из таймера после конца теста. Для runner это «tests N+1, fail 1»
// с названием файла и без подробностей, а логи серверов прежде сохранялись
// только при упавшем ТЕСТЕ — здесь не оставалось ничего. Теперь на каждый
// упавший набор (или набор с проблемами уборки) пишутся файлы:
//   <метка>-<набор>-<сервер>.log   — лог процесса каждого сервера набора;
//   <метка>-<набор>-suite.log      — причины: упавшие тесты, ошибки хуков,
//                                    необработанные исключения, сбои уборки.
// Повторное сохранение того же набора перезаписывает файлы (метка одна на
// набор), поэтому в итоге остаётся самая полная версия.

const fs = require('fs');
const path = require('path');
const { LOGS_DIR } = require('./env');

// Текст причины из чего угодно, что бросили или отклонили: Error (со стеком и
// причиной-cause, AggregateError), строка, объект.
function describeError(err, depth = 0) {
    if (err === undefined || err === null) return 'нет сведений о причине';
    if (typeof err === 'string') return err;
    if (err instanceof Error) {
        let text = err.stack || `${err.name}: ${err.message}`;
        if (Array.isArray(err.errors) && err.errors.length > 0 && depth < 2) {
            text += `\nВложенные ошибки (${err.errors.length}):\n${err.errors.map(e => describeError(e, depth + 1)).join('\n---\n')}`;
        }
        if (err.cause && depth < 2) text += `\nПричина:\n${describeError(err.cause, depth + 1)}`;
        return text;
    }
    try {
        return JSON.stringify(err);
    } catch {
        return String(err);
    }
}

const firstLine = (text) => String(text).split('\n')[0];

class SuiteDiagnostics {
    // logsDir, log, now — внедряются для юнит-теста.
    constructor(name, { logsDir = LOGS_DIR, log = console.log, now = () => new Date() } = {}) {
        this.name = name;
        this.logsDir = logsDir;
        this.log = log;
        this.now = now;
        this.problems = [];   // сбои: { where, text } — набор считается упавшим
        this.warnings = [];   // сбои уборки: тесты зелёные, но след остаётся
        this.stamp = null;
        this.announced = new Set();
    }

    get failed() { return this.problems.length > 0; }

    // Есть ли что сохранять: упал набор или не убралось.
    get needsSave() { return this.problems.length > 0 || this.warnings.length > 0; }

    fail(where, err) { this.problems.push({ where, text: describeError(err) }); }

    warn(where, err) { this.warnings.push({ where, text: describeError(err) }); }

    format({ dbName = null, files = [] } = {}) {
        const lines = [`Набор: ${this.name}`, `Время: ${this.now().toISOString()}`];
        if (dbName) lines.push(`База: ${dbName}`);
        lines.push('');
        if (this.problems.length > 0) {
            lines.push(`Причины сбоя (${this.problems.length}):`);
            this.problems.forEach((p, i) => lines.push(`${i + 1}. [${p.where}]`, p.text, ''));
        }
        if (this.warnings.length > 0) {
            lines.push(`Сбои уборки — тесты от них не падали (${this.warnings.length}):`);
            this.warnings.forEach((w, i) => lines.push(`${i + 1}. [${w.where}]`, w.text, ''));
        }
        if (files.length > 0) {
            lines.push('Логи серверов набора:');
            for (const f of files) lines.push(`  ${f.server}: ${path.basename(f.file)}`);
        } else {
            lines.push('Серверов у набора не было (или сбой случился до их создания).');
        }
        return `${lines.join('\n')}\n`;
    }

    // servers: [{ name, logs }] (logs.text() — весь лог). Возвращает пути
    // файлов. Каждый файл анонсируется в вывод теста один раз, сколько бы
    // раз набор ни сохранялся.
    save({ dbName = null, servers = [] } = {}) {
        fs.mkdirSync(this.logsDir, { recursive: true });
        if (!this.stamp) this.stamp = this.now().toISOString().replace(/[:.]/g, '-');
        const files = [];
        for (const server of servers) {
            const file = path.join(this.logsDir, `${this.stamp}-${this.name}-${server.name}.log`);
            fs.writeFileSync(file, `${server.logs.text()}\n`);
            files.push({ server: server.name, file });
        }
        const suiteFile = path.join(this.logsDir, `${this.stamp}-${this.name}-suite.log`);
        fs.writeFileSync(suiteFile, this.format({ dbName, files }));

        const announce = (key, text) => {
            if (this.announced.has(key)) return;
            this.announced.add(key);
            this.log(text);
        };
        for (const f of files) announce(f.file, `# лог сервера ${f.server}: ${path.relative(process.cwd(), f.file)}`);
        announce(suiteFile, `# причины сбоя набора ${this.name}: ${path.relative(process.cwd(), suiteFile)}`);
        for (const p of this.problems) announce(`problem:${p.where}:${p.text}`, `# сбой набора ${this.name} [${p.where}]: ${firstLine(p.text)}`);
        for (const w of this.warnings) announce(`warning:${w.where}:${w.text}`, `# ВНИМАНИЕ, уборка набора ${this.name} [${w.where}]: ${firstLine(w.text)}`);
        return { suiteFile, files };
    }
}

module.exports = { SuiteDiagnostics, describeError };
