'use strict';
// Тесты-запреты: поисковые критерии готовности этапов как тест.
//
// Критерий плана — «поиск по <шаблону> находит только …». Здесь он выполняется
// по файлам из `git ls-files`: правило = шаблон + область (пути) + список
// разрешений. Каждое разрешение — файл (иногда ещё и строка) с обоснованием;
// обоснования те же, что в docs/dev/forbidden-terms.md. При нарушении тест
// печатает «файл:строка:совпадение».
//
// Правила:
//   * этап 1 — остатки входа по почте и паролю
//     (email|password|/api/login|register-btn|парол, без учёта регистра);
//   * этап 2 — голос и аудио (record|mic|голосов|MediaRecorder|getUserMedia|audio/).
//
// Тест зелёный, только когда реализация этапов 1–2 слита целиком. На ветке, где
// клиент ещё старый, его можно пропустить: NYXO_SKIP_FORBIDDEN=1 npm test.
// Пропуск не действует в CI (переменная CI) — ворота G1 идут без него.
//
// Запуск: node test/forbidden-terms.test.js

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SELF = 'test/forbidden-terms.test.js';

// ---------- Область ----------

// Не проверяется никогда: документация (там эти слова — предмет описания),
// фикстуры старой схемы, чужие библиотеки и сам этот тест.
function isExcluded(file) {
    return file.startsWith('docs/')
        || file.endsWith('.md')
        || file.startsWith('test/e2e/fixtures/')
        || file.startsWith('public/vendor/')
        || file === SELF;
}
// Код, который работает в проде: сервер, lib/, клиент (без vendor).
const isProdCode = (file) => file === 'server.js' || file.startsWith('lib/') || file.startsWith('public/');
// Юнит-тесты: только test/*.test.js, без вложенных папок (сквозные тесты в
// test/e2e/ нарочно описывают старый вход, чтобы проверить его отсутствие).
const isUnitTest = (file) => /^test\/[^/]+\.test\.js$/.test(file);

// ---------- Правила ----------

// allow: { file: строка | RegExp, line?: RegExp, reason }. Без line — разрешён
// весь файл; с line — только подходящие строки (регулярное выражение должно
// быть узким: изменившаяся строка станет новым нарушением).
const RULES = [
    {
        id: 'stage1-legacy-auth',
        title: 'этап 1: остатки входа по почте и паролю',
        pattern: /email|password|\/api\/login|register-btn|парол/i,
        scope: (file) => isProdCode(file) || isUnitTest(file),
        allow: [
            { file: 'lib/legacy-reset.js', reason: 'сброс старой схемы: модуль ищет колонки email/password и удаляет таблицы версии 2.0.0 — ради этого он и существует' },
            { file: 'test/legacy-reset.test.js', reason: 'юнит-тест того же модуля сброса старой схемы' },
            { file: 'server.js', line: /Схема версии 2\.0\.0 \(аккаунты с email и паролем\)/, reason: 'комментарий у вызова сброса старой схемы в initDatabase' },
            { file: 'lib/security-utils.js', line: /url\.password|логин\/пароль/, reason: 'проверка Origin: адрес с логином и паролем (userinfo) не принимается — это разбор URL, а не вход в приложение' },
            { file: 'lib/security-txt.js', line: /url.password/, reason: 'security.txt: адрес связи с логином и паролем (userinfo) не принимается — это разбор URL, а не вход в приложение' },
            { file: 'lib/env-check.js', reason: 'пароль в DATABASE_URL, хэши утёкших паролей базы (DATABASE_PASSWORD), остатки PASSWORD_PEPPER и HIBP_CHECK в предупреждении «переменная не используется»' },
            { file: 'test/env-check.test.js', reason: 'юнит-тест модуля env-check (те же слова: пароль базы, PASSWORD_PEPPER)' },
            { file: /^public\//, line: /ни email, ни телефона, ни паролей/, reason: 'обязательная фраза интерфейса (экран входа, «Как это работает»)' },
        ],
    },
    {
        id: 'stage2-audio',
        title: 'этап 2: голос и аудио',
        pattern: /record|mic|голосов|MediaRecorder|getUserMedia|audio\//i,
        scope: isProdCode,
        allow: [
            { file: 'lib/privacy.js', line: /Permissions-Policy.*microphone=\(\)/, reason: 'заголовок Permissions-Policy запрещает странице доступ к микрофону' },
        ],
    },
];

// ---------- Движок ----------

const allowMatches = (allow, file) => (typeof allow.file === 'string' ? allow.file === file : allow.file.test(file));

// Находит нарушения правила в файлах. files: [{ file, text }]. Возвращает
// { violations: [{ file, line, match, text }], used: Set<allow> }.
function scanRule(rule, files) {
    const violations = [];
    const used = new Set();
    for (const { file, text } of files) {
        if (isExcluded(file) || !rule.scope(file)) continue;
        const lines = text.split(/\r?\n/);
        lines.forEach((line, index) => {
            const found = line.match(new RegExp(rule.pattern.source, rule.pattern.flags.replace('g', '')));
            if (!found) return;
            const allow = rule.allow.find(entry => allowMatches(entry, file) && (!entry.line || entry.line.test(line)));
            if (allow) { used.add(allow); return; }
            violations.push({ file, line: index + 1, match: found[0], text: line.trim().slice(0, 160) });
        });
    }
    return { violations, used };
}

const formatViolations = (rule, violations) =>
    `${rule.title}: нарушений ${violations.length} (шаблон ${rule.pattern}); разрешить можно только с обоснованием — docs/dev/forbidden-terms.md\n`
    + violations.map(v => `${v.file}:${v.line}:${v.match}    ${v.text}`).join('\n');

function trackedTextFiles() {
    const run = spawnSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (run.error || run.status !== 0) return null;
    const files = [];
    for (const file of run.stdout.split('\0').filter(Boolean)) {
        if (isExcluded(file)) continue;
        let buffer;
        try { buffer = fs.readFileSync(path.join(ROOT, file)); } catch { continue; }   // удалён в рабочей папке
        if (buffer.includes(0)) continue;                                              // двоичный файл
        files.push({ file, text: buffer.toString('utf8') });
    }
    return files;
}

// ---------- Мини-харнесс ----------

let passed = 0, failed = 0, skipped = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.message ? err.message.split('\n').join('\n        ') : err);
    }
}
function skip(name, why) {
    skipped++;
    console.log('  skip -', name, `(${why})`);
}

console.log('Forbidden terms tests\n');

// ---------- Проверка самого движка ----------

const fake = (file, text) => ({ file, text });

test('нарушение печатается как файл:строка:совпадение, регистр не важен', () => {
    const rule = RULES[0];
    const { violations } = scanRule(rule, [fake('public/x.js', 'a\nconst PASSWORD_PEPPER = 1;\nok'), fake('lib/y.js', 'fetch("/api/login")')]);
    assert.deepStrictEqual(violations.map(v => `${v.file}:${v.line}:${v.match}`), ['public/x.js:2:PASSWORD', 'lib/y.js:1:/api/login']);
    assert.match(formatViolations(rule, violations), /public\/x\.js:2:PASSWORD {4}const PASSWORD_PEPPER = 1;/);
});

test('все слова критериев находятся: email, password, /api/login, register-btn, парол; record, mic, голосов, MediaRecorder, getUserMedia, audio/', () => {
    const [auth, audio] = RULES;
    for (const word of ['Email', 'password', '/api/login', 'register-btn', 'Пароль', 'паролей']) {
        assert.strictEqual(scanRule(auth, [fake('server.js', `x ${word} y`)]).violations.length, 1, word);
    }
    for (const word of ['record-btn', 'icon-mic', 'голосовое', 'MediaRecorder', 'getUserMedia', 'audio/mpeg', 'Recording']) {
        assert.strictEqual(scanRule(audio, [fake('public/a.js', `x ${word} y`)]).violations.length, 1, word);
    }
});

test('область: этап 1 — server.js, lib/**, public/** и test/*.test.js, но не test/e2e/**; этап 2 — только прод-код', () => {
    const [auth, audio] = RULES;
    const inScope = (rule, file) => scanRule(rule, [fake(file, 'password record')]).violations.length > 0;
    for (const file of ['server.js', 'lib/a/b.js', 'public/script.js', 'public/sub/dir/x.html', 'test/some.test.js']) assert.ok(inScope(auth, file), `${file}: этап 1`);
    for (const file of ['test/e2e/x.e2e.test.js', 'test/e2e/helpers/y.js', 'test/helper.js', 'scripts/dev.js', 'README.txt', '.github/workflows/ci.yml']) assert.ok(!inScope(auth, file), `${file}: вне этапа 1`);
    for (const file of ['server.js', 'lib/a.js', 'public/script.js']) assert.ok(inScope(audio, file), `${file}: этап 2`);
    for (const file of ['test/some.test.js', 'test/e2e/x.e2e.test.js', 'scripts/dev.js']) assert.ok(!inScope(audio, file), `${file}: вне этапа 2`);
});

test('исключены: docs/**, *.md, фикстуры, public/vendor/**, сам тест', () => {
    for (const rule of RULES) {
        for (const file of ['docs/dev/x.md', 'docs/x.txt', 'README.md', 'lib/NOTES.md', 'test/e2e/fixtures/legacy.sql', 'public/vendor/lib.js', SELF]) {
            assert.deepStrictEqual(scanRule(rule, [fake(file, 'password record mic')]).violations, [], file);
        }
    }
});

test('разрешение на файл снимает все его строки, разрешение на строку — только подходящую; чужой файл не защищён', () => {
    const rule = {
        pattern: /secret/i, scope: () => true, title: 't',
        allow: [{ file: 'a.js', reason: 'r' }, { file: 'b.js', line: /^ok secret$/, reason: 'r' }, { file: /^c\//, line: /fine/, reason: 'r' }],
    };
    const result = scanRule(rule, [
        fake('a.js', 'secret\nsecret'),
        fake('b.js', 'ok secret\nbad secret'),
        fake('c/x.js', 'fine secret\nother secret'),
        fake('d.js', 'secret'),
    ]);
    assert.deepStrictEqual(result.violations.map(v => `${v.file}:${v.line}`), ['b.js:2', 'c/x.js:2', 'd.js:1']);
    assert.strictEqual(result.used.size, 3);
});

test('каждое разрешение применяется: устаревшее (ничего не разрешающее) движок находит', () => {
    const rule = { pattern: /secret/, scope: () => true, title: 't', allow: [{ file: 'a.js', reason: 'r' }, { file: 'gone.js', reason: 'r' }] };
    const { used } = scanRule(rule, [fake('a.js', 'secret')]);
    assert.deepStrictEqual(rule.allow.filter(entry => !used.has(entry)).map(entry => entry.file), ['gone.js']);
});

test('правила: у каждого разрешения есть обоснование, у строчных — узкое выражение; в документе перечислены все файлы', () => {
    const doc = fs.readFileSync(path.join(ROOT, 'docs', 'dev', 'forbidden-terms.md'), 'utf8');
    for (const rule of RULES) {
        assert.ok(doc.includes(rule.id), `в docs/dev/forbidden-terms.md нет правила ${rule.id}`);
        for (const entry of rule.allow) {
            assert.ok(typeof entry.reason === 'string' && entry.reason.length >= 20, `${rule.id}: разрешение без обоснования`);
            const name = typeof entry.file === 'string' ? entry.file : entry.file.source.replace(/^\^|\\/g, '');
            assert.ok(doc.includes(name), `в docs/dev/forbidden-terms.md не описано разрешение для ${name}`);
            if (entry.line) assert.ok(entry.line.source.length >= 10, `${rule.id}: слишком широкое выражение строки ${entry.line}`);
        }
    }
});

// ---------- Проверка репозитория ----------

const skipRequested = process.env.NYXO_SKIP_FORBIDDEN === '1';
const files = trackedTextFiles();

if (skipRequested && process.env.CI) {
    test('NYXO_SKIP_FORBIDDEN в CI не действует', () => {
        assert.fail('NYXO_SKIP_FORBIDDEN=1 допустим только на ветке разработки; в CI и на воротах G1 запреты проверяются без пропуска');
    });
} else if (skipRequested) {
    skip('репозиторий: правила этапов 1–2', 'NYXO_SKIP_FORBIDDEN=1 — ВРЕМЕННО, для ветки без слитой реализации этапов 1–2');
} else if (!files) {
    skip('репозиторий: правила этапов 1–2', 'git недоступен');
} else {
    for (const rule of RULES) {
        const { violations, used } = scanRule(rule, files);
        test(`репозиторий: ${rule.title} — нарушений нет`, () => {
            // assert.fail, а не deepStrictEqual: тот напечатал бы весь массив объектов вместо списка «файл:строка:совпадение».
            if (violations.length > 0) assert.fail('\n' + formatViolations(rule, violations));
        });
        test(`репозиторий: ${rule.id} — все разрешения ещё нужны`, () => {
            const stale = rule.allow.filter(entry => !used.has(entry)).map(entry => `${entry.file}${entry.line ? ` (строка ${entry.line})` : ''}: ${entry.reason}`);
            if (stale.length > 0) assert.fail('\nразрешения, под которые ничего не попадает, — уберите их из теста и из docs/dev/forbidden-terms.md:\n' + stale.join('\n'));
        });
    }
}

console.log(`\n${passed} passed, ${failed} failed${skipped ? `, ${skipped} skipped` : ''}`);
if (failed > 0) process.exitCode = 1;
