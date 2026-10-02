'use strict';
// Тесты scripts/audit-check.js — политика npm audit (пункт 7.1). Без сети и
// без запуска npm: отчёты берутся из фикстур test/fixtures/npm-audit/ и
// собираются в тесте, подмена запуска npm — через io.runAudit и spawn.
//
// Фикстуры — НАСТОЯЩИЙ вывод `npm audit --json` (npm 11, auditReportVersion 2),
// снятый 2026-10-02:
//   repo-snapshot.json   этот репозиторий: 5 пакетов high в проде, цепочки через ws
//   lab-prod.json        отдельный проект: прод-цепочка mkdirp -> minimist (critical)
//   lab-all.json         он же без --omit=dev: добавлен dev-пакет lodash (high, moderate)
//   clean.json           чистый отчёт
//   registry-error.json  вывод npm при недоступном реестре
// Синтетические отчёты (makeReport) нужны для случаев, которых в настоящих
// выводах нет: исключения, одинаковый advisory в двух пакетах, мусор в тексте.
// Запуск: node test/audit-check.test.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'audit-check.js');
const audit = require(SCRIPT);
const FIXTURES = path.join(__dirname, 'fixtures', 'npm-audit');

let passed = 0, failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

const fixture = (name) => JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf8'));
const parse = (name) => audit.parseAuditReport(fixture(name), name);

// ---- синтетические отчёты в формате npm audit v7+ ----

let nextSource = 9000000;
function via(ghsa, severity, name, title) {
    return {
        source: nextSource++,
        name,
        dependency: name,
        title: title || `Synthetic advisory ${ghsa}`,
        url: `https://github.com/advisories/${ghsa}`,
        severity,
        cwe: [],
        cvss: { score: 0, vectorString: null },
        range: '<1.0.0',
    };
}

// entries: { имя пакета: [via…] }, строка в via — ссылка на другой пакет цепочки.
// Серьёзность пакета, как у npm, — наибольшая по его via и по цепочке.
function makeReport(entries) {
    const rankOf = (s) => audit.SEVERITIES.indexOf(s);
    const severityOf = (name, seen = new Set()) => {
        if (seen.has(name) || !entries[name]) return -1;
        seen.add(name);
        return Math.max(...entries[name].map((v) => (typeof v === 'string' ? severityOf(v, seen) : rankOf(v.severity))));
    };
    const vulnerabilities = {};
    const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
    for (const [name, list] of Object.entries(entries)) {
        const severity = audit.SEVERITIES[severityOf(name)];
        counts[severity] += 1;
        vulnerabilities[name] = {
            name, severity, isDirect: false, via: list, effects: [], range: '<1.0.0', nodes: [`node_modules/${name}`], fixAvailable: true,
        };
    }
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    return {
        auditReportVersion: 2,
        vulnerabilities,
        metadata: {
            vulnerabilities: { ...counts, total },
            dependencies: { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 },
        },
    };
}

// Разделитель строк Юникода (U+2028): в литерале регулярного выражения он недопустим, поэтому по коду.
const LS = String.fromCharCode(0x2028);
const TODAY = '2026-10-02';
const exception = (id, expires, reason = 'временно: ждём исправление в upstream') => ({ id, reason, expires });
const evaluate = (prod, options = {}) => audit.evaluate({ prod, today: TODAY, ...options });
const ids = (list) => list.map((a) => a.id);

// Временная папка на время fn (sync или async) — удаляется только после завершения fn.
async function withTempDir(fn) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nyxo-audit-check-'));
    try {
        return await fn(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

// main с подменой ввода-вывода: собирает вывод и код выхода.
async function runMain(argv, { env = {}, io = {} } = {}) {
    const out = [];
    const err = [];
    const code = await audit.main(argv, env, {
        out: (text) => out.push(text),
        err: (text) => err.push(text),
        now: () => new Date(`${TODAY}T12:00:00Z`),
        ...io,
    });
    return { code, out: out.join('\n'), err: err.join('\n') };
}

async function main() {
    console.log('Audit check tests\n');

    // ---------------------------------------------------------------- разбор отчёта

    await test('parse: real report of this repository gives 14 unique advisories; transitive entries have none of their own', () => {
        const advisories = parse('repo-snapshot.json');
        assert.strictEqual(advisories.size, 14);
        const bySeverity = { high: 0, moderate: 0, low: 0 };
        for (const a of advisories.values()) bySeverity[a.severity] += 1;
        assert.deepStrictEqual(bySeverity, { high: 4, moderate: 9, low: 1 });

        const ws = advisories.get('GHSA-96hv-2xvq-fx4p');
        assert.strictEqual(ws.severity, 'high');
        assert.deepStrictEqual([...ws.packages], ['ws']);
        assert.strictEqual(ws.url, 'https://github.com/advisories/GHSA-96hv-2xvq-fx4p');
        // socket.io-adapter «высокий» только через ws (via: ["ws"]) — своих advisory у него нет.
        for (const a of advisories.values()) assert.ok(!a.packages.has('socket.io-adapter'), a.id);
    });

    await test('parse: clean report gives no advisories', () => {
        assert.strictEqual(parse('clean.json').size, 0);
    });

    await test('parse: the same advisory in two packages is merged and keeps the highest severity', () => {
        const report = makeReport({
            a: [via('GHSA-aaaa-aaaa-aaaa', 'moderate', 'a')],
            b: [via('GHSA-aaaa-aaaa-aaaa', 'high', 'b')],
        });
        const advisories = audit.parseAuditReport(report);
        assert.strictEqual(advisories.size, 1);
        const merged = advisories.get('GHSA-aaaa-aaaa-aaaa');
        assert.strictEqual(merged.severity, 'high');
        assert.deepStrictEqual([...merged.packages].sort(), ['a', 'b']);
    });

    await test('parse: id comes from the url in any letter case; numeric source is the fallback', () => {
        const upper = via('GHSA-AAAA-BBBB-CCCC', 'high', 'x');
        const noUrl = { ...via('GHSA-dddd-dddd-dddd', 'low', 'y'), url: undefined, source: 4242 };
        const advisories = audit.parseAuditReport(makeReport({ x: [upper], y: [noUrl] }));
        assert.deepStrictEqual([...advisories.keys()].sort(), ['GHSA-aaaa-bbbb-cccc', 'npm-4242']);
    });

    await test('parse: advisory text is cleaned (control characters, leading "::", non-https links)', () => {
        const hostile = via('GHSA-aaaa-aaaa-aaaa', 'high', 'x', 'line one\n::add-mask::secret\u0007' + LS + 'tail');
        hostile.url = 'javascript:alert(1)//GHSA-aaaa-aaaa-aaaa';
        const [advisory] = audit.parseAuditReport(makeReport({ x: [hostile] })).values();
        assert.ok(!/[\n\r\u0007]/.test(advisory.title) && !advisory.title.includes(LS), JSON.stringify(advisory.title));
        assert.strictEqual(advisory.title, 'line one ::add-mask::secret tail');
        assert.strictEqual(advisory.url, '', 'ссылка не https — не показываем');

        const leading = via('GHSA-bbbb-bbbb-bbbb', 'high', 'x', '\n  ::set-output name=a::b');
        const [second] = audit.parseAuditReport(makeReport({ x: [leading] })).values();
        assert.ok(!second.title.startsWith('::'), second.title);
    });

    await test('parse: npm error output is rejected and the reason is shown', () => {
        assert.throws(() => parse('registry-error.json'), (err) => {
            assert.ok(err instanceof audit.AuditInputError);
            assert.match(err.message, /ECONNREFUSED/);
            return true;
        });
    });

    await test('parse: unsupported or broken reports are rejected', () => {
        const bad = (report, pattern) => assert.throws(() => audit.parseAuditReport(report, 'отчёт'), (err) => {
            assert.ok(err instanceof audit.AuditInputError, String(err));
            assert.match(err.message, pattern);
            return true;
        });
        bad(null, /JSON-объект/);
        bad([], /JSON-объект/);
        bad({ vulnerabilities: {} }, /неподдерживаемый формат/);
        bad({ auditReportVersion: 1, vulnerabilities: {} }, /неподдерживаемый формат/);
        bad({ auditReportVersion: 2 }, /неподдерживаемый формат/);
        bad({ auditReportVersion: 2, vulnerabilities: { p: { name: 'p' } } }, /нет via/);
        bad({ auditReportVersion: 2, vulnerabilities: { p: { via: [42] } } }, /неожиданное значение/);
        const weird = makeReport({ p: [via('GHSA-aaaa-aaaa-aaaa', 'high', 'p')] });
        weird.vulnerabilities.p.via[0].severity = 'catastrophic';
        bad(weird, /неизвестная серьёзность/);
        const noId = makeReport({ p: [via('GHSA-aaaa-aaaa-aaaa', 'high', 'p')] });
        delete noId.vulnerabilities.p.via[0].url;
        delete noId.vulnerabilities.p.via[0].source;
        bad(noId, /нельзя построить идентификатор/);
    });

    await test('parse: metadata that promises findings the vulnerabilities do not contain is a format error', () => {
        const report = makeReport({});
        report.metadata.vulnerabilities.high = 2;
        assert.throws(() => audit.parseAuditReport(report), /формат отчёта изменился/);
        // Обратное (в vulnerabilities больше, чем в metadata) — не ошибка: счётчики лишь страховка.
        const generous = makeReport({ p: [via('GHSA-aaaa-aaaa-aaaa', 'high', 'p')] });
        generous.metadata.vulnerabilities.high = 0;
        assert.strictEqual(audit.parseAuditReport(generous).size, 1);
    });

    // ---------------------------------------------------------------- политика

    await test('policy: high in production fails, moderate and low do not', () => {
        const result = evaluate(parse('repo-snapshot.json'));
        assert.strictEqual(result.ok, false);
        assert.deepStrictEqual(ids(result.blocking), [
            'GHSA-2gc4-cqfq-p2gv', 'GHSA-2m8v-j782-fhvr', 'GHSA-96hv-2xvq-fx4p', 'GHSA-mwp4-54f8-5fhr',
        ]);
        assert.ok(result.blocking.every((a) => a.severity === 'high' && a.scope === 'prod'));
        assert.strictEqual(result.nonBlocking.length, 10);
        assert.ok(result.nonBlocking.every((a) => a.severity === 'moderate' || a.severity === 'low'));
        assert.deepStrictEqual(result.counts.prod, { info: 0, low: 1, moderate: 9, high: 4, critical: 0 });
    });

    await test('policy: only moderate and low in production passes and lands in the summary', () => {
        const report = makeReport({
            a: [via('GHSA-aaaa-aaaa-aaaa', 'moderate', 'a')],
            b: [via('GHSA-bbbb-bbbb-bbbb', 'low', 'b')],
            c: [via('GHSA-cccc-cccc-cccc', 'info', 'c')],
        });
        const result = evaluate(audit.parseAuditReport(report));
        assert.strictEqual(result.ok, true);
        assert.deepStrictEqual(result.blocking, []);
        assert.deepStrictEqual(ids(result.nonBlocking), ['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb', 'GHSA-cccc-cccc-cccc']);
    });

    await test('policy: critical in production fails (real lab report with a transitive chain)', () => {
        const result = evaluate(parse('lab-prod.json'), { all: parse('lab-all.json') });
        assert.strictEqual(result.ok, false);
        assert.deepStrictEqual(ids(result.blocking), ['GHSA-xvch-5gv4-984h']);
        // mkdirp «critical» только через minimist: своего advisory у него нет.
        assert.deepStrictEqual(result.blocking[0].packages, ['minimist']);
    });

    await test('policy: high only in dev passes, critical only in dev fails', () => {
        // Настоящие отчёты: lodash (3 high, 3 moderate) есть только в полном отчёте — это dev.
        const lab = evaluate(parse('lab-prod.json'), { all: parse('lab-all.json') });
        const highDev = lab.nonBlocking.filter((a) => a.scope === 'dev' && a.severity === 'high');
        assert.strictEqual(highDev.length, 3, 'high в dev не блокирует');
        assert.deepStrictEqual(lab.counts.dev, { info: 0, low: 0, moderate: 3, high: 3, critical: 0 });

        // Синтетика: то же с чистым продом — dev high проходит, dev critical роняет сборку.
        const prodClean = audit.parseAuditReport(makeReport({}));
        const onlyHigh = audit.parseAuditReport(makeReport({ d: [via('GHSA-dddd-dddd-dddd', 'high', 'd')] }));
        assert.strictEqual(evaluate(prodClean, { all: onlyHigh }).ok, true);
        const devCritical = audit.parseAuditReport(makeReport({ d: [via('GHSA-dddd-dddd-dddd', 'critical', 'd')] }));
        const failed = evaluate(prodClean, { all: devCritical });
        assert.strictEqual(failed.ok, false);
        assert.strictEqual(failed.blocking[0].scope, 'dev');
    });

    await test('policy: an advisory present in both reports counts as production', () => {
        const report = audit.parseAuditReport(makeReport({ p: [via('GHSA-pppp-pppp-pppp', 'high', 'p')] }));
        const result = evaluate(report, { all: report });
        assert.strictEqual(result.blocking.length, 1);
        assert.strictEqual(result.blocking[0].scope, 'prod');
        assert.deepStrictEqual(result.counts.dev, { info: 0, low: 0, moderate: 0, high: 0, critical: 0 });
    });

    await test('policy: without a separate full report everything counts as production', () => {
        const dev = audit.parseAuditReport(makeReport({ d: [via('GHSA-dddd-dddd-dddd', 'high', 'd')] }));
        assert.strictEqual(evaluate(dev, { all: null }).ok, false);
    });

    await test('policy: today must be a YYYY-MM-DD string', () => {
        assert.throws(() => audit.evaluate({ prod: new Map(), today: '02.10.2026' }), TypeError);
    });

    // ---------------------------------------------------------------- исключения

    await test('exception: closes only its own advisory and is shown as applied', () => {
        const result = evaluate(parse('repo-snapshot.json'), { exceptions: [exception('GHSA-96hv-2xvq-fx4p', '2026-12-31')] });
        assert.strictEqual(result.ok, false);
        assert.deepStrictEqual(ids(result.excepted), ['GHSA-96hv-2xvq-fx4p']);
        assert.strictEqual(result.excepted[0].exception.expires, '2026-12-31');
        assert.deepStrictEqual(ids(result.blocking), ['GHSA-2gc4-cqfq-p2gv', 'GHSA-2m8v-j782-fhvr', 'GHSA-mwp4-54f8-5fhr']);

        // Исключения на все четыре high — сборка зелёная, moderate и low и так не блокируют.
        const everyHigh = ['GHSA-2gc4-cqfq-p2gv', 'GHSA-2m8v-j782-fhvr', 'GHSA-96hv-2xvq-fx4p', 'GHSA-mwp4-54f8-5fhr'];
        const covered = evaluate(parse('repo-snapshot.json'), { exceptions: everyHigh.map((id) => exception(id, '2026-12-31')) });
        assert.strictEqual(covered.ok, true);
        assert.strictEqual(covered.excepted.length, 4);
    });

    await test('exception: the root advisory covers the whole chain, unrelated findings stay', () => {
        // ws — корень цепочки; socket.io-adapter «high» только через ws; у engine.io есть и свой advisory.
        const report = makeReport({
            ws: [via('GHSA-wwww-wwww-wwww', 'high', 'ws')],
            'socket.io-adapter': ['ws'],
            'engine.io': [via('GHSA-eeee-eeee-eeee', 'high', 'engine.io'), 'ws'],
        });
        const prod = audit.parseAuditReport(report);
        const onlyRoot = evaluate(prod, { exceptions: [exception('GHSA-wwww-wwww-wwww', '2026-12-31')] });
        assert.deepStrictEqual(ids(onlyRoot.blocking), ['GHSA-eeee-eeee-eeee']);
        const both = evaluate(prod, { exceptions: [exception('GHSA-wwww-wwww-wwww', '2026-12-31'), exception('GHSA-eeee-eeee-eeee', '2026-12-31')] });
        assert.strictEqual(both.ok, true);
        assert.strictEqual(both.excepted.length, 2);
    });

    await test('exception: valid through the end of its day, expired the day after', () => {
        const prod = audit.parseAuditReport(makeReport({ p: [via('GHSA-pppp-pppp-pppp', 'high', 'p')] }));
        const lastDay = evaluate(prod, { exceptions: [exception('GHSA-pppp-pppp-pppp', TODAY)] });
        assert.strictEqual(lastDay.ok, true);
        assert.deepStrictEqual(lastDay.expired, []);

        const dayAfter = evaluate(prod, { exceptions: [exception('GHSA-pppp-pppp-pppp', '2026-10-01')] });
        assert.strictEqual(dayAfter.ok, false);
        assert.deepStrictEqual(ids(dayAfter.expired), ['GHSA-pppp-pppp-pppp']);
        assert.deepStrictEqual(ids(dayAfter.blocking), ['GHSA-pppp-pppp-pppp'], 'просроченное исключение не защищает');
    });

    await test('exception: an expired exception fails the build even when the advisory is gone', () => {
        const result = evaluate(parse('clean.json'), { exceptions: [exception('GHSA-gone-gone-gone', '2026-01-01')] });
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.blocking.length, 0);
        assert.deepStrictEqual(ids(result.expired), ['GHSA-gone-gone-gone']);
    });

    await test('exception: one that closes nothing is reported as unused but does not fail', () => {
        const prod = audit.parseAuditReport(makeReport({ p: [via('GHSA-pppp-pppp-pppp', 'moderate', 'p')] }));
        const result = evaluate(prod, {
            exceptions: [exception('GHSA-pppp-pppp-pppp', '2026-12-31'), exception('GHSA-gone-gone-gone', '2026-12-31')],
        });
        assert.strictEqual(result.ok, true);
        assert.deepStrictEqual(ids(result.unused).sort(), ['GHSA-gone-gone-gone', 'GHSA-pppp-pppp-pppp']);
        assert.deepStrictEqual(result.excepted, []);
    });

    // ---------------------------------------------------------------- файл исключений

    await test('allowlist: the repository file is valid and has no exceptions', () => {
        assert.deepStrictEqual(audit.loadAllowlist(audit.DEFAULT_ALLOWLIST, { required: true }), []);
    });

    await test('allowlist: entries are normalized (id letter case, trimmed text)', () => {
        const list = audit.validateAllowlist({
            exceptions: [{ id: ' ghsa-AAAA-bbbb-1234 ', reason: '  причина  ', expires: '2026-12-31', note: 'лишние поля игнорируются' }],
        });
        assert.deepStrictEqual(list, [{ id: 'GHSA-aaaa-bbbb-1234', reason: 'причина', expires: '2026-12-31' }]);
    });

    await test('allowlist: invalid files are rejected with a pointer to the entry', () => {
        const good = { id: 'GHSA-aaaa-aaaa-aaaa', reason: 'r', expires: '2026-12-31' };
        const bad = (data, pattern) => assert.throws(() => audit.validateAllowlist(data, 'list.json'), (err) => {
            assert.ok(err instanceof audit.AuditInputError);
            assert.match(err.message, pattern);
            return true;
        });
        bad(null, /exceptions/);
        bad([], /exceptions/);
        bad({}, /exceptions/);
        bad({ exceptions: {} }, /exceptions/);
        bad({ exceptions: ['x'] }, /exceptions\[0\]: ожидается объект/);
        bad({ exceptions: [{ ...good, id: 'CVE-2024-0001' }] }, /GHSA-xxxx-xxxx-xxxx/);
        bad({ exceptions: [{ ...good, id: undefined }] }, /GHSA-xxxx-xxxx-xxxx/);
        bad({ exceptions: [{ ...good, reason: '   ' }] }, /нужна причина/);
        bad({ exceptions: [{ ...good, reason: undefined }] }, /нужна причина/);
        bad({ exceptions: [{ ...good, expires: '31.12.2026' }] }, /YYYY-MM-DD/);
        bad({ exceptions: [{ ...good, expires: '2026-02-30' }] }, /YYYY-MM-DD/);
        bad({ exceptions: [{ ...good, expires: '2026-13-01' }] }, /YYYY-MM-DD/);
        bad({ exceptions: [{ ...good, expires: undefined }] }, /YYYY-MM-DD/);
        bad({ exceptions: [good, { ...good, id: 'GHSA-AAAA-aaaa-aaaa' }] }, /указано дважды/);
    });

    await test('allowlist: a missing default file means no exceptions, a missing explicit file is an error', () => withTempDir((dir) => {
        const missing = path.join(dir, 'nope.json');
        assert.deepStrictEqual(audit.loadAllowlist(missing), []);
        assert.throws(() => audit.loadAllowlist(missing, { required: true }), audit.AuditInputError);
    }));

    await test('allowlist: BOM is accepted, broken JSON is an input error', () => withTempDir((dir) => {
        const file = path.join(dir, 'list.json');
        fs.writeFileSync(file, '﻿{"exceptions":[]}');
        assert.deepStrictEqual(audit.loadAllowlist(file, { required: true }), []);
        fs.writeFileSync(file, '{"exceptions": [');
        assert.throws(() => audit.loadAllowlist(file, { required: true }), /некорректный JSON/);
    }));

    // ---------------------------------------------------------------- вывод

    await test('text: violations carry severity, id, package and link; the verdict says what failed', () => {
        const result = evaluate(parse('repo-snapshot.json'), { exceptions: [exception('GHSA-gone-gone-gone', '2026-01-01', 'старая причина')] });
        const text = audit.formatText(result, TODAY);
        assert.match(text, /НАРУШЕНИЯ — блокируют сборку \(4\)/);
        assert.match(text, /high {6}GHSA-96hv-2xvq-fx4p {2}\[прод\] ws/);
        assert.match(text, /https:\/\/github\.com\/advisories\/GHSA-96hv-2xvq-fx4p/);
        assert.match(text, /ПРОСРОЧЕННЫЕ ИСКЛЮЧЕНИЯ — блокируют сборку \(1\)/);
        assert.match(text, /GHSA-gone-gone-gone {2}истекло 2026-01-01: старая причина/);
        assert.match(text, /Не блокируют сборку \(10\)/);
        assert.match(text, /ИТОГ: ПРОВАЛ — нарушений: 4, просроченных исключений: 1\./);
    });

    await test('text: a clean report ends with OK', () => {
        const text = audit.formatText(evaluate(parse('clean.json')), TODAY);
        assert.match(text, /ИТОГ: ОК/);
        assert.ok(!/НАРУШЕНИЯ/.test(text));
    });

    await test('text: applied and unused exceptions are listed', () => {
        const prod = audit.parseAuditReport(makeReport({ p: [via('GHSA-pppp-pppp-pppp', 'high', 'p')] }));
        const result = evaluate(prod, {
            exceptions: [exception('GHSA-pppp-pppp-pppp', '2026-12-31', 'ждём релиз'), exception('GHSA-gone-gone-gone', '2026-12-31')],
        });
        const text = audit.formatText(result, TODAY);
        assert.match(text, /Закрыто исключениями \(1\)/);
        assert.match(text, /до 2026-12-31: ждём релиз/);
        assert.match(text, /Исключения, которые ничего не закрывают.*\(1\)/);
        assert.match(text, /ИТОГ: ОК/);
    });

    await test('markdown: summary has tables and neutralises table-breaking and HTML text', () => {
        const hostile = via('GHSA-aaaa-aaaa-aaaa', 'moderate', 'x|y', 'title | with <b>html</b> & `code`\nsecond line');
        const prod = audit.parseAuditReport(makeReport({ 'x|y': [hostile] }));
        const md = audit.formatMarkdown(evaluate(prod), TODAY);
        assert.match(md, /^## npm audit: ОК/);
        assert.match(md, /\| Область \| critical \| high \| moderate \| low \| info \|/);
        assert.match(md, /### Не блокируют сборку \(1\)/);
        assert.ok(md.includes('x\\|y'), 'вертикальная черта в имени пакета экранирована');
        assert.ok(md.includes('title \\| with &lt;b&gt;html&lt;/b&gt; &amp; \'code\' second line'), md);
        assert.ok(!/<b>/.test(md));

        const failed = audit.formatMarkdown(evaluate(parse('repo-snapshot.json')), TODAY);
        assert.match(failed, /^## npm audit: ПРОВАЛ/);
        assert.match(failed, /### Нарушения — блокируют сборку \(4\)/);
        assert.match(failed, /\[GHSA-96hv-2xvq-fx4p\]\(https:\/\/github\.com\/advisories\/GHSA-96hv-2xvq-fx4p\)/);
    });

    // ---------------------------------------------------------------- main и запуск

    await test('main: runs npm audit twice, production first (--omit=dev), then everything', async () => {
        const calls = [];
        const runAudit = async (args) => {
            calls.push(args);
            return fixture(args.includes('--omit=dev') ? 'lab-prod.json' : 'lab-all.json');
        };
        const result = await runMain([], { io: { runAudit } });
        assert.deepStrictEqual(calls, [['--omit=dev'], []]);
        assert.strictEqual(result.code, 1);
        assert.match(result.out, /GHSA-xvch-5gv4-984h/);
        assert.strictEqual(result.err, '');
    });

    await test('main: --stdin with one report applies the production policy', async () => {
        const feed = (name) => ({ readInput: async () => JSON.stringify(fixture(name)) });
        const failing = await runMain(['--stdin'], { io: feed('repo-snapshot.json') });
        assert.strictEqual(failing.code, 1);
        assert.match(failing.out, /ИТОГ: ПРОВАЛ/);
        const clean = await runMain(['--stdin'], { io: feed('clean.json') });
        assert.strictEqual(clean.code, 0);
        assert.match(clean.out, /ИТОГ: ОК/);
    });

    await test('main: --stdin with {prod, all} separates production from dev', async () => {
        const wrapper = (prod, all) => ({ readInput: async () => JSON.stringify({ prod, all }) });
        const devOnly = await runMain(['--stdin'], { io: wrapper(fixture('clean.json'), makeReport({ d: [via('GHSA-dddd-dddd-dddd', 'high', 'd')] })) });
        assert.strictEqual(devOnly.code, 0, devOnly.out);
        assert.match(devOnly.out, /только dev: critical 0, high 1/);
        const prodHigh = await runMain(['--stdin'], { io: wrapper(makeReport({ p: [via('GHSA-pppp-pppp-pppp', 'high', 'p')] }), null) });
        assert.strictEqual(prodHigh.code, 1);
    });

    await test('main: an unreadable report is a tool failure (exit 2), not a policy failure', async () => {
        const broken = await runMain([], { io: { runAudit: async () => { throw new audit.AuditInputError('нет сети'); } } });
        assert.strictEqual(broken.code, 2);
        assert.match(broken.err, /npm audit: нет сети/);
        assert.strictEqual(broken.out, '');

        const errorReport = await runMain(['--stdin'], { io: { readInput: async () => JSON.stringify(fixture('registry-error.json')) } });
        assert.strictEqual(errorReport.code, 2);
        assert.match(errorReport.err, /ECONNREFUSED/);

        const notJson = await runMain(['--stdin'], { io: { readInput: async () => '<html>502</html>' } });
        assert.strictEqual(notJson.code, 2);
        assert.match(notJson.err, /некорректный JSON/);

        const odd = await runMain(['--stdin'], { io: { readInput: async () => '{"hello": 1}' } });
        assert.strictEqual(odd.code, 2);
    });

    await test('main: bad arguments exit 2, --help exits 0', async () => {
        const unknown = await runMain(['--frobnicate']);
        assert.strictEqual(unknown.code, 2);
        assert.match(unknown.err, /неизвестный аргумент/);
        const noValue = await runMain(['--allowlist']);
        assert.strictEqual(noValue.code, 2);
        const help = await runMain(['--help']);
        assert.strictEqual(help.code, 0);
        assert.match(help.out, /Использование/);
    });

    await test('main: --allowlist is applied: a valid exception passes, an expired one fails (fixed clock)', async () => {
        await withTempDir(async (dir) => {
            const file = path.join(dir, 'allow.json');
            const feed = { readInput: async () => JSON.stringify(fixture('lab-prod.json')) };

            fs.writeFileSync(file, JSON.stringify({ exceptions: [exception('GHSA-xvch-5gv4-984h', '2026-12-31')] }));
            const valid = await runMain(['--stdin', `--allowlist=${file}`], { io: feed });
            assert.strictEqual(valid.code, 0, valid.out);
            assert.match(valid.out, /Закрыто исключениями \(1\)/);

            fs.writeFileSync(file, JSON.stringify({ exceptions: [exception('GHSA-xvch-5gv4-984h', '2026-10-01')] }));
            const expired = await runMain(['--stdin', `--allowlist=${file}`], { io: feed });
            assert.strictEqual(expired.code, 1);
            assert.match(expired.out, /ПРОСРОЧЕННЫЕ ИСКЛЮЧЕНИЯ/);

            const missing = await runMain(['--stdin', `--allowlist=${path.join(dir, 'nope.json')}`], { io: feed });
            assert.strictEqual(missing.code, 2);
        });
    });

    await test('step summary: appended to GITHUB_STEP_SUMMARY when set, not touched otherwise', async () => {
        await withTempDir(async (dir) => {
            const file = path.join(dir, 'summary.md');
            fs.writeFileSync(file, 'earlier step\n');
            const io = { readInput: async () => JSON.stringify(fixture('repo-snapshot.json')) };
            await runMain(['--stdin'], { env: { GITHUB_STEP_SUMMARY: file }, io });
            const text = fs.readFileSync(file, 'utf8');
            assert.ok(text.startsWith('earlier step\n'), 'существующее содержимое сохранено');
            assert.match(text, /## npm audit: ПРОВАЛ/);

            // Нет переменной — ничего не пишется (и не падает).
            const before = fs.readdirSync(dir);
            await runMain(['--stdin'], { env: {}, io });
            assert.deepStrictEqual(fs.readdirSync(dir), before);

            // Ошибка записи сводки — предупреждение, решение по политике то же.
            const unwritable = await runMain(['--stdin'], { env: { GITHUB_STEP_SUMMARY: path.join(dir, 'no-such-dir', 'x.md') }, io });
            assert.strictEqual(unwritable.code, 1);
            assert.match(unwritable.err, /не удалось записать сводку/);
        });
    });

    await test('runNpmAudit: builds the command, parses stdout even for exit code 1, wraps failures', () => {
        const calls = [];
        const fake = (result) => (command, options) => {
            calls.push({ command, options });
            return result;
        };
        const json = JSON.stringify(fixture('lab-prod.json'));

        const parsed = audit.runNpmAudit(['--omit=dev'], fake({ status: 1, stdout: json, stderr: 'npm warn something' }));
        assert.strictEqual(parsed.auditReportVersion, 2);
        assert.strictEqual(calls[0].command, 'npm audit --json --omit=dev');
        assert.strictEqual(calls[0].options.shell, true);
        assert.strictEqual(calls[0].options.cwd, path.join(__dirname, '..'));

        audit.runNpmAudit([], fake({ status: 0, stdout: json }));
        assert.strictEqual(calls[1].command, 'npm audit --json');

        const fails = (result, pattern) => assert.throws(() => audit.runNpmAudit([], fake(result)), (err) => {
            assert.ok(err instanceof audit.AuditInputError);
            assert.match(err.message, pattern);
            return true;
        });
        fails({ error: new Error('spawn failed') }, /не удалось запустить.*spawn failed/);
        fails({ status: 1, stdout: '', stderr: 'npm error code ENOLOCK' }, /ничего не вывел.*ENOLOCK/);
        fails({ status: 1, stdout: 'Not JSON at all', stderr: '' }, /не JSON/);
    });

    await test('cli: a real process with --stdin reports through exit codes and the summary file', () => withTempDir((dir) => {
        const run = (input, extraArgs = [], env = {}) => spawnSync(process.execPath, [SCRIPT, '--stdin', ...extraArgs], {
            input,
            encoding: 'utf8',
            env: { ...process.env, GITHUB_STEP_SUMMARY: '', ...env },
        });
        const raw = (name) => fs.readFileSync(path.join(FIXTURES, name), 'utf8');

        const summary = path.join(dir, 'summary.md');
        const failing = run(raw('repo-snapshot.json'), [], { GITHUB_STEP_SUMMARY: summary });
        assert.strictEqual(failing.status, 1, failing.stderr);
        assert.match(failing.stdout, /ИТОГ: ПРОВАЛ — нарушений: 4/);
        assert.match(fs.readFileSync(summary, 'utf8'), /## npm audit: ПРОВАЛ/);

        const ok = run(raw('clean.json'));
        assert.strictEqual(ok.status, 0, ok.stderr);
        assert.match(ok.stdout, /ИТОГ: ОК/);

        const registryDown = run(raw('registry-error.json'));
        assert.strictEqual(registryDown.status, 2);
        assert.match(registryDown.stderr, /ECONNREFUSED/);

        // Сроки далеко от «сегодня» в обе стороны — результат не зависит от даты прогона.
        const allow = path.join(dir, 'allow.json');
        fs.writeFileSync(allow, JSON.stringify({ exceptions: [exception('GHSA-xvch-5gv4-984h', '2999-12-31')] }));
        assert.strictEqual(run(raw('lab-prod.json'), ['--allowlist', allow]).status, 0);
        fs.writeFileSync(allow, JSON.stringify({ exceptions: [exception('GHSA-xvch-5gv4-984h', '2000-01-01')] }));
        assert.strictEqual(run(raw('lab-prod.json'), ['--allowlist', allow]).status, 1);
    }));

    await test('package.json: npm run audit:check starts the script', () => {
        const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
        assert.strictEqual(pkg.scripts['audit:check'], 'node scripts/audit-check.js');
    });

    console.log('\n' + passed + ' passed, ' + failed + ' failed');
    if (failed > 0) process.exitCode = 1;
}

main().catch(err => { console.error('Test runner crashed:', err); process.exitCode = 1; });
