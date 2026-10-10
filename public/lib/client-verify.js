// Сверка файлов клиента с манифестом (6.1/6.3, roadmap R10). Функции здесь чистые,
// без DOM и сети: файл исполняется и в браузере (window.NyxoClientVerify — страница
// /verify.html), и в Node (scripts/verify-deployment.js, lib/client-manifest.js,
// test/verify-deployment.test.js). Одна логика сравнения для всех, чтобы страница и
// консольный скрипт не расходились во мнении, что считать совпадением.
//
//   toHex(bytes)                     — байты в нижний hex;
//   parseManifest(text)              — разбор и проверка формата манифеста
//                                      (бросает Error с понятным текстом);
//   compareObserved(manifest, seen)  — сверка того, что скачано, с манифестом;
//                                      seen: { "/путь": { sha256, bytes } | { error } };
//   diffManifests(reference, served) — чем манифест сервера отличается от эталона.
//
// Честная оговорка: это сравнение, а не доказательство. Если сверка идёт с
// манифестом того же сервера, она ловит только случайные расхождения (неполный
// деплой, устаревший кэш). Против подмены сервера помогает лишь эталон из
// другого канала (релиз на GitHub) и запуск проверки на своём устройстве.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoClientVerify = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const MANIFEST_FORMAT = 'nyxo-client-manifest/1';

    function toHex(bytes) {
        const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        let out = '';
        for (let i = 0; i < view.length; i++) out += view[i].toString(16).padStart(2, '0');
        return out;
    }

    // Разбор манифеста, пришедшего извне: форма проверяется строго, потому что по
    // нему решается, что считать «правильным» файлом.
    function parseManifest(text) {
        let data;
        try {
            data = JSON.parse(text);
        } catch (err) {
            throw new Error('манифест не разбирается как JSON: ' + err.message);
        }
        if (!data || data.format !== MANIFEST_FORMAT) throw new Error(`неизвестный формат манифеста: ${data && data.format}`);
        if (!Array.isArray(data.files) || data.files.length === 0) throw new Error('в манифесте нет списка files');
        const seen = new Set();
        for (const file of data.files) {
            const ok = file && typeof file.path === 'string' && file.path.startsWith('/') && !file.path.includes('..') &&
                typeof file.sha256 === 'string' && /^[0-9a-f]{64}$/.test(file.sha256) &&
                typeof file.sri === 'string' && /^sha384-[A-Za-z0-9+/]{64}$/.test(file.sri) &&
                Number.isSafeInteger(file.bytes) && file.bytes >= 0;
            if (!ok) throw new Error(`некорректная запись манифеста: ${JSON.stringify(file)}`);
            if (seen.has(file.path)) throw new Error(`путь повторяется в манифесте: ${file.path}`);
            seen.add(file.path);
        }
        const aliases = data.aliases || {};
        for (const from of Object.keys(aliases)) {
            if (!from.startsWith('/') || !seen.has(aliases[from])) throw new Error(`алиас ${from} ведёт на неизвестный файл`);
        }
        return data;
    }

    // Что нужно скачать для сверки: все файлы манифеста и адреса-алиасы («/»).
    function pathsToFetch(manifest) {
        return [...manifest.files.map((file) => file.path), ...Object.keys(manifest.aliases || {})];
    }

    // seen[path] = { sha256, bytes } — файл получен; { error: 'текст' } — не получен
    // (сеть, не 200, редирект). Возвращает { ok, entries, problems }:
    //   state: 'match' | 'mismatch' | 'error' | 'not-checked'.
    function compareObserved(manifest, seen) {
        const entries = [];
        const problems = [];
        const check = (reportPath, expectedFile) => {
            const got = seen[reportPath];
            const entry = { path: reportPath, expected: expectedFile.sha256, expectedBytes: expectedFile.bytes, actual: null, actualBytes: null, state: 'not-checked', detail: '' };
            if (!got) {
                entry.detail = 'файл не запрашивался';
            } else if (got.error) {
                entry.state = 'error';
                entry.detail = got.error;
            } else {
                entry.actual = got.sha256;
                entry.actualBytes = got.bytes;
                if (got.sha256 !== expectedFile.sha256) {
                    entry.state = 'mismatch';
                    entry.detail = 'хэш не совпал с манифестом';
                } else if (got.bytes !== expectedFile.bytes) {
                    entry.state = 'mismatch';
                    entry.detail = `размер ${got.bytes} вместо ${expectedFile.bytes}`;
                } else {
                    entry.state = 'match';
                }
            }
            entries.push(entry);
            if (entry.state !== 'match') problems.push(`${reportPath}: ${entry.detail}`);
        };
        for (const file of manifest.files) check(file.path, file);
        const byPath = new Map(manifest.files.map((file) => [file.path, file]));
        for (const [alias, target] of Object.entries(manifest.aliases || {})) check(alias, byPath.get(target));
        return { ok: problems.length === 0, entries, problems };
    }

    // Чем манифест сервера отличается от эталона: { onlyInReference, onlyInServed, changed }.
    function diffManifests(reference, served) {
        const refMap = new Map(reference.files.map((file) => [file.path, file]));
        const servedMap = new Map(served.files.map((file) => [file.path, file]));
        const onlyInReference = [...refMap.keys()].filter((p) => !servedMap.has(p)).sort();
        const onlyInServed = [...servedMap.keys()].filter((p) => !refMap.has(p)).sort();
        const changed = [...refMap.keys()].filter((p) => servedMap.has(p) && servedMap.get(p).sha256 !== refMap.get(p).sha256).sort();
        return { onlyInReference, onlyInServed, changed, same: onlyInReference.length + onlyInServed.length + changed.length === 0 };
    }

    // Строки в формате sha256sum (`хэш  путь`) для ручной сверки: хэши того, что реально
    // получено; алиасы («/») пропускаются, файла без ответа в списке нет.
    function formatSums(entries) {
        return entries
            .filter((entry) => entry.actual && entry.path !== '/')
            .map((entry) => `${entry.actual}  ${entry.path.slice(1)}`)
            .join('\n') + '\n';
    }

    // Итог сверки одной фразой. mode: 'self' — эталон манифест того же сервера,
    // 'reference' — файл из релиза (расхождение манифеста сервера с ним — тоже problem).
    function describeOutcome({ ok, total, mode, problems }) {
        if (!ok) {
            return `Найдены расхождения (${problems.length}). Файлы этого сервера не совпадают с ${mode === 'reference' ? 'эталонным манифестом' : 'его манифестом'}.`;
        }
        if (mode === 'reference') {
            return `Все ${total} адресов совпали с эталонным манифестом, а манифест сервера совпал с эталоном байт в байт. ` +
                'Это не отменяет оговорку выше: код этой страницы тоже пришёл с проверяемого сервера.';
        }
        return `Все ${total} адресов совпали с манифестом ЭТОГО ЖЕ сервера. Это не доказательство честности сервера: ` +
            'выберите эталонный манифест из релиза или проверьте файлы вручную.';
    }

    return { MANIFEST_FORMAT, toHex, parseManifest, pathsToFetch, compareObserved, diffManifests, formatSums, describeOutcome };
});
