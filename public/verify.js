// Страница сверки /verify.html: скачивает файлы клиента с этого сайта, считает SHA-256
// и сравнивает с манифестом (/client-manifest.json) либо с эталонным манифестом из
// релиза, который выбрал пользователь. Логика сравнения — в lib/client-verify.js
// (общая с scripts/verify-deployment.js); здесь только сеть и DOM, текст выводится
// через textContent.
//
// Честно: страница, манифест и файлы приходят с одного сервера, поэтому против
// злонамеренного сервера эта сверка ничего не доказывает (текст про это — на самой
// странице и в docs/VERIFY.md).
(function () {
    'use strict';

    const V = window.NyxoClientVerify;
    const $ = (id) => document.getElementById(id);
    const CONCURRENCY = 4;

    const startBtn = $('verify-start');
    if (!V || !startBtn) return;

    const statusEl = $('verify-status');
    const summaryEl = $('verify-summary');

    function setStatus(text) {
        statusEl.textContent = text;
    }

    async function sha256Hex(buffer) {
        return V.toHex(await crypto.subtle.digest('SHA-256', buffer));
    }

    async function fetchBuffer(urlPath) {
        // no-store: не брать файл из кэша браузера; redirect: error — перенаправление считается ошибкой.
        const res = await fetch(urlPath, { cache: 'no-store', credentials: 'omit', redirect: 'error' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.arrayBuffer();
    }

    function cell(row, text) {
        const td = document.createElement('td');
        td.textContent = text;
        row.appendChild(td);
    }

    const STATE_TEXT = { match: 'совпало', mismatch: 'НЕ СОВПАЛО', error: 'ОШИБКА', 'not-checked': 'не проверено' };

    function renderRows(entries) {
        const body = $('verify-rows');
        body.textContent = '';
        for (const entry of entries) {
            const row = document.createElement('tr');
            if (entry.state !== 'match') row.className = 'bad';
            cell(row, entry.path === '/' ? '/ (index.html)' : entry.path);
            cell(row, entry.detail ? `${STATE_TEXT[entry.state]}: ${entry.detail}` : STATE_TEXT[entry.state]);
            cell(row, entry.actual || '—');
            cell(row, entry.actualBytes === null ? '—' : String(entry.actualBytes));
            body.appendChild(row);
        }
    }

    async function pool(items, limit, fn) {
        let next = 0;
        const worker = async () => {
            while (next < items.length) await fn(items[next++]);
        };
        await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
    }

    async function run() {
        summaryEl.hidden = true;
        $('verify-table-wrap').hidden = true;
        $('verify-output-wrap').hidden = true;
        $('verify-hashes').hidden = true;

        if (!window.crypto || !crypto.subtle) {
            setStatus('SHA-256 в этом браузере недоступен: нужен защищённый контекст (https, localhost или .onion в Tor Browser).');
            return;
        }

        setStatus('Загружаю манифест сервера…');
        const servedBuffer = await fetchBuffer('/client-manifest.json');
        const servedHash = await sha256Hex(servedBuffer);
        const servedText = new TextDecoder().decode(servedBuffer);
        const served = V.parseManifest(servedText);

        let manifest = served;
        let referenceHash = null;
        const problems = [];
        const refFile = $('verify-ref-file').files[0];
        if (refFile) {
            const refText = await refFile.text();
            manifest = V.parseManifest(refText);
            referenceHash = await sha256Hex(new TextEncoder().encode(refText));
            if (referenceHash !== servedHash) {
                const diff = V.diffManifests(manifest, served);
                const parts = [];
                if (diff.changed.length) parts.push('другие хэши: ' + diff.changed.join(', '));
                if (diff.onlyInServed.length) parts.push('лишние файлы: ' + diff.onlyInServed.join(', '));
                if (diff.onlyInReference.length) parts.push('нет файлов: ' + diff.onlyInReference.join(', '));
                problems.push('манифест сервера отличается от эталона' + (parts.length ? ' (' + parts.join('; ') + ')' : ''));
            }
        }

        const wanted = V.pathsToFetch(manifest);
        const seen = {};
        let done = 0;
        await pool(wanted, CONCURRENCY, async (urlPath) => {
            try {
                const buffer = await fetchBuffer(urlPath);
                seen[urlPath] = { sha256: await sha256Hex(buffer), bytes: buffer.byteLength };
            } catch (err) {
                seen[urlPath] = { error: err && err.message ? err.message : 'запрос не удался' };
            }
            done++;
            setStatus(`Проверено ${done} из ${wanted.length}…`);
        });

        const compared = V.compareObserved(manifest, seen);
        problems.push(...compared.problems);
        const ok = problems.length === 0;
        const mode = refFile ? 'reference' : 'self';

        renderRows(compared.entries);
        $('verify-served-hash').textContent = servedHash;
        $('verify-ref-hash').textContent = referenceHash || '';
        $('verify-ref-hash').hidden = !referenceHash;
        $('verify-ref-hash-title').hidden = !referenceHash;
        $('verify-output').textContent = V.formatSums(compared.entries);
        $('verify-hashes').hidden = false;
        $('verify-table-wrap').hidden = false;
        $('verify-output-wrap').hidden = false;
        summaryEl.textContent = V.describeOutcome({ ok, total: compared.entries.length, mode, problems }) +
            (ok ? '' : ' ' + problems.join(' | '));
        summaryEl.hidden = false;
        setStatus(ok ? 'Готово.' : 'Готово: есть расхождения.');
    }

    startBtn.addEventListener('click', async () => {
        startBtn.disabled = true;
        try {
            await run();
        } catch (err) {
            setStatus('Сверка не удалась: ' + (err && err.message ? err.message : err));
        } finally {
            startBtn.disabled = false;
        }
    });
})();
