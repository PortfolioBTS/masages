'use strict';
// Перехват запросов вкладки через CDP-домен Fetch: тест может оборвать ответ, пропустив запрос
// на сервер (потерянный ответ), или придержать ответ, пока не случится другое событие.
// Страница при этом не подправляется: её fetch() видит обычный сетевой сбой или медленный ответ.
//
//     const cut = await interceptRequests(page, {
//         pattern: '*/api/messages',            // шаблон адреса CDP: * — любая подстрока
//         stage: 'Response',                    // 'Request' — до сервера, 'Response' — после ответа сервера
//         decide: async (entry) => (entry.index === 0 ? 'fail' : 'pass'),
//     });
//     …
//     await cut.stop();
//
// decide получает { index, method, url, body, status }: index — номер запроса среди перехваченных
// (с нуля). Возвращает 'pass' (пропустить) или 'fail' (оборвать соединение); пока промис не
// выполнен, запрос придержан. Любая ошибка в decide пропускает запрос и всплывает в stop().
// Все перехваченные запросы копятся в cut.seen.

async function interceptRequests(page, { pattern, stage = 'Response', method = 'POST', decide, reason = 'ConnectionReset' }) {
    const seen = [];
    const errors = [];
    const pending = new Set();
    await page.send('Fetch.enable', { patterns: [{ urlPattern: pattern, requestStage: stage }] });
    const off = page.on('Fetch.requestPaused', (event) => {
        const { requestId, request } = event;
        const pass = () => page.send(stage === 'Response' ? 'Fetch.continueResponse' : 'Fetch.continueRequest', { requestId });
        if (method && request.method !== method) {
            pending.add(pass().catch((err) => errors.push(err)));
            return;
        }
        const entry = { index: seen.length, method: request.method, url: request.url, body: request.postData || null, status: event.responseStatusCode || null };
        seen.push(entry);
        const task = (async () => {
            let decision = 'pass';
            try {
                decision = decide ? await decide(entry) : 'pass';
            } catch (err) {
                errors.push(err);
            }
            entry.decision = decision;
            if (decision === 'fail') await page.send('Fetch.failRequest', { requestId, errorReason: reason });
            else await pass();
        })().catch((err) => errors.push(err));
        pending.add(task);
    });
    return {
        seen,
        async stop() {
            off();
            await Promise.allSettled([...pending]);
            await page.send('Fetch.disable').catch(() => {});
            if (errors.length > 0) throw errors[0];
        },
    };
}

module.exports = { interceptRequests };
