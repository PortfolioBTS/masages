'use strict';
// Обработка пачками до исчерпания с бюджетом времени прохода (ревью W7 R2.11).
//
// Чистка просроченных анонимов брала одну пачку в 200 строк раз в 5 минут: при
// наплыве (тысячи регистраций за час) данные жили заметно дольше выбранного срока.
// Теперь проход берёт пачки, пока они полные и не вышел бюджет времени; остаток —
// следующему проходу. Строки, на которых обработка упала, в этом проходе больше не
// выбираются (иначе одна «вечная» ошибка зациклила бы проход).
//
// fetchBatch(skipIds, limit) → [{ id, … }]; handle(row) — обработать строку (бросает при
// сбое; onError(err, row) — запись в лог). Возвращает { processed, failed, batches, exhausted }:
// exhausted = false, если проход остановил бюджет, а строки ещё остались.

async function drainBatches({ fetchBatch, handle, onError = () => {}, batchSize, budgetMs, skipIds = [], clock = Date.now }) {
    if (!Number.isInteger(batchSize) || batchSize <= 0) throw new RangeError('drainBatches: batchSize — целое > 0');
    const startedAt = clock();
    const skip = new Set(skipIds);
    let processed = 0;
    let failed = 0;
    let batches = 0;
    for (;;) {
        const rows = await fetchBatch([...skip], batchSize);
        batches++;
        for (const row of rows) {
            try {
                await handle(row);
                processed++;
            } catch (err) {
                failed++;
                skip.add(row.id);
                onError(err, row);
            }
        }
        if (rows.length < batchSize) return { processed, failed, batches, exhausted: true };
        if (clock() - startedAt >= budgetMs) return { processed, failed, batches, exhausted: false };
    }
}

module.exports = { drainBatches };
