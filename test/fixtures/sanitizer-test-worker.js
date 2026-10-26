'use strict';
// Подставной поток очистки для test/sanitizer-pool.test.js: протокол тот же, что у lib/sanitizer-worker.js.
//   первый байт 0xFF — поток падает (как при нехватке памяти);
//   первый байт 0xFE — в ответ JSON с resourceLimits потока;
//   иначе — байты возвращаются как есть.
const { parentPort, resourceLimits } = require('worker_threads');

parentPort.on('message', ({ id, bytes }) => {
    const input = new Uint8Array(bytes);
    if (input[0] === 0xFF) throw new Error('падение потока');
    const out = input[0] === 0xFE ? new TextEncoder().encode(JSON.stringify(resourceLimits)) : input;
    parentPort.postMessage({ id, ok: true, bytes: out.buffer }, [out.buffer]);
});
