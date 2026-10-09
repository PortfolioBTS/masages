'use strict';
// Производные ключи от SESSION_SECRET (HKDF-SHA256, RFC 5869).
//
// Один исходный секрет не должен подписывать всё подряд: ключ для CSRF, для
// proof-of-work и для хэширования ключей лимитов выводится со СВОЕЙ меткой
// (info), поэтому подпись, снятая в одном месте, в другом ничего не значит.
// Побочное следствие, о котором знает docs/ops: смена SESSION_SECRET меняет и
// все производные ключи — лимиты, CSRF-токены и выданные задачи PoW
// сбрасываются.

const crypto = require('crypto');

// label — константа вида 'nyxo-csrf-v1'; версия в метке позволит сменить схему,
// не трогая остальные ключи.
function deriveKey(secret, label, length = 32) {
    if ((typeof secret !== 'string' && !Buffer.isBuffer(secret)) || secret.length === 0) {
        throw new TypeError('deriveKey: нужен непустой секрет (SESSION_SECRET)');
    }
    if (typeof label !== 'string' || label === '') throw new TypeError('deriveKey: нужна метка ключа');
    return Buffer.from(crypto.hkdfSync('sha256', secret, Buffer.alloc(0), label, length));
}

module.exports = { deriveKey };
