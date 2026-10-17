'use strict';
// GET /client-manifest.json — манифест клиента (lib/client-manifest.js).
// Регистрируется до sessionMiddleware (PRE_SESSION_ROUTES): сессия и куки
// манифесту не нужны, ответ одинаков для всех.
//
// Тело — те же байты, что кладёт в релиз scripts/release-manifest.js, поэтому
// хэш ответа можно сравнить с хэшем из GitHub Release. Заголовки приватности
// и Cache-Control: no-store остаются глобальными: сверка не должна читать
// манифест из кэша. Честная оговорка (docs/VERIFY.md, docs/threat-model.md):
// манифест от самого сервера ничего не доказывает против злонамеренного
// сервера — он может отдать манифест под свои файлы. Его ценность в сверке с
// внешним источником (релиз на GitHub, сторож, ручная проверка).
//
// Ключ журнала ключей. Если задан KT_SIGNING_KEY, в манифест добавляется keys.kt — открытая часть этого ключа
// (docs/security/key-transparency.md, раздел 11): клиент сверяет с ним ключ журнала при первом закреплении.
// Релиз (scripts/release-manifest.js, --kt-key или KT_PUBLIC_KEY) обязан назвать тот же ключ: иначе манифест сервера
// не совпадёт с релизом байт в байт, и сторож это покажет. Без KT_SIGNING_KEY манифест прежний.

const path = require('path');
const { createManifestProvider } = require('../client-manifest');
const { loadSigningKey } = require('../kt-log');
const { logError } = require('../log-error');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
const MANIFEST_PATH = '/client-manifest.json';

// Открытый ключ журнала из KT_SIGNING_KEY (base64) или null: журнал выключен либо ключ не загрузился
// (env-check при старте уже сообщил об ошибке; манифест без ключа безопаснее, чем отказ сервера отдавать клиент).
function ktPublicKeyFromEnv(env) {
    const encoded = env && typeof env.KT_SIGNING_KEY === 'string' ? env.KT_SIGNING_KEY.trim() : '';
    if (encoded === '') return null;
    try {
        return loadSigningKey(encoded).pub.toString('base64');
    } catch (err) {
        logError('[KT] ключ журнала не попал в манифест клиента', err);
        return null;
    }
}

function register(app, ctx) {
    const provider = createManifestProvider((ctx && ctx.publicDir) || PUBLIC_DIR, { ktKey: ktPublicKeyFromEnv(ctx && ctx.env) });

    app.get(MANIFEST_PATH, (req, res) => {
        const manifest = provider.get();
        res.set('Content-Type', 'application/json; charset=utf-8');
        // Короткий отпечаток для людей и сторожа: не нужно качать весь список ради сравнения.
        res.set('X-Client-Manifest-Sha256', manifest.sha256);
        res.send(manifest.buffer);
    });
}

module.exports = { register, ktPublicKeyFromEnv, MANIFEST_PATH };
