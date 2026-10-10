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

const path = require('path');
const { createManifestProvider } = require('../client-manifest');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
const MANIFEST_PATH = '/client-manifest.json';

function register(app, ctx) {
    const provider = createManifestProvider((ctx && ctx.publicDir) || PUBLIC_DIR);

    app.get(MANIFEST_PATH, (req, res) => {
        const manifest = provider.get();
        res.set('Content-Type', 'application/json; charset=utf-8');
        // Короткий отпечаток для людей и сторожа: не нужно качать весь список ради сравнения.
        res.set('X-Client-Manifest-Sha256', manifest.sha256);
        res.send(manifest.buffer);
    });
}

module.exports = { register, MANIFEST_PATH };
