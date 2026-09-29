# Фикстуры сквозных тестов

## `legacy-2.0.0.sql` / `legacy-2.0.0.json`

База данных версии 2.0.0 — последней, где были аккаунты с email и паролем.
Нужна, чтобы проверять миграцию удаления таких аккаунтов (флаг
`PURGE_LEGACY_ACCOUNTS=yes`), замороженный режим без флага и апгрейд схемы
на реальной, а не выдуманной структуре данных.

Засеяна **через HTTP API самой версии 2.0.0** (скрипт
`seed-legacy-2.0.0.js`), поэтому таблицы, ограничения, индексы и
зашифрованные тексты сообщений — ровно такие, какими их оставила та версия.
Что внутри и что должно остаться после очистки — в `legacy-2.0.0.json`.

Формат — `pg_dump --column-inserts` без psql-команд `\restrict`/`\unrestrict`
(их не понимает node-postgres): файл выполняется одним `client.query()`.
Метки времени в данных абсолютные; загрузчик сдвигает их на
`сейчас − anchorTime`, чтобы сроки жизни считались от момента теста.

Ключ шифрования сообщений и секрет сессий в `.json` — тестовые значения
только для этой фикстуры, не секреты.

### Как пересоздать

Нужен Docker и старая версия сервера (коммит `12f7aa8`).

```bash
docker run -d --name nyxo-fixture-pg -e POSTGRES_USER=nyxo -e POSTGRES_PASSWORD=fixture-only -e POSTGRES_DB=nyxo -p 127.0.0.1:55499:5432 postgres:16-alpine
git worktree add ../nyxo-2.0.0 12f7aa8
```

В папке `../nyxo-2.0.0` (после `npm ci`) запустить сервер с тестовыми
значениями из `legacy-2.0.0.json`:

```bash
SESSION_SECRET=test-fixture-session-secret-0123456789abcdef MESSAGE_ENCRYPTION_KEY=bnl4by10ZXN0LWZpeHR1cmUtbWVzc2FnZS1rZXktMzI= DATABASE_URL=postgresql://nyxo:fixture-only@127.0.0.1:55499/nyxo PORT=3100 HOST=127.0.0.1 POW_DIFFICULTY=8 node server.js
```

В соседнем терминале засеять и снять дамп:

```bash
BASE=http://127.0.0.1:3100 node test/e2e/fixtures/seed-legacy-2.0.0.js
docker exec nyxo-fixture-pg pg_dump -U nyxo -d nyxo --no-owner --no-privileges --column-inserts > test/e2e/fixtures/legacy-2.0.0.sql
```

Затем удалить из дампа строки, начинающиеся с `\` (`\restrict`,
`\unrestrict`), и обновить id, sid и `anchorTime` в `legacy-2.0.0.json`
(id случайные и меняются при каждом засеве).
