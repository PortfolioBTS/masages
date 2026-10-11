# Как проверить файлы клиента Nyxo

Код клиента (страница, скрипты, стили) браузер получает от сервера при каждом открытии. Здесь описано, как убедиться,
что файлы совпадают с теми, что опубликованы в релизе на GitHub: хэши SHA-256 каждого файла перечислены в манифесте
`client-manifest.json`.

## Что именно сверяется

- **Манифест** `client-manifest.json` — список всех файлов, которые сервер отдаёт из `public/` (включая клиент
  socket.io из `public/vendor/`), с `sha256`, `sri` (sha384 для будущих атрибутов `integrity`) и размером. В нём нет
  commit, времени и версий: один и тот же код даёт один и тот же манифест на любой машине и ОС.
- **Тот же файл отдаёт сервер**: `GET /client-manifest.json`. В заголовке `X-Client-Manifest-Sha256` — его хэш.
- **Релиз** (тег `v*`, GitHub Release) содержит три файла:
  - `client-manifest.json` — манифест, байт в байт тот же, что отдаёт сервер этой версии;
  - `release.json` — версия, commit, время коммита, версия Node и хэш манифеста;
  - `SHA256SUMS` — хэши файлов в формате `sha256sum` (пути — от каталога `public/`).
- Файлы релиза подтверждены **аттестацией GitHub** (`actions/attest-build-provenance`): видно, что их собрал workflow
  `release.yml` из этого репозитория на конкретном коммите.
- Не входят в манифест: `/.well-known/security.txt`, `/healthz` и прочие динамические ответы (это не код клиента), файлы
  `uploads/` (пользовательские данные) и `/sw.js` (service worker: он сам закрепляет хэш манифеста, поэтому в манифест не входит; его хэш лежит в `release.json`, поле `serviceWorker.sha256`).

## Честно: что это даёт и чего не даёт

- **Страница `/verify.html` на том же сервере ничего не доказывает против злонамеренного сервера.** Сервер, который
  подменил клиент, может отдать подменённую страницу сверки и подменённый манифест и показать «всё совпало». Страница
  полезна против случайных поломок (неполный выкат, устаревший кэш), а не против атаки.
- **Что реально защищает:**
  1. сверка с манифестом из релиза, полученным другим каналом (GitHub), — вручную или скриптом на своём устройстве;
  2. внешний сторож: workflow `watchdog.yml` раз в сутки сверяет продакшен с последним релизом. Он ловит массовую
     подмену (все пользователи получают другой код), но не адресную: сервер может отдавать чужой код только отдельным
     людям;
  3. закрепление хэша манифеста в service worker (TOFU): после первого визита браузер открывает страницу из проверенной копии и показывает сообщение, если сервер начал отдавать другой код. Первый визит и нажатие «Обновить» без сверки отпечатка закрепление не защищает (подробно — [threat-model.md](threat-model.md), раздел 6.1; эксплуатация — [ops/service-worker.md](ops/service-worker.md)).
- **SRI пока не включён.** Атрибуты `integrity` в `index.html` появятся после разбиения файлов клиента (волна 6);
  инструменты (`scripts/update-sri.js`, поле `sri` в манифесте) уже готовы. Тогда корнем доверия к странице станет хэш
  самого `index.html`. `pow-worker.js` SRI не покрывает вообще: у `Worker` нет атрибута `integrity`, его хэш проверяется
  только по манифесту.
- Сверка не покрывает серверный код, базу и инфраструктуру хостинга: проверяется только то, что получает браузер.
  Расширения браузера и вредоносное ПО на устройстве тоже вне проверки.

## Быстрый способ: скрипт на своём компьютере

Нужен Node.js 24 и копия репозитория (ставить зависимости не требуется).

1. Скачайте `client-manifest.json` со страницы релиза (`https://github.com/PortfolioBTS/masages/releases`).
2. По желанию проверьте аттестацию (нужен [GitHub CLI](https://cli.github.com/)):

   ```
   gh attestation verify client-manifest.json --repo PortfolioBTS/masages
   ```

3. Запустите сверку:

   ```
   node scripts/verify-deployment.js https://chat.example.com --manifest client-manifest.json
   ```

   Код выхода: `0` — всё совпало, `1` — есть расхождения (скрипт печатает файлы и оба хэша), `2` — проверить не удалось.
   Без `--manifest` эталоном служит манифест самого сайта: скрипт предупредит, что такая проверка не защищает от подмены сервера.
   Адреса `http://` принимаются только для localhost и `.onion` (иначе нужен `--allow-http`).

## Вручную: sha256sum (Linux, macOS, Git Bash)

Скачайте `client-manifest.json` и `SHA256SUMS` из релиза. Затем соберите копию сайта и сверьте хэши:

```
BASE=https://chat.example.com
mkdir site && cd site
for f in $(jq -r '.files[].path' ../client-manifest.json); do
  curl -sS --create-dirs -o ".$f" "$BASE$f"
done
sha256sum -c ../SHA256SUMS
```

Каждая строка должна закончиться на `OK`. Один файл можно проверить и напрямую:

```
curl -sS https://chat.example.com/e2ee.js | sha256sum
jq -r '.files[] | select(.path == "/e2ee.js") | .sha256' client-manifest.json
```

## Вручную: PowerShell (Windows)

```powershell
$base = 'https://chat.example.com'
$manifest = Get-Content .\client-manifest.json -Raw | ConvertFrom-Json
$tmp = Join-Path $env:TEMP 'nyxo-verify'
New-Item -ItemType Directory -Force $tmp | Out-Null
foreach ($file in $manifest.files) {
    $out = Join-Path $tmp ([IO.Path]::GetRandomFileName())
    Invoke-WebRequest -Uri ($base + $file.path) -OutFile $out -UseBasicParsing
    $hash = (Get-FileHash -Algorithm SHA256 -Path $out).Hash.ToLower()
    '{0}  {1}' -f $(if ($hash -eq $file.sha256) { 'OK        ' } else { 'ОТЛИЧАЕТСЯ' }), $file.path
}
Remove-Item -Recurse -Force $tmp
```

Хэш самого манифеста: `(Get-FileHash -Algorithm SHA256 .\client-manifest.json).Hash.ToLower()` — он должен совпасть с
полем `manifest.sha256` в `release.json` и с заголовком `X-Client-Manifest-Sha256` ответа `/client-manifest.json`.

## Воспроизвести манифест из исходников

Манифест строится только из файлов `public/`, поэтому его можно получить самому и сравнить с релизом:

```
git checkout vX.Y.Z
npm ci
node scripts/release-manifest.js
cmp release/client-manifest.json client-manifest.json     # скачанный из релиза
```

На Windows вместо `cmp` — `fc /b release\client-manifest.json client-manifest.json` или сравнение `Get-FileHash`. Файлы
репозитория хранятся с LF (`.gitattributes`), поэтому на Windows и Linux хэши одинаковы. Если хэши расходятся только на одной
ОС, первым делом проверьте окончания строк (`core.autocrlf`, правки редактора).

## Страница сверки в браузере

`/verify.html` скачивает все файлы с этого сайта, считает SHA-256 и сравнивает с манифестом сервера или с файлом
`client-manifest.json` из релиза, который вы выберете. Результат содержит хэши в формате `sha256sum` для ручной сверки.
Помните оговорку выше: страница приходит с проверяемого сервера. Для недоверенного сервера используйте скрипт или ручные команды.

## Сторож (watchdog)

Workflow `.github/workflows/watchdog.yml` раз в сутки скачивает `client-manifest.json` последнего релиза и запускает
`scripts/verify-deployment.js` против продакшена. При расхождении он открывает (или дополняет) issue с отчётом.
Включается переменной репозитория `WATCHDOG_URL` (адрес сайта); пока она не задана, workflow ничего не делает. Он обнаружит и
ситуацию «релиз выпущен, а продакшен ещё на старой версии»: это тоже расхождение, и его надо различать с подменой по версии в
`release.json`.
