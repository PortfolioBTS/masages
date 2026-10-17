// E2EE-клиент Nyxo: PQXDH (X3DH + ML-KEM-768) для попарных каналов +
// Sender Keys (Signal-style групповое шифрование) поверх Web Crypto API.
//
// Как устроено и почему:
//   - Попарный канал используется НЕ для самих сообщений, а только чтобы
//     передать каждому участнику комнаты "Sender Key" отправителя — общий
//     для всех получателей симметричный ключ. Дальше сообщения шифруются
//     продвижением этого ключа вперёд (KDF-цепочка), без попарной работы на
//     каждое сообщение — так делает Signal в группах.
//   - Identity-ключей два отдельных (Ed25519 для подписи + X25519 для DH),
//     а не один конвертируемый — под эту схему спроектирован
//     серверный модуль ключей (lib/key-store.js).
//   - Из внешнего кода — только ML-KEM (public/mlkem.js, чистый JS: в
//     браузерах WebCrypto его пока не умеет). Остальное — crypto.subtle и
//     crypto.getRandomValues. Это и требование CSP (script-src 'self'), и то,
//     что делает файл исполнимым один-в-один в браузере и в Node — на этом
//     построены протокольные тесты test/e2ee.protocol.test.js.
//   - Чистые функции без состояния клиента (кодирование и Padmé, обёртки Web Crypto и KDF-цепочка, разбор и
//     сборка форматов, нормализация записей) вынесены в public/lib/e2ee-*.js (roadmap R14); здесь остаётся то,
//     что зависит от createClient, хранилища и транспорта. Эти модули подключаются в index.html до e2ee.js.
//
// Что закрыто в протоколе v2:
//   - Приватные ключи подписи и обмена (identity, SPK, OPK, подпись Sender Key) —
//     неизвлекаемые CryptoKey (extractable:false): XSS не может выгрузить их и
//     унести. Это не относится к seed ML-KEM и ключам цепочек (см. «Честные
//     ограничения»). Старые JWK из хранилища мигрируются в init() и при чтении.
//   - Identity собеседника закрепляется при первом контакте (TOFU), смена
//     identity блокирует обмен ключами с ним до явного
//     acceptPeerIdentityChange(); для сверки есть 60-значный код
//     безопасности, как в Signal. Получатель больше не верит identity из
//     конверта на слово.
//   - PQXDH: к X3DH добавлен ML-KEM-768 по PQ-prekey, подписанному identity —
//     защита от "перехватить сейчас, расшифровать потом". Отката на
//     классический X3DH нет, поэтому сервер не может понизить версию.
//     Каждому инициатору сервер отдаёт одноразовый PQ-prekey (подпись identity
//     с меткой домена и key_id), получатель удаляет его секрет после первого
//     же применённого share — перехваченный позже share расшифровать нечем.
//     Когда одноразовые кончились, берётся запасной подписанный PQ-prekey
//     (он живёт до ротации, раз в 7 дней). Пул одноразовых ключей пополняется
//     при init() и целиком заменяется раз в 30 дней.
//   - AD ключевого обмена включает identity-ключи обеих сторон.
//   - SPK и PQ-prekey ротируются раз в 7 дней (старые приватные живут ещё
//     14). Канал key-share — симметричная KDF-цепочка с удалением
//     использованных ключей (прямая секретность); раз в 7 дней сессия
//     перезапускается новым PQXDH.
//   - Повтор конверта под другим messageId распознаётся ('replay').
//   - Конверт сообщения комнаты — версия 3 ({ v:3, alg:'senderkey-v3', senderKeyId, iteration, iv, ct, sig }).
//     Подпись Sender Key покрывает метку домена "nyxo-skmsg-v3\0", комнату (u32be), senderKeyId (16 байт),
//     итерацию, iv и ct (sigInputV3, sealed-sender.md 9.3); AAD шифрования — "senderkey-v3:<комната>:<автор>:<ключ>".
//     Версия 2 (подпись без метки и комнаты) не принимается: старых конвертов нет (R0).
//   - Подписи Ed25519 проверяются строго (public/lib/ed25519-strict.js, signed-membership.md 6.1):
//     ключ малого порядка, неканоническая кодировка точки и S >= L отвергаются ДО платформенного
//     verify, который принимает такие пары под любым сообщением. Это единственная функция verify
//     (SPK, PQ-prekey, конверты Sender Key); ключи подписи из чужого ввода (identity, SKDM)
//     отвергаются при разборе.
//   - Содержимое привязано к сообщению (docs/security/message-ordering.md,
//     раздел 9): внутри шифротекста лежат mid (id сообщения, который клиент
//     выбирает ДО шифрования), ts (время отправителя) и признак правки e.
//     Получатель после расшифровки и проверки подписи, но ДО любой записи в
//     таблицы seen и edit, проверяет: mid равен id строки ('id-mismatch'), автор
//     не сменился ('sender-mismatch'), правка не старее показанной версии
//     ('stale-edit'); сообщение без mid отвергается ('no-mid'). Сервер не может
//     ни выдать конверт под чужим id, ни перенести правку на другое сообщение,
//     ни откатить правку у того, кто видел новую.
//   - Sealed sender на хранении (docs/security/sealed-sender.md): в строке сообщения
//     комнаты нет автора, его определяет клиент. senderKeyId ПРИВЯЗАН к отправителю:
//     SHA-256("nyxo-skid-v1" ‖ комната ‖ отправитель ‖ открытый ключ подписи)[0..16].
//     При установке чужого ключа пересчитанный идентификатор обязан совпасть с
//     заявленным (отправитель — из AAD key-share, не из ответа сервера), иначе SKDM
//     не устанавливается: занять чужой keyId нельзя. Индекс skIndex:<комната>:<keyId>
//     хранит отправителя; удалённые ключи остаются надгробиями (gone), чтобы отказ
//     назывался 'key-expired' / 'history-not-kept', а не 'no-sender-key'.
//     decryptIncoming находит автора по индексу и ничего не пишет, пока не прошли
//     подпись, AEAD с id отправителя в AAD и проверки mid/ts/версии.
//   - Текст дополняется по схеме Padmé (минимум 256 байт); файлы шифруются
//     AES-256-GCM на клиенте, ключ едет внутри E2EE-сообщения.
//   - Клиент помнит состав комнаты: новые участники видны (атака
//     "призрачного участника" перестаёт быть тихой), при уходе участника
//     свой Sender Key ротируется.
//   - Ротация Sender Key (план криптографии, раздел 5): свой ключ меняется раз
//     в 100 сообщений или 7 дней и при уходе участника; жёсткая граница — 200
//     сообщений или 8 дней (encryptOutgoing → 'needs-room-session'). Новый ключ
//     несёт в ext SKDM prev { id, final }: получатель закрывает по нему цепочку
//     старого ключа и стирает chainKey. Участникам, бывшим в комнате при
//     создании ключа, он выдаётся «с начала эпохи»; потерянный key-share лечит
//     запрос ключа (requestRoomKeys / answerKeyRequests).
//   - Старые ключи хранятся отдельными записями skArchive:… (без предела по
//     числу ротаций), а не внутри основной записи; срок исчезающих сообщений
//     комнаты удаляет ключи вместе с сообщениями, бюджет — 20 000 ключей на
//     комнату (maintainRoomKeys). Удалённое читается как 'key-expired'.
//   - «Не хранить историю на устройстве» (раздел 6): личная настройка комнаты,
//     ключи сообщений, архив, таблицы повторов и записи о версиях стираются при
//     уходе из комнаты и закрытии вкладки; прочитанное читается как
//     'history-not-kept'.
//
// Честные ограничения (сверено с кодом в T5.1; полный список — docs/threat-model.md,
// раздел 8, и README → «Известные ограничения»):
//   - Код клиента отдаёт тот же сервер: злонамеренный сервер может выдать
//     изменённый e2ee.js, и веб-клиент от этого защититься не может. Подмену
//     замечают сверка файлов с манифестом релиза (docs/VERIFY.md) и закрепление
//     версии в service worker (docs/ops/service-worker.md), но не адресную подмену при
//     первом заходе и не обновление, которое человек принял, не сверив.
//   - Sealed sender действует только на хранении (docs/security/sealed-sender.md): в
//     строке сообщения комнаты автора нет, его определяет клиент. Но дамп без ключа
//     сервера сохраняет косвенные связи (позиция чтения, время активности, квота
//     вложений), по которым автора часто можно восстановить. На работающем сервере
//     запрос связан с сессией и IP, а в комнате на двоих автор очевиден по составу. Метаданные видны серверу: кто подключён и когда, в каких комнатах
//     состоит, кто кому передаёт ключи, время сообщений до минуты, класс размера
//     сообщения и файла (после Padmé), состав комнат.
//   - Состав комнаты задаёт сервер. Подписанный состав (docs/security/signed-membership.md)
//     не даёт ему добавить читателя: участник без подписи допуска остаётся
//     «не подтверждён» и ключ комнаты не получает, пока пользователь не нажмёт «Доверять
//     участнику». Но подписать может любой участник, а удаление и выход не подписываются:
//     сервер может оставить ушедшего в списке (читать новое тот сможет только в сговоре с
//     ним). Поворот ссылки-приглашения при выходе не отзывает старую ссылку
//     криптографически: недобросовестный сервер вправе принять join по старому сертификату.
//   - Сервер может "сжечь" одноразовые prekey без использования (выдать bundle
//     и не доставить share) или вовсе не выдавать их: тогда инициаторы берут
//     запасной PQ-prekey, у которого нет одноразовости, — не хуже, чем было до
//     одноразовых ключей. Секреты, выданные вхолостую, стираются при замене пула.
//   - Post-compromise security у Sender Keys ограничена попарным каналом: утёкший
//     ключ цепочки читает всё будущее до ротации (ключ меняется раз в 100 сообщений
//     или 7 дней и при уходе участника; жёсткая граница — 200 сообщений или 8
//     дней), но злоумышленник со снимком устройства читает и новые SKDM, пока
//     попарные сессии не пересоздадутся на новых prekey (примерно 7-14 дней).
//   - Ключи уже показанных сообщений хранятся (иначе история не открывалась бы
//     после перезагрузки — сервер отдаёт её целиком) до срока исчезающих
//     сообщений комнаты, бюджета ключей или режима «Не хранить историю», поэтому
//     от компрометации самого устройства история в обычном режиме не защищена.
//     Прямая секретность истории возникает только от удаления ключей; браузер
//     не гарантирует затирание данных на диске до уплотнения базы IndexedDB.
//   - Ключи в IndexedDB лежат открытыми байтами, кроме приватных ключей подписи и
//     обмена: seed ML-KEM (постоянного и одноразовых PQ-prekey), ключи цепочек Sender Key
//     и попарных каналов, ключи сообщений хранятся как байты, потому что цепочки надо
//     продвигать, а ML-KEM работает на чистом JS. XSS на странице или доступ к профилю
//     браузера выгрузит их. Неизвлекаемость остальных ключей не мешает активной XSS
//     ПОЛЬЗОВАТЬСЯ ими, пока она на странице. Один seed ML-KEM без X25519-ключей
//     гибридный секрет не раскрывает, но ключи цепочек и сообщений читают историю сами.
//   - Участник, бывший в комнате при создании ключа, может получить его с начала
//     эпохи, а запрос ключа ретранслирует сервер: он видит, что у кого-то нет
//     ключа с таким id, но ключа не получает (ответ идёт по попарному каналу).
//   - В режиме «Не хранить историю» владелец ключа не может выдать его с начала
//     эпохи (chainKey0 стёрт): запросивший получит текущую позицию.
//   - Первый контакт — TOFU: пока коды безопасности не сверены, MITM со
//     стороны сервера на первом контакте не исключён. Подписанный состав и журнал
//     ключей сужают окно, но не закрывают его.
//   - Прозрачность ключей — без внешнего свидетеля (docs/security/key-transparency.md,
//     public/lib/kt-client.js): журнал ведёт тот же сервер, а клиенты сверяют головы
//     журнала только между собой (в SKDM) и сканируют своё состояние сами. Журнал не
//     защищает изолированную группу, которой целиком показан поддельный мир с самого
//     начала (в том числе ключ журнала на первой синхронизации), и не защищает от
//     подмены кода клиента. Подмена ключа выявляется после закрытия эпохи (около часа).
//     Журнал необязателен: без KT_SIGNING_KEY на сервере он выключен.
//   - Подписи Ed25519 не постквантовые, а ML-KEM-768 (public/mlkem.js) написан здесь
//     и сверен с реализацией Node, но независимого аудита не было.
//   - Одно устройство на аккаунт (identity на сервере — одна запись), восстановления нет.
//   - Откат правки и подмену автора правки распознаёт только клиент, у которого
//     есть запись о версии сообщения (edit:<комната>:<mid>, не больше 5000 на
//     комнату; вытесняется запись с наименьшим ts): первое появление сообщения,
//     очищенное хранилище или вытеснение дают принять любую версию, прошедшую
//     проверки mid и ts. Таблица повторов ограничена 5000 итерациями на ключ.
//   - Порядок и пропажу сообщений не проверяем: сервер может переставить,
//     задержать или скрыть сообщение (раздел 9.6 контракта).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.E2EE = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const subtle = crypto.subtle;

    // ===================== Константы =====================
    // Блоки разделены, чтобы новые значения добавлялись в «свой» блок, а не в
    // общий хвост списка.

    // ---- Время: ротация prekey и возраст сессий ----

    const HOUR_MS = 60 * 60 * 1000;
    const DAY_MS = 24 * HOUR_MS;
    const PREKEY_ROTATE_MS = 7 * DAY_MS;   // SPK и PQ-prekey
    const PREKEY_RETAIN_MS = 14 * DAY_MS;  // сколько держим приватную часть после ротации
    const PAIRWISE_SESSION_MAX_AGE_MS = 7 * DAY_MS;

    // ---- Время: ротация Sender Key и хранение ключей сообщений ----

    // Мягкий порог: после него roomKeyDue() сообщает, что ключ пора менять, а
    // ensureRoomSession ротирует его до рассылки. Жёсткий порог страхует границу,
    // если фоновая ротация не состоялась: encryptOutgoing перестаёт шифровать
    // (needs-room-session), пока ключ не сменят.
    const ROTATE_AFTER_MESSAGES = 100;
    const ROTATE_AFTER_MS = 7 * DAY_MS;
    const FORCE_ROTATE_AFTER_MESSAGES = 200;
    const FORCE_ROTATE_AFTER_MS = 8 * DAY_MS;
    // Цепочка архивного ключа отправителя, не приславшего prev.final, живёт
    // столько после архивации, потом chainKey удаляется.
    const ARCHIVE_CHAIN_MAX_AGE_MS = 7 * DAY_MS;
    // Запас к таймеру комнаты: ключ удаляется не раньше, чем через T + 1 час
    // после своего вывода (сообщение на сервере к этому времени уже исчезло).
    const KEY_EXPIRY_GRACE_MS = HOUR_MS;
    // Запрос ключа у владельца (requestRoomKeys) и повторная выдача по запросу.
    const KEY_REQUEST_COOLDOWN_MS = HOUR_MS;
    const KEY_RESEND_COOLDOWN_MS = 10 * 60 * 1000;
    const KEY_REQUEST_RETENTION_MS = 7 * DAY_MS;
    const MAX_KEY_REQUEST_IDS = 20;

    // ---- Пределы состояния: кэши ключей, пропуски цепочек, таблицы повторов ----

    // Ключей сообщений в одной цепочке (текущей или архивной). Это защита от
    // раздувания записи, а не бюджет истории: при обрезке запоминается
    // expiredBelow, и расшифровка выдаёт 'key-expired', а не немое 'no-message-key'.
    const MAX_KEYS_PER_CHAIN = 5000;
    // Насколько далеко вперёд по цепочке Sender Key можно "перескочить" за
    // одно сообщение. Без предела конверт с iteration = 10^9 (его может
    // подписать любой участник комнаты) заставлял клиента получателя
    // посчитать миллиард HMAC подряд — вкладка намертво зависала.
    const MAX_SKIP = 5000;
    // То же для попарной цепочки key-share: передач ключей на порядки
    // меньше, чем сообщений.
    const MAX_PW_SKIP = 1000;
    // Бюджет истории комнаты: ключей сообщений во всех цепочках (текущих и
    // архивных) всех отправителей, около 1,2 МБ. Сверх бюджета удаляются самые
    // старые архивы (maintainRoomKeysLocked).
    const MAX_KEYS_PER_ROOM = 20000;
    // Индекс архива в основной записи ключа: подробные записи у последних
    // MAX_ARCHIVE_INDEX архивов, у более старых остаётся только id («надгробие»:
    // старый ключ из повторного key-share обратно не ставится). Надгробий не
    // больше MAX_ARCHIVE_TOMBSTONES; повтор очень старого key-share всё равно
    // не пройдёт попарный канал, это страховка второго рубежа.
    const MAX_ARCHIVE_INDEX = 500;
    const MAX_ARCHIVE_TOMBSTONES = 2000;
    const MAX_SEEN_PER_KEY = 5000;
    // Записей о версиях сообщений (mid → автор, ts, ключ, итерация) на комнату.
    const MAX_EDIT_ENTRIES = 5000;
    const MAX_SEEN_EPHEMERAL = 64;
    const MAX_PENDING_SHARES = 50;

    // ---- Размеры: дополнение, конверты, пакеты key-share ----

    // MSG_PAD_MIN и FILE_PAD_MIN (минимум дополнения Padmé) заданы рядом с Padmé, в lib/e2ee-codec.js.
    // Сервер принимает зашифрованный текст до 12000 символов.
    const MAX_ENVELOPE_CHARS = 12000;
    const MAX_FILE_FIELD = 1024;
    // Сервер принимает до 200 получателей и 8192 символа на один share;
    // пачки по 50 держат тело запроса небольшим.
    const SHARE_BATCH = 50;
    const MAX_SHARE_CHARS = 8192;

    // ---- Код безопасности и ML-KEM ----

    const FINGERPRINT_ITERATIONS = 5200;
    const PQ_PUBLIC_KEY_BYTES = 1184;
    const PQ_CIPHERTEXT_BYTES = 1088;
    const PQ_SEED_BYTES = 64;

    // ---- Пул одноразовых prekey и версия хранилища ----

    const LOW_WATER_OPK = 10;
    const TOPUP_OPK = 30;
    // Одноразовые PQ-prekey: пополнение, когда на сервере осталось меньше
    // LOW_WATER_PQ_OPK, до TOPUP_PQ_OPK штук, пачками по PQ_OPK_BATCH (около
    // 17 КБ JSON). Раз в PQ_OPK_REFRESH_MS пул заменяется целиком: ключи,
    // которые сервер «сжёг» без использования, не копятся в хранилище.
    const LOW_WATER_PQ_OPK = 5;
    const TOPUP_PQ_OPK = 20;
    const PQ_OPK_BATCH = 10;
    const PQ_OPK_REFRESH_MS = 30 * DAY_MS;
    const SCHEMA_VERSION = 2;

    // ---- Причины отказа в обмене ключами (тексты для интерфейса) ----

    // Общий признак версии клиента в изменяющих запросах (message-ordering.md, 14.1); равенство с PROTO_CURRENT
    // сервера (lib/proto.js) проверяет test/proto-client.test.js.
    const PROTO_VERSION = 4;

    const REASON_NOT_READY = 'у собеседника ещё не настроен E2EE';
    const REASON_OUTDATED = 'у собеседника устаревшая версия E2EE';
    const REASON_IDENTITY_CHANGED = 'ключ безопасности собеседника изменился — нужно подтверждение';
    const REASON_KEY_UNBOUND = 'ключ участника не принят: идентификатор не выведен из отправителя';
    const REASON_LOG_MISMATCH = 'ключа собеседника нет в журнале ключей — нужна сверка кода безопасности';
    // Сколько ждём проверок журнала внутри ensureRoomSession и списка участников: дольше — работаем без
    // результата (проверка продолжается в фоне и повторяется), отправка не должна зависеть от журнала.
    const KT_WAIT_MS = 8000;

    // ===================== Ошибки =====================

    // Коды типизированных ошибок инициализации: по ним интерфейс выбирает
    // текст и решает, предлагать ли «Повторить».
    //   unsupported — браузер не умеет нужную криптографию (X25519, Ed25519, HKDF, ML-KEM);
    //   storage     — локальное хранилище (IndexedDB) недоступно или отказало;
    //   network     — запрос к серверу ключей не дошёл (fetch отклонён);
    //   server      — сервер ключей ответил ошибкой (5xx, 401, 403, 404);
    //   protocol    — ответ не того формата или ключ неверной длины.
    const ERROR_CODES = Object.freeze(['unsupported', 'storage', 'network', 'server', 'protocol']);

    // Ею отвечает init() (и транспорт ключей) по фазам: probeSupport →
    // unsupported, хранилище → storage, запросы к серверу ключей → network,
    // server или protocol; кроме того, её бросает encryptOutgoing без
    // корректного messageId (protocol). script.js выбирает текст по err.code, а не
    // разбором сообщения. status — HTTP-статус для network/server, у остальных
    // кодов его нет.
    class E2eeError extends Error {
        constructor(code, message, { status, cause } = {}) {
            super(message || ('E2EE: ' + code), cause === undefined ? undefined : { cause });
            this.name = 'E2eeError';
            this.code = code;
            if (status !== undefined) this.status = status;
        }
    }

    // Ошибки хранилища и транспорта приводятся к E2eeError на самой границе,
    // а не по фазам init(): хранилище отказывает и посреди отправки, и там тоже
    // нужно отличить «браузер не даёт сохранить ключи» от «нет связи».
    //   * хранилище: NotSupportedError → unsupported, любое другое исключение → storage;
    //   * транспорт: отказ fetch (TypeError, AbortError) → network.
    // Уже типизированные ошибки проходят как есть. Результат вызова, в том числе
    // синхронный, не меняется.
    function guardCalls(target, convert) {
        return new Proxy(target, {
            get(obj, key) {
                const value = obj[key];
                if (typeof value !== 'function') return value;
                return (...args) => {
                    let result;
                    try {
                        result = value.apply(obj, args);
                    } catch (err) {
                        throw convert(err);
                    }
                    return result && typeof result.then === 'function' ? result.catch((err) => { throw convert(err); }) : result;
                };
            },
        });
    }

    function storageFailure(err) {
        if (err instanceof E2eeError) return err;
        if (err && err.name === 'NotSupportedError') {
            return new E2eeError('unsupported', 'E2EE: браузер не поддерживает хранение этих ключей', { cause: err });
        }
        return new E2eeError('storage', 'E2EE: хранилище ключей устройства недоступно', { cause: err });
    }

    function transportFailure(err) {
        if (err instanceof E2eeError) return err;
        if (err instanceof TypeError || (err && err.name === 'AbortError')) {
            return new E2eeError('network', 'E2EE: нет связи с сервером ключей', { cause: err });
        }
        return err;
    }

    // ===================== Чистые модули ядра =====================
    // Функции без состояния клиента вынесены в public/lib/e2ee-*.js (roadmap R14): кодирование и Padmé,
    // обёртки Web Crypto с KDF-цепочкой, разбор и сборка форматов, нормализация записей. Здесь остаётся
    // то, что зависит от createClient, хранилища и транспорта. В браузере модули - глобальные Nyxo*
    // (подключаются до e2ee.js, порядок - в index.html), в Node - соседние файлы. Без любого из них клиент
    // не работает: молча подменять разбор форматов или криптографию нечем.
    function resolveCoreModule(loaded, nodePath, label) {
        if (loaded) return loaded;
        if (typeof require === 'function') {
            try {
                return require(nodePath);
            } catch (cause) {
                throw new Error('E2EE: модуль ' + label + ' не загружен', { cause });
            }
        }
        throw new Error('E2EE: модуль ' + label + ' не загружен');
    }

    const Codec = resolveCoreModule(typeof NyxoE2eeCodec !== 'undefined' ? NyxoE2eeCodec : null, './lib/e2ee-codec.js', 'lib/e2ee-codec.js');
    const {
        MSG_PAD_MIN, FILE_PAD_MIN, b64encode, b64decode, decodeFixed, canonicalPubKey,
        utf8encode, utf8decode, concatBytes, bytesEqual, u32be, u64be,
        toBytes, isKeyId, isU32, isAllZero, isCanonicalKeyId, padmeLength,
        padMessage, unpadMessage, filePaddedLength,
    } = Codec;

    // Строгая проверка Ed25519 (public/lib/ed25519-strict.js, signed-membership.md 6.1): ключ малого
    // порядка или некорректная кодировка принимаются платформенным verify для ЛЮБОГО сообщения
    // (подпись R = 01 00…00, S = 0), поэтому каждая проверка подписи в этом файле идёт через verify()
    // ниже, а ключи подписи из чужого ввода (identity, SKDM) отвергаются ещё при разборе.
    // В браузере - глобальный NyxoEd25519Strict (подключается до e2ee.js), в Node - соседний модуль.
    // Без него клиент не работает: молча проверять подписи по-старому нельзя.
    function resolveEd25519Strict() {
        if (typeof NyxoEd25519Strict !== 'undefined' && NyxoEd25519Strict) return NyxoEd25519Strict;
        if (typeof require === 'function') {
            try {
                return require('./lib/ed25519-strict.js');
            } catch { /* ниже общая ошибка */ }
        }
        throw new Error('E2EE: модуль строгой проверки Ed25519 (lib/ed25519-strict.js) не загружен');
    }
    const ed25519Strict = resolveEd25519Strict();

    // Ключ подписи Ed25519 из чужого ввода: каноническое base64 и строгая проверка ключа.
    function canonicalSigningKey(str) {
        const canonical = canonicalPubKey(str);
        if (!canonical || !ed25519Strict.isStrictKey(b64decode(canonical))) return null;
        return canonical;
    }

    // ===================== Примитивы =====================

    const ZERO32 = new Uint8Array(32);
    const FF32 = new Uint8Array(32).fill(0xff);

    function randomBytes(n) {
        return crypto.getRandomValues(new Uint8Array(n));
    }

    // Приватные ключи создаются неизвлекаемыми: их можно использовать, но не
    // выгрузить наружу (exportKey кидает). Публичная половина пары по
    // спецификации WebCrypto извлекаема всегда.
    async function generateX25519() {
        const kp = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        return { pub, priv: kp.privateKey };
    }

    async function generateEd25519() {
        const kp = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
        const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
        return { pub, priv: kp.privateKey };
    }

    function isCryptoKey(v) {
        return Boolean(v) && typeof v === 'object' && typeof v.type === 'string' && Boolean(v.algorithm) && typeof v.extractable === 'boolean';
    }

    function isJwk(v) {
        return Boolean(v) && typeof v === 'object' && typeof v.kty === 'string';
    }

    // Миграция: JWK, записанный прежней версией, импортируется как
    // неизвлекаемый CryptoKey (после перезаписи в хранилище JWK исчезает).
    async function toPrivateKey(value, algName, usages) {
        if (isCryptoKey(value)) return value;
        if (isJwk(value)) return subtle.importKey('jwk', value, { name: algName }, false, usages);
        throw new Error('E2EE: повреждён приватный ключ в хранилище');
    }

    async function dh(privKey, pubRawBytes) {
        if (pubRawBytes.length !== 32 || isAllZero(pubRawBytes)) {
            throw new Error('E2EE: получен вырожденный (all-zero) публичный ключ');
        }
        const pub = await subtle.importKey('raw', pubRawBytes, { name: 'X25519' }, false, []);
        const bits = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, privKey, 256));
        if (isAllZero(bits)) throw new Error('E2EE: вырожденный результат DH (точка малого порядка)');
        return bits;
    }

    async function sign(privKey, data) {
        return new Uint8Array(await subtle.sign('Ed25519', privKey, data));
    }

    // Импорт публичного ключа стоит заметно дороже самой проверки, а ключи
    // подписи Sender Key одни и те же для тысяч сообщений истории.
    const verifyKeyCache = new Map();
    // ЕДИНСТВЕННОЕ место, где проверяется подпись Ed25519 (SPK, PQ-prekey, конверты Sender Key): строгая
    // проверка ключа и подписи (ключ малого порядка, неканонические кодировки, S >= L) выполняется ДО
    // платформенного verify, который сам такие пары принимает. Статический тест следит, что других
    // вызовов subtle.verify в файле нет.
    async function verify(pubRawBytes, sig, data) {
        try {
            if (pubRawBytes.length !== 32 || sig.length !== 64) return false;
            if (!ed25519Strict.isStrictKey(pubRawBytes) || !ed25519Strict.checkSignature(sig).ok) return false;
            const cacheKey = b64encode(pubRawBytes);
            let pub = verifyKeyCache.get(cacheKey);
            if (!pub) {
                pub = await subtle.importKey('raw', pubRawBytes, { name: 'Ed25519' }, false, ['verify']);
                if (verifyKeyCache.size >= 256) verifyKeyCache.delete(verifyKeyCache.keys().next().value);
                verifyKeyCache.set(cacheKey, pub);
            }
            return await subtle.verify('Ed25519', pub, sig, data);
        } catch {
            return false;
        }
    }

    async function hkdf(ikm, salt, infoStr, lengthBytes) {
        const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const bits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt, info: utf8encode(infoStr) },
            key,
            lengthBytes * 8
        );
        return new Uint8Array(bits);
    }

    async function hmacSha256(keyBytes, dataBytes) {
        const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return new Uint8Array(await subtle.sign('HMAC', key, dataBytes));
    }

    async function aesGcmEncrypt(rawKey32, plaintext, aad) {
        const key = await subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['encrypt']);
        const iv = randomBytes(12);
        const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext));
        return { iv, ct };
    }

    async function aesGcmDecrypt(rawKey32, iv, ct, aad) {
        const key = await subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct);
        return new Uint8Array(pt);
    }

    // ===================== KDF-цепочка =====================
    // Стандартная схема Signal: messageKey = HMAC(chainKey, 0x01),
    // nextChainKey = HMAC(chainKey, 0x02). Продвижение необратимо —
    // предыдущий chainKey нельзя восстановить из следующего. Одна и та же
    // схема у Sender Key и у попарного канала key-share.

    async function chainStep(chainKey) {
        const messageKey = await hmacSha256(chainKey, new Uint8Array([0x01]));
        const nextChainKey = await hmacSha256(chainKey, new Uint8Array([0x02]));
        return { messageKey, nextChainKey };
    }

    // Возвращает messageKey для нужной iteration, продвигая цепочку и
    // кэшируя "пропущенные" (и уже использованные — см. шапку файла про
    // историю чата) ключи по пути. hour — часовой индекс «сейчас»: он
    // записывается в keyTimes для каждого выведенного ключа и нужен таймеру
    // комнаты (maintainRoomKeysLocked).
    async function getOrDeriveMessageKey(state, targetIteration, hour) {
        if (targetIteration < state.nextIteration) {
            const cached = state.cachedKeys[targetIteration];
            if (!cached) return null; // ключ удалён (таймер, бюджет, «не хранить историю») или не сохранялся
            return b64decode(cached);
        }
        let chainKey = b64decode(state.chainKey);
        if (!state.keyTimes) state.keyTimes = {};
        for (let it = state.nextIteration; it <= targetIteration; it++) {
            const { messageKey, nextChainKey } = await chainStep(chainKey);
            state.cachedKeys[it] = b64encode(messageKey);
            state.keyTimes[it] = hour;
            chainKey = nextChainKey;
        }
        state.chainKey = b64encode(chainKey);
        state.nextIteration = targetIteration + 1;
        trimChain(state);
        const key = state.cachedKeys[targetIteration];
        return key ? b64decode(key) : null;
    }

    function trimNumericMap(map, max) {
        const keys = Object.keys(map);
        if (keys.length <= max) return;
        keys.map(Number).sort((a, b) => a - b)
            .slice(0, keys.length - max)
            .forEach(k => { delete map[k]; });
    }

    // Удаляет ключи сообщений, для которых shouldDrop(итерация) истинно, и
    // запоминает в expiredBelow, что на этой цепочке ключи удаляли намеренно:
    // отсутствие ключа ниже этой границы — не «никогда не было», а «удалён»
    // ('key-expired'). Возвращает число удалённых ключей.
    function dropKeys(rec, shouldDrop) {
        let dropped = 0;
        let highest = -1;
        for (const name of Object.keys(rec.cachedKeys)) {
            const it = Number(name);
            if (!shouldDrop(it)) continue;
            delete rec.cachedKeys[name];
            if (rec.keyTimes) delete rec.keyTimes[name];
            dropped++;
            if (it > highest) highest = it;
        }
        if (dropped > 0) rec.expiredBelow = Math.max(rec.expiredBelow || 0, highest + 1);
        return dropped;
    }

    // Предел ключей в одной цепочке: самые старые уходят первыми.
    function trimChain(rec) {
        const names = Object.keys(rec.cachedKeys);
        if (names.length <= MAX_KEYS_PER_CHAIN) return;
        const sorted = names.map(Number).sort((a, b) => a - b);
        const boundary = sorted[names.length - MAX_KEYS_PER_CHAIN];
        dropKeys(rec, it => it < boundary);
    }

    // Закрывает архивную цепочку чужого ключа по prev.final: выводит оставшиеся
    // ключи до final включительно (не больше MAX_SKIP — абсурдный final не
    // заставит считать миллиарды HMAC), кэширует их и стирает chainKey: больше
    // эта цепочка ничего не даёт. false — цепочки нет или final меньше уже
    // прочитанного (противоречие: не трогаем). final при обрезке по MAX_SKIP
    // записывается обрезанным: что дальше, прочитать всё равно нельзя.
    async function closeChain(rec, final, hour) {
        if (!rec.chainKey || !Number.isInteger(rec.nextIteration)) return false;
        if (final < rec.nextIteration - 1) return false;
        const last = Math.min(final, rec.nextIteration + MAX_SKIP - 1);
        if (last >= rec.nextIteration) await getOrDeriveMessageKey(rec, last, hour);
        delete rec.chainKey;
        rec.final = last;
        return true;
    }

    // Ключ сообщения n попарной цепочки. В отличие от Sender Key здесь
    // использованный ключ сразу удаляется, а в сессии остаются только
    // следующий chainKey и ключи ещё не пришедших (пропущенных) передач —
    // это и есть прямая секретность канала key-share.
    async function takePairwiseKey(session, n) {
        if (n < session.n) {
            const stored = session.skipped[n];
            if (!stored) return null; // уже использован (повтор) или слишком старый
            delete session.skipped[n];
            return b64decode(stored);
        }
        if (n - session.n > MAX_PW_SKIP) return null;
        let chainKey = b64decode(session.ck);
        let target = null;
        for (let i = session.n; i <= n; i++) {
            const { messageKey, nextChainKey } = await chainStep(chainKey);
            if (i === n) target = messageKey;
            else session.skipped[i] = b64encode(messageKey);
            chainKey = nextChainKey;
        }
        session.ck = b64encode(chainKey);
        session.n = n + 1;
        trimNumericMap(session.skipped, MAX_PW_SKIP);
        return target;
    }

    // ===================== Содержимое сообщения v2 =====================

    function normalizeFileDescriptor(o) {
        if (!o || typeof o !== 'object') return null;
        const { mime, name, size, key, iv } = o;
        if (typeof mime !== 'string' || mime.length > MAX_FILE_FIELD) return null;
        if (typeof name !== 'string' || name.length > MAX_FILE_FIELD) return null;
        if (!Number.isSafeInteger(size) || size < 0) return null;
        if (!decodeFixed(key, 32) || !decodeFixed(iv, 12)) return null;
        return { mime, name, size, key, iv };
    }

    // Формат содержимого (message-ordering.md, раздел 9.1):
    //   { t:'text', b, mid, ts, e?:1 }
    //   { t:'file', mime, name, size, key, iv, caption, mid, ts }
    // mid — String(id сообщения), ts — время отправителя в мс, e:1 — правка
    // (правятся только текстовые сообщения).
    function encodeContent(content, { mid, ts, edit = false }) {
        if (typeof content === 'string') {
            const text = { t: 'text', b: content, mid, ts };
            if (edit) text.e = 1;
            return text;
        }
        if (content && typeof content === 'object' && content.type === 'file') {
            if (edit) throw new Error('E2EE: правятся только текстовые сообщения');
            const file = normalizeFileDescriptor(content);
            if (!file) throw new Error('E2EE: некорректное описание файла');
            const caption = content.caption === undefined || content.caption === null ? '' : content.caption;
            if (typeof caption !== 'string') throw new Error('E2EE: подпись к файлу должна быть строкой');
            return { t: 'file', mime: file.mime, name: file.name, size: file.size, key: file.key, iv: file.iv, caption, mid, ts };
        }
        throw new Error('E2EE: неподдерживаемое содержимое сообщения');
    }

    // Разбор формы содержимого. mid и ts здесь не проверяются: это делает
    // decryptIncoming по порядку раздела 9.4 (сначала 'no-mid', потом
    // 'id-mismatch', потом 'bad-plaintext' для ts). Признак правки допустим
    // только у текста.
    function decodeContent(obj) {
        if (!obj || typeof obj !== 'object') return null;
        let content;
        if (obj.t === 'text' && typeof obj.b === 'string') {
            content = { text: obj.b, edit: obj.e === 1 };
        } else if (obj.t === 'file') {
            const file = normalizeFileDescriptor(obj);
            if (!file || typeof obj.caption !== 'string' || obj.e !== undefined) return null;
            content = { text: obj.caption, file, edit: false };
        } else {
            return null;
        }
        content.mid = obj.mid;
        content.ts = obj.ts;
        return content;
    }

    // Id сообщения (раздел 6.1): строка ^[1-9]\d{6,9}$, не больше 2^31-1.
    function isValidMessageId(value) {
        return typeof value === 'string' && /^[1-9]\d{6,9}$/.test(value) && Number(value) <= 2147483647;
    }

    // ===================== Файлы =====================
    // Каждый файл — свой случайный ключ AES-256-GCM и iv; ключ, iv и
    // исходный размер передаются внутри E2EE-сообщения (encryptOutgoing с
    // объектом { type:'file', ... }), серверу достаётся только шифротекст
    // Padmé-длины.

    const FILE_AAD = utf8encode('nyxo-file-v1');

    async function encryptFile(bytes) {
        const data = toBytes(bytes);
        const padded = new Uint8Array(filePaddedLength(data.length));
        padded.set(data, 0);
        const key = randomBytes(32);
        const { iv, ct } = await aesGcmEncrypt(key, padded, FILE_AAD);
        return { ciphertext: ct, key: b64encode(key), iv: b64encode(iv), size: data.length };
    }

    async function decryptFile(ciphertext, key, iv, size) {
        const keyBytes = decodeFixed(key, 32);
        const ivBytes = decodeFixed(iv, 12);
        if (!keyBytes || !ivBytes) throw new Error('E2EE: некорректный ключ файла');
        if (!Number.isSafeInteger(size) || size < 0) throw new Error('E2EE: некорректный размер файла');
        let pt;
        try {
            pt = await aesGcmDecrypt(keyBytes, ivBytes, toBytes(ciphertext), FILE_AAD);
        } catch {
            throw new Error('E2EE: файл повреждён или подменён');
        }
        // Размер пришёл в подписанном сообщении; несовпадение с длиной
        // расшифрованного — признак чужого файла или испорченного описания.
        if (pt.length !== filePaddedLength(size)) throw new Error('E2EE: размер файла не совпадает');
        for (let i = size; i < pt.length; i++) {
            if (pt[i] !== 0) throw new Error('E2EE: некорректный паддинг файла');
        }
        return pt.slice(0, size);
    }

    // ===================== Код безопасности =====================
    // Как NumericFingerprintGenerator в Signal: для каждой стороны
    // hash0 = 0x0000 ‖ signPub ‖ dhPub ‖ utf8(userId), затем 5200 раз
    // hash = SHA-512(hash ‖ signPub ‖ dhPub); первые 30 байт → 6 блоков по
    // 5 байт → uint40 mod 100000 → по 5 цифр. Половины упорядочены по
    // числовому userId, поэтому обе стороны видят одну и ту же строку.

    async function fingerprintHalf(userId, signPubB64, dhPubB64) {
        const keys = concatBytes(b64decode(signPubB64), b64decode(dhPubB64));
        let hash = concatBytes(new Uint8Array([0, 0]), keys, utf8encode(String(userId)));
        for (let i = 0; i < FINGERPRINT_ITERATIONS; i++) {
            hash = new Uint8Array(await subtle.digest('SHA-512', concatBytes(hash, keys)));
        }
        let out = '';
        for (let i = 0; i < 30; i += 5) {
            let v = 0;
            for (let j = 0; j < 5; j++) v = v * 256 + hash[i + j];
            out += String(v % 100000).padStart(5, '0');
        }
        return out;
    }

    async function computeSafetyNumber(idA, signA, dhA, idB, signB, dhB) {
        const halfA = await fingerprintHalf(idA, signA, dhA);
        const halfB = await fingerprintHalf(idB, signB, dhB);
        const digits = Number(idA) <= Number(idB) ? halfA + halfB : halfB + halfA;
        return digits.match(/.{5}/g).join(' ');
    }

    // ===================== Хранилище (внедряется) =====================
    // storage — { get(key)->Promise<any|null>, set(key,value)->Promise,
    //             delete(key)->Promise, keys(prefix)->Promise<string[]> }

    // Значения клонируются так же, как их клонирует IndexedDB (structured
    // clone): тесты на MemoryStorage ловят забытый set() после изменения
    // объекта и заодно проверяют, что CryptoKey переживает клонирование.
    class MemoryStorage {
        constructor() { this.map = new Map(); }
        async get(key) { return this.map.has(key) ? structuredClone(this.map.get(key)) : null; }
        async set(key, value) { this.map.set(key, structuredClone(value)); }
        async delete(key) { this.map.delete(key); }
        async keys(prefix) { return Array.from(this.map.keys()).filter(k => k.startsWith(prefix)); }
    }

    // IndexedDB-хранилище для браузера. Ключи устройства никогда не
    // покидают этот origin и не отправляются на сервер; приватные ключи
    // лежат в нём как неизвлекаемые CryptoKey (structured clone это умеет).
    function makeIndexedDbStorage(dbName) {
        let dbPromise = null;
        function openDb() {
            if (dbPromise) return dbPromise;
            dbPromise = new Promise((resolve, reject) => {
                const req = indexedDB.open(dbName || 'nyxo-e2ee', 1);
                req.onupgradeneeded = () => {
                    if (!req.result.objectStoreNames.contains('kv')) req.result.createObjectStore('kv');
                };
                req.onsuccess = () => {
                    const db = req.result;
                    // deleteLocalData() (или другая вкладка) удаляет базу —
                    // отпускаем соединение, иначе удаление заблокируется.
                    db.onversionchange = () => { db.close(); dbPromise = null; };
                    resolve(db);
                };
                req.onerror = () => { dbPromise = null; reject(req.error); };
            });
            return dbPromise;
        }
        return {
            async get(key) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction('kv', 'readonly').objectStore('kv').get(key);
                    tx.onsuccess = () => resolve(tx.result === undefined ? null : tx.result);
                    tx.onerror = () => reject(tx.error);
                });
            },
            async set(key, value) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction('kv', 'readwrite').objectStore('kv').put(value, key);
                    tx.onsuccess = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            },
            async delete(key) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const tx = db.transaction('kv', 'readwrite').objectStore('kv').delete(key);
                    tx.onsuccess = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            },
            async keys(prefix) {
                const db = await openDb();
                return new Promise((resolve, reject) => {
                    const out = [];
                    // Диапазон по префиксу: курсор не обходит всё хранилище (записи о
                    // версиях сообщений edit:<комната>:<mid> — тысячи ключей).
                    const range = IDBKeyRange.bound(prefix, prefix + '\uffff');
                    const req = db.transaction('kv', 'readonly').objectStore('kv').openCursor(range);
                    req.onsuccess = () => {
                        const cursor = req.result;
                        if (!cursor) return resolve(out);
                        if (String(cursor.key).startsWith(prefix)) out.push(String(cursor.key));
                        cursor.continue();
                    };
                    req.onerror = () => reject(req.error);
                });
            },
        };
    }

    // Удаляет локальную базу ключей пользователя (выход с удалением данных,
    // удаление аккаунта). Резолвится true после удаления, false — если
    // IndexedDB нет вовсе.
    function deleteLocalData(userId) {
        return new Promise((resolve, reject) => {
            const id = Number(userId);
            if (!Number.isSafeInteger(id) || id <= 0) {
                reject(new Error('E2EE: некорректный userId'));
                return;
            }
            if (typeof indexedDB === 'undefined' || !indexedDB) {
                resolve(false);
                return;
            }
            let settled = false;
            let timer = null;
            const finish = (fn, value) => {
                if (settled) return;
                settled = true;
                if (timer) clearTimeout(timer);
                fn(value);
            };
            const req = indexedDB.deleteDatabase('nyxo-e2ee-' + id);
            req.onsuccess = () => finish(resolve, true);
            req.onerror = () => finish(reject, req.error || new Error('E2EE: не удалось удалить локальные ключи'));
            // База открыта в другой вкладке. Наши соединения закрываются сами
            // по versionchange (makeIndexedDbStorage), но зависшая вкладка
            // может держать её долго — не ждём вечно. Запрос на удаление при
            // этом остаётся в очереди и выполнится, когда вкладку закроют.
            req.onblocked = () => {
                if (settled || timer) return;
                timer = setTimeout(() => finish(reject, new Error(
                    'E2EE: локальные ключи открыты в другой вкладке — закройте её, удаление завершится автоматически'
                )), 10000);
            };
        });
    }

    // ===================== Транспорт (внедряется) =====================
    // transport — обёртка над /api/keys/* и /api/keys/key-shares*.
    // Реализация по умолчанию для браузера — fetch с CSRF-заголовком.

    function getCsrfTokenFromCookies() {
        if (typeof document === 'undefined') return '';
        const match = document.cookie.match(/csrf_token=([^;]+)/);
        return match ? match[1] : '';
    }

    function makeFetchTransport() {
        async function call(url, method, body) {
            let res;
            try {
                res = await fetch(url, {
                    method,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': getCsrfTokenFromCookies(),
                    },
                    body: body !== undefined ? JSON.stringify(body) : undefined,
                });
            } catch (cause) {
                throw new E2eeError('network', 'E2EE: нет связи с сервером ключей', { cause });
            }
            let data;
            try {
                data = await res.json();
            } catch (cause) {
                // Страница ошибки прокси или шлюза (502, 503) — это «сервер не отвечает»,
                // а не нарушение формата: повтор имеет смысл. Остальное — не наш формат.
                throw new E2eeError(res.status >= 500 ? 'server' : 'protocol',
                    'E2EE: сервер ключей ответил не JSON', { status: res.status, cause });
            }
            return { status: res.status, data };
        }
        return {
            async putIdentity(body) { return call('/api/keys/identity', 'PUT', { ...body, proto: PROTO_VERSION }); },
            async putSignedPrekey(body) { return call('/api/keys/signed-prekey', 'PUT', body); },
            async putPqPrekey(body) { return call('/api/keys/pq-prekey', 'PUT', body); },
            async postOneTimePrekeys(body) { return call('/api/keys/one-time-prekeys', 'POST', body); },
            async postPqOneTimePrekeys(body) { return call('/api/keys/pq-one-time-prekeys', 'POST', body); },
            async deletePqOneTimePrekeys() { return call('/api/keys/pq-one-time-prekeys', 'DELETE'); },
            async getOneTimePrekeyCount() { return call('/api/keys/one-time-prekeys/count', 'GET'); },
            async getBundle(targetUserId) { return call('/api/keys/bundle/' + encodeURIComponent(targetUserId), 'GET'); },
            async getIdentities(ids) {
                const list = ids.map(Number).filter(id => Number.isSafeInteger(id) && id > 0);
                return call('/api/keys/identities?ids=' + list.join(','), 'GET');
            },
            async deleteKeys() { return call('/api/keys', 'DELETE'); },
            // Журнал ключей (docs/security/key-transparency.md, 6.5).
            async ktHead() { return call('/api/kt/head', 'GET'); },
            async ktRoots(gen, from, limit) { return call(`/api/kt/roots?gen=${Number(gen)}&from=${Number(from)}&limit=${Number(limit)}`, 'GET'); },
            async ktProof(userId, gen, epoch) { return call(`/api/kt/proof?user=${Number(userId)}&gen=${Number(gen)}&epoch=${Number(epoch)}`, 'GET'); },
            async ktSelf(gen, from, limit) { return call(`/api/kt/self?gen=${Number(gen)}&from=${Number(from)}&limit=${Number(limit)}`, 'GET'); },
            async getParticipants(chatId) { return call('/api/chats/' + encodeURIComponent(chatId) + '/participants', 'GET'); },
            // Сертификаты состава (signed-membership.md, 7.2): чужие - отдельным запросом, до 200 id; публикация допуска.
            async getMemberCerts(chatId, ids) {
                const list = ids.map(Number).filter(id => Number.isSafeInteger(id) && id > 0);
                return call('/api/chats/' + encodeURIComponent(chatId) + '/member-certs?subjects=' + list.join(','), 'GET');
            },
            async postMemberCert(chatId, body) {
                return call('/api/chats/' + encodeURIComponent(chatId) + '/member-certs', 'POST', { ...body, proto: PROTO_VERSION });
            },
            async postKeyShares(chatId, shares) { return call('/api/keys/key-shares', 'POST', { chatId, shares, proto: PROTO_VERSION }); },
            async getKeyShares(chatId) { return call('/api/keys/key-shares/' + encodeURIComponent(chatId), 'GET'); },
            // Запрос ключа: «пришлите Sender Key с этим id» (потерянный key-share).
            async postKeyRequests(chatId, senderKeyIds) { return call('/api/keys/key-requests', 'POST', { chatId, senderKeyIds }); },
            async getKeyRequests(chatId) { return call('/api/keys/key-requests/' + encodeURIComponent(chatId), 'GET'); },
            async postKeyRequestsDone(chatId, senderKeyIds) { return call('/api/keys/key-requests/done', 'POST', { chatId, senderKeyIds }); },
        };
    }

    // ML-KEM по умолчанию: в браузере — глобальный MLKEM (public/mlkem.js
    // подключается до e2ee.js), в Node — соседний модуль.
    function resolveDefaultKem() {
        if (typeof MLKEM !== 'undefined' && MLKEM) return MLKEM;
        if (typeof require === 'function') {
            try {
                return require('./mlkem.js');
            } catch {
                throw new Error('E2EE: модуль ML-KEM (mlkem.js) недоступен');
            }
        }
        throw new Error('E2EE: модуль ML-KEM (mlkem.js) не загружен');
    }

    // Клиент журнала ключей: в браузере — глобальный NyxoKtClient (public/lib/kt-client.js подключается
    // до e2ee.js), в Node — соседний модуль. Нет модуля — клиент работает без журнала.
    function resolveKtClient() {
        if (typeof NyxoKtClient !== 'undefined' && NyxoKtClient) return NyxoKtClient;
        if (typeof require === 'function') {
            try {
                return require('./lib/kt-client.js');
            } catch {
                return null;
            }
        }
        return null;
    }

    // Подписанный состав группы (docs/security/signed-membership.md): форматы сертификатов и клиент состава.
    // В браузере - глобальные NyxoMembership и NyxoMembershipClient (подключаются до e2ee.js), в Node - соседние модули.
    // Без них клиент не работает: решение, кому отправлять ключ комнаты, принимает именно состав.
    function resolveMembershipModules() {
        if (typeof NyxoMembership !== 'undefined' && NyxoMembership && typeof NyxoMembershipClient !== 'undefined' && NyxoMembershipClient) {
            return { lib: NyxoMembership, client: NyxoMembershipClient };
        }
        if (typeof require === 'function') {
            try {
                return { lib: require('./lib/membership.js'), client: require('./lib/membership-client.js') };
            } catch {
                return null;
            }
        }
        return null;
    }
    const membershipModules = resolveMembershipModules();

    // ===================== Форматы конвертов =====================

    // Подпись одноразового PQ-prekey: Ed25519(IK, метка ‖ u64be(key_id) ‖ pk).
    // Метка и привязка к key_id отличают её от подписи SPK (32 байта) и PQ
    // last-resort («сырые» 1184 байта): сервер не может выдать один вид ключа
    // за другой, а подпись нельзя перенести на другой key_id. Все части
    // фиксированной длины (14 + 8 + 1184).
    const PQ_OPK_LABEL = utf8encode('nyxo-pqopk-v1\0');
    function pqOneTimeSigInput(keyId, publicKey) {
        return concatBytes(PQ_OPK_LABEL, u64be(keyId), publicKey);
    }

    // Подпись конверта сообщения комнаты (версия 3): Ed25519(ключ подписи Sender Key, sigInputV3).
    //   sigInput = "nyxo-skmsg-v3\0" ‖ u32be(roomId) ‖ senderKeyId[16] ‖ u32be(iteration) ‖ iv[12] ‖ ct
    // Метка домена (реестр меток, план криптографии 1.1) отличает эту подпись от любой другой подписи
    // Ed25519 в системе, а комната входит в подписанные байты: конверт, снятый с одной комнаты, не
    // подходит к другой, даже если сервер подсунул чужой индекс отправителей. Все поля до ct —
    // фиксированной длины (14 + 4 + 16 + 4 + 12 = 50 байт), ct (не короче 272 байт) идёт последним:
    // два разных набора полей не дают одну и ту же строку. senderKeyId берётся сырыми 16 байтами,
    // а не текстом base64, поэтому каноничность записи на подпись не влияет. Прежняя версия
    // (iv ‖ ct ‖ iteration ‖ keyId без метки и комнаты) не принимается: R0, конвертов v2 нет.
    const SKMSG_LABEL = utf8encode('nyxo-skmsg-v3\0');

    function sigInputV3(roomId, senderKeyIdBytes, iteration, iv, ct) {
        return concatBytes(SKMSG_LABEL, u32be(roomId), senderKeyIdBytes, u32be(iteration), iv, ct);
    }

    function msgAadV3(roomId, senderId, senderKeyId) {
        return utf8encode('senderkey-v3:' + roomId + ':' + senderId + ':' + senderKeyId);
    }

    // AD key-share v2: помимо комнаты и направления — identity-ключи обеих
    // сторон (требование X3DH: AD = IK_A ‖ IK_B). Подмена identity любой из
    // сторон ломает AEAD, даже если сессионный ключ каким-то образом совпал.
    function skdmAadV2(roomId, senderUserId, recipientUserId, senderSignPub, senderDhPub, recipientSignPub, recipientDhPub) {
        return concatBytes(
            utf8encode('nyxo-skdm-v2:' + roomId + ':' + senderUserId + ':' + recipientUserId),
            b64decode(senderSignPub), b64decode(senderDhPub),
            b64decode(recipientSignPub), b64decode(recipientDhPub)
        );
    }

    // Идентификатор ключа отправителя ПРИВЯЗАН к отправителю (sealed-sender.md, 9.2):
    //   senderKeyId = base64( SHA-256( "nyxo-skid-v1" ‖ u32be(roomId) ‖ u32be(senderId) ‖ signingPublicKey[32] )[0..16] )
    // Вход — 52 байта: метка (12 байт, без нулевого) и поля фиксированной длины.
    // Формат значения тот же, что у прежнего случайного идентификатора (16 байт в
    // каноническом base64). Занять чужой идентификатор нельзя: для этого нужен
    // прообраз SHA-256 по 128 битам, а не просто знание чужих keyId и открытого
    // ключа из конвертов. Поэтому на один keyId в комнате приходится ровно один
    // отправитель, и индекс отправителей (skIndex) не знает «кандидатов».
    const SKID_LABEL = utf8encode('nyxo-skid-v1');

    async function deriveSenderKeyId(roomId, senderId, signingPublicKey) {
        const room = Number(roomId);
        const sender = Number(senderId);
        const pub = typeof signingPublicKey === 'string' ? decodeFixed(signingPublicKey, 32) : null;
        if (!isU32(room) || !isU32(sender) || !pub) throw new TypeError('E2EE: не из чего вывести идентификатор ключа отправителя');
        const digest = new Uint8Array(await subtle.digest('SHA-256', concatBytes(SKID_LABEL, u32be(room), u32be(sender), pub)));
        return b64encode(digest.subarray(0, 16));
    }

    // Конверт key-share v2: { v:2, type:'skdm', n, iv, ct, init:{...} }.
    // Заголовок PQXDH (init) повторяется в каждой передаче сессии: получатель
    // узнаёт сессию по эфемерному ключу, а если первая передача потерялась
    // (или была отложена до подтверждения смены identity) — выводит её из
    // заголовка любой следующей.
    function parseShareEnvelope(ciphertext) {
        let env;
        try { env = JSON.parse(ciphertext); } catch { return null; }
        if (!env || typeof env !== 'object' || env.v !== 2 || env.type !== 'skdm') return null;
        if (!Number.isSafeInteger(env.n) || env.n < 0) return null;
        const iv = decodeFixed(env.iv, 12);
        const ct = typeof env.ct === 'string' ? b64decode(env.ct) : null;
        if (!iv || !ct || ct.length < 16) return null;
        const h = env.init;
        if (!h || typeof h !== 'object') return null;
        const signPub = canonicalSigningKey(h.senderIdentitySignPub);
        const dhPub = canonicalPubKey(h.senderIdentityDhPub);
        const eph = canonicalPubKey(h.senderEphemeralPub);
        const opkId = h.usedOneTimePrekeyId === null || h.usedOneTimePrekeyId === undefined ? null : h.usedOneTimePrekeyId;
        // Без PQ-части заголовок не принимается вовсе: иначе сервер мог бы
        // "понизить" обмен до классического X3DH.
        const pqCt = decodeFixed(h.pqCiphertext, PQ_CIPHERTEXT_BYTES);
        if (!signPub || !dhPub || !eph || !pqCt) return null;
        if (!isKeyId(h.usedSignedPrekeyId) || !isKeyId(h.usedPqPrekeyId) || (opkId !== null && !isKeyId(opkId))) return null;
        // pqOneTime: true — usedPqPrekeyId указывает на одноразовый PQ-prekey
        // (pqopk:<id>), иначе на запасной (pqpk). Поле в заголовок не
        // подписано, но подмена безвредна: с ключом не той роли общий секрет
        // ML-KEM не сойдётся (implicit rejection) и AEAD отвергнет share.
        const pqOneTime = h.pqOneTime === true;
        return {
            n: env.n, iv, ct,
            init: { signPub, dhPub, eph, spkId: h.usedSignedPrekeyId, opkId, pqId: h.usedPqPrekeyId, pqOneTime, pqCt },
        };
    }

    // Поле ext в SKDM (roadmap R9): расширяемый словарь внутри AEAD key-share,
    // то есть под защитой попарного канала. Сегодня в нём одно известное поле:
    //   prev: { id, final } — прежний ключ отправителя в этой комнате и последняя
    //                         использованная им итерация (5.2). Получатель
    //                         выводит оставшиеся ключи до final и стирает chainKey
    //                         старой цепочки. Дальше сюда лягут view (5.4) и голова
    //                         журнала ключей (5.6).
    // Правила разбора: известное поле обязано быть корректным, иначе SKDM
    // отвергается целиком (испорченный ext — признак сбоя или подделки, молча
    // принять половину нельзя); неизвестные поля игнорируются и наружу не
    // отдаются, чтобы будущая версия могла добавлять поля, а старая — работать.
    const MAX_EXT_CHARS = 2048;

    // kt: { g, e, h, s } — последняя проверенная подписанная голова журнала отправителя (7.5):
    // поколение, эпоха, голова (32 байта) и подпись (64 байта) в base64. Строгий разбор — null при порче.
    function parseKtGossip(raw) {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        const isU32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xFFFFFFFF;
        if (!isU32(raw.g) || raw.g < 1 || !isU32(raw.e)) return null;
        if (!decodeFixed(raw.h, 32) || !decodeFixed(raw.s, 64)) return null;
        return { g: raw.g, e: raw.e, h: raw.h, s: raw.s };
    }

    function parseSkdmExt(raw) {
        if (raw === undefined) return {};
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        let json;
        try { json = JSON.stringify(raw); } catch { return null; }
        // kt и view - справочные подсказки, а не условие ключа: при порче или превышении предела ext эти поля
        // отбрасываются с предупреждением, SKDM принимается (строго разбирается только prev).
        let hintsDropped = false;
        if (json.length > MAX_EXT_CHARS) {
            const { kt: ignoredKt, view: ignoredView, ...rest } = raw;
            let restJson;
            try { restJson = JSON.stringify(rest); } catch { return null; }
            if (restJson.length > MAX_EXT_CHARS || (raw.kt === undefined && raw.view === undefined)) return null;
            hintsDropped = true;
        }
        const ext = {};
        if (raw.kt !== undefined) {
            const kt = hintsDropped ? null : parseKtGossip(raw.kt);
            if (kt) ext.kt = kt;
            else console.warn('E2EE: поле kt в SKDM испорчено или не помещается в ext и отброшено');
        }
        if (raw.view !== undefined) {
            const view = hintsDropped || !membershipModules ? null : membershipModules.client.parseViewField(raw.view);
            if (view) ext.view = view;
            else console.warn('E2EE: поле view в SKDM испорчено или не помещается в ext и отброшено');
        }
        if (raw.prev !== undefined) {
            const prev = raw.prev;
            if (!prev || typeof prev !== 'object' || Array.isArray(prev)) return null;
            if (!isCanonicalKeyId(prev.id)) return null;
            if (!Number.isInteger(prev.final) || prev.final < 0 || prev.final > 0xFFFFFFFF) return null;
            ext.prev = { id: prev.id, final: prev.final };
        }
        return ext;
    }

    function parseSkdm(pt, roomId) {
        let skdm;
        try { skdm = JSON.parse(utf8decode(pt)); } catch { return null; }
        if (!skdm || skdm.v !== 2 || skdm.type !== 'skdm' || Number(skdm.roomId) !== Number(roomId)) return null;
        if (!isCanonicalKeyId(skdm.senderKeyId)) return null;
        if (!decodeFixed(skdm.chainKey, 32)) return null;
        if (!Number.isInteger(skdm.iteration) || skdm.iteration < 0 || skdm.iteration > 0xFFFFFFFF) return null;
        const signingPublicKey = canonicalSigningKey(skdm.signingPublicKey);
        if (!signingPublicKey) return null;
        const ext = parseSkdmExt(skdm.ext);
        if (!ext) return null;
        return {
            senderKeyId: skdm.senderKeyId,
            chainKey: skdm.chainKey,
            iteration: skdm.iteration,
            signingPublicKey,
            ext,
        };
    }

    // SKDM к отправке. ext пишется только когда в нём есть поля: ключ без
    // истории (первый в комнате) уходит ровно в прежнем виде.
    function buildSkdm(roomId, key, ext) {
        const skdm = {
            v: 2, type: 'skdm', roomId,
            senderKeyId: key.senderKeyId,
            chainKey: key.chainKey,
            iteration: key.iteration,
            signingPublicKey: key.signingPublicKey,
        };
        if (ext && Object.keys(ext).length > 0) skdm.ext = ext;
        return skdm;
    }

    // ---- Записи ключей: индекс архива, часы вывода ----

    const hourOf = (t) => Math.floor(t / HOUR_MS);
    const archiveEntryId = (entry) => (typeof entry === 'string' ? entry : entry && entry.id);
    const archiveHas = (state, keyId) => (state.archive || []).some(entry => archiveEntryId(entry) === keyId);

    // Почему нет ключа сообщения, которое ниже позиции цепочки (раздел 5 и 6
    // плана криптографии): удалено режимом «не хранить историю», удалено по
    // сроку или бюджету, либо ключа не было вовсе (цепочка началась позже).
    function missingKeyReason(rec, iteration) {
        if (iteration < (rec.forgottenBelow || 0)) return 'history-not-kept';
        if (iteration < (rec.expiredBelow || 0)) return 'key-expired';
        return 'no-message-key';
    }

    // Политика комнаты на устройстве (roomPolicy:<комната>): режим истории и
    // срок исчезающих сообщений. Любой мусор в записи сводится к значениям по умолчанию.
    function normalizePolicy(raw) {
        const p = raw && typeof raw === 'object' ? raw : {};
        return {
            historyMode: p.historyMode === 'none' ? 'none' : 'keep',
            expirySeconds: Number.isSafeInteger(p.expirySeconds) && p.expirySeconds > 0 ? p.expirySeconds : null,
            updatedAt: Number.isFinite(p.updatedAt) ? p.updatedAt : 0,
        };
    }

    function normalizeIds(list) {
        const out = [];
        for (const v of Array.isArray(list) ? list : []) {
            const id = Number(v);
            if (Number.isSafeInteger(id) && id > 0 && !out.includes(id)) out.push(id);
        }
        return out;
    }

    function normalizeParticipants(list) {
        const out = [];
        const seen = new Set();
        for (const p of Array.isArray(list) ? list : []) {
            const id = Number(p && p.id);
            if (!Number.isSafeInteger(id) || id <= 0 || seen.has(id)) continue;
            seen.add(id);
            out.push({ id, username: p && typeof p.username === 'string' ? p.username : '' });
        }
        return out;
    }

    // Ключа собеседника нет в журнале (mismatch) — отдельный статус, пока код безопасности не сверен
    // (markPeerVerified) и пользователь не продолжил явно (overrideLogMismatch). pending журнала статус
    // не меняет: это «ключ ждёт подтверждения», а не нарушение.
    function logExcluded(pin) {
        return Boolean(pin && pin.kt && pin.kt.status === 'mismatch' && !pin.verified && !pin.kt.override);
    }

    function identityStatus(pin) {
        if (!pin) return 'unknown';
        if (pin.pending) return 'changed';
        if (logExcluded(pin)) return 'log-mismatch';
        return pin.verified ? 'verified' : 'unverified';
    }

    // ===================== Клиент =====================

    // Параметры (кроме storage все необязательны):
    //   storage   — хранилище ключей устройства (MemoryStorage, makeIndexedDbStorage);
    //   transport — обмен с сервером ключей (по умолчанию makeFetchTransport());
    //   kem       — реализация ML-KEM (по умолчанию public/mlkem.js);
    //   userId    — id пользователя (можно задать позже через setUserId);
    //   now       — часы: () => миллисекунды (по умолчанию Date.now). По ним
    //               считаются ротация prekey и возраст сессий, а подмена часов
    //               позволяет тестам проверять сроки в 7 и 14 дней;
    //   lock      — внешняя блокировка lock(fn) → Promise, см. withLock ниже.
    function createClient(options) {
        const storage = guardCalls(options.storage, storageFailure);
        const transport = guardCalls(options.transport || makeFetchTransport(), transportFailure);
        // Часы внедряются ради тестов ротации prekey (7/14 дней).
        const now = typeof options.now === 'function' ? options.now : () => Date.now();
        let kem = options.kem || null;
        let userId = options.userId || null;

        function getKem() {
            if (!kem) kem = resolveDefaultKem();
            return kem;
        }

        // Все изменения состояния в хранилище идут строго по очереди: иначе
        // два параллельных вызова (открытие чата + отправка, синхронизация
        // ключей + расшифровка истории) читали одно состояние и затирали
        // изменения друг друга — например, ротацию Sender Key собеседника
        // перезаписывало продвижение его старой цепочки. Сетевые запросы по
        // возможности делаются вне очереди, чтобы не тормозить расшифровку.
        // Функции *Locked вызываются только изнутри withLock.
        //
        // Внешняя блокировка options.lock нужна, когда одно хранилище делят
        // несколько клиентов, — например, две вкладки одного пользователя
        // пишут в одну IndexedDB (Web Locks). Это функция lock(fn) → Promise:
        // она выполняет fn эксклюзивно и возвращает его результат. Очередь
        // клиента остаётся снаружи: свои секции идут строго по порядку вызова,
        // а к внешней блокировке клиент обращается не более чем за одной
        // секцией сразу. Без lock работает одна внутренняя очередь, как раньше.
        const externalLock = typeof options.lock === 'function' ? options.lock : null;
        let lockTail = Promise.resolve();
        function withLock(fn) {
            const run = lockTail.then(() => (externalLock ? externalLock(fn) : fn()));
            lockTail = run.then(() => undefined, () => undefined);
            return run;
        }

        // Журнал ключей: состояние и проверки — в public/lib/kt-client.js. Сеть вне withLock; в блокировке
        // клиент журнала только ставит задачи (kt:queue) и пишет результаты (7.6).
        const ktModule = resolveKtClient();
        const ktLog = ktModule ? ktModule.createLogClient({
            storage, transport, withLock, now,
            getUserId: () => userId,
            getIdentity: async () => {
                const identity = await storage.get('identity');
                return identity ? { signPub: identity.signPub, dhPub: identity.dhPub, createdHour: identity.createdHour } : null;
            },
            onAlert: options.onTransparencyAlert,
            manifestKey: options.ktManifestKey,
            genEpochs: options.ktGenEpochs,
            graceEpochs: options.ktGraceEpochs,
            epochSeconds: options.ktEpochSeconds,
            schedule: options.ktSchedule,
        }) : null;
        const ktOn = () => Boolean(ktLog) && ktLog.supported();

        // Подписанный состав группы (public/lib/membership-client.js): состояние V, removed, joinIntent, журнал доставок,
        // проверка сертификатов. Сеть вне withLock; в блокировке клиент состава только читает и пишет хранилище.
        if (!membershipModules) throw new E2eeError('unsupported', 'E2EE: модуль состава группы (membership.js) не загружен');
        const Membership = membershipModules.lib;
        const membership = membershipModules.client.createMembershipClient({
            storage, transport, withLock, now,
            getUserId: () => userId,
            loadIdentityLocked,
            sign,
            logExcluded,
            checkPeers: (ids) => checkPeersWithServer(ids),
        });

        // Мои ключи для проверок состава (в блокировке не вызывать: берёт её сама).
        async function myKeys() {
            return withLock(async () => {
                const identity = await loadIdentityLocked();
                return { id: Number(userId), signPub: b64decode(identity.signPub), dhPub: b64decode(identity.dhPub) };
            });
        }

        // Проверки журнала с пределом ожидания: ответ сервера не должен задерживать отправку.
        async function runKtChecksBounded() {
            if (!ktOn()) return;
            let timer = null;
            try {
                await Promise.race([
                    ktLog.runKtChecks(),
                    new Promise((resolve) => { timer = setTimeout(resolve, KT_WAIT_MS); if (timer.unref) timer.unref(); }),
                ]);
            } catch (err) {
                console.warn('E2EE: проверка журнала ключей не удалась:', err);
            } finally {
                if (timer) clearTimeout(timer);
            }
        }

        async function nextKeyId() {
            const cur = (await storage.get('nextKeyId')) || Math.floor(now() / 1000);
            await storage.set('nextKeyId', cur + 1);
            return cur;
        }

        // ---- Ключи устройства (с ленивой миграцией JWK → CryptoKey) ----

        async function loadIdentityLocked() {
            const identity = await storage.get('identity');
            if (!identity) return null;
            if (!isCryptoKey(identity.dhPriv) || !isCryptoKey(identity.signPriv)) {
                identity.dhPriv = await toPrivateKey(identity.dhPriv, 'X25519', ['deriveBits']);
                identity.signPriv = await toPrivateKey(identity.signPriv, 'Ed25519', ['sign']);
                await storage.set('identity', identity);
            }
            return identity;
        }

        async function loadOrCreateIdentityLocked() {
            let identity = await loadIdentityLocked();
            if (identity) return identity;
            const dhKp = await generateX25519();
            const signKp = await generateEd25519();
            identity = {
                dhPub: b64encode(dhKp.pub), dhPriv: dhKp.priv,
                signPub: b64encode(signKp.pub), signPriv: signKp.priv,
                // Час создания (с точностью до часа, только на устройстве): диалог «чужое обязательство в
                // журнале» показывает, что старше этого момента, — вероятно прежние ключи аккаунта (7.4).
                createdHour: hourOf(now()),
            };
            await storage.set('identity', identity);
            return identity;
        }

        async function loadSpkLocked() {
            const spk = await storage.get('spk');
            if (!spk) return null;
            if (!isCryptoKey(spk.priv)) {
                spk.priv = await toPrivateKey(spk.priv, 'X25519', ['deriveBits']);
                // У ключа прежней версии нет даты создания: считаем его
                // давно просроченным, init() сразу его ротирует.
                if (typeof spk.createdAt !== 'number') spk.createdAt = 0;
                await storage.set('spk', spk);
            }
            return spk;
        }

        async function loadOpkLocked(keyId) {
            const name = 'opk:' + keyId;
            const opk = await storage.get(name);
            if (!opk) return null;
            if (!isCryptoKey(opk.priv)) {
                opk.priv = await toPrivateKey(opk.priv, 'X25519', ['deriveBits']);
                await storage.set(name, opk);
            }
            return opk;
        }

        // ---- Sender Key: записи хранилища (план криптографии, раздел 5) ----
        //
        //   senderKey:<комната>:<отправитель> — ТЕКУЩИЙ ключ отправителя:
        //     { senderKeyId, signingPublicKey, [signingPrivateKey у своего], chainKey,
        //       nextIteration, startIteration (с какой итерации у нас есть цепочка),
        //       cachedKeys { итерация: ключ }, keyTimes { итерация: часовой индекс вывода },
        //       createdAt, installedBy { eph, n } (у чужого), expiredBelow?, forgottenBelow?,
        //       archive [ { id, archivedAt, final } …, затем «надгробия» — просто id ] }
        //   skArchive:<комната>:<отправитель>:<senderKeyId> — по записи на каждый
        //     старый ключ: { signingPublicKey, cachedKeys, keyTimes, startIteration,
        //     [chainKey, nextIteration — пока цепочка чужого ключа не закрыта], final,
        //     archivedAt }. Архив не раздувает основную запись, которую клиент
        //     переписывает на каждое сообщение, а нужный старый ключ читается
        //     одним обращением по senderKeyId из конверта.
        //   seen:<комната>:<отправитель>:<senderKeyId> — таблица повторов, живёт
        //     и умирает вместе со своим ключом.
        //   roomPolicy:<комната> — { historyMode, expirySeconds, updatedAt }.

        const stateName = (roomId, senderId) => 'senderKey:' + roomId + ':' + senderId;
        const archiveName = (roomId, senderId, keyId) => 'skArchive:' + roomId + ':' + senderId + ':' + keyId;
        const seenName = (roomId, senderId, keyId) => 'seen:' + roomId + ':' + senderId + ':' + keyId;
        const archivePrefix = (roomId) => 'skArchive:' + roomId + ':';
        // Индекс отправителей (sealed-sender.md, 9.2): keyId → отправитель. В строке
        // сообщения комнаты автора нет, автора находит клиент по keyId из конверта.
        //   skIndex:<комната>:<senderKeyId> = { v:1, sender }              — ключ есть
        //   skIndex:<комната>:<senderKeyId> = { v:1, sender, gone:true }   — ключ удалён намеренно
        // Надгробие нужно, чтобы удалённый ключ давал причину 'key-expired' /
        // 'history-not-kept', а не 'no-sender-key' (иначе интерфейс счёл бы ключ
        // потерянным и слал лишние запросы ключа). Флаг unverifiedSender в индексе
        // НЕ хранится: он считается при каждой расшифровке по текущему составу.
        const skIndexName = (roomId, keyId) => 'skIndex:' + roomId + ':' + keyId;
        const skIndexPrefix = (roomId) => 'skIndex:' + roomId + ':';

        function ownKeyName(roomId) {
            return stateName(roomId, userId);
        }

        async function readIndexLocked(roomId, keyId) {
            const entry = await storage.get(skIndexName(roomId, keyId));
            if (!entry || typeof entry !== 'object' || entry.v !== 1) return null;
            const sender = Number(entry.sender);
            if (!Number.isSafeInteger(sender) || sender <= 0) return null;
            return entry.gone === true ? { sender, gone: true } : { sender, gone: false };
        }

        // Записывает отправителя ключа. Повтор идемпотентен и надгробие обратно в
        // «ключ есть» не превращает. false — для этого keyId уже записан ДРУГОЙ
        // отправитель (возможно только при коллизии SHA-256 по 128 битам): запись
        // не меняется, вызывающий отвергает SKDM.
        async function writeIndexLocked(roomId, keyId, senderId) {
            const sender = Number(senderId);
            const current = await readIndexLocked(roomId, keyId);
            if (current) return current.sender === sender;
            await storage.set(skIndexName(roomId, keyId), { v: 1, sender });
            return true;
        }

        // Ключ удалён намеренно (срок, бюджет, «Не хранить историю»): запись
        // становится надгробием. Записи, которой не было, надгробие не создаётся.
        async function tombstoneIndexLocked(roomId, keyId) {
            const current = await readIndexLocked(roomId, keyId);
            if (!current || current.gone) return;
            await storage.set(skIndexName(roomId, keyId), { v: 1, sender: current.sender, gone: true });
        }

        // Читает текущий ключ отправителя и доводит запись до нынешнего формата:
        // поля, которых не было у прежних версий, и встроенный archived: […]
        // (по записи на старый ключ в skArchive:…). Правка сохраняется сразу.
        async function readStateLocked(roomId, senderId) {
            const name = stateName(roomId, senderId);
            const state = await storage.get(name);
            if (!state) return null;
            if (await upgradeStateLocked(roomId, senderId, state)) await storage.set(name, state);
            return state;
        }

        async function upgradeStateLocked(roomId, senderId, state) {
            let changed = false;
            const hour = hourOf(now());
            if (!state.cachedKeys || typeof state.cachedKeys !== 'object') { state.cachedKeys = {}; changed = true; }
            if (!state.keyTimes || typeof state.keyTimes !== 'object') {
                // Время вывода прежних ключей неизвестно: считаем его нынешним —
                // таймер комнаты удалит их не раньше срока от сегодняшнего дня.
                state.keyTimes = {};
                for (const it of Object.keys(state.cachedKeys)) state.keyTimes[it] = hour;
                changed = true;
            }
            if (!Number.isInteger(state.startIteration)) {
                let lowest = Infinity;
                for (const it of Object.keys(state.cachedKeys)) lowest = Math.min(lowest, Number(it));
                state.startIteration = lowest === Infinity ? (Number.isInteger(state.nextIteration) ? state.nextIteration : 0) : lowest;
                changed = true;
            }
            if (!Array.isArray(state.archive)) { state.archive = []; changed = true; }
            if (Array.isArray(state.archived)) {
                // Встроенный архив прежней версии раскладывается по записям.
                // Записи пишутся до правки основной: оборвавшаяся миграция
                // повторится и перепишет те же записи.
                const migrated = [];
                for (const old of state.archived) {
                    if (!old || !isCanonicalKeyId(old.senderKeyId) || archiveHas({ archive: migrated }, old.senderKeyId)) continue;
                    const cachedKeys = old.cachedKeys && typeof old.cachedKeys === 'object' ? old.cachedKeys : {};
                    const keyTimes = {};
                    for (const it of Object.keys(cachedKeys)) keyTimes[it] = hour;
                    let lowest = Infinity;
                    for (const it of Object.keys(cachedKeys)) lowest = Math.min(lowest, Number(it));
                    const rec = {
                        signingPublicKey: old.signingPublicKey,
                        cachedKeys, keyTimes,
                        startIteration: lowest === Infinity ? 0 : lowest,
                        final: null,
                        archivedAt: now(),
                    };
                    if (old.chainKey && Number.isInteger(old.nextIteration)) {
                        rec.chainKey = old.chainKey;
                        rec.nextIteration = old.nextIteration;
                    }
                    await storage.set(archiveName(roomId, senderId, old.senderKeyId), rec);
                    migrated.push({ id: old.senderKeyId, archivedAt: rec.archivedAt, final: null });
                }
                state.archive = migrated.concat(state.archive.filter(entry => !archiveHas({ archive: migrated }, archiveEntryId(entry))));
                delete state.archived;
                await dropArchivesLocked(roomId, senderId, await trimArchiveIndex(roomId, senderId, state));
                changed = true;
            }
            return changed;
        }

        async function loadOwnSenderKeyLocked(roomId) {
            const name = ownKeyName(roomId);
            const state = await readStateLocked(roomId, userId);
            if (!state) return null;
            if (state.signingPrivateKey && !isCryptoKey(state.signingPrivateKey)) {
                state.signingPrivateKey = await toPrivateKey(state.signingPrivateKey, 'Ed25519', ['sign']);
                await storage.set(name, state);
            }
            return state;
        }

        // Сжимает индекс архива: подробные записи только у последних
        // MAX_ARCHIVE_INDEX архивов, у более старых остаётся id («надгробие»),
        // самые старые надгробия забываются; вместе с забытым надгробием
        // исчезает и запись индекса отправителей (дальше 'no-sender-key', как для
        // ключа, которого устройство никогда не видело). Возвращает id архивов,
        // чьи записи теперь надо удалить (dropArchivesLocked).
        async function trimArchiveIndex(roomId, senderId, state) {
            const list = state.archive;
            const evicted = [];
            let detailed = 0;
            for (let i = 0; i < list.length; i++) {
                if (typeof list[i] === 'string') continue;
                if (++detailed > MAX_ARCHIVE_INDEX) {
                    evicted.push(list[i].id);
                    list[i] = list[i].id;
                }
            }
            if (list.length > MAX_ARCHIVE_INDEX + MAX_ARCHIVE_TOMBSTONES) {
                const forgotten = list.splice(MAX_ARCHIVE_INDEX + MAX_ARCHIVE_TOMBSTONES);
                for (const entry of forgotten) {
                    const id = archiveEntryId(entry);
                    if (id) await storage.delete(skIndexName(roomId, id));
                }
            }
            return evicted;
        }

        // Удаляет записи архива и их таблицы повторов, а запись индекса
        // отправителей превращает в надгробие. В индексе архива (state.archive)
        // эти id остаются надгробиями — меняет его вызывающий.
        async function dropArchivesLocked(roomId, senderId, keyIds) {
            for (const id of keyIds) {
                await storage.delete(archiveName(roomId, senderId, id));
                await storage.delete(seenName(roomId, senderId, id));
                await tombstoneIndexLocked(roomId, id);
            }
        }

        // Переносит ключ, вытесненный ротацией, в отдельную запись архива и
        // дописывает его в индекс state.archive (основную запись потом сохраняет
        // вызывающий). Возвращает id архивов, вытесненных из индекса.
        //   * Свой ключ (own): все ключи сообщений уже в cachedKeys, а цепочка
        //     дальше не нужна, поэтому final = последняя использованная итерация.
        //   * Чужой ключ: сохраняется позиция цепочки (chainKey), и сообщения,
        //     отправленные до ротации, но ещё не открытые, останутся читаемыми.
        //     Если отправитель сообщил final (prev в SKDM), цепочка сразу
        //     закрывается: оставшиеся ключи выводятся и кэшируются, chainKey
        //     стирается. Без final chainKey живёт ARCHIVE_CHAIN_MAX_AGE_MS
        //     (maintainRoomKeysLocked).
        // Подписывающий приватный ключ в архив не попадает.
        async function moveToArchiveLocked(roomId, senderId, state, { own = false, final = null } = {}) {
            const t = now();
            const rec = {
                signingPublicKey: state.signingPublicKey,
                cachedKeys: state.cachedKeys || {},
                keyTimes: state.keyTimes || {},
                startIteration: Number.isInteger(state.startIteration) ? state.startIteration : 0,
                final: null,
                archivedAt: t,
            };
            if (state.expiredBelow) rec.expiredBelow = state.expiredBelow;
            if (state.forgottenBelow) rec.forgottenBelow = state.forgottenBelow;
            if (own) {
                rec.final = (Number.isInteger(state.nextIteration) ? state.nextIteration : 0) - 1;
            } else if (state.chainKey && Number.isInteger(state.nextIteration)) {
                rec.chainKey = state.chainKey;
                rec.nextIteration = state.nextIteration;
                if (final !== null) await closeChain(rec, final, hourOf(t));
            }
            await storage.set(archiveName(roomId, senderId, state.senderKeyId), rec);
            if (!Array.isArray(state.archive)) state.archive = [];
            state.archive.unshift({ id: state.senderKeyId, archivedAt: t, final: rec.final });
            return trimArchiveIndex(roomId, senderId, state);
        }

        // ---- Политика комнаты на устройстве и хранение ключей ----

        async function readPolicyLocked(roomId) {
            return normalizePolicy(await storage.get('roomPolicy:' + roomId));
        }

        // Почему ключа архивного сообщения нет, хотя id в индексе остался: режим
        // «Не хранить историю» (сейчас включён или уже срабатывал на этом ключе
        // отправителя) либо срок и бюджет хранения.
        async function goneKeyReasonLocked(roomId, state) {
            if (state && state.forgottenBelow > 0) return 'history-not-kept';
            return (await readPolicyLocked(roomId)).historyMode === 'none' ? 'history-not-kept' : 'key-expired';
        }

        // В индексе архива запись превращается в надгробие (просто id): ключ
        // удалён, но заменённый ротацией ключ обратно уже не поставить.
        function tombstoneArchive(state, keyId) {
            const list = state.archive || [];
            const i = list.findIndex(entry => archiveEntryId(entry) === keyId);
            if (i >= 0 && typeof list[i] !== 'string') list[i] = keyId;
        }

        // Убирает из таблицы повторов итерации ниже границы: их ключи удалены, а
        // повторно показать такое сообщение всё равно нечем.
        async function pruneSeenLocked(roomId, senderId, keyId, boundary) {
            const name = seenName(roomId, senderId, keyId);
            const seen = await storage.get(name);
            if (!seen) return;
            let changed = false;
            for (const it of Object.keys(seen)) {
                if (Number(it) < boundary) { delete seen[it]; changed = true; }
            }
            if (!changed) return;
            if (Object.keys(seen).length === 0) await storage.delete(name);
            else await storage.set(name, seen);
        }

        // Хранение ключей комнаты (раздел 5 плана): вызывается при открытии
        // комнаты, после пачек расшифровки и раз в час (script.js).
        //   1. Таймер комнаты T (roomPolicy.expirySeconds): удаляются ключи,
        //      выведенные раньше, чем T + 1 час назад, и архивы старше этого
        //      срока вместе с таблицами повторов. keyTimes — ЛОКАЛЬНОЕ время
        //      вывода ключа, а не created_at от сервера: сервер влияет на
        //      удаление только значением таймера.
        //   2. Цепочка архивного чужого ключа без prev.final живёт не дольше
        //      ARCHIVE_CHAIN_MAX_AGE_MS после архивации.
        //   3. Бюджет MAX_KEYS_PER_ROOM ключей на комнату: сначала удаляются
        //      самые старые архивы, затем самые старые ключи самой большой
        //      цепочки. Расшифровка удалённого — 'key-expired'.
        // Свой архив подчиняется тем же правилам. Возвращает счётчики для тестов.
        async function maintainRoomKeysLocked(roomId) {
            const t = now();
            const policy = await readPolicyLocked(roomId);
            const cutoff = policy.expirySeconds ? t - policy.expirySeconds * 1000 - KEY_EXPIRY_GRACE_MS : null;
            const cutoffHour = cutoff === null ? null : hourOf(cutoff);
            const tooOld = (rec) => (it) => cutoffHour !== null && Number.isInteger(rec.keyTimes && rec.keyTimes[it]) && rec.keyTimes[it] < cutoffHour;
            const stats = { expiredKeys: 0, removedArchives: 0 };

            const states = new Map();   // отправитель → текущая запись
            for (const name of await storage.keys('senderKey:' + roomId + ':')) {
                const parts = name.split(':');
                if (parts.length !== 3) continue;
                const senderId = Number(parts[2]);
                const state = await readStateLocked(roomId, senderId);
                if (state) states.set(senderId, state);
            }
            const dirty = new Set();    // отправители с изменённой основной записью

            if (cutoffHour !== null) {
                for (const [senderId, state] of states) {
                    const dropped = dropKeys(state, tooOld(state));
                    if (dropped === 0) continue;
                    stats.expiredKeys += dropped;
                    dirty.add(senderId);
                    await pruneSeenLocked(roomId, senderId, state.senderKeyId, state.expiredBelow);
                }
            }

            const removeArchive = async (senderId, keyId) => {
                await dropArchivesLocked(roomId, senderId, [keyId]);
                const owner = states.get(senderId);
                if (owner) { tombstoneArchive(owner, keyId); dirty.add(senderId); }
                stats.removedArchives++;
            };

            const archives = [];
            for (const name of await storage.keys(archivePrefix(roomId))) {
                const parts = name.split(':');
                if (parts.length !== 4) continue;
                const senderId = Number(parts[2]);
                const keyId = parts[3];
                const rec = await storage.get(name);
                if (!rec) continue;
                // Архив без текущей записи отправителя недостижим (расшифровка
                // начинается с неё), а ключевой материал на диске не нужен.
                if (!states.has(senderId)) { await removeArchive(senderId, keyId); continue; }
                if (cutoff !== null && rec.archivedAt < cutoff) { await removeArchive(senderId, keyId); continue; }
                let changed = false;
                const dropped = dropKeys(rec, tooOld(rec));
                if (dropped > 0) {
                    stats.expiredKeys += dropped;
                    changed = true;
                    await pruneSeenLocked(roomId, senderId, keyId, rec.expiredBelow);
                }
                if (rec.chainKey && (rec.final === null || rec.final === undefined) && t - rec.archivedAt >= ARCHIVE_CHAIN_MAX_AGE_MS) {
                    rec.final = (Number.isInteger(rec.nextIteration) ? rec.nextIteration : 0) - 1;
                    delete rec.chainKey;
                    changed = true;
                }
                if (changed) await storage.set(name, rec);
                archives.push({ senderId, keyId, archivedAt: rec.archivedAt, keys: Object.keys(rec.cachedKeys).length });
            }

            let total = archives.reduce((sum, a) => sum + a.keys, 0);
            for (const state of states.values()) total += Object.keys(state.cachedKeys).length;
            if (total > MAX_KEYS_PER_ROOM) {
                archives.sort((a, b) => a.archivedAt - b.archivedAt);
                while (total > MAX_KEYS_PER_ROOM && archives.length > 0) {
                    const oldest = archives.shift();
                    await removeArchive(oldest.senderId, oldest.keyId);
                    total -= oldest.keys;
                }
                // Одни текущие цепочки: режем самую большую с начала.
                const chains = Array.from(states.entries())
                    .map(([senderId, state]) => ({ senderId, state, keys: Object.keys(state.cachedKeys).length }))
                    .sort((a, b) => b.keys - a.keys);
                for (const chain of chains) {
                    if (total <= MAX_KEYS_PER_ROOM) break;
                    const cut = Math.min(chain.keys, total - MAX_KEYS_PER_ROOM);
                    const iterations = Object.keys(chain.state.cachedKeys).map(Number).sort((a, b) => a - b);
                    const boundary = cut >= iterations.length ? Infinity : iterations[cut];
                    const dropped = dropKeys(chain.state, it => it < boundary);
                    stats.expiredKeys += dropped;
                    total -= dropped;
                    if (dropped > 0) {
                        dirty.add(chain.senderId);
                        await pruneSeenLocked(roomId, chain.senderId, chain.state.senderKeyId, chain.state.expiredBelow);
                    }
                }
            }

            for (const senderId of dirty) await storage.set(stateName(roomId, senderId), states.get(senderId));

            // Служебные отметки запросов ключа: свой запрос живёт столько же, сколько
            // строка на сервере, отметка об ответе владельца — не дольше часа.
            for (const name of await storage.keys('keyReq:' + roomId + ':')) {
                const at = await storage.get(name);
                if (!Number.isFinite(at) || t - at >= KEY_REQUEST_RETENTION_MS) await storage.delete(name);
            }
            for (const name of await storage.keys('keyServed:' + roomId + ':')) {
                const at = await storage.get(name);
                if (!Number.isFinite(at) || t - at >= HOUR_MS) await storage.delete(name);
            }
            return stats;
        }

        async function maintainRoomKeys(roomId) {
            await ensureLocal();
            return withLock(() => maintainRoomKeysLocked(roomId));
        }

        // Политика комнаты на этом устройстве (личная настройка, roadmap R9):
        //   expirySeconds — срок исчезающих сообщений комнаты в секундах или 0/null
        //     (нет срока): ключи удаляются вместе с сообщениями (maintainRoomKeysLocked);
        //   historyMode   — 'keep' (по умолчанию) или 'none' («Не хранить историю на
        //     устройстве», forgetRoomHistoryLocked).
        // Смена срока сразу применяется к ключам комнаты; включение 'none' сразу
        // забывает историю. Возврат в 'keep' удалённое не воскрешает.
        async function setRoomPolicy(roomId, patch) {
            if (!patch || typeof patch !== 'object') throw new TypeError('E2EE: setRoomPolicy ждёт объект с настройками');
            await ensureLocal();
            return withLock(async () => {
                const name = 'roomPolicy:' + roomId;
                const current = await readPolicyLocked(roomId);
                const next = Object.assign({}, current);
                if (patch.expirySeconds !== undefined) {
                    const seconds = patch.expirySeconds;
                    if (seconds === null || seconds === 0) next.expirySeconds = null;
                    else if (Number.isSafeInteger(seconds) && seconds > 0) next.expirySeconds = seconds;
                    else throw new TypeError('E2EE: expirySeconds — целое число секунд, 0 или null');
                }
                if (patch.historyMode !== undefined) {
                    if (patch.historyMode !== 'keep' && patch.historyMode !== 'none') {
                        throw new TypeError("E2EE: historyMode — 'keep' или 'none'");
                    }
                    next.historyMode = patch.historyMode;
                }
                const expiryChanged = next.expirySeconds !== current.expirySeconds;
                const modeChanged = next.historyMode !== current.historyMode;
                if (expiryChanged || modeChanged) {
                    next.updatedAt = now();
                    if (next.expirySeconds === null && next.historyMode === 'keep') await storage.delete(name);
                    else await storage.set(name, next);
                }
                // Настройка записана до удаления: оборванное забывание повторится при init().
                if (modeChanged && next.historyMode === 'none') await forgetRoomHistoryLocked(roomId);
                else if (expiryChanged) await maintainRoomKeysLocked(roomId);
                return next;
            });
        }

        // ---- «Не хранить историю на устройстве» (план криптографии, раздел 6) ----
        //
        // Режим 'none' — личная настройка этого устройства: другие участники и сервер
        // о ней не знают, их копии сообщений остаются. Что забывает
        // forgetRoomHistoryLocked: ключи сообщений всех отправителей комнаты (включая
        // свои), все записи архива, таблицы повторов seen, записи о версиях сообщений
        // edit:<комната>:*, отметки запросов ключа и, у своего ключа, chainKey0 —
        // иначе вся эпоха выводилась бы заново. Что остаётся: текущие chainKey и
        // nextIteration (они открывают только будущие сообщения), ключи подписи,
        // попарные сессии, закрепления identity, состав комнаты.
        // Предел честности: браузер не гарантирует затирание данных на диске до
        // уплотнения базы IndexedDB.
        async function forgetRoomHistoryLocked(roomId) {
            const forgotten = { senders: 0, archives: 0 };
            for (const name of await storage.keys('senderKey:' + roomId + ':')) {
                const parts = name.split(':');
                if (parts.length !== 3) continue;
                const senderId = Number(parts[2]);
                const state = await readStateLocked(roomId, senderId);
                if (!state) continue;
                const next = Number.isInteger(state.nextIteration) ? state.nextIteration : 0;
                state.forgottenBelow = Math.max(state.forgottenBelow || 0, next);
                state.cachedKeys = {};
                state.keyTimes = {};
                state.startIteration = next;
                delete state.expiredBelow;
                delete state.origin;
                // В индексе архива остаются только id: старый ключ обратно не поставить.
                state.archive = (state.archive || []).map(archiveEntryId).filter(Boolean);
                await storage.set(name, state);
                forgotten.senders++;
            }
            for (const name of await storage.keys(archivePrefix(roomId))) {
                const parts = name.split(':');
                if (parts.length === 4) await tombstoneIndexLocked(roomId, parts[3]);
                await storage.delete(name);
                forgotten.archives++;
            }
            for (const prefix of ['seen:' + roomId + ':', editPrefix(roomId), 'keyReq:' + roomId + ':', 'keyServed:' + roomId + ':']) {
                for (const name of await storage.keys(prefix)) await storage.delete(name);
            }
            // Карта имён участников живёт вместе с историей комнаты (sealed-sender.md, 9.5).
            await storage.delete('memberNames:' + roomId);
            editCounts.delete(roomId);
            return forgotten;
        }

        async function forgetRoomHistory(roomId) {
            await ensureLocal();
            return withLock(() => forgetRoomHistoryLocked(roomId));
        }

        // Все комнаты в режиме 'none': init() зовёт это на старте, на случай закрытой
        // или упавшей вкладки (событие закрытия не гарантировано).
        async function forgetAllNoHistoryRoomsLocked() {
            const rooms = [];
            for (const name of await storage.keys('roomPolicy:')) {
                const policy = normalizePolicy(await storage.get(name));
                if (policy.historyMode !== 'none') continue;
                const roomId = name.slice('roomPolicy:'.length);
                await forgetRoomHistoryLocked(roomId);
                rooms.push(roomId);
            }
            return rooms;
        }

        async function forgetAllNoHistoryRooms() {
            await ensureLocal();
            return withLock(forgetAllNoHistoryRoomsLocked);
        }

        async function setRoomHistoryMode(roomId, mode) {
            if (mode !== 'keep' && mode !== 'none') throw new TypeError("E2EE: режим истории — 'keep' или 'none'");
            const policy = await setRoomPolicy(roomId, { historyMode: mode });
            return policy.historyMode;
        }

        async function getRoomHistoryMode(roomId) {
            await ensureLocal();
            return withLock(async () => (await readPolicyLocked(roomId)).historyMode);
        }

        // Локальная очистка комнаты при выходе из неё (sealed-sender.md, 9.2): ключи
        // отправителей, архив, таблицы повторов, записи о версиях, ИНДЕКС
        // ОТПРАВИТЕЛЕЙ (вместе с надгробиями), отметки рассылки, запросы ключа,
        // состав и настройки комнаты. Попарные сессии с участниками не комнатные
        // и остаются. Вернувшийся в комнату начинает с чистого листа.
        async function forgetRoomLocked(roomId) {
            const prefixes = [
                'senderKey:' + roomId + ':', archivePrefix(roomId), 'seen:' + roomId + ':', skIndexPrefix(roomId),
                editPrefix(roomId), 'keyReq:' + roomId + ':', 'keyServed:' + roomId + ':', 'sharedWith2:' + roomId + ':',
            ];
            let removed = 0;
            for (const prefix of prefixes) {
                for (const name of await storage.keys(prefix)) { await storage.delete(name); removed++; }
            }
            for (const name of ['members:' + roomId, 'memberNames:' + roomId, 'roomPolicy:' + roomId]) {
                if ((await storage.get(name)) !== null) { await storage.delete(name); removed++; }
            }
            // Записи состава (signed-membership.md, 5.6): V, removed, очередь повторных допусков, намерение входа, журнал
            // доставок, секрет ссылки. Вернувшийся в комнату начинает заново: новый joinIntent и якорная проверка.
            removed += await membership.forgetRoomLocked(roomId);
            editCounts.delete(roomId);
            return { removed };
        }

        async function forgetRoom(roomId) {
            await ensureLocal();
            return withLock(() => forgetRoomLocked(roomId));
        }

        // Разовая миграция хранилища прежней версии: JWK → неизвлекаемые
        // CryptoKey, флаг загрузки → отдельные флаги по ключам, статичные
        // попарные секреты v1 удаляются (их заменяет цепочка v2, а лишний
        // ключевой материал на диске — лишний риск).
        async function migrateLegacyLocked() {
            if ((await storage.get('schema')) === SCHEMA_VERSION) return;
            const identity = await loadIdentityLocked();
            const spk = await loadSpkLocked();
            for (const name of await storage.keys('opk:')) {
                await loadOpkLocked(name.slice('opk:'.length));
            }
            for (const name of await storage.keys('senderKey:')) {
                const parts = name.split(':');
                if (parts.length === 3 && parts[2] === String(userId)) await loadOwnSenderKeyLocked(parts[1]);
            }
            if (await storage.get('uploaded')) {
                if (identity) await storage.set('up:identity', identity.signPub + ':' + identity.dhPub);
                if (spk) await storage.set('up:spk', spk.keyId);
                await storage.delete('uploaded');
            }
            for (const prefix of ['pairwiseSend:', 'pairwiseRecv:', 'sharedWith:']) {
                for (const name of await storage.keys(prefix)) await storage.delete(name);
            }
            await storage.set('schema', SCHEMA_VERSION);
        }

        let localReady = null;
        function ensureLocal() {
            if (!localReady) {
                localReady = withLock(async () => {
                    await migrateLegacyLocked();
                    await loadOrCreateIdentityLocked();
                });
                localReady.catch(() => { localReady = null; });
            }
            return localReady;
        }

        // Секретный ключ ML-KEM восстанавливается из 64-байтового seed
        // детерминированно; держим пару последних в памяти.
        const pqSecretCache = new Map();
        // cache: false — для одноразовых ключей: секретный ключ не должен
        // пережить декапсуляцию в памяти (вызывающий затирает его fill(0)).
        async function pqSecretKey(seedB64, { cache = true } = {}) {
            if (!cache) return (await getKem().keygen(b64decode(seedB64))).secretKey;
            let sk = pqSecretCache.get(seedB64);
            if (!sk) {
                sk = (await getKem().keygen(b64decode(seedB64))).secretKey;
                if (pqSecretCache.size >= 4) pqSecretCache.delete(pqSecretCache.keys().next().value);
                pqSecretCache.set(seedB64, sk);
            }
            return sk;
        }

        // Создание и ротация SPK и PQ-prekey. Старый приватный ключ уходит в
        // spkOld:/pqpkOld: и живёт ещё 14 дней — x3dh-init, собранные по
        // bundle до ротации, должны расшифроваться.
        async function maintainPrekeysLocked(identity) {
            const t = now();
            let spk = await loadSpkLocked();
            if (spk && t - spk.createdAt >= PREKEY_ROTATE_MS) {
                await storage.set('spkOld:' + spk.keyId, { keyId: spk.keyId, priv: spk.priv, retiredAt: t });
                spk = null;
            }
            if (!spk) {
                const kp = await generateX25519();
                const keyId = await nextKeyId();
                const sig = await sign(identity.signPriv, kp.pub);
                spk = { keyId, pub: b64encode(kp.pub), priv: kp.priv, sig: b64encode(sig), createdAt: t };
                await storage.set('spk', spk);
            }

            let pq = await storage.get('pqpk');
            if (pq && t - pq.createdAt >= PREKEY_ROTATE_MS) {
                await storage.set('pqpkOld:' + pq.keyId, { keyId: pq.keyId, seed: pq.seed, retiredAt: t });
                pq = null;
            }
            if (!pq) {
                const seed = randomBytes(PQ_SEED_BYTES);
                const { publicKey } = await getKem().keygen(seed);
                if (!publicKey || publicKey.length !== PQ_PUBLIC_KEY_BYTES) throw new E2eeError('protocol', 'E2EE: ML-KEM вернул ключ неверной длины');
                const keyId = await nextKeyId();
                const sig = await sign(identity.signPriv, publicKey);
                pq = { keyId, pub: b64encode(publicKey), seed: b64encode(seed), sig: b64encode(sig), createdAt: t };
                await storage.set('pqpk', pq);
            }

            for (const prefix of ['spkOld:', 'pqpkOld:']) {
                for (const name of await storage.keys(prefix)) {
                    const old = await storage.get(name);
                    if (!old || t - old.retiredAt > PREKEY_RETAIN_MS) await storage.delete(name);
                }
            }
        }

        // Отказ сервера ключей при публикации своих ключей. Код — по статусу:
        // 400 на собственные ключи и 2xx без success:true (или ответ не того вида)
        // — protocol; 5xx, 401, 403, 404 и остальное — server. Статус сохраняется.
        function keyServerError(what, res) {
            const known = Boolean(res) && typeof res === 'object' && typeof res.status === 'number';
            const status = known ? res.status : 0;
            const protocol = !known || status === 400 || (status >= 200 && status < 300);
            return new E2eeError(protocol ? 'protocol' : 'server', 'E2EE: не удалось зарегистрировать ' + what, known ? { status } : {});
        }

        async function putIdentity(identity) {
            const res = await transport.putIdentity({
                identity_signing_key: identity.signPub,
                identity_dh_key: identity.dhPub,
            });
            if (!res || !res.data || res.data.success !== true) {
                throw keyServerError('identity-ключи', res);
            }
            return res.data;
        }

        // 409 от key-server значит "identity не зарегистрирован" (например,
        // его база была очищена) — регистрируем заново и повторяем.
        async function putWithIdentityRetry(doPut, identity, what) {
            let res = await doPut();
            if (res && res.status === 409) {
                await putIdentity(identity);
                res = await doPut();
            }
            if (!res || !res.data || res.data.success !== true) {
                throw keyServerError(what, res);
            }
        }

        async function uploadKeysIfNeeded() {
            const { identity, spk, pq } = await withLock(async () => ({
                identity: await loadIdentityLocked(),
                spk: await storage.get('spk'),
                pq: await storage.get('pqpk'),
            }));
            const idTag = identity.signPub + ':' + identity.dhPub;
            let registration = null;
            if ((await storage.get('up:identity')) !== idTag) {
                // Новый identity (новая установка): ключи прошлой установки на
                // сервере бесполезны — их приватных частей больше нет. Особенно
                // OPK: сервер продолжал бы раздавать их инициаторам, и каждый
                // такой key-share был бы нерасшифровываем.
                if (typeof transport.deleteKeys === 'function') {
                    try { await transport.deleteKeys(); } catch { /* best effort */ }
                }
                registration = await putIdentity(identity);
                // Секретные части одноразовых ключей прошлой установки тоже
                // бесполезны (на сервере их публичные половины стёрты), а
                // лежать в хранилище им незачем. До записи up:identity: если
                // вкладку закроют посреди, следующий init повторит всё сначала.
                await withLock(wipeOneTimeSecretsLocked);
                await storage.set('up:identity', idTag);
                await storage.delete('up:spk');
                await storage.delete('up:pq');
            }
            // Регистрация в журнале ключей (key-transparency.md, 6.2): повторный PUT тех же ключей ничего не
            // меняет, а в ответе — nonce и SKT моих текущих ключей (их же регистрирует и identity, внесённая
            // до включения журнала). Раньше PUT шёл только при смене identity.
            if (ktOn()) {
                if (!registration) registration = await putIdentity(identity);
                await withLock(() => ktLog.noteOwnLocked(registration.kt));
            }
            if ((await storage.get('up:spk')) !== spk.keyId) {
                await putWithIdentityRetry(() => transport.putSignedPrekey({
                    key_id: spk.keyId, public_key: spk.pub, signature: spk.sig,
                }), identity, 'signed prekey');
                await storage.set('up:spk', spk.keyId);
            }
            if ((await storage.get('up:pq')) !== pq.keyId) {
                await putWithIdentityRetry(() => transport.putPqPrekey({
                    key_id: pq.keyId, public_key: pq.pub, signature: pq.sig,
                }), identity, 'PQ prekey');
                await storage.set('up:pq', pq.keyId);
            }
        }

        async function topUpOneTimePreKeysIfNeeded() {
            const countRes = await transport.getOneTimePrekeyCount();
            const count = countRes && countRes.data && typeof countRes.data.count === 'number' ? countRes.data.count : 0;
            if (count >= LOW_WATER_OPK) return;
            const keys = await withLock(async () => {
                const out = [];
                for (let i = 0; i < TOPUP_OPK - count; i++) {
                    const kp = await generateX25519();
                    const keyId = await nextKeyId();
                    await storage.set('opk:' + keyId, { pub: b64encode(kp.pub), priv: kp.priv });
                    out.push({ key_id: keyId, public_key: b64encode(kp.pub) });
                }
                return out;
            });
            if (keys.length > 0) await transport.postOneTimePrekeys({ keys });
        }

        // ---- Пул одноразовых PQ-prekey ----
        //
        // Секрет каждого ключа — 64-байтовое семя ML-KEM в
        // pqopk:<keyId> = { seed, createdAt, retiredAt? }; публичная часть и
        // подпись уходят на сервер, который отдаёт каждый ключ ровно одному
        // инициатору. После использования (commit() в openShareLocked) семя
        // удаляется. pqopk:refreshedAt — время последней замены пула целиком.
        // Все функции *Locked вызываются только внутри withLock.

        const PQ_OPK_REFRESHED = 'pqopk:refreshedAt';
        const PQ_OPK_NAME = /^pqopk:\d+$/;

        async function pqOneTimeNamesLocked() {
            return (await storage.keys('pqopk:')).filter(name => PQ_OPK_NAME.test(name));
        }

        // Секретные части классических и PQ одноразовых ключей (новая identity).
        async function wipeOneTimeSecretsLocked() {
            for (const prefix of ['opk:', 'pqopk:']) {
                for (const name of await storage.keys(prefix)) await storage.delete(name);
            }
        }

        // Семена, отставленные при замене пула, живут ещё PREKEY_RETAIN_MS:
        // key-share, собранные по bundle до замены, ещё могут прийти.
        async function prunePqOneTimeLocked(t) {
            for (const name of await pqOneTimeNamesLocked()) {
                const rec = await storage.get(name);
                if (!rec || (typeof rec.retiredAt === 'number' && t - rec.retiredAt > PREKEY_RETAIN_MS)) await storage.delete(name);
            }
        }

        // Создаёт n ключей и сразу сохраняет семена: если вкладку закроют
        // посреди загрузки, а сервер ключи успел принять, расшифровать share
        // по ним всё равно будет чем. Возвращает то, что уйдёт на сервер.
        async function generatePqOneTimeLocked(identity, n, t) {
            const out = [];
            for (let i = 0; i < n; i++) {
                const seed = randomBytes(PQ_SEED_BYTES);
                const { publicKey } = await getKem().keygen(seed);
                if (!publicKey || publicKey.length !== PQ_PUBLIC_KEY_BYTES) throw new Error('E2EE: ML-KEM вернул ключ неверной длины');
                const keyId = await nextKeyId();
                const sig = await sign(identity.signPriv, pqOneTimeSigInput(keyId, publicKey));
                await storage.set('pqopk:' + keyId, { seed: b64encode(seed), createdAt: t });
                out.push({ key_id: keyId, public_key: b64encode(publicKey), signature: b64encode(sig) });
            }
            return out;
        }

        // Загрузка пачками вне блокировки. Явный отказ сервера (success !==
        // true) — этих ключей у него нет, их семена удаляются (вместе с семенами
        // непринятых пачек). Сетевое исключение — семена остаются: сервер мог
        // принять пачку, а ответ потерялся.
        async function uploadPqOneTime(keys) {
            for (let i = 0; i < keys.length; i += PQ_OPK_BATCH) {
                const res = await transport.postPqOneTimePrekeys({ keys: keys.slice(i, i + PQ_OPK_BATCH) });
                if (!res || !res.data || res.data.success !== true) {
                    await withLock(async () => {
                        for (const key of keys.slice(i)) await storage.delete('pqopk:' + key.key_id);
                    });
                    throw keyServerError('одноразовые PQ-prekey', res);
                }
            }
        }

        async function maintainPqOneTime() {
            const t = now();
            // Локальная часть: убрать просроченные отставленные семена и
            // завести отметку времени пула (нет отметки — пул считается
            // созданным сейчас, иначе замена не наступила бы никогда).
            const refreshedAt = await withLock(async () => {
                await prunePqOneTimeLocked(t);
                const value = await storage.get(PQ_OPK_REFRESHED);
                if (typeof value === 'number') return value;
                await storage.set(PQ_OPK_REFRESHED, t);
                return t;
            });

            const countRes = await transport.getOneTimePrekeyCount();
            const data = countRes && countRes.data;
            // Сервер без пула (нет поля) — работаем с запасным ключом.
            if (!data || typeof data.pq_count !== 'number') return;
            let have = data.pq_count;

            // Замена раз в 30 дней: стереть пул на сервере, отставить старые
            // семена (они ещё пригодятся для уже собранных key-share), загрузить
            // новый пул. Так локальное хранилище ограничено, даже если сервер
            // раздавал ключи вхолостую.
            const due = t - refreshedAt >= PQ_OPK_REFRESH_MS;
            if (due) {
                const res = await transport.deletePqOneTimePrekeys();
                if (!res || !res.data || res.data.success !== true) throw keyServerError('очистку пула одноразовых PQ-prekey', res);
                have = 0;
            } else if (have >= LOW_WATER_PQ_OPK) {
                return;
            }

            const keys = await withLock(async () => {
                const identity = await loadIdentityLocked();
                if (due) {
                    for (const name of await pqOneTimeNamesLocked()) {
                        const rec = await storage.get(name);
                        if (rec && typeof rec.retiredAt !== 'number') await storage.set(name, Object.assign({}, rec, { retiredAt: t }));
                    }
                    await storage.set(PQ_OPK_REFRESHED, t);
                }
                return generatePqOneTimeLocked(identity, TOPUP_PQ_OPK - have, t);
            });
            await uploadPqOneTime(keys);
        }

        // Пул — оптимизация, а не условие работы: без него остаётся запасной
        // ключ. Поэтому сбой пополнения init() не роняет, а только
        // предупреждает в консоли (иначе временная ошибка сети или старый сервер
        // отключали бы E2EE целиком).
        async function topUpPqOneTimePrekeysIfNeeded() {
            if (typeof transport.postPqOneTimePrekeys !== 'function' || typeof transport.deletePqOneTimePrekeys !== 'function') return;
            try {
                await maintainPqOneTime();
            } catch (err) {
                if (typeof console !== 'undefined' && console.warn) {
                    console.warn('E2EE: пул одноразовых PQ-prekey не пополнен, пока работает запасной ключ:', err && err.message);
                }
            }
        }

        // Инициализация: сгенерировать (или загрузить и мигрировать) ключи
        // устройства, ротировать просроченные SPK/PQ-prekey, загрузить
        // публичные части на сервер, пополнить пулы одноразовых ключей. Идемпотентна —
        // можно вызывать повторно (например, раз в сутки), чтобы ротация
        // срабатывала и без перезагрузки страницы.
        //
        // Ошибки — только E2eeError (ERROR_CODES), по фазам:
        //   probeSupport                 → unsupported;
        //   ensureLocal                  → storage (NotSupportedError → unsupported);
        //   maintainPrekeysLocked        → unsupported или protocol (длина ключа ML-KEM);
        //   uploadKeysIfNeeded и topUp*  → network, server или protocol.
        async function init() {
            await probeSupport();
            try {
                await ensureLocal();
            } catch (err) {
                throw asInitError(err, 'storage');
            }
            // Комнаты в режиме «Не хранить историю»: прошлая вкладка могла закрыться или
            // упасть, не успев стереть ключи. Только при первом init() клиента — плановый
            // init() раз в 6 часов не должен стирать историю открытой комнаты.
            if (!forgotNoHistoryAtStart) {
                try {
                    await forgetAllNoHistoryRooms();
                    forgotNoHistoryAtStart = true;
                } catch (err) {
                    console.warn('E2EE: не удалось забыть историю комнат без хранения:', err);
                }
            }
            let identity;
            try {
                identity = await withLock(async () => {
                    const id = await loadIdentityLocked();
                    await maintainPrekeysLocked(id);
                    return id;
                });
            } catch (err) {
                throw asInitError(err, 'unsupported');
            }
            try {
                await uploadKeysIfNeeded();
                await topUpOneTimePreKeysIfNeeded();
                await topUpPqOneTimePrekeysIfNeeded();
            } catch (err) {
                throw asInitError(err, 'protocol');
            }
            return { identityPub: identity.dhPub, signPub: identity.signPub };
        }

        // Приводит любую ошибку фазы к E2eeError; fallback — код, если ничего
        // более точного о ней не известно (непонятное исключение внутри фазы).
        // Отказ fetch (TypeError, AbortError) в фазе обмена с сервером — network.
        function asInitError(err, fallback) {
            if (err instanceof E2eeError) return err;
            if (err && err.name === 'NotSupportedError') {
                return new E2eeError('unsupported', 'E2EE: браузер не поддерживает нужный алгоритм', { cause: err });
            }
            if (fallback === 'protocol' && (err instanceof TypeError || (err && err.name === 'AbortError'))) {
                return new E2eeError('network', 'E2EE: нет связи с сервером ключей', { cause: err });
            }
            const detail = err && err.message ? ': ' + err.message : '';
            return new E2eeError(fallback, 'E2EE: не удалось подготовить ключи устройства' + detail, { cause: err });
        }

        // Умеет ли этот браузер то, без чего E2EE не заработает: X25519, Ed25519,
        // HKDF и ML-KEM. Успех запоминается на клиента; отказ — нет, чтобы
        // «Повторить» (после обновления браузера, подгрузки модуля) не требовало
        // нового клиента. Бросает E2eeError('unsupported').
        let forgotNoHistoryAtStart = false;
        let supportProbe = null;
        function probeSupport() {
            if (!supportProbe) {
                supportProbe = (async () => {
                    if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
                        throw new E2eeError('unsupported', 'E2EE: в браузере нет Web Crypto (нужен https или localhost)');
                    }
                    try {
                        await generateX25519();
                        await generateEd25519();
                        await subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, ['deriveBits']);
                    } catch (cause) {
                        throw new E2eeError('unsupported', 'E2EE: браузер не поддерживает X25519, Ed25519 или HKDF', { cause });
                    }
                    let module;
                    try {
                        module = getKem();
                    } catch (cause) {
                        throw new E2eeError('unsupported', 'E2EE: модуль ML-KEM недоступен', { cause });
                    }
                    if (!module || ['keygen', 'encapsulate', 'decapsulate'].some(name => typeof module[name] !== 'function')) {
                        throw new E2eeError('unsupported', 'E2EE: модуль ML-KEM неполный');
                    }
                })();
                supportProbe.catch(() => { supportProbe = null; });
            }
            return supportProbe;
        }

        function setUserId(id) { userId = id; }

        // ---- Закрепление identity собеседников ----

        // Сверка identity, который сообщил сервер, с закреплённым.
        // Первый контакт — TOFU; несовпадение — status 'changed', новый
        // ключ ждёт в pending до acceptPeerIdentityChange().
        async function reconcilePinLocked(peerId, signPub, dhPub) {
            const name = 'peer:' + peerId;
            const pin = await storage.get(name);
            if (!pin) {
                await storage.set(name, { signPub, dhPub, verified: false, firstSeenAt: now() });
                return 'unverified';
            }
            if (pin.signPub === signPub && pin.dhPub === dhPub) {
                if (pin.pending) {
                    // Сервер снова отдаёт закреплённый ключ — "смена"
                    // отменена; закреплённому ключу мы и так доверяли.
                    delete pin.pending;
                    await storage.set(name, pin);
                }
                return identityStatus(pin);
            }
            if (!pin.pending || pin.pending.signPub !== signPub || pin.pending.dhPub !== dhPub) {
                pin.pending = { signPub, dhPub, seenAt: now() };
                await storage.set(name, pin);
            }
            return 'changed';
        }

        // Map userId → { signPub, dhPub } по данным сервера или null, если
        // узнать не удалось (сеть, старый сервер без /api/keys/identities).
        async function fetchServerIdentities(ids) {
            if (typeof transport.getIdentities !== 'function' || ids.length === 0) return null;
            const out = new Map();
            for (let i = 0; i < ids.length; i += 200) {
                const chunk = ids.slice(i, i + 200);
                let res;
                try { res = await transport.getIdentities(chunk); } catch { return null; }
                if (!res || !res.data || res.data.success !== true || !Array.isArray(res.data.identities)) return null;
                for (const item of res.data.identities) {
                    const id = Number(item && item.user_id);
                    if (!chunk.includes(id)) continue;
                    const signPub = canonicalPubKey(item.identity_signing_key);
                    const dhPub = canonicalPubKey(item.identity_dh_key);
                    if (signPub && dhPub) out.set(id, { signPub, dhPub, kt: item.kt });
                }
            }
            return out;
        }

        // Сверка закреплённых ключей с сервером. serverKnown — множество id, у
        // которых identity на сервере есть, или null, если сервер не ответил
        // (тогда "ключей нет" и "не удалось узнать" неразличимы).
        async function checkPeersWithServer(userIds) {
            await ensureLocal();
            const me = Number(userId);
            const ids = normalizeIds(userIds).filter(id => id !== me);
            const server = await fetchServerIdentities(ids);
            await withLock(async () => {
                for (const id of ids) {
                    const s = server && server.get(id);
                    if (!s) continue;
                    await reconcilePinLocked(id, s.signPub, s.dhPub);
                    // Ключ собеседника проверит журнал: в блокировке — только задача (7.6).
                    if (ktOn()) await ktLog.notePeerLocked(id, s.kt);
                }
            });
            await runKtChecksBounded();
            const statuses = await withLock(async () => {
                const out = [];
                for (const id of ids) {
                    const pin = await storage.get('peer:' + id);
                    const entry = { userId: id, status: identityStatus(pin) };
                    if (pin && pin.kt) entry.kt = pin.kt.status;
                    out.push(entry);
                }
                return out;
            });
            return { statuses, serverKnown: server ? new Set(server.keys()) : null };
        }

        async function checkPeerIdentities(userIds) {
            return (await checkPeersWithServer(userIds)).statuses;
        }

        async function getPeerIdentityStatus(peerId) {
            return identityStatus(await storage.get('peer:' + Number(peerId)));
        }

        // Пользователь сверил код безопасности. Для собеседника со
        // сменившимся (не подтверждённым) ключом отметка не ставится.
        async function markPeerVerified(peerId) {
            await ensureLocal();
            return withLock(async () => {
                const name = 'peer:' + Number(peerId);
                const pin = await storage.get(name);
                if (!pin || pin.pending) return false;
                pin.verified = true;
                await storage.set(name, pin);
                return true;
            });
        }

        // Код безопасности для закреплённого (не pending) ключа собеседника.
        async function getSafetyNumber(peerId) {
            await ensureLocal();
            const id = Number(peerId);
            if (!Number.isSafeInteger(id) || id <= 0 || id === Number(userId)) return null;
            const identity = await storage.get('identity');
            const pin = await storage.get('peer:' + id);
            if (!identity || !pin) return null;
            return computeSafetyNumber(Number(userId), identity.signPub, identity.dhPub, id, pin.signPub, pin.dhPub);
        }

        // Пользователь принял новый ключ собеседника: он становится
        // закреплённым (не проверенным), старые попарные сессии и отметки
        // "ключ комнаты уже отправлен" для него сбрасываются — при следующем
        // ensureRoomSession ключи уйдут к нему заново. Отложенные key-share
        // от него обрабатываются сразу.
        async function acceptPeerIdentityChange(peerId) {
            await ensureLocal();
            const id = Number(peerId);
            const queued = await withLock(async () => {
                const name = 'peer:' + id;
                const pin = await storage.get(name);
                if (!pin || !pin.pending) return null;
                await storage.set(name, {
                    signPub: pin.pending.signPub,
                    dhPub: pin.pending.dhPub,
                    verified: false,
                    firstSeenAt: pin.pending.seenAt || now(),
                });
                await storage.delete('pw2Send:' + id);
                await storage.delete('pw2Recv:' + id);
                for (const name of await storage.keys('sharedWith2:')) {
                    if (name.split(':')[3] === String(id)) await storage.delete(name);
                }
                // Решение человека о новом ключе подтверждает участника вручную там, где он есть в списке сервера (9.7).
                await membership.trustAfterAcceptLocked(id, (members, peerId) => {
                    const found = members.find(p => Number(p.id) === peerId);
                    return found && typeof found.username === 'string' ? found.username : '';
                });
                // Ключи участника сменились: ключи комнат, которые он получил по прежним ключам, меняются везде (9.1).
                await rotateCommonRoomsLocked(null, [id]);
                const list = (await storage.get('pendingShares:' + id)) || [];
                await storage.delete('pendingShares:' + id);
                return list;
            });
            if (!queued) return false;
            for (const item of queued) {
                try { await applyShare(item.roomId, id, item.ciphertext); } catch { /* битый отложенный share просто пропускаем */ }
            }
            return true;
        }

        // ---- Прозрачность ключей (docs/security/key-transparency.md, 10) ----

        // { status: 'ok' | 'unavailable' | 'inconsistent', peers: [{ userId, status }], self: 'ok' | 'alert' | 'unknown' }.
        async function checkTransparency() {
            await ensureLocal();
            if (!ktLog) return { status: 'unavailable', peers: [], self: 'unknown' };
            return ktLog.checkTransparency();
        }

        // Проверки журнала сейчас (вне блокировки; повтор при сетевой ошибке идёт сам).
        async function runKtChecks() {
            await ensureLocal();
            if (ktOn()) await ktLog.runKtChecks();
        }

        // Статус журнала для ключа собеседника: 'ok' | 'pending' | 'unavailable' | 'mismatch' | null (не проверялся).
        async function getPeerTransparency(peerId) {
            const pin = await storage.get('peer:' + Number(peerId));
            return pin && pin.kt ? { status: pin.kt.status, reason: pin.kt.reason || null, override: Boolean(pin.kt.override) } : null;
        }

        // Пользователь явно продолжает общение с собеседником, чьего ключа нет в журнале: он снова адресат рассылки
        // (со следующей ротацией), статус и баннер остаются.
        async function overrideLogMismatch(peerId) {
            await ensureLocal();
            return withLock(async () => {
                const name = 'peer:' + Number(peerId);
                const pin = await storage.get(name);
                if (!pin || !pin.kt || pin.kt.status !== 'mismatch') return false;
                pin.kt.override = true;
                await storage.set(name, pin);
                return true;
            });
        }

        // Проверка ключа заявителя до вступления (одобряющий поручается за него): данные из join-requests.
        async function checkApplicantKey(userIdOfApplicant, identity) {
            await ensureLocal();
            if (!ktOn() || !identity) return { status: 'unavailable' };
            const signPub = canonicalPubKey(identity.signingKey);
            const dhPub = canonicalPubKey(identity.dhKey);
            if (!signPub || !dhPub) return { status: 'unavailable' };
            const result = await ktLog.checkKeys(Number(userIdOfApplicant), signPub, dhPub, identity.kt);
            return result.retry ? { status: 'unavailable' } : { status: result.status, reason: result.reason || null };
        }

        async function getTransparencyAlerts() {
            await ensureLocal();
            return ktLog ? ktLog.getAlerts() : [];
        }

        async function dismissTransparencyAlerts(kinds) {
            await ensureLocal();
            if (ktLog) await ktLog.dismissAlerts(kinds);
        }

        // «Это были мои прежние ключи»: гасит тревогу self-foreign-entry для выбранных обязательств.
        async function ackSelfEntries(list) {
            await ensureLocal();
            if (ktLog) await ktLog.ackSelfEntries(list);
        }

        async function getPendingLogKey() {
            await ensureLocal();
            return ktLog ? ktLog.getPendingLogKey() : null;
        }

        async function acceptLogKey() {
            await ensureLocal();
            return ktLog ? ktLog.acceptLogKey() : false;
        }

        // Плановые проверки раз в час (закрытие эпохи) и самомониторинг; запускает интерфейс после init().
        function startTransparency() { if (ktOn()) ktLog.startTimers(); }
        function stopTransparency() { if (ktLog) ktLog.stopTimers(); }

        // ---- Попарный канал: я — отправитель key-share ----

        function sessionMatchesPin(session, pin) {
            return Boolean(session && pin && !pin.pending
                && session.peerSignPub === pin.signPub && session.peerDhPub === pin.dhPub);
        }

        async function fetchBundle(peerId) {
            let res;
            try { res = await transport.getBundle(peerId); } catch { return { error: 'не удалось получить ключи собеседника' }; }
            if (!res) return { error: 'не удалось получить ключи собеседника' };
            if (res.status === 404) return { error: REASON_NOT_READY };
            if (res.status === 403) return { error: (res.data && res.data.message) || 'нет общего чата с пользователем' };
            if (res.status === 429) return { error: (res.data && res.data.message) || 'слишком много запросов ключей — попробуйте позже' };
            if (res.status >= 500) return { error: 'сервер ключей недоступен' };
            if (!res.data || !res.data.identity_dh_key) return { error: REASON_NOT_READY };
            return { bundle: res.data };
        }

        // PQXDH со стороны инициатора. Возвращает { session } | { changed } | { error }.
        async function startSendSessionLocked(identity, peerId, bundle) {
            const signPub = canonicalSigningKey(bundle.identity_signing_key);
            const dhPub = canonicalPubKey(bundle.identity_dh_key);
            if (!signPub || !dhPub) return { error: 'некорректные identity-ключи собеседника' };

            // Bundle обязан совпасть с закреплённым identity: иначе сервер мог
            // бы подсунуть свой bundle (MITM) — раньше это проходило молча.
            const pinName = 'peer:' + peerId;
            const pin = await storage.get(pinName);
            if (pin && pin.pending) return { changed: true };
            if (pin && (pin.signPub !== signPub || pin.dhPub !== dhPub)) {
                await reconcilePinLocked(peerId, signPub, dhPub);
                return { changed: true };
            }

            // Критическая проверка: подпись Signed PreKey СВОИМ identity-
            // ключом пира. Сервер ключей эту подпись при загрузке тоже
            // проверяет, но полагаться только на это нельзя.
            const spkInfo = bundle.signed_prekey || {};
            const spkPub = decodeFixed(spkInfo.public_key, 32);
            const spkSig = decodeFixed(spkInfo.signature, 64);
            if (!spkPub || !spkSig || !isKeyId(spkInfo.key_id)) return { error: 'некорректный Signed PreKey собеседника' };
            if (!(await verify(b64decode(signPub), spkSig, spkPub))) {
                return { error: 'неверная подпись Signed PreKey у пользователя ' + peerId + ' — возможная подмена ключа' };
            }

            // Постквантовая часть. Если сервер выдал одноразовый PQ-prekey, берём
            // его: он достаётся ровно одному инициатору, а получатель удаляет
            // секретную часть после использования. Подпись у него другая (с
            // меткой и key_id, см. pqOneTimeSigInput), поэтому «сырую» подпись
            // запасного ключа на его месте сервер подсунуть не может, как и
            // наоборот. Подпись не сошлась — отказ, а не тихий переход на
            // запасной ключ: иначе сервер, портя подпись, выбирал бы, каким
            // ключом нас защищать. Одноразового нет — запасной (last-resort).
            // Без PQ-части не откатываемся на классический X3DH: иначе сервер,
            // просто убрав её из bundle, понижал бы защиту.
            const pqOneInfo = bundle.pq_one_time_prekey || null;
            const pqInfo = pqOneInfo || bundle.pq_prekey;
            if (!pqInfo) return { error: REASON_OUTDATED };
            const pqKind = pqOneInfo ? 'одноразового PQ-prekey' : 'PQ-prekey';
            const pqPub = decodeFixed(pqInfo.public_key, PQ_PUBLIC_KEY_BYTES);
            const pqSig = decodeFixed(pqInfo.signature, 64);
            if (!pqPub || !pqSig || !isKeyId(pqInfo.key_id)) return { error: 'некорректный ' + (pqOneInfo ? 'одноразовый ' : '') + 'PQ-prekey собеседника' };
            if (!(await verify(b64decode(signPub), pqSig, pqOneInfo ? pqOneTimeSigInput(pqInfo.key_id, pqPub) : pqPub))) {
                return { error: 'неверная подпись ' + pqKind + ' у пользователя ' + peerId + ' — возможная подмена ключа' };
            }

            const otpk = bundle.one_time_prekey || null;
            let otpkPub = null;
            if (otpk) {
                otpkPub = decodeFixed(otpk.public_key, 32);
                if (!otpkPub || !isKeyId(otpk.key_id)) return { error: 'некорректный one-time prekey собеседника' };
            }

            let pqResult;
            try {
                pqResult = await getKem().encapsulate(pqPub);
            } catch {
                return { error: 'некорректный PQ-prekey собеседника' };
            }
            const pqCiphertext = pqResult && pqResult.ciphertext;
            const pqShared = pqResult && pqResult.sharedSecret;
            if (!pqCiphertext || pqCiphertext.length !== PQ_CIPHERTEXT_BYTES || !pqShared || pqShared.length !== 32) {
                return { error: 'ошибка ML-KEM' };
            }

            let sk;
            const eph = await generateX25519();
            try {
                const dh1 = await dh(identity.dhPriv, spkPub);
                const dh2 = await dh(eph.priv, b64decode(dhPub));
                const dh3 = await dh(eph.priv, spkPub);
                const dh4 = otpkPub ? await dh(eph.priv, otpkPub) : new Uint8Array(0);
                sk = await hkdf(concatBytes(FF32, dh1, dh2, dh3, dh4, pqShared), ZERO32, 'nyxo-e2ee-pqxdh-v1', 32);
            } catch (err) {
                return { error: err.message };
            }

            if (!pin) await storage.set(pinName, { signPub, dhPub, verified: false, firstSeenAt: now() });
            const session = {
                ck: b64encode(await hkdf(sk, ZERO32, 'nyxo-e2ee-pw-chain-v2', 32)),
                n: 0,
                header: {
                    type: 'x3dh-init',
                    senderIdentityDhPub: identity.dhPub,
                    senderIdentitySignPub: identity.signPub,
                    senderEphemeralPub: b64encode(eph.pub),
                    usedSignedPrekeyId: spkInfo.key_id,
                    usedOneTimePrekeyId: otpk ? otpk.key_id : null,
                    pqCiphertext: b64encode(pqCiphertext),
                    usedPqPrekeyId: pqInfo.key_id,
                    // Поле только у одноразового ключа: оно решает, где получатель ищет секрет.
                    ...(pqOneInfo ? { pqOneTime: true } : {}),
                },
                peerSignPub: signPub,
                peerDhPub: dhPub,
                createdAt: now(),
            };
            await storage.set('pw2Send:' + peerId, session);
            return { session };
        }

        // Готовит key-share моего текущего Sender Key для одного участника.
        // Возвращает { share, senderKeyId } | { changed:true } | { warning }.
        async function prepareShareForPeer(roomId, peerId) {
            const pre = await withLock(async () => {
                const pin = await storage.get('peer:' + peerId);
                if (pin && pin.pending) return { changed: true };
                const session = await storage.get('pw2Send:' + peerId);
                return { fresh: sessionMatchesPin(session, pin) && now() - session.createdAt < PAIRWISE_SESSION_MAX_AGE_MS };
            });
            if (pre.changed) return { changed: true };

            // Сессия старше 7 дней перезапускается новым PQXDH (свежий
            // эфемерный ключ и свежий prekey собеседника).
            let fetched = null;
            if (!pre.fresh) fetched = await fetchBundle(peerId);

            return withLock(async () => {
                const identity = await loadIdentityLocked();
                let session = null;
                let bundleError = null;
                if (fetched && fetched.bundle) {
                    const started = await startSendSessionLocked(identity, peerId, fetched.bundle);
                    if (started.changed) return { changed: true };
                    if (started.error) bundleError = started.error;
                    else session = started.session;
                } else if (fetched) {
                    bundleError = fetched.error;
                }

                const pin = await storage.get('peer:' + peerId);
                if (pin && pin.pending) return { changed: true };
                if (!session) {
                    // Новую сессию начать не удалось (лимит запросов, нет
                    // PQ-prekey, битый bundle) — старая, заведённая по PQXDH с
                    // закреплённым identity, по-прежнему безопасна.
                    const old = await storage.get('pw2Send:' + peerId);
                    if (!sessionMatchesPin(old, pin)) return { warning: bundleError || REASON_NOT_READY };
                    session = old;
                }

                const own = await loadOwnSenderKeyLocked(roomId);
                if (!own) return { warning: 'нет ключа комнаты' };

                // Журнал доставок (signed-membership.md, 9.1, 9.4): пара { id, memkey } по закреплённым ключам, по которым
                // шифруется share, - ДО сетевого вызова и только на добавление. Если запрос ушёл, а ответ потерян или вкладка
                // закрылась, ключ мог дойти, и журнал это учитывает; по нему же решается ротация.
                const peerMemkey = Membership.toHex(await Membership.memkey(Number(peerId), b64decode(pin.signPub), b64decode(pin.dhPub)));
                const stored = await storage.get('members:' + roomId);
                await membership.appendDeliveredLocked(roomId, own.senderKeyId, Number(peerId), peerMemkey, Array.isArray(stored) ? stored.length : 0);

                const { messageKey, nextChainKey } = await chainStep(b64decode(session.ck));
                const n = session.n;
                session.ck = b64encode(nextChainKey);
                session.n = n + 1;
                await storage.set('pw2Send:' + peerId, session);

                // Участникам, которые были в комнате при создании ключа, ключ
                // выдаётся «с начала эпохи» (chainKey0, итерация 0): так читается
                // всё, что отправлено им до того, как key-share дошёл (поздняя
                // настройка E2EE, потеря share, запрос ключа). Новичкам — текущая
                // позиция: что было до их вступления, они читать не должны. На
                // прямую секретность это не влияет: свои ключи сообщений
                // отправитель и так хранит в cachedKeys.
                // Право на ключ с начала эпохи - у пары { id, memkey } из recipients на момент создания ключа: участник, сменивший
                // ключи, и участник, подтверждённый позже, получают его как новички (signed-membership.md, 9.4).
                const fromStart = Boolean(own.origin && own.origin.chainKey0)
                    && Array.isArray(own.entitled) && own.entitled.includes(Number(peerId))
                    && (!own.entitledKeys || own.entitledKeys[Number(peerId)] === peerMemkey);
                // ext: прежний ключ (prev) и последняя проверенная подписанная голова журнала (kt, 7.5).
                const ext = {};
                if (own.prev) ext.prev = own.prev;
                const gossip = ktOn() ? await ktLog.gossipHead() : null;
                if (gossip) ext.kt = gossip;
                // Хэш взгляда на состав и ключи участников (6.3): справочная подсказка внутри AEAD попарного канала.
                const view = await membership.computeViewLocked(roomId, { id: Number(userId), signPub: b64decode(identity.signPub), dhPub: b64decode(identity.dhPub) });
                if (view) ext.view = membership.encodeView(view);
                const skdm = buildSkdm(roomId, {
                    senderKeyId: own.senderKeyId,
                    chainKey: fromStart ? own.origin.chainKey0 : own.chainKey,
                    iteration: fromStart ? 0 : own.nextIteration,
                    signingPublicKey: own.signingPublicKey,
                }, ext);
                const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-skdm-v2', 32);
                const aad = skdmAadV2(roomId, userId, peerId, identity.signPub, identity.dhPub, session.peerSignPub, session.peerDhPub);
                const { iv, ct } = await aesGcmEncrypt(aesKey, utf8encode(JSON.stringify(skdm)), aad);
                const ciphertext = JSON.stringify({ v: 2, type: 'skdm', n, iv: b64encode(iv), ct: b64encode(ct), init: session.header });
                // Размер фиксирован структурой (~2,3 тыс. символов, основная
                // часть — pqCiphertext); проверка — страховка от регрессий.
                if (ciphertext.length > MAX_SHARE_CHARS) return { warning: 'key-share превышает допустимый размер' };
                return {
                    share: { recipientUserId: peerId, ciphertext },
                    senderKeyId: own.senderKeyId,
                };
            });
        }

        // ---- Попарный канал: я — получатель key-share ----

        // PQXDH со стороны получателя; null, если нужный prekey уже удалён
        // или вычисление не удалось.
        async function deriveRecvSecretLocked(identity, h) {
            const t = now();
            try {
                let spkPriv = null;
                const spk = await loadSpkLocked();
                if (spk && spk.keyId === h.spkId) {
                    spkPriv = spk.priv;
                } else {
                    const old = await storage.get('spkOld:' + h.spkId);
                    if (old && t - old.retiredAt <= PREKEY_RETAIN_MS) spkPriv = await toPrivateKey(old.priv, 'X25519', ['deriveBits']);
                }
                if (!spkPriv) return null; // SPK давно ротирован — расшифровать нечем

                // Одноразовый PQ-prekey ищется только среди pqopk:<id>, запасной —
                // только среди pqpk/pqpkOld: ключ одной роли на место другой не
                // подставляется. Записи pqopk нет — ключ уже использован (повтор
                // или второй инициатор на тот же ключ), расшифровывать нечем.
                let pqSeed = null;
                if (h.pqOneTime) {
                    const rec = await storage.get('pqopk:' + h.pqId);
                    if (rec && typeof rec.seed === 'string'
                        && (typeof rec.retiredAt !== 'number' || t - rec.retiredAt <= PREKEY_RETAIN_MS)) pqSeed = rec.seed;
                } else {
                    const pq = await storage.get('pqpk');
                    if (pq && pq.keyId === h.pqId) {
                        pqSeed = pq.seed;
                    } else {
                        const old = await storage.get('pqpkOld:' + h.pqId);
                        if (old && t - old.retiredAt <= PREKEY_RETAIN_MS) pqSeed = old.seed;
                    }
                }
                if (!pqSeed) return null;

                let opkPriv = null;
                if (h.opkId !== null) {
                    // Раньше отсутствующий OPK молча пропускался, и ключ
                    // расходился с отправителем; теперь это явная ошибка.
                    const opk = await loadOpkLocked(h.opkId);
                    if (!opk) return null;
                    opkPriv = opk.priv;
                }

                const senderDh = b64decode(h.dhPub);
                const eph = b64decode(h.eph);
                const dh1 = await dh(spkPriv, senderDh);
                const dh2 = await dh(identity.dhPriv, eph);
                const dh3 = await dh(spkPriv, eph);
                const dh4 = opkPriv ? await dh(opkPriv, eph) : new Uint8Array(0);
                // Неверный шифротекст ML-KEM правильной длины не бросает
                // (implicit rejection) — ошибка проявится на AEAD.
                // Одноразовый секретный ключ в кэш не попадает и после
                // декапсуляции затирается: в памяти он живёт ровно один вызов.
                const pqSecret = await pqSecretKey(pqSeed, { cache: !h.pqOneTime });
                let ss;
                try {
                    ss = toBytes(await getKem().decapsulate(pqSecret, h.pqCt));
                } finally {
                    if (h.pqOneTime && pqSecret && typeof pqSecret.fill === 'function') pqSecret.fill(0);
                }
                if (ss.length !== 32) return null;
                return await hkdf(concatBytes(FF32, dh1, dh2, dh3, dh4, ss), ZERO32, 'nyxo-e2ee-pqxdh-v1', 32);
            } catch {
                return null;
            }
        }

        // Расшифровывает key-share, ничего не сохраняя: состояние
        // коммитится только после успешной проверки AEAD, иначе поддельный
        // share мог бы сжечь OPK или сбить сессию.
        async function openShareLocked(roomId, senderId, env, identity) {
            const h = env.init;
            const current = await storage.get('pw2Recv:' + senderId);
            let session;
            let isNew = false;
            if (current && current.eph === h.eph && current.peerSignPub === h.signPub && current.peerDhPub === h.dhPub) {
                session = current;
            } else {
                // Эфемерный ключ уже встречался, но это не текущая сессия —
                // повтор старой сессии (например, чтобы откатить ключ).
                const seen = (await storage.get('pw2Seen:' + senderId)) || [];
                if (seen.includes(h.eph)) return null;
                const sk = await deriveRecvSecretLocked(identity, h);
                if (!sk) return null;
                session = {
                    eph: h.eph,
                    ck: b64encode(await hkdf(sk, ZERO32, 'nyxo-e2ee-pw-chain-v2', 32)),
                    n: 0,
                    skipped: {},
                    peerSignPub: h.signPub,
                    peerDhPub: h.dhPub,
                    createdAt: now(),
                };
                isNew = true;
            }

            const messageKey = await takePairwiseKey(session, env.n);
            if (!messageKey) return null;
            const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-skdm-v2', 32);
            const aad = skdmAadV2(roomId, senderId, userId, h.signPub, h.dhPub, identity.signPub, identity.dhPub);
            let pt;
            try { pt = await aesGcmDecrypt(aesKey, env.iv, env.ct, aad); } catch { return null; }
            const skdm = parseSkdm(pt, roomId);
            if (!skdm) return null;

            return {
                skdm,
                async commit() {
                    await storage.set('pw2Recv:' + senderId, session);
                    if (isNew) {
                        const seen = (await storage.get('pw2Seen:' + senderId)) || [];
                        seen.push(h.eph);
                        if (seen.length > MAX_SEEN_EPHEMERAL) seen.splice(0, seen.length - MAX_SEEN_EPHEMERAL);
                        await storage.set('pw2Seen:' + senderId, seen);
                        if (h.opkId !== null) await storage.delete('opk:' + h.opkId); // одноразовый — использован
                        // Одноразовый PQ-prekey тоже: после этого перехваченный
                        // позже key-share расшифровать нечем. Поддельный share сюда
                        // не доходит (AEAD в openShareLocked), и ключ не сгорает.
                        if (h.pqOneTime) await storage.delete('pqopk:' + h.pqId);
                    }
                },
            };
        }

        // Достраивает цепочку назад: SKDM «с начала эпохи» (iteration раньше
        // startIteration) отдаёт ключи сообщений, отправленных до того, как у нас
        // появился этот ключ (поздняя настройка E2EE, потерянный share, запрос
        // ключа). Выводятся итерации [skdm.iteration, startIteration), не больше
        // MAX_SKIP; уже имеющиеся ключи не перезаписываются, текущая позиция
        // цепочки не трогается. Разрыв больше MAX_SKIP не достраивается: вывести
        // середину, не пройдя начало, нельзя.
        async function mergeEarlierChain(rec, skdm, hour) {
            const gap = rec.startIteration - skdm.iteration;
            if (gap <= 0 || gap > MAX_SKIP) return false;
            if (!rec.keyTimes) rec.keyTimes = {};
            let chain = b64decode(skdm.chainKey);
            for (let it = skdm.iteration; it < rec.startIteration; it++) {
                const step = await chainStep(chain);
                if (!rec.cachedKeys[it]) {
                    rec.cachedKeys[it] = b64encode(step.messageKey);
                    rec.keyTimes[it] = hour;
                }
                chain = step.nextChainKey;
            }
            rec.startIteration = skdm.iteration;
            trimChain(rec);
            return true;
        }

        // prev из SKDM нового ключа для УЖЕ архивного ключа (не для вытесняемого
        // сейчас — тому final передаётся прямо в moveToArchiveLocked): закрывает его
        // открытую цепочку по final. true — индекс state.archive изменён, основную
        // запись сохраняет вызывающий.
        async function applyPrevLocked(roomId, senderId, state, prev) {
            if (!prev || prev.id === state.senderKeyId || !archiveHas(state, prev.id)) return false;
            const name = archiveName(roomId, senderId, prev.id);
            const rec = await storage.get(name);
            if (!rec || !rec.chainKey) return false;
            if (!(await closeChain(rec, prev.final, hourOf(now())))) return false;
            await storage.set(name, rec);
            const entry = state.archive.find(item => typeof item === 'object' && item.id === prev.id);
            if (entry) entry.final = rec.final;
            return true;
        }

        // Можно ли заносить этот SKDM в индекс отправителей (sealed-sender.md, 9.2):
        // senderId берётся из AAD key-share (проверенного AEAD), а не из поля ответа
        // сервера; пересчитанный идентификатор обязан совпасть с заявленным, и в
        // индексе под этим keyId не должно стоять другого отправителя (возможно
        // только при коллизии SHA-256 по 128 битам). Ничего не пишет.
        async function skdmBindingHoldsLocked(roomId, senderId, skdm) {
            let derived;
            try { derived = await deriveSenderKeyId(roomId, senderId, skdm.signingPublicKey); } catch { return false; }
            if (derived !== skdm.senderKeyId) return false;
            const entry = await readIndexLocked(roomId, skdm.senderKeyId);
            return !entry || entry.sender === Number(senderId);
        }

        // order = { eph, n } — позиция key-share в попарной сессии. Возвращает
        // senderKeyId ключа, который теперь есть у нас (новый или уже имевшийся), либо
        // null: идентификатор не выведен из отправителя — SKDM не устанавливается,
        // состояние и индекс не меняются (проверка ДО любой записи).
        async function installSenderKeyLocked(roomId, senderId, skdm, order) {
            if (!(await skdmBindingHoldsLocked(roomId, senderId, skdm))) return null;
            const name = stateName(roomId, senderId);
            const existing = await readStateLocked(roomId, senderId);
            const t = now();
            const prev = skdm.ext && skdm.ext.prev ? skdm.ext.prev : null;
            if (existing && existing.senderKeyId === skdm.senderKeyId) {
                // Уже есть: состояние вперёд не откатываем. Но SKDM «с начала эпохи»
                // достраивает цепочку назад, а prev закрывает архивный предыдущий ключ.
                // Тот же id при другом ключе подписи — сбой или подделка: не трогаем.
                if (existing.signingPublicKey !== skdm.signingPublicKey) return skdm.senderKeyId;
                let changed = false;
                // Забытое режимом «не хранить историю» не воскрешается: SKDM с начала
                // эпохи достраивает цепочку назад только если ниже границы ничего не стирали.
                if (skdm.iteration < existing.startIteration && !(existing.forgottenBelow > skdm.iteration)) {
                    changed = await mergeEarlierChain(existing, skdm, hourOf(t));
                }
                if (await applyPrevLocked(roomId, senderId, existing, prev)) changed = true;
                if (changed) await storage.set(name, existing);
                await writeIndexLocked(roomId, skdm.senderKeyId, senderId);
                return skdm.senderKeyId;
            }
            // Ключ, который уже был заменён ротацией, обратно не ставим: иначе
            // повтор старого key-share возвращал бы в оборот старый ключ.
            if (existing && archiveHas(existing, skdm.senderKeyId)) return skdm.senderKeyId;
            if (existing && existing.installedBy && existing.installedBy.eph === order.eph && order.n < existing.installedBy.n) {
                // Более ранняя передача той же сессии, пришедшая позже более
                // поздней, несёт более старый ключ: текущий ею не заменяем, но и
                // не выбрасываем — старый ключ уходит прямо в архив, и сообщения,
                // отправленные им, остаются читаемыми.
                await storage.set(archiveName(roomId, senderId, skdm.senderKeyId), {
                    signingPublicKey: skdm.signingPublicKey,
                    cachedKeys: {}, keyTimes: {},
                    startIteration: skdm.iteration,
                    chainKey: skdm.chainKey, nextIteration: skdm.iteration,
                    final: null,
                    archivedAt: t,
                });
                existing.archive.unshift({ id: skdm.senderKeyId, archivedAt: t, final: null });
                const evicted = await trimArchiveIndex(roomId, senderId, existing);
                await applyPrevLocked(roomId, senderId, existing, prev);
                await storage.set(name, existing);
                await writeIndexLocked(roomId, skdm.senderKeyId, senderId);
                await dropArchivesLocked(roomId, senderId, evicted);
                return skdm.senderKeyId;
            }
            const next = {
                senderKeyId: skdm.senderKeyId,
                signingPublicKey: skdm.signingPublicKey,
                chainKey: skdm.chainKey,
                nextIteration: skdm.iteration,
                startIteration: skdm.iteration,
                cachedKeys: {},
                keyTimes: {},
                createdAt: t,
                archive: [],
                installedBy: { eph: order.eph, n: order.n },
            };
            let evicted = [];
            if (existing) {
                // Отправитель сообщил, до какой итерации дошёл прежний ключ (prev.final):
                // оставшиеся ключи выводятся сразу, chainKey стирается.
                const final = prev && prev.id === existing.senderKeyId ? prev.final : null;
                evicted = await moveToArchiveLocked(roomId, senderId, existing, { final });
                next.archive = existing.archive;
                await applyPrevLocked(roomId, senderId, next, prev);
            }
            await storage.set(name, next);
            await writeIndexLocked(roomId, skdm.senderKeyId, senderId);
            await dropArchivesLocked(roomId, senderId, evicted);
            return skdm.senderKeyId;
        }

        async function queuePendingShareLocked(senderId, roomId, ciphertext) {
            const name = 'pendingShares:' + senderId;
            const list = (await storage.get(name)) || [];
            if (list.some(item => item.ciphertext === ciphertext)) return;
            list.push({ roomId, ciphertext, receivedAt: now() });
            if (list.length > MAX_PENDING_SHARES) list.splice(0, list.length - MAX_PENDING_SHARES);
            await storage.set(name, list);
        }

        // Обрабатывает один key-share → 'applied' | 'failed' | 'changed' | 'unbound'
        // (идентификатор ключа не выведен из отправителя, раздел 9.2).
        // onInstalled(senderKeyId) — вызывается для применённого ключа: syncKeyShares
        // по нему снимает собственные запросы этого ключа.
        async function applyShare(roomId, senderId, ciphertext, onInstalled) {
            const me = Number(userId);
            if (!Number.isSafeInteger(senderId) || senderId <= 0 || senderId === me) return 'failed';
            if (typeof ciphertext !== 'string') return 'failed';
            const env = parseShareEnvelope(ciphertext);
            if (!env) return 'failed';
            const h = env.init;

            // identity из заголовка на слово не принимается: он должен
            // совпасть с закреплённым, а если закрепления нет — с тем, что
            // сервер отдаёт как identity отправителя (запрос — вне очереди).
            const pinBefore = await storage.get('peer:' + senderId);
            let serverIdentity = null;
            const matchesPin = pinBefore && !pinBefore.pending && pinBefore.signPub === h.signPub && pinBefore.dhPub === h.dhPub;
            if (!matchesPin && !(pinBefore && pinBefore.pending)) {
                const map = await fetchServerIdentities([senderId]);
                serverIdentity = map ? map.get(senderId) || null : null;
            }
            const serverMatches = Boolean(serverIdentity && serverIdentity.signPub === h.signPub && serverIdentity.dhPub === h.dhPub);

            return withLock(async () => {
                const identity = await loadIdentityLocked();
                const pin = await storage.get('peer:' + senderId);
                if (pin && pin.pending) {
                    // Смена identity ещё не подтверждена: x3dh-init от нового
                    // ключа откладываем до acceptPeerIdentityChange, прочие
                    // отбрасываем.
                    if (pin.pending.signPub === h.signPub && pin.pending.dhPub === h.dhPub) {
                        await queuePendingShareLocked(senderId, roomId, ciphertext);
                        return 'changed';
                    }
                    return 'failed';
                }
                if (pin && (pin.signPub !== h.signPub || pin.dhPub !== h.dhPub)) {
                    if (serverMatches) {
                        await reconcilePinLocked(senderId, h.signPub, h.dhPub);
                        await queuePendingShareLocked(senderId, roomId, ciphertext);
                        return 'changed';
                    }
                    return 'failed'; // чужой identity, сервер его не подтверждает — подделка
                }
                if (!pin && !serverMatches) return 'failed';

                const opened = await openShareLocked(roomId, senderId, env, identity);
                if (!opened) return 'failed';
                // Привязка senderKeyId к отправителю — до любой записи (в том числе до
                // фиксации попарной сессии и сжигания одноразовых ключей): SKDM с
                // чужим или случайным идентификатором не меняет ничего на устройстве.
                if (!(await skdmBindingHoldsLocked(roomId, senderId, opened.skdm))) {
                    console.warn('E2EE: SKDM отвергнут: senderKeyId не выведен из (комната, отправитель, ключ подписи)',
                        { roomId, senderId, senderKeyId: opened.skdm.senderKeyId });
                    return 'unbound';
                }
                if (!pin) await storage.set('peer:' + senderId, { signPub: h.signPub, dhPub: h.dhPub, verified: false, firstSeenAt: now() });
                await opened.commit();
                const keyId = await installSenderKeyLocked(roomId, senderId, opened.skdm, { eph: h.eph, n: env.n });
                if (keyId === null) return 'unbound';
                if (onInstalled) onInstalled(keyId);
                // Голова журнала отправителя (7.5): сверка — вне блокировки, в блокировке только задача.
                if (ktOn() && opened.skdm.ext && opened.skdm.ext.kt) await ktLog.noteGossipLocked(opened.skdm.ext.kt);
                // Хэш взгляда (9.6): в блокировке - только задача, сверка идёт вне блокировки (runViewChecks).
                if (opened.skdm.ext && opened.skdm.ext.view) await membership.noteViewLocked(roomId, senderId, opened.skdm.ext.view);
                return 'applied';
            });
        }

        // ---- Sender Key: моё состояние в комнате ----

        // roomId — комната: senderKeyId выводится из (комната, я, открытый ключ
        // подписи) и потому порождается ПОСЛЕ пары Ed25519 (раздел 9.2). Каждая
        // ротация даёт новую пару и новый идентификатор.
        // entitled — участники (id), которые были в комнате при создании ключа:
        // им ключ выдаётся с начала эпохи (prepareShareForPeer). prev — { id, final }
        // прежнего ключа: уходит в ext каждого SKDM нового ключа.
        async function newOwnSenderKeyState({ roomId, entitled = [], prev = null, logExcluded = [] } = {}) {
            // entitled - ids либо пары { id, memkey } (recipients на момент создания ключа, signed-membership.md, 9.4).
            const entitledIds = [];
            const entitledKeys = {};
            for (const item of Array.isArray(entitled) ? entitled : []) {
                const id = Number(item && typeof item === 'object' ? item.id : item);
                if (!Number.isSafeInteger(id) || id <= 0 || id === Number(userId) || entitledIds.includes(id)) continue;
                entitledIds.push(id);
                if (item && typeof item === 'object' && typeof item.memkey === 'string') entitledKeys[id] = item.memkey;
            }
            const signKp = await generateEd25519();
            const chainKey = b64encode(randomBytes(32));
            const signingPublicKey = b64encode(signKp.pub);
            const state = {
                senderKeyId: await deriveSenderKeyId(roomId, userId, signingPublicKey),
                signingPublicKey,
                signingPrivateKey: signKp.priv,
                chainKey,
                nextIteration: 0,
                startIteration: 0,
                cachedKeys: {},
                keyTimes: {},
                createdAt: now(),
                origin: { chainKey0: chainKey },
                entitled: entitledIds,
                // Пары: право на ключ с начала эпохи привязано к ключам участника (prepareShareForPeer).
                entitledKeys,
                // Участники, исключённые из рассылки журналом ключей (log-mismatch) к моменту создания ключа:
                // решение о ротации из-за mismatch принимается по статусу, а не по отметкам рассылки (sharedWith2),
                // которые стирает запрос ключа или принятие нового ключа.
                logExcluded: normalizeIds(logExcluded),
                archive: [],
            };
            if (prev) state.prev = prev;
            return state;
        }

        // Ключ пора менять (мягкий порог): 100 сообщений или 7 дней. Состояние без
        // createdAt — из версии до ротации: считается просроченным и меняется при
        // первом же использовании комнаты, лениво и без всплеска рассылок.
        function ownKeyDue(state) {
            if (!Number.isFinite(state.createdAt)) return true;
            const sent = state.nextIteration - (state.startIteration || 0);
            return sent >= ROTATE_AFTER_MESSAGES || now() - state.createdAt >= ROTATE_AFTER_MS;
        }

        // Жёсткий порог: 200 сообщений или 8 дней. Дальше encryptOutgoing не шифрует,
        // пока ключ не сменят: граница держится, даже если фоновая ротация не удалась.
        function ownKeyExpired(state) {
            if (!Number.isFinite(state.createdAt)) return true;
            const sent = state.nextIteration - (state.startIteration || 0);
            return sent >= FORCE_ROTATE_AFTER_MESSAGES || now() - state.createdAt >= FORCE_ROTATE_AFTER_MS;
        }

        // memberNames:<комната> = { <id>: <имя> } — имена всех, кто когда-либо был в
        // комнате на этом устройстве. Предел защищает хранилище от разрастания.
        const MAX_MEMBER_NAMES = 2000;
        async function rememberMemberNamesLocked(roomId, participants) {
            const name = 'memberNames:' + roomId;
            const stored = await storage.get(name);
            const names = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {};
            let changed = false;
            for (const p of participants) {
                if (!p.username || names[p.id] === p.username) continue;
                if (!(p.id in names) && Object.keys(names).length >= MAX_MEMBER_NAMES) continue;
                names[p.id] = p.username;
                changed = true;
            }
            if (changed || stored === null) await storage.set(name, names);
        }

        async function getRoomMemberNames(roomId) {
            await ensureLocal();
            const stored = await withLock(() => storage.get('memberNames:' + roomId));
            const out = {};
            if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
                for (const [id, value] of Object.entries(stored)) if (typeof value === 'string') out[id] = value;
            }
            return out;
        }

        // Из ids — те, кого журнал ключей исключил из рассылки (в блокировке).
        async function logExcludedIdsLocked(ids) {
            const out = [];
            for (const id of ids) {
                if (logExcluded(await storage.get('peer:' + Number(id)))) out.push(Number(id));
            }
            return out;
        }

        // Идентификатор своего ключа выведен из (комната, я, ключ подписи)?
        async function ownKeyBoundLocked(roomId, own) {
            try { return (await deriveSenderKeyId(roomId, userId, own.signingPublicKey)) === own.senderKeyId; } catch { return false; }
        }

        // Участники, которым новый ключ выдаётся с начала эпохи: весь известный
        // состав комнаты, кроме меня (members:<комната> ведёт ensureRoomSession).
        async function knownMemberIdsLocked(roomId) {
            const known = await storage.get('members:' + roomId);
            return Array.isArray(known) ? known.map(p => Number(p.id)).filter(id => id !== Number(userId)) : [];
        }

        // Ротация собственного Sender Key: новый chainKey и новая подписывающая
        // пара, старое состояние уходит в архив, чтобы уже отправленные сообщения
        // остались читаемыми для нас самих. В ext нового ключа едет prev — id
        // прежнего и последняя использованная им итерация: получатели закроют по
        // ней цепочку старого ключа и сотрут её chainKey. Если старым ключом
        // ничего не отправлено, закрывать нечего и prev не пишется.
        async function rotateRoomKeyLocked(roomId, entitled) {
            const existing = await loadOwnSenderKeyLocked(roomId);
            const known = await knownMemberIdsLocked(roomId);
            const excluded = await logExcludedIdsLocked(known);
            // Исключённые журналом не читают нового ключа с начала эпохи. Без явного списка - текущие получатели
            // (подтверждённые участники состава), а не весь список сервера (signed-membership.md, 9.4).
            const base = entitled || await membership.currentRecipientsLocked(roomId, Number(userId));
            const ids = base.filter(item => !excluded.includes(Number(item && typeof item === 'object' ? item.id : item)));
            const prev = existing && existing.nextIteration > 0 ? { id: existing.senderKeyId, final: existing.nextIteration - 1 } : null;
            const next = await newOwnSenderKeyState({ roomId, entitled: ids, prev, logExcluded: excluded });
            if (existing) {
                // Свой прежний ключ всегда в индексе: на устройстве с ключом, созданным
                // до привязки идентификатора, он мог быть не записан, а свои старые
                // сообщения должны читаться.
                await writeIndexLocked(roomId, existing.senderKeyId, userId);
                const evicted = await moveToArchiveLocked(roomId, userId, existing, { own: true });
                next.archive = existing.archive;
                await dropArchivesLocked(roomId, userId, evicted);
                // Отметки рассылки старого ключа и ответов на его запросы больше ни к чему; журнал доставок старого
                // ключа удаляется вместе с его ротацией (signed-membership.md, 8): новый ключ ведёт свой.
                for (const prefix of [
                    'sharedWith2:' + roomId + ':' + existing.senderKeyId + ':',
                    'keyServed:' + roomId + ':' + existing.senderKeyId + ':',
                    'delivered:' + roomId + ':' + existing.senderKeyId,
                ]) {
                    for (const name of await storage.keys(prefix)) await storage.delete(name);
                }
            }
            await storage.set(ownKeyName(roomId), next);
            await writeIndexLocked(roomId, next.senderKeyId, userId);
            return next;
        }

        // События уровня человека (signed-membership.md, 9.1): смена ключа участника (changed), log-mismatch, принятие нового
        // ключа проверяются во ВСЕХ общих комнатах, а не только в той, где они замечены. Проверка локальная (без сети): по
        // сохранённым V, списку сервера и журналу доставок собственного ключа каждой комнаты. Новый ключ уходит получателям
        // при следующем ensureRoomSession этой комнаты; до того он только создан - старый, известный подозреваемому, не живёт.
        async function rotateCommonRoomsLocked(exceptRoomId, personIds) {
            const rotated = [];
            const seen = new Set();
            for (const personId of personIds) {
                for (const roomId of await membership.roomsWithMemberLocked(Number(personId))) {
                    if (seen.has(roomId) || String(roomId) === String(exceptRoomId)) continue;
                    seen.add(roomId);
                    const own = await loadOwnSenderKeyLocked(roomId);
                    if (!own) continue;
                    const reason = await membership.journalReasonStoredLocked(roomId, own.senderKeyId, Number(userId));
                    if (!reason) continue;
                    await rotateRoomKeyLocked(roomId, await membership.currentRecipientsLocked(roomId, Number(userId)));
                    rotated.push({ roomId, reason });
                }
            }
            return rotated;
        }

        // После ротации нужно вызвать ensureRoomSession, чтобы разослать
        // новый ключ, — и сделать это ДО отправки сообщений новым ключом:
        // участникам, которых не было в комнате при создании ключа, key-share
        // несёт текущую позицию цепочки, более ранние итерации они не выведут.
        async function rotateRoomKey(roomId) {
            await ensureLocal();
            const next = await withLock(() => rotateRoomKeyLocked(roomId));
            return { senderKeyId: next.senderKeyId };
        }

        // Пора ли менять ключ комнаты (мягкий порог). script.js после отправки
        // запускает ensureRoomSession в фоне, и тот ротирует ключ до рассылки.
        async function roomKeyDue(roomId) {
            await ensureLocal();
            return withLock(async () => {
                const own = await loadOwnSenderKeyLocked(roomId);
                return Boolean(own) && ownKeyDue(own);
            });
        }

        async function hasRoomKey(roomId) {
            return Boolean(await storage.get(ownKeyName(roomId)));
        }

        function sharedMarkName(roomId, senderKeyId, peerId) {
            return 'sharedWith2:' + roomId + ':' + senderKeyId + ':' + peerId;
        }

        // Что клиент знает о составе из ответа GET participants (signed-membership.md, 7.2): свои сертификаты,
        // снимки к ним и сертификат приглашения. Всё разбирается строго: сервер недоверенный.
        function normalizeMembershipInfo(info, meId) {
            const certMap = membershipModules.client.parseCertItems(info && info.certs, new Set([meId]));
            const snaps = [];
            for (const item of info && Array.isArray(info.snaps) ? info.snaps : []) {
                const snap = Membership.fromB64(item && item.snap);
                const kind = Number(item && item.kind);
                const actorId = Number(item && item.actorId);
                if (snap && snap.length > 0 && Number.isSafeInteger(actorId) && (kind === 1 || kind === 3 || kind === 4)) snaps.push({ actorId, kind, snap });
            }
            return { certMap, snaps };
        }

        // Устанавливает/подтверждает мой Sender Key для комнаты, проверяет состав группы (signed-membership.md, 9.1),
        // сверяет его с запомненным и рассылает ключ ТОЛЬКО подтверждённым участникам, которым текущая версия ещё не
        // отправлена. info - ответ GET participants целиком: { certs, snaps, invite }; без него сертификатов у меня нет.
        async function ensureRoomSession(chatId, roomId, participants, info) {
            await ensureLocal();
            const me = Number(userId);
            const current = normalizeParticipants(participants);
            const empty = {
                newMembers: [], removedMembers: [], rotated: false, rotationReason: null, identityChanges: [], peers: 0, keyHolders: 0,
                members: [], unconfirmed: [], duplicateKeys: [], viewMismatch: false, viewIdsDiverged: false,
            };
            if (!current.some(p => p.id === me)) {
                return Object.assign({ ok: false, warnings: [{ reason: 'вы не участник этой комнаты' }] }, empty);
            }
            const others = current.filter(p => p.id !== me);

            // Закрепление ключей участников - до проверки состава (сеть и короткие секции блокировки).
            const { statuses, serverKnown } = await checkPeersWithServer(others.map(p => p.id));
            const changedIds = new Set(statuses.filter(s => s.status === 'changed').map(s => s.userId));

            // Сертификаты других участников - вне блокировки: тех, кого я ещё не подтвердил, и тех, чей подписавший вышел.
            const given = normalizeMembershipInfo(info, me);
            const certMap = new Map(given.certMap);
            for (const [subject, list] of await membership.fetchCerts(chatId, await membership.planCertFetch(roomId, current, me))) certMap.set(subject, list);
            if (info && Object.prototype.hasOwnProperty.call(info, 'invite')) await membership.noteServerInvite(roomId, info.invite);

            const membershipState = await withLock(async () => {
                const identity = await loadIdentityLocked();
                const meKeys = {
                    id: me, username: (current.find(p => p.id === me) || {}).username || '',
                    signPub: b64decode(identity.signPub), dhPub: b64decode(identity.dhPub),
                };
                const prevMembers = await storage.get('members:' + roomId);
                const pins = await membership.loadPins(others.map(p => p.id));
                // Проверка состава: V, removed, замыкание по сертификатам, якорь новичка, получатели (9.1, 9.2).
                const verdict = await membership.verifyLocked({
                    roomId, current, prevMembers: Array.isArray(prevMembers) ? prevMembers : null,
                    certMap, snaps: given.snaps, me: meKeys, pins, nowMs: now(),
                });
                // Получатели нового ключа с начала эпохи (entitled) - пары { id, memkey } на момент создания ключа, а не V.
                const entitledNow = verdict.recipients;
                const excludedNow = others.filter(p => pins.get(p.id) && pins.get(p.id).excluded).map(p => p.id);
                let own = await loadOwnSenderKeyLocked(roomId);
                let rotated = false;
                let rotationReason = null;
                if (!own) {
                    own = await newOwnSenderKeyState({ roomId, entitled: entitledNow, logExcluded: excludedNow });
                    await storage.set(ownKeyName(roomId), own);
                    // Свой ключ в индексе отправителей — до первой отправки.
                    await writeIndexLocked(roomId, own.senderKeyId, userId);
                } else if (!own.signingPrivateKey || !(await ownKeyBoundLocked(roomId, own))) {
                    // Состояние из очень старой версии без ключа подписи либо ключ, чей
                    // идентификатор не выведен из отправителя (создан до sealed sender):
                    // получатели такой SKDM не примут, поэтому ключ меняется.
                    await rotateRoomKeyLocked(roomId, entitledNow);
                    rotated = true;
                    rotationReason = 'upgrade';
                }
                let newMembers = [];
                let removedMembers = [];
                // Первый вызов для комнаты только запоминает состав: сравнивать
                // не с чем, и "новыми" оказались бы все.
                if (Array.isArray(prevMembers)) {
                    const knownIds = new Set(prevMembers.map(p => Number(p.id)));
                    const currentIds = new Set(current.map(p => p.id));
                    newMembers = current.filter(p => p.id !== me && !knownIds.has(p.id));
                    removedMembers = prevMembers
                        .filter(p => Number(p.id) !== me && !currentIds.has(Number(p.id)))
                        .map(p => ({ id: Number(p.id), username: typeof p.username === 'string' ? p.username : '' }));
                }
                // Ротация до рассылки по ЖУРНАЛУ ДОСТАВОК (9.1): получатель текущего ключа перестал быть адресатом - вышел,
                // выпал из V (changed), получил log-mismatch или сменил ключи. Отметки рассылки sharedWith2 решения не
                // определяют: сервер мог стереть их запросом ключа. Ключ, которого получатель не видел, ротировать незачем.
                if (!rotated) {
                    const ownNow = await loadOwnSenderKeyLocked(roomId);
                    const reason = ownNow
                        ? await membership.journalRotationReasonLocked(roomId, ownNow.senderKeyId, verdict.recipients, new Map(current.map(p => [p.id, p])), verdict.V, pins)
                        : null;
                    if (reason) {
                        await rotateRoomKeyLocked(roomId, entitledNow);
                        rotated = true;
                        rotationReason = reason;
                    }
                }
                // Плановая ротация: 100 сообщений или 7 дней. Делается здесь, до
                // рассылки, чтобы новый ключ ушёл тем же проходом, что и все остальные.
                if (!rotated && ownKeyDue(own)) {
                    await rotateRoomKeyLocked(roomId, entitledNow);
                    rotated = true;
                    rotationReason = 'scheduled';
                }
                await storage.set('members:' + roomId, current);
                // Имена для сообщений вышедших участников (sealed-sender.md, 9.5):
                // карта пополняется при каждом проходе и ушедших не теряет. Автора
                // сообщения сервер не называет, а список участников хранит только
                // текущих.
                await rememberMemberNamesLocked(roomId, current);
                return { newMembers, removedMembers, rotated, rotationReason, verdict };
            });
            const { verdict } = membershipState;
            const recipientIds = new Set(verdict.recipients.map(r => r.id));

            // Журнал ключей (7.3): собеседник с mismatch исключается из рассылки, а свой ключ комнаты ротируется,
            // если он мог получить текущий: решение по самому статусу — в состоянии ключа записано, кто был исключён
            // при его создании. Ротация идёт в каждой общей комнате при её ensureRoomSession.
            const logMismatchIds = new Set(await withLock(() => logExcludedIdsLocked(others.map(p => p.id))));
            let logRotated = false;
            if (logMismatchIds.size > 0) {
                logRotated = await withLock(async () => {
                    const ownNow = await loadOwnSenderKeyLocked(roomId);
                    const excludedAtCreation = new Set(ownNow && Array.isArray(ownNow.logExcluded) ? ownNow.logExcluded : []);
                    if ([...logMismatchIds].every(id => excludedAtCreation.has(id))) return false;
                    await rotateRoomKeyLocked(roomId, verdict.recipients);
                    return true;
                });
            }
            const logMismatches = [];
            // Те же события в остальных общих комнатах (9.1).
            const personEvents = [...changedIds, ...logMismatchIds];
            if (personEvents.length > 0) await withLock(() => rotateCommonRoomsLocked(roomId, personEvents));

            const warnings = [];
            const identityChanges = [];
            const shares = [];
            const marks = [];
            const noteChanged = (peer) => {
                identityChanges.push({ userId: peer.id, username: peer.username });
                warnings.push({ userId: peer.id, reason: REASON_IDENTITY_CHANGED });
            };
            // Предупреждения о составе: неподтверждённые и совпадающие ключи (signed-membership.md, 10).
            for (const group of verdict.duplicateKeys) warnings.push({ userIds: group.ids.slice(), reason: 'duplicate-keys' });

            for (const peer of others) {
                if (changedIds.has(peer.id)) { noteChanged(peer); continue; }
                if (logMismatchIds.has(peer.id)) {
                    logMismatches.push({ userId: peer.id, username: peer.username });
                    warnings.push({ userId: peer.id, reason: REASON_LOG_MISMATCH });
                    continue;
                }
                // У собеседника нет identity на сервере — bundle заведомо 404.
                // Не запрашиваем его: каждый запрос bundle расходует лимит на
                // пару (5 в час), и после нескольких открытий комнаты ключ не
                // ушёл бы даже тогда, когда собеседник E2EE настроит.
                if (serverKnown && !serverKnown.has(peer.id)) {
                    warnings.push({ userId: peer.id, reason: REASON_NOT_READY });
                    continue;
                }
                // Ключ комнаты получают только подтверждённые участники (П1): остальные остаются в unconfirmed, без
                // запроса bundle и без отметки рассылки.
                if (!recipientIds.has(peer.id)) {
                    warnings.push({ userId: peer.id, reason: 'unconfirmed-member' });
                    continue;
                }
                const own = await storage.get(ownKeyName(roomId));
                if (own && await storage.get(sharedMarkName(roomId, own.senderKeyId, peer.id))) continue;
                let prepared;
                try {
                    prepared = await prepareShareForPeer(roomId, peer.id);
                } catch (err) {
                    warnings.push({ userId: peer.id, reason: err.message });
                    continue;
                }
                if (prepared.changed) { noteChanged(peer); continue; }
                if (prepared.warning) { warnings.push({ userId: peer.id, reason: prepared.warning }); continue; }
                shares.push(prepared.share);
                marks.push(sharedMarkName(roomId, prepared.senderKeyId, peer.id));
            }

            let ok = true;
            for (let i = 0; i < shares.length; i += SHARE_BATCH) {
                let res = null;
                try { res = await transport.postKeyShares(chatId, shares.slice(i, i + SHARE_BATCH)); } catch { res = null; }
                if (!res || !res.data || res.data.success !== true) {
                    ok = false;
                    warnings.push({ reason: 'сервер отклонил отправку key-share' });
                    continue;
                }
                // Отметка ставится только после того, как сервер принял
                // share, — иначе при сбое ключ так и не ушёл бы повторно.
                const done = marks.slice(i, i + SHARE_BATCH);
                await withLock(async () => { for (const name of done) await storage.set(name, true); });
            }

            // Повторный допуск после ухода подписавшего (5.5): задачи, срок которых наступил. Сбой публикации не
            // мешает сессии комнаты: задача остаётся в очереди и повторится.
            let revouchPublished = [];
            if (verdict.revouchDue.length > 0) {
                try { revouchPublished = await membership.publishDueRevouches(chatId, roomId, verdict.revouchDue); } catch (err) { console.warn('E2EE: повторный допуск не опубликован:', err); }
            }

            // Сколько остальных участников получили ТЕКУЩИЙ ключ (по отметкам об успешной
            // рассылке). Если участники есть, а ключа нет ни у кого, отправка в комнату
            // бессмысленна: script.js в этом случае её блокирует.
            const ownNow = await storage.get(ownKeyName(roomId));
            let keyHolders = 0;
            if (ownNow) {
                for (const peer of others) {
                    if (await storage.get(sharedMarkName(roomId, ownNow.senderKeyId, peer.id))) keyHolders++;
                }
            }

            return {
                ok, warnings,
                newMembers: membershipState.newMembers,
                removedMembers: membershipState.removedMembers,
                rotated: membershipState.rotated || logRotated,
                rotationReason: membershipState.rotationReason || (logRotated ? 'log-mismatch' : null),
                identityChanges,
                logMismatches,
                peers: others.length,
                keyHolders,
                members: verdict.members,
                unconfirmed: verdict.unconfirmed,
                duplicateKeys: verdict.duplicateKeys,
                anchor: verdict.anchor,
                revouchPublished,
                viewMismatch: false,
                viewIdsDiverged: false,
            };
        }

        // Забирает и применяет ожидающие key-share для этого чата.
        async function syncKeyShares(chatId, roomId) {
            await ensureLocal();
            const res = await transport.getKeyShares(chatId);
            const list = res && res.data && Array.isArray(res.data.shares) ? res.data.shares : [];
            let applied = 0, failed = 0;
            const changes = [];
            const warnings = [];
            const installed = new Set();
            for (const item of list) {
                const senderId = Number(item && item.senderId);
                let result;
                try {
                    result = await applyShare(roomId, senderId, item && item.ciphertext, keyId => installed.add(keyId));
                } catch { result = 'failed'; }
                if (result === 'applied') applied++;
                else if (result === 'changed') { if (!changes.includes(senderId)) changes.push(senderId); }
                else {
                    failed++;
                    if (result === 'unbound') warnings.push({ userId: senderId, reason: REASON_KEY_UNBOUND });
                }
            }
            await settleKeyRequests(chatId, roomId, Array.from(installed));
            // Головы журнала из принятых SKDM сверяются в фоне.
            if (ktOn() && applied > 0) ktLog.runKtChecks().catch(err => console.warn('E2EE: сверка голов журнала не удалась:', err));
            const result = { applied, failed, identityChanges: changes };
            // Сверка взглядов на состав и ключи (9.6): вне блокировки, после обработки key-share. Тревога информативная:
            // отправка не блокируется.
            if (applied > 0) {
                try {
                    const views = await membership.runViewChecks(roomId, await myKeys());
                    if (views.viewMismatch) result.viewMismatch = true;
                    if (views.viewIdsDiverged) result.viewIdsDiverged = true;
                } catch (err) {
                    console.warn('E2EE: сверка взглядов не удалась:', err);
                }
            }
            // Предупреждения — только когда есть о чём предупреждать.
            if (warnings.length > 0) result.warnings = warnings;
            return result;
        }

        // ---- Запрос ключа (план криптографии, раздел 5) ----
        //
        // Лечит потерю key-share: сообщение пришло, а Sender Key его автора у нас
        // нет (share не дошёл, вытеснен из очереди, в T3.2 — одноразовый PQ-prekey
        // «сожжён» без применённого share). Клиент просит ключ по id из конверта,
        // не называя отправителя (после 4.3 его и нет), владелец ключа переотправляет
        // его с начала эпохи, если мы имели на неё право. Для архивных ключей
        // (ротированных) переотправки нет.

        const keyRequestName = (roomId, keyId) => 'keyReq:' + roomId + ':' + keyId;
        const keyServedName = (roomId, keyId, requesterId) => 'keyServed:' + roomId + ':' + keyId + ':' + requesterId;

        function envelopeKeyId(text) {
            let envelope;
            try { envelope = JSON.parse(text); } catch { return null; }
            return envelope && typeof envelope === 'object' && isCanonicalKeyId(envelope.senderKeyId) ? envelope.senderKeyId : null;
        }

        // envelopes — тексты конвертов, которые не удалось расшифровать из-за
        // 'no-sender-key' или 'stale-sender-key'. Один и тот же ключ запрашивается
        // не чаще раза в час; не больше MAX_KEY_REQUEST_IDS ключей за раз.
        // → { requested: сколько ключей запрошено }
        async function requestRoomKeys(chatId, roomId, envelopes) {
            await ensureLocal();
            const ids = [];
            for (const text of Array.isArray(envelopes) ? envelopes : []) {
                const id = envelopeKeyId(text);
                if (id && !ids.includes(id)) ids.push(id);
                if (ids.length >= MAX_KEY_REQUEST_IDS) break;
            }
            const t = now();
            const fresh = await withLock(async () => {
                const out = [];
                for (const id of ids) {
                    const last = await storage.get(keyRequestName(roomId, id));
                    if (Number.isFinite(last) && t - last < KEY_REQUEST_COOLDOWN_MS) continue;
                    await storage.set(keyRequestName(roomId, id), t);
                    out.push(id);
                }
                return out;
            });
            if (fresh.length === 0) return { requested: 0 };
            let ok = false;
            try {
                const res = await transport.postKeyRequests(chatId, fresh);
                ok = Boolean(res && res.data && res.data.success === true);
            } catch { ok = false; }
            if (!ok) {
                // Не дошло (сеть, лимит сервера): отметки снимаем, чтобы повторить сразу, как станет можно.
                await withLock(async () => { for (const id of fresh) await storage.delete(keyRequestName(roomId, id)); });
                return { requested: 0 };
            }
            return { requested: fresh.length };
        }

        // Ключи из key-share дошли: свои запросы этих ключей снимаем (локально и на сервере).
        async function settleKeyRequests(chatId, roomId, installedIds) {
            if (installedIds.length === 0) return;
            const fulfilled = await withLock(async () => {
                const out = [];
                for (const id of installedIds) {
                    if ((await storage.get(keyRequestName(roomId, id))) === null) continue;
                    await storage.delete(keyRequestName(roomId, id));
                    out.push(id);
                }
                return out;
            });
            if (fulfilled.length === 0) return;
            try { await transport.postKeyRequestsDone(chatId, fulfilled.slice(0, MAX_KEY_REQUEST_IDS)); } catch { /* срок строки на сервере — 7 суток */ }
        }

        // Владелец отвечает на запросы ключа. requests — [{ fromUserId, senderKeyIds }]
        // (событие e2eeKeyRequest или ответ GET); не переданы — берутся с сервера
        // (владелец был офлайн). Если среди запрошенных есть МОЙ ТЕКУЩИЙ ключ и
        // запросил участник комнаты, снимается отметка «разослано» — следующий
        // ensureRoomSession переотправит ему ключ (с начала эпохи, если он имеет на
        // неё право). Чужие и архивные ключи игнорируются; повторная выдача одного
        // ключа одному участнику — не чаще раза в 10 минут.
        // → { resend: [id участников] }; при непустом списке нужен ensureRoomSession.
        async function answerKeyRequests(chatId, roomId, requests) {
            await ensureLocal();
            let list = requests;
            if (!Array.isArray(list)) {
                let res = null;
                try { res = await transport.getKeyRequests(chatId); } catch { res = null; }
                list = res && res.data && res.data.success === true && Array.isArray(res.data.requests) ? res.data.requests : [];
            }
            const t = now();
            return withLock(async () => {
                const resend = [];
                const own = await loadOwnSenderKeyLocked(roomId);
                if (!own) return { resend };
                // Ответ - только текущим получателям ключа (signed-membership.md, 9.4): запрос от неподтверждённого, от
                // участника с log-mismatch или от того, кого нет в списке, не снимает отметку и не расходует кулдаун.
                const members = (await membership.currentRecipientsLocked(roomId, Number(userId))).map(r => r.id);
                for (const request of list) {
                    const from = Number(request && request.fromUserId);
                    if (!Number.isSafeInteger(from) || from <= 0 || from === Number(userId) || !members.includes(from)) continue;
                    const ids = request && Array.isArray(request.senderKeyIds) ? request.senderKeyIds : [];
                    if (!ids.includes(own.senderKeyId)) continue;
                    const served = keyServedName(roomId, own.senderKeyId, from);
                    const last = await storage.get(served);
                    if (Number.isFinite(last) && t - last < KEY_RESEND_COOLDOWN_MS) continue;
                    await storage.set(served, t);
                    await storage.delete(sharedMarkName(roomId, own.senderKeyId, from));
                    if (!resend.includes(from)) resend.push(from);
                }
                return { resend };
            });
        }

        // ---- Шифрование/расшифровка сообщений чата ----

        // ---- Записи о версиях сообщений (раздел 9.3 контракта) ----
        //
        // edit:<комната>:<mid> = { author, ts, keyId, it } — последняя принятая
        // версия сообщения с этим mid: автор (числовой id пользователя), ts,
        // senderKeyId и итерация конверта. Запись создаётся при первой принятой
        // расшифровке сообщения (оригинала или правки), а не только правок: иначе
        // первая правка не с чем было бы сверять. По записи на mid — запись одной
        // версии не переписывает всю карту. Предел MAX_EDIT_ENTRIES на комнату,
        // вытесняется запись с наименьшим ts: вытесненный mid теряет защиту от
        // отката и подмены автора. Функции *Locked — только внутри withLock.
        const editPrefix = (roomId) => 'edit:' + roomId + ':';
        const editName = (roomId, mid) => editPrefix(roomId) + mid;
        // Сколько записей в комнате было при последнем пересчёте. Чужая вкладка
        // может дописать своих — тогда при достижении предела пересчитаем по хранилищу.
        const editCounts = new Map();

        async function writeEditEntryLocked(roomId, mid, entry) {
            await storage.set(editName(roomId, mid), entry);
            let count = editCounts.has(roomId) ? editCounts.get(roomId) + 1 : (await storage.keys(editPrefix(roomId))).length;
            if (count > MAX_EDIT_ENTRIES) {
                const names = await storage.keys(editPrefix(roomId));
                count = names.length;
                if (count > MAX_EDIT_ENTRIES) {
                    const entries = [];
                    for (const name of names) {
                        const item = await storage.get(name);
                        entries.push({ name, ts: item && Number.isFinite(item.ts) ? item.ts : -1 });
                    }
                    entries.sort((a, b) => a.ts - b.ts);
                    for (const victim of entries.slice(0, count - MAX_EDIT_ENTRIES)) await storage.delete(victim.name);
                    count = MAX_EDIT_ENTRIES;
                }
            }
            editCounts.set(roomId, count);
        }

        // Бросает E2eeError('needs-room-session'), если ключ комнаты исчерпал жёсткий
        // порог ротации: script.js ждёт ensureRoomSession и повторяет один раз.
        //
        // options: { messageId, edit? }. messageId обязателен (строка по формату
        // 6.1: id сообщения, который клиент выбрал ДО шифрования и отправит на
        // сервер как clientMessageId), иначе E2eeError('protocol'): содержимое
        // без mid получатель всё равно отвергнет ('no-mid'). ts = now() для нового
        // сообщения; для правки (edit:true) — max(now(), ts известной версии + 1),
        // чтобы правка при отстающих часах не выглядела старой ('stale-edit').
        async function encryptOutgoing(roomId, content, options = {}) {
            const messageId = options ? options.messageId : undefined;
            if (!isValidMessageId(messageId)) {
                throw new E2eeError('protocol', 'E2EE: не указан идентификатор сообщения (messageId)');
            }
            const edit = Boolean(options.edit);
            await ensureLocal();
            let ts = Math.max(0, Math.trunc(now()));
            if (edit) {
                const known = await withLock(() => storage.get(editName(roomId, messageId)));
                if (known && Number.isSafeInteger(known.ts)) ts = Math.max(ts, known.ts + 1);
            }
            const padded = padMessage(utf8encode(JSON.stringify(encodeContent(content, { mid: messageId, ts, edit }))));
            const { state, iteration, messageKey } = await withLock(async () => {
                const st = await loadOwnSenderKeyLocked(roomId);
                if (!st) throw new Error('E2EE: для этой комнаты ещё не создан Sender Key — вызовите ensureRoomSession()');
                if (!st.signingPrivateKey) throw new Error('E2EE: ключ комнаты устарел — вызовите ensureRoomSession()');
                // Жёсткая граница ротации (200 сообщений или 8 дней): мягкая — в
                // ensureRoomSession; если она не состоялась, дальше шифровать нельзя.
                if (ownKeyExpired(st)) {
                    throw new E2eeError('needs-room-session', 'E2EE: ключ комнаты пора сменить — вызовите ensureRoomSession()');
                }
                const it = st.nextIteration;
                const step = await chainStep(b64decode(st.chainKey));
                st.cachedKeys[it] = b64encode(step.messageKey); // сохраняем и для собственного отображения истории
                st.keyTimes[it] = hourOf(now());
                st.chainKey = b64encode(step.nextChainKey);
                st.nextIteration = it + 1;
                trimChain(st);
                await storage.set(ownKeyName(roomId), st);
                return { state: st, iteration: it, messageKey: step.messageKey };
            });

            const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-msgkey-v2', 32);
            const { iv, ct } = await aesGcmEncrypt(aesKey, padded, msgAadV3(roomId, userId, state.senderKeyId));
            const keyIdBytes = decodeFixed(state.senderKeyId, 16);
            if (!isU32(Number(roomId)) || !keyIdBytes) throw new Error('E2EE: некорректный идентификатор комнаты или ключа отправителя');
            const sig = await sign(state.signingPrivateKey, sigInputV3(Number(roomId), keyIdBytes, iteration, iv, ct));
            const envelope = JSON.stringify({
                v: 3, alg: 'senderkey-v3',
                senderKeyId: state.senderKeyId,
                iteration,
                iv: b64encode(iv), ct: b64encode(ct),
                sig: b64encode(sig),
            });
            if (envelope.length > MAX_ENVELOPE_CHARS) throw new Error('E2EE: сообщение слишком длинное для шифрования');
            return envelope;
        }

        // Расшифровка сообщения комнаты (sealed-sender.md, 9.3). Автора в строке
        // сообщения нет: его находит клиент по senderKeyId из конверта через
        // индекс отправителей skIndex, пополняемый только из key-share, принятых по
        // попарному каналу (applyShare). senderKeyId привязан к отправителю, поэтому
        // кандидат всегда один; подсказка сервера об авторе в расшифровку не
        // попадает — production-код передаёт senderIdHint = null, непустую подсказку
        // используют только юнит-тесты (не равна найденному отправителю — 'sender-mismatch').
        //
        // messageId (id сообщения на сервере, строка) нужен для защиты от повтора
        // и подмены: пара (senderKeyId, iteration) привязывается к первому
        // messageId, с которым её расшифровали, и под другим id конверт не
        // принимается; mid внутри содержимого обязан равняться messageId.
        // Правка — новая итерация для того же messageId, это легально.
        //
        // Порядок проверок (все до любой записи в хранилище):
        //   1. форма конверта (v3, senderkey-v3; v1 и v2 больше нет)       → 'bad-envelope'
        //   2. запись skIndex                                              → 'no-sender-key'
        //   3. подсказка ≠ отправителю                                     → 'sender-mismatch';
        //      надгробие (ключ удалён)                                     → 'history-not-kept' | 'key-expired'
        //   4. запись ключа (текущая или архив)                            → 'stale-sender-key';
        //      подпись                                                     → 'bad-signature';
        //      цепочка закрыта (final)                                     → 'stale-sender-key';
        //      далеко вперёд (MAX_SKIP)                                    → 'too-far-ahead';
        //      итерация уже привязана к другому id                         → 'replay';
        //      ключ сообщения выводится на КОПИИ состояния                 → 'history-not-kept' | 'key-expired' | 'no-message-key';
        //      AEAD с AAD отправителя                                      → 'decrypt-failed'; дополнение/разбор → 'bad-plaintext'
        //   5. раздел 9.4 контракта порядка: нет mid — 'no-mid'; mid ≠ id — 'id-mismatch'; ts — 'bad-plaintext';
        //      запись о версии: другой автор — 'sender-mismatch'; правка — 'stale-edit', если ts не больше известного;
        //      оригинал с другой итерацией — 'id-mismatch'
        //   6. только теперь запись: продвинутая цепочка, seen, запись о версии.
        // Результат: { ok:true, text, file?, senderId, ts, edit } или { ok:false, reason }.
        async function decryptIncoming(roomId, senderIdHint, text, messageId) {
            const bad = { ok: false, reason: 'bad-envelope' };
            let envelope;
            try { envelope = JSON.parse(text); } catch { return bad; }
            if (!envelope || typeof envelope !== 'object') return bad;
            if (envelope.v !== 3 || envelope.alg !== 'senderkey-v3') return bad;
            if (!Number.isInteger(envelope.iteration) || envelope.iteration < 0 || envelope.iteration > 0xFFFFFFFF) return bad;
            if (!isCanonicalKeyId(envelope.senderKeyId)) return bad;
            const iv = decodeFixed(envelope.iv, 12);
            const sig = decodeFixed(envelope.sig, 64);
            const ct = typeof envelope.ct === 'string' ? b64decode(envelope.ct) : null;
            if (!iv || !sig || !ct || ct.length < 16) return bad;
            const iteration = envelope.iteration;
            const keyId = envelope.senderKeyId;
            const room = Number(roomId);
            if (!isU32(room)) return bad;
            const sigInput = sigInputV3(room, decodeFixed(keyId, 16), iteration, iv, ct);
            const boundId = messageId === undefined || messageId === null ? null : String(messageId);
            const hint = senderIdHint === undefined || senderIdHint === null ? null : Number(senderIdHint);

            await ensureLocal();
            return withLock(async () => {
                const entry = await readIndexLocked(roomId, keyId);
                if (!entry) return { ok: false, reason: 'no-sender-key' };
                const senderId = entry.sender;
                if (hint !== null && hint !== senderId) return { ok: false, reason: 'sender-mismatch' };
                const state = await readStateLocked(roomId, senderId);
                if (entry.gone) return { ok: false, reason: await goneKeyReasonLocked(roomId, state) };
                if (!state) return { ok: false, reason: 'no-sender-key' };

                // Какая запись отвечает за ключ из конверта: текущая или, если
                // сообщение отправлено ДО ротации, запись архива (одно
                // обращение по senderKeyId, независимо от числа архивов).
                let rec;
                let saveRec;
                if (state.senderKeyId === keyId) {
                    rec = state;
                    saveRec = (next) => storage.set(stateName(roomId, senderId), next);
                } else {
                    const archiveKey = archiveName(roomId, senderId, keyId);
                    rec = await storage.get(archiveKey);
                    if (!rec) {
                        // В индексе архива есть, а записи нет — ключ удалён намеренно
                        // (режим «не хранить историю», таймер комнаты, бюджет).
                        if (archiveHas(state, keyId)) return { ok: false, reason: await goneKeyReasonLocked(roomId, state) };
                        return { ok: false, reason: 'stale-sender-key' };
                    }
                    saveRec = (next) => storage.set(archiveKey, next);
                }

                if (!(await verify(b64decode(rec.signingPublicKey), sig, sigInput))) return { ok: false, reason: 'bad-signature' };
                // Закрытая цепочка (отправитель сообщил final): дальше этой
                // итерации ключ не использовался, такой конверт — не от него.
                if (rec.final !== undefined && rec.final !== null && iteration > rec.final) return { ok: false, reason: 'stale-sender-key' };
                const hasChain = Boolean(rec.chainKey) && Number.isInteger(rec.nextIteration);
                if (hasChain && iteration - rec.nextIteration > MAX_SKIP) return { ok: false, reason: 'too-far-ahead' };

                const seenKey = seenName(roomId, senderId, keyId);
                const seen = (await storage.get(seenKey)) || {};
                const bound = Object.prototype.hasOwnProperty.call(seen, iteration) ? seen[iteration] : undefined;
                if (boundId !== null && bound !== undefined && bound !== boundId) return { ok: false, reason: 'replay' };

                // Ключ сообщения выводится на КОПИИ записи: пока конверт не прошёл
                // AEAD и проверки 9.4, хранилище не пишется (иначе сервер мог бы
                // двигать чужую цепочку конвертами, которые потом не пройдут).
                // Цепочка продвигается только для новых итераций — при простом
                // повторном показе истории хранилище не переписывается.
                let messageKey = null;
                let advanced = null;
                if (hasChain && iteration >= rec.nextIteration) {
                    advanced = Object.assign({}, rec, { cachedKeys: Object.assign({}, rec.cachedKeys), keyTimes: Object.assign({}, rec.keyTimes || {}) });
                    messageKey = await getOrDeriveMessageKey(advanced, iteration, hourOf(now()));
                } else if (rec.cachedKeys[iteration]) {
                    messageKey = b64decode(rec.cachedKeys[iteration]);
                }
                if (!messageKey) return { ok: false, reason: missingKeyReason(rec, iteration) };

                let content;
                try {
                    const aesKey = await hkdf(messageKey, ZERO32, 'nyxo-e2ee-msgkey-v2', 32);
                    const pt = await aesGcmDecrypt(aesKey, iv, ct, msgAadV3(roomId, senderId, keyId));
                    const body = unpadMessage(pt);
                    let decoded = null;
                    if (body) {
                        try { decoded = decodeContent(JSON.parse(utf8decode(body))); } catch { decoded = null; }
                    }
                    if (!decoded) return { ok: false, reason: 'bad-plaintext' };
                    content = decoded;
                } catch {
                    return { ok: false, reason: 'decrypt-failed' };
                }

                // ---- Проверки получателя 9.4: до любой записи ----
                if (content.mid === undefined || content.mid === null) return { ok: false, reason: 'no-mid' };
                if (boundId === null || String(content.mid) !== boundId) return { ok: false, reason: 'id-mismatch' };
                if (!Number.isSafeInteger(content.ts) || content.ts < 0) return { ok: false, reason: 'bad-plaintext' };
                const entryName = editName(roomId, boundId);
                const known = await storage.get(entryName);
                let newEntry = null;
                if (!known) {
                    newEntry = { author: senderId, ts: content.ts, keyId, it: iteration };
                } else if (Number(known.author) !== senderId) {
                    return { ok: false, reason: 'sender-mismatch' };
                } else if (known.keyId === keyId && known.it === iteration) {
                    // Повторный показ той же версии: запись не меняется.
                } else if (content.edit) {
                    if (!(content.ts > known.ts)) return { ok: false, reason: 'stale-edit' };
                    newEntry = { author: senderId, ts: content.ts, keyId, it: iteration };
                } else {
                    return { ok: false, reason: 'id-mismatch' };
                }

                // ---- Запись: продвинутая цепочка, seen (как раньше), запись о версии ----
                if (advanced) await saveRec(advanced);
                if (bound === undefined) {
                    seen[iteration] = boundId;
                    trimNumericMap(seen, MAX_SEEN_PER_KEY);
                    await storage.set(seenKey, seen);
                }
                if (newEntry) await writeEditEntryLocked(roomId, boundId, newEntry);
                const result = { ok: true, text: content.text };
                if (content.file) result.file = content.file;
                result.senderId = senderId;
                result.ts = content.ts;
                result.edit = content.edit;
                // Отправитель вне V: SKDM принят, но сообщения помечаются. Флаг вычисляется при каждой расшифровке по
                // текущему V, а не хранится: после подтверждения пометка исчезает без перешифровки (9.4).
                if (!(await membership.isTrustedMember(roomId, senderId))) result.unverifiedSender = true;
                return result;
            });
        }

        // ---- Состав группы: публичные методы (обёртки над клиентом состава) ----

        async function noteRoomCreated(roomId, username) { await ensureLocal(); return membership.noteRoomCreated(roomId, username); }
        async function signApproval(roomId, applicant) { await ensureLocal(); return membership.signApproval(roomId, applicant); }
        async function signInvite(roomId, options) { await ensureLocal(); return membership.signInvite(roomId, options); }
        async function getInviteSecret(roomId, serverInvite) { await ensureLocal(); return membership.getInviteSecret(roomId, serverInvite); }
        async function dropInviteSecret(roomId) { await ensureLocal(); return membership.dropInviteSecret(roomId); }
        async function prepareJoin(roomId, options) { await ensureLocal(); return membership.prepareJoin(roomId, options); }
        async function completeJoin(roomId, inviteSnap) { await ensureLocal(); return membership.completeJoin(roomId, inviteSnap); }
        async function cancelJoinIntent(roomId) { await ensureLocal(); return membership.cancelJoinIntent(roomId); }
        async function getJoinIntent(roomId) { await ensureLocal(); return membership.getJoinIntent(roomId); }
        async function trustMember(roomId, userId) { await ensureLocal(); return membership.trustMember(roomId, userId); }
        async function vouchForMember(chatId, roomId, userId) { await ensureLocal(); return membership.vouchForMember(chatId, roomId, userId); }
        async function getMembers(roomId) { await ensureLocal(); return membership.getMembers(roomId); }
        async function nextRevouchDueMs(roomId) { await ensureLocal(); return membership.nextRevouchDueMs(roomId); }
        async function runViewChecks(roomId) {
            await ensureLocal();
            return membership.runViewChecks(roomId, await myKeys());
        }

        // Публичный API клиента: по одному имени в строке, группы разделены —
        // новый метод добавляется в свою группу (и в test/e2ee-api.test.js).
        return {
            // Инициализация и пользователь
            init,
            probeSupport,
            setUserId,

            // Комнаты: Sender Key и key-share
            ensureRoomSession,
            syncKeyShares,
            hasRoomKey,
            rotateRoomKey,

            // Состав группы: подписи, приглашения, вход, подтверждение участников (signed-membership.md, 10)
            noteRoomCreated,
            signApproval,
            signInvite,
            getInviteSecret,
            dropInviteSecret,
            prepareJoin,
            completeJoin,
            cancelJoinIntent,
            getJoinIntent,
            trustMember,
            vouchForMember,
            getMembers,
            runViewChecks,
            nextRevouchDueMs,

            // Комнаты: ротация ключа и запрос ключа
            roomKeyDue,
            requestRoomKeys,
            answerKeyRequests,

            // Комнаты: хранение ключей на устройстве (архив, срок, бюджет)
            maintainRoomKeys,
            setRoomPolicy,

            // Комнаты: «Не хранить историю на устройстве»
            setRoomHistoryMode,
            getRoomHistoryMode,
            forgetRoomHistory,
            forgetAllNoHistoryRooms,

            // Комнаты: локальная очистка при выходе и имена участников
            forgetRoom,
            getRoomMemberNames,

            // Сообщения и файлы
            encryptOutgoing,
            decryptIncoming,
            encryptFile,
            decryptFile,

            // Identity собеседников и код безопасности
            checkPeerIdentities,
            getPeerIdentityStatus,
            getSafetyNumber,
            markPeerVerified,
            acceptPeerIdentityChange,

            // Прозрачность ключей
            checkTransparency,
            runKtChecks,
            getPeerTransparency,
            overrideLogMismatch,
            checkApplicantKey,
            getTransparencyAlerts,
            dismissTransparencyAlerts,
            ackSelfEntries,
            getPendingLogKey,
            acceptLogKey,
            startTransparency,
            stopTransparency,
        };
    }

    // Экспорт модуля: по одному имени в строке, группы разделены.
    return {
        // Клиент
        createClient,

        // Хранилища и транспорт (внедряются в createClient)
        MemoryStorage,
        makeIndexedDbStorage,
        makeFetchTransport,

        // Очистка локальных данных (выход с удалением данных, удаление аккаунта)
        deleteLocalData,

        // Ошибки (пока бросает только encryptOutgoing: 'protocol' без messageId)
        E2eeError,
        ERROR_CODES,

        // Для тестов
        _internal: {
            // Кодирование
            b64encode,
            b64decode,
            bytesEqual,

            // Дополнение (Padmé) и размеры
            padmeLength,
            padMessage,
            unpadMessage,
            filePaddedLength,

            // Код безопасности
            computeSafetyNumber,

            // Идентификатор ключа отправителя (привязан к комнате, отправителю и ключу подписи)
            deriveSenderKeyId,

            // Проверка подписи Ed25519 (строгая, единственная в файле) и разбор ключа подписи из чужого ввода
            verify,
            canonicalSigningKey,

            // Разбор SKDM (поле ext)
            parseSkdm,
            parseSkdmExt,
            parseKtGossip,
            buildSkdm,
            MAX_EXT_CHARS,

            // Пределы и сроки
            MAX_SKIP,
            MAX_PW_SKIP,
            MAX_EDIT_ENTRIES,
            MAX_KEYS_PER_CHAIN,
            MAX_KEYS_PER_ROOM,
            MAX_ARCHIVE_INDEX,
            MAX_ARCHIVE_TOMBSTONES,
            ROTATE_AFTER_MESSAGES,
            ROTATE_AFTER_MS,
            FORCE_ROTATE_AFTER_MESSAGES,
            FORCE_ROTATE_AFTER_MS,
            ARCHIVE_CHAIN_MAX_AGE_MS,
            KEY_EXPIRY_GRACE_MS,
            PREKEY_ROTATE_MS,
            PREKEY_RETAIN_MS,
            LOW_WATER_PQ_OPK,
            TOPUP_PQ_OPK,
            PQ_OPK_BATCH,
            PQ_OPK_REFRESH_MS,

            // Размеры
            MSG_PAD_MIN,
            FILE_PAD_MIN,
            MAX_ENVELOPE_CHARS,
            MAX_SHARE_CHARS,
            SHARE_BATCH,
        },
    };
});
