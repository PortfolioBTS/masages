// Правила обязательного E2EE на клиенте (R7, план криптографии, раздел 3).
//
// Выключателя шифрования нет: в комнате сообщение уходит только зашифрованным,
// а открытым текстом — только в чат с ботом, номер которого клиент запомнил при
// создании аккаунта (ответ регистрации, поле botChatId), а не по признаку от
// сервера: недоверенный сервер мог бы назвать «ботом» любой чат. Функции здесь
// чистые, без DOM и сети: файл исполняется и в браузере (window.NyxoE2eePolicy),
// и в Node (test/e2ee-policy.test.js).
//
//   parseBotChatId(raw)             — номер чата с ботом из localStorage или null;
//   plaintextAllowed(botChatId, chatId, roomId)
//                                   — можно ли отправить в чат открытый текст;
//   sessionBlock(session)           — результат ensureRoomSession: нужно ли
//                                     прервать отправку (ключ не дошёл никому);
//   replyQuoteTrusted(serverReplyTo, result)
//                                   — совпала ли цитата сервера с подписанным id ответа;
//   initErrorReason(err)            — причина недоступности шифрования по err.code;
//   initErrorRetryable(err)         — есть ли смысл в «Повторить»;
//   composerView(state)             — что показать под полем ввода и в шапке.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoE2eePolicy = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Номер чата с ботом: положительное целое. Строка вроде "12abc" или "1e3" не
    // подходит — в хранилище её мог записать кто угодно.
    function parseBotChatId(raw) {
        if (typeof raw !== 'string' && typeof raw !== 'number') return null;
        const text = String(raw);
        if (!/^[1-9]\d{0,9}$/.test(text)) return null;
        const id = Number(text);
        return Number.isSafeInteger(id) ? id : null;
    }

    // Открытый текст — только в чат без комнаты, и только в тот, что запомнен как чат с ботом.
    function plaintextAllowed(botChatId, chatId, roomId) {
        if (roomId) return false;
        const bot = parseBotChatId(botChatId);
        const chat = parseBotChatId(chatId);
        return bot !== null && chat !== null && bot === chat;
    }

    // Причины недоступности шифрования по E2eeError.code (public/e2ee.js, ERROR_CODES).
    const INIT_REASONS = Object.freeze({
        unsupported: 'браузер не поддерживает нужное шифрование (X25519, Ed25519), обновите его',
        storage: 'браузер не даёт сохранить ключи шифрования (приватное окно или запрет хранилища)',
        network: 'нет связи с сервером ключей',
        server: 'сервер ключей не отвечает',
        protocol: 'сервер ключей ответил в неожиданном формате',
    });
    const INIT_REASON_DEFAULT = 'не удалось подготовить ключи шифрования';

    function initErrorReason(err) {
        const code = err && err.code;
        return Object.prototype.hasOwnProperty.call(INIT_REASONS, code) ? INIT_REASONS[code] : INIT_REASON_DEFAULT;
    }

    // «Повторить» — когда причина может пройти сама или после починки сервера;
    // для старого браузера и закрытого хранилища повтор ничего не изменит.
    function initErrorRetryable(err) {
        const code = err && err.code;
        return code !== 'unsupported' && code !== 'storage';
    }

    const BLOCK_TEXTS = Object.freeze({
        'session-failed': 'Не удалось подготовить ключи группы — сообщение не отправлено. Проверьте соединение и повторите.',
        'keys-not-delivered': 'Ключ шифрования не удалось передать ни одному участнику — сообщение не отправлено, иначе его никто не смог бы прочитать. Повторите попытку.',
        'keys-withheld': 'Ключ шифрования некому передать: участники группы не подтверждены или у них изменился ключ. Сообщение не отправлено, иначе его никто не смог бы прочитать. Подтвердите участников в окне «Участники и ключи» и повторите.',
    });

    // Результат ensureRoomSession → null (отправлять можно) или { code, text }.
    //   * сессию подготовить не удалось (null) — без ключа комнаты шифровать нечем;
    //   * ключ не дошёл ни до одного участника при ok === false и других участниках
    //     в комнате — блокируем; если не дошёл лишь до части, отправляем (о части
    //     предупреждает handleRoomSessionResult);
    //   * ключ не получил никто, а часть участников с ключами на сервере осталась без него
    //     из-за статуса (не подтверждены, сменили ключ, расхождение с журналом) — блокируем
    //     независимо от ok: рассылка не падала, адресатов просто нет, и сообщение не прочитает
    //     никто, в том числе подтверждённый позже (signed-membership.md, 9.4);
    //   * ok === true, но ключа ни у кого нет, потому что у остальных не настроено
    //     шифрование, — не блокируем: рассылка не упала, отправка не зависит от
    //     готовности остальных, а предупреждение показывает handleRoomSessionResult.
    function sessionBlock(session) {
        if (!session) return { code: 'session-failed', text: BLOCK_TEXTS['session-failed'] };
        if (session.ok === false && Number(session.peers) > 0 && Number(session.keyHolders) === 0) {
            return { code: 'keys-not-delivered', text: BLOCK_TEXTS['keys-not-delivered'] };
        }
        if (Number(session.withheldPeers) > 0 && Number(session.keyHolders) === 0) {
            return { code: 'keys-withheld', text: BLOCK_TEXTS['keys-withheld'] };
        }
        return null;
    }

    // Цитата в комнате (З3): сервер хранит reply_to_id открыто, поэтому может приписать сообщению участника любую цитату.
    // Цитата принимается, только если её id совпал с id, который отправитель подписал внутри шифротекста (result.replyTo).
    // Нет цитаты - нечего проверять; сообщение не расшифровано - проверить нечем, цитата не показывается.
    function replyQuoteTrusted(serverReplyTo, result) {
        if (!serverReplyTo) return true;
        if (!result || result.ok !== true || typeof result.replyTo !== 'string') return false;
        return result.replyTo === String(serverReplyTo.id);
    }

    const PLACEHOLDERS = Object.freeze({
        room: 'Зашифрованное сообщение...',
        bot: 'Спросите бота или выберите тему',
        disabled: 'Отправка недоступна',
    });

    // Что показать для открытого чата. state:
    //   inRoom      — чат является комнатой;
    //   plaintextOk — plaintextAllowed(...) для этого чата;
    //   e2ee        — 'off' | 'pending' | 'ready' | 'unavailable';
    //   initError   — E2eeError последней неудачной инициализации;
    //   block       — { text } из sessionBlock или null.
    // Результат:
    //   kind        — 'ready' | 'pending' | 'unavailable' | 'blocked' | 'bot' | 'unknown';
    //   text, icon  — строка под полем ввода и её иконка; spin — иконка крутится;
    //   retry       — показывать «Повторить»;
    //   disabled    — поле ввода, отправка и вложения отключены;
    //   placeholder — подсказка в поле ввода;
    //   indicator   — { show, ok, text, title } для значка в шапке.
    function composerView(state) {
        const { inRoom, plaintextOk, e2ee, initError, block } = state;
        if (!inRoom) {
            if (plaintextOk) {
                return {
                    kind: 'bot', text: 'Чат с ботом: сообщения не защищены сквозным шифрованием',
                    icon: 'unlock', spin: false, retry: false, disabled: false,
                    placeholder: PLACEHOLDERS.bot, indicator: { show: false, ok: false, text: '', title: '' },
                };
            }
            return {
                kind: 'unknown',
                text: 'Отправка в этот чат отключена: на этом устройстве не сохранён номер чата с ботом, а открытый текст другим чатам не отправляется',
                icon: 'alert-triangle', spin: false, retry: false, disabled: true,
                placeholder: PLACEHOLDERS.disabled, indicator: { show: false, ok: false, text: '', title: '' },
            };
        }
        const missing = {
            show: true, ok: false, text: 'нет шифрования',
            title: 'Нет сквозного шифрования — нажмите, чтобы открыть «Участники и ключи»',
        };
        if (e2ee === 'unavailable') {
            return {
                kind: 'unavailable',
                text: `Сообщения в группу не отправляются: ${initErrorReason(initError)}.`,
                icon: 'alert-triangle', spin: false, retry: initErrorRetryable(initError), disabled: true,
                placeholder: PLACEHOLDERS.disabled, indicator: missing,
            };
        }
        if (e2ee !== 'ready') {
            return {
                kind: 'pending', text: 'Готовим ключи шифрования… Отправка станет доступна через несколько секунд',
                icon: 'loader', spin: true, retry: false, disabled: false,
                placeholder: PLACEHOLDERS.room,
                indicator: { show: true, ok: true, text: 'шифрование', title: 'Сквозное шифрование: открыть «Участники и ключи»' },
            };
        }
        if (block) {
            return {
                kind: 'blocked', text: block.text,
                icon: 'alert-triangle', spin: false, retry: true, disabled: false,
                placeholder: PLACEHOLDERS.room, indicator: missing,
            };
        }
        return {
            kind: 'ready', text: 'Сообщения защищены сквозным шифрованием',
            icon: 'lock', spin: false, retry: false, disabled: false,
            placeholder: PLACEHOLDERS.room,
            indicator: { show: true, ok: true, text: 'шифрование', title: 'Сквозное шифрование: открыть «Участники и ключи»' },
        };
    }

    return {
        PLACEHOLDERS,
        INIT_REASONS,
        parseBotChatId,
        plaintextAllowed,
        sessionBlock,
        replyQuoteTrusted,
        initErrorReason,
        initErrorRetryable,
        composerView,
    };
});
