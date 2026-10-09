// Срок хранения временного аккаунта: подписи и тексты для экрана входа,
// профиля, заметки в сайдбаре и окна удаления.
//
// Числа — из контракта волны 1 (docs/dev/contracts/stage-1.md, §4): аккаунт
// удаляется после 30 минут без открытой вкладки (tab), суток (day) или 7 дней
// (week) без входа. Потолка «от создания» нет: пока человек заходит, аккаунт
// живёт. Все тексты о сроке собраны здесь, чтобы их можно было сверить с
// поведением сервера в одном месте.
//
// Чистые функции без DOM и сети: файл исполняется и в браузере
// (window.NyxoLifetime), и в Node (test/client-lib.test.js). Дата показывается
// в часовом поясе устройства.

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoLifetime = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const LIFETIMES = Object.freeze(['tab', 'day', 'week']);

    // По умолчанию — самый короткий срок: он оставляет меньше всего следов.
    const DEFAULT_LIFETIME = 'tab';

    const LIFETIME_LABELS = Object.freeze({
        tab: 'Пока открыта вкладка',
        day: '1 день',
        week: '7 дней',
    });

    function isLifetime(value) {
        return LIFETIMES.includes(value);
    }

    // Подсказка под выбором срока на экране входа: чем варианты отличаются на деле.
    const DETAILS = Object.freeze({
        tab: 'Удалится через 30 минут после закрытия последней вкладки. Закроете браузер — вход пропадёт сразу.',
        day: 'Можно закрыть вкладку и вернуться в этом же браузере. Удалится после суток без входа.',
        week: 'Можно закрыть вкладку и вернуться в этом же браузере. Удалится после 7 дней без входа.',
    });

    function lifetimeDetail(lifetime) {
        return DETAILS[lifetime] || '';
    }

    // Заметка в сайдбаре — статичная: дата «удалится, если не заходить до …»
    // сдвигается при каждом входе, её место — в профиле.
    const NOTES = Object.freeze({
        tab: 'Удалится через 30 минут после закрытия вкладки',
        day: 'Удалится, если не заходить 1 день',
        week: 'Удалится, если не заходить 7 дней',
    });

    function lifetimeNote(lifetime) {
        return NOTES[lifetime] || '';
    }

    const MONTHS_GENITIVE = [
        'января', 'февраля', 'марта', 'апреля', 'мая', 'июня',
        'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря',
    ];

    function toDate(value) {
        if (value === null || value === undefined || value === '') return null;
        const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
        return Number.isNaN(date.getTime()) ? null : date;
    }

    // «3 октября, 14:05»; год — только если он не текущий. Без Intl: вывод
    // toLocaleString отличается между движками и версиями ICU.
    function formatDeadline(date, now) {
        const time = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
        const year = date.getFullYear() !== now.getFullYear() ? ` ${date.getFullYear()} г.` : '';
        return `${date.getDate()} ${MONTHS_GENITIVE[date.getMonth()]}${year}, ${time}`;
    }

    // Статус в профиле. user — поля из /api/auth: anonLifetime и anonExpiresAt
    // (для day/week — время удаления, если больше не заходить; для tab — null).
    function lifetimeStatus(user, now) {
        const lifetime = user ? user.anonLifetime : null;
        if (lifetime === 'tab') return 'Удалится через 30 минут после закрытия последней вкладки';
        if (lifetime !== 'day' && lifetime !== 'week') return '';
        const current = toDate(now) || new Date();
        const expires = toDate(user.anonExpiresAt);
        if (expires && expires.getTime() > current.getTime()) {
            return `Удалится, если не заходить до ${formatDeadline(expires, current)}`;
        }
        return lifetime === 'day' ? 'Удалится после суток без входа' : 'Удалится после 7 дней без входа';
    }

    // Окно «Удалить и выйти»: как уйти, НЕ удаляя аккаунт.
    const LEAVE_ALTERNATIVES = Object.freeze({
        tab: 'Если просто закрыть вкладку, аккаунт удалится сам через 30 минут.',
        day: 'Хотите вернуться позже? Просто закройте вкладку: аккаунт сохранится, если заходить хотя бы раз в сутки.',
        week: 'Хотите вернуться позже? Просто закройте вкладку: аккаунт сохранится, если заходить хотя бы раз в 7 дней.',
    });

    function leaveAlternative(lifetime) {
        return LEAVE_ALTERNATIVES[lifetime] || '';
    }

    // Совет для заявки в группу при сроке «Пока открыта вкладка»: заявка
    // удаляется вместе с аккаунтом, а одобрения можно ждать долго. pending —
    // заявка уже отправлена; иначе (экран входа) ещё неизвестно, нужно ли
    // группе одобрение.
    function inviteTabWarning(lifetime, pending) {
        if (lifetime !== 'tab') return '';
        return pending
            ? 'Не закрывайте вкладку, пока заявку не примут: с этим сроком аккаунт удалится через 30 минут после закрытия — вместе с заявкой.'
            : 'Если в группу пускают по одобрению, не закрывайте вкладку, пока заявку не примут: с этим сроком аккаунт удалится через 30 минут после закрытия — вместе с заявкой.';
    }

    return {
        LIFETIMES,
        DEFAULT_LIFETIME,
        LIFETIME_LABELS,
        isLifetime,
        lifetimeDetail,
        lifetimeNote,
        lifetimeStatus,
        leaveAlternative,
        inviteTabWarning,
    };
});
