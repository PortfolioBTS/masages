// Блокировка хранилища ключей E2EE между вкладками одного аккаунта
// (docs/security/message-ordering.md, раздел 9.7).
//
// Ключи устройства лежат в IndexedDB 'nyxo-e2ee-<userId>', и её делят все
// вкладки пользователя. Продвижение цепочки Sender Key — «прочитать состояние,
// сдвинуть цепочку, записать» — не атомарно: две вкладки могли бы прочитать одно
// состояние и выдать двум разным сообщениям одну итерацию ключа (повтор
// одноразового ключа сообщения). Web Locks делают такие секции эксклюзивными
// между вкладками. Очередь внутри клиента (e2ee.js) остаётся снаружи, а эта
// блокировка берётся один раз на секцию и только вокруг чтения и записи
// хранилища: сетевых запросов внутри секции нет.
//
// Без Web Locks (старый браузер, окно без navigator.locks) возвращается null:
// клиент работает с одной внутренней очередью, как раньше, и один раз пишет
// предупреждение в консоль. Запасной вариант «одна активная вкладка» через
// BroadcastChannel не строится (раздел 9.7).
//
// Файл исполняется и в браузере (window.NyxoE2eeLock), и в Node
// (test/e2ee-lock.test.js).

(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.NyxoE2eeLock = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // Одно имя на аккаунт: вкладки разных аккаунтов друг другу не мешают.
    function lockName(userId) {
        return 'nyxo-e2ee-' + userId;
    }

    // locks — navigator.locks (или его подобие в тестах); warn — куда писать
    // предупреждение. Результат — функция lock(fn) → Promise или null.
    function makeLock(locks, userId, warn) {
        if (!locks || typeof locks.request !== 'function') {
            if (typeof warn === 'function') {
                warn('E2EE: Web Locks недоступны — две вкладки одного аккаунта могут выдать одну итерацию ключа дважды. '
                    + 'Пользуйтесь Nyxo в одной вкладке или обновите браузер.');
            }
            return null;
        }
        const name = lockName(userId);
        return (fn) => locks.request(name, { mode: 'exclusive' }, fn);
    }

    return { lockName, makeLock };
});
