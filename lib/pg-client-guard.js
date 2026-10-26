'use strict';
// Соединение, взятое из пула (pool.connect()), и обрыв связи с Postgres.
//
// Пока соединение простаивает в пуле, его событие 'error' слушает сам pg-pool
// (и передаёт пулу, у которого есть обработчик). На время выдачи — от
// connect() до release() — pg-pool своего слушателя снимает. Обрыв в это время
// (рестарт или failover Postgres, pg_terminate_backend, сетевой сбой) приходит
// активному запросу ошибкой, а затем закрытие сокета даёт 'error' на клиенте
// уже без слушателя: необработанное событие → uncaughtException → выход
// процесса (src/lifecycle.js). Так один оборванный запрос ронял весь сервер.
//
// guardClient вешает на выданное соединение заглушку с записью в лог и
// возвращает release(err): он снимает заглушку и возвращает соединение в пул.
// После обрыва (или если вызывающий передал ошибку) соединение закрывается, а
// не уходит обратно: состояние его сессии неизвестно. Заглушка снимается при
// каждом возврате, иначе у соединения, которое выдаётся много раз, копились бы
// слушатели.

const { logError } = require('./log-error');

function guardClient(client, context, { report = logError } = {}) {
    let failure = null;
    const onError = (err) => {
        if (!failure) failure = err || new Error('ошибка соединения с базой');
        report(context, err);
    };
    // Подставные клиенты юнит-тестов бывают без EventEmitter.
    const canListen = typeof client.on === 'function' && typeof client.removeListener === 'function';
    if (canListen) client.on('error', onError);
    let released = false;
    return function release(err) {
        // Повторный release — ошибка вызывающего (pg-pool бросает на нём), но
        // заглушку снимаем один раз.
        if (!released && canListen) client.removeListener('error', onError);
        released = true;
        const reason = err || failure;
        client.release(reason ? (reason instanceof Error ? reason : true) : undefined);
    };
}

module.exports = { guardClient };
