'use strict';
// Помощник протокольных тестов, которым состав группы не важен (ротация, архив, запрос ключа, порядок
// сообщений, прозрачность ключей): install(E2EE) оборачивает createClient, и клиент подтверждает вручную
// всех участников, которых тест передаёт в ensureRoomSession, - как будто они давно в группе. Так прежние
// тесты проверяют своё, а не допуск; сам допуск проверяют test/membership.*.test.js на настоящих
// сертификатах (там install не вызывается).
// Не *.test.js, поэтому раннер юнит-тестов файл сам не запускает.

function autoTrust(client, getSelfId) {
    const original = client.ensureRoomSession.bind(client);
    client.ensureRoomSession = async (chatId, roomId, participants, info) => {
        const me = Number(getSelfId());
        const ids = (participants || []).map(p => Number(p.id)).filter(id => id !== me);
        if (ids.length > 0) {
            await client.checkPeerIdentities(ids);
            for (const id of ids) await client.trustMember(roomId, id);
        }
        return original(chatId, roomId, participants, info);
    };
    return client;
}

function install(E2EE) {
    if (E2EE.__autoTrustInstalled) return;
    const create = E2EE.createClient;
    E2EE.createClient = function createClientWithAutoTrust(options) {
        let selfId = options && options.userId;
        const client = create.call(this, options);
        const setUserId = client.setUserId;
        client.setUserId = (id) => { selfId = id; return setUserId(id); };
        return autoTrust(client, () => selfId);
    };
    E2EE.__autoTrustInstalled = true;
}

module.exports = { autoTrust, install };
