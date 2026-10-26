'use strict';
// События socket.io для клиентов: обновить список чатов, состав комнаты, заявки на вступление,
// сообщение комнаты. Вынесено из server.js.

const { getSocketRoomKey } = require('./io');

function createEvents(ctx) {
    const { io } = ctx;

    // Синхронизация списка чатов между вкладками/устройствами пользователя.
    function notifyChatListChanged(userId) {
        io.to('user:' + userId).emit('chatListChanged', {});
    }

    // Рассылка события сообщения комнаты. Сокеты отправителя состоят и в room:<id>, и
    // в user:<id>: без except комнатное событие пришло бы его вкладке дважды (с mine и
    // без). Поэтому комнате — except автора (и тех, для кого сообщение под границей
    // видимости), а автору — одна копия на user:<id> с mine: true. onlyAuthor — только
    // копия автору (границы видимости не удалось прочитать, services/messages.js).
    function emitRoomMessageEvent(event, roomId, authorId, payload, { hiddenUserIds = [], toAuthor = true, onlyAuthor = false } = {}) {
        if (!onlyAuthor) {
            let target = io.to(getSocketRoomKey(null, roomId)).except('user:' + authorId);
            for (const id of hiddenUserIds) target = target.except('user:' + id);
            target.emit(event, payload);
        }
        if (toAuthor) io.to('user:' + authorId).emit(event, { ...payload, mine: true });
    }

    // Состав комнаты изменился: клиенты участников перечитывают список
    // участников (E2EE: новичку — Sender Key, после ухода — ротация ключа).
    // inviteRotated: true - из-за выхода участника сервер обнулил подписанное приглашение и выдал новый код
    // (решение владельца, signed-membership.md, вопрос 17): клиенты показывают «Ссылка-приглашение обновлена».
    function notifyRoomMembersChanged(roomId, extra) {
        io.to(`room:${roomId}`).emit('roomMembersChanged', { roomId, ...extra });
    }

    // Список заявок комнаты изменился — только участникам (заявитель в
    // room:<id> не подписан и чужих заявок не видит).
    function notifyJoinRequestsChanged(roomId) {
        io.to(`room:${roomId}`).emit('joinRequestsChanged', { roomId });
    }

    function notifyJoinRequestDecided(userId, payload) {
        io.to('user:' + userId).emit('joinRequestDecided', payload);
    }

    return {
        notifyChatListChanged, emitRoomMessageEvent, notifyRoomMembersChanged, notifyJoinRequestsChanged,
        notifyJoinRequestDecided,
    };
}

module.exports = { createEvents };
