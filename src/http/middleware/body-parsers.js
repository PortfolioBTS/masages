'use strict';
// Разбор тела запроса: специальные парсеры с большим лимитом стоят раньше общего (тот видит
// уже разобранное тело и пропускает запрос). Вынесено из server.js.

const express = require('express');
// Подписанный состав группы (signed-membership.md): проверки сертификатов на сервере и общий с клиентом разбор.
const MembershipCerts = require('../../../lib/membership-certs');

const SNAP_BODY_ROUTES = [/^\/api\/join-requests\/\d+\/approve$/, /^\/api\/chats\/\d+\/invite\/rotate$/, /^\/api\/chats\/\d+\/member-certs$/];

function installBodyParsers(app) {
    // Тело парсится только после проверок источника и CSRF. Глобальный лимит
    // остаётся маленьким (100 КБ по умолчанию); key-shares — исключение: до 200
    // получателей по 8 КБ (x3dh-init с постквантовой частью весит 2.4–4 КБ).
    // Специальный парсер стоит раньше: общий видит уже разобранное тело и
    // пропускает запрос.
    app.use('/api/keys/key-shares', express.json({ limit: '2mb' }));
    // Пачка одноразовых PQ-prekey: до 50 ключей по ~1,7 КБ в base64 (ключ ML-KEM
    // 1184 байта + подпись 64) — около 90 КБ, впритык к 100 КБ по умолчанию.
    app.use('/api/keys/pq-one-time-prekeys', express.json({ limit: '256kb' }));
    // Запросы со снимком состава (approve, invite/rotate, member-certs): снимок на 1000 участников - 16 000 байт, в base64
    // около 21,3 тыс. символов, плюс сертификат и JSON; общий лимит их не вмещает, но и 100 КБ для них слишком много
    // (signed-membership.md, 7.2: 32 КБ). Парсер стоит раньше общего: тот видит разобранное тело и пропускает запрос.
    const snapBodyParser = express.json({ limit: MembershipCerts.BODY_LIMIT_WITH_SNAP });

    app.use((req, res, next) => (
        req.method === 'POST' && SNAP_BODY_ROUTES.some(re => re.test(req.path)) ? snapBodyParser(req, res, next) : next()
    ));
    app.use(express.json());
}

module.exports = { installBodyParsers };
