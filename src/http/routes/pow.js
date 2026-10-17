'use strict';
// GET /api/pow/challenge — задача proof-of-work для регистрации. Вынесено из server.js.

const { createChallenge } = require('../../../lib/pow');
const { POW_PURPOSES } = require('../../services/pow');

function register(app, ctx) {
    app.get('/api/pow/challenge', (req, res) => {
        const purpose = typeof req.query.purpose === 'string' ? req.query.purpose : '';
        if (!POW_PURPOSES.has(purpose)) {
            return res.status(400).json({ success: false, message: 'Некорректная цель проверки' });
        }
        const { token, difficulty } = createChallenge(purpose);
        res.json({ success: true, token, difficulty });
    });
}

module.exports = { register };
