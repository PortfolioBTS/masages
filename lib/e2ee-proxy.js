// Прокси для E2EE Key Server
const KEY_SERVER_URL = process.env.KEY_SERVER_URL || 'http://127.0.0.1:7420';
const KEY_SERVER_SECRET = process.env.INTERNAL_KEY_SERVER_SECRET;

// Middleware для проверки авторизации
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Не авторизован' });
    }
    next();
}

// Регистрация/обновление identity ключей
app.put('/api/keys/identity', requireAuth, async (req, res) => {
    try {
        const response = await fetch(`${KEY_SERVER_URL}/internal/v1/keys/identity`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
            body: JSON.stringify(req.body),
        });

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        console.error('[E2EE] Identity key registration error:', error.message);
        res.status(500).json({ success: false, message: 'Ошибка регистрации ключей' });
    }
});

// Ротация Signed PreKey
app.put('/api/keys/signed-prekey', requireAuth, async (req, res) => {
    try {
        const response = await fetch(`${KEY_SERVER_URL}/internal/v1/keys/signed-prekey`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
            body: JSON.stringify(req.body),
        });

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        console.error('[E2EE] Signed prekey rotation error:', error.message);
        res.status(500).json({ success: false, message: 'Ошибка ротации ключа' });
    }
});

// Пополнение пула One-Time PreKeys
app.post('/api/keys/one-time-prekeys', requireAuth, async (req, res) => {
    try {
        const response = await fetch(`${KEY_SERVER_URL}/internal/v1/keys/one-time-prekeys`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
            body: JSON.stringify(req.body),
        });

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        console.error('[E2EE] One-time prekeys upload error:', error.message);
        res.status(500).json({ success: false, message: 'Ошибка загрузки одноразовых ключей' });
    }
});

// Получение количества оставшихся OPK
app.get('/api/keys/one-time-prekeys/count', requireAuth, async (req, res) => {
    try {
        const response = await fetch(`${KEY_SERVER_URL}/internal/v1/keys/one-time-prekeys/count`, {
            method: 'GET',
            headers: {
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
        });

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        console.error('[E2EE] OPK count error:', error.message);
        res.status(500).json({ success: false, message: 'Ошибка получения количества ключей' });
    }
});

// Получение key bundle для инициации сессии
app.get('/api/keys/bundle/:targetUserId', requireAuth, async (req, res) => {
    try {
        const targetUserId = req.params.targetUserId;
        const response = await fetch(`${KEY_SERVER_URL}/internal/v1/keys/bundle/${targetUserId}`, {
            method: 'GET',
            headers: {
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
        });

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        console.error('[E2EE] Bundle fetch error:', error.message);
        res.status(500).json({ success: false, message: 'Ошибка получения ключей собеседника' });
    }
});

// Удаление всех ключей пользователя
app.delete('/api/keys', requireAuth, async (req, res) => {
    try {
        const response = await fetch(`${KEY_SERVER_URL}/internal/v1/keys`, {
            method: 'DELETE',
            headers: {
                'X-Internal-Secret': KEY_SERVER_SECRET,
                'X-User-Id': String(req.session.userId),
            },
        });

        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        console.error('[E2EE] Keys deletion error:', error.message);
        res.status(500).json({ success: false, message: 'Ошибка удаления ключей' });
    }
});

module.exports = {
    requireAuth
};
