# Nyxo Messenger v2.0 🔒

Максимально анонимный и безопасный мессенджер с поддержкой E2EE, Tor routing и автоматическим удалением метаданных.

## ✨ Ключевые возможности

### 🛡️ Безопасность и Приватность
- **End-to-End шифрование (E2EE)** — X3DH протокол с отдельным Rust-сервисом для обмена ключами
- **Tor Hidden Service поддержка** — полная анонимность через .onion адреса
- **Автоматическое удаление метаданных** — EXIF из фото, метаданные из PDF
- **Disappearing messages** — самоуничтожающиеся сообщения с таймером
- **Защита от timing attacks** — случайные задержки в критических операциях
- **Усиленные заголовки приватности** — CSP, CORS, Permissions Policy
- **Анонимный режим** — полное удаление данных при выходе

### 🎨 Современный интерфейс
- **Темная тема по умолчанию** — профессиональный дизайн с glassmorphism эффектами
- **Плавные анимации** — современные переходы и микроанимации
- **Градиенты и свечение** — визуально приятный интерфейс
- **Адаптивный дизайн** — работает на всех устройствах

### 💬 Функции мессенджера
- Групповые чаты с кодами приглашений
- Редактирование и удаление сообщений
- Реакции на сообщения (emoji)
- Ответы на сообщения (quotes)
- Поиск по чатам и сообщениям
- Статусы сообщений (отправлено/доставлено/прочитано)
- Загрузка файлов (фото, видео, аудио, документы)
- Бот-помощник

## 🚀 Быстрый старт

### Требования
- Node.js 18+
- PostgreSQL 14+
- Rust 1.70+ (для микросервисов)
- Tor (опционально, для .onion адресов)

### Установка

```bash
# 1. Клонирование репозитория
git clone https://github.com/PortfolioBTS/masages.git
cd masages

# 2. Установка зависимостей Node.js
npm install

# 3. Настройка переменных окружения
cp .env.example .env
# Отредактируйте .env и укажите параметры БД и секреты

# 4. Запуск микросервиса анонимности (Rust)
cd anon-service
cargo run --release &
cd ..

# 5. Запуск E2EE Key Server (Rust) - опционально
cd e2ee-key-server
cargo run --release &
cd ..

# 6. Запуск основного сервера
npm start
```

### Конфигурация Tor (опционально)

Для максимальной анонимности через Tor:

```bash
# 1. Установка Tor
# Ubuntu/Debian:
sudo apt install tor

# macOS:
brew install tor

# 2. Настройка Hidden Service
# Добавьте в /etc/tor/torrc:
HiddenServiceDir /var/lib/tor/nyxo/
HiddenServicePort 80 127.0.0.1:3000
HiddenServiceVersion 3

# 3. Перезапуск Tor
sudo systemctl restart tor

# 4. Получение .onion адреса
sudo cat /var/lib/tor/nyxo/hostname

# 5. Включение Tor routing в .env
ENABLE_TOR_ROUTING=true
TOR_PROXY_HOST=127.0.0.1
TOR_PROXY_PORT=9050
```

## 📁 Структура проекта

```
masages/
├── server.js                 # Основной сервер (Express + Socket.io)
├── public/                   # Фронтенд
│   ├── index.html
│   ├── script.js
│   └── style.css            # Новый современный дизайн
├── lib/                     # Библиотеки безопасности
│   ├── metadata-stripper.js # Удаление метаданных
│   ├── disappearing-messages.js
│   ├── privacy.js           # Функции приватности
│   ├── tor-support.js       # Tor/SOCKS5 поддержка
│   └── e2ee-proxy.js        # Прокси для E2EE сервера
├── anon-service/            # Rust микросервис (генерация ID)
├── e2ee-key-server/         # Rust микросервис (E2EE ключи)
└── uploads/                 # Загруженные файлы

```

## 🔐 Безопасность

### Реализованная защита

1. **Content Security Policy (CSP)** — nonce-based, запрещает inline скрипты
2. **CSRF Protection** — double-submit cookie pattern с улучшениями
3. **Rate Limiting** — защита от bruteforce на всех критических эндпоинтах
4. **Magic Bytes Verification** — проверка реального типа файлов
5. **Metadata Stripping** — автоматическое удаление EXIF и метаданных
6. **Timing Attack Protection** — случайные задержки в аутентификации
7. **Параметризованные запросы** — защита от SQL-инъекций
8. **WebSocket авторизация** — проверка сессий перед подключением
9. **Защищенная раздача файлов** — контроль доступа на уровне участников
10. **Enhanced Privacy Headers** — полный набор заголовков безопасности

### E2EE Implementation

Мессенджер использует модифицированный X3DH протокол:

- **Два identity-ключа** вместо одного (Ed25519 для подписей, X25519 для DH)
- **Signed PreKey** с ротацией для forward secrecy
- **One-Time PreKeys** пул для каждой новой сессии
- **Сервер не видит приватные ключи** — только публичный материал

⚠️ **Важно**: Интеграция E2EE на клиенте (браузер) еще не завершена. Сервис готов, но требуется WASM-модуль для криптографии в браузере.

## 🎯 Новые API эндпоинты

### Disappearing Messages

```javascript
// Установка таймера самоуничтожения для сообщения
POST /api/messages/:messageId/set-expiry
Body: { expirySeconds: 3600, autoDeleteOnRead: false }

// Настройка автоудаления для чата
POST /api/chats/:chatId/set-default-expiry
Body: { expirySeconds: 3600 }

// Получение настроек чата
GET /api/chats/:chatId/settings
```

### E2EE Key Management

```javascript
// Регистрация identity ключей
PUT /api/keys/identity
Body: { identity_signing_key: "base64", identity_dh_key: "base64" }

// Ротация Signed PreKey
PUT /api/keys/signed-prekey
Body: { key_id: 1, public_key: "base64", signature: "base64" }

// Пополнение One-Time PreKeys
POST /api/keys/one-time-prekeys
Body: { keys: [{ key_id: 1, public_key: "base64" }, ...] }

// Получение bundle для начала сессии
GET /api/keys/bundle/:targetUserId

// Количество оставшихся OPK
GET /api/keys/one-time-prekeys/count

// Удаление всех ключей
DELETE /api/keys
```

## 🎨 Визуальные улучшения

### До vs После

**Было:**
- Светлая тема с базовыми цветами
- Emoji иконки вместо профессиональных
- Простые переходы
- Стандартные формы

**Стало:**
- Темная тема с градиентами и glassmorphism
- Современная типографика
- Плавные анимации и микроинтеракции
- Профессиональные формы с улучшенным UX
- Визуальная иерархия и воздушность

## 📊 Технические характеристики

- **Backend**: Node.js + Express + Socket.io
- **Database**: PostgreSQL с индексами
- **Security Services**: 2 Rust микросервиса
- **Frontend**: Vanilla JS (без фреймворков)
- **Encryption**: X3DH протокол (готов к интеграции)
- **Anonymity**: Tor Hidden Service support

## 🔄 Roadmap

- [ ] Завершение клиентского E2EE модуля (WASM)
- [ ] Desktop приложение (Electron)
- [ ] Mobile приложения (React Native)
- [ ] Voice/Video calls через WebRTC
- [ ] Multi-device поддержка
- [ ] Групповое E2EE
- [ ] Stickers и GIF поддержка

## 🤝 Безопасное использование

### Рекомендации

1. **Всегда используйте HTTPS** в production
2. **Настройте Tor** для максимальной анонимности
3. **Регулярно обновляйте** зависимости
4. **Используйте сильные пароли** для БД и секретов
5. **Настройте firewall** для закрытия неиспользуемых портов
6. **Включите E2EE** после завершения клиентской интеграции

### Ограничения

- E2EE на клиенте еще не реализован (сервис готов)
- Multi-device не поддерживается
- Групповое E2EE отсутствует
- Voice/Video звонки не реализованы

## 📄 Лицензия

MIT License

## 🔗 Ссылки

- [SECURITY.md](./SECURITY.md) — Детали безопасности
- [FEATURES.md](./FEATURES.md) — Полный список функций
- [anon-service/README.md](./anon-service/README.md) — Rust микросервис анонимности
- [e2ee-key-server/README.md](./e2ee-key-server/README.md) — E2EE сервис

## 🐛 Нашли баг?

Создайте Issue с тегом `security` для проблем безопасности или `bug` для обычных багов.

---

**Сделано с ❤️ для приватности и анонимности**
