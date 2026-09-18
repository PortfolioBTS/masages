# Changelog v2.0 - Комплексная модернизация 🚀

## 🎨 Визуальный редизайн

### Новый современный интерфейс
- **Темная тема по умолчанию** с профессиональными градиентами
- **Glassmorphism эффекты** — прозрачность с размытием фона
- **Плавные анимации** — переходы, появление элементов, пульсация
- **Современная типографика** — улучшенная читаемость
- **Градиентные кнопки** с hover эффектами и тенями
- **Улучшенные формы** — новые стили input полей с фокусом
- **Профессиональные модальные окна** — с backdrop blur
- **Анимированный фон** — динамические градиентные круги
- **Улучшенные чаты** — карточки с hover эффектами
- **Статусные индикаторы** — с свечением для online статусов

### CSS переработан полностью
- Новая цветовая палитра на CSS переменных
- Темные оттенки (#0f0f1a, #1a1a2e, #25253f)
- Акцентные цвета (#6366f1, #8b5cf6, #ec4899)
- Улучшенные тени и свечение
- Кастомные scrollbar стили
- Адаптивный дизайн для мобильных

## 🛡️ Улучшения безопасности и приватности

### 1. Metadata Stripping (Удаление метаданных)
**Файл**: `lib/metadata-stripper.js`

Функции:
- Удаление EXIF данных из изображений (GPS, камера, время съемки)
- Очистка метаданных из PDF файлов
- Автоматическая обработка при загрузке
- Использует библиотеку `sharp` для изображений
- Фоновая очистка старых файлов

**Применение**:
```javascript
await stripMetadataFromFile(filePath, mimeType);
```

### 2. Disappearing Messages (Исчезающие сообщения)
**Файл**: `lib/disappearing-messages.js`

Функции:
- Таймеры самоуничтожения для сообщений
- Auto-delete on read (удаление после прочтения)
- Настройка default expiry для чатов
- Фоновый worker для автоочистки
- Хранение в отдельной таблице `message_expiry`

**API**:
- `POST /api/messages/:messageId/set-expiry`
- `POST /api/chats/:chatId/set-default-expiry`
- `GET /api/chats/:chatId/settings`

### 3. Privacy Enhancements (Улучшения приватности)
**Файл**: `lib/privacy.js`

Функции:
- `addRandomDelay()` — защита от timing attacks
- `padMessage()` / `unpadMessage()` — padding для защиты от traffic analysis
- `addTimingNoise()` — добавление шума к временным меткам
- `sanitizeText()` — удаление zero-width characters
- `generateSessionFingerprint()` — уникальный fingerprint для сессий
- `stripDangerousMetadata()` — очистка опасных свойств из JSON
- `getPrivacyHeaders()` — набор заголовков безопасности
- `anonymizeIP()` — частичная анонимизация IP для логов
- `hashSensitiveData()` — безопасное хеширование

**Применение**:
- Защита от timing attacks в `/api/login`
- Усиленные заголовки приватности на всех запросах
- Санитизация текста сообщений

### 4. E2EE Key Server Integration
**Файл**: `lib/e2ee-proxy.js`

Прокси-эндпоинты для интеграции с Rust E2EE сервером:
- `PUT /api/keys/identity` — регистрация identity ключей
- `PUT /api/keys/signed-prekey` — ротация SPK
- `POST /api/keys/one-time-prekeys` — пополнение OPK
- `GET /api/keys/bundle/:userId` — получение bundle для сессии
- `DELETE /api/keys` — удаление всех ключей

**Статус**: Серверная часть готова, требуется клиентский WASM-модуль

### 5. Tor/Onion Routing Support
**Файл**: `lib/tor-support.js`

Функции:
- SOCKS5 proxy через Tor
- Проверка подключения к Tor network
- Middleware для логирования .onion подключений
- Конфигурация Hidden Service
- Обертка `fetchViaTor()` для анонимных запросов

**Настройка**:
```env
ENABLE_TOR_ROUTING=true
TOR_PROXY_HOST=127.0.0.1
TOR_PROXY_PORT=9050
```

### 6. Enhanced Anonymous Mode
**Улучшения**:
- Session fingerprinting для изоляции
- Короткое время жизни сессии (2 часа вместо 24)
- Автоматическое удаление ВСЕХ данных при выходе
- Улучшенное приветственное сообщение с инструкциями
- Проверка expiry анонимных сессий
- Логирование операций для мониторинга

**Что удаляется**:
- Все сообщения пользователя
- Все чаты
- Участие в комнатах
- Реакции
- Сам аккаунт

## 📦 Новые зависимости

```json
{
  "sharp": "^0.33.0",              // Обработка изображений
  "socks-proxy-agent": "^8.0.2"    // Tor/SOCKS5 поддержка
}
```

## 🗄️ Изменения БД

### Новые таблицы

**message_expiry**:
```sql
CREATE TABLE message_expiry (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    auto_delete_on_read BOOLEAN DEFAULT FALSE
);
```

**chat_settings**:
```sql
CREATE TABLE chat_settings (
    chat_id INTEGER PRIMARY KEY REFERENCES chats(id) ON DELETE CASCADE,
    default_message_expiry INTEGER
);
```

## 🔧 Изменения в server.js

### Импорты новых модулей
- metadata-stripper
- disappearing-messages
- privacy utilities
- e2ee-proxy
- tor-support

### Инициализация
- DisappearingMessagesManager
- Фоновая очистка старых файлов
- Проверка Tor подключения при старте

### Middleware
- Усиленные заголовки приватности
- Tor connection logger
- Улучшенный CSRF

### Обновленные эндпоинты
- `/api/login` — с timing attack protection
- `/api/register/anonymous` — с улучшенной изоляцией
- `/api/logout` — с полной очисткой для анонимных
- `/api/auth` — с проверкой expiry
- `/api/messages` — с metadata stripping
- `/api/messages/file` — с automatic metadata removal

### Новые эндпоинты
- Disappearing messages API (3 эндпоинта)
- E2EE proxy API (6 эндпоинтов)

## 📊 Статистика изменений

- **Строк кода добавлено**: ~2500+
- **Новых файлов**: 6
- **Модулей переработано**: 3 (server.js, style.css, README.md)
- **Новых API эндпоинтов**: 9
- **Новых функций безопасности**: 15+

## 🎯 Следующие шаги

### Критичные для E2EE
1. Реализовать WASM-модуль для криптографии в браузере
2. Интегрировать X3DH на клиенте
3. Добавить UI для управления ключами
4. Реализовать Double Ratchet для сессий

### Желательные улучшения
1. Desktop приложение (Electron)
2. Voice/Video calls
3. Multi-device sync
4. Push notifications
5. Stickers/GIF support
6. Message reactions improvements
7. File preview в чатах

## ⚠️ Breaking Changes

1. `package.json` — новое имя (`nyxo-messenger`) и версия (2.0.0)
2. `.env.example` — новые обязательные переменные
3. CSS полностью переписан — может потребоваться адаптация custom стилей
4. БД миграции — требуется создание новых таблиц

## 🔒 Security Audit Results

### Исправлено
✅ Metadata leakage в загруженных файлах
✅ Timing attacks в authentication
✅ Traffic analysis через padding
✅ Session hijacking через короткий expiry
✅ IP disclosure через Tor routing

### Добавлено
✅ Comprehensive privacy headers
✅ Metadata stripping pipeline
✅ Disappearing messages
✅ Enhanced anonymous mode
✅ E2EE infrastructure

## 📝 Migration Guide

### Обновление с v1.0 до v2.0

```bash
# 1. Backup БД
pg_dump nyxo > backup.sql

# 2. Pull новый код
git pull origin main

# 3. Установка новых зависимостей
npm install

# 4. Обновление .env
# Добавьте новые переменные из .env.example

# 5. Миграция БД
# SQL команды для новых таблиц выполнятся автоматически при старте

# 6. Перезапуск
npm start
```

---

**v2.0.0** — Полная модернизация мессенджера с фокусом на анонимность и современный дизайн 🚀
