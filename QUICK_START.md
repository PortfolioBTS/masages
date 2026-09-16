# 🚀 Quick Start Guide - Nyxo Messenger v2.0

## Быстрый запуск (5 минут)

### Минимальная установка

```bash
# 1. Переход в директорию проекта
cd C:\Users\Lenovo\masages

# 2. Установка зависимостей
npm install

# 3. Создание .env файла
copy .env.example .env

# 4. Редактирование .env (укажите DATABASE_URL и SESSION_SECRET)
notepad .env

# 5. Запуск сервера
npm start
```

Откройте браузер: `http://localhost:3000`

---

## Подробная настройка

### 1. База данных PostgreSQL

```bash
# Создание БД
psql -U postgres
CREATE DATABASE nyxo;
CREATE USER nyxo_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE nyxo TO nyxo_user;
\q

# В .env укажите:
DATABASE_URL=postgresql://nyxo_user:your_secure_password@localhost:5432/nyxo
```

### 2. Обязательные переменные .env

```env
# Основные
SESSION_SECRET=generate_random_64_char_string_here
DATABASE_URL=postgresql://user:pass@localhost:5432/nyxo
NODE_ENV=development
PORT=3000
HOST=0.0.0.0

# Микросервисы (опционально, если не запускаете Rust сервисы)
ANON_SERVICE_URL=http://127.0.0.1:8080
INTERNAL_KEY_SERVER_SECRET=another_secure_random_secret_min_32_chars
KEY_SERVER_URL=http://127.0.0.1:7420
```

### 3. Генерация безопасных секретов

```bash
# Для SESSION_SECRET (64 символа)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Для INTERNAL_KEY_SERVER_SECRET (32+ символов)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

---

## Опциональные компоненты

### A. Rust микросервис анонимности

```bash
# Установка Rust (если не установлен)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Запуск сервиса
cd anon-service
cargo build --release
cargo run --release &

# Проверка
curl http://127.0.0.1:8080/generate
```

### B. E2EE Key Server (Rust)

```bash
cd e2ee-key-server
cargo build --release
cargo run --release &

# Проверка
curl http://127.0.0.1:7420/health
```

### C. Tor Hidden Service

```bash
# 1. Установка Tor
# Windows: скачать Tor Browser Bundle
# Linux: sudo apt install tor

# 2. Редактирование torrc
# Windows: Browser\TorBrowser\Data\Tor\torrc
# Linux: /etc/tor/torrc

# Добавить:
HiddenServiceDir /var/lib/tor/nyxo/
HiddenServicePort 80 127.0.0.1:3000
HiddenServiceVersion 3

# 3. Перезапуск Tor
# Linux:
sudo systemctl restart tor

# 4. Получение .onion адреса
# Linux:
sudo cat /var/lib/tor/nyxo/hostname

# 5. Включение в .env
ENABLE_TOR_ROUTING=true
TOR_PROXY_HOST=127.0.0.1
TOR_PROXY_PORT=9050
```

---

## Проверка установки

### 1. Проверка сервера

```bash
npm start
```

Вы должны увидеть:
```
============================================================
Nyxo Messenger запущен на порту 3000
============================================================

Доступен по адресам:
  → http://192.168.1.100:3000
  → http://localhost:3000

Функции безопасности:
  ✓ CSRF Protection
  ✓ Rate Limiting
  ✓ Metadata Stripping
  ✓ Disappearing Messages
  ✓ Enhanced Privacy Headers
  ✓ Timing Attack Protection

============================================================
```

### 2. Проверка функций

#### Metadata Stripping
```bash
# Загрузите фото с EXIF данными
# Скачайте файл обратно
# Проверьте exiftool:
exiftool downloaded_image.jpg
# EXIF данные должны отсутствовать
```

#### Disappearing Messages
```javascript
// В браузере (DevTools Console):
fetch('/api/messages/1/set-expiry', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ expirySeconds: 60 })
})
// Сообщение удалится через 60 секунд
```

#### E2EE API
```bash
curl http://localhost:3000/api/keys/one-time-prekeys/count \
  -H "Cookie: connect.sid=your_session_cookie"
```

---

## Типичные проблемы

### Проблема: "Cannot connect to database"

**Решение**:
```bash
# Проверьте что PostgreSQL запущен
# Windows:
net start postgresql-x64-14

# Linux:
sudo systemctl status postgresql

# Проверьте DATABASE_URL в .env
```

### Проблема: "sharp module not found"

**Решение**:
```bash
npm install sharp
# Если не помогло:
npm rebuild sharp
```

### Проблема: "Session secret not configured"

**Решение**:
```bash
# Добавьте в .env:
SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
```

### Проблема: "Tor connection failed"

**Решение**:
```bash
# Проверьте что Tor запущен
# Linux:
sudo systemctl status tor

# Или отключите Tor в .env:
ENABLE_TOR_ROUTING=false
```

---

## Production Deployment

### 1. Используйте HTTPS

```bash
# С Nginx:
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### 2. Настройка .env для production

```env
NODE_ENV=production
SESSION_SECRET=strong_random_64_chars
DATABASE_URL=postgresql://user:pass@db-host:5432/nyxo?sslmode=require
DB_CA_CERT=your_ssl_certificate_chain

# Отключите development функции
ENABLE_TOR_ROUTING=false  # если не нужен Tor
```

### 3. Process Manager

```bash
# PM2
npm install -g pm2
pm2 start server.js --name nyxo
pm2 startup
pm2 save

# Или systemd
sudo nano /etc/systemd/system/nyxo.service
```

Пример systemd unit:
```ini
[Unit]
Description=Nyxo Messenger
After=network.target postgresql.service

[Service]
Type=simple
User=nyxo
WorkingDirectory=/opt/nyxo
ExecStart=/usr/bin/node server.js
Restart=always
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

### 4. Резервное копирование БД

```bash
# Ежедневный бэкап
crontab -e

# Добавить:
0 2 * * * pg_dump nyxo > /backup/nyxo_$(date +\%Y\%m\%d).sql
```

---

## Мониторинг

### Логи

```bash
# Логи сервера
tail -f logs/nyxo.log

# Логи PostgreSQL
tail -f /var/log/postgresql/postgresql-14-main.log
```

### Метрики

В консоли сервера вы увидите:
- `[Privacy]` — операции metadata stripping
- `[DisappearingMessages]` — очистка сообщений
- `[Anon]` — операции анонимных пользователей
- `[Tor]` — Tor подключения
- `[E2EE]` — операции с ключами

---

## Тестирование безопасности

### 1. CSRF Protection

```bash
# Должно быть отклонено без CSRF токена
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test"}'
```

### 2. Rate Limiting

```bash
# 10+ запросов за минуту должны блокироваться
for i in {1..15}; do
  curl http://localhost:3000/api/login -X POST
done
```

### 3. Metadata Stripping

```bash
# Загрузите фото с GPS
# Скачайте обратно и проверьте:
exiftool image.jpg | grep -i gps
# Результат: пусто
```

---

## Дополнительные ресурсы

- **README.md** — общий обзор
- **CHANGELOG.md** — детали изменений v2.0
- **MODERNIZATION_REPORT.md** — полный отчёт о модернизации
- **SECURITY.md** — рекомендации по безопасности
- **anon-service/README.md** — документация Rust сервиса
- **e2ee-key-server/README.md** — документация E2EE сервиса

---

## Поддержка

Если что-то не работает:

1. Проверьте логи сервера
2. Проверьте .env конфигурацию
3. Убедитесь что все зависимости установлены
4. Проверьте что PostgreSQL запущен
5. Создайте Issue на GitHub с логами

---

**Готово! Ваш Nyxo Messenger v2.0 запущен! 🚀**

Первый запуск: создайте аккаунт или используйте "Приватный режим" для анонимного доступа.
