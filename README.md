# Nyxo Messenger

Безопасный мессенджер на Node.js + PostgreSQL с приватным режимом и микросервисом анонимности на Rust.

## Требования

- Node.js 18+
- PostgreSQL 14+
- Rust 1.70+ (для микросервиса анонимности)

## Переменные окружения

Скопируйте `.env.example` в `.env` и заполните:

```env
SESSION_SECRET=your_random_secret_min_32_chars
DATABASE_URL=postgresql://user:pass@localhost:5432/nyxo
NODE_ENV=development
PORT=3000
HOST=0.0.0.0
ANON_SERVICE_URL=http://127.0.0.1:8080
```

## Установка

```bash
# 1. Установка зависимостей Node.js
npm install

# 2. Запуск микросервиса анонимности (Rust)
cd anon-service
cargo run --release
# или через Docker:
docker build -t anon-service . && docker run -p 8080:8080 anon-service

# 3. Запуск основного сервера (в новом терминале)
npm start
```

## Структура проекта

- `server.js` — основной сервер (Express + Socket.io)
- `public/` — статика (HTML, CSS, JS)
- `anon-service/` — Rust микросервис генерации приватных идентификаторов
- `uploads/` — загруженные файлы (создаётся автоматически)

## Безопасность

- CSP с nonce
- CSRF double-submit cookie
- Rate limiting на auth эндпоинтах
- Проверка magic bytes для загрузок
- Параметризованные SQL-запросы
- Сессии в PostgreSQL

⚠️ Сквозное шифрование (E2EE) сообщений пока не подключено, несмотря на
наличие сервиса `e2ee-key-server` в репозитории — подробности и текущий
статус см. в [SECURITY.md](./SECURITY.md#известные-ограничения).
