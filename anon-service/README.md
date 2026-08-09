# Anon Service (Rust)

Микросервис для криптографически стойкой генерации приватных идентификаторов.

## API

### POST /generate

Возвращает JSON:
```json
{
  "unique_code": "A3F9K2M8",
  "username": "Гость-X7B2Q"
}
```

## Запуск

```bash
cargo run --release
```

Сервер слушает `0.0.0.0:8080`.
