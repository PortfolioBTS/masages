# Сборка: docker build -t e2ee-key-server e2ee-key-server/
# (на Railway — Root Directory = e2ee-key-server, Dockerfile подхватывается сам).
#
# Тулчейн закреплён: Cargo.lock требует Rust >= 1.71 (максимальный MSRV среди
# зависимостей), Cargo.toml — >= 1.75. Образ на bookworm — под тот же glibc,
# что и рантайм-образ ниже.
FROM rust:1.94-bookworm AS builder
WORKDIR /app

# Cargo.lock обязателен: --locked собирает ровно проверенные версии
# зависимостей и падает, если lock-файл расходится с Cargo.toml.
COPY Cargo.toml Cargo.lock build.rs ./
# migrations/ нужна уже на этапе компиляции: sqlx::migrate! встраивает SQL в
# бинарник, без папки сборка упадёт.
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Сервис ничего не пишет на диск и не слушает привилегированные порты —
# root ему не нужен.
RUN groupadd --system --gid 10001 keyserver \
    && useradd --system --uid 10001 --gid keyserver --no-create-home \
       --shell /usr/sbin/nologin keyserver
WORKDIR /app
COPY --from=builder /app/target/release/e2ee-key-server /app/e2ee-key-server
USER 10001:10001

# BIND_ADDR намеренно не задаётся: по умолчанию сервис слушает 127.0.0.1:7420
# (config.rs), а в контейнере это значит «недоступен никому». Адрес задаётся
# явно при деплое — на Railway BIND_ADDR=[::]:7420 для private networking,
# см. README. Обязательны также DATABASE_URL и INTERNAL_SHARED_SECRET.
EXPOSE 7420
CMD ["/app/e2ee-key-server"]
