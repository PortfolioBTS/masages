# Cargo.lock в репозитории нет, зависимости резолвятся при каждой сборке в
# самые свежие совместимые версии. На rust:1.80 сборка уже не проходила:
# свежий hyper-util (зависимость axum 0.7) требует Rust 1.85 и edition 2024.
# fallback-резолвер (cargo >= 1.84) предпочитает версии, совместимые с
# rust-version из Cargo.toml, чтобы очередной подъём MSRV у зависимостей не
# ломал сборку.
FROM rust:1.94-bookworm AS builder
ENV CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
# Сервису не нужен root: он ничего не пишет на диск и слушает порт 8080.
RUN groupadd --system --gid 10001 anon \
    && useradd --system --uid 10001 --gid anon --no-create-home \
       --shell /usr/sbin/nologin anon
WORKDIR /app
COPY --from=builder /app/target/release/anon-service /app/anon-service
USER 10001:10001
# Адрес по умолчанию — [::]:8080 (см. BIND_ADDR в README).
EXPOSE 8080
CMD ["/app/anon-service"]
