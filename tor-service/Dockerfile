# Onion-сервис Nyxo (tor + socat) — отдельный сервис Railway, см. README.md.
FROM debian:bookworm-slim

# tor — из bookworm-backports: ветка tor в основном репозитории bookworm
# отстаёт от поддерживаемой апстримом, а для onion-сервиса это исправления
# безопасности и защиты от DoS. "-t" лишь поднимает приоритет backports:
# если пакета там не окажется, apt возьмёт версию из bookworm, сборка не сломается.
RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' > /etc/apt/sources.list.d/backports.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends -t bookworm-backports tor \
    && apt-get install -y --no-install-recommends socat tini ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && tor --version \
    && command -v setpriv \
    && id debian-tor

COPY entrypoint.sh /usr/local/bin/nyxo-tor-entrypoint

# sed: CRLF из Windows-чекаута сломал бы shebang и сравнения в скрипте.
# Каталоги создаются и в образе — на случай запуска без volume (тогда адрес
# будет новым при каждом деплое, см. README).
RUN sed -i 's/\r$//' /usr/local/bin/nyxo-tor-entrypoint \
    && chmod 755 /usr/local/bin/nyxo-tor-entrypoint \
    && install -d -o debian-tor -g debian-tor -m 700 /var/lib/tor /var/lib/tor/nyxo /var/lib/tor/data

# USER не задан намеренно: Railway монтирует volume в /var/lib/tor от root,
# поэтому entrypoint стартует root'ом только чтобы выставить права на него,
# а tor (debian-tor) и socat (nobody) запускает без привилегий через setpriv
# с no_new_privs. tini — PID 1: пересылает SIGTERM и собирает зомби socat.
# Портов наружу нет: tor сам устанавливает исходящие соединения в сеть Tor.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/nyxo-tor-entrypoint"]
