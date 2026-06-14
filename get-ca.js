// Запускать на Railway: node get-ca.js
// Скрипт подключается к PostgreSQL и сохраняет CA-сертификат в файл railway-ca.pem

const tls = require('tls');
const fs = require('fs');
const url = require('url');

const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
    console.error('DATABASE_URL не задан!');
    process.exit(1);
}

const parsed = new url.URL(dbUrl);
const host = parsed.hostname;
const port = parseInt(parsed.port) || 5432;

console.log(`Подключаемся к ${host}:${port}...`);

// PostgreSQL требует SSL handshake через StartTLS — сначала шлём байты запроса
const socket = require('net').createConnection(port, host, () => {
    // SSLRequest message для PostgreSQL
    const sslRequest = Buffer.from([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]);
    socket.write(sslRequest);
});

socket.once('data', (data) => {
    // PostgreSQL отвечает 'S' если поддерживает SSL
    if (data[0] !== 0x53) {
        console.error('Сервер не поддерживает SSL');
        socket.destroy();
        process.exit(1);
    }

    // Апгрейдим до TLS
    const tlsSocket = tls.connect({
        socket,
        host,
        rejectUnauthorized: false, // нужно чтобы получить сертификат даже если он self-signed
    }, () => {
        const cert = tlsSocket.getPeerCertificate(true);

        if (!cert || !cert.raw) {
            console.error('Не удалось получить сертификат');
            tlsSocket.destroy();
            process.exit(1);
        }

        // Идём по цепочке до корневого CA
        let current = cert;
        let rootCert = cert;
        const seen = new Set();

        while (current.issuerCertificate && current.issuerCertificate !== current) {
            const fp = current.fingerprint;
            if (seen.has(fp)) break;
            seen.add(fp);
            rootCert = current.issuerCertificate;
            current = current.issuerCertificate;
        }

        // Конвертируем в PEM
        const pemCert = [
            '-----BEGIN CERTIFICATE-----',
            rootCert.raw.toString('base64').match(/.{1,64}/g).join('\n'),
            '-----END CERTIFICATE-----',
        ].join('\n');

        fs.writeFileSync('railway-ca.pem', pemCert);
        console.log('\n✅ Сертификат сохранён в railway-ca.pem\n');
        console.log('Субъект:', rootCert.subject);
        console.log('Издатель:', rootCert.issuer);
        console.log('Действителен до:', rootCert.valid_to);
        console.log('\n--- Содержимое для DB_CA_CERT ---');
        console.log(pemCert);
        console.log('--- Конец ---');

        tlsSocket.destroy();
        process.exit(0);
    });

    tlsSocket.on('error', (err) => {
        console.error('TLS ошибка:', err.message);
        process.exit(1);
    });
});

socket.on('error', (err) => {
    console.error('Ошибка подключения:', err.message);
    process.exit(1);
});

socket.setTimeout(10000, () => {
    console.error('Таймаут подключения');
    socket.destroy();
    process.exit(1);
});