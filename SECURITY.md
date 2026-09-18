# Security Guidelines - Nyxo Messenger

## 🔒 Рекомендации по безопасности

### Для пользователей

#### Максимальная анонимность
1. **Используйте Tor Browser** для доступа к мессенджеру
2. **Включите "Приватный режим"** вместо регистрации с email
3. **Настройте disappearing messages** для важных чатов
4. **Не загружайте файлы** с личными метаданными (даже с stripping есть риски)
5. **Используйте VPN + Tor** для дополнительной защиты

#### Операционная безопасность
- Не используйте реальные имена в username
- Не делитесь уникальными кодами публично
- Выходите из аккаунта после использования (особенно анонимный режим)
- Регулярно очищайте кэш браузера
- Используйте отдельный профиль браузера для мессенджера

#### Риски
⚠️ **E2EE еще не реализован на клиенте** — сообщения хранятся в БД без шифрования
⚠️ **Сервер видит контент** — не используйте для критически важных данных
⚠️ **Metadata stripping** не защищает от уже переданной информации

---

### Для администраторов

#### Обязательные настройки

1. **Используйте HTTPS**
   ```nginx
   # Обязательно SSL/TLS
   listen 443 ssl http2;
   ssl_protocols TLSv1.3 TLSv1.2;
   ssl_ciphers HIGH:!aNULL:!MD5;
   ```

2. **Сильные секреты**
   ```bash
   # Минимум 32 байта (64 hex символа)
   SESSION_SECRET=$(openssl rand -hex 32)
   INTERNAL_KEY_SERVER_SECRET=$(openssl rand -base64 32)
   ```

3. **Защита БД**
   ```env
   # Используйте SSL для PostgreSQL
   DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=require
   DB_CA_CERT=your_certificate_chain
   ```

4. **Firewall правила**
   ```bash
   # Только необходимые порты
   ufw allow 443/tcp   # HTTPS
   ufw allow 9050/tcp  # Tor (если используется)
   ufw deny 3000/tcp   # Node.js должен быть за Nginx
   ```

5. **Rate Limiting**
   ```javascript
   // Уже настроено в server.js
   // Проверьте логи на bruteforce попытки
   grep "Too many requests" /var/log/nyxo/*.log
   ```

#### Мониторинг безопасности

1. **Аудит логов**
   ```bash
   # Подозрительная активность
   grep -E "CSRF|Rate limit|Metadata strip fail" logs/*.log
   
   # Анонимные пользователи
   grep "\[Anon\]" logs/*.log
   
   # Failed logins
   grep "Неверный email или пароль" logs/*.log
   ```

2. **База данных**
   ```sql
   -- Проверка анонимных пользователей
   SELECT COUNT(*) FROM users WHERE email IS NULL;
   
   -- Старые неудаленные анонимные пользователи
   SELECT id, username, created_at FROM users 
   WHERE email IS NULL 
   AND created_at < NOW() - INTERVAL '24 hours';
   
   -- Сообщения с метаданными экспирации
   SELECT COUNT(*) FROM message_expiry 
   WHERE expires_at < NOW();
   ```

3. **Обновления безопасности**
   ```bash
   # Регулярно проверяйте уязвимости
   npm audit
   npm audit fix
   
   # Обновление зависимостей
   npm update
   npm outdated
   ```

#### Защита от атак

1. **DDoS Protection**
   - Используйте Cloudflare или аналог
   - Настройте rate limiting на уровне Nginx
   - Мониторьте необычный трафик

2. **SQL Injection**
   - ✅ Уже защищено параметризованными запросами
   - Никогда не используйте string concatenation в SQL

3. **XSS**
   - ✅ CSP с nonce уже настроен
   - Проверяйте что nonce генерируется на каждый запрос

4. **CSRF**
   - ✅ Double-submit cookie pattern реализован
   - Мониторьте failed CSRF токены

#### Резервное копирование

```bash
# Ежедневный бэкап БД
0 2 * * * pg_dump nyxo | gzip > /backup/nyxo_$(date +\%Y\%m\%d).sql.gz

# Ротация бэкапов (хранить 30 дней)
0 3 * * * find /backup -name "nyxo_*.sql.gz" -mtime +30 -delete

# Бэкап .env и конфигов
0 2 * * * tar -czf /backup/config_$(date +\%Y\%m\%d).tar.gz /opt/nyxo/.env /etc/nginx/sites-available/nyxo
```

#### Инциденты

При компрометации:

1. **Немедленно**:
   - Остановите сервер: `pm2 stop nyxo`
   - Смените все секреты в .env
   - Сбросьте все сессии: `DELETE FROM session;`

2. **Анализ**:
   - Проверьте логи на точку входа
   - Проверьте целостность файлов
   - Проверьте БД на изменения

3. **Восстановление**:
   - Обновите все зависимости
   - Смените DATABASE_URL credentials
   - Уведомите пользователей

---

## 🛡️ Implemented Security Features

### ✅ Already Protected

1. **CSRF Protection** — double-submit cookie pattern
2. **Rate Limiting** — на всех критичных эндпоинтах
3. **SQL Injection** — параметризованные запросы
4. **XSS** — CSP с nonce
5. **File Upload** — magic bytes verification + whitelist
6. **Metadata Stripping** — EXIF, PDF metadata removal
7. **Timing Attacks** — random delays в authentication
8. **Traffic Analysis** — message padding
9. **Session Security** — httpOnly, secure, sameSite cookies
10. **Privacy Headers** — полный набор защитных заголовков

### ⏳ In Progress

1. **E2EE Client** — требуется WASM модуль
2. **Perfect Forward Secrecy** — после E2EE интеграции
3. **Multi-device** — синхронизация ключей

### 🔜 Planned

1. **Code Signing** — проверка целостности клиента
2. **Reproducible Builds** — для верификации
3. **Security Audit** — третьей стороной
4. **Bug Bounty Program**

---

## 📋 Security Checklist

### Deployment Checklist

- [ ] HTTPS настроен с валидным сертификатом
- [ ] SESSION_SECRET — случайная строка 64+ символов
- [ ] DATABASE_URL использует SSL (sslmode=require)
- [ ] NODE_ENV=production
- [ ] Firewall настроен (только 443, 80)
- [ ] Rate limiting активен
- [ ] Логи ротируются
- [ ] Бэкапы настроены
- [ ] Мониторинг работает
- [ ] .env не в git
- [ ] Секреты не в логах
- [ ] PostgreSQL требует пароль
- [ ] Tor настроен (если используется)
- [ ] E2EE key server защищен INTERNAL_KEY_SERVER_SECRET

### Regular Maintenance

- [ ] Еженедельно: проверка npm audit
- [ ] Ежемесячно: обновление зависимостей
- [ ] Ежемесячно: аудит логов
- [ ] Ежемесячно: проверка бэкапов
- [ ] Ежеквартально: тестирование восстановления
- [ ] Ежеквартально: review security политик

---

## 🚨 Vulnerability Reporting

Если вы нашли уязвимость безопасности:

1. **НЕ** создавайте публичный Issue
2. Отправьте email: [security@example.com]
3. Опишите проблему детально
4. Дайте время на исправление (90 дней)
5. Coordinated disclosure после патча

Мы ценим responsible disclosure и можем наградить за находки.

---

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
- [Tor Hidden Service](https://community.torproject.org/onion-services/)
- [Signal Protocol](https://signal.org/docs/) — для референса E2EE

---

**Security is a process, not a product. Stay vigilant! 🔒**
