use std::env;

/// Конфигурация сервиса, читаемая из окружения (.env в разработке).
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Общий секрет для внутренней аутентификации запросов от Node.
    /// Сервис никогда не должен быть напрямую доступен из интернета —
    /// этот секрет лишь defense-in-depth на случай, если сетевая
    /// изоляция где-то ослабнет.
    pub internal_shared_secret: String,
    /// Максимальный размер батча one-time prekeys за один запрос.
    pub max_otpk_batch: usize,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // В проде переменные окружения обычно приходят от процесс-менеджера,
        // поэтому отсутствие .env — не ошибка.
        let _ = dotenvy::dotenv();

        let database_url =
            env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is not set"))?;
        let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:7420".to_string());
        let internal_shared_secret = env::var("INTERNAL_SHARED_SECRET").map_err(|_| {
            anyhow::anyhow!(
                "INTERNAL_SHARED_SECRET is not set — this must be a long random value \
                 shared with the Node backend, see .env.example"
            )
        })?;
        if internal_shared_secret.len() < 32 {
            anyhow::bail!("INTERNAL_SHARED_SECRET must be at least 32 characters long");
        }
        let max_otpk_batch = env::var("MAX_OTPK_BATCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);

        Ok(Self {
            database_url,
            bind_addr,
            internal_shared_secret,
            max_otpk_batch,
        })
    }
}
