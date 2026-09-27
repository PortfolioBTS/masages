use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use rand::{thread_rng, Rng};
use serde::Serialize;
use std::{env, hint::black_box, net::SocketAddr, process, sync::Arc};

// [::] — dual-stack: на Linux такой сокет принимает и IPv6, и IPv4. Private
// networking Railway в старых окружениях только IPv6, и слушать 0.0.0.0 там
// значит быть недоступным для Node.
const DEFAULT_BIND_ADDR: &str = "[::]:8080";

#[derive(Clone)]
struct AppState {
    /// Общий секрет с Node (ANON_SERVICE_SECRET). None — проверка выключена,
    /// сервис полагается только на сетевую изоляцию, как раньше.
    secret: Option<Arc<String>>,
}

#[derive(Serialize)]
struct AnonIdentity {
    unique_code: String,
    username: String,
}

fn generate_code() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = thread_rng();
    (0..8).map(|_| {
        let idx = rng.gen_range(0..CHARS.len());
        CHARS[idx] as char
    }).collect()
}

fn generate_username() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = thread_rng();
    let suffix: String = (0..5).map(|_| {
        let idx = rng.gen_range(0..CHARS.len());
        CHARS[idx] as char
    }).collect();
    format!("Гость-{}", suffix)
}

/// Сравнение без раннего выхода: время не зависит от того, в каком байте
/// первое расхождение, поэтому секрет нельзя подобрать побайтно по таймингу.
/// Длина секрета при этом не скрывается — она не секретна. black_box не
/// даёт оптимизатору превратить свёртку обратно в сравнение с ранним выходом.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff = black_box(diff | (x ^ y));
    }
    diff == 0
}

async fn generate_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AnonIdentity>, StatusCode> {
    if let Some(expected) = &state.secret {
        let authorized = headers
            .get("x-internal-secret")
            .map(|given| constant_time_eq(given.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !authorized {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    Ok(Json(AnonIdentity {
        unique_code: generate_code(),
        username: generate_username(),
    }))
}

/// Адрес из BIND_ADDR (пустое значение = не задано). Только IP:порт —
/// имя хоста вроде localhost:8080 не принимается, чтобы адрес
/// прослушивания не зависел от DNS.
fn bind_addr() -> Result<SocketAddr, String> {
    let raw = env::var("BIND_ADDR")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string());
    raw.parse::<SocketAddr>().map_err(|e| {
        format!(
            "BIND_ADDR={raw:?} — не адрес вида IP:порт \
             (например [::]:8080 или 0.0.0.0:8080): {e}"
        )
    })
}

#[tokio::main]
async fn main() {
    let addr = bind_addr().unwrap_or_else(|message| {
        eprintln!("[Anon] {message}");
        process::exit(1);
    });

    let secret = env::var("ANON_SERVICE_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .map(Arc::new);
    if secret.is_some() {
        println!("[Anon] POST /generate требует заголовок X-Internal-Secret");
    } else {
        println!("[Anon] ANON_SERVICE_SECRET не задан — /generate доступен без секрета");
    }

    let app = Router::new()
        .route("/generate", post(generate_identity))
        .with_state(AppState { secret });

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("[Anon] Не удалось открыть {addr}: {e}");
        process::exit(1);
    });
    println!("[Anon] Listening on {}", addr);

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("[Anon] Сервер остановился с ошибкой: {e}");
        process::exit(1);
    }
}
