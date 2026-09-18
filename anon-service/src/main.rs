use axum::{
    routing::post,
    Router,
    Json,
    http::StatusCode,
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

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

async fn generate_identity() -> Result<Json<AnonIdentity>, StatusCode> {
    Ok(Json(AnonIdentity {
        unique_code: generate_code(),
        username: generate_username(),
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/generate", post(generate_identity));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("[Anon] Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
