//! HTTP API server for The Vault CTF challenge.
//!
//! Serves both the WASM browser experience (static files) and a JSON API
//! for programmatic access by AI tools (ChatGPT, Gemini, etc.).

use std::net::SocketAddr;

use axum::extract::{Json, Path};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::info;

use ctf_engine::{AttackResult, CtfEngine, Level, LevelMeta, ToolCall};

mod openapi;

// ── API types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AttackRequest {
    level: u8,
    tool_calls: Vec<ToolCall>,
}

#[derive(Serialize)]
struct LevelsResponse {
    levels: Vec<LevelMeta>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ── Handlers ─────────────────────────────────────────────────────────────

async fn list_levels() -> Json<LevelsResponse> {
    let levels: Vec<LevelMeta> = (1..=7).map(|n| Level::new(n).meta()).collect();
    Json(LevelsResponse { levels })
}

async fn get_level(
    Path(level): Path<u8>,
) -> Result<Json<LevelMeta>, (StatusCode, Json<ErrorResponse>)> {
    if !(1..=7).contains(&level) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Level must be 1-7".into(),
            }),
        ));
    }
    Ok(Json(Level::new(level).meta()))
}

async fn submit_attack(
    Json(req): Json<AttackRequest>,
) -> Result<Json<AttackResult>, (StatusCode, Json<ErrorResponse>)> {
    if !(1..=7).contains(&req.level) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Level must be 1-7".into(),
            }),
        ));
    }
    if req.tool_calls.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "tool_calls must not be empty".into(),
            }),
        ));
    }
    if req.tool_calls.len() > 50 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Maximum 50 tool calls per request".into(),
            }),
        ));
    }

    let level = Level::new(req.level);
    let mut engine = CtfEngine::new(&level);
    let result = engine.run_attack(&req.tool_calls);
    Ok(Json(result))
}

// ── Main ─────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_routes = Router::new()
        .route("/api/v1/levels", get(list_levels))
        .route("/api/v1/levels/{level}", get(get_level))
        .route("/api/v1/attack", post(submit_attack))
        .route("/openapi.json", get(openapi::spec))
        .route(
            "/.well-known/ai-plugin.json",
            get(openapi::ai_plugin_manifest),
        )
        .layer(cors);

    // Serve static WASM site at root, API routes take priority
    let app = Router::new()
        .merge(api_routes)
        .fallback_service(ServeDir::new("/public"));

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("The Vault CTF server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
