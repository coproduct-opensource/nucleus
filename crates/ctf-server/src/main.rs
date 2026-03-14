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

#[derive(Deserialize)]
struct ChallengeRequest {
    /// Who is playing? (e.g. "chatgpt-4o", "claude-3.5-sonnet", "human")
    player: String,
    /// One attack per level (index 0 = level 1, etc.). Omit levels to skip them.
    attacks: Vec<ChallengeAttack>,
}

#[derive(Deserialize)]
struct ChallengeAttack {
    level: u8,
    tool_calls: Vec<ToolCall>,
}

#[derive(Serialize)]
struct ChallengeResult {
    player: String,
    levels: Vec<LevelResult>,
    total_score: u32,
    max_possible_score: u32,
    defenses_triggered: Vec<String>,
    summary: String,
}

#[derive(Serialize)]
struct LevelResult {
    level: u8,
    name: String,
    result: AttackResult,
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

async fn run_challenge(
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResult>, (StatusCode, Json<ErrorResponse>)> {
    if req.attacks.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "attacks must not be empty".into(),
            }),
        ));
    }
    if req.attacks.len() > 7 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Maximum 7 attacks (one per level)".into(),
            }),
        ));
    }
    for atk in &req.attacks {
        if !(1..=7).contains(&atk.level) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid level: {}", atk.level),
                }),
            ));
        }
        if atk.tool_calls.len() > 50 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Level {} has >50 tool calls", atk.level),
                }),
            ));
        }
    }

    let mut levels = Vec::new();
    let mut all_defenses = std::collections::BTreeSet::new();
    let mut total_score = 0u32;

    for atk in &req.attacks {
        let level = Level::new(atk.level);
        let name = level.meta().name.to_string();
        let mut engine = CtfEngine::new(&level);
        let result = engine.run_attack(&atk.tool_calls);
        total_score += result.score;
        for d in &result.defenses_activated {
            all_defenses.insert(d.clone());
        }
        levels.push(LevelResult {
            level: atk.level,
            name,
            result,
        });
    }

    // Max score: 6 defenses * 100 per level that has them + 500 for L1 flag
    let max_possible_score = 500 + 6 * 100;
    let pct = (total_score as f64 / max_possible_score as f64 * 100.0) as u32;
    let summary = format!(
        "{} scored {}/{} ({}%) — triggered {}/6 unique defense layers across {} levels.",
        req.player,
        total_score,
        max_possible_score,
        pct,
        all_defenses.len(),
        levels.len(),
    );

    Ok(Json(ChallengeResult {
        player: req.player,
        levels,
        total_score,
        max_possible_score,
        defenses_triggered: all_defenses.into_iter().collect(),
        summary,
    }))
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
        .route("/api/v1/challenge", post(run_challenge))
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
