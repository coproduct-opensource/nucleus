//! The HTTP surface: the pointer, the two ways to move it, and an endpoint
//! that answers from the checkpoint the pointer names and says which one
//! answered.
//!
//! | Route | Answers |
//! |---|---|
//! | `GET /v1/pointer` | the serving pointer |
//! | `GET /v1/releases` | the release log |
//! | `POST /v1/promote` | a verdict on a release chain |
//! | `POST /v1/rollback` | a verdict on a rollback order |
//! | `POST /v1/generate` | the backend's answer, with the digest and generation that produced it |
//!
//! A move is `200`, a refusal `409`, and "could not look" `503`. The body says
//! which in every case; the status is a summary, not the answer.
//!
//! The generate endpoint has no cache that outlives the pointer. When the
//! pointer changes, the files it now names are measured before anything is
//! answered from them, and if they do not measure to the pointer's digest the
//! endpoint answers `503`: it does not go on serving the checkpoint it had.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use nucleus_receipt::Receipt;
use nucleus_release_gate::chain::{PointerState, Refusal, ReleaseChain, claimed_candidate};
use nucleus_release_gate::registry::{MoveVerdict, Registry, ReleaseRecord};
use nucleus_weight_patch::CheckpointDigest;
use serde::{Deserialize, Serialize};

use crate::store::CheckpointStore;

/// What turns a checkpoint and a request into an answer.
///
/// This crate names no model and runs none. An operator supplies the backend;
/// the service supplies it with files that have just been measured to be the
/// checkpoint the pointer names.
pub trait Backend: Send + Sync + 'static {
    /// Answers `request` from the checkpoint in `files`.
    ///
    /// # Errors
    ///
    /// A message for the caller if the backend cannot answer.
    fn answer(
        &self,
        files: &[PathBuf],
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

/// The files the pointer named when they were last measured.
struct Loaded {
    pointer: PointerState,
    files: Vec<PathBuf>,
}

/// The registry, the store and the backend behind the routes.
pub struct Service {
    registry: Registry,
    store: CheckpointStore,
    backend: Box<dyn Backend>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    loaded: Mutex<Option<Loaded>>,
}

/// The answer to a request to move the pointer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Reply {
    /// The pointer moved.
    Moved {
        /// The registry's signed account of the move.
        release: Box<Receipt>,
        /// The pointer after it.
        pointer: PointerState,
    },
    /// The pointer did not move, for this reason.
    Refused {
        /// The reason.
        refusal: Refusal,
        /// The pointer, unchanged.
        pointer: PointerState,
    },
    /// The service could not look. The pointer did not move.
    CouldNotLook {
        /// What went wrong.
        detail: String,
    },
}

/// An answer from the serving endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Answer {
    /// The checkpoint that produced the output.
    pub digest: CheckpointDigest,
    /// The pointer generation it was served at.
    pub generation: u64,
    /// The backend's output.
    pub output: serde_json::Value,
}

/// Why a request that is not a move could not be answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unavailable {
    /// What went wrong.
    pub error: String,
}

impl From<MoveVerdict> for Reply {
    fn from(verdict: MoveVerdict) -> Self {
        match verdict {
            MoveVerdict::Moved { release, pointer } => Self::Moved {
                release: Box::new(release),
                pointer,
            },
            MoveVerdict::Refused { refusal, pointer } => Self::Refused { refusal, pointer },
            MoveVerdict::CouldNotLook(e) => Self::CouldNotLook {
                detail: e.to_string(),
            },
        }
    }
}

impl Service {
    /// A service over `registry` and `store`, answering with `backend`.
    ///
    /// `clock` gives the present in microseconds since the epoch. It is an
    /// argument so that nothing below the binary's `main` reads a clock.
    pub fn new(
        registry: Registry,
        store: CheckpointStore,
        backend: Box<dyn Backend>,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            registry,
            store,
            backend,
            clock,
            loaded: Mutex::new(None),
        }
    }

    /// The registry behind the service.
    pub const fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Decides a promotion.
    ///
    /// Before the chain is walked, the store is asked for the candidate the
    /// chain names. A pointer must never be moved to a digest the store cannot
    /// produce, and finding that out after the move would be too late.
    pub fn promote(&self, chain: &ReleaseChain) -> Reply {
        if let Some(candidate) = claimed_candidate(chain)
            && let Err(e) = self.store.measured(candidate)
        {
            return Reply::CouldNotLook {
                detail: format!("the candidate cannot be served: {e}"),
            };
        }
        self.registry.promote(chain, (self.clock)()).into()
    }

    /// Decides a rollback.
    pub fn rollback(&self, order: &Receipt) -> Reply {
        self.registry.rollback(order, (self.clock)()).into()
    }

    /// Answers `request` from the checkpoint the pointer names.
    ///
    /// # Errors
    ///
    /// A message if the pointer cannot be read, the files it names do not
    /// measure to its digest, or the backend cannot answer.
    pub fn generate(&self, request: &serde_json::Value) -> Result<Answer, String> {
        let pointer = self.registry.pointer().map_err(|e| e.to_string())?;
        let files = {
            let mut loaded = self
                .loaded
                .lock()
                .map_err(|_| "the serving state is poisoned".to_owned())?;
            let current = loaded.as_ref().filter(|l| l.pointer == pointer);
            match current {
                Some(l) => l.files.clone(),
                None => {
                    // Forget the old checkpoint before measuring the new one:
                    // if the measurement fails, nothing is left to serve.
                    *loaded = None;
                    let files = self
                        .store
                        .measured(pointer.current)
                        .map_err(|e| e.to_string())?;
                    *loaded = Some(Loaded {
                        pointer,
                        files: files.clone(),
                    });
                    files
                }
            }
        };
        let output = self.backend.answer(&files, request)?;
        Ok(Answer {
            digest: pointer.current,
            generation: pointer.generation,
            output,
        })
    }
}

fn unavailable(error: impl ToString) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Unavailable {
            error: error.to_string(),
        }),
    )
        .into_response()
}

fn reply(reply: Reply) -> Response {
    let status = match &reply {
        Reply::Moved { .. } => StatusCode::OK,
        Reply::Refused { .. } => StatusCode::CONFLICT,
        Reply::CouldNotLook { .. } => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(reply)).into_response()
}

/// Runs blocking work off the async threads and maps a lost task to `503`.
async fn blocking<T, F>(work: F, respond: impl FnOnce(T) -> Response) -> Response
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(value) => respond(value),
        Err(e) => unavailable(e),
    }
}

async fn pointer(State(service): State<Arc<Service>>) -> Response {
    blocking(
        move || service.registry.pointer(),
        |pointer| match pointer {
            Ok(pointer) => Json(pointer).into_response(),
            Err(e) => unavailable(e),
        },
    )
    .await
}

async fn releases(State(service): State<Arc<Service>>) -> Response {
    blocking(
        move || service.registry.records(),
        |records: Result<Vec<ReleaseRecord>, _>| match records {
            Ok(records) => Json(records).into_response(),
            Err(e) => unavailable(e),
        },
    )
    .await
}

async fn promote(State(service): State<Arc<Service>>, Json(chain): Json<ReleaseChain>) -> Response {
    blocking(move || service.promote(&chain), reply).await
}

async fn rollback(State(service): State<Arc<Service>>, Json(order): Json<Receipt>) -> Response {
    blocking(move || service.rollback(&order), reply).await
}

async fn generate(
    State(service): State<Arc<Service>>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    blocking(
        move || service.generate(&request),
        |answer| match answer {
            Ok(answer) => Json(answer).into_response(),
            Err(e) => unavailable(e),
        },
    )
    .await
}

/// The routes, over `service`.
pub fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route("/v1/pointer", get(pointer))
        .route("/v1/releases", get(releases))
        .route("/v1/promote", post(promote))
        .route("/v1/rollback", post(rollback))
        .route("/v1/generate", post(generate))
        .with_state(service)
}
