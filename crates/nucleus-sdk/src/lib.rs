//! # Nucleus SDK
//!
//! Rust SDK for building sandboxed AI agents with [nucleus](https://github.com/coproduct-opensource/nucleus).
//!
//! This crate provides a unified client for interacting with nucleus services:
//!
//! - **[`ProxyClient`]** — HTTP client for the tool-proxy (file I/O, execution, web access)
//! - **[`NodeClient`]** — gRPC client for nucleus-node (pod lifecycle, streaming logs)
//! - **[`Nucleus`]** — Unified facade combining both clients
//! - **[`Intent`]** — High-level permission profiles mapped to lattice-guard policies
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use nucleus_sdk::{Nucleus, Intent, HmacAuth};
//!
//! # async fn example() -> nucleus_sdk::Result<()> {
//! // Connect to a running tool-proxy
//! let nucleus = Nucleus::builder()
//!     .proxy_url("http://127.0.0.1:8080")
//!     .auth(HmacAuth::new(b"my-secret", Some("agent")))
//!     .build()?;
//!
//! // Open a scoped session with trifecta-safe permissions
//! let session = nucleus.intent(Intent::FixIssue).await?;
//!
//! // All operations enforced by lattice-guard inside the pod
//! let source = session.read("src/main.rs").await?;
//! session.write("src/main.rs", &source.replace("bug", "fix")).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │  nucleus-sdk (this crate)               │
//! │  ┌─────────┐  ┌──────────┐  ┌────────┐ │
//! │  │ Nucleus  │──│  Intent  │──│ Auth   │ │
//! │  │ (facade) │  │ (profile)│  │ (HMAC) │ │
//! │  └────┬─────┘  └──────────┘  └────────┘ │
//! │       │                                  │
//! │  ┌────┴────────┐  ┌────────────────┐    │
//! │  │ ProxyClient │  │  NodeClient    │    │
//! │  │ (HTTP)      │  │  (gRPC/tonic)  │    │
//! │  └─────────────┘  └────────────────┘    │
//! └──────────────────────────────────────────┘
//!        │                    │
//!        ▼                    ▼
//!   tool-proxy            nucleus-node
//!   (in-pod HTTP)         (gRPC service)
//! ```
//!
//! ## Feature Flags
//!
//! - **`identity`** — Enable SPIFFE identity support via `nucleus-identity`.
//!   Adds mTLS client configuration and workload certificate management.

pub mod auth;
pub mod client;
pub mod error;
pub mod intent;
pub mod node;
pub mod proxy;
pub mod types;

// Flat re-exports for ergonomic use
pub use auth::{AuthStrategy, HmacAuth, MtlsConfig};
pub use client::{Nucleus, NucleusBuilder};
pub use error::Error;
pub use intent::{Intent, IntentProfile, IntentSession};
pub use node::NodeClient;
pub use proxy::ProxyClient;
pub use types::*;

/// Result type alias for nucleus SDK operations.
pub type Result<T> = std::result::Result<T, Error>;
