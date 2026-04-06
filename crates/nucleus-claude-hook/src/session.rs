#![allow(clippy::disallowed_types)] // #1216 exempt: session state management (lock files, HWM, compartments)
//! Session state persistence for cross-invocation exposure tracking.
//!
//! This module handles all session lifecycle concerns:
//! - Persisting `SessionState` to disk (atomic writes with advisory locks)
//! - High-water-mark tamper detection
//! - Schema versioning and migration
//! - Compartment token generation and resolution
//! - Session garbage collection

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current schema version for SessionState.
/// Increment when adding fields that require migration logic beyond `#[serde(default)]`.
/// Version history:
///   1 — initial schema (implicit in pre-versioned files)
///   2 — added schema_version, last_pre_tool_obs_index (#523, #593)
///   3 — added flagged_tools for manifest violation tracking (#485)
pub(crate) const SESSION_SCHEMA_VERSION: u32 = 3;

/// Number of manifest violations before a tool is denied for the session (#485).
/// First violation: logged + flagged. Second violation: tool denied.
pub(crate) const MANIFEST_VIOLATION_REVOKE_THRESHOLD: u32 = 2;

/// Default TTL for stale session files (24 hours).
pub(crate) const SESSION_GC_TTL_SECS: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Session state types
// ---------------------------------------------------------------------------

/// Persisted session state for cross-invocation exposure tracking.
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionState {
    /// Schema version — enables forward/backward compatibility (#523).
    /// Missing (0) means pre-versioned file (treated as version 1).
    #[serde(default)]
    pub(crate) schema_version: u32,
    /// Profile name used for this session.
    pub(crate) profile: String,
    /// Monotonic operation counter — must never decrease.
    /// If state is loaded with hwm=0 but the watermark file says otherwise,
    /// someone deleted the state file (social engineering attack).
    #[serde(default)]
    pub(crate) high_water_mark: u64,
    /// Operations that were allowed (replayed to rebuild kernel exposure).
    pub(crate) allowed_ops: Vec<(String, String)>, // (operation, subject)
    /// Flow graph observations: (NodeKind discriminant, operation, subject).
    /// Replayed to rebuild the causal DAG across hook invocations.
    #[serde(default)]
    pub(crate) flow_observations: Vec<(u8, String, String)>,
    /// SHA-256 hash of the most recent receipt in the chain.
    /// Each new receipt includes this as `prev_hash`, creating an
    /// append-only chain that is tamper-evident when signed.
    #[serde(default)]
    pub(crate) chain_head_hash: [u8; 32],
    /// Ephemeral Ed25519 signing key (PKCS#8 DER, generated per session).
    /// Stored so receipts across hook invocations use the same key.
    ///
    /// **Threat model**: The session file is protected by 0600 permissions and
    /// the parent directory by 0700. This prevents other-user access but not
    /// same-user process access. Full protection against same-user compromise
    /// requires process isolation (Nucleus pods / Firecracker microVMs). See #744.
    #[serde(default)]
    pub(crate) signing_key_pkcs8: Vec<u8>,
    /// Active compartment name (if any). Used to detect transitions.
    #[serde(default)]
    pub(crate) active_compartment: Option<String>,
    /// Lowest compartment reached during this session (#471).
    /// When `NUCLEUS_RATCHET_MODE=1`, escalation above this level is denied.
    /// Tracks the lowest (most restrictive) compartment ever activated.
    #[serde(default)]
    pub(crate) lowest_compartment: Option<String>,
    /// Random token for keying the compartment filename (hex string).
    /// Generated once per session. The model cannot predict this because
    /// it's stored in session state (which the model can't read).
    #[serde(default)]
    pub(crate) compartment_token: String,
    /// Parent agent's session ID (for cross-agent receipt chaining).
    #[serde(default)]
    pub(crate) parent_session_id: Option<String>,
    /// Parent agent's chain head hash at spawn time (hex).
    /// Links this child's receipt chain to the parent's chain.
    #[serde(default)]
    pub(crate) parent_chain_hash: Option<String>,
    /// Number of flow observations at the time of the last PreToolUse Allow.
    /// PostToolUse uses this to know which observation was the pre-tool node,
    /// so the ToolResponse can be wired as a sibling in the DAG (#593).
    #[serde(default)]
    pub(crate) last_pre_tool_obs_index: Option<usize>,
    /// Per-tool manifest violation counts (#485). Incremented on PostToolUse
    /// when behavioral enforcement detects a violation. On PreToolUse, tools
    /// with count >= MANIFEST_VIOLATION_REVOKE_THRESHOLD are denied.
    /// Monotonic — trust can only decrease within a session.
    #[serde(default)]
    pub(crate) flagged_tools: std::collections::HashMap<String, u32>,
    /// Fingerprint of the last additionalContext injected (#842).
    /// Format: "compartment:taint_state" (e.g. "research:clean", "draft:tainted").
    /// When this changes (or is empty), we inject context again.
    #[serde(default)]
    pub(crate) last_injected_context_key: Option<String>,
    /// Whether this session has been tainted by web content (#838).
    /// Set on PostToolUse when a web-fetching tool returns data.
    /// Once true, never reverts — web taint is monotonic within a session.
    #[serde(default)]
    pub(crate) web_tainted: bool,
    /// Whether the web taint warning has been injected into additionalContext (#838).
    /// Prevents repeated injection — the model only needs to be told once.
    #[serde(default)]
    pub(crate) web_taint_context_injected: bool,
    /// Set by `UserPromptSubmit` when the user types `! <cmd>` (#918).
    /// Consumed by the next `PostToolUse` to classify the output as
    /// `Deterministic/Directive` (user-directed reduction).
    #[serde(default)]
    pub(crate) pending_user_bash: bool,
    /// Content hashes of web tool outputs, captured at PostToolUse time (#873).
    /// Each entry records the SHA-256 of the tool result, the tool name, and
    /// the Unix timestamp. These are the anchors for future `ReductionWitness`
    /// chains — `/clearance` can reference them as `InputBlob.content_hash`.
    #[serde(default)]
    pub(crate) pending_source_hashes: Vec<PendingSourceHash>,
    /// Completed parser steps from WASM execution (#915).
    /// Consumed by `/clearance` to assemble `WitnessBundle`s.
    #[serde(default)]
    pub(crate) pending_parser_steps: Vec<PendingParserStep>,
    /// Completed deterministic binds (#932). Each records a parser output
    /// that was bound to a schema field without model intermediation.
    /// Replayed during session rebuild to re-insert DeterministicBind
    /// observations into the flow graph.
    #[serde(default)]
    pub(crate) deterministic_binds: Vec<DeterministicBindRecord>,
    /// Whether provenance mode is active (#1020).
    /// Set on first PreToolUse when a .provenance.json schema is detected.
    #[serde(default)]
    pub(crate) provenance_mode: bool,
    /// Number of flow observations archived to checkpoint (#1007).
    #[serde(default)]
    pub(crate) checkpoint_offset: usize,
}

/// A content hash captured from a tool output during PostToolUse (#873).
///
/// This is the "record" side of record-and-replay: we record the SHA-256
/// of untrusted content at capture time so that a future reduction pipeline
/// can prove it processed *this exact content*.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct PendingSourceHash {
    /// SHA-256 of the tool result content.
    pub(crate) content_hash: [u8; 32],
    /// Tool that produced this content (e.g. "WebFetch", "mcp__server__tool").
    pub(crate) tool_name: String,
    /// Unix timestamp (seconds) when the content was captured.
    pub(crate) captured_at: u64,
    /// Whether a `ReductionWitness` has been constructed for this content.
    /// Once true, the hash has been consumed by the reduction pipeline.
    pub(crate) witnessed: bool,
    /// Raw content bytes for replay verification (#986).
    /// Capped at 1MB. When present, an auditor can re-execute the parser
    /// on this exact content and verify the output hash matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) raw_content: Option<Vec<u8>>,
}

/// A completed parser step captured during PostToolUse (#915).
///
/// Records the deterministic transformation of source content through a
/// registered WASM parser. The hash chain (input → parser → output) forms
/// the core of a `WitnessBundle` that proves data wasn't AI-derived.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct PendingParserStep {
    /// SHA-256 of the parser input (matches a `PendingSourceHash.content_hash`).
    pub(crate) input_hash: [u8; 32],
    /// Parser ID from the registry (e.g. "jq", "json_extract").
    pub(crate) parser_id: String,
    /// SHA-256 of the parser WASM binary (content-addressed).
    pub(crate) parser_hash: [u8; 32],
    /// SHA-256 of the parser output.
    pub(crate) output_hash: [u8; 32],
    /// The raw parser output bytes (kept for schema binding).
    pub(crate) output: Vec<u8>,
    /// Unix timestamp when the parser ran.
    pub(crate) executed_at: u64,
}

/// A completed deterministic bind — parser output routed to a schema field
/// without model intermediation (#932).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct DeterministicBindRecord {
    /// Schema field name this bind populates.
    pub(crate) field_name: String,
    /// SHA-256 of the parser output (links to PendingParserStep.output_hash).
    pub(crate) output_hash: [u8; 32],
    /// Parser ID that produced the output.
    pub(crate) parser_id: String,
    /// Flow graph NodeKind discriminant stored for replay (always 16 = DeterministicBind).
    pub(crate) node_kind_u8: u8,
}

impl SessionState {
    /// Create a fresh session state with the current schema version.
    pub(crate) fn new_versioned() -> Self {
        Self {
            schema_version: SESSION_SCHEMA_VERSION,
            ..Default::default()
        }
    }
}

/// Result of loading session state — distinguishes clean start from tampered.
#[derive(Debug)]
pub(crate) enum SessionLoad {
    /// Fresh session, no prior state.
    Fresh(SessionState),
    /// Loaded existing state successfully.
    Loaded(SessionState),
    /// State file was deleted after at least one operation was recorded.
    /// This is a tamper signal — fail closed.
    Tampered { expected_hwm: u64 },
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Set file permissions to owner-only read/write (0600) on Unix.
/// This is a defense-in-depth measure for files containing key material (#744).
#[cfg(unix)]
fn set_file_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "nucleus: WARNING — failed to set 0600 permissions on {}: {e}. \
             Key material may be readable by other processes.",
            path.display()
        );
    }
}

/// Check that the session directory does not have group or other permissions.
/// Warns if the directory is too permissive (e.g., someone ran chmod manually).
#[cfg(unix)]
fn warn_if_dir_too_permissive(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(dir) {
        let mode = meta.permissions().mode();
        // Check for group (0o070) or other (0o007) permission bits
        if mode & 0o077 != 0 {
            eprintln!(
                "nucleus: WARNING — session directory {} has group/other permissions \
                 (mode {:04o}). Key material may be accessible to other users. \
                 Expected 0700. Run: chmod 700 {}",
                dir.display(),
                mode & 0o7777,
                dir.display()
            );
        }
    }
}

pub(crate) fn session_dir() -> PathBuf {
    // Use XDG-compliant path: ~/.local/share/nucleus/sessions/ (#552)
    // Falls back to /tmp/nucleus-hook if home dir unavailable.
    // This survives reboots (unlike /tmp on some systems).
    let dir = if let Some(home) = dirs_next::home_dir() {
        home.join(".local")
            .join("share")
            .join("nucleus")
            .join("sessions")
    } else {
        std::env::temp_dir().join("nucleus-hook")
    };
    std::fs::create_dir_all(&dir).ok();
    // Restrict directory permissions: owner-only (0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        // Warn if permissions were externally changed (#744)
        warn_if_dir_too_permissive(&dir);
    }
    dir
}

/// Sanitize session_id to prevent path traversal attacks.
/// A malicious session_id like "../../etc/cron.d/evil" could write
/// outside the session directory. Strip everything except alphanumerics,
/// hyphens, and underscores.
pub(crate) fn sanitize_session_id(session_id: &str) -> String {
    session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128) // Reasonable length limit
        .collect()
}

pub(crate) fn session_state_path(session_id: &str) -> PathBuf {
    let safe_id = sanitize_session_id(session_id);
    session_dir().join(format!("{safe_id}.json"))
}

/// Separate high-water-mark file — survives state file deletion.
/// If someone socially engineers "rm session.json", this file persists
/// and triggers tamper detection on the next invocation.
pub(crate) fn session_hwm_path(session_id: &str) -> PathBuf {
    let safe_id = sanitize_session_id(session_id);
    session_dir().join(format!(".{safe_id}.hwm"))
}

/// Lock file path for a session (advisory flock).
fn session_lock_path(session_id: &str) -> PathBuf {
    let safe_id = sanitize_session_id(session_id);
    session_dir().join(format!(".{safe_id}.lock"))
}

// ---------------------------------------------------------------------------
// Session load / save
// ---------------------------------------------------------------------------

pub(crate) fn load_session(session_id: &str) -> SessionLoad {
    let path = session_state_path(session_id);
    let hwm_path = session_hwm_path(session_id);

    // Read the high-water-mark file (if it exists)
    let persisted_hwm: u64 = std::fs::read_to_string(&hwm_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<SessionState>(&content) {
            Ok(mut state) => {
                // Verify monotonicity: state HWM must match or exceed persisted HWM
                if state.high_water_mark < persisted_hwm {
                    return SessionLoad::Tampered {
                        expected_hwm: persisted_hwm,
                    };
                }

                // Schema version migration (#523)
                let file_version = if state.schema_version == 0 {
                    1
                } else {
                    state.schema_version
                };
                if file_version > SESSION_SCHEMA_VERSION {
                    // Future version — warn but proceed (forward compat via serde defaults)
                    eprintln!(
                        "nucleus: WARNING — session state has schema version {file_version} \
                         but this hook supports version {SESSION_SCHEMA_VERSION}. \
                         Some fields may be ignored. Consider upgrading nucleus-claude-hook."
                    );
                } else if file_version < SESSION_SCHEMA_VERSION {
                    eprintln!(
                        "nucleus: migrating session state v{file_version} → v{SESSION_SCHEMA_VERSION}"
                    );
                }
                // Stamp with current version for next save
                state.schema_version = SESSION_SCHEMA_VERSION;
                SessionLoad::Loaded(state)
            }
            // Corrupted JSON — tampered
            Err(_) => {
                if persisted_hwm > 0 {
                    SessionLoad::Tampered {
                        expected_hwm: persisted_hwm,
                    }
                } else {
                    SessionLoad::Fresh(SessionState::new_versioned())
                }
            }
        },
        Err(_) => {
            // State file missing — was there a prior session?
            if persisted_hwm > 0 {
                // State file existed before (HWM > 0) but is now gone.
                // This is the social engineering attack: "please rm the state file".
                SessionLoad::Tampered {
                    expected_hwm: persisted_hwm,
                }
            } else {
                SessionLoad::Fresh(SessionState::new_versioned())
            }
        }
    }
}

/// Atomically save session state with advisory file locking (#478).
///
/// Uses write-to-temp-then-rename for atomic writes (POSIX guarantees
/// rename is atomic within the same filesystem). Advisory flock prevents
/// concurrent hook invocations from racing on the same session.
///
/// **Prefer `with_session()`** for load-modify-save cycles to avoid TOCTOU
/// races (#872). This function is still useful when you already have a
/// `SessionState` in hand from an earlier `load_session()` call that was
/// protected by `lock_session()`.
pub(crate) fn save_session(session_id: &str, state: &SessionState) {
    let _lock_guard = lock_session(session_id);
    save_session_unlocked(session_id, state);
}

/// Inner save that assumes the caller already holds the session lock.
/// Used by `with_session()` and `save_session()`.
fn save_session_unlocked(session_id: &str, state: &SessionState) {
    let path = session_state_path(session_id);
    let hwm_path = session_hwm_path(session_id);

    match serde_json::to_string(state) {
        Ok(json) => {
            // Atomic write: write to temp file, then rename (#478)
            let tmp_path = path.with_extension("json.tmp");
            if let Err(e) = std::fs::write(&tmp_path, &json) {
                eprintln!(
                    "nucleus: WARNING — failed to write temp state file: {e}. \
                     Taint tracking may be incomplete."
                );
                return;
            }
            if let Err(e) = std::fs::rename(&tmp_path, &path) {
                eprintln!(
                    "nucleus: WARNING — atomic rename failed: {e}. \
                     Falling back to non-atomic write."
                );
                // Fallback: direct write (better than losing state entirely)
                std::fs::write(&path, &json).ok();
            }
            // Restrict file permissions to owner-only (0600) — key material (#744)
            #[cfg(unix)]
            set_file_owner_only(&path);

            // Write HWM file separately — survives state file deletion.
            // Also atomic: temp + rename.
            let hwm_tmp = hwm_path.with_extension("hwm.tmp");
            let hwm_content = state.high_water_mark.to_string();
            if std::fs::write(&hwm_tmp, &hwm_content).is_ok() {
                if let Err(e) = std::fs::rename(&hwm_tmp, &hwm_path) {
                    eprintln!("nucleus: WARNING — HWM atomic rename failed: {e}");
                    std::fs::write(&hwm_path, &hwm_content).ok();
                }
            } else {
                // Direct write fallback
                if let Err(e) = std::fs::write(&hwm_path, &hwm_content) {
                    eprintln!("nucleus: WARNING — failed to save HWM file: {e}");
                }
            }
            // Restrict HWM file permissions to owner-only (0600)
            #[cfg(unix)]
            set_file_owner_only(&hwm_path);

            // Update session index for O(1) lookups (#1008).
            update_session_index(session_id, state);
        }
        Err(e) => {
            eprintln!("nucleus: WARNING �� failed to serialize session state: {e}");
        }
    }
}

/// Update `.session-index` with this session's metadata (#1008).
/// Checkpoint flow observations if they exceed the threshold (#1007).
///
/// Archives older observations to a checkpoint file, keeping only the
/// most recent MAX_LIVE_OBSERVATIONS in session state. This bounds
/// session JSON growth and replay time.
#[allow(dead_code)]
const MAX_LIVE_OBSERVATIONS: usize = 1000;

#[allow(dead_code)]
pub(crate) fn checkpoint_flow_observations(session_id: &str, state: &mut SessionState) {
    if state.flow_observations.len() <= MAX_LIVE_OBSERVATIONS {
        return;
    }

    // Archive older observations to checkpoint file.
    let safe_id = sanitize_session_id(session_id);
    let checkpoint_dir = session_dir().join("checkpoints");
    std::fs::create_dir_all(&checkpoint_dir).ok();
    let checkpoint_path = checkpoint_dir.join(format!("{safe_id}.jsonl"));

    let archive_count = state.flow_observations.len() - MAX_LIVE_OBSERVATIONS;
    let archived: Vec<_> = state.flow_observations.drain(..archive_count).collect();

    // Append to checkpoint file.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&checkpoint_path)
    {
        use std::io::Write;
        for obs in &archived {
            if let Ok(json) = serde_json::to_string(obs) {
                writeln!(f, "{json}").ok();
            }
        }
    }

    state.checkpoint_offset += archive_count;
    eprintln!(
        "nucleus: checkpointed {archive_count} flow observations ({} total archived)",
        state.checkpoint_offset
    );
}

fn update_session_index(session_id: &str, state: &SessionState) {
    let index_path = session_dir().join(".session-index");
    let entry = serde_json::json!({
        "id": sanitize_session_id(session_id),
        "parent": state.parent_session_id,
        "chain_head": hex::encode(state.chain_head_hash),
        "ops": state.allowed_ops.len(),
        "tainted": state.web_tainted,
    });
    if let Ok(line) = serde_json::to_string(&entry) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)
        {
            writeln!(f, "{line}").ok();
        }
    }
}

// ---------------------------------------------------------------------------
// Advisory file locking
// ---------------------------------------------------------------------------

/// Default timeout for acquiring the session lock (milliseconds).
/// Short enough to avoid stalling Claude Code, long enough to survive
/// brief contention from concurrent PostToolUse invocations (#872).
const SESSION_LOCK_TIMEOUT_MS: u64 = 500;

/// RAII guard for advisory file lock.
/// Holds the lock file open; the flock is released when the File is dropped.
pub(crate) struct SessionLockGuard {
    #[cfg(unix)]
    _file: std::fs::File,
}

/// Acquire an advisory file lock for a session by ID.
///
/// Returns a guard that releases the lock on drop. The lock is blocking
/// with a short timeout — concurrent hook invocations will wait briefly
/// rather than silently racing (#872).
pub(crate) fn lock_session(session_id: &str) -> SessionLockGuard {
    let lock_path = session_lock_path(session_id);
    acquire_session_lock(&lock_path)
}

/// Acquire an advisory file lock (blocking with timeout).
///
/// Uses a polling loop with `LOCK_NB` to implement a timeout, since
/// `flock(LOCK_EX)` has no native timeout on most Unix systems.
/// If the lock cannot be acquired within `SESSION_LOCK_TIMEOUT_MS`,
/// logs a warning and returns a guard anyway (defense in depth — we'd
/// rather have a rare race than a hung hook process).
fn acquire_session_lock(lock_path: &std::path::Path) -> SessionLockGuard {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
        {
            Ok(file) => {
                let fd = file.as_raw_fd();
                // Try non-blocking first (fast path — no contention)
                // SAFETY: fd is valid, LOCK_EX | LOCK_NB is a valid flock operation
                let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
                if ret != 0 {
                    // Contention — poll with backoff up to timeout (#872)
                    let deadline = std::time::Instant::now()
                        + std::time::Duration::from_millis(SESSION_LOCK_TIMEOUT_MS);
                    let mut backoff = std::time::Duration::from_millis(1);
                    let mut acquired = false;
                    while std::time::Instant::now() < deadline {
                        std::thread::sleep(backoff);
                        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
                        if ret == 0 {
                            acquired = true;
                            break;
                        }
                        // Exponential backoff: 1ms, 2ms, 4ms, 8ms, ... capped at 50ms
                        backoff = std::cmp::min(backoff * 2, std::time::Duration::from_millis(50));
                    }
                    if !acquired {
                        eprintln!(
                            "nucleus: WARNING — session lock timeout after {SESSION_LOCK_TIMEOUT_MS}ms \
                             (concurrent hook invocation). Proceeding without lock — \
                             taint state may be incomplete (#872)."
                        );
                    }
                }
                SessionLockGuard { _file: file }
            }
            Err(e) => {
                eprintln!("nucleus: WARNING — failed to create lock file: {e}");
                // Create a dummy guard with /dev/null as fallback
                let file = std::fs::File::open("/dev/null").unwrap_or_else(|_| {
                    std::fs::OpenOptions::new()
                        .read(true)
                        .open(lock_path)
                        .unwrap_or_else(|_| panic!("cannot open /dev/null or lock file"))
                });
                SessionLockGuard { _file: file }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = lock_path;
        SessionLockGuard {}
    }
}

/// Atomically load, mutate, and save session state under a single lock (#872).
///
/// This eliminates the TOCTOU race where concurrent PostToolUse calls could
/// each load stale state, mutate independently, and overwrite each other's
/// changes. The lock is held across the entire load-modify-save cycle.
///
/// Returns `None` if the session is tampered (caller should deny).
/// The closure receives a mutable reference to the session state.
pub(crate) fn with_session<F>(session_id: &str, f: F) -> Option<SessionState>
where
    F: FnOnce(&mut SessionState),
{
    let _lock = lock_session(session_id);

    match load_session(session_id) {
        SessionLoad::Loaded(mut state) | SessionLoad::Fresh(mut state) => {
            f(&mut state);
            save_session_unlocked(session_id, &state);
            Some(state)
        }
        SessionLoad::Tampered { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Compartment helpers
// ---------------------------------------------------------------------------

/// Derive a keyed compartment filename from session_id and a secret token.
///
/// The compartment file is written by the orchestrator (or a privileged tool)
/// to tell the hook which compartment to activate. The filename is keyed so
/// that the model can't guess it:
///
/// 1. The token is generated randomly (ring SystemRandom)
/// 2. It's stored in the session state file (which the model can't read —
///    it's in /tmp with 0700 permissions on the directory)
/// 3. The HMAC output is unpredictable without the token
///
/// SECURITY (#477): Uses HMAC(token, session_id) where the token is a
/// random secret stored in session state. The model cannot predict this
/// because:
/// 1. The token is generated randomly (ring SystemRandom)
/// 2. It's stored in the session state file (which the model can't read —
///    it's in /tmp with 0700 permissions on the directory)
/// 3. The HMAC output is unpredictable without the token
pub(crate) fn keyed_compartment_name(session_id: &str, token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.update(b":");
    h.update(sanitize_session_id(session_id).as_bytes());
    let hash = h.finalize();
    hex::encode(&hash[..8])
}

/// Generate a random compartment token (hex string).
pub(crate) fn generate_compartment_token() -> String {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 16];
    if let Err(e) = rng.fill(&mut bytes) {
        eprintln!("nucleus: WARNING — SystemRandom failed: {e}. Using fallback token.");
        // Fallback: use process ID + timestamp as low-entropy token.
        // Not cryptographically secure, but prevents a panic in the hot path (#481).
        let fallback = format!(
            "{:016x}{:016x}",
            std::process::id() as u64,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        );
        return fallback;
    }
    hex::encode(bytes)
}

/// Resolve the active compartment for a session.
///
/// When `current` is `Some`, detects privilege escalation and logs a
/// WARNING to stderr (#464). For breakglass escalation, the compartment
/// file (or env var) must use the `breakglass:reason` format — bare
/// `breakglass` without a reason is rejected to prevent social-engineering
/// attacks where the model tricks the user into writing just "breakglass".
pub(crate) fn resolve_compartment(
    session_id: &str,
    token: &str,
    current: Option<portcullis_core::compartment::Compartment>,
) -> Option<portcullis_core::compartment::Compartment> {
    let (resolved, raw_content) = resolve_compartment_raw(session_id, token);
    let target = resolved?;

    // Enforce breakglass reason requirement (#464)
    if target == portcullis_core::compartment::Compartment::Breakglass {
        let content = raw_content.unwrap_or_default();
        let trimmed = content.trim();
        if !trimmed.starts_with("breakglass:")
            || trimmed
                .strip_prefix("breakglass:")
                .map_or(true, |r| r.trim().is_empty())
        {
            eprintln!(
                "nucleus: DENIED — breakglass compartment requires a reason. \
                 Use 'breakglass:<reason>' format (e.g. 'breakglass:production outage P1'). \
                 Bare 'breakglass' is not accepted to prevent social-engineering attacks (#464)."
            );
            return None;
        }
    }

    // Enforce single-step escalation (#733) and detect escalation (#464)
    if let Some(from) = current {
        if !from.can_transition_to(target) {
            eprintln!(
                "nucleus: DENIED — skip-level compartment escalation {from} -> {target}. \
                 Escalation must be single-step (e.g. research -> draft -> execute -> breakglass). \
                 Transition one level at a time to maintain an audit trail (#733)."
            );
            return None;
        }
        if portcullis_core::compartment::is_escalation(from, target) {
            eprintln!(
                "nucleus: WARNING — compartment escalation detected: {from} -> {target}. \
                 This grants additional capabilities. Ensure this was an intentional operator action."
            );
            if target == portcullis_core::compartment::Compartment::Breakglass {
                eprintln!(
                    "nucleus: WARNING — BREAKGLASS escalation grants ALL capabilities \
                     with enhanced audit. This should only be used for emergency operations."
                );
            }
        }
    }

    Some(target)
}

/// Inner resolution that returns both the parsed compartment and the raw
/// content string (needed for breakglass reason validation).
fn resolve_compartment_raw(
    session_id: &str,
    token: &str,
) -> (
    Option<portcullis_core::compartment::Compartment>,
    Option<String>,
) {
    // 1. Check side-channel file with keyed filename
    if !token.is_empty() {
        let keyed_name = keyed_compartment_name(session_id, token);
        let compartment_file = session_dir().join(format!("{keyed_name}.compartment"));
        if let Ok(content) = std::fs::read_to_string(&compartment_file) {
            let trimmed = content.trim().to_string();
            if let Some(c) = portcullis_core::compartment::Compartment::from_str_opt(&trimmed) {
                return (Some(c), Some(trimmed));
            }
        }
    }

    // 2. Fall back to env var
    if let Ok(s) = std::env::var("NUCLEUS_COMPARTMENT") {
        if let Some(c) = portcullis_core::compartment::Compartment::from_str_opt(&s) {
            return (Some(c), Some(s));
        }
    }

    (None, None)
}

/// Get the compartment file path for a session (for external tools to write).
///
/// Exposed via `nucleus-claude-hook --compartment-path <session_id>` so that
/// the CLI can write to the correct file without knowing the keyed hash.
/// Reads the session state to get the token.
pub(crate) fn compartment_file_path(session_id: &str) -> std::path::PathBuf {
    // Load session to get token
    let token = match load_session(session_id) {
        SessionLoad::Loaded(s) | SessionLoad::Fresh(s) => s.compartment_token,
        SessionLoad::Tampered { .. } => String::new(),
    };
    if token.is_empty() {
        // No session yet — return a placeholder (will be wrong until session exists)
        return session_dir().join("no-session.compartment");
    }
    let keyed_name = keyed_compartment_name(session_id, &token);
    session_dir().join(format!("{keyed_name}.compartment"))
}

/// Find the most recently modified session (by `.json` mtime in the session dir).
///
/// Returns the session ID (filename stem) of the newest session, or `None`
/// if no sessions exist. Used by `--compartment` to target the active session
/// without requiring the caller to know the session ID.
pub(crate) fn find_latest_session() -> Option<String> {
    let dir = session_dir();
    let mut best: Option<(String, std::time::SystemTime)> = None;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(meta) = path.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        let stem = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();
                        if !stem.is_empty() {
                            match &best {
                                Some((_, best_time)) if mtime <= *best_time => {}
                                _ => best = Some((stem, mtime)),
                            }
                        }
                    }
                }
            }
        }
    }
    best.map(|(id, _)| id)
}

/// Write a compartment value for a given session.
///
/// **Note**: Direct compartment writes are deprecated for external callers
/// (#875). Use `request_compartment_transition()` instead, which goes through
/// the hook-mediated validation path. This function is retained for internal
/// use (parent compartment inheritance) and tests.
#[allow(dead_code)]
pub(crate) fn write_compartment(session_id: &str, value: &str) -> Result<(), String> {
    let path = compartment_file_path(session_id);
    if path.file_name().and_then(|f| f.to_str()) == Some("no-session.compartment") {
        return Err(format!(
            "no active session found for '{session_id}' -- start a Claude Code session first"
        ));
    }
    std::fs::write(&path, value).map_err(|e| format!("failed to write compartment file: {e}"))
}

/// Switch the compartment for the latest active session.
///
/// **Deprecated path** -- retained for backward compatibility. Now writes a
/// transition *request* file instead of directly mutating the compartment.
/// The actual transition is applied by the PreToolUse hook via
/// `check_pending_transition()` + `apply_pending_transition()`.
pub(crate) fn switch_compartment(name: &str) {
    let session_id = match find_latest_session() {
        Some(id) => id,
        None => {
            eprintln!("nucleus: no active session found -- start a Claude Code session first");
            std::process::exit(1);
        }
    };
    match request_compartment_transition(&session_id, name, "CLI --compartment flag") {
        Ok(path) => println!(
            "nucleus: transition to '{name}' requested (session: {session_id})\n\
             nucleus: request written to {}. Will be applied on next hook invocation.",
            path.display()
        ),
        Err(e) => {
            eprintln!("nucleus: error: {e}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Transition request protocol (#875)
// ---------------------------------------------------------------------------
//
// Instead of the model (or CLI) directly writing compartment files, transitions
// go through a request file that the PreToolUse hook validates and applies.
// This ensures policy enforcement (single-step escalation, breakglass reason)
// happens in trusted hook code, not in an untrusted Bash invocation.
//
// Flow:
// 1. Model writes `.nucleus/transition-request.json` (or CLI `--compartment`)
// 2. PreToolUse hook calls `check_pending_transition()` -- reads & validates
// 3. If valid, `apply_pending_transition()` writes the keyed compartment file
// 4. Request file is deleted regardless of outcome (single-use)

/// A compartment transition request written by the model or CLI.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub(crate) struct TransitionRequest {
    /// Target compartment name (e.g. "draft", "execute", "breakglass:reason").
    pub(crate) target: String,
    /// Human-readable reason for the transition.
    pub(crate) reason: String,
    /// Unix timestamp when the request was created.
    #[serde(default)]
    pub(crate) requested_at: u64,
}

/// Errors that can occur when applying a transition request.
#[derive(Debug)]
pub(crate) enum TransitionError {
    /// Target compartment name is not recognized.
    InvalidTarget(String),
    /// Transition violates single-step escalation policy.
    SkipLevel { from: String, to: String },
    /// Breakglass requires a reason string.
    BreakglassNoReason,
    /// Request file is stale (older than 60 seconds).
    Stale,
    /// Failed to write compartment file.
    WriteError(String),
    /// Ratchet mode: escalation above lowest-ever compartment denied (#471).
    RatchetViolation { lowest: String, requested: String },
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransitionError::InvalidTarget(t) => {
                write!(f, "unrecognized compartment target: '{t}'")
            }
            TransitionError::SkipLevel { from, to } => {
                write!(
                    f,
                    "skip-level escalation {from} -> {to} denied. \
                     Escalate one step at a time (research -> draft -> execute -> breakglass)."
                )
            }
            TransitionError::BreakglassNoReason => {
                write!(
                    f,
                    "breakglass requires a reason. Use 'breakglass:<reason>' format."
                )
            }
            TransitionError::Stale => {
                write!(f, "transition request is stale (>60s old). Re-request.")
            }
            TransitionError::WriteError(e) => write!(f, "failed to apply transition: {e}"),
            TransitionError::RatchetViolation { lowest, requested } => {
                write!(
                    f,
                    "ratchet mode: escalation to '{requested}' denied — session already \
                     de-escalated to '{lowest}'. De-escalation is permanent in ratchet mode."
                )
            }
        }
    }
}

/// Maximum age (in seconds) for a transition request to be considered valid.
/// Prevents replay of old request files.
const TRANSITION_REQUEST_MAX_AGE_SECS: u64 = 60;

/// Path to the transition request file in the project's `.nucleus/` directory.
pub(crate) fn transition_request_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_default()
        .join(".nucleus")
        .join("transition-request.json")
}

/// Write a transition request file (#875).
///
/// Called by the `/airlock` skill (via model file-write) or by
/// `--compartment` CLI flag. The hook will read and validate this on the
/// next PreToolUse invocation.
///
/// Returns the path to the written request file.
pub(crate) fn request_compartment_transition(
    _session_id: &str,
    target: &str,
    reason: &str,
) -> Result<PathBuf, String> {
    let path = transition_request_path();
    // Ensure .nucleus/ directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create .nucleus/ directory: {e}"))?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let request = TransitionRequest {
        target: target.to_string(),
        reason: reason.to_string(),
        requested_at: now,
    };
    let json = serde_json::to_string_pretty(&request)
        .map_err(|e| format!("failed to serialize transition request: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write transition request: {e}"))?;
    Ok(path)
}

/// Check for a pending transition request (#875).
///
/// Reads `.nucleus/transition-request.json` if it exists. Returns `None`
/// if no request is pending. Does NOT delete the file -- that happens in
/// `apply_pending_transition()` or `deny_pending_transition()`.
pub(crate) fn check_pending_transition() -> Option<TransitionRequest> {
    let path = transition_request_path();
    let content = std::fs::read_to_string(&path).ok()?;
    let request: TransitionRequest = serde_json::from_str(&content).ok()?;
    Some(request)
}

/// Delete the transition request file (called after apply or deny).
fn delete_transition_request() {
    let path = transition_request_path();
    std::fs::remove_file(&path).ok();
}

/// Apply a pending transition request after validation (#875).
///
/// Validates:
/// 1. Request is not stale (within `TRANSITION_REQUEST_MAX_AGE_SECS`)
/// 2. Target is a recognized compartment name
/// 3. Transition follows single-step escalation policy (`can_transition_to()`)
/// 4. Breakglass includes a reason string
///
/// On success, writes the keyed compartment file and deletes the request.
/// On failure, deletes the request and returns the error.
pub(crate) fn apply_pending_transition(
    session_id: &str,
    token: &str,
    current: Option<portcullis_core::compartment::Compartment>,
    request: &TransitionRequest,
) -> Result<(), TransitionError> {
    // 1. Check staleness
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if request.requested_at > 0
        && now.saturating_sub(request.requested_at) > TRANSITION_REQUEST_MAX_AGE_SECS
    {
        delete_transition_request();
        return Err(TransitionError::Stale);
    }

    // 2. Parse target compartment
    let target = portcullis_core::compartment::Compartment::from_str_opt(&request.target)
        .ok_or_else(|| {
            delete_transition_request();
            TransitionError::InvalidTarget(request.target.clone())
        })?;

    // 3. Enforce breakglass reason
    if target == portcullis_core::compartment::Compartment::Breakglass {
        let trimmed = request.target.trim();
        if !trimmed.starts_with("breakglass:")
            || trimmed
                .strip_prefix("breakglass:")
                .map_or(true, |r| r.trim().is_empty())
        {
            delete_transition_request();
            return Err(TransitionError::BreakglassNoReason);
        }
    }

    // 4. Enforce single-step escalation
    if let Some(from) = current {
        if !from.can_transition_to(target) {
            delete_transition_request();
            return Err(TransitionError::SkipLevel {
                from: from.to_string(),
                to: target.to_string(),
            });
        }
    }

    // 4b. Enforce ratchet mode (#471) — if enabled, deny escalation above
    // the lowest compartment ever reached in this session.
    let ratchet_mode = std::env::var("NUCLEUS_RATCHET_MODE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if ratchet_mode {
        let lowest_from_session = match load_session(session_id) {
            SessionLoad::Loaded(s) | SessionLoad::Fresh(s) => s.lowest_compartment.clone(),
            _ => None,
        };
        if let Some(lowest) = lowest_from_session {
            if let Some(lowest_comp) =
                portcullis_core::compartment::Compartment::from_str_opt(&lowest)
            {
                if target > lowest_comp {
                    delete_transition_request();
                    return Err(TransitionError::RatchetViolation {
                        lowest: lowest.clone(),
                        requested: target.to_string(),
                    });
                }
            }
        }
    }

    // 5. Write the keyed compartment file (trusted path)
    let keyed_name = keyed_compartment_name(session_id, token);
    let compartment_file = session_dir().join(format!("{keyed_name}.compartment"));
    std::fs::write(&compartment_file, &request.target).map_err(|e| {
        delete_transition_request();
        TransitionError::WriteError(e.to_string())
    })?;

    // 6. Update lowest compartment for ratchet tracking (#471).
    with_session(session_id, |s| {
        let target_str = target.to_string();
        let should_update = match &s.lowest_compartment {
            None => true,
            Some(existing) => portcullis_core::compartment::Compartment::from_str_opt(existing)
                .map_or(true, |existing_comp| target < existing_comp),
        };
        if should_update {
            s.lowest_compartment = Some(target_str);
        }
    });

    // 7. Delete the request file (single-use)
    delete_transition_request();

    Ok(())
}

/// Deny and delete a pending transition request, returning a user-facing message.
pub(crate) fn deny_pending_transition(error: &TransitionError) -> String {
    delete_transition_request();
    format!("nucleus: DENIED -- compartment transition request rejected: {error}")
}

// ---------------------------------------------------------------------------
// Auto-compartment detection (#472)
// ---------------------------------------------------------------------------

/// Infer compartment from tool usage when no compartment is set.
///
/// When `NUCLEUS_AUTO_COMPARTMENT=1` and no compartment is active, maps:
/// WebSearch/WebFetch → Research, Write/Edit → Draft, RunBash/GitPush → Execute.
/// Never auto-escalates — only sets the initial compartment.
pub(crate) fn auto_detect_compartment(
    current: Option<portcullis_core::compartment::Compartment>,
    prev: Option<portcullis_core::compartment::Compartment>,
    operation_name: &str,
    tool_name: &str,
    session_id: &str,
    token: &str,
) -> Option<portcullis_core::compartment::Compartment> {
    if current.is_some() || prev.is_some() {
        return current;
    }
    if !std::env::var("NUCLEUS_AUTO_COMPARTMENT")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return current;
    }
    let inferred = match operation_name {
        "WebSearch" | "WebFetch" => Some(portcullis_core::compartment::Compartment::Research),
        "WriteFiles" | "EditFiles" | "NotebookEdit" => {
            Some(portcullis_core::compartment::Compartment::Draft)
        }
        "RunBash" | "GitPush" | "GitCommit" => {
            Some(portcullis_core::compartment::Compartment::Execute)
        }
        _ => None,
    };
    if let Some(ref comp) = inferred {
        let keyed_name = keyed_compartment_name(session_id, token);
        let comp_path = session_dir().join(format!("{keyed_name}.compartment"));
        std::fs::write(&comp_path, comp.to_string()).ok();
        eprintln!("nucleus: auto-compartment detected from {tool_name}: {comp}");
    }
    inferred
}

// ---------------------------------------------------------------------------
// PostToolUse observation + user bash passthrough (#593, #873, #918)
// ---------------------------------------------------------------------------

/// Record a PostToolUse observation in session state.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn record_post_tool(
    s: &mut SessionState,
    output_kind: portcullis_core::flow::NodeKind,
    op: &str,
    result_text: &str,
    is_web: bool,
    content_hash: [u8; 32],
    taint_tool: &str,
    hash_tool: &str,
) {
    #[allow(unused_imports)]
    use crate::classify::{node_kind_to_u8, truncate_subject};
    #[allow(unused_imports)]
    use crate::context::web_taint_warning;
    let user_bash = s.pending_user_bash;
    if user_bash {
        s.pending_user_bash = false;
    }
    // When the user typed `! <cmd>`, the output is user-directed deterministic
    // data — classify as UserPrompt so the flow graph assigns Directive authority
    // and Deterministic derivation (#918).
    let effective_kind = if user_bash {
        portcullis_core::flow::NodeKind::UserPrompt
    } else {
        output_kind
    };
    let label = if user_bash {
        format!("post:user:{op}")
    } else {
        format!("post:{op}")
    };
    let subj = if result_text.len() > 200 {
        &result_text[..200]
    } else {
        result_text
    };
    s.flow_observations
        .push((node_kind_to_u8(effective_kind), label, subj.to_string()));
    s.last_pre_tool_obs_index = None;
    if user_bash {
        eprintln!("nucleus: user ! passthrough — Deterministic");
    } else if is_web {
        if !s.web_tainted {
            s.web_tainted = true;
            eprintln!("{}", web_taint_warning(taint_tool, result_text));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Store raw bytes for replay verification (#986, #1006).
        // Write to separate blob file instead of inline in session JSON.
        const MAX_RAW_BYTES: usize = 1_048_576;
        let raw = if result_text.len() <= MAX_RAW_BYTES {
            // Write blob to .nucleus/sessions/blobs/{hash}.bin
            let blob_dir = session_dir().join("blobs");
            std::fs::create_dir_all(&blob_dir).ok();
            let hash_hex = hex::encode(content_hash);
            let blob_path = blob_dir.join(format!("{hash_hex}.bin"));
            if !blob_path.exists() {
                std::fs::write(&blob_path, result_text.as_bytes()).ok();
            }
            // Don't store in session JSON — load from blob on demand.
            None
        } else {
            None
        };
        s.pending_source_hashes.push(PendingSourceHash {
            content_hash,
            tool_name: hash_tool.to_string(),
            captured_at: now,
            witnessed: false,
            raw_content: raw,
        });
        eprintln!(
            "nucleus: source hash {:02x}{:02x}{:02x}{:02x}...",
            content_hash[0], content_hash[1], content_hash[2], content_hash[3]
        );
        // Attempt WASM reduction on the captured content (#915).
        let steps_before = s.pending_parser_steps.len();
        try_wasm_reduction(s, content_hash, result_text.as_bytes(), hash_tool);

        // If a parser step was added, record a DeterministicBind observation (#932).
        // The bind's flow_observations entry uses NodeKind::DeterministicBind (16)
        // with no parents from the LeafTracker — the actual parent (the parser
        // output's WebContent source) will be wired during flow graph replay.
        if s.pending_parser_steps.len() > steps_before {
            let step = &s.pending_parser_steps[s.pending_parser_steps.len() - 1];
            let bind_label = format!("bind:{}:{}", step.parser_id, hash_tool);
            s.flow_observations.push((
                node_kind_to_u8(portcullis_core::flow::NodeKind::DeterministicBind),
                bind_label,
                String::new(),
            ));
            s.deterministic_binds.push(DeterministicBindRecord {
                field_name: String::new(), // resolved by resolve_bind_field_names()
                output_hash: step.output_hash,
                parser_id: step.parser_id.clone(),
                node_kind_u8: node_kind_to_u8(portcullis_core::flow::NodeKind::DeterministicBind),
            });
            eprintln!(
                "nucleus: DeterministicBind recorded for parser '{}'",
                step.parser_id
            );
        }
    }
}

/// Attempt to run a registered WASM parser on captured web content (#915).
///
/// If `.nucleus/parsers/` contains a declaration matching the tool's content
/// type, compiles and executes the parser, then records a `PendingParserStep`
/// with the full hash chain: input_hash → parser_hash → output_hash.
///
/// This is the "reduction" step: deterministic transformation of untrusted
/// content, producing a witness-ready output that bypasses the AI-derived gate.
#[cfg(feature = "wasm-sandbox")]
pub(crate) fn try_wasm_reduction(
    s: &mut SessionState,
    content_hash: [u8; 32],
    result_bytes: &[u8],
    tool_name: &str,
) {
    use portcullis_core::parser_registry::ParserRegistry;
    use portcullis_core::wasm_sandbox::ParserSandbox;
    use sha2::{Digest, Sha256};

    // Load parser declarations from .nucleus/parsers/
    let cwd = std::env::current_dir().unwrap_or_default();
    let parsers_dir = cwd.join(".nucleus").join("parsers");
    if !parsers_dir.is_dir() {
        return;
    }

    let mut registry = ParserRegistry::new();
    if registry.load_from_dir(&parsers_dir).is_err() {
        return;
    }

    // Find a parser whose input_format matches the tool name convention.
    // Convention: WebFetch → "http", WebSearch → "search", or explicit match.
    let input_format = match tool_name {
        "WebFetch" => "http",
        "WebSearch" => "search",
        _ if tool_name.starts_with("mcp__") => "mcp",
        _ => return,
    };

    let matching_parser = registry
        .parsers()
        .find(|(_, decl)| decl.input_format == input_format && decl.is_deterministic);

    let (parser_id, decl) = match matching_parser {
        Some((id, decl)) => (id.clone(), decl.clone()),
        None => return,
    };

    // Load and compile the WASM module.
    let wasm_path = parsers_dir.join(format!("{parser_id}.wasm"));
    let wasm_bytes = match std::fs::read(&wasm_path) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    // Cache the sandbox engine across invocations (#1005).
    // ParserSandbox::new() creates a Wasmtime Engine — expensive (~50ms).
    use std::sync::OnceLock;
    static SANDBOX: OnceLock<ParserSandbox> = OnceLock::new();
    let sandbox = SANDBOX.get_or_init(ParserSandbox::new);
    if registry
        .compile_parser(sandbox, &parser_id, &wasm_bytes)
        .is_err()
    {
        return;
    }

    // Execute with a conservative fuel limit.
    let fuel_limit = 10_000_000;
    let output = match registry.execute_parser(sandbox, &parser_id, result_bytes, fuel_limit) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("nucleus: WASM parser '{parser_id}' failed: {e}");
            return;
        }
    };

    let output_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&output);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Mark the source hash as witnessed.
    if let Some(src) = s
        .pending_source_hashes
        .iter_mut()
        .find(|h| h.content_hash == content_hash && !h.witnessed)
    {
        src.witnessed = true;
    }

    s.pending_parser_steps.push(PendingParserStep {
        input_hash: content_hash,
        parser_id: parser_id.clone(),
        parser_hash: decl.build_hash,
        output_hash,
        output,
        executed_at: now,
    });

    eprintln!(
        "nucleus: WASM reduction '{parser_id}' → output {:02x}{:02x}{:02x}{:02x}... (Deterministic)",
        output_hash[0], output_hash[1], output_hash[2], output_hash[3]
    );
}

#[cfg(not(feature = "wasm-sandbox"))]
pub(crate) fn try_wasm_reduction(
    _s: &mut SessionState,
    _content_hash: [u8; 32],
    _result_bytes: &[u8],
    _tool_name: &str,
) {
    // WASM sandbox not enabled — parser steps skipped.
}

// ---------------------------------------------------------------------------
// WitnessBundle assembly for /clearance (#916)
// ---------------------------------------------------------------------------

/// Result of attempting to assemble a WitnessBundle from pending session state.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ClearanceResult {
    /// Successfully assembled and verified a WitnessBundle.
    Verified {
        bundle: Box<portcullis_core::witness::WitnessBundle>,
        digest: [u8; 32],
    },
    /// No pending source hashes — nothing to clear.
    NoPendingContent,
    /// Source hashes exist but no parser steps — reduction pipeline incomplete.
    NoParserSteps { pending_sources: usize },
    /// Chain verification failed.
    ChainBroken(String),
}

/// Assemble a `WitnessBundle` from pending session state (#916).
///
/// Collects unwitnessed `PendingSourceHash`es as `InputBlob`s and
/// `PendingParserStep`s as `ParserStep`s, then verifies the chain.
/// On success, marks all consumed sources as witnessed and clears
/// the pending parser steps.
#[allow(dead_code)]
pub(crate) fn assemble_witness_bundle(s: &mut SessionState) -> ClearanceResult {
    use portcullis_core::witness::{InputBlob, ParserStep, WitnessBundle};

    // Collect unwitnessed source hashes.
    let unwitnessed: Vec<(usize, &PendingSourceHash)> = s
        .pending_source_hashes
        .iter()
        .enumerate()
        .filter(|(_, h)| !h.witnessed)
        .collect();

    if unwitnessed.is_empty() {
        return ClearanceResult::NoPendingContent;
    }

    if s.pending_parser_steps.is_empty() {
        return ClearanceResult::NoParserSteps {
            pending_sources: unwitnessed.len(),
        };
    }

    // Build InputBlobs from source hashes.
    let input_blobs: Vec<InputBlob> = unwitnessed
        .iter()
        .map(|(_, src)| InputBlob {
            source_class: "web".to_string(),
            content_hash: src.content_hash,
            fetched_at: src.captured_at,
            fetched_by: src.tool_name.clone(),
            // Load raw content from blob file if not inline (#1006).
            raw_content: src.raw_content.clone().or_else(|| {
                let hash_hex = hex::encode(src.content_hash);
                let blob_path = session_dir().join("blobs").join(format!("{hash_hex}.bin"));
                std::fs::read(&blob_path).ok()
            }),
        })
        .collect();

    // Build ParserSteps from pending steps.
    let parser_chain: Vec<ParserStep> = s
        .pending_parser_steps
        .iter()
        .map(|step| ParserStep {
            parser_id: step.parser_id.clone(),
            parser_version: "1.0.0".to_string(),
            parser_hash: step.parser_hash,
            input_hash: step.input_hash,
            output_hash: step.output_hash,
        })
        .collect();

    // Final output hash is the last parser step's output.
    let final_output_hash = s
        .pending_parser_steps
        .last()
        .map(|s| s.output_hash)
        .unwrap_or([0u8; 32]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let bundle = WitnessBundle {
        witness_id: format!("wtn_{now:x}"),
        input_blobs,
        parser_chain,
        transform_chain: vec![],
        validation_results: vec![],
        final_output_hash,
        signature: None,
        created_at: now,
        field_witnesses: std::collections::BTreeMap::new(),
        zkvm_receipt: None,
    };

    // Verify the chain.
    if let Err(e) = bundle.verify_chain() {
        return ClearanceResult::ChainBroken(format!("{e}"));
    }

    // Mark sources as witnessed and clear parser steps.
    let consumed_hashes: Vec<[u8; 32]> = unwitnessed
        .iter()
        .map(|(_, src)| src.content_hash)
        .collect();
    for src in &mut s.pending_source_hashes {
        if consumed_hashes.contains(&src.content_hash) {
            src.witnessed = true;
        }
    }
    s.pending_parser_steps.clear();

    let digest = bundle.compute_digest();
    ClearanceResult::Verified {
        bundle: Box::new(bundle),
        digest,
    }
}

// ---------------------------------------------------------------------------
// Deterministic field enforcement (#933)
// ---------------------------------------------------------------------------

/// Check whether a write to a schema field should be denied because the
/// field is declared `derivation: deterministic` but no `DeterministicBind`
/// exists for it.
///
/// Returns `Some(reason)` if the write should be denied, `None` if allowed.
pub(crate) fn check_deterministic_field_write(
    s: &SessionState,
    schema: &portcullis_core::provenance_schema::ProvenanceSchema,
    field_name: &str,
) -> Option<String> {
    use portcullis_core::provenance_schema::DerivationKind;

    let field = schema.fields.get(field_name)?;

    if field.derivation != DerivationKind::Deterministic {
        // AI-derived and user-provided fields can be written directly.
        return None;
    }

    // Deterministic field — check for a DeterministicBind record.
    let has_bind = s
        .deterministic_binds
        .iter()
        .any(|b| b.field_name == field_name);

    if has_bind {
        None
    } else {
        Some(format!(
            "field '{}' is declared deterministic — use the WASM parser pipeline, not direct model output. \
             Apply a registered parser first, then the DeterministicBind will populate this field automatically.",
            field_name
        ))
    }
}

/// Resolve field names on DeterministicBindRecords from a schema (#987).
///
/// Matches bind records (which have parser_id but empty field_name) to
/// schema fields that declare the same parser. Called after schema is loaded.
pub(crate) fn resolve_bind_field_names(
    s: &mut SessionState,
    schema: &portcullis_core::provenance_schema::ProvenanceSchema,
) {
    use portcullis_core::provenance_schema::DerivationKind;

    for bind in &mut s.deterministic_binds {
        if !bind.field_name.is_empty() {
            continue; // already resolved
        }
        // Find a deterministic field whose parser matches this bind's parser_id.
        for (name, field) in &schema.fields {
            if field.derivation == DerivationKind::Deterministic
                && field.parser.as_deref() == Some(&bind.parser_id)
            {
                bind.field_name = name.clone();
                break;
            }
        }
    }
}

/// Build a ProvenanceOutput from session state + schema (#988).
///
/// For each schema field, constructs the per-field provenance attestation:
/// - Deterministic fields with DeterministicBind: full hash chain
/// - AI-derived fields: honest labeling
pub(crate) fn build_provenance_output(
    s: &SessionState,
    schema: &portcullis_core::provenance_schema::ProvenanceSchema,
) -> portcullis_core::provenance_output::ProvenanceOutput {
    use portcullis_core::provenance_output::{ProvenanceHeader, ProvenanceOutput};
    use portcullis_core::provenance_schema::DerivationKind;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let header = ProvenanceHeader {
        schema_hash: format!("sha256:{}", hex::encode(schema.content_hash())),
        schema_version: schema.schema_version,
        completed_at: format!("{now}"),
        receipt_chain_head: format!("sha256:{}", hex::encode(s.chain_head_hash)),
        nucleus_version: env!("CARGO_PKG_VERSION").to_string(),
        contains_ai_derived: false,
    };

    let mut output = ProvenanceOutput::new(header);

    for (name, field) in &schema.fields {
        match field.derivation {
            DerivationKind::Deterministic => {
                // Find the bind record for this field.
                if let Some(bind) = s.deterministic_binds.iter().find(|b| b.field_name == *name) {
                    // Find the source hash from pending_source_hashes.
                    let source_hash = s
                        .pending_parser_steps
                        .iter()
                        .find(|p| p.parser_id == bind.parser_id)
                        .map(|p| hex::encode(p.input_hash))
                        .unwrap_or_default();

                    output.add_deterministic(
                        name,
                        serde_json::Value::Null, // value populated by caller
                        &format!("sha256:{source_hash}"),
                        &bind.parser_id,
                        field.expression.as_deref(),
                        &format!("sha256:{}", hex::encode(bind.output_hash)),
                    );
                }
            }
            DerivationKind::AiDerived => {
                output.add_ai_derived(name, serde_json::Value::Null, None);
            }
            DerivationKind::UserProvided => {
                // User-provided fields are like deterministic — Directive authority.
                output.add_deterministic(name, serde_json::Value::Null, "", "user", None, "");
            }
        }
    }

    output
}

/// Handle `UserPromptSubmit` — detect `!` bash passthrough (#918).
pub(crate) fn handle_user_prompt_submit(input: &crate::protocol::HookInput) {
    let prompt = input
        .tool_input
        .get("prompt")
        .and_then(|v| v.as_str())
        .or(input.tool_result.as_deref())
        .unwrap_or("");
    if prompt.starts_with('!') {
        with_session(&input.session_id, |s| {
            s.pending_user_bash = true;
        });
        eprintln!("nucleus: user bash passthrough detected — next output Deterministic/Directive");
    }
}

// ---------------------------------------------------------------------------
// Garbage collection
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Cross-session chain linking (#942)
// ---------------------------------------------------------------------------

/// Find the most recent prior session and return its chain head hash (#942).
///
/// Creates a timeline-linked chain across independent sessions (not spawned
/// sub-agents, which use NUCLEUS_PARENT_SESSION instead).
pub(crate) fn find_prior_session_chain(current_session_id: &str) -> Option<(String, String)> {
    let dir = session_dir();
    let entries = std::fs::read_dir(&dir).ok()?;

    let current_safe = sanitize_session_id(current_session_id);
    let mut best: Option<(String, u64, [u8; 32])> = None;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if filename == current_safe {
            continue;
        }

        let mtime = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let state: SessionState = match serde_json::from_str(&contents) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if state.chain_head_hash == [0u8; 32] {
            continue;
        }

        match &best {
            Some((_, best_mtime, _)) if mtime <= *best_mtime => {}
            _ => {
                best = Some((filename.to_string(), mtime, state.chain_head_hash));
            }
        }
    }

    best.map(|(sid, _, hash)| (sid, hex::encode(hash)))
}

// ---------------------------------------------------------------------------
// Child provenance verification (#955)
// ---------------------------------------------------------------------------

/// Verify a child agent's provenance chain links back to the parent (#955).
///
/// Scans session state files for a child whose `parent_session_id` matches
/// our session ID. If found, verifies the child's `parent_chain_hash` matches
/// our current chain head.
///
/// Returns:
/// - `Some(true)` — child found and chain links verified
/// - `Some(false)` — child found but chain link broken
/// - `None` — no child session found
pub(crate) fn verify_child_provenance(parent_session_id: &str, _agent_name: &str) -> Option<bool> {
    let dir = session_dir();
    let entries = std::fs::read_dir(&dir).ok()?;

    let parent_safe_id = sanitize_session_id(parent_session_id);

    // Load parent's current chain head.
    let parent_state = match load_session(parent_session_id) {
        SessionLoad::Loaded(s) | SessionLoad::Fresh(s) => s,
        _ => return None,
    };
    let parent_chain_head = parent_state.chain_head_hash;

    // Scan for child sessions referencing this parent.
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // Skip our own session file.
        let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if filename == parent_safe_id {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let child: SessionState = match serde_json::from_str(&contents) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Check if this child references our session as parent.
        if child.parent_session_id.as_deref() == Some(parent_session_id) {
            // Found a child — verify its chain link.
            if let Some(ref child_parent_hash) = child.parent_chain_hash {
                let parent_head_hex = hex::encode(parent_chain_head);
                if *child_parent_hash == parent_head_hex || parent_chain_head == [0u8; 32] {
                    return Some(true);
                } else {
                    eprintln!(
                        "nucleus: child chain link mismatch: child claims {}, parent head is {}",
                        &child_parent_hash[..16.min(child_parent_hash.len())],
                        &parent_head_hex[..16]
                    );
                    return Some(false);
                }
            }
            // Child has no parent_chain_hash — treat as unverified but found.
            return Some(true);
        }
    }

    None
}

/// Garbage-collect stale session files older than `ttl_secs` (#520).
///
/// Removes .json (state), .hwm (watermark), and .compartment files.
/// Receipt directories are preserved for audit.
/// Returns the number of files removed.
pub(crate) fn gc_stale_sessions(ttl_secs: u64) -> usize {
    let dir = session_dir();
    let now = std::time::SystemTime::now();
    let mut removed = 0;

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Only GC session files, not the receipts directory
        if path.is_dir() {
            continue;
        }

        // Only GC known session file extensions
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let is_session_file = ext == "json"
            || ext == "hwm"
            || ext == "compartment"
            || ext == "lock"
            || ext == "tmp"
            || name.ends_with(".parent-label")
            || name.ends_with(".parent-chain")
            || name.ends_with(".parent-compartment");

        if !is_session_file {
            continue;
        }

        // Check file age
        let age = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|modified| now.duration_since(modified).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if age > ttl_secs && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }

    removed
}

/// Run the `--gc` command: remove stale session files.
pub(crate) fn run_gc() {
    let removed = gc_stale_sessions(SESSION_GC_TTL_SECS);
    if removed > 0 {
        println!("nucleus: garbage collected {removed} stale session file(s) (older than 24h)");
    } else {
        println!("nucleus: no stale session files to clean up");
    }
    println!("nucleus: session directory: {}", session_dir().display());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_tamper_detection() {
        // Simulate: create a session, save it, delete state file, verify tamper detected
        let test_id = format!("tamper-test-{}", std::process::id());
        let state = SessionState {
            high_water_mark: 5,
            profile: "test".to_string(),
            ..Default::default()
        };
        save_session(&test_id, &state);

        // Verify loads correctly
        assert!(matches!(load_session(&test_id), SessionLoad::Loaded(_)));

        // Delete state file (simulating social engineering attack)
        let state_path = session_state_path(&test_id);
        std::fs::remove_file(&state_path).unwrap();

        // HWM file still exists -> tamper detected
        assert!(matches!(
            load_session(&test_id),
            SessionLoad::Tampered { expected_hwm: 5 }
        ));

        // Cleanup
        let hwm_path = session_hwm_path(&test_id);
        std::fs::remove_file(&hwm_path).ok();
    }

    #[test]
    fn test_fresh_session_is_not_tampered() {
        let test_id = format!("fresh-test-{}", std::process::id());
        // No prior state, no HWM file -> fresh session
        assert!(matches!(load_session(&test_id), SessionLoad::Fresh(_)));
    }

    // -----------------------------------------------------------------
    // Schema versioning tests (#523)
    // -----------------------------------------------------------------

    #[test]
    fn test_fresh_session_has_current_schema_version() {
        let state = SessionState::new_versioned();
        assert_eq!(state.schema_version, SESSION_SCHEMA_VERSION);
    }

    #[test]
    fn test_pre_versioned_state_deserializes() {
        // Simulate a pre-versioned session file (no schema_version field)
        let json = r#"{"profile":"test","high_water_mark":3,"allowed_ops":[]}"#;
        let state: SessionState = serde_json::from_str(json).unwrap();
        // schema_version defaults to 0, which load_session treats as version 1
        assert_eq!(state.schema_version, 0);
        assert_eq!(state.profile, "test");
        assert_eq!(state.high_water_mark, 3);
    }

    #[test]
    fn test_future_version_state_deserializes() {
        // A future version with unknown fields -- serde ignores them gracefully
        let json = r#"{"schema_version":99,"profile":"future","high_water_mark":1,
                        "allowed_ops":[],"future_field":"should_be_ignored"}"#;
        let state: SessionState = serde_json::from_str(json).unwrap();
        assert_eq!(state.schema_version, 99);
        assert_eq!(state.profile, "future");
    }

    #[test]
    fn test_save_roundtrip_preserves_version() {
        let test_id = format!("version-roundtrip-{}", std::process::id());
        let mut state = SessionState::new_versioned();
        state.profile = "test-profile".to_string();
        state.high_water_mark = 1;

        save_session(&test_id, &state);

        match load_session(&test_id) {
            SessionLoad::Loaded(loaded) => {
                assert_eq!(loaded.schema_version, SESSION_SCHEMA_VERSION);
                assert_eq!(loaded.profile, "test-profile");
            }
            other => panic!("expected Loaded, got {other:?}"),
        }

        // Cleanup
        std::fs::remove_file(session_state_path(&test_id)).ok();
        std::fs::remove_file(session_hwm_path(&test_id)).ok();
    }

    // -----------------------------------------------------------------
    // Session GC tests (#520)
    // -----------------------------------------------------------------

    #[test]
    fn test_gc_preserves_fresh_files() {
        let dir = session_dir();
        let fresh_file = dir.join("gc-test-fresh.json");

        // Create a fresh file
        std::fs::write(&fresh_file, "{}").unwrap();

        // GC with 24h TTL should preserve it (it's < 1 second old)
        gc_stale_sessions(SESSION_GC_TTL_SECS);
        assert!(fresh_file.exists(), "fresh file should be preserved");

        // Cleanup
        std::fs::remove_file(&fresh_file).ok();
    }

    #[test]
    fn test_gc_skips_non_session_files() {
        let dir = session_dir();
        let txt_file = dir.join("gc-test-notes.txt");
        std::fs::write(&txt_file, "not a session file").unwrap();

        // GC with TTL=0 should still skip .txt files (not a session extension)
        gc_stale_sessions(0);
        assert!(txt_file.exists(), ".txt file should not be GC'd");

        // Cleanup
        std::fs::remove_file(&txt_file).ok();
    }

    #[test]
    fn test_gc_preserves_receipts_dir() {
        let dir = session_dir();
        let receipts = dir.join("receipts");
        std::fs::create_dir_all(&receipts).ok();

        gc_stale_sessions(0);

        // Receipts directory should survive GC
        assert!(receipts.is_dir(), "receipts directory should be preserved");
    }

    // -----------------------------------------------------------------------
    // Trust revocation via flagged_tools (#485)
    // -----------------------------------------------------------------------

    #[test]
    fn flagged_tools_persists_in_session_state() {
        let mut session = SessionState::new_versioned();
        assert!(session.flagged_tools.is_empty());

        session
            .flagged_tools
            .insert("mcp__evil__tool".to_string(), 1);

        let json = serde_json::to_string(&session).unwrap();
        let loaded: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.flagged_tools.get("mcp__evil__tool"), Some(&1));
    }

    #[test]
    fn flagged_tools_defaults_empty_on_old_schema() {
        // Simulate loading a schema v2 session (no flagged_tools field).
        let json = r#"{"schema_version":2,"profile":"default","high_water_mark":5,
                       "allowed_ops":[],"flow_observations":[],"chain_head_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                       "signing_key_pkcs8":[],"compartment_token":""}"#;
        let session: SessionState = serde_json::from_str(json).unwrap();
        assert!(
            session.flagged_tools.is_empty(),
            "old schema should deserialize with empty flagged_tools"
        );
    }

    #[test]
    fn violation_count_is_monotonic() {
        let mut session = SessionState::new_versioned();
        let tool = "mcp__shady__fetch".to_string();

        // First violation
        let count = session.flagged_tools.entry(tool.clone()).or_insert(0);
        *count = count.saturating_add(1);
        assert_eq!(session.flagged_tools[&tool], 1);

        // Second violation
        let count = session.flagged_tools.entry(tool.clone()).or_insert(0);
        *count = count.saturating_add(2);
        assert_eq!(session.flagged_tools[&tool], 3);

        // Verify threshold check
        assert!(session.flagged_tools[&tool] >= MANIFEST_VIOLATION_REVOKE_THRESHOLD);
    }

    #[test]
    fn test_post_tool_observation_roundtrip() {
        // Verify that a PostToolUse observation can be serialized and
        // deserialized as part of SessionState (backward compatible).
        //
        // NodeKind discriminants used here (see node_kind_to_u8 in classify.rs):
        //   FileRead = 5, ToolResponse = 1
        const FILE_READ: u8 = 5;
        const TOOL_RESPONSE: u8 = 1;

        let mut state = SessionState {
            profile: "test".to_string(),
            ..Default::default()
        };

        // Simulate PreToolUse adding an observation
        state.flow_observations.push((
            FILE_READ,
            "ReadFiles".to_string(),
            "/some/file.rs".to_string(),
        ));
        state.last_pre_tool_obs_index = Some(0);

        // Simulate PostToolUse adding a ToolResponse
        state.flow_observations.push((
            TOOL_RESPONSE,
            "post:ReadFiles".to_string(),
            "file contents here...".to_string(),
        ));
        state.last_pre_tool_obs_index = None;

        // Serialize and deserialize
        let json = serde_json::to_string(&state).unwrap();
        let restored: SessionState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.flow_observations.len(), 2);
        assert_eq!(restored.flow_observations[0].0, FILE_READ);
        assert_eq!(restored.flow_observations[1].0, TOOL_RESPONSE);
        assert!(restored.flow_observations[1].1.starts_with("post:"));
        assert!(restored.last_pre_tool_obs_index.is_none());
    }

    #[test]
    fn pending_source_hash_round_trip() {
        let hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"<html>example</html>");
            let result: [u8; 32] = h.finalize().into();
            result
        };
        let mut state = SessionState {
            profile: "test".to_string(),
            ..Default::default()
        };
        state.pending_source_hashes.push(PendingSourceHash {
            content_hash: hash,
            tool_name: "WebFetch".to_string(),
            captured_at: 1711900000,
            witnessed: false,
            raw_content: None,
        });

        let json = serde_json::to_string(&state).unwrap();
        let restored: SessionState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.pending_source_hashes.len(), 1);
        assert_eq!(restored.pending_source_hashes[0].content_hash, hash);
        assert_eq!(restored.pending_source_hashes[0].tool_name, "WebFetch");
        assert!(!restored.pending_source_hashes[0].witnessed);
    }

    #[test]
    fn pending_source_hash_backward_compatible() {
        // Old session JSON without pending_source_hashes field should deserialize
        let json = r#"{"schema_version":3,"profile":"test","high_water_mark":0,
            "allowed_ops":[],"flow_observations":[],"chain_head_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "signing_key_pkcs8":[],"compartment_token":"","web_tainted":false,
            "web_taint_context_injected":false}"#;
        let state: SessionState = serde_json::from_str(json).unwrap();
        assert!(state.pending_source_hashes.is_empty());
    }

    // -----------------------------------------------------------------------
    // Compartment escalation detection (#464)
    // -----------------------------------------------------------------------

    /// Helper: write a compartment file for a test session and resolve it.
    fn write_and_resolve(
        session_id: &str,
        token: &str,
        content: &str,
        current: Option<portcullis_core::compartment::Compartment>,
    ) -> Option<portcullis_core::compartment::Compartment> {
        let keyed = keyed_compartment_name(session_id, token);
        let path = session_dir().join(format!("{keyed}.compartment"));
        std::fs::write(&path, content).unwrap();
        let result = resolve_compartment(session_id, token, current);
        // Cleanup
        std::fs::remove_file(&path).ok();
        result
    }

    #[test]
    fn resolve_compartment_no_escalation_from_none() {
        let sid = format!("esc-none-{}", std::process::id());
        let token = "test-token-esc-none";
        // No current compartment -> no escalation warning, just resolution
        let result = write_and_resolve(&sid, token, "draft", None);
        assert_eq!(
            result,
            Some(portcullis_core::compartment::Compartment::Draft)
        );
    }

    #[test]
    fn resolve_compartment_skip_level_research_to_execute_denied() {
        let sid = format!("esc-r2e-{}", std::process::id());
        let token = "test-token-esc-r2e";
        let result = write_and_resolve(
            &sid,
            token,
            "execute",
            Some(portcullis_core::compartment::Compartment::Research),
        );
        // Research -> Execute skips Draft — must be denied (#733)
        assert_eq!(
            result, None,
            "skip-level escalation research -> execute must be denied"
        );
    }

    #[test]
    fn resolve_compartment_single_step_research_to_draft_allowed() {
        let sid = format!("esc-r2d-{}", std::process::id());
        let token = "test-token-esc-r2d";
        let result = write_and_resolve(
            &sid,
            token,
            "draft",
            Some(portcullis_core::compartment::Compartment::Research),
        );
        assert_eq!(
            result,
            Some(portcullis_core::compartment::Compartment::Draft),
            "single-step research -> draft should be allowed"
        );
    }

    #[test]
    fn resolve_compartment_single_step_draft_to_execute_allowed() {
        let sid = format!("esc-d2e-{}", std::process::id());
        let token = "test-token-esc-d2e";
        let result = write_and_resolve(
            &sid,
            token,
            "execute",
            Some(portcullis_core::compartment::Compartment::Draft),
        );
        assert_eq!(
            result,
            Some(portcullis_core::compartment::Compartment::Execute),
            "single-step draft -> execute should be allowed"
        );
    }

    #[test]
    fn resolve_compartment_skip_level_research_to_breakglass_denied() {
        let sid = format!("esc-r2bg-{}", std::process::id());
        let token = "test-token-esc-r2bg";
        let result = write_and_resolve(
            &sid,
            token,
            "breakglass:emergency",
            Some(portcullis_core::compartment::Compartment::Research),
        );
        // Research -> Breakglass skips two levels — must be denied (#733)
        assert_eq!(
            result, None,
            "skip-level escalation research -> breakglass must be denied"
        );
    }

    #[test]
    fn resolve_compartment_de_escalation_no_warning() {
        let sid = format!("esc-deesc-{}", std::process::id());
        let token = "test-token-deesc";
        let result = write_and_resolve(
            &sid,
            token,
            "research",
            Some(portcullis_core::compartment::Compartment::Execute),
        );
        assert_eq!(
            result,
            Some(portcullis_core::compartment::Compartment::Research)
        );
    }

    #[test]
    fn resolve_compartment_breakglass_requires_reason() {
        let sid = format!("esc-bg-noreason-{}", std::process::id());
        let token = "test-token-bg-noreason";
        // Bare "breakglass" without reason should be DENIED
        let result = write_and_resolve(
            &sid,
            token,
            "breakglass",
            Some(portcullis_core::compartment::Compartment::Research),
        );
        assert_eq!(
            result, None,
            "bare breakglass without reason must be denied"
        );
    }

    #[test]
    fn resolve_compartment_breakglass_with_reason_accepted() {
        let sid = format!("esc-bg-reason-{}", std::process::id());
        let token = "test-token-bg-reason";
        let result = write_and_resolve(
            &sid,
            token,
            "breakglass:production outage P1",
            Some(portcullis_core::compartment::Compartment::Execute),
        );
        assert_eq!(
            result,
            Some(portcullis_core::compartment::Compartment::Breakglass)
        );
    }

    #[test]
    fn resolve_compartment_breakglass_empty_reason_denied() {
        let sid = format!("esc-bg-empty-{}", std::process::id());
        let token = "test-token-bg-empty";
        // "breakglass:" with empty reason should be denied
        let result = write_and_resolve(&sid, token, "breakglass:", None);
        assert_eq!(result, None, "breakglass with empty reason must be denied");
    }

    // -----------------------------------------------------------------
    // File permission tests (#744)
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_session_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let test_id = format!("perms-test-{}", std::process::id());
        let state = SessionState {
            high_water_mark: 1,
            profile: "test".to_string(),
            signing_key_pkcs8: vec![1, 2, 3, 4], // Simulated key material
            ..Default::default()
        };
        save_session(&test_id, &state);

        // Verify session state file has 0600 permissions
        let state_path = session_state_path(&test_id);
        let meta = std::fs::metadata(&state_path).expect("state file should exist");
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o600,
            "session state file should have 0600 permissions, got {:04o}",
            mode
        );

        // Verify HWM file also has 0600 permissions
        let hwm_path = session_hwm_path(&test_id);
        let hwm_meta = std::fs::metadata(&hwm_path).expect("HWM file should exist");
        let hwm_mode = hwm_meta.permissions().mode() & 0o7777;
        assert_eq!(
            hwm_mode, 0o600,
            "HWM file should have 0600 permissions, got {:04o}",
            hwm_mode
        );

        // Verify session directory has 0700 permissions
        let dir = session_dir();
        let dir_meta = std::fs::metadata(&dir).expect("session dir should exist");
        let dir_mode = dir_meta.permissions().mode() & 0o7777;
        assert_eq!(
            dir_mode, 0o700,
            "session directory should have 0700 permissions, got {:04o}",
            dir_mode
        );

        // Cleanup
        std::fs::remove_file(&state_path).ok();
        std::fs::remove_file(&hwm_path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_session_dir_permission_warning() {
        // Verify that session_dir() sets 0700 permissions even if
        // the directory already exists with looser permissions.
        let dir = session_dir();
        use std::os::unix::fs::PermissionsExt;

        // Temporarily loosen permissions
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).ok();

        // Re-call session_dir() — it should fix permissions back to 0700
        let dir2 = session_dir();
        let meta = std::fs::metadata(&dir2).expect("session dir should exist");
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o700,
            "session_dir() should restore 0700 permissions, got {:04o}",
            mode
        );
    }

    // -----------------------------------------------------------------------
    // TOCTOU race prevention tests (#872)
    // -----------------------------------------------------------------------

    #[test]
    fn with_session_atomic_increment() {
        // Verify that with_session correctly loads, mutates, and saves.
        let test_id = format!("atomic-incr-{}", std::process::id());

        // Create initial state
        let mut state = SessionState::new_versioned();
        state.profile = "test".to_string();
        state.high_water_mark = 10;
        save_session(&test_id, &state);

        // Atomically increment HWM
        let result = with_session(&test_id, |s| {
            s.high_water_mark += 1;
        });
        assert!(result.is_some());
        assert_eq!(result.unwrap().high_water_mark, 11);

        // Verify persisted correctly
        match load_session(&test_id) {
            SessionLoad::Loaded(s) => assert_eq!(s.high_water_mark, 11),
            other => panic!("expected Loaded, got {other:?}"),
        }

        // Cleanup
        std::fs::remove_file(session_state_path(&test_id)).ok();
        std::fs::remove_file(session_hwm_path(&test_id)).ok();
    }

    #[test]
    fn with_session_returns_none_on_tampered() {
        // Verify that with_session returns None for tampered sessions.
        let test_id = format!("atomic-tamper-{}", std::process::id());

        // Create session with HWM > 0
        let mut state = SessionState::new_versioned();
        state.profile = "test".to_string();
        state.high_water_mark = 5;
        save_session(&test_id, &state);

        // Delete state file (simulate social engineering)
        std::fs::remove_file(session_state_path(&test_id)).unwrap();

        // with_session should detect tamper and return None
        let result = with_session(&test_id, |s| {
            s.high_water_mark += 1; // should never execute
        });
        assert!(result.is_none(), "tampered session should return None");

        // Cleanup
        std::fs::remove_file(session_hwm_path(&test_id)).ok();
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_with_session_no_lost_updates() {
        // Spawn N threads that each atomically increment HWM via with_session.
        // If the lock works, final HWM == initial + N. Without the lock,
        // concurrent load+save would lose increments.
        use std::sync::Arc;

        let test_id = format!("concurrent-{}", std::process::id());
        let initial_hwm = 0u64;
        let num_threads = 8;

        // Create initial state
        let mut state = SessionState::new_versioned();
        state.profile = "test".to_string();
        state.high_water_mark = initial_hwm;
        save_session(&test_id, &state);

        let test_id = Arc::new(test_id);
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let id = Arc::clone(&test_id);
                std::thread::spawn(move || {
                    with_session(&id, |s| {
                        s.high_water_mark += 1;
                    });
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Verify all increments were applied (no lost updates)
        match load_session(&test_id) {
            SessionLoad::Loaded(s) => {
                assert_eq!(
                    s.high_water_mark,
                    initial_hwm + num_threads,
                    "expected {num_threads} increments, got {} (lost updates!)",
                    s.high_water_mark - initial_hwm
                );
            }
            other => panic!("expected Loaded, got {other:?}"),
        }

        // Cleanup
        std::fs::remove_file(session_state_path(&test_id)).ok();
        std::fs::remove_file(session_hwm_path(&test_id)).ok();
        std::fs::remove_file(session_lock_path(&test_id)).ok();
    }

    // -----------------------------------------------------------------------
    // Transition request protocol tests (#875)
    // -----------------------------------------------------------------------

    /// In-process mutex for transition request tests — prevents parallel
    /// test interference on the global transition-request.json file.
    static TRANSITION_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn transition_test_lock() -> std::sync::MutexGuard<'static, ()> {
        TRANSITION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn transition_request_roundtrip() {
        let _lock = transition_test_lock();
        let sid = format!("tr-roundtrip-{}", std::process::id());
        let path = request_compartment_transition(&sid, "draft", "test transition")
            .expect("should write request file");
        assert!(path.exists(), "request file should exist");

        let request = check_pending_transition().expect("should read pending transition");
        assert_eq!(request.target, "draft");
        assert_eq!(request.reason, "test transition");
        assert!(request.requested_at > 0, "timestamp should be set");

        // Cleanup
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn transition_request_apply_valid_single_step() {
        let _lock = transition_test_lock();
        let sid = format!("tr-apply-{}", std::process::id());
        let token = "test-token-tr-apply";

        let request = TransitionRequest {
            target: "draft".to_string(),
            reason: "escalate to draft".to_string(),
            requested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let req_path = transition_request_path();
        if let Some(parent) = req_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let result = apply_pending_transition(
            &sid,
            token,
            Some(portcullis_core::compartment::Compartment::Research),
            &request,
        );
        assert!(
            result.is_ok(),
            "single-step research -> draft should succeed"
        );

        // Verify compartment file was written
        let keyed = keyed_compartment_name(&sid, token);
        let comp_path = session_dir().join(format!("{keyed}.compartment"));
        let content = std::fs::read_to_string(&comp_path).expect("compartment file should exist");
        assert_eq!(content.trim(), "draft");

        // Verify request file was deleted
        assert!(
            !req_path.exists(),
            "request file should be deleted after apply"
        );

        // Cleanup
        std::fs::remove_file(&comp_path).ok();
    }

    #[test]
    fn transition_request_deny_skip_level() {
        let _lock = transition_test_lock();
        let sid = format!("tr-skip-{}", std::process::id());
        let token = "test-token-tr-skip";

        let request = TransitionRequest {
            target: "execute".to_string(),
            reason: "try to skip".to_string(),
            requested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let req_path = transition_request_path();
        if let Some(parent) = req_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let result = apply_pending_transition(
            &sid,
            token,
            Some(portcullis_core::compartment::Compartment::Research),
            &request,
        );
        assert!(
            matches!(result, Err(TransitionError::SkipLevel { .. })),
            "skip-level research -> execute must be denied, got: {result:?}"
        );

        // Verify request file was deleted even on denial
        assert!(
            !req_path.exists(),
            "request file should be deleted after denial"
        );
    }

    #[test]
    fn transition_request_deny_breakglass_no_reason() {
        let _lock = transition_test_lock();
        let sid = format!("tr-bg-noreason-{}", std::process::id());
        let token = "test-token-tr-bg-noreason";

        let request = TransitionRequest {
            target: "breakglass".to_string(),
            reason: "emergency".to_string(),
            requested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let req_path = transition_request_path();
        if let Some(parent) = req_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let result = apply_pending_transition(
            &sid,
            token,
            Some(portcullis_core::compartment::Compartment::Execute),
            &request,
        );
        assert!(
            matches!(result, Err(TransitionError::BreakglassNoReason)),
            "bare breakglass without reason in target must be denied, got: {result:?}"
        );

        std::fs::remove_file(&req_path).ok();
    }

    #[test]
    fn transition_request_breakglass_with_reason_accepted() {
        let _lock = transition_test_lock();
        let sid = format!("tr-bg-reason-{}", std::process::id());
        let token = "test-token-tr-bg-reason";

        let request = TransitionRequest {
            target: "breakglass:production outage P1".to_string(),
            reason: "production outage P1".to_string(),
            requested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let req_path = transition_request_path();
        if let Some(parent) = req_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let result = apply_pending_transition(
            &sid,
            token,
            Some(portcullis_core::compartment::Compartment::Execute),
            &request,
        );
        assert!(
            result.is_ok(),
            "breakglass with reason should succeed, got: {result:?}"
        );

        let keyed = keyed_compartment_name(&sid, token);
        let comp_path = session_dir().join(format!("{keyed}.compartment"));
        std::fs::remove_file(&comp_path).ok();
        std::fs::remove_file(&req_path).ok();
    }

    #[test]
    fn transition_request_stale_rejected() {
        let _lock = transition_test_lock();
        let sid = format!("tr-stale-{}", std::process::id());
        let token = "test-token-tr-stale";

        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120; // 2 minutes ago, well past the 60s TTL

        let request = TransitionRequest {
            target: "draft".to_string(),
            reason: "stale request".to_string(),
            requested_at: old_timestamp,
        };

        let req_path = transition_request_path();
        if let Some(parent) = req_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let result = apply_pending_transition(
            &sid,
            token,
            Some(portcullis_core::compartment::Compartment::Research),
            &request,
        );
        assert!(
            matches!(result, Err(TransitionError::Stale)),
            "stale request should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn transition_request_invalid_target() {
        let _lock = transition_test_lock();
        let sid = format!("tr-invalid-{}", std::process::id());
        let token = "test-token-tr-invalid";

        let request = TransitionRequest {
            target: "nonexistent".to_string(),
            reason: "bad target".to_string(),
            requested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let req_path = transition_request_path();
        if let Some(parent) = req_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let result = apply_pending_transition(&sid, token, None, &request);
        assert!(
            matches!(result, Err(TransitionError::InvalidTarget(_))),
            "invalid target should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn transition_request_de_escalation_allowed() {
        let _lock = transition_test_lock();
        let sid = format!("tr-deesc-{}", std::process::id());
        let token = "test-token-tr-deesc";

        let request = TransitionRequest {
            target: "research".to_string(),
            reason: "sealing back down".to_string(),
            requested_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let req_path = transition_request_path();
        if let Some(parent) = req_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let result = apply_pending_transition(
            &sid,
            token,
            Some(portcullis_core::compartment::Compartment::Execute),
            &request,
        );
        assert!(
            result.is_ok(),
            "de-escalation should always be allowed, got: {result:?}"
        );

        let keyed = keyed_compartment_name(&sid, token);
        let comp_path = session_dir().join(format!("{keyed}.compartment"));
        std::fs::remove_file(&comp_path).ok();
    }

    #[test]
    fn check_pending_transition_returns_none_when_no_file() {
        let _lock = transition_test_lock();
        let req_path = transition_request_path();
        std::fs::remove_file(&req_path).ok();

        assert!(
            check_pending_transition().is_none(),
            "should return None when no request file exists"
        );
    }

    // -----------------------------------------------------------------
    // User bash passthrough (#918)
    // -----------------------------------------------------------------

    #[test]
    fn record_post_tool_user_bash_sets_user_prompt_kind() {
        use crate::classify::node_kind_to_u8;

        let mut s = SessionState {
            pending_user_bash: true,
            ..Default::default()
        };

        record_post_tool(
            &mut s,
            portcullis_core::flow::NodeKind::OutboundAction,
            "Bash",
            "hello world",
            false,
            [0u8; 32],
            "",
            "",
        );

        assert!(!s.pending_user_bash, "flag should be cleared after use");
        assert_eq!(s.flow_observations.len(), 1);
        let (kind_u8, ref label, _) = s.flow_observations[0];
        assert_eq!(
            kind_u8,
            node_kind_to_u8(portcullis_core::flow::NodeKind::UserPrompt),
            "user bash passthrough should be classified as UserPrompt"
        );
        assert!(
            label.starts_with("post:user:"),
            "label should have user prefix, got: {label}"
        );
    }

    #[test]
    fn record_post_tool_normal_bash_keeps_original_kind() {
        use crate::classify::node_kind_to_u8;

        let mut s = SessionState::default();
        // pending_user_bash is false by default

        record_post_tool(
            &mut s,
            portcullis_core::flow::NodeKind::OutboundAction,
            "Bash",
            "hello world",
            false,
            [0u8; 32],
            "",
            "",
        );

        assert_eq!(s.flow_observations.len(), 1);
        let (kind_u8, ref label, _) = s.flow_observations[0];
        assert_eq!(
            kind_u8,
            node_kind_to_u8(portcullis_core::flow::NodeKind::OutboundAction),
            "normal bash should keep OutboundAction kind"
        );
        assert!(
            label.starts_with("post:Bash"),
            "label should NOT have user prefix, got: {label}"
        );
    }

    // -----------------------------------------------------------------
    // WASM reduction pipeline (#915)
    // -----------------------------------------------------------------

    #[test]
    fn pending_parser_step_serialization_roundtrip() {
        let step = PendingParserStep {
            input_hash: [0xAA; 32],
            parser_id: "jq".into(),
            parser_hash: [0xBB; 32],
            output_hash: [0xCC; 32],
            output: b"parsed output".to_vec(),
            executed_at: 1234567890,
        };
        let json = serde_json::to_string(&step).unwrap();
        let restored: PendingParserStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, restored);
    }

    #[test]
    fn try_wasm_reduction_noop_without_parsers_dir() {
        // No .nucleus/parsers/ directory → should return without error.
        let mut s = SessionState::default();
        try_wasm_reduction(&mut s, [0u8; 32], b"test", "WebFetch");
        assert!(
            s.pending_parser_steps.is_empty(),
            "no parser steps should be added without a parsers directory"
        );
    }

    // -----------------------------------------------------------------
    // WitnessBundle assembly / /clearance (#916)
    // -----------------------------------------------------------------

    #[test]
    fn assemble_witness_no_pending_content() {
        let mut s = SessionState::default();
        assert!(matches!(
            assemble_witness_bundle(&mut s),
            ClearanceResult::NoPendingContent
        ));
    }

    #[test]
    fn assemble_witness_no_parser_steps() {
        let mut s = SessionState::default();
        s.pending_source_hashes.push(PendingSourceHash {
            content_hash: [0xAA; 32],
            tool_name: "WebFetch".into(),
            captured_at: 1000,
            witnessed: false,
            raw_content: None,
        });
        match assemble_witness_bundle(&mut s) {
            ClearanceResult::NoParserSteps { pending_sources } => {
                assert_eq!(pending_sources, 1);
            }
            other => panic!("expected NoParserSteps, got: {other:?}"),
        }
    }

    #[test]
    fn assemble_witness_valid_chain() {
        let source_hash = [0xAA; 32];
        let parser_hash = [0xBB; 32];
        let output_hash = [0xCC; 32];

        let mut s = SessionState::default();
        s.pending_source_hashes.push(PendingSourceHash {
            content_hash: source_hash,
            tool_name: "WebFetch".into(),
            captured_at: 1000,
            witnessed: false,
            raw_content: None,
        });
        s.pending_parser_steps.push(PendingParserStep {
            input_hash: source_hash, // links to source
            parser_id: "jq".into(),
            parser_hash,
            output_hash,
            output: b"parsed".to_vec(),
            executed_at: 1001,
        });

        match assemble_witness_bundle(&mut s) {
            ClearanceResult::Verified { bundle, digest } => {
                assert!(bundle.is_valid());
                assert_eq!(bundle.parser_chain.len(), 1);
                assert_eq!(bundle.input_blobs.len(), 1);
                assert_eq!(bundle.final_output_hash, output_hash);
                assert_ne!(digest, [0u8; 32]);
            }
            other => panic!("expected Verified, got: {other:?}"),
        }

        // Sources should be marked as witnessed.
        assert!(s.pending_source_hashes[0].witnessed);
        // Parser steps should be cleared.
        assert!(s.pending_parser_steps.is_empty());
    }

    #[test]
    fn assemble_witness_broken_chain() {
        let mut s = SessionState::default();
        s.pending_source_hashes.push(PendingSourceHash {
            content_hash: [0xAA; 32],
            tool_name: "WebFetch".into(),
            captured_at: 1000,
            witnessed: false,
            raw_content: None,
        });
        s.pending_parser_steps.push(PendingParserStep {
            input_hash: [0xFF; 32], // does NOT link to source hash
            parser_id: "jq".into(),
            parser_hash: [0xBB; 32],
            output_hash: [0xCC; 32],
            output: b"parsed".to_vec(),
            executed_at: 1001,
        });

        assert!(matches!(
            assemble_witness_bundle(&mut s),
            ClearanceResult::ChainBroken(_)
        ));
    }

    // -----------------------------------------------------------------
    // DeterministicBind records (#932)
    // -----------------------------------------------------------------

    #[test]
    fn deterministic_bind_record_serialization_roundtrip() {
        let record = DeterministicBindRecord {
            field_name: "revenue".into(),
            output_hash: [0xCC; 32],
            parser_id: "jq".into(),
            node_kind_u8: 16,
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: DeterministicBindRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, restored);
    }

    #[test]
    fn session_with_deterministic_binds_roundtrip() {
        let mut state = SessionState::default();
        state.deterministic_binds.push(DeterministicBindRecord {
            field_name: "revenue".into(),
            output_hash: [0xCC; 32],
            parser_id: "jq".into(),
            node_kind_u8: 16,
        });
        let json = serde_json::to_string(&state).unwrap();
        let restored: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.deterministic_binds, restored.deterministic_binds);
    }

    // -----------------------------------------------------------------
    // Deterministic field enforcement (#933)
    // -----------------------------------------------------------------

    fn test_schema() -> portcullis_core::provenance_schema::ProvenanceSchema {
        use portcullis_core::provenance_schema::*;
        use std::collections::BTreeMap;

        let mut sources = BTreeMap::new();
        sources.insert(
            "api".into(),
            SourceDeclaration {
                url_template: "https://example.com".into(),
                content_type: None,
                max_staleness_secs: None,
            },
        );
        let mut fields = BTreeMap::new();
        fields.insert(
            "revenue".into(),
            FieldDeclaration {
                source: "api".into(),
                derivation: DerivationKind::Deterministic,
                parser: Some("jq".into()),
                expression: Some(".revenue".into()),
            },
        );
        fields.insert(
            "summary".into(),
            FieldDeclaration {
                source: "api".into(),
                derivation: DerivationKind::AiDerived,
                parser: None,
                expression: None,
            },
        );
        ProvenanceSchema {
            schema_version: 1,
            description: "test".into(),
            sources,
            fields,
        }
    }

    #[test]
    fn deterministic_field_denied_without_bind() {
        let s = SessionState::default();
        let schema = test_schema();
        let result = check_deterministic_field_write(&s, &schema, "revenue");
        assert!(
            result.is_some(),
            "should deny write to deterministic field without bind"
        );
    }

    #[test]
    fn deterministic_field_allowed_with_bind() {
        let mut s = SessionState::default();
        s.deterministic_binds.push(DeterministicBindRecord {
            field_name: "revenue".into(),
            output_hash: [0xCC; 32],
            parser_id: "jq".into(),
            node_kind_u8: 16,
        });
        let schema = test_schema();
        let result = check_deterministic_field_write(&s, &schema, "revenue");
        assert!(result.is_none(), "should allow write when bind exists");
    }

    #[test]
    fn ai_derived_field_always_allowed() {
        let s = SessionState::default();
        let schema = test_schema();
        let result = check_deterministic_field_write(&s, &schema, "summary");
        assert!(
            result.is_none(),
            "AI-derived fields should always be writable"
        );
    }

    #[test]
    fn unknown_field_always_allowed() {
        let s = SessionState::default();
        let schema = test_schema();
        let result = check_deterministic_field_write(&s, &schema, "nonexistent");
        assert!(result.is_none(), "unknown fields should pass through");
    }
}
