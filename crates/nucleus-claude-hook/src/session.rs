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
    #[serde(default)]
    pub(crate) signing_key_pkcs8: Vec<u8>,
    /// Active compartment name (if any). Used to detect transitions.
    #[serde(default)]
    pub(crate) active_compartment: Option<String>,
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
pub(crate) fn save_session(session_id: &str, state: &SessionState) {
    let path = session_state_path(session_id);
    let hwm_path = session_hwm_path(session_id);
    let lock_path = session_lock_path(session_id);

    // Acquire advisory lock (non-blocking — if locked, warn and proceed)
    let _lock_guard = acquire_session_lock(&lock_path);

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
        }
        Err(e) => {
            eprintln!("nucleus: WARNING �� failed to serialize session state: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Advisory file locking
// ---------------------------------------------------------------------------

/// RAII guard for advisory file lock.
struct SessionLockGuard {
    #[cfg(unix)]
    _file: std::fs::File,
}

/// Acquire an advisory file lock (non-blocking).
///
/// Returns a guard that releases the lock on drop. If locking fails
/// (e.g., another invocation holds it), logs a warning and returns
/// a no-op guard — we proceed without the lock rather than blocking
/// the hook response (which would stall Claude Code).
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
                // Non-blocking exclusive lock
                let fd = file.as_raw_fd();
                // SAFETY: fd is valid, LOCK_EX | LOCK_NB is a valid flock operation
                let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
                if ret != 0 {
                    eprintln!(
                        "nucleus: WARNING — session lock contention (concurrent hook invocation). \
                         Proceeding without lock."
                    );
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

// ---------------------------------------------------------------------------
// Garbage collection
// ---------------------------------------------------------------------------

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
}
