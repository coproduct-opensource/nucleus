//! Ephemeral session identity for AI agent conversations.
//!
//! This module provides session-scoped SPIFFE identities that tie a conversation
//! or task to a cryptographic credential. Session identities:
//!
//! - Derive from a parent workload identity
//! - Have a unique session ID (UUID v7 for time-ordering)
//! - Auto-expire when the session TTL elapses
//! - Enable audit correlation across tool calls
//!
//! # SPIFFE URI Format
//!
//! Session identities extend the parent URI with a session segment:
//! ```text
//! spiffe://trust-domain/ns/namespace/sa/service/session/{uuid}
//! ```
//!
//! # Example
//!
//! ```
//! use nucleus_identity::{Identity, SessionIdentity};
//! use std::time::Duration;
//!
//! let parent = Identity::new("nucleus.local", "agents", "claude");
//! let session = SessionIdentity::new(parent, Duration::from_secs(3600));
//!
//! println!("Session SPIFFE URI: {}", session.to_spiffe_uri());
//! // spiffe://nucleus.local/ns/agents/sa/claude/session/01941234-...
//! ```

use crate::identity::Identity;
use chrono::{DateTime, Utc};
use std::fmt;
use std::time::Duration;

/// A session-scoped identity derived from a parent workload identity.
///
/// Session identities provide conversation-level credentials for AI agents,
/// enabling:
/// - Audit correlation across multiple tool calls
/// - Automatic credential expiry when sessions end
/// - Cryptographic binding of actions to specific conversations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionIdentity {
    /// The parent workload identity this session derives from.
    pub(crate) parent: Identity,
    /// Unique session identifier (UUID v7 for time-ordering).
    pub(crate) session_id: SessionId,
    /// When this session was created.
    pub(crate) created_at: DateTime<Utc>,
    /// How long this session is valid.
    pub(crate) ttl: Duration,
}

/// A unique session identifier using UUID v7 format.
///
/// UUID v7 is preferred because:
/// - Time-ordered for natural sorting
/// - Includes millisecond timestamp
/// - Globally unique without coordination
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionIdentity {
    /// Creates a new session identity derived from a parent.
    ///
    /// The session ID is automatically generated as a UUID v7.
    pub fn new(parent: Identity, ttl: Duration) -> Self {
        Self {
            parent,
            session_id: SessionId::new_v7(),
            created_at: Utc::now(),
            ttl,
        }
    }

    /// Creates a session identity with a specific session ID.
    ///
    /// Useful for resuming sessions or testing.
    pub fn with_id(parent: Identity, session_id: SessionId, ttl: Duration) -> Self {
        Self {
            parent,
            session_id,
            created_at: Utc::now(),
            ttl,
        }
    }

    /// Returns the parent workload identity.
    pub fn parent(&self) -> &Identity {
        &self.parent
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns when this session was created.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Returns the session TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns when this session expires.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.created_at + chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::hours(1))
    }

    /// Returns true if the session has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at()
    }

    /// Returns the remaining time before expiry, or None if expired.
    pub fn remaining(&self) -> Option<Duration> {
        let remaining = self.expires_at() - Utc::now();
        if remaining <= chrono::Duration::zero() {
            None
        } else {
            remaining.to_std().ok()
        }
    }

    /// Converts to a SPIFFE URI string.
    ///
    /// Format: `spiffe://{trust-domain}/ns/{namespace}/sa/{service}/session/{session-id}`
    pub fn to_spiffe_uri(&self) -> String {
        format!(
            "{}/session/{}",
            self.parent.to_spiffe_uri(),
            self.session_id
        )
    }

    /// Returns the trust domain (from parent).
    pub fn trust_domain(&self) -> &str {
        self.parent.trust_domain()
    }

    /// Returns the namespace (from parent).
    pub fn namespace(&self) -> &str {
        self.parent.namespace()
    }

    /// Returns the service account (from parent).
    pub fn service_account(&self) -> &str {
        self.parent.service_account()
    }

    /// Converts this session identity to a workload Identity for certificate issuance.
    ///
    /// The resulting identity has the session ID as the service account suffix:
    /// `spiffe://domain/ns/namespace/sa/service-{session-id}`
    ///
    /// This ensures each session gets a unique certificate while maintaining
    /// SPIFFE compatibility.
    pub fn to_certificate_identity(&self) -> Identity {
        Identity::new(
            self.parent.trust_domain(),
            self.parent.namespace(),
            format!("{}-{}", self.parent.service_account(), self.session_id),
        )
    }
}

impl fmt::Display for SessionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_spiffe_uri())
    }
}

impl SessionId {
    /// Creates a new UUID v7 session ID.
    ///
    /// UUID v7 format (RFC 9562):
    /// - 48 bits: Unix timestamp in milliseconds
    /// - 4 bits: Version (7)
    /// - 12 bits: Random
    /// - 2 bits: Variant (RFC 4122)
    /// - 62 bits: Random
    pub fn new_v7() -> Self {
        let mut bytes = [0u8; 16];

        // Get Unix timestamp in milliseconds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let millis = now.as_millis() as u64;

        // First 48 bits: timestamp
        bytes[0] = ((millis >> 40) & 0xff) as u8;
        bytes[1] = ((millis >> 32) & 0xff) as u8;
        bytes[2] = ((millis >> 24) & 0xff) as u8;
        bytes[3] = ((millis >> 16) & 0xff) as u8;
        bytes[4] = ((millis >> 8) & 0xff) as u8;
        bytes[5] = (millis & 0xff) as u8;

        // Fill remaining with random data
        // Note: RNG failure is extremely rare but we handle it by leaving zeros
        // which still produces a valid (though less random) UUID v7
        let rng = ring::rand::SystemRandom::new();
        if ring::rand::SecureRandom::fill(&rng, &mut bytes[6..]).is_err() {
            // Fallback: use timestamp bits repeated if RNG fails
            // This maintains time-ordering while providing some uniqueness
            bytes[6] = (millis & 0xff) as u8;
            bytes[7] = ((millis >> 8) & 0xff) as u8;
            bytes[9] = ((millis >> 16) & 0xff) as u8;
            bytes[10] = ((millis >> 24) & 0xff) as u8;
            bytes[11] = ((millis >> 32) & 0xff) as u8;
            bytes[12] = ((millis >> 40) & 0xff) as u8;
            // XOR with process ID for additional entropy
            let pid = std::process::id() as u64;
            bytes[13] = (pid & 0xff) as u8;
            bytes[14] = ((pid >> 8) & 0xff) as u8;
            bytes[15] = ((pid >> 16) & 0xff) as u8;
        }

        // Set version (7) in bits 48-51
        bytes[6] = (bytes[6] & 0x0f) | 0x70;

        // Set variant (RFC 4122) in bits 64-65
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        Self(bytes)
    }

    /// Creates a session ID from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parses a session ID from a string.
    ///
    /// Accepts formats:
    /// - With hyphens: `01234567-89ab-7cde-8f01-23456789abcd`
    /// - Without hyphens: `0123456789ab7cde8f0123456789abcd`
    pub fn parse(s: &str) -> Option<Self> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 32 {
            return None;
        }

        let mut bytes = [0u8; 16];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).ok()?;
            bytes[i] = u8::from_str_radix(hex_str, 16).ok()?;
        }

        Some(Self(bytes))
    }

    /// Extracts the timestamp from a UUID v7.
    ///
    /// Returns the Unix timestamp in milliseconds, or None if this
    /// doesn't appear to be a valid UUID v7.
    pub fn timestamp_millis(&self) -> Option<u64> {
        // Check version (should be 7)
        if (self.0[6] >> 4) != 7 {
            return None;
        }

        let millis = ((self.0[0] as u64) << 40)
            | ((self.0[1] as u64) << 32)
            | ((self.0[2] as u64) << 24)
            | ((self.0[3] as u64) << 16)
            | ((self.0[4] as u64) << 8)
            | (self.0[5] as u64);

        Some(millis)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format as UUID with hyphens: 8-4-4-4-12
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[4], self.0[5],
            self.0[6], self.0[7],
            self.0[8], self.0[9],
            self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15]
        )
    }
}

impl std::str::FromStr for SessionId {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| crate::Error::InvalidSpiffeUri(format!("invalid session ID: {}", s)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_v7_format() {
        let id = SessionId::new_v7();

        // Check version bits
        assert_eq!(id.0[6] >> 4, 7, "UUID version should be 7");

        // Check variant bits
        assert_eq!(id.0[8] >> 6, 2, "UUID variant should be RFC 4122");

        // Check timestamp is reasonable (within last minute)
        let ts = id.timestamp_millis().expect("should have timestamp");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(ts <= now, "timestamp should not be in future");
        assert!(ts > now - 60_000, "timestamp should be within last minute");
    }

    #[test]
    fn test_session_id_display_parse_roundtrip() {
        let id = SessionId::new_v7();
        let s = id.to_string();

        // Should be in UUID format
        assert_eq!(s.len(), 36);
        assert_eq!(&s[8..9], "-");
        assert_eq!(&s[13..14], "-");
        assert_eq!(&s[18..19], "-");
        assert_eq!(&s[23..24], "-");

        // Should round-trip
        let parsed = SessionId::parse(&s).expect("should parse");
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_session_id_parse_no_hyphens() {
        let id = SessionId::new_v7();
        let hex: String = id.0.iter().map(|b| format!("{:02x}", b)).collect();

        let parsed = SessionId::parse(&hex).expect("should parse without hyphens");
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_session_identity_spiffe_uri() {
        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session = SessionIdentity::new(parent, Duration::from_secs(3600));

        let uri = session.to_spiffe_uri();
        assert!(uri.starts_with("spiffe://nucleus.local/ns/agents/sa/claude/session/"));
        assert!(uri.len() > 60); // Base URI + session ID
    }

    #[test]
    fn test_session_identity_expiry() {
        let parent = Identity::new("nucleus.local", "agents", "claude");

        // Short TTL that's already expired
        let session = SessionIdentity {
            parent: parent.clone(),
            session_id: SessionId::new_v7(),
            created_at: Utc::now() - chrono::Duration::seconds(10),
            ttl: Duration::from_secs(5),
        };
        assert!(session.is_expired());
        assert!(session.remaining().is_none());

        // Long TTL that's still valid
        let session = SessionIdentity::new(parent, Duration::from_secs(3600));
        assert!(!session.is_expired());
        assert!(session.remaining().is_some());
        assert!(session.remaining().unwrap() > Duration::from_secs(3500));
    }

    #[test]
    fn test_session_identity_to_certificate_identity() {
        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));

        let cert_id = session.to_certificate_identity();
        assert_eq!(cert_id.trust_domain(), "nucleus.local");
        assert_eq!(cert_id.namespace(), "agents");
        assert!(cert_id.service_account().starts_with("claude-"));
        assert!(cert_id.service_account().len() > 40); // claude + hyphen + UUID
    }

    #[test]
    fn test_session_identity_display() {
        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session = SessionIdentity::new(parent, Duration::from_secs(3600));

        let display = format!("{}", session);
        assert!(display.starts_with("spiffe://nucleus.local/ns/agents/sa/claude/session/"));
    }

    #[test]
    fn test_session_id_uniqueness() {
        let id1 = SessionId::new_v7();
        let id2 = SessionId::new_v7();
        assert_ne!(id1, id2, "session IDs should be unique");
    }

    #[test]
    fn test_session_id_ordering() {
        // UUID v7 should be time-ordered
        let id1 = SessionId::new_v7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = SessionId::new_v7();

        let ts1 = id1.timestamp_millis().unwrap();
        let ts2 = id2.timestamp_millis().unwrap();
        assert!(ts2 >= ts1, "later UUID should have >= timestamp");
    }
}
