//! The session root of a `nucleus-mcp` session (#3459): the instruction source
//! every tool call names as its control parent, content-addressed by the policy
//! the session was started under.

use anyhow::{Result, anyhow};
use portcullis::PermissionLattice;

/// The content identity of a session's policy: its SHA-256 checksum (which
/// covers the grant's validity window, so it names this grant), decoded from
/// the hex `PermissionLattice::checksum` returns. A checksum of any other shape
/// is refused rather than recorded as some other identity.
pub(crate) fn policy_content_hash(
    policy: &PermissionLattice,
) -> Result<portcullis_core::ContentHash> {
    let hex = policy.checksum();
    let mut digest = [0u8; 32];
    let pairs = hex.as_bytes().chunks_exact(2);
    if pairs.len() != digest.len() || !pairs.remainder().is_empty() {
        return Err(anyhow!(
            "policy checksum is not a SHA-256 hex digest: {hex}"
        ));
    }
    for (byte, pair) in digest.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair)
            .map_err(|e| anyhow!("policy checksum is not hex ({e}): {hex}"))?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|e| anyhow!("policy checksum is not hex ({e}): {hex}"))?;
    }
    Ok(portcullis_core::ContentHash::from_bytes(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_root_is_content_addressed_by_its_policy() {
        let policy = PermissionLattice::permissive();
        let a = policy_content_hash(&policy).unwrap();
        assert_eq!(
            a,
            policy_content_hash(&policy).unwrap(),
            "one grant, one identity"
        );
        let hex: String = a.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            policy.checksum(),
            "the identity is the policy's checksum"
        );
        let other = policy_content_hash(&PermissionLattice::read_only()).unwrap();
        assert_ne!(a, other, "different grants, different identities");
    }
}
