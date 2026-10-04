//! Binding a signed authority charge to its payer and recomputed payment.
use crate::{ClearingReceipt, content_hash_hex};

/// Versioned spend receipts carry this basis grammar on both sides of vsock.
pub const PREFIX: &str = "authority-round:";

/// The full payer is retained, including any colons in a SPIFFE identifier.
#[must_use]
pub fn basis(receipt: &ClearingReceipt, payer: &str) -> String {
    format!("{PREFIX}{}:{payer}", content_hash_hex(receipt))
}

/// Split a recognized basis into its content hash and payer. Empty or malformed
/// components are refused. The hash is canonical lowercase SHA-256 hex.
#[must_use]
pub fn parse(basis: &str) -> Option<(&str, &str)> {
    let (hash, payer) = basis.strip_prefix(PREFIX)?.split_once(':')?;
    (hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && !payer.is_empty())
    .then_some((hash, payer))
}

/// Check a payment against a clearing the caller has already recomputed.
#[must_use]
pub fn payment_matches(receipt: &ClearingReceipt, payer: &str, amount: u64) -> bool {
    match receipt {
        ClearingReceipt::Vcg(claim) => claim
            .clearing
            .winners
            .iter()
            .any(|winner| winner.bidder == payer && winner.vcg_payment_micro_usd == amount),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basis_keeps_the_full_payer_and_requires_a_canonical_hash() {
        let hash = "ab".repeat(32);
        let text = format!("{PREFIX}{hash}:spiffe://example.org/pod/peer:7");
        assert_eq!(
            parse(&text),
            Some((hash.as_str(), "spiffe://example.org/pod/peer:7"))
        );
        for text in [
            format!("{PREFIX}{hash}:"),
            format!("{PREFIX}{}:payer", hash.to_uppercase()),
            format!("{PREFIX}short:payer"),
            format!("wrong:{hash}:payer"),
        ] {
            assert_eq!(parse(&text), None, "{text}");
        }
    }
}
