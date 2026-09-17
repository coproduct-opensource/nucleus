//! The length prefix of a canonical, signed byte string.
//!
//! Every `canonical_*_bytes` here is domain-tagged and length-prefixed so that the signature
//! commits to an unambiguous parse. A prefix written with `len as u32` breaks exactly that: two
//! inputs whose lengths differ by 2^32 produce the same prefix, so the same signed bytes stand
//! for both. The cast never fires in practice — nothing here is four gigabytes — but "never in
//! practice" is not a property, and the ratcheted cast lints exist to say so.
//!
//! Refusing is the safe direction: a claim that cannot be prefixed unambiguously is one this
//! crate must not sign, and the caller has no error path to take instead.

/// The big-endian `u32` length prefix for `n`.
///
/// # Panics
///
/// When `n` does not fit in a `u32`. Signing ambiguous bytes is the alternative.
#[must_use]
pub(crate) fn be_len(n: usize) -> [u8; 4] {
    u32::try_from(n)
        .expect("a canonical length prefix must fit u32; signing a truncated one would make two inputs share their signed bytes")
        .to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::be_len;

    #[test]
    fn a_prefix_is_the_length_itself_big_endian() {
        assert_eq!(be_len(0), [0, 0, 0, 0]);
        assert_eq!(be_len(1), [0, 0, 0, 1]);
        assert_eq!(be_len(0xdead_beef), [0xde, 0xad, 0xbe, 0xef]);
    }

    /// The case the cast used to swallow: 2^32 and 0 would have shared a prefix.
    #[test]
    #[should_panic(expected = "must fit u32")]
    #[cfg(target_pointer_width = "64")]
    fn a_length_that_does_not_fit_is_refused_rather_than_truncated() {
        let _ = be_len(usize::try_from(u64::from(u32::MAX) + 1).unwrap());
    }
}
