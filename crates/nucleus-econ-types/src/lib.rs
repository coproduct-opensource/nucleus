//! Financially load-bearing newtypes for the Nucleus economic surface.
//!
//! # Why this crate exists
//!
//! The paragon audit flagged *primitive obsession* on the money/ID
//! surface: 66 bare-`u64` `*_micro_usd` fields and bare-`String` ids
//! threaded positionally (e.g. `BidBuilder::new(auction_id,
//! agent_spiffe_id)` — two `String` args that silently swap). Bare
//! primitives carry no unit and no identity, so the type system cannot
//! catch a dollars-for-cents mixup or a swapped id pair.
//!
//! This crate introduces:
//!
//! - [`MicroUsd`] — a `u64` micro-USD amount with *checked* and
//!   *saturating* arithmetic, `From<u64>` available **only at trusted
//!   boundaries** (deserialization, explicit construction), and no
//!   bare `+`/`-` operators that would silently bypass overflow
//!   handling.
//! - [`AuctionId`], [`AgentId`], [`ProposalId`] — `String` newtypes
//!   that cannot be positionally swapped because they are distinct
//!   types.
//!
//! # Wire compatibility is non-negotiable
//!
//! Every type here is `#[serde(transparent)]`, so the JSON / wire
//! encoding is **byte-identical** to the underlying primitive. A
//! `MicroUsd(2_000_000)` serializes as the bare integer `2000000`; an
//! `AuctionId("a1")` serializes as the bare string `"a1"`. This is
//! what lets us thread the newtypes through structs without breaking
//! the Lean-parity proptests, signed receipts, or HTTP contracts.

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// An integer micro-USD (1e-6 USD) amount.
///
/// Micro-USD is the canonical money unit across the Nucleus economic
/// kernels — see `docs/ECON-PRECISION.md`. The float ban in
/// `nucleus-econ-kernels` exists precisely so payments stay exact; this
/// newtype carries that discipline into the *type system* so an amount
/// can't be silently mixed with an unrelated `u64` (a count, a
/// timestamp, a depth) or mutated with un-checked arithmetic.
///
/// # Construction
///
/// `From<u64>` is implemented so callers at trusted boundaries
/// (deserialization, config parsing, an explicit "this u64 is dollars"
/// site) can lift a raw amount. Internal arithmetic must go through
/// [`MicroUsd::checked_add`] / [`MicroUsd::saturating_add`] / etc., not
/// the bare operators, which are deliberately **not** implemented.
///
/// # Serde
///
/// `#[serde(transparent)]` — the wire shape is the bare integer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct MicroUsd(u64);

impl MicroUsd {
    /// Zero micro-USD.
    pub const ZERO: MicroUsd = MicroUsd(0);

    /// The maximum representable amount.
    pub const MAX: MicroUsd = MicroUsd(u64::MAX);

    /// Construct from a raw `u64` micro-USD amount.
    ///
    /// `const` so it can be used in constant contexts (e.g. test
    /// fixtures, ceiling constants). This is a *trusted boundary*
    /// constructor — use it where you are asserting "this `u64` is a
    /// micro-USD amount", not as a way to escape checked arithmetic.
    #[inline]
    pub const fn new(micros: u64) -> Self {
        MicroUsd(micros)
    }

    /// The underlying `u64` micro-USD amount.
    ///
    /// Use at the boundary where you must hand the amount to code that
    /// genuinely needs the raw integer (a Lean-parity math primitive, a
    /// proto field, a `u128` welfare accumulator). Inside the kernel,
    /// prefer the checked/saturating combinators below.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The amount as `u128`, for overflow-free intermediate accumulation
    /// (welfare sums, cross-product ratio comparisons).
    #[inline]
    pub const fn as_u128(self) -> u128 {
        self.0 as u128
    }

    /// Checked addition. `None` on `u64` overflow.
    #[inline]
    pub fn checked_add(self, rhs: MicroUsd) -> Option<MicroUsd> {
        self.0.checked_add(rhs.0).map(MicroUsd)
    }

    /// Checked subtraction. `None` if `rhs > self`.
    #[inline]
    pub fn checked_sub(self, rhs: MicroUsd) -> Option<MicroUsd> {
        self.0.checked_sub(rhs.0).map(MicroUsd)
    }

    /// Saturating addition — clamps at [`MicroUsd::MAX`]. Use where the
    /// kernel already saturates welfare/payment sums (see
    /// `docs/ECON-PRECISION.md` §6).
    #[inline]
    pub const fn saturating_add(self, rhs: MicroUsd) -> MicroUsd {
        MicroUsd(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction — clamps at [`MicroUsd::ZERO`]. This is
    /// the kernel's payment-floor discipline (`max(0, …)`): VCG
    /// payments and `budget_remaining` are saturating-sub by design so
    /// they can never go negative.
    #[inline]
    pub const fn saturating_sub(self, rhs: MicroUsd) -> MicroUsd {
        MicroUsd(self.0.saturating_sub(rhs.0))
    }

    /// Saturating conversion from a `u128` accumulator back to a
    /// `MicroUsd` — clamps at [`MicroUsd::MAX`]. Mirrors the kernel's
    /// `u128_to_u64_saturating` so welfare sums land back in the
    /// money type without an unchecked `as` cast.
    #[inline]
    pub const fn saturating_from_u128(v: u128) -> MicroUsd {
        if v > u64::MAX as u128 {
            MicroUsd::MAX
        } else {
            MicroUsd(v as u64)
        }
    }
}

impl From<u64> for MicroUsd {
    #[inline]
    fn from(micros: u64) -> Self {
        MicroUsd(micros)
    }
}

impl From<MicroUsd> for u64 {
    #[inline]
    fn from(m: MicroUsd) -> Self {
        m.0
    }
}

impl From<MicroUsd> for u128 {
    #[inline]
    fn from(m: MicroUsd) -> Self {
        m.0 as u128
    }
}

impl fmt::Display for MicroUsd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bare micro-USD digits — matches the canonical attribute
        // encoding used by the macaroon caveat layer (`.to_string()` /
        // `.parse()` round-trip).
        write!(f, "{}", self.0)
    }
}

impl FromStr for MicroUsd {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u64>().map(MicroUsd)
    }
}

/// Declare a transparent `String` newtype id with the full ergonomic
/// surface (Display, FromStr, From<String>/<&str>, AsRef<str>, serde
/// transparent). The point is to make two ids of *different* kinds
/// non-interchangeable so they can't be positionally swapped.
macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct from anything string-like. Trusted boundary
            /// constructor — once built, the type prevents swapping it
            /// for an id of a different kind.
            #[inline]
            pub fn new(s: impl Into<String>) -> Self {
                $name(s.into())
            }

            /// Borrow as `&str`.
            #[inline]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the underlying `String`.
            #[inline]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl From<String> for $name {
            #[inline]
            fn from(s: String) -> Self {
                $name(s)
            }
        }

        impl From<&str> for $name {
            #[inline]
            fn from(s: &str) -> Self {
                $name(s.to_owned())
            }
        }

        impl From<&String> for $name {
            #[inline]
            fn from(s: &String) -> Self {
                $name(s.clone())
            }
        }

        impl From<$name> for String {
            #[inline]
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl AsRef<str> for $name {
            #[inline]
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::borrow::Borrow<str> for $name {
            #[inline]
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl std::ops::Deref for $name {
            type Target = str;
            #[inline]
            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl ::std::str::FromStr for $name {
            // String ids are infallible to parse; we keep a FromStr
            // impl for symmetry with `Display` so wire round-trips and
            // generic `.parse()` call sites Just Work.
            type Err = ::std::convert::Infallible;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok($name(s.to_owned()))
            }
        }
    };
}

string_id! {
    /// Identity of an auction. Distinct type from [`AgentId`] /
    /// [`ProposalId`] so the two-`String` constructor swap the audit
    /// flagged (`BidBuilder::new(auction_id, agent_spiffe_id)`) is now
    /// a compile error rather than a silent logic bug.
    AuctionId
}

string_id! {
    /// SPIFFE-style identity of an agent / bidder.
    AgentId
}

string_id! {
    /// Identity of a proposal a bid is placed against.
    ProposalId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_usd_serializes_as_bare_integer() {
        let m = MicroUsd::new(2_000_000);
        assert_eq!(serde_json::to_string(&m).unwrap(), "2000000");
        let back: MicroUsd = serde_json::from_str("2000000").unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn micro_usd_round_trips_inside_a_struct_byte_identically() {
        // A struct that previously had a bare-u64 field must serialize
        // identically once the field becomes MicroUsd.
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Bare {
            cost_micro_usd: u64,
        }
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Typed {
            cost_micro_usd: MicroUsd,
        }
        let bare = Bare {
            cost_micro_usd: 1_500_000,
        };
        let typed = Typed {
            cost_micro_usd: MicroUsd::new(1_500_000),
        };
        assert_eq!(
            serde_json::to_string(&bare).unwrap(),
            serde_json::to_string(&typed).unwrap()
        );
    }

    #[test]
    fn checked_add_detects_overflow() {
        assert_eq!(
            MicroUsd::new(10).checked_add(MicroUsd::new(5)),
            Some(MicroUsd::new(15))
        );
        assert_eq!(MicroUsd::MAX.checked_add(MicroUsd::new(1)), None);
    }

    #[test]
    fn checked_sub_detects_underflow() {
        assert_eq!(
            MicroUsd::new(10).checked_sub(MicroUsd::new(3)),
            Some(MicroUsd::new(7))
        );
        assert_eq!(MicroUsd::new(3).checked_sub(MicroUsd::new(10)), None);
    }

    #[test]
    fn saturating_ops_clamp() {
        assert_eq!(
            MicroUsd::MAX.saturating_add(MicroUsd::new(99)),
            MicroUsd::MAX
        );
        assert_eq!(
            MicroUsd::new(3).saturating_sub(MicroUsd::new(10)),
            MicroUsd::ZERO
        );
    }

    #[test]
    fn saturating_from_u128_clamps_at_max() {
        assert_eq!(MicroUsd::saturating_from_u128(42), MicroUsd::new(42));
        assert_eq!(MicroUsd::saturating_from_u128(u128::MAX), MicroUsd::MAX);
    }

    #[test]
    fn micro_usd_display_and_fromstr_round_trip() {
        let m = MicroUsd::new(9_999);
        assert_eq!(m.to_string(), "9999");
        assert_eq!("9999".parse::<MicroUsd>().unwrap(), m);
    }

    #[test]
    fn ids_serialize_as_bare_strings() {
        let a = AuctionId::new("a1");
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"a1\"");
        let back: AuctionId = serde_json::from_str("\"a1\"").unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn distinct_id_types_do_not_unify() {
        // This is a compile-time property; the test documents intent.
        // `let _: AuctionId = AgentId::new("x");` would not compile.
        let auction = AuctionId::new("a1");
        let agent = AgentId::new("spiffe://x");
        assert_eq!(auction.as_str(), "a1");
        assert_eq!(agent.as_str(), "spiffe://x");
    }

    #[test]
    fn id_display_fromstr_asref() {
        let p = ProposalId::new("p1");
        assert_eq!(p.to_string(), "p1");
        assert_eq!("p1".parse::<ProposalId>().unwrap(), p);
        assert_eq!(p.as_ref(), "p1");
    }
}
