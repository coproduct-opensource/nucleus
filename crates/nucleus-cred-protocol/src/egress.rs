//! What a streamed host-performed call may say about its HTTP shape (#3210).
//!
//! # Why this is wire format and not a host detail
//!
//! A host-performed call used to be a POST, always: the open frame had no way
//! to say otherwise, so the host never had to decide. Smart-HTTP version
//! control needs a GET with a query (`info/refs?service=…`) before its POST,
//! so the method and the query now cross from the guest. Both are inside the
//! signed open frame, and both are bound into the host's effect digest, so an
//! approval granted for a GET cannot be spent on a POST.

use serde::{Deserialize, Serialize};

/// The version of [`crate::StreamRequest`] this crate writes and accepts.
///
/// Version 1 had no `version` field, no method (every call was a POST) and no
/// query. A node that read a version 1 frame as a version 2 one would have to
/// invent a method for it; refusing it by name instead tells the operator the
/// guest image is older than the node, which is the actual cause.
pub const OPEN_VERSION: u32 = 2;

/// The version a frame without a `version` field was written at.
const LEGACY_VERSION: u32 = 1;

/// The HTTP method of a host-performed call.
///
/// # Closed, and with no default (ADR 0007 B-3)
///
/// Not a string: a free-form method would let a guest ask for `DELETE` or
/// `PUT` and leave the host deciding what that means for a capability check.
/// Not defaulted: a frame that omits the method is refused, rather than read
/// as the POST every older frame meant, because "could not tell" is not "was
/// a POST" (A-1). Add a variant only with a
/// decision about which capability it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EgressMethod {
    /// A read with no request body: the host refuses a GET that uploaded one.
    Get,
    /// A request with a body.
    Post,
}

impl EgressMethod {
    /// The method's name on the wire, as HTTP spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }

    /// The method an HTTP request line named, if it is one a call may use.
    /// Case-sensitive, as HTTP methods are.
    #[must_use]
    pub fn from_http(name: &str) -> Option<Self> {
        match name {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            _ => None,
        }
    }

    /// Whether a request with this method carries a body upstream.
    #[must_use]
    pub const fn carries_body(self) -> bool {
        match self {
            Self::Get => false,
            Self::Post => true,
        }
    }
}

/// The least a host reads of a frame to tell an older stream open from a
/// malformed one.
///
/// Every stream open carries `nonce`, and no other ask does, so a frame with
/// a nonce and the wrong version is an old (or newer) GUEST, not garbage, and
/// is refused by [`VersionMismatch`]'s name instead of as malformed.
#[derive(Debug, Deserialize)]
pub struct OpenProbe {
    /// The frame's version; absent means version 1.
    #[serde(default = "legacy_version")]
    pub version: u32,
    /// Present on every stream open, and only there.
    #[serde(default)]
    pub nonce: Option<serde::de::IgnoredAny>,
}

fn legacy_version() -> u32 {
    LEGACY_VERSION
}

impl OpenProbe {
    /// The mismatch, when this is a stream open at a version this crate does
    /// not speak.
    #[must_use]
    pub fn mismatch(&self) -> Option<VersionMismatch> {
        (self.nonce.is_some() && self.version != OPEN_VERSION)
            .then_some(VersionMismatch { got: self.version })
    }
}

/// A stream open at a version this side does not speak, named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMismatch {
    /// The version the frame carried (1 for a frame with none).
    pub got: u32,
}

impl std::fmt::Display for VersionMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stream open frame version {} is not supported: this node speaks version {OPEN_VERSION}; \
             the guest image's tool-proxy is a different release than the node",
            self.got
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_is_closed_and_spelled_as_http_spells_it() {
        for method in [EgressMethod::Get, EgressMethod::Post] {
            let wire = serde_json::to_string(&method).unwrap();
            assert_eq!(wire, format!("\"{}\"", method.as_str()));
            assert_eq!(EgressMethod::from_http(method.as_str()), Some(method));
            assert_eq!(serde_json::from_str::<EgressMethod>(&wire).unwrap(), method);
        }
        for other in ["PUT", "DELETE", "PATCH", "get", "post", "", "CONNECT"] {
            assert_eq!(EgressMethod::from_http(other), None, "{other}");
            assert!(
                serde_json::from_str::<EgressMethod>(&format!("\"{other}\"")).is_err(),
                "{other}"
            );
        }
        assert!(!EgressMethod::Get.carries_body());
        assert!(EgressMethod::Post.carries_body());
    }

    #[test]
    fn an_older_stream_open_is_named_and_other_asks_are_not() {
        let probe = |json: &str| serde_json::from_str::<OpenProbe>(json).unwrap();
        let legacy = probe(r#"{"operation":"WebFetch","nonce":"n","path":"p"}"#);
        let mismatch = legacy.mismatch().expect("a version 1 stream open");
        assert_eq!(mismatch.got, 1);
        assert!(mismatch.to_string().contains("version 1 is not supported"));
        assert!(mismatch.to_string().contains("speaks version 2"));

        assert_eq!(
            probe(r#"{"version":3,"nonce":"n"}"#)
                .mismatch()
                .unwrap()
                .got,
            3
        );
        assert!(probe(r#"{"version":2,"nonce":"n"}"#).mismatch().is_none());
        // A query or perform frame carries no nonce: not a stream, not named.
        assert!(
            probe(r#"{"operation":"WebFetch","target":"t","justification":"j"}"#)
                .mismatch()
                .is_none()
        );
    }
}
