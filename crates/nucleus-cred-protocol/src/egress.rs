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
}
