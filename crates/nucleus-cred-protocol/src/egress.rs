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
//!
//! # One classifier, both sides
//!
//! [`operation_for`] decides which policy operation a call is. The guest's
//! tool-proxy labels the frame with it and gates it under its own kernel; the
//! host recomputes it from the same three inputs and refuses a frame whose
//! label disagrees. Written once, here, so the two cannot drift (ADR 0007
//! G-1): a push the guest called a fetch is refused by the host, not
//! performed under the weaker capability.

use serde::{Deserialize, Serialize};

/// The HTTP method of a host-performed call.
///
/// # Closed, and with no default (ADR 0007 B-3)
///
/// Not a string: a free-form method would let a guest ask for `DELETE` or
/// `PUT` and leave the host deciding what that means for a capability check.
/// Not defaulted: a frame that omits the method is refused, rather than read
/// as the POST every older frame meant, because "could not tell" is not "was
/// a POST" (A-1). Add a variant only with the operation [`operation_for`]
/// maps it to.
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

/// The policy operation a call is, from what it does rather than what the
/// guest calls it.
///
/// # A push is a write, whichever method carries it
///
/// Smart HTTP names the push service in the path (`…/git-receive-pack`) for
/// the POST that carries the pack, and in the query (`service=git-receive-pack`)
/// for the GET that advertises refs. Either one is a push: the advertisement
/// is the first half of the same effect, and refusing only the POST would let
/// a profile without push learn the remote's refs through a capability check
/// it was meant to fail. So any appearance of the receive service, in the
/// path or the query, after percent-decoding and ignoring case, is
/// `GitPush`. A false positive costs a stricter check; a false negative would
/// send a write under the read capability.
///
/// Everything else, a fetch (`git-upload-pack`) included, is `WebFetch`: it
/// reads from the network, which is what that capability gates.
#[must_use]
pub fn operation_for(method: EgressMethod, path: &str, query: Option<&str>) -> EgressOperation {
    // The method does not change the answer today; it is an input so a
    // variant added later has to be considered here (E-1 by signature).
    let (EgressMethod::Get | EgressMethod::Post) = method;
    let names_push = |text: &str| decoded_lowercase(text).contains(RECEIVE_SERVICE);
    if names_push(path) || query.is_some_and(names_push) {
        EgressOperation::GitPush
    } else {
        EgressOperation::WebFetch
    }
}

/// The policy operations a host-performed call can be. A closed set, so a
/// caller maps it onto its own operation type with an exhaustive `match`
/// rather than by parsing a string back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EgressOperation {
    /// A network read: `web_fetch`.
    WebFetch,
    /// A push to a version-control remote: `git_push`, as well as `web_fetch`.
    GitPush,
}

impl EgressOperation {
    /// The label a stream open carries, as the policy layer names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WebFetch => "WebFetch",
            Self::GitPush => "GitPush",
        }
    }
}

/// The smart-HTTP push service, without its `git-` prefix so a path that
/// spells it differently (`receive-pack` under another prefix) still matches.
const RECEIVE_SERVICE: &str = "receive-pack";

/// `text` with percent-escapes decoded until none remain (bounded), lowercased.
///
/// Decoded repeatedly because a double-encoded escape (`%252d`) is decoded
/// once by each layer it passes, and the classifier must see what the last
/// layer sees. Bounded, because each pass shortens the text or stops.
fn decoded_lowercase(text: &str) -> String {
    let mut current = text.to_ascii_lowercase();
    for _ in 0..4 {
        let next = percent_decode_once(&current).to_ascii_lowercase();
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// One pass of `%XX` decoding. A malformed escape is kept verbatim; a decoded
/// byte that is not ASCII is dropped, because no service name contains one.
fn percent_decode_once(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let escape = (b == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escape {
            Some(decoded) => {
                if decoded.is_ascii() {
                    out.push(char::from(decoded));
                }
                i += 3;
            }
            None => {
                out.push(char::from(b));
                i += 1;
            }
        }
    }
    out
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

    /// Both halves of a push are a push; a fetch is a read. The evasions are
    /// the cases a substring check on the raw text would miss.
    #[test]
    fn a_push_is_classified_by_what_it_does() {
        use EgressMethod::{Get, Post};
        let push = [
            (Post, "org/repo.git/git-receive-pack", None),
            (
                Get,
                "org/repo.git/info/refs",
                Some("service=git-receive-pack"),
            ),
            (Post, "org/repo.git/GIT-RECEIVE-PACK", None),
            (Post, "org/repo.git/git%2dreceive%2Dpack", None),
            (Post, "org/repo.git/git%252dreceive-pack", None),
            (
                Get,
                "org/repo.git/info/refs",
                Some("service=git%2Dreceive-pack"),
            ),
            (
                Get,
                "org/repo.git/info/refs",
                Some("service=git-upload-pack&service=git-receive-pack"),
            ),
        ];
        for (method, path, query) in push {
            assert_eq!(
                operation_for(method, path, query),
                EgressOperation::GitPush,
                "{method:?} {path} {query:?}"
            );
        }
        let read = [
            (
                Get,
                "org/repo.git/info/refs",
                Some("service=git-upload-pack"),
            ),
            (Post, "org/repo.git/git-upload-pack", None),
            (Post, "v1/complete", None),
            (Get, "v1/models", None),
            (Get, "a%zz", Some("%")),
        ];
        for (method, path, query) in read {
            assert_eq!(
                operation_for(method, path, query),
                EgressOperation::WebFetch,
                "{method:?} {path} {query:?}"
            );
        }
    }
}
