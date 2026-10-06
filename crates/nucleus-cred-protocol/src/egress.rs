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

mod effects;
pub use effects::{
    DeclaredEffect, EffectTable, EffectTableError, MAX_EFFECTS, MAX_PATTERN_SEGMENTS, UpstreamKind,
};

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
/// # Then the operator's table (#3229)
///
/// A call that is not a push is what the upstream's [`EffectTable`] declares
/// for its method and path: opening a pull request on a forge, say. A push is
/// a push whatever the table says, so no declaration can weaken it.
///
/// # And a write nothing classifies
///
/// Everything else, a fetch (`git-upload-pack`) included, is `WebFetch`: it
/// reads from the network, which is what that capability gates. Except a
/// write (a method that carries a body) to an upstream of kind
/// [`UpstreamKind::Forge`]: on a forge an unclassified write is an effect the
/// policy cannot name, so it is refused ([`Unclassified`]) rather than
/// decided as a fetch (ADR 0007 B).
///
/// # Errors
/// [`Unclassified`] for a write to a forge that no declared effect matches.
pub fn operation_for(
    table: &EffectTable,
    method: EgressMethod,
    path: &str,
    query: Option<&str>,
) -> Result<EgressOperation, Unclassified> {
    let names_push = |text: &str| decoded_lowercase(text).contains(RECEIVE_SERVICE);
    if names_push(path) || query.is_some_and(names_push) {
        return Ok(EgressOperation::GitPush);
    }
    if let Some(declared) = table.declared(method, path) {
        return Ok(declared);
    }
    match (table.kind(), method.carries_body()) {
        (UpstreamKind::Forge, true) => Err(Unclassified),
        (UpstreamKind::Forge, false) | (UpstreamKind::Api, _) => Ok(EgressOperation::WebFetch),
    }
}

/// A write to a forge upstream that no declared effect classifies: refused
/// on both sides, never decided as a fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unclassified;

impl std::fmt::Display for Unclassified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "a write to a forge upstream that no declared effect classifies is refused; \
             the operator's registry must declare it",
        )
    }
}

impl std::error::Error for Unclassified {}

/// The policy operations a host-performed call can be. A closed set, so a
/// caller maps it onto its own operation type with an exhaustive `match`
/// rather than by parsing a string back. An operator's declared effect names
/// one in `snake_case`, as a profile names the capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressOperation {
    /// A network read: `web_fetch`.
    WebFetch,
    /// A push to a version-control remote: `git_push`, as well as `web_fetch`.
    GitPush,
    /// Opening a pull request on a forge: `create_pr`, as well as
    /// `web_fetch` (#3229).
    CreatePr,
}

impl EgressOperation {
    /// The label a stream open carries, as the policy layer names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WebFetch => "WebFetch",
            Self::GitPush => "GitPush",
            Self::CreatePr => "CreatePr",
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

    fn classify(
        method: EgressMethod,
        path: &str,
        query: Option<&str>,
    ) -> Result<EgressOperation, Unclassified> {
        operation_for(&EffectTable::unclassified(), method, path, query)
    }

    fn forge() -> EffectTable {
        let effect = |method, path: &str, operation| DeclaredEffect {
            method,
            path: path.into(),
            operation,
        };
        EffectTable::from_parts(
            Some(UpstreamKind::Forge),
            vec![
                effect(
                    EgressMethod::Post,
                    "/repos/*/*/pulls",
                    EgressOperation::CreatePr,
                ),
                effect(EgressMethod::Post, "/graphql", EgressOperation::WebFetch),
                effect(
                    EgressMethod::Post,
                    "*/*/git-upload-pack",
                    EgressOperation::WebFetch,
                ),
            ],
        )
        .expect("a valid table")
    }

    /// **A forge's declared effects classify its writes, and an unclassified
    /// write is refused.** The pull-request route is `CreatePr` however it is
    /// spelled; a declared read stays a read; a GET is a read; a push is a
    /// push even where a declaration would call it a fetch; and a write no
    /// effect names is `Unclassified`. The same calls to an `api` upstream
    /// with no table are all `WebFetch` (or `GitPush`), as before #3229.
    #[test]
    fn a_forge_write_is_what_the_operator_declared_or_refused() {
        use EgressMethod::{Get, Post};
        use EgressOperation::{CreatePr, GitPush, WebFetch};
        let table = forge();
        for (method, path, expected) in [
            (Post, "repos/org/repo/pulls", Ok(CreatePr)),
            (Post, "/repos/org/repo/pulls/", Ok(CreatePr)),
            (Post, "repos//org/repo/pulls", Ok(CreatePr)),
            (Post, "REPOS/org/repo/PULLS", Ok(CreatePr)),
            (Post, "repos/org/repo/pull%73", Ok(CreatePr)),
            (Post, "repos/org/repo/pull%2573", Ok(CreatePr)),
            (Post, "graphql", Ok(WebFetch)),
            (Post, "org/repo.git/git-upload-pack", Ok(WebFetch)),
            (Post, "org/repo.git/git-receive-pack", Ok(GitPush)),
            (Get, "repos/org/repo/pulls", Ok(WebFetch)),
            (Get, "repos/org/repo", Ok(WebFetch)),
            (Post, "repos/org/repo/issues", Err(Unclassified)),
            (Post, "repos/org/repo/pulls/1/merge", Err(Unclassified)),
            (Post, "repos/org/pulls", Err(Unclassified)),
            (Post, "repos/org/repo%2Fx/pulls", Err(Unclassified)),
        ] {
            assert_eq!(
                operation_for(&table, method, path, None),
                expected,
                "{method:?} {path}"
            );
        }
        assert_eq!(
            classify(Post, "repos/org/repo/pulls", None),
            Ok(WebFetch),
            "an api upstream with no table is decided as before"
        );
        assert_eq!(classify(Post, "repos/org/repo/issues", None), Ok(WebFetch));
    }

    /// A table is validated wherever it is built, deserialisation included:
    /// a pattern that is not one, or two effects that could disagree about a
    /// request, are refused; the operator's wire form round-trips; and an
    /// absent kind is an `api`.
    #[test]
    fn an_effect_table_is_valid_or_refused() {
        let one = |path: &str| DeclaredEffect {
            method: EgressMethod::Post,
            path: path.into(),
            operation: EgressOperation::CreatePr,
        };
        for bad in ["", "/", "repos/*x/pulls", "a/%2e/b", "a/../b", "a?b", "a#b"] {
            assert_eq!(
                EffectTable::from_parts(None, vec![one(bad)]),
                Err(EffectTableError::BadPattern(bad.into())),
                "{bad:?}"
            );
        }
        let mut read = one("repos/org/*/pulls");
        read.operation = EgressOperation::WebFetch;
        assert!(matches!(
            EffectTable::from_parts(None, vec![one("repos/*/*/pulls"), read.clone()]),
            Err(EffectTableError::Ambiguous(..))
        ));
        read.method = EgressMethod::Get;
        let table = EffectTable::from_parts(None, vec![one("repos/*/*/pulls"), read]).unwrap();
        assert_eq!(table.kind(), UpstreamKind::Api);
        assert!(!table.is_unclassified());
        assert!(
            EffectTable::from_parts(None, Vec::new())
                .unwrap()
                .is_unclassified()
        );
        assert!(matches!(
            EffectTable::from_parts(None, vec![one("a"); MAX_EFFECTS + 1]),
            Err(EffectTableError::TooMany(_))
        ));

        let wire = serde_json::to_string(&forge()).unwrap();
        assert!(wire.contains("\"kind\":\"forge\""), "{wire}");
        assert!(wire.contains("\"operation\":\"create_pr\""), "{wire}");
        assert_eq!(serde_json::from_str::<EffectTable>(&wire).unwrap(), forge());
        let ambiguous = r#"{"kind":"forge","effects":[
            {"method":"POST","path":"a/*","operation":"create_pr"},
            {"method":"POST","path":"*/b","operation":"web_fetch"}]}"#;
        assert!(serde_json::from_str::<EffectTable>(ambiguous).is_err());
        let unknown_operation = r#"{"kind":"forge","effects":[
            {"method":"POST","path":"a","operation":"delete_repo"}]}"#;
        assert!(serde_json::from_str::<EffectTable>(unknown_operation).is_err());
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
            for table in [EffectTable::unclassified(), forge()] {
                assert_eq!(
                    operation_for(&table, method, path, query),
                    Ok(EgressOperation::GitPush),
                    "{method:?} {path} {query:?}"
                );
            }
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
                classify(method, path, query),
                Ok(EgressOperation::WebFetch),
                "{method:?} {path} {query:?}"
            );
        }
    }
}
