//! Which refs a push may update: the operator's ref patterns, checked against
//! the receive-pack request's own command list before any byte goes upstream.
//!
//! # Why the body, and not the path
//!
//! [`super::operation_for`] decides that a call IS a push from its path
//! (`…/git-receive-pack`). It cannot say WHAT the push does: which refs it
//! creates, moves or deletes is written in the request body, as the
//! pkt-line command list that precedes the pack (gitprotocol-pack(5),
//! "Reference Update Request and Packfile Transfer"):
//!
//! ```text
//! <len><old-oid> SP <new-oid> SP <refname> NUL <capabilities> LF
//! <len><old-oid> SP <new-oid> SP <refname> LF
//! …
//! 0000
//! <pack, unless every command is a deletion>
//! ```
//!
//! So a grant of "push to this repository" without this check is a grant to
//! update every ref the credential can reach, `main` and tags included. With
//! it, a push whose command list names any ref outside the patterns is
//! refused whole, before the credential is fetched and before any upstream
//! I/O.
//!
//! # Refused, not filtered
//!
//! The whole push is refused when any one command is outside the patterns.
//! Dropping the offending command and forwarding the rest would change what
//! the guest asked for (an `atomic` push would no longer be the transaction
//! its author wrote), and rewriting the body would make the host an author of
//! the effect rather than its judge.
//!
//! # What else is refused
//!
//! Anything this parser cannot read exactly: a malformed length, a command
//! that is not `<oid> SP <oid> SP <refname>`, a refname git itself would
//! refuse, mixed object-id lengths, a body without the flush that ends the
//! command list, or more than [`MAX_COMMANDS`] commands. A signed push
//! (`push-cert`) and push options (`push-options`) are refused: both carry
//! data to the remote's hooks that the ref check does not see, and nothing in
//! the Studio flow uses them. A capability outside [`KNOWN_CAPABILITIES`] is
//! refused, because the parser cannot say it leaves the command list's
//! meaning alone. `atomic` and `report-status` are accepted: they change how
//! the remote applies and reports the commands, never which refs they name,
//! and every named ref has already matched.
//!
//! A `shallow <oid>` line before the commands (a push from a shallow clone)
//! is accepted: it tells the remote where the client's history is cut, and
//! names no ref.
//!
//! # Patterns
//!
//! A pattern is a full refname whose `/`-separated segments are literals,
//! `*` (exactly one non-empty segment) or, as the LAST segment only, `**`
//! (one or more segments). `refs/heads/studio/**` therefore matches
//! `refs/heads/studio/a` and `refs/heads/studio/a/b`, and not
//! `refs/heads/studio` or `refs/heads/studio-x`. These are the same
//! meanings GitHub gives `*` and `**` in a ruleset's ref patterns, so the
//! broker's rule and the forge's rule can be written with one string.

use serde::{Deserialize, Serialize};

/// The most commands one push may carry. Far above a Studio push (one or two
/// branches); a bound so a hostile body cannot make the host parse forever.
pub const MAX_COMMANDS: usize = 1024;

/// The most body bytes the host reads to find the command list. A command
/// list longer than this is refused as having no flush: 1 MiB holds
/// [`MAX_COMMANDS`] commands with long refnames many times over.
pub const MAX_COMMAND_LIST_BYTES: usize = 1 << 20;

/// The most patterns one upstream may declare.
pub const MAX_PUSH_REF_PATTERNS: usize = 32;

/// The capabilities a push may request, by name (the part before any `=`).
///
/// Each either shapes the remote's reply (`report-status`, `report-status-v2`,
/// `side-band`, `side-band-64k`, `quiet`), describes the pack (`ofs-delta`,
/// `object-format`), identifies the client (`agent`, `session-id`), lets a
/// command delete (`delete-refs`: the deleted ref is still checked) or asks
/// for all-or-nothing application (`atomic`). None of them changes which refs
/// the commands name.
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "report-status",
    "report-status-v2",
    "side-band",
    "side-band-64k",
    "quiet",
    "ofs-delta",
    "object-format",
    "agent",
    "session-id",
    "delete-refs",
    "atomic",
];

/// One validated ref pattern. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RefPattern(String);

impl TryFrom<String> for RefPattern {
    type Error = PushRefsError;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        let segments: Vec<&str> = text.split('/').collect();
        let valid = segments.len() >= 2
            && segments[0] == "refs"
            && segments.iter().enumerate().all(|(i, segment)| match *segment {
                "*" => true,
                "**" => i + 1 == segments.len(),
                literal => valid_ref_component(literal),
            });
        if valid {
            Ok(Self(text))
        } else {
            Err(PushRefsError::BadPattern(text))
        }
    }
}

impl From<RefPattern> for String {
    fn from(pattern: RefPattern) -> Self {
        pattern.0
    }
}

impl RefPattern {
    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `refname` matches. Both are already valid, so this is a plain
    /// segment comparison: case-sensitive, as refnames are.
    #[must_use]
    pub fn matches(&self, refname: &str) -> bool {
        let pattern: Vec<&str> = self.0.split('/').collect();
        let name: Vec<&str> = refname.split('/').collect();
        match pattern.split_last() {
            Some((&"**", head)) => {
                name.len() > head.len() && segments_match(head, &name[..head.len()])
            }
            _ => pattern.len() == name.len() && segments_match(&pattern, &name),
        }
    }
}

fn segments_match(pattern: &[&str], name: &[&str]) -> bool {
    pattern
        .iter()
        .zip(name)
        .all(|(p, n)| *p == "*" || p == n)
}

/// Why a pattern list was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRefsError {
    /// Not a pattern: see the module docs.
    BadPattern(String),
    /// More than [`MAX_PUSH_REF_PATTERNS`].
    TooMany(usize),
}

impl std::fmt::Display for PushRefsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPattern(p) => write!(
                f,
                "push ref pattern {p:?} is not a pattern: it starts `refs/`, and its segments \
                 are valid ref components, `*`, or a final `**`"
            ),
            Self::TooMany(n) => write!(
                f,
                "{n} push ref patterns declared, above the {MAX_PUSH_REF_PATTERNS} allowed"
            ),
        }
    }
}

impl std::error::Error for PushRefsError {}

/// Validate an upstream's declared push ref patterns.
///
/// # Errors
/// See [`PushRefsError`].
pub fn parse_patterns(texts: Vec<String>) -> Result<Vec<RefPattern>, PushRefsError> {
    if texts.len() > MAX_PUSH_REF_PATTERNS {
        return Err(PushRefsError::TooMany(texts.len()));
    }
    texts.into_iter().map(RefPattern::try_from).collect()
}

/// One command of a push: `old` to `new` on `refname`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefUpdate {
    /// The object id the client believes the ref holds (all zeros: create).
    pub old: String,
    /// The object id the ref is to hold (all zeros: delete).
    pub new: String,
    /// The full refname.
    pub refname: String,
}

impl RefUpdate {
    /// Whether this command deletes the ref.
    #[must_use]
    pub fn is_delete(&self) -> bool {
        self.new.bytes().all(|b| b == b'0')
    }
}

/// Why a push's command list was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushRefusal {
    /// The body is not a command list this parser reads exactly.
    Malformed(&'static str),
    /// A capability that may change what the push does, or one not known.
    Capability(String),
    /// A ref outside every pattern. The whole push is refused.
    RefOutsideGrant(String),
}

impl std::fmt::Display for PushRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "push refused: malformed command list ({why})"),
            Self::Capability(name) => write!(f, "push refused: capability {name:?} is not allowed"),
            Self::RefOutsideGrant(refname) => write!(
                f,
                "push refused: ref {refname:?} is outside this upstream's push ref patterns; \
                 the whole push was refused and nothing was sent upstream"
            ),
        }
    }
}

impl std::error::Error for PushRefusal {}

/// Parse a receive-pack request body's command list.
///
/// Reads up to and including the flush that ends the commands; the pack
/// after it is not read. Returns the commands in order.
///
/// # Errors
/// See [`PushRefusal`]: every byte before the flush must parse.
pub fn commands(body: &[u8]) -> Result<Vec<RefUpdate>, PushRefusal> {
    let mut at = 0usize;
    let mut out: Vec<RefUpdate> = Vec::new();
    let mut oid_len: Option<usize> = None;
    let mut seen_command = false;
    loop {
        let Some(payload) = next_pkt(body, &mut at)? else {
            // The flush that ends the command list.
            break;
        };
        let line = payload.strip_suffix(b"\n").unwrap_or(payload);
        if !seen_command && line.starts_with(b"shallow ") {
            let oid = &line[b"shallow ".len()..];
            check_oid(oid, &mut oid_len)?;
            continue;
        }
        if line.starts_with(b"push-cert") {
            return Err(PushRefusal::Capability("push-cert".to_string()));
        }
        let (command, capabilities) = match line.iter().position(|&b| b == 0) {
            Some(nul) if !seen_command => (&line[..nul], Some(&line[nul + 1..])),
            Some(_) => return Err(PushRefusal::Malformed("capabilities after the first command")),
            None => (line, None),
        };
        if let Some(capabilities) = capabilities {
            check_capabilities(capabilities)?;
        } else if !seen_command {
            // Git always writes a capability list on the first command, even
            // an empty one after the NUL. A first command without the NUL is
            // not what any client sends.
            return Err(PushRefusal::Malformed("first command carries no capability list"));
        }
        seen_command = true;
        let mut fields = command.split(|&b| b == b' ');
        let (Some(old), Some(new), Some(refname), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(PushRefusal::Malformed("a command is not <old> <new> <refname>"));
        };
        check_oid(old, &mut oid_len)?;
        check_oid(new, &mut oid_len)?;
        let refname = std::str::from_utf8(refname)
            .ok()
            .filter(|r| valid_refname(r))
            .ok_or(PushRefusal::Malformed("a refname git would refuse"))?;
        if out.len() == MAX_COMMANDS {
            return Err(PushRefusal::Malformed("too many commands"));
        }
        out.push(RefUpdate {
            old: String::from_utf8_lossy(old).into_owned(),
            new: String::from_utf8_lossy(new).into_owned(),
            refname: refname.to_string(),
        });
    }
    if out.is_empty() {
        return Err(PushRefusal::Malformed("no commands"));
    }
    Ok(out)
}

/// Check a push body against `patterns`: every command's ref must match one.
///
/// # Errors
/// The parse's own refusal, or [`PushRefusal::RefOutsideGrant`] naming the
/// first ref no pattern matches.
pub fn check(patterns: &[RefPattern], body: &[u8]) -> Result<Vec<RefUpdate>, PushRefusal> {
    let updates = commands(body)?;
    if let Some(outside) = updates
        .iter()
        .find(|u| !patterns.iter().any(|p| p.matches(&u.refname)))
    {
        return Err(PushRefusal::RefOutsideGrant(outside.refname.clone()));
    }
    Ok(updates)
}

/// The next pkt-line's payload, or `None` at a flush. `at` advances past it.
fn next_pkt<'b>(body: &'b [u8], at: &mut usize) -> Result<Option<&'b [u8]>, PushRefusal> {
    let header = body
        .get(*at..*at + 4)
        .ok_or(PushRefusal::Malformed("the command list ends without a flush"))?;
    let len = std::str::from_utf8(header)
        .ok()
        .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
        .and_then(|h| usize::from_str_radix(h, 16).ok())
        .ok_or(PushRefusal::Malformed("a pkt-line length that is not four hex digits"))?;
    match len {
        0 => {
            *at += 4;
            Ok(None)
        }
        // 0001 (delim) and 0002 (response-end) are protocol v2 only, and 0003
        // and 0004 are not valid lengths: a push has neither.
        1..=4 => Err(PushRefusal::Malformed("a pkt-line length below 5")),
        _ => {
            let payload = body
                .get(*at + 4..*at + len)
                .ok_or(PushRefusal::Malformed("a pkt-line longer than the body"))?;
            *at += len;
            Ok(Some(payload))
        }
    }
}

/// An object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits, the same
/// length throughout one push.
fn check_oid(oid: &[u8], len: &mut Option<usize>) -> Result<(), PushRefusal> {
    let shaped = (oid.len() == 40 || oid.len() == 64)
        && oid.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
    if !shaped {
        return Err(PushRefusal::Malformed("an object id that is not 40 or 64 lowercase hex"));
    }
    match len {
        Some(l) if *l != oid.len() => Err(PushRefusal::Malformed("object ids of mixed length")),
        _ => {
            *len = Some(oid.len());
            Ok(())
        }
    }
}

fn check_capabilities(list: &[u8]) -> Result<(), PushRefusal> {
    let list = std::str::from_utf8(list).map_err(|_| PushRefusal::Malformed("capabilities are not UTF-8"))?;
    for capability in list.split(' ').filter(|c| !c.is_empty()) {
        let name = capability.split_once('=').map_or(capability, |(n, _)| n);
        if !KNOWN_CAPABILITIES.contains(&name) {
            return Err(PushRefusal::Capability(name.to_string()));
        }
    }
    Ok(())
}

/// A full refname git's `check-ref-format` accepts, restricted to `refs/…`
/// and to visible ASCII. Stricter than git where git is lenient (no
/// non-ASCII), never more lenient.
fn valid_refname(name: &str) -> bool {
    let segments: Vec<&str> = name.split('/').collect();
    segments.len() >= 2
        && segments[0] == "refs"
        && segments.iter().all(|s| valid_ref_component(s))
        && !name.ends_with('.')
        && !name.contains("@{")
        && name != "@"
}

/// One `/`-separated component of a refname (git-check-ref-format(1)):
/// non-empty, visible ASCII without space or `~^:?*[\`, not starting with
/// `.`, without `..`, and not ending `.lock`.
fn valid_ref_component(component: &str) -> bool {
    !component.is_empty()
        && !component.starts_with('.')
        && !component.ends_with(".lock")
        && !component.contains("..")
        && !component.contains("@{")
        && component
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"~^:?*[\\".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const Z: &str = "0000000000000000000000000000000000000000";
    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";

    pub(crate) fn pkt(payload: &str) -> String {
        format!("{:04x}{payload}", payload.len() + 4)
    }

    /// A body as git writes it: the first command carries the capabilities
    /// after a NUL, every line ends LF, a flush, then (here) a fake pack.
    fn body(commands: &[(&str, &str, &str)], caps: &str) -> Vec<u8> {
        let mut out = String::new();
        for (i, (old, new, name)) in commands.iter().enumerate() {
            if i == 0 {
                out.push_str(&pkt(&format!("{old} {new} {name}\0{caps}\n")));
            } else {
                out.push_str(&pkt(&format!("{old} {new} {name}\n")));
            }
        }
        out.push_str("0000PACK\x00\x00\x00\x02");
        out.into_bytes()
    }

    fn studio() -> Vec<RefPattern> {
        parse_patterns(vec!["refs/heads/studio/**".into()]).unwrap()
    }

    const CAPS: &str = "report-status side-band-64k quiet object-format=sha1 agent=git/2.47.0";

    #[test]
    fn a_push_to_a_studio_branch_is_allowed() {
        let updates = check(&studio(), &body(&[(A, B, "refs/heads/studio/foo")], CAPS)).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].refname, "refs/heads/studio/foo");
        check(&studio(), &body(&[(Z, B, "refs/heads/studio/a/b")], CAPS)).unwrap();
    }

    #[test]
    fn a_push_to_main_is_refused() {
        assert_eq!(
            check(&studio(), &body(&[(A, B, "refs/heads/main")], CAPS)),
            Err(PushRefusal::RefOutsideGrant("refs/heads/main".into()))
        );
    }

    #[test]
    fn a_push_to_a_tag_is_refused() {
        assert_eq!(
            check(&studio(), &body(&[(Z, B, "refs/tags/x")], CAPS)),
            Err(PushRefusal::RefOutsideGrant("refs/tags/x".into()))
        );
    }

    #[test]
    fn a_mixed_push_is_refused_whole_even_atomic() {
        for caps in [CAPS, "report-status atomic"] {
            assert_eq!(
                check(
                    &studio(),
                    &body(
                        &[(A, B, "refs/heads/studio/a"), (A, B, "refs/heads/main")],
                        caps
                    )
                ),
                Err(PushRefusal::RefOutsideGrant("refs/heads/main".into())),
                "{caps}"
            );
        }
    }

    #[test]
    fn a_deletion_outside_the_patterns_is_refused_and_inside_is_allowed() {
        let caps = "report-status delete-refs";
        assert_eq!(
            check(&studio(), &body(&[(A, Z, "refs/heads/release")], caps)),
            Err(PushRefusal::RefOutsideGrant("refs/heads/release".into()))
        );
        let ok = check(&studio(), &body(&[(A, Z, "refs/heads/studio/old")], caps)).unwrap();
        assert!(ok[0].is_delete());
    }

    #[test]
    fn near_misses_of_the_pattern_are_refused() {
        for name in [
            "refs/heads/studio",
            "refs/heads/studio-x/a",
            "refs/heads/Studio/a",
            "refs/heads/x/studio/a",
            "refs/remotes/studio/a",
        ] {
            assert!(
                matches!(
                    check(&studio(), &body(&[(A, B, name)], CAPS)),
                    Err(PushRefusal::RefOutsideGrant(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn malformed_command_lists_are_refused() {
        let ok_first = pkt(&format!("{A} {B} refs/heads/studio/a\0report-status\n"));
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("no flush", ok_first.clone().into_bytes()),
            ("only a flush", b"0000".to_vec()),
            ("bad length", format!("zz{ok_first}0000").into_bytes()),
            ("length 3", b"00030000".to_vec()),
            ("delim", format!("0001{ok_first}0000").into_bytes()),
            ("length past end", b"00ff0123".to_vec()),
            (
                "two fields",
                format!("{}0000", pkt(&format!("{A} refs/heads/studio/a\0\n"))).into_bytes(),
            ),
            (
                "four fields",
                format!("{}0000", pkt(&format!("{A} {B} refs/heads/studio/a extra\0\n")))
                    .into_bytes(),
            ),
            (
                "short oid",
                format!("{}0000", pkt(&format!("abc {B} refs/heads/studio/a\0\n"))).into_bytes(),
            ),
            (
                "upper-case oid",
                format!("{}0000", pkt(&format!("{} {B} refs/heads/studio/a\0\n", "A".repeat(40))))
                    .into_bytes(),
            ),
            (
                "mixed oid lengths",
                format!("{}0000", pkt(&format!("{A} {} refs/heads/studio/a\0\n", "2".repeat(64))))
                    .into_bytes(),
            ),
            (
                "not under refs/",
                format!("{}0000", pkt(&format!("{A} {B} HEAD\0\n"))).into_bytes(),
            ),
            (
                "dot-dot",
                format!("{}0000", pkt(&format!("{A} {B} refs/heads/studio/../../main\0\n")))
                    .into_bytes(),
            ),
            (
                "double slash",
                format!("{}0000", pkt(&format!("{A} {B} refs/heads/studio//a\0\n"))).into_bytes(),
            ),
            (
                "first command without NUL",
                format!("{}0000", pkt(&format!("{A} {B} refs/heads/studio/a\n"))).into_bytes(),
            ),
            (
                "second command with NUL",
                format!(
                    "{ok_first}{}0000",
                    pkt(&format!("{A} {B} refs/heads/studio/b\0atomic\n"))
                )
                .into_bytes(),
            ),
        ];
        for (what, bytes) in cases {
            assert!(
                matches!(check(&studio(), &bytes), Err(PushRefusal::Malformed(_))),
                "{what}: {:?}",
                check(&studio(), &bytes)
            );
        }
    }

    #[test]
    fn push_options_signed_pushes_and_unknown_capabilities_are_refused() {
        for (caps, name) in [
            ("report-status push-options", "push-options"),
            ("report-status push-cert=1234", "push-cert"),
            ("report-status no-thin", "no-thin"),
            ("report-status future-thing=1", "future-thing"),
        ] {
            assert_eq!(
                check(&studio(), &body(&[(A, B, "refs/heads/studio/a")], caps)),
                Err(PushRefusal::Capability(name.into())),
                "{caps}"
            );
        }
        // A signed push leads with a `push-cert` pkt-line, not a command.
        let cert = format!("{}0000", pkt("push-cert\0report-status\n"));
        assert_eq!(
            check(&studio(), cert.as_bytes()),
            Err(PushRefusal::Capability("push-cert".into()))
        );
    }

    #[test]
    fn shallow_lines_before_the_commands_are_read_and_name_no_ref() {
        let mut bytes = pkt(&format!("shallow {A}\n")).into_bytes();
        bytes.extend(body(&[(A, B, "refs/heads/studio/a")], CAPS));
        check(&studio(), &bytes).unwrap();
        // After a command, `shallow` is not a command.
        let mut late = pkt(&format!("{A} {B} refs/heads/studio/a\0\n")).into_bytes();
        late.extend(pkt(&format!("shallow {A}\n")).into_bytes());
        late.extend(b"0000");
        assert!(matches!(check(&studio(), &late), Err(PushRefusal::Malformed(_))));
    }

    #[test]
    fn patterns_are_validated() {
        for good in ["refs/heads/studio/**", "refs/heads/*", "refs/heads/main", "refs/*/x"] {
            parse_patterns(vec![good.into()]).unwrap();
        }
        for bad in [
            "",
            "heads/studio/*",
            "refs",
            "refs/heads/studio*",
            "refs/**/x",
            "refs/heads//a",
            "refs/heads/../main",
            "refs/heads/a.lock",
            "refs/heads/a b",
        ] {
            assert!(parse_patterns(vec![bad.into()]).is_err(), "{bad}");
        }
        assert!(parse_patterns(vec!["refs/heads/a".into(); MAX_PUSH_REF_PATTERNS + 1]).is_err());
    }

    #[test]
    fn single_star_matches_one_segment_and_double_star_one_or_more() {
        let p = |s: &str| RefPattern::try_from(s.to_string()).unwrap();
        assert!(p("refs/heads/studio/*").matches("refs/heads/studio/a"));
        assert!(!p("refs/heads/studio/*").matches("refs/heads/studio/a/b"));
        assert!(p("refs/heads/studio/**").matches("refs/heads/studio/a/b"));
        assert!(!p("refs/heads/studio/**").matches("refs/heads/studio"));
        assert!(p("refs/heads/main").matches("refs/heads/main"));
        assert!(!p("refs/heads/main").matches("refs/heads/main2"));
    }
}
