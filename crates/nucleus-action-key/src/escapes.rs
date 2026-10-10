//! Compile-time reads that leave the closure the key is built from.
//!
//! # The hole this closes
//!
//! [`crate::closure`] states its own limit: it "says nothing about a crate
//! reading a file at runtime that is not a source file of any crate:
//! `include_str!`, a fixture directory, a `build.rs` reading the tree. Those
//! are real and unmodelled." This module measures the compile-time half of
//! that list, because it is the half a machine can settle.
//!
//! [`crate::closure::Workspace::read_set`] takes *every tracked file* under
//! each closure member's directory, not only `*.rs`. So an `include_str!` of a
//! file beside its reader is already in the key, and the hole is narrower than
//! the sentence above suggests: it is exactly the reads whose target resolves
//! **outside every closure member's directory**.
//!
//! Measured on this workspace, 2026-09-14: **10 distinct macro sites escape
//! their closure, affecting 12 (crate, site) pairs across 7 of 90 crates.** A
//! receipt keyed on such a crate's closure answers green after its target
//! changed.
//!
//! The count of pairs exceeds the count of sites because an escape propagates
//! along the dependency graph: `nucleus-control-plane-server` has no offending
//! macro of its own and inherits both of `nucleus-github-oidc`'s, because that
//! crate is in its closure. That is why the unit of scanning here is the
//! closure rather than the crate — scanning crates alone would report the
//! defect as local when the stale green it causes is not.
//!
//! Two sites that *look* like escapes are not: `portcullis` reads
//! `portcullis-core`'s generated Lean, and that crate is a declared dependency,
//! so the closure already covers it.
//!
//! An earlier hand-counted estimate of this population, made with `grep` and an
//! `awk` depth heuristic, said nine sites across six crates. It missed one site
//! and the whole of `nucleus-control-plane-server`. That is F-144 and F-152
//! recurring on the person writing their fix, which is the reason the count
//! below is asserted by the token walk and not by the hand count.
//!
//! # The two refusals, and why they are not one
//!
//! [`crate::Refusal::EscapingRead`] is a key that *could* be completed — the
//! target is tracked, so a digest for it exists, and widening the closure would
//! capture it. It is a defect in the read-set.
//!
//! [`crate::Refusal::UntrackedRead`] cannot be completed that way.
//! `read_set` iterates the repository's tracked-file list, so a file `git
//! ls-files` does not name can never contribute a digest no matter how the
//! closure is widened. `nucleus-verifier-service` embeds
//! `sdks/verifier-js/pkg/nucleus_verifier_wasm_bg.wasm`, an untracked build
//! product of another toolchain: its bytes can change with no change to any
//! tracked file in the tree. Folding that into the first refusal would report
//! a key that is *wrong* as a key that is merely *narrow*.
//!
//! # Why a lexer and not a pattern
//!
//! Gatehouse's ledger records the same mistake twice — F-144 and F-152, a
//! population verified with a hand-rolled parser and reported wrong, the second
//! one loop after recording the first. A regex over Rust source counts
//! `include_str!` inside a line comment, inside a string literal, and inside
//! `#[cfg(FALSE)]`, and misses every raw-string form. So this tokenizes with
//! `proc_macro2`, which is the same lexer the compiler's front end uses, and
//! walks the token tree.
//!
//! The population it reports is cross-checked in
//! `tests/escapes_population.rs` against an independent enumeration, per the
//! rule those two findings produced.
//!
//! # What it does not claim
//!
//! It resolves a **literal** path argument. `include_str!(concat!(...))`, a
//! path built through a macro, `env!("OUT_DIR")` joins, and any runtime
//! `fs::read` are outside what a token walk can settle — they are reported by
//! [`Unresolvable`] rather than counted as covered, because a read this module
//! could not resolve is not a read it showed to be safe. `build.rs` is not
//! scanned: what a build script reads is a runtime question.
//!
//! This is a *necessary* condition on the key, not a sufficient one. Nothing
//! here establishes that a crate with no escapes reads only its closure; only
//! an enforced read bound in the pod can establish that, and that is the layer
//! `docs/build-cache-design.md` lists after this one.

use crate::closure::{WORKSPACE_WIDE, Workspace};
use anyhow::{Context, Result};
use proc_macro2::{TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::str::FromStr;

/// The macros whose argument is a path read at compile time.
const READING_MACROS: &[&str] = &["include_str", "include_bytes"];

/// One compile-time read whose target lies outside the reading crate's closure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Escape {
    /// The repo-relative `.rs` file holding the macro call.
    pub site: String,
    /// The macro's name, without the `!`.
    pub macro_name: String,
    /// The repo-relative path the literal resolved to.
    pub target: String,
    /// Whether the repository tracks that target.
    ///
    /// `false` is the strictly worse case: no digest for it can enter the key
    /// under any closure, because `read_set` iterates tracked files.
    pub tracked: bool,
}

/// A macro call whose path argument is not a single string literal.
///
/// Reported rather than skipped: see "What it does not claim" above.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unresolvable {
    pub site: String,
    pub macro_name: String,
    /// The argument tokens as written, for a person to read.
    pub argument: String,
}

/// What a scan of one crate found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// Reads resolving outside the closure, sorted.
    pub escapes: Vec<Escape>,
    /// Reads whose path a token walk cannot settle, sorted.
    pub unresolvable: Vec<Unresolvable>,
    /// How many macro sites were examined, escaping or not.
    pub sites_examined: usize,
}

impl Scan {
    /// Whether this crate's closure is a complete read-set as far as compile-time
    /// reads can show.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.escapes.is_empty() && self.unresolvable.is_empty()
    }
}

/// Scan one crate's closure for compile-time reads that leave it.
///
/// `tracked` is the repository's tracked-file list, passed in for the same
/// reason [`crate::closure::Workspace::read_set`] takes it: `git ls-files` over
/// a large tree is not free, and this is called once per crate.
///
/// A caller scanning more than one crate should hold a [`Lexer`] and call
/// [`Lexer::scan`]: this function lexes every file of the closure afresh.
pub fn scan(ws: &Workspace, root: &Path, tracked: &[String], crate_name: &str) -> Result<Scan> {
    Lexer::new(root).scan(ws, tracked, crate_name)
}

/// One reading-macro call as the lexer found it, before any closure is applied.
///
/// Everything here is a function of the file alone. Whether the read is
/// covered depends on whose closure is asking, so that is decided per scan.
#[derive(Debug, Clone)]
struct Site {
    macro_name: String,
    read: SiteRead,
}

#[derive(Debug, Clone)]
enum SiteRead {
    /// A literal path, resolved repo-relative against the file holding it.
    Target(String),
    /// An argument a token walk cannot settle, as a person should read it.
    Unresolvable(String),
}

/// Files lexed once and kept, so a crate shared by many closures is tokenized
/// once rather than once per closure that holds it.
///
/// Measured 2026-10-08 (nucleus `docs/findings/live-path-gates-critical-path.md`):
/// `cargo xtask test-shards --check` scans all ~90 members, each lexing its
/// whole closure, and the re-lexing was nearly all of the gate's time. The
/// gate of gates runs it seven times per merge-queue group.
pub struct Lexer {
    root: std::path::PathBuf,
    files: BTreeMap<String, Vec<Site>>,
}

impl Lexer {
    /// An empty cache over the tree at `root`.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            files: BTreeMap::new(),
        }
    }

    /// The reading-macro sites of one tracked file, lexing it on first use.
    fn sites(&mut self, f: &str) -> Result<&[Site]> {
        if !self.files.contains_key(f) {
            let source = std::fs::read_to_string(self.root.join(f))
                .with_context(|| format!("reading {f} to scan its compile-time reads"))?;
            // A file that does not lex is not a file with no reads. Rust source
            // that the compiler accepts and `proc_macro2` rejects would be a bug in
            // one of them, and reporting it as "nothing found" is the vacuity this
            // whole crate is written against.
            let stream =
                TokenStream::from_str(&source).map_err(|e| anyhow::anyhow!("lexing {f}: {e}"))?;
            let dir = Path::new(f).parent().unwrap_or(Path::new(""));
            let mut sites = Vec::new();
            walk(&stream, dir, &mut sites);
            self.files.insert(f.to_string(), sites);
        }
        Ok(self.files.get(f).map_or(&[], Vec::as_slice))
    }

    /// Scan one crate's closure, reusing every file an earlier scan lexed.
    ///
    /// The answer is [`scan`]'s exactly: the same files are visited, in the
    /// same order, and a file that does not lex is the same error.
    pub fn scan(&mut self, ws: &Workspace, tracked: &[String], crate_name: &str) -> Result<Scan> {
        let Some(members) = ws.closures.get(crate_name) else {
            anyhow::bail!("{crate_name} is not a workspace crate");
        };
        let prefixes: Vec<String> = members
            .iter()
            .filter_map(|m| ws.dirs.get(m))
            .map(|d| format!("{d}/"))
            .collect();
        let tracked_set: BTreeSet<&str> = tracked.iter().map(String::as_str).collect();

        let mut scan = Scan::default();
        for f in tracked {
            if !f.ends_with(".rs") {
                continue;
            }
            if !prefixes.iter().any(|p| f.starts_with(p.as_str())) {
                continue;
            }
            for site in self.sites(f)? {
                scan.sites_examined = scan.sites_examined.saturating_add(1);
                classify(site, f, &prefixes, &tracked_set, &mut scan);
            }
        }
        scan.escapes.sort();
        scan.unresolvable.sort();
        Ok(scan)
    }
}

/// Walk a token stream looking for `<macro>!( <literal> )`.
fn walk(stream: &TokenStream, dir: &Path, out: &mut Vec<Site>) {
    // `Ident Punct('!') Group` is the whole shape. Keeping the last two idents
    // rather than collecting the stream avoids allocating a Vec per file.
    let mut prev_ident: Option<String> = None;
    let mut bang_after: Option<String> = None;

    for tt in stream.clone() {
        match tt {
            TokenTree::Ident(ref id) => {
                prev_ident = Some(id.to_string());
                bang_after = None;
            }
            TokenTree::Punct(ref p) if p.as_char() == '!' => {
                bang_after = prev_ident.take();
            }
            TokenTree::Group(ref g) => {
                if let Some(name) = bang_after.take() {
                    if READING_MACROS.contains(&name.as_str()) {
                        out.push(Site {
                            read: resolve(&g.stream(), dir),
                            macro_name: name,
                        });
                        // The argument was handled; do not also descend into it.
                        prev_ident = None;
                        continue;
                    }
                }
                // Not a reading macro: descend, since a call can nest inside any
                // group — a function body, a `vec![]`, an attribute's tokens.
                walk(&g.stream(), dir, out);
                prev_ident = None;
            }
            _ => {
                prev_ident = None;
                bang_after = None;
            }
        }
    }
}

/// What one reading-macro call's argument names, relative to no closure.
fn resolve(args: &TokenStream, dir: &Path) -> SiteRead {
    let tokens: Vec<TokenTree> = args.clone().into_iter().collect();
    // `include_str!("p")` and `include_str!("p",)` are the only shapes with a
    // literal path. Anything else goes to `Unresolvable` by construction.
    let literal = match tokens.as_slice() {
        [TokenTree::Literal(l)] => Some(l.to_string()),
        [TokenTree::Literal(l), TokenTree::Punct(p)] if p.as_char() == ',' => Some(l.to_string()),
        _ => None,
    };
    let Some(raw) = literal.as_deref().and_then(string_literal_value) else {
        return SiteRead::Unresolvable(args.to_string());
    };

    // `include_str!` resolves relative to the file holding it.
    match normalize(&dir.join(&raw)) {
        Some(target) => SiteRead::Target(target),
        // A path climbing above the repository root. Not an escape from the
        // closure — an escape from the tree — and a person has to look.
        None => SiteRead::Unresolvable(raw),
    }
}

/// Decide what one site is to the closure asking, and record it.
fn classify(
    site: &Site,
    file: &str,
    prefixes: &[String],
    tracked: &BTreeSet<&str>,
    out: &mut Scan,
) {
    let target = match &site.read {
        SiteRead::Unresolvable(argument) => {
            out.unresolvable.push(Unresolvable {
                site: file.to_string(),
                macro_name: site.macro_name.clone(),
                argument: argument.clone(),
            });
            return;
        }
        SiteRead::Target(target) => target,
    };
    let covered =
        WORKSPACE_WIDE.contains(&target.as_str()) || prefixes.iter().any(|p| target.starts_with(p));
    if covered {
        return;
    }
    out.escapes.push(Escape {
        site: file.to_string(),
        macro_name: site.macro_name.clone(),
        tracked: tracked.contains(target.as_str()),
        target: target.clone(),
    });
}

/// The value of a Rust string literal token, or `None` if it is not one.
///
/// Handles the plain and raw forms. A literal with escapes in it is returned
/// with the escapes intact, which would be wrong for a path containing one —
/// so a literal carrying a backslash is refused rather than guessed at. On the
/// platforms this repository builds for a path separator is `/`, and a
/// backslash in an `include_str!` argument is more likely a mistake than a
/// filename.
fn string_literal_value(tok: &str) -> Option<String> {
    let body = if let Some(rest) = tok.strip_prefix('r') {
        // r"..", r#".."#, r##".."##, ...
        let hashes = rest.len().checked_sub(rest.trim_start_matches('#').len())?;
        let inner = rest.get(hashes..)?;
        let inner = inner.strip_prefix('"')?;
        let end = inner.len().checked_sub(hashes.checked_add(1)?)?;
        let closed = inner.get(end..)?;
        if !closed.starts_with('"') {
            return None;
        }
        inner.get(..end)?
    } else {
        tok.strip_prefix('"')?.strip_suffix('"')?
    };
    if body.contains('\\') {
        return None;
    }
    Some(body.to_string())
}

/// Resolve `.` and `..` textually, repo-relative. `None` if it climbs out.
fn normalize(p: &Path) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            // An absolute path is not repo-relative and cannot be keyed.
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

#[cfg(test)]
#[path = "escapes/tests.rs"]
mod tests;
