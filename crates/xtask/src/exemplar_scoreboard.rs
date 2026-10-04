//! `cargo xtask exemplar-scoreboard` — the measuring half of the exemplar
//! ratchet, ported from `scripts/exemplar-scoreboard.sh` (#3146).
//!
//! The metrics, their regexes and the `scoreboard.json` schema are the shell
//! script's, unchanged, so `scoreboard-ratchet` and
//! `scripts/exemplar-baseline.json` read this output exactly as they read the
//! script's. One thing is different, and it is the reason for the port.
//!
//! **A `#[cfg(test)] mod x;` whose body is in another file is test code.** The
//! script decided "test" by path (`/tests/`, `_test.rs`) and by stripping the
//! body of an INLINE `#[cfg(test)]` item with a brace counter. It could not see
//!
//! ```text
//! #[cfg(test)]
//! #[path = "command_tests.rs"]
//! mod tests;
//! ```
//!
//! or `#[cfg(all(test, feature = "local-driver"))] mod trust_boundary;`, so the
//! child file was counted as production. That cost two false positives in one
//! day: #3118 raised the `permissive_verify` baseline 13 -> 14 for
//! `pod_api/trust_boundary.rs`, and #3129's moved test module took
//! `unsafe_blocks` 4 -> 10 and stopped the merge queue. "Is this file under a
//! test-only module?" is a module-tree question, so it is answered here with a
//! parse ([`test_only_files`]): resolve `mod x;` to `x.rs` / `x/mod.rs`, honour
//! `#[path]`, and evaluate the `cfg` predicate ([`Cfg::requires_test`]).
//!
//! Everything else is a faithful port, including the line filter's known
//! coarseness (a line containing `//` anywhere is dropped; the inline stripper
//! counts braces in string literals). Those are the script's semantics and the
//! baselines were measured with them; changing them here would make the port's
//! verdict differ for reasons that are not this fix. See [`strip_inline_test_items`].
//!
//! The file domain is `git ls-files`, never a directory walk (a nested worktree
//! reads as repo content); on a CI checkout the two are the same set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Item, Token};

// ── The scoreboard.json schema (unchanged from the shell script) ─────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scoreboard {
    pub formal_verification: FormalVerification,
    pub rust_craft: RustCraft,
    pub sandboxing: Sandboxing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormalVerification {
    pub extracted_proofs: usize,
    pub handmodel_proofs: usize,
    pub extraction_ratio_pct: usize,
    pub sorry_admit: usize,
    pub vacuous_lean: usize,
    #[serde(rename = "lean_theorems_GUARD")]
    pub lean_theorems_guard: usize,
    pub clean_axiom_footprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustCraft {
    pub permissive_verify: usize,
    #[serde(rename = "verify_calls_GUARD")]
    pub verify_calls_guard: usize,
    pub unsafe_blocks: usize,
    pub crates_total: usize,
    pub crates_lints_workspace: usize,
    pub lints_adoption_pct: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sandboxing {
    pub mediation_drift: usize,
    pub bypass_sites: usize,
    pub disallow_sites: usize,
    pub effect_stubs: usize,
}

// ── The file domain ──────────────────────────────────────────────────────────

/// The tree being measured: every tracked file under `crates/`, by path.
pub struct Tree {
    files: BTreeMap<String, String>,
    /// `ci/badges/axiom-footprint.json`, when present.
    axiom_badge: Option<String>,
}

impl Tree {
    /// Read the tracked tree under `root`. A tracked path deleted in the
    /// worktree is not in the tree being measured; any other read failure is
    /// "could not look" and is an error, never an omission (ADR 0007 A-2).
    pub fn read(root: &Path) -> Result<Self> {
        let out = std::process::Command::new("git")
            .args(["ls-files", "-z", "crates"])
            .current_dir(root)
            .output()
            .context("running `git ls-files`")?;
        if !out.status.success() {
            bail!(
                "`git ls-files` failed; the file domain must come from git, not a directory walk"
            );
        }
        let mut files = BTreeMap::new();
        for path in String::from_utf8_lossy(&out.stdout).split('\0') {
            let measured =
                path.ends_with(".rs") || path.ends_with(".lean") || path.ends_with("/Cargo.toml");
            if path.is_empty() || !measured {
                continue;
            }
            match std::fs::read(root.join(path)) {
                Ok(bytes) => {
                    files.insert(
                        path.to_string(),
                        String::from_utf8_lossy(&bytes).into_owned(),
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("reading {path}")),
            }
        }
        let badge = root.join("ci/badges/axiom-footprint.json");
        let axiom_badge = match std::fs::read_to_string(&badge) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("reading {}", badge.display())),
        };
        Self::from_files(files, axiom_badge)
    }

    /// A tree from an in-memory corpus (tests, and the A-19 fixtures).
    pub fn from_files(
        files: BTreeMap<String, String>,
        axiom_badge: Option<String>,
    ) -> Result<Self> {
        // Non-vacuity: a scoreboard over no Rust is all zeroes, which the
        // ratchet would read as a perfect score.
        if !files.keys().any(|p| p.ends_with(".rs")) {
            bail!("no tracked Rust files under crates/; the scoreboard would measure nothing");
        }
        Ok(Self { files, axiom_badge })
    }
}

/// `grep --exclude-dir`: any DIRECTORY component of the path named one of `dirs`.
fn in_excluded_dir(path: &str, dirs: &[&str]) -> bool {
    let mut comps: Vec<&str> = path.split('/').collect();
    comps.pop();
    comps.iter().any(|c| dirs.contains(c))
}

/// The script's `RS` set: `--include='*.rs' --exclude-dir={target,.lake,.claude}`.
fn is_rs(path: &str) -> bool {
    path.ends_with(".rs") && !in_excluded_dir(path, &["target", ".lake", ".claude"])
}

/// The script's `LN` set: `--include='*.lean' --exclude-dir={.lake,.claude}`.
fn is_lean(path: &str) -> bool {
    path.ends_with(".lean") && !in_excluded_dir(path, &[".lake", ".claude"])
}

/// Lines as awk and grep see them: split on `\n`, a trailing newline ends the
/// last line rather than starting an empty one, and `\r` is kept.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
        .map(|l| l.strip_suffix('\n').unwrap_or(l))
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a literal regex")
}

// ── cfg predicates ───────────────────────────────────────────────────────────

/// A `cfg(...)` predicate, parsed rather than matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cfg {
    Test,
    All(Vec<Cfg>),
    Any(Vec<Cfg>),
    Not(Box<Cfg>),
    /// `feature = "x"`, `unix`, `target_os = "linux"`, ...: anything that is not `test`.
    Other,
}

impl Parse for Cfg {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name = input.call(syn::Ident::parse_any)?;
        if input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
            input.parse::<syn::Lit>()?;
            return Ok(Cfg::Other);
        }
        if input.peek(syn::token::Paren) {
            let content;
            syn::parenthesized!(content in input);
            let args: Vec<Cfg> = Punctuated::<Cfg, Token![,]>::parse_terminated(&content)?
                .into_iter()
                .collect();
            return Ok(match name.to_string().as_str() {
                "all" => Cfg::All(args),
                "any" => Cfg::Any(args),
                "not" => match <[Cfg; 1]>::try_from(args) {
                    Ok([one]) => Cfg::Not(Box::new(one)),
                    Err(_) => {
                        return Err(syn::Error::new(name.span(), "not() takes one predicate"));
                    }
                },
                _ => Cfg::Other,
            });
        }
        Ok(if name == "test" {
            Cfg::Test
        } else {
            Cfg::Other
        })
    }
}

impl Cfg {
    /// Is this predicate FALSE whenever `test` is false? That is the only
    /// sense in which code under it is test code: `all(test, feature = "x")`
    /// requires test, `any(test, feature = "x")` does not (it compiles into a
    /// production build with the feature on), and `not(..)` never does.
    #[must_use]
    pub fn requires_test(&self) -> bool {
        match self {
            Cfg::Test => true,
            Cfg::All(xs) => xs.iter().any(Cfg::requires_test),
            Cfg::Any(xs) => !xs.is_empty() && xs.iter().all(Cfg::requires_test),
            Cfg::Not(_) | Cfg::Other => false,
        }
    }
}

/// Several `#[cfg]`s on one item are a conjunction. A `cfg` that does not
/// parse is an error: an unreadable predicate is "could not look" (A-2).
fn attrs_require_test(attrs: &[Attribute], file: &str) -> Result<bool> {
    let mut any = false;
    for a in attrs.iter().filter(|a| a.path().is_ident("cfg")) {
        let cfg: Cfg = a
            .parse_args()
            .with_context(|| format!("{file}: unreadable #[cfg] predicate"))?;
        any |= cfg.requires_test();
    }
    Ok(any)
}

fn path_attr(attrs: &[Attribute]) -> Option<String> {
    attrs
        .iter()
        .find(|a| a.path().is_ident("path"))
        .and_then(|a| match &a.meta {
            syn::Meta::NameValue(nv) => match &nv.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(s.value()),
                _ => None,
            },
            _ => None,
        })
}

// ── The module tree ──────────────────────────────────────────────────────────

/// One `mod x;` declaration (no body: the body is another file).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModDecl {
    name: String,
    path_attr: Option<String>,
    /// Enclosing INLINE modules, as directory components (a `#[path]` on an
    /// inline module replaces its name).
    nest: Vec<String>,
    /// Under a `cfg` that requires `test`, on itself or an enclosing inline module.
    gated: bool,
}

fn collect_decls(
    items: &[Item],
    nest: &[String],
    gated: bool,
    file: &str,
    out: &mut Vec<ModDecl>,
) -> Result<()> {
    for item in items {
        let Item::Mod(m) = item else { continue };
        let here = gated || attrs_require_test(&m.attrs, file)?;
        match &m.content {
            Some((_, inner)) => {
                let mut deeper = nest.to_vec();
                deeper.push(path_attr(&m.attrs).unwrap_or_else(|| m.ident.unraw().to_string()));
                collect_decls(inner, &deeper, here, file, out)?;
            }
            None => out.push(ModDecl {
                name: m.ident.unraw().to_string(),
                path_attr: path_attr(&m.attrs),
                nest: nest.to_vec(),
                gated: here,
            }),
        }
    }
    Ok(())
}

/// Lexically normalise `a/b/../c` -> `a/c` (a `#[path]` may climb).
fn normalise(p: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    parts.join("/")
}

/// The files `decl` (declared in `parent`) may name, most specific first.
///
/// A non-mod-rs file `foo.rs` owns `foo/`; `mod.rs`, `lib.rs` and `main.rs`
/// own their own directory. A crate root with another name (`src/bin/x.rs`,
/// `build.rs`) and a file loaded through `#[path]` also own their directory,
/// so that is the fallback when `foo/` holds no such child.
fn candidates(parent: &str, decl: &ModDecl) -> Vec<String> {
    let file = Path::new(parent);
    let dir = file.parent().unwrap_or(Path::new(""));
    let stem = file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mod_rs = matches!(stem.as_str(), "mod" | "lib" | "main");
    let mut owned: Vec<PathBuf> = Vec::new();
    if !mod_rs {
        owned.push(dir.join(&stem));
    }
    owned.push(dir.to_path_buf());
    let nested = |base: &Path| decl.nest.iter().fold(base.to_path_buf(), |b, c| b.join(c));
    let mut out = Vec::new();
    match (&decl.path_attr, decl.nest.is_empty()) {
        // An outer `#[path]` is relative to the declaring file's own directory.
        (Some(p), true) => out.push(normalise(&dir.join(p))),
        (Some(p), false) => {
            for o in &owned {
                out.push(normalise(&nested(o).join(p)));
            }
        }
        (None, _) => {
            for o in &owned {
                let n = nested(o);
                out.push(normalise(&n.join(format!("{}.rs", decl.name))));
                out.push(normalise(&n.join(&decl.name).join("mod.rs")));
            }
        }
    }
    out
}

/// Files whose every route into a crate passes a `cfg` that requires `test`.
///
/// A file is test-only when (a) its own inner attributes require test
/// (`#![cfg(test)]`), or (b) it is declared by at least one `mod x;`, and
/// every declaration of it is either gated on test or sits in a file that is
/// itself test-only. A file nobody declares (a crate root, `build.rs`, an
/// integration test, an orphan) is not test-only by this rule; the path
/// filter still applies to it. A file reachable from production by ANY route
/// is production.
///
/// A test-gated declaration that resolves to no file is an error: the module
/// exists (it compiles under `cargo test`), so failing to find it means this
/// resolver is wrong, and silently counting nothing would hide that.
pub fn test_only_files(files: &BTreeMap<String, String>) -> Result<BTreeSet<String>> {
    let rs: BTreeSet<&str> = files
        .keys()
        .map(String::as_str)
        .filter(|p| is_rs(p))
        .collect();
    // child -> [(parent, gated)]
    let mut incoming: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    let mut test_only = BTreeSet::new();
    let mut unresolved = Vec::new();
    for &path in &rs {
        let src = &files[path];
        let ast = match syn::parse_file(src) {
            Ok(ast) => ast,
            // Not Rust a compiler would accept (a fixture, a template). Fine
            // while it declares no out-of-line module: it is still measured
            // line by line, as the script measured it. If it does declare one,
            // the split below would be decided without reading that
            // declaration, so it is "could not look" (A-2). Measured
            // 2026-10-02: no tracked file under crates/ fails to parse.
            Err(e) if OUT_OF_LINE_MOD.is_match(src) => {
                bail!("{path}: does not parse ({e}) and declares a module this scan cannot see")
            }
            Err(_) => continue,
        };
        if attrs_require_test(&ast.attrs, path)? {
            test_only.insert(path.to_string());
        }
        let mut decls = Vec::new();
        collect_decls(&ast.items, &[], false, path, &mut decls)?;
        for d in decls {
            let found = candidates(path, &d)
                .into_iter()
                .find(|c| rs.contains(c.as_str()));
            match found {
                Some(child) => incoming
                    .entry(child)
                    .or_default()
                    .push((path.to_string(), d.gated)),
                None if d.gated => unresolved.push(format!("{path}: mod {}", d.name)),
                // A production `mod` under some other cfg may name a file that
                // does not exist on this platform; it makes nothing test-only.
                None => {}
            }
        }
    }
    if !unresolved.is_empty() {
        bail!(
            "could not resolve {} test-gated module declaration(s) to a file, so the \
             test/production split is unknown:\n  {}",
            unresolved.len(),
            unresolved.join("\n  ")
        );
    }
    loop {
        let before = test_only.len();
        for (child, from) in &incoming {
            if !test_only.contains(child)
                && from
                    .iter()
                    .all(|(parent, gated)| *gated || test_only.contains(parent))
            {
                test_only.insert(child.clone());
            }
        }
        if test_only.len() == before {
            break;
        }
    }
    Ok(test_only)
}

static OUT_OF_LINE_MOD: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?m)^\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*;"));

// ── The script's line filter ────────────────────────────────────────────────

static CFG_TEST_ATTR: LazyLock<Regex> =
    LazyLock::new(|| re(r"#\[cfg\((test\)|.*[(,][ ]*test[,)])"));

/// The script's awk: from a line matching the cfg-test regex, skip the item it
/// guards, through the matching close brace. Yields `(line_number, line)` for
/// every line outside such an item.
///
/// One deliberate difference, found by this port's own A-19 probe. The awk
/// stayed "armed" after an item that ends WITHOUT opening a brace (`#[cfg(test)]
/// mod tests;`, `#[cfg(test)] use y;`) or that opened and closed on the
/// attribute's own line, and so also skipped the NEXT braced item, which is
/// production code. `#[cfg(test)] mod tests;` is usually the last item in a
/// file, so a production `unsafe` block added after it was invisible to the
/// shell gate. Here an item also ends at a line that ends with `;`, and the
/// attribute's own line counts as the item's first line. That can only ADD
/// production lines; measured on main (4f14275f) it changes no metric.
///
/// Kept: the regex also matches `#[cfg(not(test))]`, which under-counts.
pub fn strip_inline_test_items(text: &str) -> Vec<(usize, &str)> {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        Armed,
        InBody(i64),
    }
    let mut state = State::Code;
    let mut out = Vec::new();
    for (i, line) in lines(text).enumerate() {
        let opens = i64::try_from(line.matches('{').count()).unwrap_or(i64::MAX);
        let closes = i64::try_from(line.matches('}').count()).unwrap_or(i64::MAX);
        // Where the guarded item stands after `line`, which is one of its lines.
        let item = || {
            if opens > 0 {
                let depth = opens - closes;
                if depth > 0 {
                    State::InBody(depth)
                } else {
                    State::Code
                }
            } else if line.trim_end().ends_with(';') {
                State::Code
            } else {
                State::Armed
            }
        };
        state = match state {
            State::Code if CFG_TEST_ATTR.is_match(line) => item(),
            State::Code => {
                out.push((i + 1, line));
                State::Code
            }
            State::Armed => item(),
            State::InBody(depth) => {
                let depth = depth + opens - closes;
                if depth <= 0 {
                    State::Code
                } else {
                    State::InBody(depth)
                }
            }
        };
    }
    out
}

static NON_TEST_LINE: LazyLock<Regex> = LazyLock::new(|| re(r"/tests/|_test\.rs|//|///"));

/// The script's `nt PATTERN`: `path:line:text` records matching `pattern`, in
/// production code. Test-only files are skipped whole.
fn nt(tree: &Tree, test_only: &BTreeSet<String>, pattern: &Regex) -> Vec<String> {
    let mut out = Vec::new();
    for (path, src) in tree.files.iter().filter(|(p, _)| is_rs(p)) {
        if test_only.contains(path) || !pattern.is_match(src) {
            continue;
        }
        for (n, line) in strip_inline_test_items(src) {
            let rec = format!("{path}:{n}:{line}");
            if pattern.is_match(&rec) && !NON_TEST_LINE.is_match(&rec) {
                out.push(rec);
            }
        }
    }
    out
}

fn count_lines(tree: &Tree, keep: impl Fn(&str) -> bool, pattern: &Regex) -> usize {
    tree.files
        .iter()
        .filter(|(p, _)| keep(p))
        .map(|(_, s)| lines(s).filter(|l| pattern.is_match(l)).count())
        .sum()
}

fn count_occurrences(tree: &Tree, needle: &str) -> usize {
    tree.files
        .iter()
        .filter(|(p, _)| is_rs(p))
        .map(|(_, s)| s.matches(needle).count())
        .sum()
}

fn pct(part: usize, whole: usize) -> usize {
    part.saturating_mul(100).checked_div(whole).unwrap_or(0)
}

// ── The measurement ──────────────────────────────────────────────────────────

/// Measure `tree`. Every metric is the script's; only the `nt` domain differs,
/// by the files [`test_only_files`] returns.
pub fn measure(tree: &Tree) -> Result<Scoreboard> {
    let test_only = test_only_files(&tree.files)?;

    // Formal verification
    // Every needle below is ASSEMBLED, never written whole: this file is in the
    // domain it measures, and a literal here would count itself (the script was
    // a .sh, outside the domain, and never had to care).
    let extracted = count_occurrences(tree, concat!("Extracted", "KernelChecked"));
    let handmodel = count_occurrences(tree, concat!("HandModel", "KernelChecked"));
    let sorry_admit = count_lines(tree, is_lean, &re(r"^[[:space:]]*(sorry|admit)"));
    let lean_theorems = count_lines(tree, is_lean, &re(r"^[[:space:]]*(theorem|lemma) "));
    let vacuous_lean = count_lines(
        tree,
        is_lean,
        &re(
            r":=[[:space:]]*by[[:space:]]+trivial|:[[:space:]]*True[[:space:]]*:=|axiom[[:space:]].*:[[:space:]]*True",
        ),
    );

    // Rust craft
    let sigctx = re(r"(?i)sig|signature|vk|verifying|pubkey|public_key|ed25519");
    let permissive_verify = nt(tree, &test_only, &re(r"\.verify\("))
        .iter()
        .filter(|r| !r.contains("verify_strict") && sigctx.is_match(r))
        .count();
    let verify_calls = nt(tree, &test_only, &re(r"\.verify(_strict)?\("))
        .iter()
        .filter(|r| sigctx.is_match(r))
        .count();
    let unsafe_blocks = nt(tree, &test_only, &re(r"\bunsafe[[:space:]]+(\{|fn|impl)")).len();
    let manifests: Vec<(&String, &String)> = tree
        .files
        .iter()
        .filter(|(p, _)| p.ends_with("/Cargo.toml"))
        .collect();
    // `find crates -maxdepth 2 -name Cargo.toml`
    let crates_total = manifests
        .iter()
        .filter(|(p, _)| p.split('/').count() <= 3)
        .count();
    let ws = re(r"(?m)^\s*workspace\s*=\s*true");
    let crates_lints_ws = manifests
        .iter()
        .filter(|(_, s)| ws.is_match(s) && s.contains("[lints]"))
        .count();

    // Sandboxing
    let bypass = re(concat!(
        "dangerously-skip-",
        "permissions|bypass",
        "Permissions"
    ));
    let lattice = re(concat!("allowed", "Tools|mcp-", "config"));
    let disallow = re(concat!(
        "DISALLOWED_",
        "BUILTIN_TOOLS|--disallowed",
        "Tools"
    ));
    let (mut bypass_sites, mut mediation_drift) = (0usize, 0usize);
    for (path, src) in tree.files.iter().filter(|(p, _)| is_rs(p)) {
        if path.contains("/examples/") || !bypass.is_match(src) || !lattice.is_match(src) {
            continue;
        }
        bypass_sites += 1;
        if !disallow.is_match(src) {
            mediation_drift += 1;
        }
    }
    let effect_stubs = count_lines(
        tree,
        |p| {
            is_rs(p)
                && (p.starts_with("crates/portcullis-effects/")
                    || p.starts_with("crates/portcullis-core/"))
        },
        &re(concat!("Not", "Implemented|Not", "Wired")),
    );

    let clean_axioms = tree
        .axiom_badge
        .as_deref()
        .and_then(|b| {
            let found: Vec<String> = re(r#""message":"([^"]*)""#)
                .captures_iter(b)
                .map(|c| c[1].to_string())
                .collect();
            (!found.is_empty()).then(|| found.join("\n"))
        })
        .unwrap_or_else(|| "n/a".to_string());

    Ok(Scoreboard {
        formal_verification: FormalVerification {
            extracted_proofs: extracted,
            handmodel_proofs: handmodel,
            extraction_ratio_pct: pct(extracted, extracted + handmodel),
            sorry_admit,
            vacuous_lean,
            lean_theorems_guard: lean_theorems,
            clean_axiom_footprint: clean_axioms,
        },
        rust_craft: RustCraft {
            permissive_verify,
            verify_calls_guard: verify_calls,
            unsafe_blocks,
            crates_total,
            crates_lints_workspace: crates_lints_ws,
            lints_adoption_pct: pct(crates_lints_ws, crates_total),
        },
        sandboxing: Sandboxing {
            mediation_drift,
            bypass_sites,
            disallow_sites: bypass_sites - mediation_drift,
            effect_stubs,
        },
    })
}

/// The script's three summary lines.
pub fn summary(s: &Scoreboard) -> String {
    let (f, r, x) = (&s.formal_verification, &s.rust_craft, &s.sandboxing);
    format!(
        "  FV : extraction {}/{} | sorry/admit {} | vacuous-lean {} (of {} thm) | clean-axioms {}\n  \
         RUST: permissive .verify {} (of {}) | unsafe blocks {} | lints.workspace {}/{}\n  \
         SANDBOX: mediation-drift {} (bypass {} / disallow {}) | effect-stubs {}",
        f.extracted_proofs,
        f.extracted_proofs + f.handmodel_proofs,
        f.sorry_admit,
        f.vacuous_lean,
        f.lean_theorems_guard,
        f.clean_axiom_footprint,
        r.permissive_verify,
        r.verify_calls_guard,
        r.unsafe_blocks,
        r.crates_lints_workspace,
        r.crates_total,
        x.mediation_drift,
        x.bypass_sites,
        x.disallow_sites,
        x.effect_stubs,
    )
}

/// Measure the tree at the current directory.
pub fn measure_cwd() -> Result<Scoreboard> {
    let root = std::env::current_dir().context("reading the current directory")?;
    let board = measure(&Tree::read(&root)?)?;
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    println!("exemplar scoreboard — {name}");
    println!("{}", summary(&board));
    Ok(board)
}

/// `cargo xtask exemplar-scoreboard [OUT]`: measure, and write `OUT`.
pub fn run(out: &str) -> Result<()> {
    let board = measure_cwd()?;
    let mut json = serde_json::to_string_pretty(&board).context("serialising the scoreboard")?;
    json.push('\n');
    std::fs::write(out, json).with_context(|| format!("writing {out}"))?;
    println!("  -> {out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> Tree {
        let files = files
            .iter()
            .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
            .collect();
        Tree::from_files(files, None).unwrap()
    }

    fn board(files: &[(&str, &str)]) -> Scoreboard {
        measure(&tree(files)).unwrap()
    }

    fn cfg(s: &str) -> Cfg {
        syn::parse_str(s).unwrap()
    }

    const UNSAFE_CHILD: &str = "fn t() {\n    unsafe { set(1) }\n}\n";

    #[test]
    fn requires_test_is_the_predicate_not_the_spelling() {
        assert!(cfg("test").requires_test());
        assert!(cfg(r#"all(test, feature = "local-driver")"#).requires_test());
        assert!(cfg("all(unix, all(test))").requires_test());
        assert!(cfg("any(test, all(test, unix))").requires_test());
        assert!(!cfg(r#"any(test, feature = "x")"#).requires_test());
        assert!(!cfg("not(test)").requires_test());
        assert!(!cfg(r#"feature = "test""#).requires_test());
        assert!(!cfg("any()").requires_test());
    }

    /// #3129: `#[cfg(test)] #[path = "command_tests.rs"] mod tests;`. The
    /// shell counted the child's `unsafe` blocks as production.
    #[test]
    fn a_path_attributed_test_module_in_another_file_is_test_code() {
        let b = board(&[
            (
                "crates/n/src/command.rs",
                "pub fn f() {}\n\n#[cfg(test)]\n#[path = \"command_tests.rs\"]\nmod tests;\n",
            ),
            ("crates/n/src/lib.rs", "mod command;\n"),
            ("crates/n/src/command_tests.rs", UNSAFE_CHILD),
        ]);
        assert_eq!(b.rust_craft.unsafe_blocks, 0);
    }

    /// #3118: `#[cfg(all(test, feature = "local-driver"))] mod trust_boundary;`
    /// declared from `pod_api.rs`, body in `pod_api/trust_boundary.rs`.
    #[test]
    fn a_compound_cfg_test_module_in_a_child_directory_is_test_code() {
        let child = "fn t(vk: &K) { vk.verify(&m, &signature).unwrap(); }\n";
        let b = board(&[
            ("crates/n/src/lib.rs", "mod pod_api;\n"),
            (
                "crates/n/src/pod_api.rs",
                "#[cfg(all(test, feature = \"local-driver\"))]\nmod trust_boundary;\n",
            ),
            ("crates/n/src/pod_api/trust_boundary.rs", child),
        ]);
        assert_eq!(b.rust_craft.permissive_verify, 0);
        assert_eq!(b.rust_craft.verify_calls_guard, 0);
    }

    /// A-19, the other direction: the same block in production is counted.
    #[test]
    fn production_unsafe_is_counted_in_a_child_file_and_in_the_root() {
        let b = board(&[
            (
                "crates/n/src/lib.rs",
                "mod a;\nmod b;\npub fn r() { unsafe { x() } }\n",
            ),
            ("crates/n/src/a.rs", UNSAFE_CHILD),
            ("crates/n/src/b/mod.rs", UNSAFE_CHILD),
        ]);
        assert_eq!(b.rust_craft.unsafe_blocks, 3);
    }

    #[test]
    fn a_feature_or_any_gated_module_is_production() {
        let b = board(&[
            (
                "crates/n/src/lib.rs",
                "#[cfg(feature = \"x\")]\nmod a;\n#[cfg(any(test, feature = \"y\"))]\nmod b;\n",
            ),
            ("crates/n/src/a.rs", UNSAFE_CHILD),
            ("crates/n/src/b.rs", UNSAFE_CHILD),
        ]);
        assert_eq!(b.rust_craft.unsafe_blocks, 2);
    }

    #[test]
    fn test_only_is_inherited_and_lost_to_any_production_route() {
        let files: BTreeMap<String, String> = [
            ("crates/n/src/lib.rs", "#[cfg(test)]\nmod t;\nmod shared;\n"),
            // Grandchild of a test-only module: test-only.
            (
                "crates/n/src/t.rs",
                "mod deep;\n#[path = \"../shared.rs\"]\nmod also;\n",
            ),
            ("crates/n/src/t/deep.rs", ""),
            // Declared from test code AND from production: production.
            ("crates/n/src/shared.rs", ""),
            // Inline test module declaring an out-of-line child.
            (
                "crates/n/src/main.rs",
                "#[cfg(test)]\nmod tests {\n    mod helpers;\n}\n",
            ),
            ("crates/n/src/tests/helpers.rs", ""),
            // A file that says so itself.
            ("crates/n/src/inner.rs", "#![cfg(test)]\nfn t() {}\n"),
        ]
        .iter()
        .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
        .collect();
        let got = test_only_files(&files).unwrap();
        let want: BTreeSet<String> = [
            "crates/n/src/t.rs",
            "crates/n/src/t/deep.rs",
            "crates/n/src/tests/helpers.rs",
            "crates/n/src/inner.rs",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn a_non_mod_rs_crate_root_falls_back_to_its_own_directory() {
        let files: BTreeMap<String, String> = [
            (
                "crates/n/src/bin/tool.rs",
                "#[cfg(test)]\nmod tool_tests;\n",
            ),
            ("crates/n/src/bin/tool_tests.rs", ""),
        ]
        .iter()
        .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
        .collect();
        let got = test_only_files(&files).unwrap();
        assert!(got.contains("crates/n/src/bin/tool_tests.rs"));
    }

    /// "Could not look" is not "looked and it was fine" (A-2).
    #[test]
    fn an_unresolvable_test_module_is_an_error_not_an_omission() {
        let files: BTreeMap<String, String> = [(
            "crates/n/src/lib.rs".to_string(),
            "#[cfg(test)]\nmod gone;\n".to_string(),
        )]
        .into();
        let err = test_only_files(&files)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("mod gone"), "{err}");
        // ...and a production module under another cfg is allowed to be absent.
        let files: BTreeMap<String, String> = [(
            "crates/n/src/lib.rs".to_string(),
            "#[cfg(windows)]\nmod gone;\n".to_string(),
        )]
        .into();
        assert!(test_only_files(&files).is_ok());
    }

    #[test]
    fn an_unparseable_file_is_refused_only_when_it_declares_a_module() {
        let files: BTreeMap<String, String> = [(
            "crates/n/src/lib.rs".to_string(),
            "fn (\nmod hidden;\n".to_string(),
        )]
        .into();
        assert!(test_only_files(&files).is_err());
        let files: BTreeMap<String, String> =
            [("crates/n/src/fixture.rs".to_string(), "fn (\n".to_string())].into();
        assert!(test_only_files(&files).is_ok());
    }

    #[test]
    fn an_empty_tree_is_refused() {
        assert!(Tree::from_files(BTreeMap::new(), None).is_err());
    }

    #[test]
    fn the_inline_stripper_is_the_scripts_awk_without_the_eaten_item() {
        // `awk` is what the script's awk printed for the same input (GNU awk,
        // 2026-10-02); `want` is this stripper. They differ only where the awk
        // skipped a production item after a test item that had already ended,
        // so `want` is always a superset of `awk`.
        let cases: [(&str, &[usize], &[usize]); 5] = [
            (
                "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn x() {\n    }\n}\nfn b() {}\n",
                &[1, 7],
                &[1, 7],
            ),
            // An item opened and closed on the attribute's own line.
            (
                "#[cfg(all(test, unix))] mod t { fn x() {} }\nfn b() {}\nfn c() {}\n",
                &[3],
                &[2, 3],
            ),
            // An out-of-line `mod x;`: the awk ate the next item.
            (
                "#[cfg(test)]\nmod t;\nfn eaten() {\n}\nfn kept() {}\n",
                &[5],
                &[3, 4, 5],
            ),
            (
                "#[cfg(test)]\n#[path = \"t.rs\"]\nmod t;\nfn f() {\n}\n",
                &[],
                &[4, 5],
            ),
            // Kept: the regex also matches `not(test)`.
            (
                "#[cfg(not(test))]\nfn prod() {\n}\nfn kept() {}\n",
                &[4],
                &[4],
            ),
        ];
        for (src, awk, want) in cases {
            assert!(awk.iter().all(|n| want.contains(n)), "{src:?}");
            let kept: Vec<usize> = strip_inline_test_items(src)
                .iter()
                .map(|(n, _)| *n)
                .collect();
            assert_eq!(kept, want, "{src:?}");
        }
    }

    /// A-19 at unit scale: production `unsafe` after a `#[cfg(test)] mod x;`
    /// is counted; the shell's awk ate it.
    #[test]
    fn production_after_an_out_of_line_test_module_is_counted() {
        let b = board(&[
            (
                "crates/n/src/lib.rs",
                "#[cfg(test)]\n#[path = \"t.rs\"]\nmod tests;\n\npub fn p(x: *const u8) -> u8 {\n    unsafe { *x }\n}\n",
            ),
            ("crates/n/src/t.rs", UNSAFE_CHILD),
        ]);
        assert_eq!(b.rust_craft.unsafe_blocks, 1);
    }

    /// This file is in the domain it measures. It must not count itself.
    #[test]
    fn the_scanner_does_not_measure_its_own_needles() {
        let me = include_str!("exemplar_scoreboard.rs");
        let b = board(&[("crates/xtask/src/exemplar_scoreboard.rs", me)]);
        assert_eq!(b.formal_verification.extracted_proofs, 0);
        assert_eq!(b.formal_verification.handmodel_proofs, 0);
        assert_eq!(b.rust_craft.permissive_verify, 0);
        assert_eq!(b.rust_craft.verify_calls_guard, 0);
        assert_eq!(b.rust_craft.unsafe_blocks, 0);
        assert_eq!(b.sandboxing.bypass_sites, 0);
    }

    #[test]
    fn the_line_filter_and_signature_context_are_the_scripts() {
        let b = board(&[(
            "crates/n/src/lib.rs",
            "fn f() {\n    vk.verify(m, s);\n    key.verify(m, s);\n    vk.verify(m, s); // ok\n    vk.verify_strict(m, s);\n}\n",
        )]);
        // `key.verify` has no signature context; the `//` line is dropped.
        assert_eq!(b.rust_craft.permissive_verify, 1);
        assert_eq!(b.rust_craft.verify_calls_guard, 2);
        // A `/tests/` path is never production.
        let b = board(&[("crates/n/tests/it.rs", "fn f() { unsafe { x() } }\n")]);
        assert_eq!(b.rust_craft.unsafe_blocks, 0);
    }

    #[test]
    fn the_json_keeps_the_scripts_metric_names() {
        let b = board(&[("crates/n/src/lib.rs", "")]);
        let v = serde_json::to_value(&b).unwrap();
        for (section, key) in [
            ("formal_verification", "lean_theorems_GUARD"),
            ("formal_verification", "clean_axiom_footprint"),
            ("rust_craft", "verify_calls_GUARD"),
            ("rust_craft", "unsafe_blocks"),
            ("sandboxing", "mediation_drift"),
        ] {
            assert!(v[section].get(key).is_some(), "{section}.{key}");
        }
        // And the committed baseline parses as this schema: one shape, not two.
        let baseline = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/exemplar-baseline.json"),
        )
        .unwrap();
        assert!(serde_json::from_str::<Scoreboard>(&baseline).is_ok());
    }

    #[test]
    fn excluded_dirs_are_grep_exclude_dir() {
        assert!(!is_rs("crates/a/target/x.rs"));
        assert!(!is_rs("crates/a/.claude/x.rs"));
        assert!(is_lean("crates/a/target/X.lean"));
        assert!(!is_lean("crates/a/.lake/X.lean"));
        assert!(is_rs("crates/a/src/target.rs"));
    }
}
