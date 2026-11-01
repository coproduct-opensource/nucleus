//! `cargo xtask egress-proofs [--check]` — how many of the broker's egress
//! decision functions have an Aeneas-extracted Lean theorem stating a
//! `Pa.Egress.1` law, with a Rust–Lean parity test beside it.
//!
//! The decisions and the laws are pinned in `ci/egress-decisions.toml`; the
//! number is re-derived from the tracked tree on every run and printed as
//! `{"decisions": N, "proved": M, "pct": P}`. `--check` holds it to the
//! committed `ci/egress-proofs.json` in both directions, so a rise and a fall
//! are each a visible edit (docs/egress-as-olog.md).
//!
//! # A decision counts only when every obligation holds
//!
//! Each law a decision cites needs an obligation naming a Lean proof file and
//! theorem, the theorem's signature pinned verbatim, the Aeneas `Funs.lean`
//! the extracted definition lives in, and a Rust parity test. An obligation
//! that is PRESENT but fails — a `sorry`, a vacuous statement, a signature
//! that is not the pinned one, a definition that is not in the extraction, a
//! parity test that does not exist — is refused, naming the obligation, and
//! the command exits non-zero. It is never quietly counted as "unproved": a
//! claim that does not hold is a defect, not a lower score (ADR 0007 A).
//!
//! # What this does not check
//!
//! It is static. It does not run `lake build` or `#print axioms`; those stay
//! the job of the Aeneas workflows, which build the proofs it points at.
//! "States the law" is checked as exact equality with a signature pinned by
//! review, so whether that signature says what the law's prose says is human
//! review. The body scan for `sorry`/`admit`/`native_decide` ends at the next
//! top-level declaration, which is a textual rule, not Lean's parser.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// The pinned decisions and laws.
pub const DECISIONS: &str = "ci/egress-decisions.toml";
/// The committed measurement `--check` holds the tree to.
pub const COMMITTED: &str = "ci/egress-proofs.json";

// ── The decisions file ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decisions {
    #[serde(default)]
    law: Vec<Law>,
    #[serde(default)]
    decision: Vec<Decision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Law {
    id: String,
    statement: String,
    /// `path::test_fn`, each an existing Rust test that would fail if the law
    /// broke. Empty only for a law whose code is not on main.
    #[serde(default)]
    falsifier: Vec<String>,
    status: Status,
}

/// A law's standing. A closed set, so a status that claims more than the
/// tree shows is a parse error or a refusal, never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum Status {
    #[serde(rename = "stated; enforced by Rust tests; not proved")]
    Stated,
    /// The law has no decision on main yet; the decision is added in the
    /// change that lands its code.
    #[serde(rename = "code not on main")]
    CodeNotOnMain,
    /// Every decision citing the law discharges its obligation for it.
    #[serde(rename = "proved")]
    Proved,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: String,
    #[serde(rename = "crate")]
    krate: String,
    file: String,
    /// `name`, or `Type::name` for a method.
    #[serde(rename = "fn")]
    function: String,
    laws: Vec<String>,
    #[serde(default)]
    obligation: Vec<Obligation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Obligation {
    law: String,
    lean: String,
    theorem: String,
    statement: String,
    extracted: String,
    lean_def: String,
    parity: String,
    parity_test: String,
}

impl Decision {
    /// The production function's own name, `name` of `Type::name`.
    fn name(&self) -> &str {
        self.function
            .rsplit_once("::")
            .map_or(self.function.as_str(), |(_, n)| n)
    }
}

// ── The file domain ──────────────────────────────────────────────────────────

/// The tracked files, and the text of every one the decisions file names.
pub struct Tree {
    tracked: BTreeSet<String>,
    files: BTreeMap<String, String>,
}

impl Tree {
    /// The tracked set from `git ls-files`, never a directory walk (a nested
    /// worktree reads as repo content), and the text of the decisions file
    /// and of every tracked file it names. A tracked file that cannot be read
    /// is "could not look", an error (ADR 0007 A-2).
    pub fn read(root: &Path) -> Result<Self> {
        let out = std::process::Command::new("git")
            .args(["ls-files", "-z"])
            .current_dir(root)
            .output()
            .context("running `git ls-files`")?;
        if !out.status.success() {
            bail!(
                "`git ls-files` failed; the file domain must come from git, not a directory walk"
            );
        }
        let tracked: BTreeSet<String> = String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        let mut files = BTreeMap::new();
        let read = |path: &str| -> Result<Option<String>> {
            match std::fs::read(root.join(path)) {
                Ok(b) => Ok(Some(String::from_utf8_lossy(&b).into_owned())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e).with_context(|| format!("reading {path}")),
            }
        };
        let Some(text) = tracked
            .contains(DECISIONS)
            .then(|| read(DECISIONS))
            .transpose()?
            .flatten()
        else {
            bail!("{DECISIONS} is not a tracked file; there is nothing to measure");
        };
        let parsed = parse(&text)?;
        files.insert(DECISIONS.to_string(), text);
        for path in referenced(&parsed) {
            if tracked.contains(&path)
                && let Some(t) = read(&path)?
            {
                files.insert(path, t);
            }
        }
        Ok(Self { tracked, files })
    }

    /// A tree from an in-memory corpus: every file given is tracked.
    #[cfg(test)]
    fn from_files(files: &[(&str, &str)]) -> Self {
        let files: BTreeMap<String, String> = files
            .iter()
            .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
            .collect();
        Self {
            tracked: files.keys().cloned().collect(),
            files,
        }
    }

    /// The text of a tracked file, or why there is none.
    fn text(&self, path: &str) -> Result<&str, String> {
        if !self.tracked.contains(path) {
            return Err(format!("{path} is not a tracked file"));
        }
        self.files
            .get(path)
            .map(String::as_str)
            .ok_or_else(|| format!("{path} is tracked but not in the worktree"))
    }
}

fn parse(text: &str) -> Result<Decisions> {
    toml::from_str(text).with_context(|| format!("parsing {DECISIONS}"))
}

/// Every path the decisions file names.
fn referenced(d: &Decisions) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for law in &d.law {
        for f in &law.falsifier {
            if let Some((path, _)) = f.rsplit_once("::") {
                out.insert(path.to_string());
            }
        }
    }
    for dec in &d.decision {
        out.insert(dec.file.clone());
        for o in &dec.obligation {
            out.extend([o.lean.clone(), o.extracted.clone(), o.parity.clone()]);
        }
    }
    out
}

// ── The measurement ──────────────────────────────────────────────────────────

/// What `egress-proofs` prints, and `ci/egress-proofs.json` pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Count {
    pub decisions: usize,
    pub proved: usize,
    pub pct: usize,
}

impl Count {
    fn new(decisions: usize, proved: usize) -> Self {
        Self {
            decisions,
            proved,
            pct: proved
                .saturating_mul(100)
                .checked_div(decisions)
                .unwrap_or(0),
        }
    }
}

fn rx(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("egress-proofs regex {pattern}: {e}"))
}

/// `fn <name>` as a whole word.
fn declares_fn(text: &str, name: &str) -> bool {
    rx(&format!(r"\bfn[ \t]+{}\b", regex::escape(name))).is_match(text)
}

/// `name` as a whole Rust identifier.
fn mentions(text: &str, name: &str) -> bool {
    rx(&format!(r"\b{}\b", regex::escape(name))).is_match(text)
}

/// Measure `tree`. Every problem found is reported, then the command fails:
/// a decision whose function is gone, a law nobody cites, an obligation that
/// does not hold. A clean tree yields the count.
pub fn measure(tree: &Tree) -> Result<Count> {
    let d = parse(tree.text(DECISIONS).map_err(anyhow::Error::msg)?)?;
    let mut problems: Vec<String> = Vec::new();

    let mut laws: BTreeMap<&str, &Law> = BTreeMap::new();
    for law in &d.law {
        if laws.insert(law.id.as_str(), law).is_some() {
            problems.push(format!("law {} is declared twice", law.id));
        }
        if law.statement.trim().is_empty() {
            problems.push(format!("law {} has no statement", law.id));
        }
        match (law.falsifier.is_empty(), law.status) {
            (true, Status::CodeNotOnMain) => {}
            (true, _) => problems.push(format!(
                "law {} names no falsifier; only a law whose code is not on main may",
                law.id
            )),
            (false, _) => {}
        }
        for f in &law.falsifier {
            match f.rsplit_once("::") {
                None => problems.push(format!(
                    "law {}: falsifier {f:?} is not `path::test_fn`",
                    law.id
                )),
                Some((path, test)) => match tree.text(path) {
                    Err(why) => problems.push(format!("law {}: falsifier {f}: {why}", law.id)),
                    Ok(text) if !declares_fn(text, test) => problems.push(format!(
                        "law {}: falsifier {f}: no `fn {test}` in {path}",
                        law.id
                    )),
                    Ok(_) => {}
                },
            }
        }
    }

    let mut ids = BTreeSet::new();
    let mut cited: BTreeSet<&str> = BTreeSet::new();
    let mut proved = 0usize;
    // law -> whether every citing decision discharged it.
    let mut law_discharged: BTreeMap<&str, bool> = BTreeMap::new();
    for dec in &d.decision {
        if !ids.insert(dec.id.as_str()) {
            problems.push(format!("decision {} is declared twice", dec.id));
        }
        decision_fn(tree, dec, &mut problems);
        if dec.laws.is_empty() {
            problems.push(format!("decision {} cites no law", dec.id));
        }
        for law in &dec.laws {
            cited.insert(law.as_str());
            match laws.get(law.as_str()) {
                None => problems.push(format!(
                    "decision {} cites {law}, which is not a law in {DECISIONS}",
                    dec.id
                )),
                Some(l) if l.status == Status::CodeNotOnMain => problems.push(format!(
                    "decision {} cites {law}, whose status says its code is not on main",
                    dec.id
                )),
                Some(_) => {}
            }
        }
        let mut by_law: BTreeMap<&str, &Obligation> = BTreeMap::new();
        for o in &dec.obligation {
            if !dec.laws.contains(&o.law) {
                problems.push(format!(
                    "decision {}: an obligation for {}, which the decision does not cite",
                    dec.id, o.law
                ));
            }
            if by_law.insert(o.law.as_str(), o).is_some() {
                problems.push(format!(
                    "decision {}: two obligations for {}",
                    dec.id, o.law
                ));
            }
            for why in obligation(tree, dec, o) {
                problems.push(format!(
                    "decision {} obligation {} ({}::{}): {why}",
                    dec.id, o.law, o.lean, o.theorem
                ));
            }
        }
        let all = dec.laws.iter().all(|l| by_law.contains_key(l.as_str()));
        for law in &dec.laws {
            let e = law_discharged.entry(law.as_str()).or_insert(true);
            *e &= by_law.contains_key(law.as_str());
        }
        if all {
            proved += 1;
        }
    }
    for law in &d.law {
        let is_cited = cited.contains(law.id.as_str());
        if !is_cited && law.status != Status::CodeNotOnMain {
            problems.push(format!(
                "law {} is cited by no decision; a law with no decision must say its code is not on main",
                law.id
            ));
        }
        if law.status == Status::Proved
            && !law_discharged
                .get(law.id.as_str())
                .copied()
                .unwrap_or(false)
        {
            problems.push(format!(
                "law {} says proved, but a decision citing it has no obligation for it",
                law.id
            ));
        }
    }

    if !problems.is_empty() {
        bail!(
            "{DECISIONS}: {} problem(s):\n  {}",
            problems.len(),
            problems.join("\n  ")
        );
    }
    Ok(Count::new(d.decision.len(), proved))
}

/// The decision's function exists in its file, and in its crate. A missing
/// function is an error, not an omission: the list would otherwise count a
/// decision that is no longer there.
fn decision_fn(tree: &Tree, dec: &Decision, problems: &mut Vec<String>) {
    if !dec.file.starts_with(&format!("crates/{}/", dec.krate)) {
        problems.push(format!(
            "decision {}: {} is not in crates/{}/",
            dec.id, dec.file, dec.krate
        ));
    }
    let text = match tree.text(&dec.file) {
        Ok(t) => t,
        Err(why) => {
            problems.push(format!("decision {}: {why}", dec.id));
            return;
        }
    };
    if !declares_fn(text, dec.name()) {
        problems.push(format!(
            "decision {}: no `fn {}` in {}",
            dec.id,
            dec.name(),
            dec.file
        ));
    }
    if let Some((ty, _)) = dec.function.rsplit_once("::")
        && !rx(&format!(r"\bimpl\b[^{{;]*\b{}\b", regex::escape(ty))).is_match(text)
    {
        problems.push(format!(
            "decision {}: no `impl {ty}` in {}",
            dec.id, dec.file
        ));
    }
}

/// A top-level declaration, at column 0: where the previous one's body ends.
static TOP_LEVEL: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?m)^(?:(?:theorem|lemma|def|abbrev|instance|structure|inductive|class|example|",
        r"axiom|opaque|noncomputable|private|protected|partial|unsafe|mutual|end|namespace|",
        r"section|open|variable|universe|set_option|attribute|import)\b|@\[|#|/-)"
    ))
});

/// An `axiom` declared in a proof file: anything follows from one.
static AXIOM_DECL: LazyLock<Regex> = LazyLock::new(|| {
    rx(r"(?m)^[ \t]*(?:@\[[^\]]*\][ \t]*)?(?:(?:private|protected|noncomputable)[ \t]+)*axiom[ \t]")
});

/// What may not appear in a proof body (comments removed).
static UNPROVED: LazyLock<Regex> = LazyLock::new(|| {
    rx(concat!(
        r"\b(",
        "so",
        "rry|ad",
        "mit|native",
        "_decide",
        r")\b"
    ))
});

/// Lean source with `--` line comments and `/- ... -/` block comments
/// (nested) removed. A `sorry` in a comment proves nothing and refutes
/// nothing.
fn strip_lean_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut depth, mut start) = (0usize, 0usize, 0usize);
    while i < b.len() {
        if b[i..].starts_with(b"/-") {
            if depth == 0 {
                out.push_str(&text[start..i]);
            }
            depth += 1;
            i += 2;
        } else if depth > 0 && b[i..].starts_with(b"-/") {
            depth -= 1;
            i += 2;
            if depth == 0 {
                out.push(' ');
                start = i;
            }
        } else if depth == 0 && b[i..].starts_with(b"--") {
            out.push_str(&text[start..i]);
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            start = i;
        } else {
            i += 1;
        }
    }
    if depth == 0 {
        out.push_str(&text[start..]);
    }
    out
}

fn normalise(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The theorem `name` in `text`: its signature (binders and type, between
/// the name and the `:=` at bracket depth 0) and its whole declaration text.
fn theorem<'a>(text: &'a str, name: &str) -> Result<(&'a str, &'a str), String> {
    let decl = rx(&format!(
        r"(?m)^[ \t]*(?:@\[[^\]]*\][ \t]*)?(?:(?:private|protected|nonrec)[ \t]+)*theorem[ \t]+{}(?:[ \t\r\n(\[{{:]|$)",
        regex::escape(name)
    ));
    let found: Vec<_> = decl.find_iter(text).collect();
    let m = match found.as_slice() {
        [] => return Err(format!("no `theorem {name}` in the proof file")),
        [m] => *m,
        _ => {
            return Err(format!(
                "`theorem {name}` is declared {} times",
                found.len()
            ));
        }
    };
    // The match may have consumed the character after the name.
    let name_end = text[m.start()..]
        .find(name)
        .map(|i| m.start() + i + name.len())
        .ok_or_else(|| format!("`theorem {name}`: the name is not in its own match"))?;
    let b = text.as_bytes();
    let mut depth = 0i32;
    let mut assign = None;
    let mut i = name_end;
    while i + 1 < b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b':' if depth == 0 && b[i + 1] == b'=' => {
                assign = Some(i);
                break;
            }
            _ => {}
        }
        i += 1;
    }
    let assign = assign.ok_or_else(|| format!("`theorem {name}` has no `:=`"))?;
    let body_start = assign + 2;
    let end = TOP_LEVEL
        .find_at(text, body_start)
        .map_or(text.len(), |n| n.start());
    Ok((&text[name_end..assign], &text[m.start()..end]))
}

/// Why `o` does not hold, if it does not: every reason, not the first.
fn obligation(tree: &Tree, dec: &Decision, o: &Obligation) -> Vec<String> {
    let mut why = Vec::new();

    // The proof.
    if !o.lean.ends_with(".lean") {
        why.push(format!("{} is not a Lean file", o.lean));
    }
    match tree.text(&o.lean) {
        Err(e) => why.push(e),
        Ok(text) => {
            if AXIOM_DECL.is_match(&strip_lean_comments(text)) {
                why.push(format!(
                    "{} declares an axiom; a theorem there may rest on it",
                    o.lean
                ));
            }
            match theorem(text, &o.theorem) {
                Err(e) => why.push(e),
                Ok((signature, declaration)) => {
                    if normalise(signature) != normalise(&o.statement) {
                        why.push(format!(
                            "the theorem's signature is `{}`, not the pinned statement `{}`",
                            normalise(signature),
                            normalise(&o.statement)
                        ));
                    }
                    let code = strip_lean_comments(declaration);
                    if let Some(m) = UNPROVED.find(&code) {
                        why.push(format!("the proof uses `{}`", m.as_str()));
                    }
                    if crate::exemplar_scoreboard::VACUOUS_LEAN.is_match(&code) {
                        why.push(
                            "the theorem is vacuous by the exemplar scoreboard's `vacuous_lean`"
                                .to_string(),
                        );
                    }
                }
            }
        }
    }
    let lean_name = rx(&format!(
        r"(?:^|[^A-Za-z0-9_.']){}(?:$|[^A-Za-z0-9_'])",
        regex::escape(&o.lean_def)
    ));
    if !lean_name.is_match(&o.statement) {
        why.push(format!(
            "the pinned statement does not mention `{}`, the extracted def",
            o.lean_def
        ));
    }

    // The extraction.
    if !o.extracted.ends_with("/Funs.lean") || !o.extracted.split('/').any(|c| c == "generated") {
        why.push(format!(
            "{} is not an Aeneas `generated/**/Funs.lean`",
            o.extracted
        ));
    }
    match tree.text(&o.extracted) {
        Err(e) => why.push(e),
        Ok(text) => {
            let def = rx(&format!(
                r"(?m)^[ \t]*(?:@\[[^\]]*\][ \t]*)?(?:(?:noncomputable|private|protected|partial|divergent|unsafe)[ \t]+)*def[ \t]+{}(?:[ \t\r\n(\[{{:]|$)",
                regex::escape(&o.lean_def)
            ));
            if !def.is_match(&strip_lean_comments(text)) {
                why.push(format!("no `def {}` in {}", o.lean_def, o.extracted));
            }
        }
    }

    // The parity test.
    match tree.text(&o.parity) {
        Err(e) => why.push(format!("parity: {e}")),
        Ok(text) => {
            if !declares_fn(text, &o.parity_test) {
                why.push(format!("parity: no `fn {}` in {}", o.parity_test, o.parity));
            }
            if !mentions(text, dec.name()) {
                why.push(format!(
                    "parity: {} does not mention `{}`, the production fn",
                    o.parity,
                    dec.name()
                ));
            }
        }
    }
    why
}

// ── The command ──────────────────────────────────────────────────────────────

/// Hold `measured` to the committed pin, both directions.
fn check(measured: Count, committed: &str) -> Result<()> {
    let pinned: Count =
        serde_json::from_str(committed).with_context(|| format!("parsing {COMMITTED}"))?;
    if pinned != measured {
        bail!(
            "{COMMITTED} pins {} but the tree measures {}: a rise or a fall is an edit to \
             {COMMITTED} in the change that makes it",
            serde_json::to_string(&pinned)?,
            serde_json::to_string(&measured)?
        );
    }
    Ok(())
}

/// `cargo xtask egress-proofs [--check]`.
pub fn run(root: &Path, check_pin: bool) -> Result<()> {
    let count = measure(&Tree::read(root)?)?;
    println!("{}", serde_json::to_string(&count)?);
    if check_pin {
        let committed = std::fs::read_to_string(root.join(COMMITTED))
            .with_context(|| format!("reading {COMMITTED}"))?;
        check(count, &committed)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "egress_proofs_tests.rs"]
mod tests;
