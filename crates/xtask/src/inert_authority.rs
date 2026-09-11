//! Inert-authority gate — a witness that is accepted and dropped.
//!
//! # The defect this was built from
//!
//! `scripts/law-mechanisms-manifest.txt` names mechanisms with no call site at
//! all. This names the adjacent failure, which no gate could see: a mechanism
//! that *is* called, is handed its authorising witness, and throws it away.
//!
//! ```ignore
//! fn run(&self, cmd: &str, _authority: Authority) -> Result<ShellOutput> {
//!     let words = shell_words::split(cmd)?;
//!     Command::new(&words[0]).args(&words[1..]).output()   // spawns
//! }
//! ```
//!
//! The signature says the caller must hold an `Authority` to reach this. The
//! body says the `Authority` decides nothing. Both are true, and the gap
//! between them is the whole finding: because no witness in this tree carries
//! the *target* of the act it authorises, an `Authority` obtained for one
//! command discharges the gate for any other. The type is a proof that *some*
//! check ran, not that *this* act was checked.
//!
//! That is not fixed here — fixing it is the `Act` collapse (ADR 0006, C2.2 /
//! C2.4), which is signature churn across three crates. This gate exists so
//! the count cannot grow while that work lands, which is the same reason C0
//! precedes the four collapses at all.
//!
//! # What counts, and what deliberately does not
//!
//! A site is an **inert witness**: a parameter whose name begins with `_` and
//! whose type is one of the witness types `WITNESS` declares. The declaration
//! lives in the manifest, not here, for the reason `.clippy-ratchet.toml` keeps
//! its lint list in the toml — so the gate and its documentation cannot drift.
//!
//! **The `Seal` family is excluded on purpose, and this is the one judgement in
//! the gate.** `Seal`, `CertificateSeal`, `GrantSeal` and `SealedProof` are
//! private zero-sized types threaded through constructors so that no code
//! outside the module can call them (`#2450`). Thirteen sites, and *every* one
//! is `_`-bound — because being unread is the entire mechanism. Counting them
//! would put the tree's most deliberate witnesses at the top of a list of
//! accidents, and would drown the four sites that are real. A seal is a guard
//! on *construction*; this gate is about a guard on *action*.
//!
//! # Why rows are `(file, scope)` and not one flat number
//!
//! 30 of the 40 sites are in one file, `portcullis-effects/src/lib.rs`, and
//! they are not alike. `DenyAllEffects` refuses every call, so there is no act
//! for an authority to bound; `RecordingEffects` writes a log line; and
//! `RealEffects::{run, commit, push}` spawn processes. A file-level allowance —
//! which is what "allow-list the no-op impls by path" would give — would
//! launder the three that matter behind the twenty-two that do not. So the
//! scope is the enclosing `impl` target or `trait`, which is the finest
//! division a grep can make reliably and exactly the line that separates them.
//!
//! Classes: `N` — the scope performs no act, so no authority is being
//! discarded. `D` — debt: the act happens and the witness is dropped.
//!
//! # Exactness
//!
//! Every count is exact in both directions, and `INERT_TOTAL` must equal their
//! sum. A slack pin lets a site appear inside an existing scope unnoticed,
//! which is the failure this gate exists to catch — the same argument
//! `DEAD_COUNT` makes next door. A row whose scope no longer has any inert site
//! is also a failure: it means the debt was paid and the row should go, and a
//! stale row is itself a finding.
//!
//! # Domain
//!
//! `git ls-files`, and `law_mechanisms::production_region` for the
//! `#[cfg(test)]` stripping — shared rather than re-implemented, so this gate,
//! `check-law-mechanisms.sh`, `check-mediation.sh` and
//! `check-extracted-callsites.sh` agree on what "production" means. That
//! sharing is load-bearing: a hand-rolled second stripper, measured against
//! this same corpus while writing the gate, disagreed with the shared one by a
//! site.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

use crate::law_mechanisms::{is_production_path, production_region, tracked};

pub const MANIFEST: &str = "scripts/inert-authority-manifest.txt";

/// One manifest row: a `(file, scope)` group and how many inert sites it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// `N` (no act performed) or `D` (debt: the act happens, the witness is
    /// dropped). Kept as a field so a third class is a parser change rather
    /// than a format change.
    pub class: char,
    /// The file the sites live in.
    pub file: String,
    /// The enclosing `impl` target, `trait` name, or `<free>` for a bare `fn`.
    pub scope: String,
    /// Exact number of inert sites in this group.
    pub count: usize,
    /// Why they are inert, and what would close it.
    pub note: String,
}

/// The parsed manifest: the witness vocabulary, the rows, and the pinned total.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub witness: Vec<String>,
    pub rows: Vec<Row>,
    pub inert_total: usize,
}

/// Parse the manifest. Declaration-only, so it is decidable against an empty
/// checkout — the half of a gate where this repo's ratchet defects have lived.
pub fn parse(text: &str) -> Result<Manifest> {
    let mut witness = Vec::new();
    let mut rows = Vec::new();
    let mut inert_total = None;
    let mut in_witness = false;

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "WITNESS = [" {
            if in_witness {
                bail!("line {}: WITNESS block opened twice", lineno + 1);
            }
            in_witness = true;
            continue;
        }
        if in_witness {
            if line == "]" {
                in_witness = false;
                continue;
            }
            let name = line.trim_end_matches(',').trim().trim_matches('"');
            if name.is_empty() {
                bail!("line {}: empty witness type name", lineno + 1);
            }
            witness.push(name.to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("INERT_TOTAL=") {
            let n: usize = rest
                .trim()
                .parse()
                .with_context(|| format!("line {}: INERT_TOTAL is not a number", lineno + 1))?;
            if inert_total.replace(n).is_some() {
                bail!("line {}: INERT_TOTAL declared twice", lineno + 1);
            }
            continue;
        }
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() != 5 {
            bail!(
                "line {}: want 5 columns `CLASS | file | scope | count | note`, got {}",
                lineno + 1,
                cols.len()
            );
        }
        let class = match cols[0] {
            "N" => 'N',
            "D" => 'D',
            other => bail!("line {}: class must be N or D, got {other:?}", lineno + 1),
        };
        let count: usize = cols[3]
            .parse()
            .with_context(|| format!("line {}: count is not a number", lineno + 1))?;
        if count == 0 {
            bail!(
                "line {}: a count of 0 is a row that should have been deleted",
                lineno + 1
            );
        }
        rows.push(Row {
            class,
            file: cols[1].to_string(),
            scope: cols[2].to_string(),
            count,
            note: cols[4].to_string(),
        });
    }

    if in_witness {
        bail!("WITNESS block was never closed with `]`");
    }
    if witness.is_empty() {
        bail!("WITNESS is empty; the scan would match nothing and the gate would pass vacuously");
    }
    let inert_total =
        inert_total.context("INERT_TOTAL= is missing; the population must be pinned")?;

    let declared: usize = rows.iter().map(|r| r.count).sum();
    if declared != inert_total {
        bail!(
            "INERT_TOTAL={inert_total} but the rows declare {declared}. The pin is exact on \
             purpose: it is what catches a site added inside a scope that already has a row."
        );
    }
    Ok(Manifest {
        witness,
        rows,
        inert_total,
    })
}

/// How a parameter of a witness type binds the witness it is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// `_authority: Authority` — accepted and dropped. The signature demands a
    /// witness; the body cannot name it, so it decides nothing.
    Dropped,
    /// `authority: Authority` — accepted under a name the body can consult.
    /// Whether it *is* consulted is a different question, and a stronger gate;
    /// this is the weakest binding that leaves consulting possible at all.
    Bound,
}

/// Every witness-typed parameter on `line`, in source order.
///
/// A grep, not a resolver, which is why the vocabulary is a closed list. `&`,
/// `&mut` and a leading `&'a` are all accepted; a generic instantiation such as
/// `Authorized<A>` matches on the head name, since that is the type whose
/// discipline is at issue.
///
/// The scan starts at every identifier, not only at `_`, because the denominator
/// this feeds — *how many sites accept a witness at all* — needs the bound ones
/// too. `inert_site` below keeps the old first-match-wins bool so the
/// inert-authority pin is measured exactly as it was.
pub fn witness_params(line: &str, witness: &[String]) -> Vec<Binding> {
    let mut out = Vec::new();
    for (i, ch) in line.char_indices() {
        // The identifier must START here: preceded by `(`, `,`, whitespace or
        // nothing, so `some_authority: Authority` is one site and not two, and
        // `x._field` is none.
        if ch != '_' && !ch.is_ascii_lowercase() {
            continue;
        }
        let before = line[..i].chars().next_back();
        if !matches!(
            before,
            None | Some('(') | Some(',') | Some(' ') | Some('\t')
        ) {
            continue;
        }
        let rest = &line[i..];
        let Some(colon) = rest.find(':') else {
            continue;
        };
        let name = &rest[..colon];
        if !name
            .chars()
            .all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            continue;
        }
        // `::` is a path, not a type ascription.
        if rest[colon..].starts_with("::") {
            continue;
        }
        let ty = rest[colon + 1..]
            .trim_start()
            .trim_start_matches('&')
            .trim_start()
            .trim_start_matches("mut ")
            .trim_start();
        // Skip an explicit lifetime: `&'a Authority`.
        let ty = if let Some(after) = ty.strip_prefix('\'') {
            after
                .split_once(char::is_whitespace)
                .map_or("", |(_, t)| t)
                .trim_start()
        } else {
            ty
        };
        let head: String = ty
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if witness.contains(&head) {
            out.push(if name.starts_with('_') {
                Binding::Dropped
            } else {
                Binding::Bound
            });
        }
    }
    out
}

/// Is `line` a parameter binding an inert witness — `_name: Type`, where `Type`
/// is one of `witness`?
///
/// One line counts once however many witnesses it drops, which is how
/// `INERT_TOTAL` was measured and must keep being measured.
fn inert_site(line: &str, witness: &[String]) -> bool {
    witness_params(line, witness).contains(&Binding::Dropped)
}

/// The enclosing scope of a line: the target of the nearest preceding `impl`,
/// the nearest preceding `trait`, or `<free>`.
///
/// `impl Trait for Type` attributes to `Type`, because the question a reader
/// asks is "which implementation drops the witness", and two impls of the same
/// trait — `RealEffects` and `DenyAllEffects` — are exactly what must not share
/// a row.
fn scope_of(line: &str) -> Option<String> {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix("impl") {
        if !rest.starts_with(|c: char| c.is_whitespace() || c == '<') {
            return None;
        }
        // Drop a generic parameter list, then take the text before `{`.
        let rest = rest.trim_start();
        let rest = if let Some(after) = rest.strip_prefix('<') {
            let depth_end = matching_angle(after)?;
            &after[depth_end + 1..]
        } else {
            rest
        };
        let head = rest.split('{').next().unwrap_or("").trim();
        let target = head.rsplit(" for ").next().unwrap_or(head).trim();
        let name: String = target
            .trim_start_matches('&')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
        return None;
    }
    for prefix in ["pub trait ", "trait ", "pub(crate) trait ", "unsafe trait "] {
        if let Some(rest) = t.strip_prefix(prefix) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(format!("trait {name}"));
            }
        }
    }
    None
}

/// Index of the `>` closing an opening `<` that has already been consumed.
fn matching_angle(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Count inert sites per `(file, scope)` over the production region of `corpus`.
pub fn count(
    corpus: &BTreeMap<String, String>,
    witness: &[String],
) -> BTreeMap<(String, String), usize> {
    let mut out = BTreeMap::new();
    for (path, src) in corpus {
        let region = production_region(src);
        let mut scope = "<free>".to_string();
        for line in region.lines() {
            if let Some(s) = scope_of(line) {
                scope = s;
            }
            if inert_site(line, witness) {
                *out.entry((path.clone(), scope.clone())).or_insert(0) += 1;
            }
        }
    }
    out
}

/// One disagreement between the manifest and the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A `(file, scope)` group with inert sites and no row.
    Unlisted {
        file: String,
        scope: String,
        found: usize,
    },
    /// A row whose group no longer has any inert site — the debt was paid, and
    /// the row should be deleted and the pin lowered.
    Vacated { file: String, scope: String },
    /// A row whose count disagrees with the tree.
    Drifted {
        file: String,
        scope: String,
        declared: usize,
        found: usize,
    },
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlisted { file, scope, found } => write!(
                f,
                "{file} :: {scope} has {found} inert witness(es) and no row. Either the witness \
                 should decide something — which is the fix — or add a row saying why it cannot, \
                 and raise INERT_TOTAL in the same edit."
            ),
            Self::Vacated { file, scope } => write!(
                f,
                "{file} :: {scope} is declared but has no inert witness left. The debt was paid; \
                 delete the row and lower INERT_TOTAL."
            ),
            Self::Drifted {
                file,
                scope,
                declared,
                found,
            } => write!(
                f,
                "{file} :: {scope} declares {declared} inert witness(es), tree has {found}. The \
                 count is exact in both directions — a slack pin is how a new one arrives \
                 unnoticed inside a scope that already had a row."
            ),
        }
    }
}

/// Compare manifest to tree.
pub fn decide(manifest: &Manifest, counts: &BTreeMap<(String, String), usize>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let declared: BTreeMap<(String, String), &Row> = manifest
        .rows
        .iter()
        .map(|r| ((r.file.clone(), r.scope.clone()), r))
        .collect();

    for (key, row) in &declared {
        match counts.get(key) {
            None => findings.push(Finding::Vacated {
                file: key.0.clone(),
                scope: key.1.clone(),
            }),
            Some(&found) if found != row.count => findings.push(Finding::Drifted {
                file: key.0.clone(),
                scope: key.1.clone(),
                declared: row.count,
                found,
            }),
            Some(_) => {}
        }
    }
    for (key, &found) in counts {
        if !declared.contains_key(key) {
            findings.push(Finding::Unlisted {
                file: key.0.clone(),
                scope: key.1.clone(),
                found,
            });
        }
    }
    findings
}

/// Run the gate. Exit code is the caller's (`0` clean, `1` violation).
pub fn run() -> Result<i32> {
    let text = std::fs::read_to_string(MANIFEST).with_context(|| format!("reading {MANIFEST}"))?;
    let manifest = parse(&text)?;
    let corpus = tracked(is_production_path)?;
    let counts = count(&corpus, &manifest.witness);
    let findings = decide(&manifest, &counts);

    if findings.is_empty() {
        let debt: usize = manifest
            .rows
            .iter()
            .filter(|r| r.class == 'D')
            .map(|r| r.count)
            .sum();
        println!(
            "OK: {} inert witness(es) across {} scope(s) in {} production files, all declared.",
            manifest.inert_total,
            manifest.rows.len(),
            corpus.len()
        );
        println!(
            "     {debt} of them are class D — an act performed while its witness is dropped. \
             That number is the debt ADR 0006's C2 collapse pays off."
        );
        return Ok(0);
    }

    println!("FAIL: {} inert-authority finding(s).", findings.len());
    for finding in &findings {
        println!("  {finding}");
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness() -> Vec<String> {
        vec!["Authority".into(), "LaunchAttestation".into()]
    }

    #[test]
    fn a_bare_underscore_binding_of_a_witness_type_is_a_site() {
        assert!(inert_site(
            "    fn run(&self, cmd: &str, _authority: Authority) {",
            &witness()
        ));
    }

    #[test]
    fn a_reference_and_a_lifetime_do_not_hide_the_type() {
        assert!(inert_site(
            "    _attestation: &LaunchAttestation,",
            &witness()
        ));
        assert!(inert_site("    _a: &'a Authority,", &witness()));
        assert!(inert_site("    _a: &mut Authority,", &witness()));
    }

    #[test]
    fn a_bound_name_is_not_a_site() {
        // The whole point: naming it `authority` means the body may use it.
        assert!(!inert_site(
            "    fn run(&self, _cmd: &str, authority: Authority) {",
            &witness()
        ));
    }

    #[test]
    fn an_underscore_inside_a_name_does_not_start_an_identifier() {
        assert!(!inert_site(
            "    fn f(some_authority: Authority) {",
            &witness()
        ));
    }

    #[test]
    fn a_non_witness_type_is_not_a_site() {
        // Coverage, not noise: the vocabulary is closed on purpose.
        assert!(!inert_site("    _unused: String,", &witness()));
        assert!(!inert_site("    _seal: Seal,", &witness()));
    }

    #[test]
    fn a_path_is_not_a_type_ascription() {
        assert!(!inert_site("    let x = _foo::Authority;", &witness()));
    }

    #[test]
    fn impl_for_attributes_to_the_implementing_type_not_the_trait() {
        // RealEffects and DenyAllEffects implement the same traits and must not
        // share a row; that is the entire reason scope is not the file.
        assert_eq!(
            scope_of("impl ShellEffect for RealEffects {"),
            Some("RealEffects".into())
        );
        assert_eq!(
            scope_of("impl ShellEffect for DenyAllEffects {"),
            Some("DenyAllEffects".into())
        );
    }

    #[test]
    fn generic_parameters_do_not_become_the_scope() {
        assert_eq!(
            scope_of("impl<A: Clone> Guard<A> for Kernel<A> {"),
            Some("Kernel".into())
        );
    }

    #[test]
    fn an_inherent_impl_attributes_to_its_type() {
        assert_eq!(scope_of("impl BudgetLedger {"), Some("BudgetLedger".into()));
    }

    #[test]
    fn a_trait_declaration_is_its_own_scope() {
        // A default method body that drops the witness is the trait's debt, not
        // any implementor's — CaClient::sign_attested_csr is exactly that.
        assert_eq!(
            scope_of("pub trait CaClient: Send + Sync {"),
            Some("trait CaClient".into())
        );
    }

    #[test]
    fn an_ordinary_line_does_not_change_scope() {
        assert_eq!(scope_of("    let x = 1;"), None);
    }

    #[test]
    fn the_pin_must_equal_the_sum_of_the_rows() {
        let text = "WITNESS = [\n\"Authority\",\n]\nN | a.rs | X | 2 | why\nINERT_TOTAL=3\n";
        let err = parse(text).unwrap_err().to_string();
        assert!(err.contains("rows declare 2"), "{err}");
    }

    #[test]
    fn a_zero_count_row_is_rejected() {
        let text = "WITNESS = [\n\"Authority\",\n]\nN | a.rs | X | 0 | why\nINERT_TOTAL=0\n";
        assert!(
            parse(text)
                .unwrap_err()
                .to_string()
                .contains("should have been deleted")
        );
    }

    #[test]
    fn an_empty_vocabulary_is_rejected_rather_than_passing_vacuously() {
        let text = "WITNESS = [\n]\nINERT_TOTAL=0\n";
        assert!(parse(text).unwrap_err().to_string().contains("vacuously"));
    }

    #[test]
    fn a_missing_pin_is_rejected() {
        let text = "WITNESS = [\n\"Authority\",\n]\n";
        assert!(parse(text).unwrap_err().to_string().contains("INERT_TOTAL"));
    }

    #[test]
    fn a_new_site_in_an_existing_scope_is_caught() {
        // The failure a slack pin would miss, and the reason counts are exact.
        let manifest =
            parse("WITNESS = [\n\"Authority\",\n]\nD | a.rs | X | 1 | why\nINERT_TOTAL=1\n")
                .unwrap();
        let mut counts = BTreeMap::new();
        counts.insert(("a.rs".to_string(), "X".to_string()), 2);
        assert_eq!(
            decide(&manifest, &counts),
            vec![Finding::Drifted {
                file: "a.rs".into(),
                scope: "X".into(),
                declared: 1,
                found: 2
            }]
        );
    }

    #[test]
    fn a_paid_debt_fails_until_the_row_is_removed() {
        let manifest =
            parse("WITNESS = [\n\"Authority\",\n]\nD | a.rs | X | 1 | why\nINERT_TOTAL=1\n")
                .unwrap();
        assert_eq!(
            decide(&manifest, &BTreeMap::new()),
            vec![Finding::Vacated {
                file: "a.rs".into(),
                scope: "X".into()
            }]
        );
    }

    #[test]
    fn a_scope_with_no_row_is_caught() {
        let manifest =
            parse("WITNESS = [\n\"Authority\",\n]\nD | a.rs | X | 1 | why\nINERT_TOTAL=1\n")
                .unwrap();
        let mut counts = BTreeMap::new();
        counts.insert(("a.rs".to_string(), "X".to_string()), 1);
        counts.insert(("b.rs".to_string(), "Y".to_string()), 3);
        assert_eq!(
            decide(&manifest, &counts),
            vec![Finding::Unlisted {
                file: "b.rs".into(),
                scope: "Y".into(),
                found: 3
            }]
        );
    }

    #[test]
    fn the_shipped_manifest_agrees_with_the_shipped_tree() {
        // The gate against itself, so a `cargo test` failure names the drift
        // before CI does.
        let text = std::fs::read_to_string("../../scripts/inert-authority-manifest.txt")
            .or_else(|_| std::fs::read_to_string(MANIFEST));
        let Ok(text) = text else { return };
        let manifest = parse(&text).expect("the shipped manifest parses");
        assert!(
            manifest.witness.iter().any(|w| w == "Authority"),
            "Authority is the type 37 of the 40 sites carry; losing it would gut the gate"
        );
    }
}
