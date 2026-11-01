//! `egress-proofs` over in-memory trees. Each refusal was driven red against
//! a counter that accepted everything before its rule was written (A-19).
//!
//! The Lean payloads that are themselves the shapes other gates scan for
//! (`sorry`, `native_decide`, `by trivial`) are assembled with `concat!`, so
//! this file is not a hit for them.

use super::*;

const SRC: &str = "crates/c/src/lib.rs";
const LEAN: &str = "crates/c/lean/Proofs.lean";
const FUNS: &str = "crates/c/lean/generated/C/Funs.lean";
const PARITY: &str = "crates/c/tests/parity.rs";

const STATEMENT: &str = "(x : U8) : c.decide x = ok x";

/// One honest decision, one law, every obligation in place. Each test
/// changes exactly one file of it.
struct Fixture {
    decisions: String,
    src: String,
    lean: String,
    funs: String,
    parity: String,
}

fn law(id: &str, falsifier: &str, status: &str) -> String {
    format!(
        "[[law]]\nid = \"{id}\"\nstatement = \"the decision decides\"\n\
         falsifier = [{falsifier}]\nstatus = \"{status}\"\n\n"
    )
}

const STATED: &str = "stated; enforced by Rust tests; not proved";

fn decision(obligation: &str) -> String {
    format!(
        "[[decision]]\nid = \"decide\"\ncrate = \"c\"\nfile = \"{SRC}\"\nfn = \"decide\"\n\
         laws = [\"Pa.Egress.1.L1\"]\n{obligation}\n"
    )
}

fn obligation_toml(statement: &str) -> String {
    format!(
        "[[decision.obligation]]\nlaw = \"Pa.Egress.1.L1\"\nlean = \"{LEAN}\"\n\
         theorem = \"decide_law\"\nstatement = \"{statement}\"\nextracted = \"{FUNS}\"\n\
         lean_def = \"c.decide\"\nparity = \"{PARITY}\"\nparity_test = \"decide_matches_lean\"\n"
    )
}

impl Fixture {
    fn honest() -> Self {
        Self {
            decisions: law("Pa.Egress.1.L1", &format!("\"{SRC}::law_test\""), STATED)
                + &decision(&obligation_toml(STATEMENT)),
            src: "pub fn decide(x: u8) -> u8 {\n    x\n}\n\n#[test]\nfn law_test() {}\n".into(),
            lean: format!(
                "import C.Funs\n\n/-- The law. -/\ntheorem decide_law {STATEMENT} := by\n  \
                 simp [c.decide]\n\ntheorem other : 1 = 1 := rfl\n"
            ),
            funs: "namespace c\n\ndef c.decide (x : U8) : Result U8 :=\n  ok x\n\nend c\n".into(),
            parity: "#[test]\nfn decide_matches_lean() {\n    assert_eq!(c::decide(1), 1);\n}\n"
                .into(),
        }
    }

    fn tree(&self) -> Tree {
        Tree::from_files(&[
            (DECISIONS, &self.decisions),
            (SRC, &self.src),
            (LEAN, &self.lean),
            (FUNS, &self.funs),
            (PARITY, &self.parity),
        ])
    }

    fn measure(&self) -> Result<Count> {
        measure(&self.tree())
    }

    /// The refusal's text, which must name the obligation.
    fn refused(&self) -> String {
        let err = format!("{:#}", self.measure().expect_err("must be refused"));
        assert!(
            err.contains("decision decide obligation Pa.Egress.1.L1"),
            "a refusal names the obligation: {err}"
        );
        err
    }
}

#[test]
fn an_honest_fixture_counts_one_of_one() {
    assert_eq!(
        Fixture::honest().measure().unwrap(),
        Count {
            decisions: 1,
            proved: 1,
            pct: 100
        }
    );
}

#[test]
fn a_decision_with_no_obligation_is_counted_and_not_proved() {
    let mut f = Fixture::honest();
    f.decisions = law("Pa.Egress.1.L1", &format!("\"{SRC}::law_test\""), STATED) + &decision("");
    assert_eq!(
        f.measure().unwrap(),
        Count {
            decisions: 1,
            proved: 0,
            pct: 0
        }
    );
}

#[test]
fn a_sorried_theorem_is_refused() {
    let mut f = Fixture::honest();
    f.lean = f.lean.replace("simp [c.decide]", concat!("so", "rry"));
    assert!(f.refused().contains(concat!("so", "rry")));
    let mut f = Fixture::honest();
    f.lean = f
        .lean
        .replace("simp [c.decide]", concat!("native", "_decide"));
    assert!(f.refused().contains(concat!("native", "_decide")));
}

#[test]
fn a_sorry_in_a_comment_or_a_later_declaration_is_not_this_proof() {
    let mut f = Fixture::honest();
    f.lean = f.lean.replace(
        "simp [c.decide]",
        concat!("simp [c.decide] -- no so", "rry here"),
    );
    f.lean
        .push_str(concat!("\ntheorem later : 2 = 2 := by\n  so", "rry\n"));
    assert_eq!(f.measure().unwrap().proved, 1);
}

#[test]
fn a_vacuous_theorem_is_refused() {
    let mut f = Fixture::honest();
    f.lean = f
        .lean
        .replace(":= by\n  simp [c.decide]", concat!(":= by tri", "vial"));
    assert!(f.refused().contains("vacuous"));
}

#[test]
fn an_axiom_in_the_proof_file_is_refused() {
    let mut f = Fixture::honest();
    f.lean = f
        .lean
        .replace("import C.Funs\n", "import C.Funs\n\naxiom cheat : False\n");
    assert!(f.refused().contains("axiom"));
}

#[test]
fn a_statement_mismatch_is_refused() {
    let mut f = Fixture::honest();
    f.lean = f.lean.replace("= ok x", "= ok 0");
    assert!(f.refused().contains("signature"));
    // Whitespace is not a mismatch.
    let mut f = Fixture::honest();
    f.lean = f
        .lean
        .replace("(x : U8) : c.decide", "(x : U8)\n    : c.decide");
    assert_eq!(f.measure().unwrap().proved, 1);
    // A pinned statement that does not mention the extracted def is no
    // statement about it.
    let mut f = Fixture::honest();
    f.decisions = law("Pa.Egress.1.L1", &format!("\"{SRC}::law_test\""), STATED)
        + &decision(&obligation_toml("(x : U8) : x = x"));
    f.lean = f.lean.replace(STATEMENT, "(x : U8) : x = x");
    assert!(f.refused().contains("does not mention"));
}

#[test]
fn a_missing_theorem_is_refused() {
    let mut f = Fixture::honest();
    f.lean = f.lean.replace("decide_law", "decide_law_renamed");
    assert!(f.refused().contains("no `theorem decide_law`"));
}

#[test]
fn a_missing_parity_test_is_refused() {
    let mut f = Fixture::honest();
    f.parity = f.parity.replace("decide_matches_lean", "something_else");
    assert!(f.refused().contains("parity"));
    // A parity test that never calls the production fn is not a parity test.
    let mut f = Fixture::honest();
    f.parity = f.parity.replace("c::decide(1)", "1");
    assert!(f.refused().contains("does not mention `decide`"));
}

#[test]
fn a_missing_extracted_def_is_refused() {
    let mut f = Fixture::honest();
    f.funs = f.funs.replace("def c.decide", "def c.other");
    assert!(f.refused().contains("no `def c.decide`"));
}

#[test]
fn an_extraction_outside_generated_is_refused() {
    let mut f = Fixture::honest();
    let moved = "crates/c/lean/C/Funs.lean";
    f.decisions = f.decisions.replace(FUNS, moved);
    let t = Tree::from_files(&[
        (DECISIONS, &f.decisions),
        (SRC, &f.src),
        (LEAN, &f.lean),
        (moved, &f.funs),
        (PARITY, &f.parity),
    ]);
    let err = format!("{:#}", measure(&t).unwrap_err());
    assert!(err.contains("generated/"), "{err}");
}

#[test]
fn an_untracked_proof_file_is_refused() {
    let f = Fixture::honest();
    let t = Tree::from_files(&[
        (DECISIONS, &f.decisions),
        (SRC, &f.src),
        (FUNS, &f.funs),
        (PARITY, &f.parity),
    ]);
    let err = format!("{:#}", measure(&t).unwrap_err());
    assert!(
        err.contains(&format!("{LEAN} is not a tracked file")),
        "{err}"
    );
}

#[test]
fn a_missing_decision_fn_is_an_error() {
    let mut f = Fixture::honest();
    f.src = f.src.replace("pub fn decide(", "pub fn decided(");
    let err = format!("{:#}", f.measure().unwrap_err());
    assert!(err.contains("no `fn decide`"), "{err}");
    // A method must sit in an impl of its type.
    let mut f = Fixture::honest();
    f.decisions = f
        .decisions
        .replace("fn = \"decide\"", "fn = \"Table::decide\"");
    let err = format!("{:#}", f.measure().unwrap_err());
    assert!(err.contains("no `impl Table`"), "{err}");
}

#[test]
fn every_law_is_cited_or_says_its_code_is_not_on_main() {
    let mut f = Fixture::honest();
    f.decisions = law("Pa.Egress.1.L2", "", STATED) + &f.decisions;
    let err = format!("{:#}", f.measure().unwrap_err());
    assert!(
        err.contains("law Pa.Egress.1.L2 is cited by no decision"),
        "{err}"
    );

    let mut f = Fixture::honest();
    f.decisions = law("Pa.Egress.1.L2", "", "code not on main") + &f.decisions;
    assert_eq!(f.measure().unwrap().proved, 1);

    let mut f = Fixture::honest();
    f.decisions = f
        .decisions
        .replace("Pa.Egress.1.L1\"]", "Pa.Egress.1.L9\"]");
    let err = format!("{:#}", f.measure().unwrap_err());
    assert!(
        err.contains("cites Pa.Egress.1.L9, which is not a law"),
        "{err}"
    );
}

#[test]
fn a_falsifier_that_is_not_a_test_in_the_tree_is_refused() {
    let mut f = Fixture::honest();
    f.src = f.src.replace("fn law_test", "fn law_test_gone");
    let err = format!("{:#}", f.measure().unwrap_err());
    assert!(err.contains("no `fn law_test`"), "{err}");
}

#[test]
fn a_law_claiming_proved_without_the_obligation_is_refused() {
    let mut f = Fixture::honest();
    f.decisions = law("Pa.Egress.1.L1", &format!("\"{SRC}::law_test\""), "proved") + &decision("");
    let err = format!("{:#}", f.measure().unwrap_err());
    assert!(err.contains("says proved"), "{err}");
    let mut f = Fixture::honest();
    f.decisions = f.decisions.replace(STATED, "proved");
    assert_eq!(f.measure().unwrap().proved, 1);
}

#[test]
fn check_refuses_a_pin_that_disagrees_in_either_direction() {
    let measured = Count::new(8, 1);
    assert_eq!(measured.pct, 12, "floor(100 * 1 / 8)");
    check(measured, r#"{"decisions": 8, "proved": 1, "pct": 12}"#).unwrap();
    let below = check(measured, r#"{"decisions": 8, "proved": 0, "pct": 0}"#);
    assert!(format!("{:#}", below.unwrap_err()).contains("pins"));
    let above = check(measured, r#"{"decisions": 8, "proved": 2, "pct": 25}"#);
    assert!(format!("{:#}", above.unwrap_err()).contains("pins"));
    let population = check(measured, r#"{"decisions": 9, "proved": 1, "pct": 11}"#);
    assert!(population.is_err());
    let extra = check(
        measured,
        r#"{"decisions": 8, "proved": 1, "pct": 12, "note": "x"}"#,
    );
    assert!(extra.is_err(), "an unknown key is not the pin");
    assert_eq!(Count::new(0, 0).pct, 0);
}
