//! IFC Demo: 4 scenarios showing information flow control for AI agents.
//!
//! Run with: cargo run -p nucleus-ifc --example ifc_demo

use nucleus_ifc::{FlowTracker, NodeKind, SafetyCheck};

fn main() {
    println!("═══ Nucleus IFC Demo ═══\n");

    // Scenario 1: Web injection blocked
    scenario_web_injection();

    // Scenario 2: Clean workflow allowed
    scenario_clean_workflow();

    // Scenario 3: Compartment transition
    scenario_compartment_transition();

    // Scenario 4: DeterministicBind (model excluded)
    scenario_deterministic_bind();

    println!("\n═══ All scenarios passed ═══");
}

fn scenario_web_injection() {
    println!("─── Scenario 1: Web injection blocked ───");

    let mut t = FlowTracker::new();

    // Agent searches the web. A malicious page has hidden instructions.
    let web = t.observe(NodeKind::WebContent).unwrap();
    println!("  WebContent observed (Adversarial integrity)");

    // Model reads the web content (taint propagates).
    let plan = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();
    println!("  ModelPlan inherits Adversarial from WebContent");

    // Agent tries to write a file based on web-derived data.
    let check = t.check_safety(&[plan], true);
    assert!(check.is_denied());
    println!("  ✗ Write DENIED — adversarial ancestry detected");

    if let SafetyCheck::AdversarialAncestry { tainted_node } = check {
        println!("    Tainted by node {tainted_node} (WebContent)");
    }
    println!();
}

fn scenario_clean_workflow() {
    println!("─── Scenario 2: Clean workflow allowed ───");

    let mut t = FlowTracker::new();

    // User gives a prompt (Directive authority, Trusted integrity).
    let user = t.observe(NodeKind::UserPrompt).unwrap();
    println!("  UserPrompt observed (Trusted, Directive)");

    // Agent reads a local file (Trusted integrity).
    let file = t.observe(NodeKind::FileRead).unwrap();
    println!("  FileRead observed (Trusted)");

    // Model reasons about both.
    let plan = t
        .observe_with_parents(NodeKind::ModelPlan, &[user, file])
        .unwrap();
    println!("  ModelPlan inherits Trusted from clean sources");

    // Write is safe — no adversarial ancestry.
    let check = t.check_safety(&[plan], true);
    assert!(check.is_safe());
    println!("  ✓ Write ALLOWED — clean ancestry");
    println!();
}

fn scenario_compartment_transition() {
    println!("─── Scenario 3: Compartment transition ───");

    // Research compartment: web content enters.
    let mut research = FlowTracker::new();
    research.observe(NodeKind::WebContent).unwrap();
    assert!(research.is_tainted());
    println!("  Research compartment: tainted (web content present)");

    // Compartment transition: new tracker (flow graph resets).
    let draft = FlowTracker::new();
    assert!(!draft.is_tainted());
    println!("  Draft compartment: clean (fresh flow graph)");
    println!("  ✓ Compartment transition cleared taint");
    println!();
}

fn scenario_deterministic_bind() {
    println!("─── Scenario 4: DeterministicBind (model excluded) ───");

    let mut t = FlowTracker::new();

    // WebFetch captures content.
    let web = t.observe(NodeKind::WebContent).unwrap();
    println!("  WebContent fetched (content hash captured)");

    // WASM parser extracts a field deterministically.
    // DeterministicBind has NO model node in its ancestry.
    let bind = t
        .observe_with_parents(NodeKind::DeterministicBind, &[])
        .unwrap();
    println!("  DeterministicBind (no parents — model excluded)");

    // The bind is clean — Deterministic derivation, Trusted integrity.
    let label = t.label(bind).unwrap();
    println!(
        "  Label: integrity={:?}, derivation={:?}",
        label.integrity, label.derivation
    );

    // But the web content is still adversarial.
    let web_label = t.label(web).unwrap();
    println!(
        "  Web label: integrity={:?} (adversarial — correctly tracked)",
        web_label.integrity
    );

    // Session knows it has both clean and tainted data.
    assert!(t.is_tainted());
    assert!(!t.has_ai_derived()); // DeterministicBind is NOT AIDerived
    println!("  ✓ Deterministic data separated from adversarial");
    println!();
}
