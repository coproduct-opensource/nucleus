//! ck-policy's `check_monotonicity` IS the meet-attenuation instance —
//! parity-pinned, honestly scoped.
//!
//! The constitutional policy order is a product of mixed-variance
//! dimensions: capabilities ⊆, I/O surface ⊆, budget ≤ (authority
//! shrinks downward) and proof-requirements ⊇, governance flags ⊇
//! (obligations GROW downward — order-duals). On the fragment where
//! the parent enables all three `require_monotone_*` flags, the
//! bespoke field-by-field checker accepts an amendment **iff** the
//! child is ≤ the parent in this lattice — i.e. constitutional
//! admission is `MeetCap`/narrowing, the same object as capability
//! meet and delegation narrowing (see `src/attenuation.rs`, proved
//! generically in `lean/PortcullisCore/AttenuationProofs.lean`).
//!
//! Honest scoping, in the `LiteralDelegation` tradition:
//!
//! - **Quotient equality.** The checker deliberately ignores
//!   `version`, `may_modify`/`may_not_modify`, and the
//!   `constitutional_human_signatures` threshold (see the SCOPE note
//!   on `AmendmentRules::weakened_flags_over`). The order is therefore
//!   a preorder on manifests; the lattice lives on the quotient, so
//!   `ConstitutionalPoint`'s equality compares exactly the five
//!   checked components.
//! - **Fragment restriction.** With a `require_monotone_*` flag OFF,
//!   the checker accepts more than the lattice order (deliberate
//!   constitutional flexibility) — `gated_fragment_diverges_by_design`
//!   pins one such divergence so the restriction stays visible.
//!
//! Dependency direction: this lives in portcullis-core's DEV-deps so
//! ck-types/ck-policy (the minimal verified kernel) gain no dependency
//! on the algebra crate, and the algebra crate's production graph
//! stays dependency-free for Aeneas.

use ck_policy::check_monotonicity;
use ck_types::manifest::{
    AmendmentRules, BudgetBounds, CapabilitySet, IoSurface, PolicyManifest, ProofRequirements,
};
use portcullis_core::attenuation::{Attenuation, MeetCap, verify_attenuation_laws};
use portcullis_core::category::{Lattice, verify_lattice_laws};
use std::collections::BTreeSet;

/// A policy manifest as a point in the constitutional product lattice.
#[derive(Debug, Clone)]
struct ConstitutionalPoint(PolicyManifest);

/// Quotient equality: exactly the five components `check_monotonicity`
/// reads. (`version`, `may_modify`/`may_not_modify`, and the human-
/// signature threshold are outside the checker's order — see module
/// docs.)
impl PartialEq for ConstitutionalPoint {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (&self.0, &other.0);
        a.capabilities == b.capabilities
            && a.io_surface == b.io_surface
            && a.budget_bounds == b.budget_bounds
            && a.proof_requirements == b.proof_requirements
            && a.amendment_rules.require_monotone_capabilities
                == b.amendment_rules.require_monotone_capabilities
            && a.amendment_rules.require_monotone_io == b.amendment_rules.require_monotone_io
            && a.amendment_rules.require_monotone_proofreq
                == b.amendment_rules.require_monotone_proofreq
    }
}

fn set_meet(a: &BTreeSet<String>, b: &BTreeSet<String>) -> BTreeSet<String> {
    a.intersection(b).cloned().collect()
}

fn set_join(a: &BTreeSet<String>, b: &BTreeSet<String>) -> BTreeSet<String> {
    a.union(b).cloned().collect()
}

impl Lattice for ConstitutionalPoint {
    /// Meet = authority-ward greatest lower bound: permissions
    /// intersect and budgets min (authority axes), while proof
    /// requirements union and governance flags OR (obligation axes —
    /// the duals). Unchecked fields ride along from `self` and are
    /// invisible to the quotient equality.
    fn meet(&self, other: &Self) -> Self {
        let (a, b) = (&self.0, &other.0);
        let mut m = a.clone();
        m.capabilities = CapabilitySet {
            filesystem_read: set_meet(
                &a.capabilities.filesystem_read,
                &b.capabilities.filesystem_read,
            ),
            filesystem_write: set_meet(
                &a.capabilities.filesystem_write,
                &b.capabilities.filesystem_write,
            ),
            network_allow: set_meet(&a.capabilities.network_allow, &b.capabilities.network_allow),
            tools_allow: set_meet(&a.capabilities.tools_allow, &b.capabilities.tools_allow),
            secret_classes: set_meet(
                &a.capabilities.secret_classes,
                &b.capabilities.secret_classes,
            ),
            max_parallel_tasks: a
                .capabilities
                .max_parallel_tasks
                .min(b.capabilities.max_parallel_tasks),
        };
        m.io_surface = IoSurface {
            outbound_domains: set_meet(
                &a.io_surface.outbound_domains,
                &b.io_surface.outbound_domains,
            ),
            local_file_roots: set_meet(
                &a.io_surface.local_file_roots,
                &b.io_surface.local_file_roots,
            ),
            env_vars_readable: set_meet(
                &a.io_surface.env_vars_readable,
                &b.io_surface.env_vars_readable,
            ),
            tool_namespaces: set_meet(&a.io_surface.tool_namespaces, &b.io_surface.tool_namespaces),
            repo_write_targets: set_meet(
                &a.io_surface.repo_write_targets,
                &b.io_surface.repo_write_targets,
            ),
        };
        m.budget_bounds = BudgetBounds {
            max_tokens: a.budget_bounds.max_tokens.min(b.budget_bounds.max_tokens),
            max_wall_ms: a.budget_bounds.max_wall_ms.min(b.budget_bounds.max_wall_ms),
            max_cpu_ms: a.budget_bounds.max_cpu_ms.min(b.budget_bounds.max_cpu_ms),
            max_memory_bytes: a
                .budget_bounds
                .max_memory_bytes
                .min(b.budget_bounds.max_memory_bytes),
            max_network_calls: a
                .budget_bounds
                .max_network_calls
                .min(b.budget_bounds.max_network_calls),
            max_files_touched: a
                .budget_bounds
                .max_files_touched
                .min(b.budget_bounds.max_files_touched),
            max_dollar_spend_millicents: a
                .budget_bounds
                .max_dollar_spend_millicents
                .min(b.budget_bounds.max_dollar_spend_millicents),
            max_patch_attempts: a
                .budget_bounds
                .max_patch_attempts
                .min(b.budget_bounds.max_patch_attempts),
        };
        // Obligation axes are DUAL: lower authority = MORE required.
        m.proof_requirements = ProofRequirements {
            config_patch: set_join(
                &a.proof_requirements.config_patch,
                &b.proof_requirements.config_patch,
            ),
            controller_patch: set_join(
                &a.proof_requirements.controller_patch,
                &b.proof_requirements.controller_patch,
            ),
            evaluator_patch: set_join(
                &a.proof_requirements.evaluator_patch,
                &b.proof_requirements.evaluator_patch,
            ),
        };
        m.amendment_rules.require_monotone_capabilities =
            a.amendment_rules.require_monotone_capabilities
                || b.amendment_rules.require_monotone_capabilities;
        m.amendment_rules.require_monotone_io =
            a.amendment_rules.require_monotone_io || b.amendment_rules.require_monotone_io;
        m.amendment_rules.require_monotone_proofreq = a.amendment_rules.require_monotone_proofreq
            || b.amendment_rules.require_monotone_proofreq;
        ConstitutionalPoint(m)
    }

    fn join(&self, other: &Self) -> Self {
        let (a, b) = (&self.0, &other.0);
        let mut j = a.clone();
        j.capabilities = CapabilitySet {
            filesystem_read: set_join(
                &a.capabilities.filesystem_read,
                &b.capabilities.filesystem_read,
            ),
            filesystem_write: set_join(
                &a.capabilities.filesystem_write,
                &b.capabilities.filesystem_write,
            ),
            network_allow: set_join(&a.capabilities.network_allow, &b.capabilities.network_allow),
            tools_allow: set_join(&a.capabilities.tools_allow, &b.capabilities.tools_allow),
            secret_classes: set_join(
                &a.capabilities.secret_classes,
                &b.capabilities.secret_classes,
            ),
            max_parallel_tasks: a
                .capabilities
                .max_parallel_tasks
                .max(b.capabilities.max_parallel_tasks),
        };
        j.io_surface = IoSurface {
            outbound_domains: set_join(
                &a.io_surface.outbound_domains,
                &b.io_surface.outbound_domains,
            ),
            local_file_roots: set_join(
                &a.io_surface.local_file_roots,
                &b.io_surface.local_file_roots,
            ),
            env_vars_readable: set_join(
                &a.io_surface.env_vars_readable,
                &b.io_surface.env_vars_readable,
            ),
            tool_namespaces: set_join(&a.io_surface.tool_namespaces, &b.io_surface.tool_namespaces),
            repo_write_targets: set_join(
                &a.io_surface.repo_write_targets,
                &b.io_surface.repo_write_targets,
            ),
        };
        j.budget_bounds = BudgetBounds {
            max_tokens: a.budget_bounds.max_tokens.max(b.budget_bounds.max_tokens),
            max_wall_ms: a.budget_bounds.max_wall_ms.max(b.budget_bounds.max_wall_ms),
            max_cpu_ms: a.budget_bounds.max_cpu_ms.max(b.budget_bounds.max_cpu_ms),
            max_memory_bytes: a
                .budget_bounds
                .max_memory_bytes
                .max(b.budget_bounds.max_memory_bytes),
            max_network_calls: a
                .budget_bounds
                .max_network_calls
                .max(b.budget_bounds.max_network_calls),
            max_files_touched: a
                .budget_bounds
                .max_files_touched
                .max(b.budget_bounds.max_files_touched),
            max_dollar_spend_millicents: a
                .budget_bounds
                .max_dollar_spend_millicents
                .max(b.budget_bounds.max_dollar_spend_millicents),
            max_patch_attempts: a
                .budget_bounds
                .max_patch_attempts
                .max(b.budget_bounds.max_patch_attempts),
        };
        j.proof_requirements = ProofRequirements {
            config_patch: set_meet(
                &a.proof_requirements.config_patch,
                &b.proof_requirements.config_patch,
            ),
            controller_patch: set_meet(
                &a.proof_requirements.controller_patch,
                &b.proof_requirements.controller_patch,
            ),
            evaluator_patch: set_meet(
                &a.proof_requirements.evaluator_patch,
                &b.proof_requirements.evaluator_patch,
            ),
        };
        j.amendment_rules.require_monotone_capabilities =
            a.amendment_rules.require_monotone_capabilities
                && b.amendment_rules.require_monotone_capabilities;
        j.amendment_rules.require_monotone_io =
            a.amendment_rules.require_monotone_io && b.amendment_rules.require_monotone_io;
        j.amendment_rules.require_monotone_proofreq = a.amendment_rules.require_monotone_proofreq
            && b.amendment_rules.require_monotone_proofreq;
        ConstitutionalPoint(j)
    }

    /// `child ≤ parent` — exactly the five conditions the checker
    /// enforces when every `require_monotone_*` flag is enabled.
    fn leq(&self, other: &Self) -> bool {
        let (c, p) = (&self.0, &other.0);
        c.capabilities.is_subset_of(&p.capabilities)
            && c.io_surface.is_subset_of(&p.io_surface)
            && c.budget_bounds.is_within(&p.budget_bounds)
            && c.proof_requirements.is_superset_of(&p.proof_requirements)
            && c.amendment_rules
                .weakened_flags_over(&p.amendment_rules)
                .is_empty()
    }
}

// ── Sample manifests ─────────────────────────────────────────────────────

fn strings(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// All `require_monotone_*` flags enabled — the parity fragment.
fn manifest(
    read: &[&str],
    domains: &[&str],
    tokens: u64,
    config_proofs: &[&str],
) -> ConstitutionalPoint {
    ConstitutionalPoint(PolicyManifest {
        version: 1,
        capabilities: CapabilitySet {
            filesystem_read: strings(read),
            filesystem_write: BTreeSet::new(),
            network_allow: strings(domains),
            tools_allow: strings(&["bash"]),
            secret_classes: BTreeSet::new(),
            max_parallel_tasks: 4,
        },
        io_surface: IoSurface {
            outbound_domains: strings(domains),
            local_file_roots: strings(read),
            env_vars_readable: BTreeSet::new(),
            tool_namespaces: strings(&["core"]),
            repo_write_targets: BTreeSet::new(),
        },
        budget_bounds: BudgetBounds {
            max_tokens: tokens,
            max_wall_ms: 60_000,
            max_cpu_ms: 30_000,
            max_memory_bytes: 1 << 30,
            max_network_calls: 100,
            max_files_touched: 50,
            max_dollar_spend_millicents: 10_000,
            max_patch_attempts: 3,
        },
        proof_requirements: ProofRequirements {
            config_patch: strings(config_proofs),
            controller_patch: strings(&["kani"]),
            evaluator_patch: BTreeSet::new(),
        },
        amendment_rules: AmendmentRules {
            may_modify: strings(&["src/**"]),
            may_not_modify: strings(&["PolicyManifest.toml"]),
            require_monotone_capabilities: true,
            require_monotone_io: true,
            require_monotone_proofreq: true,
            constitutional_human_signatures: 2,
        },
    })
}

fn samples() -> Vec<ConstitutionalPoint> {
    vec![
        manifest(&[], &[], 1_000, &["fmt", "clippy", "test"]),
        manifest(&["src"], &["api.example.com"], 10_000, &["fmt", "clippy"]),
        manifest(
            &["src", "docs"],
            &["api.example.com", "crates.io"],
            100_000,
            &["fmt"],
        ),
        manifest(&["docs"], &["crates.io"], 5_000, &["fmt", "test"]),
    ]
}

// ── The claims ───────────────────────────────────────────────────────────

#[test]
fn constitutional_quotient_is_a_lawful_lattice() {
    assert_eq!(verify_lattice_laws(&samples()), Vec::<String>::new());
}

#[test]
fn meet_cap_is_a_lawful_attenuation_on_policies() {
    let pts = samples();
    for cap in &pts {
        let f = MeetCap(cap.clone());
        assert_eq!(verify_attenuation_laws(&f, &pts), Vec::<String>::new());
    }
}

/// THE PARITY PIN: on the all-flags-enabled fragment, the bespoke
/// checker and the lattice order decide identically, and an admitted
/// amendment is exactly the meet (= the child) — i.e. constitutional
/// admission is the `MeetCap` attenuation instance.
#[test]
fn check_monotonicity_is_the_lattice_order_on_the_full_flag_fragment() {
    for p in samples() {
        for c in samples() {
            let verdict = check_monotonicity(&p.0, &c.0);
            assert_eq!(
                verdict.passed,
                c.leq(&p),
                "checker and lattice disagree:\nparent={p:?}\nchild={c:?}\ndiff={:?}",
                verdict.diff
            );
            if verdict.passed {
                let admitted = MeetCap(c.clone()).attenuate(&p);
                assert!(
                    admitted == c,
                    "admitted amendment is not the meet: {admitted:?} vs {c:?}"
                );
                assert!(c == admitted, "quotient equality must be symmetric");
            }
        }
    }
}

/// With a `require_monotone_*` flag OFF the checker accepts amendments
/// the lattice order rejects — deliberate constitutional flexibility,
/// and exactly why the parity claim is fragment-scoped.
#[test]
fn gated_fragment_diverges_by_design() {
    let mut p = manifest(&["src"], &["api.example.com"], 10_000, &["fmt"]);
    p.0.amendment_rules.require_monotone_capabilities = false;
    // Child escalates capabilities (new read root + new domain)…
    let mut c = manifest(&["src", "secrets"], &["api.example.com"], 10_000, &["fmt"]);
    // …but keeps the gating flag disabled like its parent, and widens
    // nothing the checker still polices.
    c.0.amendment_rules.require_monotone_capabilities = false;
    c.0.io_surface = p.0.io_surface.clone();

    let verdict = check_monotonicity(&p.0, &c.0);
    assert!(verdict.passed, "checker accepts under the disabled flag");
    assert!(!c.leq(&p), "…but the lattice order rejects the escalation");
}
