#![cfg(kani)]

use crate::{
    BudgetLattice, CapabilityLattice, CapabilityLevel, CommandLattice, Obligations, Operation,
    PathLattice, PermissionLattice, TimeLattice,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

fn level_from_u8(value: u8) -> CapabilityLevel {
    match value % 3 {
        0 => CapabilityLevel::Never,
        1 => CapabilityLevel::LowRisk,
        _ => CapabilityLevel::Always,
    }
}

fn ordered_level_pair(a: u8, b: u8) -> (CapabilityLevel, CapabilityLevel) {
    let left = level_from_u8(a);
    let right = level_from_u8(b);
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn obligations_from_masks(mask_base: u16, mask_extra: u16) -> (Obligations, Obligations) {
    let mut base = Obligations::default();
    let mut superset = Obligations::default();

    let ops = [
        Operation::ReadFiles,
        Operation::WriteFiles,
        Operation::EditFiles,
        Operation::RunBash,
        Operation::GlobSearch,
        Operation::GrepSearch,
        Operation::WebSearch,
        Operation::WebFetch,
        Operation::GitCommit,
        Operation::GitPush,
        Operation::CreatePr,
        Operation::ManagePods,
    ];

    for (idx, op) in ops.iter().enumerate() {
        let bit = 1u16 << idx;
        if mask_base & bit != 0 {
            base.insert(*op);
            superset.insert(*op);
        }
        if mask_extra & bit != 0 {
            superset.insert(*op);
        }
    }

    (superset, base)
}

fn fixed_timestamp() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).unwrap()
}

fn base_permission() -> PermissionLattice {
    PermissionLattice {
        id: Uuid::nil(),
        description: "kani".to_string(),
        derived_from: None,
        capabilities: CapabilityLattice::default(),
        obligations: Obligations::default(),
        paths: PathLattice::block_sensitive(),
        budget: BudgetLattice::with_cost_limit(1.0),
        commands: CommandLattice::restrictive(),
        time: TimeLattice::minutes(1),
        trifecta_constraint: true,
        created_at: fixed_timestamp(),
        created_by: "kani".to_string(),
    }
}

fn build_ordered_permissions() -> (PermissionLattice, PermissionLattice) {
    let (read_lo, read_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (write_lo, write_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (edit_lo, edit_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (run_lo, run_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (glob_lo, glob_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (grep_lo, grep_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (webs_lo, webs_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (webf_lo, webf_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (commit_lo, commit_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (push_lo, push_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (pr_lo, pr_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());
    let (pods_lo, pods_hi) = ordered_level_pair(kani::any::<u8>(), kani::any::<u8>());

    let (superset_obligations, base_obligations) =
        obligations_from_masks(kani::any::<u16>(), kani::any::<u16>());

    let trifecta = kani::any::<bool>();

    let mut lhs = base_permission();
    lhs.capabilities = CapabilityLattice {
        read_files: read_lo,
        write_files: write_lo,
        edit_files: edit_lo,
        run_bash: run_lo,
        glob_search: glob_lo,
        grep_search: grep_lo,
        web_search: webs_lo,
        web_fetch: webf_lo,
        git_commit: commit_lo,
        git_push: push_lo,
        create_pr: pr_lo,
        manage_pods: pods_lo,
    };
    lhs.obligations = superset_obligations;
    lhs.trifecta_constraint = trifecta;

    let mut rhs = base_permission();
    rhs.capabilities = CapabilityLattice {
        read_files: read_hi,
        write_files: write_hi,
        edit_files: edit_hi,
        run_bash: run_hi,
        glob_search: glob_hi,
        grep_search: grep_hi,
        web_search: webs_hi,
        web_fetch: webf_hi,
        git_commit: commit_hi,
        git_push: push_hi,
        create_pr: pr_hi,
        manage_pods: pods_hi,
    };
    rhs.obligations = base_obligations;
    rhs.trifecta_constraint = trifecta;

    (lhs, rhs)
}

#[kani::proof]
fn proof_normalize_idempotent() {
    let (lhs, _) = build_ordered_permissions();
    let once = lhs.clone().normalize();
    let twice = once.clone().normalize();
    assert!(once == twice);
}

#[kani::proof]
fn proof_normalize_deflationary() {
    let (lhs, _) = build_ordered_permissions();
    let normalized = lhs.clone().normalize();
    assert!(normalized.leq(&lhs));
}

#[kani::proof]
fn proof_normalize_monotone() {
    let (lhs, rhs) = build_ordered_permissions();
    assert!(lhs.leq(&rhs));
    let lhs_norm = lhs.normalize();
    let rhs_norm = rhs.normalize();
    assert!(lhs_norm.leq(&rhs_norm));
}
