//! Kani proofs for nucleus properties.

use crate::{
    BudgetLattice, CapabilityLattice, CapabilityLevel, CommandLattice, Obligations, PathLattice,
    PermissionLattice, TimeLattice,
};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

fn any_level() -> CapabilityLevel {
    match kani::any::<u8>() % 3 {
        0 => CapabilityLevel::Never,
        1 => CapabilityLevel::LowRisk,
        _ => CapabilityLevel::Always,
    }
}

fn any_capabilities() -> CapabilityLattice {
    CapabilityLattice {
        read_files: any_level(),
        write_files: any_level(),
        edit_files: any_level(),
        run_bash: any_level(),
        glob_search: any_level(),
        grep_search: any_level(),
        web_search: any_level(),
        web_fetch: any_level(),
        git_commit: any_level(),
        git_push: any_level(),
        create_pr: any_level(),
    }
}

fn kani_lattice() -> PermissionLattice {
    PermissionLattice {
        id: Uuid::nil(),
        description: "kani".to_string(),
        derived_from: None,
        capabilities: any_capabilities(),
        obligations: Obligations::default(),
        paths: PathLattice::default(),
        budget: BudgetLattice::default(),
        commands: CommandLattice::default(),
        time: TimeLattice::default(),
        trifecta_constraint: true,
        created_at: Utc.timestamp_opt(0, 0).unwrap(),
        created_by: "kani".to_string(),
    }
}

#[kani::proof]
fn proof_nucleus_idempotent() {
    let lattice = kani_lattice();
    let normalized = lattice.normalize();
    let normalized_again = normalized.clone().normalize();
    kani::assert!(normalized == normalized_again);
}

#[kani::proof]
fn proof_nucleus_monotone() {
    let left = kani_lattice();
    let right = kani_lattice();
    kani::assume(left.leq(&right));
    let left_n = left.normalize();
    let right_n = right.normalize();
    kani::assert!(left_n.leq(&right_n));
}
