//! The invariants, one module each. Every module's doc comment names the
//! founding defect it was written for; `tests/founding_defects.rs` carries a
//! fixture reproducing each and asserts the rule fires on it and is silent
//! on the repaired shape.

pub mod concurrency;
pub mod gates;
pub mod merge_group;
pub mod producers;
pub mod scope;
pub mod self_hosted_tools;
pub mod timeouts;
pub mod twins;
pub mod vacuity;
pub mod wired;

use crate::{Finding, Severity};

pub(crate) fn finding(
    rule: &'static str,
    severity: Severity,
    file: &str,
    line: usize,
    subject: &str,
    why: String,
    fix: &str,
) -> Finding {
    Finding {
        rule,
        severity,
        file: file.to_string(),
        line,
        subject: subject.to_string(),
        why,
        fix: fix.to_string(),
        job: String::new(),
    }
}
