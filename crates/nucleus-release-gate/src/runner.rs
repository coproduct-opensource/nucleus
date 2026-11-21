//! The runner's verdict on one application, derived from measurements.
//!
//! A runner applies a manifest's program and signs what happened. What
//! happened is not the runner's to phrase: [`measure`] turns the manifest, the
//! program and the applier's result into the outcome, and there is no other
//! way in this crate to arrive at `Applied`.

use nucleus_weight_patch::{Applied, ApplyError, PatchProgram, WriteVerdict, check_writes};

use crate::body::{ApplyOutcome, PatchManifest};

/// The outcome of applying `program` under `manifest`, given what the applier
/// returned.
#[must_use]
pub fn measure(
    manifest: &PatchManifest,
    program: &PatchProgram,
    applied: Result<Applied, ApplyError>,
) -> ApplyOutcome {
    let could_not = |reason: String| ApplyOutcome::CouldNotApply { reason };
    if program.digest() != manifest.program {
        return could_not("the program is not the one the manifest names".to_owned());
    }
    let applied = match applied {
        Ok(applied) => applied,
        Err(e) => return could_not(e.to_string()),
    };
    if applied.base().digest() != manifest.base {
        return could_not("the files are not the base the manifest names".to_owned());
    }
    let measured = match applied.diff() {
        Ok(measured) => measured,
        Err(e) => return could_not(e.to_string()),
    };
    match check_writes(&measured, &manifest.declared) {
        WriteVerdict::Outside { undeclared, writes } => ApplyOutcome::WriteSetViolation {
            undeclared: undeclared.into_iter().collect(),
            writes,
        },
        WriteVerdict::Within(within) => {
            let actual = applied.output().digest();
            if actual == manifest.expected_output {
                ApplyOutcome::Applied {
                    output: actual,
                    writes: within.writes().to_vec(),
                }
            } else {
                ApplyOutcome::OutputMismatch {
                    expected: manifest.expected_output,
                    actual,
                }
            }
        }
    }
}
