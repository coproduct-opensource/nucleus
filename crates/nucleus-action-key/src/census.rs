//! Which required contexts have a key, and which do not — by name.
//!
//! This is the audit the design rests on. A context with no declared read-set
//! cannot have a receipt, and the honest thing is to say which ones and let
//! someone decide, rather than invent a filter. An invented filter is a
//! receipt that lies.

use crate::{ActionKey, Refusal, derive};
use anyhow::Result;
use std::path::Path;

/// One context's outcome.
#[derive(Debug)]
pub enum Outcome {
    /// A key was derived.
    Keyed {
        context: String,
        key: ActionKey,
        reads: usize,
        gate_files: usize,
    },
    /// No key, for a reason a person has to resolve.
    Refused(Refusal),
    /// Could not look. Never folded into `Refused`: an unreadable filter and a
    /// job that legitimately has none are different situations, and reporting
    /// the first as the second is the vacuity ADR 0002 was written about.
    Unmeasured { context: String, why: String },
}

/// The whole census over the required-context ledger.
#[derive(Debug, Default)]
pub struct Census {
    pub outcomes: Vec<Outcome>,
}

impl Census {
    #[must_use]
    pub fn keyed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Keyed { .. }))
            .count()
    }

    #[must_use]
    pub fn refused(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Refused(_)))
            .count()
    }

    #[must_use]
    pub fn unmeasured(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Unmeasured { .. }))
            .count()
    }
}

/// Run the census over every context in `ci/required-checks.txt`.
pub fn run(root: &Path) -> Result<Census> {
    let model = ci_spec::loader::from_repo(root)?;
    let mut census = Census::default();
    for context in &model.ledger.contexts {
        let outcome = match derive::key_for(root, &model, context) {
            // One call, not two. This derived the key and then re-derived the
            // inputs to count them, with an `expect` asserting the second call
            // agreed with the first — an assumption about determinism enforced
            // by a panic. `inputs_for` gives both, so there is nothing to
            // assume.
            Ok(Ok(key)) => match derive::inputs_for(root, &model, context)? {
                Ok(inputs) => Outcome::Keyed {
                    context: context.clone(),
                    key,
                    reads: inputs.read_set.len(),
                    gate_files: inputs.gate.len(),
                },
                Err(refusal) => Outcome::Refused(refusal),
            },
            Ok(Err(refusal)) => Outcome::Refused(refusal),
            Err(e) => Outcome::Unmeasured {
                context: context.clone(),
                why: format!("{e:#}"),
            },
        };
        census.outcomes.push(outcome);
    }
    Ok(census)
}
