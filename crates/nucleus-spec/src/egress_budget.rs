//! `network.egress` in a pod spec: the declared egress volume authority (#2905).
//!
//! The ledger that enforces it is `portcullis::egress_budget`; this is only the
//! wire shape and its reading into a `portcullis::EgressCeiling`. What absence
//! means is decided in exactly one place, `NetworkSpec::egress_ceiling`.

use serde::{Deserialize, Serialize};

/// A pod's declared egress volume authority: `network.egress` in a pod spec.
///
/// ```yaml
/// network:
///   dns_allow: ["registry.example:443"]
///   egress:
///     max_bytes: 67108864      # 64 MiB, total, for the pod's life
///     rate:                    # optional
///       bytes: 1048576         # at most 1 MiB ...
///       window_secs: 60        # ... per minute
/// ```
///
/// Counts UPLOAD bytes — pod toward network — because exfiltration is what it
/// bounds; see `portcullis::egress_budget` for why responses are not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressBudgetSpec {
    /// Total bytes the pod may send over its life. Exhaustion latches: every
    /// later send is refused.
    pub max_bytes: u64,
    /// An optional pace on top of the total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<EgressRateSpec>,
}

/// `network.egress.rate`: at most `bytes` per `window_secs`-second window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRateSpec {
    /// Bytes admitted per window.
    pub bytes: u64,
    /// Window length in seconds. Zero is refused at parse time.
    pub window_secs: std::num::NonZeroU32,
}

impl EgressBudgetSpec {
    /// The authority this declaration grants.
    pub fn ceiling(&self) -> portcullis::EgressCeiling {
        let pace = match self.rate {
            Some(EgressRateSpec { bytes, window_secs }) => {
                portcullis::EgressPace::PerWindow { bytes, window_secs }
            }
            // A declared total with no pace: the TOTAL still bounds. This
            // `None` is the absence of a second dimension, not of a limit.
            None => portcullis::EgressPace::Unpaced,
        };
        portcullis::EgressCeiling::new(self.max_bytes, pace)
    }
}

#[cfg(test)]
mod egress_budget_spec_tests {
    //! `network.egress` (#2905): what a spec says, and what silence means.
    use crate::NetworkSpec;

    fn network(yaml: &str) -> NetworkSpec {
        serde_yaml::from_str(yaml).expect("network section parses")
    }

    /// ADR 0007 B-2: no section, and a section without `egress`, are both the
    /// finite default — never unbounded.
    #[test]
    fn a_missing_declaration_is_the_finite_default_not_unbounded() {
        let undeclared = portcullis::EgressCeiling::undeclared();
        assert_eq!(NetworkSpec::egress_ceiling(None), undeclared);
        let with_allowlist = network("dns_allow: [\"registry.example:443\"]\n");
        assert_eq!(
            NetworkSpec::egress_ceiling(Some(&with_allowlist)),
            undeclared
        );
        assert_eq!(undeclared.max_bytes(), portcullis::DEFAULT_EGRESS_MAX_BYTES);
        assert!(undeclared.max_bytes() < u64::MAX);
    }

    #[test]
    fn a_declared_ceiling_and_rate_are_read_as_written() {
        let n =
            network("egress:\n  max_bytes: 4096\n  rate:\n    bytes: 512\n    window_secs: 10\n");
        let c = NetworkSpec::egress_ceiling(Some(&n));
        assert_eq!(c.max_bytes(), 4096);
        assert_eq!(
            c.pace(),
            portcullis::EgressPace::PerWindow {
                bytes: 512,
                window_secs: std::num::NonZeroU32::new(10).expect("non-zero"),
            }
        );
        let total_only = network("egress:\n  max_bytes: 4096\n");
        assert_eq!(
            NetworkSpec::egress_ceiling(Some(&total_only)).pace(),
            portcullis::EgressPace::Unpaced
        );
    }

    #[test]
    fn a_zero_window_and_an_unknown_field_are_refused_at_parse() {
        assert!(
            serde_yaml::from_str::<NetworkSpec>(
                "egress:\n  max_bytes: 1\n  rate:\n    bytes: 1\n    window_secs: 0\n"
            )
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<NetworkSpec>("egress:\n  max_bytes: 1\n  unlimited: true\n")
                .is_err()
        );
        // A ceiling must be WRITTEN when the section is: `egress: {}` is not a
        // way to spell "no limit".
        assert!(serde_yaml::from_str::<NetworkSpec>("egress: {}\n").is_err());
    }

    /// Absent means absent on the wire: a spec that does not set `egress`
    /// serializes as it did before the field existed, so no program identity
    /// minted to date moves.
    #[test]
    fn an_absent_declaration_does_not_serialize() {
        let json = serde_json::to_string(&NetworkSpec::nothing_listed()).expect("serializes");
        assert!(!json.contains("egress"), "{json}");
    }
}
