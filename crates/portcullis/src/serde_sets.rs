//! Stable wire order for semantic sets. HashSet's random iteration order must
//! not make a policy checksum change after deserialization or a lattice meet.

use serde::{Serialize, Serializer};
use std::collections::{BTreeSet, HashSet};

pub(crate) fn ordered<S: Serializer>(
    set: &HashSet<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    set.iter().collect::<BTreeSet<_>>().serialize(serializer)
}

#[cfg(test)]
mod tests {
    use crate::PermissionLattice;

    #[test]
    fn policy_checksum_survives_fresh_set_seeds_and_reissued_provenance() {
        let mut original = PermissionLattice::default();
        original.paths.allowed = ["/work/z", "/work/a", "/work/m"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        original.paths.blocked = ["/secret/z", "/secret/a", "/secret/m"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let json = serde_json::to_value(&original).unwrap();
        // An explicit expected order makes this deterministic even if two
        // independently seeded hash sets happen to choose the same order.
        assert_eq!(
            json["paths"]["allowed"],
            serde_json::json!(["/work/a", "/work/m", "/work/z"])
        );
        assert_eq!(
            json["paths"]["blocked"],
            serde_json::json!(["/secret/a", "/secret/m", "/secret/z"])
        );
        for field in ["allowed", "blocked"] {
            let commands = json["commands"][field].as_array().unwrap();
            let mut sorted = commands.clone();
            sorted.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            assert_eq!(commands, &sorted);
        }
        for _ in 0..8 {
            let decoded: PermissionLattice = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(original, decoded);
            assert_eq!(original.checksum(), decoded.checksum());
            let reissued = decoded.meet(&decoded);
            assert_eq!(original, reissued);
            assert_eq!(original.checksum(), reissued.checksum());
        }
    }
}
