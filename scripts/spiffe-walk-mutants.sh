#!/usr/bin/env bash
# The SPIFFE taxonomy walk can fail (docs/spiffe-taxonomy.md).
#
# Each mutant below seeds one defect the walk exists to catch into the shipped
# code, runs the walk test that should catch it, and requires that test to FAIL.
# A substitution that does not apply is itself a failure: a mutant that never
# landed proves nothing. The tree is restored after every mutant, from a copy,
# so uncommitted work survives.
#
#   bash scripts/spiffe-walk-mutants.sh            # every mutant
#   bash scripts/spiffe-walk-mutants.sh M3 M5      # some
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

NODE='cargo test -q -p nucleus-node --bin nucleus-node spiffe_walk'
CP='cargo test -q -p nucleus-control-plane-server --lib an_admitted_subject_is_below_its_prefix'
OP='cargo test -q -p nucleus-oidc-provider --lib a_rule_matches_whole_segments_only'

# Each mutant: its id, the file, a perl substitution applied once (-0, so it
# may span lines), the walk test that must fail, and what it seeds.
ID=(); FILE=(); SUBST=(); TEST=(); WHAT=()
mutant() { ID+=("$1"); FILE+=("$2"); SUBST+=("$3"); TEST+=("$4"); WHAT+=("$5"); }

mutant M1a crates/nucleus-control-plane-server/src/auth.rs \
    's/    prefix\.ends_with\(.\/.\)\n        && nucleus_oidc_core/    true\n        && nucleus_oidc_core/' \
    "$CP" "a subject prefix accepted without its trailing /"
mutant M1b crates/nucleus-node/src/auth.rs \
    's/\.filter\(\|td\| self\.federated_trust_domains\.contains\(\*td\)\)/.filter(|td| self.federated_trust_domains.iter().any(|t| td.starts_with(t.as_str())))/' \
    "$NODE" "a tenant trust domain matched as a string prefix"
mutant M2 crates/nucleus-identity/src/identity.rs \
    's/(        validate_trust_domain\(trust_domain\)\?;\n)/$1        let workload_path = &workload_path.to_ascii_lowercase();\n/' \
    "$NODE" "the path case-folded"
mutant M3 crates/nucleus-lineage/src/id.rs \
    's/            if segment == "\." \|\| segment == "\.\." \{/            if false {/' \
    "$NODE" "lineage accepting . and .."
mutant M4 crates/nucleus-lineage/src/id.rs \
    's/matches!\(c, .-. \| .\.. \| ._.\)\)/matches!(c, \x27-\x27 | \x27.\x27 | \x27_\x27 | \x27%\x27))/' \
    "$NODE" "lineage accepting percent-encoding (%2F)"
mutant M5 crates/portcullis/src/certificate.rs \
    's/meet_with_justification\(parent_permissions, requested\)/meet_with_justification(requested, requested)/' \
    "$NODE" "a delegated child keeping its request instead of the meet"
mutant M6 crates/nucleus-node/src/auth.rs \
    's/\(pod\.hyphenated\(\)\.to_string\(\) == rest\)\.then_some\(pod\)/Some(pod)/' \
    "$NODE" "a pod named by a non-canonical uuid spelling"
mutant M7 crates/nucleus-oidc-provider/src/federation.rs \
    's/                literal_prefix\.ends_with\(.\/.\)\n                    && nucleus_lineage/                true\n                    && nucleus_lineage/' \
    "$OP" "a federation rule wildcard inside a segment"

want=("$@")
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for i in "${!ID[@]}"; do
    id=${ID[$i]} file=${FILE[$i]} subst=${SUBST[$i]} test=${TEST[$i]} what=${WHAT[$i]}
    if [ ${#want[@]} -gt 0 ] && ! printf '%s\n' "${want[@]}" | grep -qx "$id"; then continue; fi
    cp "$file" "$tmp/orig"
    perl -0pi -e "$subst" "$file"
    if cmp -s "$file" "$tmp/orig"; then
        echo "  FAIL  $id: the substitution did not apply ($what)"; fail=1; continue
    fi
    start=$(date +%s)
    if $test >"$tmp/out" 2>&1; then
        echo "  FAIL  $id survived: $what"; fail=1
    else
        # Red for the right reason: a test failed, not the build.
        if grep -q 'error\[E[0-9]' "$tmp/out"; then
            echo "  FAIL  $id did not compile ($what)"; tail -20 "$tmp/out"; fail=1
        else
            line=$(grep -m1 -E "panicked at|assertion" "$tmp/out" | cut -c1-160)
            echo "  ok    $id killed in $(( $(date +%s) - start ))s: $what"
            echo "          $line"
        fi
    fi
    cp "$tmp/orig" "$file"
done
[ $fail = 0 ] && echo "spiffe-walk-mutants: every mutant killed" || { echo "spiffe-walk-mutants: FAILED"; exit 1; }
