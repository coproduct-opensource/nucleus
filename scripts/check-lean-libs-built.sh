#!/usr/bin/env bash
# Every `lean_lib` must be type-checked by something.
#
# WHY THIS EXISTS
#
# #2162 landed as "two flagship proofs were never built". It fixed the two that
# had been noticed. It did not ask what the whole set was — so
# `CapabilityResiduatedQuantaleProofs`, the residuation adjunction proven over
# the Aeneas-generated capability core, is in exactly the same state and nobody
# saw it. A hand-maintained list of build targets has the same blind spot as a
# hand-maintained list of anything: what is absent from it is also absent from
# every check over it.
#
# An unbuilt Lean library is worse than an unbuilt Rust crate. It contains
# theorem statements that read as guarantees in docs and papers, and a statement
# that is never elaborated can be false, ill-typed, or `sorry`-carrying with
# nothing anywhere reporting it. `#print axioms` cannot save you: it needs the
# constant to exist, and returns "Unknown constant" for a lib that never built.
#
# WHAT COUNTS AS BUILT
#
# Naming a lib in `lake build X` is not the only way it gets compiled. Building X
# compiles everything X imports, so a lib with importers is covered
# transitively. `@[default_target]` matters too: a bare `lake build` compiles a
# package's default targets, and `portcullis-core/lean/lakefile.lean` declares
# NONE — so a bare `lake build` there builds nothing at all, which is why so much
# of that package depends on being named explicitly.
#
# WHAT THIS DOES NOT COVER — read before trusting a green run
#
# The reachability below is ONE HOP, not a fixpoint: a lib is covered if it is
# named, or if some file imports one of its root modules. A lib imported ONLY by
# another uncovered lib is therefore reported as covered when it is not. That is
# deliberate — the check is sound in the direction that matters (anything it
# flags is genuinely unbuilt) and incomplete in the other. It is stated here
# rather than discovered later, because a coverage checker that quietly
# overstates its own reach is the exact failure it exists to find.
#
# Usage: scripts/check-lean-libs-built.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

lakefiles=$(find . \( -name .lake -o -name target -o -name node_modules -o -name .git \) -prune -o -name "lakefile.lean" -print | sort)
if [[ -z "$lakefiles" ]]; then
    echo "ERROR: no lakefile.lean found. This gate is looking in the wrong place,"
    echo "so a clean result below would mean nothing."
    exit 1
fi

# Every lib named as an explicit `lake build` target in any workflow.
#
# Targets are frequently listed across BACKSLASH-CONTINUED lines:
#
#     lake build \
#       DerivationProofs \
#       SessionCeilingProofs \
#       ...
#
# so the shell line must be reassembled before extracting names. The first
# version of this matched `lake build <word>` per physical line and reported 23
# libraries as unbuilt; all but a handful of them were on continuation lines of a
# single command in portcullis-core-proven-lean.yml. A coverage checker that
# reads only the first line of a multi-line command does not find gaps, it
# invents them — and the invented ones are indistinguishable from real findings
# until someone checks by hand.
named=$(for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
            [[ -f "$wf" ]] || continue
            # Join continuations, then pull every word after `lake build`.
            sed -e :a -e '/\\$/N; s/\\\n/ /; ta' "$wf" 2>/dev/null \
                | grep -oE "lake build( +[A-Za-z][A-Za-z0-9_]*)+" \
                | sed 's/lake build//'
        done | tr ' ' '\n' | grep -vE '^$' | sort -u)

# Every module imported by any Lean source in the tree. A lib whose root module
# appears here is compiled as a dependency of whoever imports it.
imported=$(find . \( -name .lake -o -name target -o -name node_modules -o -name .git \) -prune -o -name "*.lean" -print0 2>/dev/null \
           | xargs -0 grep -hoE "^import [A-Za-z][A-Za-z0-9_.]*" 2>/dev/null \
           | sed 's/^import //' | sort -u)

if [[ -z "$imported" ]]; then
    echo "ERROR: no \`import\` lines found in any .lean file. The scan is broken,"
    echo "so every lib would look unimported and this gate would flag all of them."
    exit 1
fi

total=0
covered=0
declare -a UNBUILT=()

for lf in $lakefiles; do
    pkgdir="$(dirname "$lf")"
    # Does this package have a default target? If so a bare `lake build` covers
    # it, and bare invocations are common enough that we must not flag it.
    has_default=0
    grep -q "@\[default_target\]" "$lf" && has_default=1

    # `lean_lib «Name»` — the guillemets are how every lakefile here writes it.
    while IFS= read -r lib; do
        [[ -z "$lib" ]] && continue
        total=$((total + 1))

        if [[ "$has_default" -eq 1 ]]; then
            covered=$((covered + 1)); continue
        fi
        if grep -qx "$lib" <<<"$named"; then
            covered=$((covered + 1)); continue
        fi

        # Roots default to the lib name; an explicit `roots := #[\`A, \`B]` overrides.
        # `${lib}` braced deliberately: `"$lib»"` makes bash try to read a
        # variable named `lib»` — the guillemet is multibyte and does not
        # terminate the name — which fails under `set -u` and left `roots` empty
        # for EVERY lib, silently falling back to the lib name. A lib whose
        # roots differ from its name was then checked against the wrong module.
        roots="$(grep -A2 "lean_lib «${lib}»" "$lf" | grep -oE 'roots := #\[[^]]*\]' \
                 | grep -oE '`[A-Za-z][A-Za-z0-9_.]*' | tr -d '`' || true)"
        [[ -z "$roots" ]] && roots="$lib"

        hit=0
        for r in $roots; do
            # Imported directly, or as a parent of a submodule import.
            if grep -qE "^$r(\.|$)" <<<"$imported"; then hit=1; break; fi
        done
        if [[ "$hit" -eq 1 ]]; then
            covered=$((covered + 1)); continue
        fi

        UNBUILT+=("$lib  ($pkgdir)")
    done < <(grep -oE 'lean_lib «[^»]*»' "$lf" | sed 's/lean_lib «//; s/»//')
done

# NON-VACUITY. If the lakefile parse produced nothing, or every lib matched, the
# loop above would report a clean sheet without having examined anything.
if [[ "$total" -lt 2 ]]; then
    echo "ERROR: found $total lean_lib declaration(s). The lakefile parse is broken,"
    echo "so the result below describes nothing."
    exit 1
fi

echo "lean_lib coverage: $total declared, $covered covered (named target, default target, or imported)"

# Known-unbuilt, named with a reason rather than tolerated as a count. A bare
# number would let one library be fixed while another silently took its place;
# naming them means the set itself is reviewed. This is a ratchet — entries may
# leave, and a new one is a failure until someone writes down why.
#
# Every entry is a theorem statement that nothing elaborates.
# A plain `name|reason` list, NOT an associative array: macOS ships bash 3.2,
# which has no `declare -A`. The first version used one, and under `set -u` the
# membership test errored per library and the script still **exited 0** — a
# false green in the gate written to find false greens. Portable constructs are
# not pedantry here; the gate must run wherever it is probed.
ALLOWED_UNBUILT=(
    # CONFIRMED by direct build, not inherited from the workflow comment that
    # asserts it: a clean rebuild fails with `unknown namespace
    # PortcullisCoreBridge` plus ~12 unsynthesized instances. It was also the
    # CONTROL that validated the triage of the two libraries below — without a
    # library known to fail, "it compiles" is not a measurement.
    "CategoryProofs|does not compile — Mathlib order-refactor drift / unbound auto-implicits; Tier 3 (STALE) in CONJECTURES.md, excluded by name in portcullis-core-proven-lean.yml"
    "AugmentedBorromeanTheorems|research spike, never wired"
    "BraidObstruction|research spike, never wired"
    "BraidEmpirical|research spike, never wired"
    "BraidAnalysis|research spike, never wired"
    "DiamondActions|research spike, never wired"
    "RealWorldActions|research spike, never wired"
    "LipschitzEquivariance|research spike, never wired"
    "GovernanceCompletenessSpike|research spike, never wired"
)

is_allowed() {
    local want="$1" e
    for e in "${ALLOWED_UNBUILT[@]}"; do
        [[ "${e%%|*}" == "$want" ]] && return 0
    done
    return 1
}

UNEXPECTED=()
for u in "${UNBUILT[@]}"; do
    name="${u%% *}"
    is_allowed "$name" || UNEXPECTED+=("$name")
done

# The ratchet's other half: an allowlist entry for a library that is now built —
# or no longer exists — is stale, and a stale allowlist quietly re-admits things.
STALE_ALLOWANCES=()
for e in "${ALLOWED_UNBUILT[@]}"; do
    name="${e%%|*}"
    found=0
    for u in "${UNBUILT[@]}"; do [[ "${u%% *}" == "$name" ]] && found=1 && break; done
    [[ "$found" -eq 0 ]] && STALE_ALLOWANCES+=("$name")
done

echo "unbuilt: ${#UNBUILT[@]} (all allowed: ${#ALLOWED_UNBUILT[@]} entries, ${#UNEXPECTED[@]} unexpected, ${#STALE_ALLOWANCES[@]} stale)"

rc=0
if [[ "${#UNEXPECTED[@]}" -gt 0 ]]; then
    echo
    echo "VIOLATION: ${#UNEXPECTED[@]} lean_lib(s) are built by nothing and are not"
    echo "on the allowlist — not named by a workflow, not a default target, and"
    echo "imported by no file:"
    for g in "${UNEXPECTED[@]}"; do echo "    $g"; done
    echo
    echo "A library that never elaborates can contain a false statement, an"
    echo "ill-typed one, or a \`sorry\`, and no gate anywhere will say so."
    echo "Add it to a workflow's target list, delete it, or add it to"
    echo "ALLOWED_UNBUILT above WITH THE REASON."
    rc=1
fi

if [[ "${#STALE_ALLOWANCES[@]}" -gt 0 ]]; then
    echo
    echo "VIOLATION: ${#STALE_ALLOWANCES[@]} allowlist entr(ies) name a library that is"
    echo "now built or no longer declared:"
    for g in "${STALE_ALLOWANCES[@]}"; do echo "    $g"; done
    echo "Remove them, so the allowlist keeps meaning what it says."
    rc=1
fi

[[ "$rc" -eq 0 ]] && echo "OK: every lean_lib is type-checked by something, or is allowlisted with a reason."
exit "$rc"
