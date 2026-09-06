#!/usr/bin/env bash
# CI assurance ledger — docs/assurance/ci-assurance.md cannot outrun its wiring.
#
# The same discipline as scripts/check-north-star-ledger.sh, for the claims
# ADR 0002 makes about the CI pipeline: every row names a clause of the
# sentence verbatim, carries a status from a closed vocabulary, an evidence
# handle that must dereference, and the gate that catches the status
# regressing. The population is pinned in both directions (rows may only be
# added; NOT-YET may only shrink, and the pin moves in the same change).
#
# Exit 0 clean, 1 a violation. Refuses (exit 1) if the sentence or the table
# cannot be found — a check over an empty table would "pass".
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
DOC="docs/assurance/ci-assurance.md"
RATCHET="scripts/ci-assurance-ledger-ratchet.txt"
failures=0
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }

[[ -f "$DOC" ]] || { echo "ERROR: $DOC not found"; exit 1; }
[[ -f "$RATCHET" ]] || { echo "ERROR: $RATCHET not found — the ledger has no pinned population"; exit 1; }

# ── The sentence ────────────────────────────────────────────────────────────
sentence="$(awk '/^\*\*The sentence\.\*\*/{grab=1} grab{printf "%s ", $0} grab&&/\*$/{exit}' "$DOC" | tr -s '[:space:]' ' ')"
if [[ -z "$sentence" || "$sentence" != *"merges in order"* ]]; then
    echo "ERROR: could not extract the CI assurance sentence from $DOC (anchor moved?)"
    exit 1
fi

# ── The pins ────────────────────────────────────────────────────────────────
clauses_pinned="$(sed -n 's/^CLAUSES=\([0-9]*\)$/\1/p' "$RATCHET" | head -1)"
notyet_pinned="$(sed -n 's/^NOT_YET=\([0-9]*\)$/\1/p' "$RATCHET" | head -1)"
[[ "$clauses_pinned" =~ ^[0-9]+$ && "$notyet_pinned" =~ ^[0-9]+$ ]] || {
    echo "ERROR: $RATCHET must pin CLAUSES=<n> and NOT_YET=<n>"; exit 1; }

# ── The table ───────────────────────────────────────────────────────────────
rows="$(grep -E '^\| CI-[0-9]+ \|' "$DOC")"
n_rows="$(printf '%s\n' "$rows" | grep -c . || true)"
[[ "$n_rows" =~ ^[0-9]+$ ]] || n_rows=0
if [ "$n_rows" -lt 1 ]; then
    echo "ERROR: no '| CI-n |' rows found in $DOC — the ledger is empty, which is not a pass"
    exit 1
fi

seen_ids=""
n_notyet=0
while IFS= read -r row; do
    [ -n "$row" ] || continue
    id="$(printf '%s' "$row" | awk -F'|' '{gsub(/^ +| +$/, "", $2); print $2}')"
    clause="$(printf '%s' "$row" | awk -F'|' '{gsub(/^ +| +$/, "", $3); print $3}')"
    status="$(printf '%s' "$row" | awk -F'|' '{gsub(/^ +| +$/, "", $4); print $4}')"
    evidence="$(printf '%s' "$row" | awk -F'|' '{gsub(/^ +| +$/, "", $5); print $5}')"
    falsifier="$(printf '%s' "$row" | awk -F'|' '{gsub(/^ +| +$/, "", $6); print $6}')"

    case " $seen_ids " in *" $id "*) fail "$id — duplicate row id (double-counted coverage)";; esac
    seen_ids="$seen_ids $id"

    # Clause fragment: the quoted part must be verbatim in the sentence.
    frag="$(printf '%s' "$clause" | sed -n 's/^"\([^"]*\)".*/\1/p')"
    if [ -z "$frag" ]; then
        fail "$id — clause does not start with a quoted fragment of the sentence"
    elif [[ "$sentence" != *"$frag"* ]]; then
        fail "$id — clause fragment \"$frag\" is not in the sentence"
    fi

    case "$status" in
        PROVED|DECIDED|TESTED) ;;
        NOT-YET) n_notyet=$((n_notyet + 1)) ;;
        *) fail "$id — status '$status' is not one of PROVED|DECIDED|TESTED|NOT-YET" ;;
    esac

    # Evidence handles: `path` must exist; `path#symbol` must exist AND contain the symbol.
    n_ev=0
    while IFS= read -r h; do
        [ -n "$h" ] || continue
        n_ev=$((n_ev + 1))
        path="${h%%#*}"
        sym=""; [[ "$h" == *"#"* ]] && sym="${h#*#}"
        if [ ! -e "$path" ]; then
            fail "$id — evidence '$h': $path does not exist"
        elif [ -n "$sym" ] && ! grep -qF -- "$sym" "$path"; then
            fail "$id — evidence '$h': '$sym' not found in $path"
        fi
    done <<EOF
$(printf '%s' "$evidence" | grep -oE '`[^`]+`' | tr -d '`')
EOF
    if [ "$n_ev" -lt 1 ]; then fail "$id — no evidence handle"; fi

    # Falsifier: a script must exist and be invoked by a workflow; a workflow must exist.
    f="$(printf '%s' "$falsifier" | grep -oE '`[^`]+`' | head -1 | tr -d '`')"
    if [ "$status" = "NOT-YET" ]; then
        :
    elif [ -z "$f" ]; then
        fail "$id — a $status row needs a falsifier"
    elif [ ! -e "$f" ]; then
        fail "$id — falsifier '$f' does not exist"
    elif [[ "$f" == scripts/*.sh ]] && ! grep -rqlF -- "$f" .github/workflows/; then
        fail "$id — falsifier '$f' is invoked by no workflow (a gate CI does not run enforces nothing)"
    fi
done <<EOF
$rows
EOF

# ── The population, both directions ─────────────────────────────────────────
if [ "$n_rows" -lt "$clauses_pinned" ]; then
    fail "the ledger has $n_rows rows but CLAUSES=$clauses_pinned is pinned — a row was deleted (dodging a red?)"
elif [ "$n_rows" -gt "$clauses_pinned" ]; then
    fail "the ledger has $n_rows rows but CLAUSES=$clauses_pinned — raise the pin in the same change that adds the row"
fi
if [ "$n_notyet" -ne "$notyet_pinned" ]; then
    fail "NOT-YET rows: $n_notyet, pinned $notyet_pinned — a promotion lowers the pin in the same change; a demotion raises it, on the record in $RATCHET"
fi

if [ "$failures" -ne 0 ]; then
    echo "VIOLATION: $failures — the CI assurance ledger claims more than its wiring supports"
    exit 1
fi
echo "OK: $n_rows CI assurance rows, every clause verbatim, every handle dereferences, every falsifier wired; NOT-YET=$n_notyet as pinned"
