#!/usr/bin/env bash
# North Star claim ledger — the status table cannot outrun its wiring.
#
# WHY THIS EXISTS
#
# docs/north-star.md carries the flagship confidentiality sentence and, below
# it, a table saying which parts are PROVED, which are TESTED, and which are
# NOT-YET. That table is the project's single most load-bearing honesty
# artifact — and until this gate, nothing checked it. It drifted in the exact
# way the doc's own preamble warns about: a row claimed "tested on the live
# path" for the declassification token while scripts/check-declassify-token-
# dormant.sh — running in the same CI — asserted that path has no production
# caller at all, and the row's "not adversary-steerable" leg was proved only in
# a hand model of a sink restriction the shipping code does not implement.
#
# So: make the table a ledger. Every row names the clause of the sentence it
# covers (verbatim, so a row cannot cover a clause the sentence does not make),
# carries a status from a closed vocabulary, an evidence handle that must
# resolve, and the gate that would catch the status regressing. The checker
# fails on: a dangling handle, an uncovered clause, a deleted row (the clause
# count is pinned — carrying the population, a count that can silently shrink
# rewards deletion), and — the finding that motivated all of this — a row
# claiming live-path status for a subject that another in-tree gate declares
# dormant. Two independent declarations, compared; not a tautology.
#
# Usage: scripts/check-north-star-ledger.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

DOC="docs/north-star.md"
RATCHET="scripts/north-star-ledger-ratchet.txt"
STATUS_HEADING='#### Status'

failures=0
fail() {
    echo "  FAIL  $1"
    failures=$((failures + 1))
}

[[ -f "$DOC" ]] || { echo "ERROR: $DOC not found"; exit 1; }
[[ -f "$RATCHET" ]] || { echo "ERROR: $RATCHET not found — the ledger has no pinned population"; exit 1; }

# ── The sentence ────────────────────────────────────────────────────────────
# The flagship claim, extracted verbatim so clause fragments below are checked
# against what the sentence actually says, not against what a row wishes it said.
sentence="$(awk '/^\*\*Whatever an agent workload does/{grab=1} grab{printf "%s ", $0} grab&&/about\.\*\*$/{exit}' "$DOC" | tr -s '[:space:]' ' ')"

# Non-vacuity: if the anchor moved, everything below would "pass" against an
# empty string. Refuse instead.
if [[ -z "$sentence" || "$sentence" != *"single-use token"* ]]; then
    echo "ERROR: could not extract the North Star sentence from $DOC"
    echo "       (anchor '**Whatever an agent workload does' … 'about.**' moved?)"
    exit 1
fi

# ── The table ───────────────────────────────────────────────────────────────
# Everything between the Status heading and the next heading.
section="$(awk -v h="$STATUS_HEADING" 'index($0,h)==1{grab=1; next} grab && /^#{2,4} /{exit} grab{print}' "$DOC")"

# All table rows (any line starting with '|'), minus the header and separator.
all_rows="$(printf '%s\n' "$section" | grep -E '^\|' | grep -vE '^\|[ -]*-' | grep -viE '^\| *#? *\| *clause|^\| *part of the claim')"
if [[ -z "$all_rows" ]]; then
    echo "ERROR: no table rows found under '$STATUS_HEADING' in $DOC"
    exit 1
fi

# ── Ratchet: the pinned population ──────────────────────────────────────────
# Both directions, like the cmdline five-keys ratchet: a clause vanishing from
# the ledger and a NOT-YET quietly appearing are both events a human must
# acknowledge by editing this file in the same change.
clauses_pinned="$(grep -E '^CLAUSES=' "$RATCHET" | cut -d= -f2)"
not_yet_pinned="$(grep -E '^NOT_YET=' "$RATCHET" | cut -d= -f2)"
if [[ -z "$clauses_pinned" || -z "$not_yet_pinned" ]]; then
    echo "ERROR: $RATCHET must pin CLAUSES=<n> and NOT_YET=<n>"
    exit 1
fi

# ── Per-row checks ──────────────────────────────────────────────────────────
declare -a seen_ids=()
valid_rows=0
not_yet_count=0

while IFS= read -r row; do
    # Strict ledger rows: | C<n> | "<clause fragment>" | STATUS | evidence | falsified-by |
    if [[ ! "$row" =~ ^\|[[:space:]]*C[0-9]+[[:space:]]*\| ]]; then
        fail "row not in ledger format (no clause ID): ${row:0:100}"
        continue
    fi

    id="$(echo "$row"  | awk -F'|' '{gsub(/^ +| +$/,"",$2); print $2}')"
    clause="$(echo "$row" | awk -F'|' '{gsub(/^ +| +$/,"",$3); print $3}')"
    status="$(echo "$row" | awk -F'|' '{gsub(/^ +| +$/,"",$4); print $4}')"
    evidence="$(echo "$row" | awk -F'|' '{gsub(/^ +| +$/,"",$5); print $5}')"
    falsifier="$(echo "$row" | awk -F'|' '{gsub(/^ +| +$/,"",$6); print $6}')"

    # Unique IDs — a duplicated row is double-counted coverage.
    for s in "${seen_ids[@]:-}"; do
        [[ "$s" == "$id" ]] && fail "$id: duplicate clause ID"
    done
    seen_ids+=("$id")

    # The clause fragment must be verbatim in the sentence. Strip the quotes
    # and any markdown emphasis, collapse whitespace, then substring-match.
    frag="$(echo "$clause" | sed -e 's/^"//' -e 's/"$//' -e 's/\*\*//g' | tr -s '[:space:]' ' ' | sed -e 's/^ *//' -e 's/ *$//')"
    if [[ -z "$frag" ]]; then
        fail "$id: empty clause fragment"
    elif [[ "$sentence" != *"$frag"* ]]; then
        fail "$id: clause fragment is not verbatim in the sentence: \"$frag\""
        continue
    fi

    # Closed status vocabulary. "Proved in the model; tested on the live path"
    # is two claims in one cell, which is how the last drift hid.
    case "$status" in
        PROVED|TESTED) : ;;
        NOT-YET) not_yet_count=$((not_yet_count + 1)) ;;
        *) fail "$id: status '$status' not in {PROVED, TESTED, NOT-YET}"; continue ;;
    esac

    # Evidence handles must resolve: `path` (file exists) or `path#symbol`
    # (file exists AND names the symbol). An evidence cell nothing can
    # dereference is prose wearing a column.
    if [[ -z "$evidence" ]]; then
        fail "$id: empty evidence cell"
    fi
    while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        path="${h%%#*}"
        sym=""
        [[ "$h" == *"#"* ]] && sym="${h#*#}"
        if [[ ! -f "$path" ]]; then
            fail "$id: evidence handle dangles — no such file: $path"
        elif [[ -n "$sym" ]] && ! grep -qF "$sym" "$path"; then
            fail "$id: evidence handle dangles — '$sym' not found in $path"
        fi
    done < <(echo "$evidence" | grep -oE '`[^`]+`' | tr -d '`')

    # The falsifier must exist, and a gate script must actually be wired into
    # a workflow — an uncalled falsifier falsifies nothing. NOT-YET rows may
    # carry '—': there is no earned status to regress.
    f="$(echo "$falsifier" | grep -oE '`[^`]+`' | head -1 | tr -d '\`')"
    if [[ -z "$f" || "$f" == "—" ]]; then
        if [[ "$status" != "NOT-YET" ]]; then
            fail "$id: status $status but no falsifying gate named"
        fi
    else
        if [[ ! -f "$f" ]]; then
            fail "$id: falsifier does not exist: $f"
        elif [[ "$f" == scripts/*.sh ]] && ! grep -rql "$f" .github/workflows/ 2>/dev/null; then
            fail "$id: falsifier $f is not invoked by any workflow"
        fi
    fi

    valid_rows=$((valid_rows + 1))
done <<< "$all_rows"

# ── Coverage: every clause of the sentence has a row ────────────────────────
if [[ "$valid_rows" -lt "$clauses_pinned" ]]; then
    fail "clause coverage: $valid_rows valid ledger row(s), but the sentence has $clauses_pinned pinned clauses — the missing rows are the claim's uncovered clauses"
elif [[ "$valid_rows" -gt "$clauses_pinned" ]]; then
    fail "clause coverage: $valid_rows valid rows exceed the $clauses_pinned pinned clauses — raise CLAUSES in $RATCHET in the same change (it may only grow)"
fi

# ── NOT-YET ratchet ─────────────────────────────────────────────────────────
if [[ "$not_yet_count" -gt "$not_yet_pinned" ]]; then
    fail "NOT-YET count rose: $not_yet_count row(s), ratchet pins $not_yet_pinned — a status was demoted; if that is real, raise the pin in $RATCHET and say why in the change"
elif [[ "$not_yet_count" -lt "$not_yet_pinned" ]]; then
    fail "NOT-YET count fell to $not_yet_count but $RATCHET still pins $not_yet_pinned — lower the pin in the same change so the promotion is on the record"
fi

# ── Cross-declaration: live-path claims vs dormancy gates ───────────────────
# A scripts/check-*dormant*.sh gate is an in-tree declaration that some path
# has no production caller. No ledger row may simultaneously claim that
# subject is exercised on the live path. This compares two independent
# declarations that run in the same CI; when they disagree, one of them is
# lying, and the gate refuses to let the table be the one that wins.
for dg in scripts/check-*dormant*.sh; do
    [[ -f "$dg" ]] || continue
    # Subject word derived from the gate's own filename: check-<subject>-…-dormant.sh
    # Stemmed (trailing 'y' dropped) so "declassify" also matches
    # "declassification" — the noun is how the table talks about it.
    subject="$(basename "$dg" | sed -e 's/^check-//' -e 's/-dormant.*$//' | cut -d- -f1)"
    subject="${subject%y}"
    [[ -z "$subject" ]] && continue

    # (a) Prose form: any row about this subject claiming "tested … live path".
    while IFS= read -r row; do
        if echo "$row" | grep -qi "$subject" \
           && echo "$row" | grep -qi 'tested' \
           && echo "$row" | grep -qiE 'live[ -]path'; then
            fail "cross-declaration: this row claims live-path testing for '$subject' while $dg asserts that path is DORMANT (no production caller):"
            echo "        ${row:0:160}"
        fi
    done <<< "$all_rows"

    # (b) Structured form: a PROVED/TESTED row whose evidence cites one of the
    # dormancy gate's own DEFINING_FILES — status earned on a path the gate
    # says nothing reaches.
    defining="$(sed -n '/^DEFINING_FILES=(/,/^)/p' "$dg" | grep -oE '"[^"]+"' | tr -d '"')"
    while IFS= read -r row; do
        [[ "$row" =~ ^\|[[:space:]]*C[0-9]+[[:space:]]*\| ]] || continue
        st="$(echo "$row" | awk -F'|' '{gsub(/^ +| +$/,"",$4); print $4}')"
        [[ "$st" == "PROVED" || "$st" == "TESTED" ]] || continue
        ev="$(echo "$row" | awk -F'|' '{gsub(/^ +| +$/,"",$5); print $5}')"
        while IFS= read -r df; do
            [[ -z "$df" ]] && continue
            if echo "$ev" | grep -qF "$df"; then
                fail "cross-declaration: a $st row cites $df as evidence, but $dg declares that file's path dormant"
            fi
        done <<< "$defining"
    done <<< "$all_rows"
done

echo
if [[ "$failures" -gt 0 ]]; then
    echo "FAILED: $failures problem(s) in the North Star ledger."
    echo "The status table is the claim's public face; a row it cannot back is"
    echo "the exact overclaim the doc's own preamble warns about."
    exit 1
fi
echo "OK: every ledger row covers a verbatim clause, resolves its evidence,"
echo "names its falsifier, and contradicts no in-tree dormancy declaration."
echo "($valid_rows clauses, $not_yet_count NOT-YET — both pinned by $RATCHET)"
