#!/usr/bin/env bash
# The INPUTS of a gate, derived from the gate's own text rather than listed beside it.
#
# `check-gates-can-fail.sh` asks, per probe, whether gate G REDs on a violation of its subject
# and GREENs when it is restored. That answer is a function of G's code and of what G reads. A
# change that touches none of those cannot move it, so a pull request only has to re-ask the
# probes whose inputs it touched -- and this file is what says which those are.
#
# It is derived, not declared, for the reason the gate of gates gives about its own domain: a
# hand-kept list is a membership test and cannot say that everything read is listed. What is
# derived here, per gate:
#
#   code   the gate script, and transitively every script it names;
#          every cargo package it builds or runs (`-p`, `--package`, `--manifest-path`,
#          `--workspace`, `xtask -- <sub>`) with that package's path-dependency closure, plus
#          Cargo.lock, the root Cargo.toml, rust-toolchain.toml and .cargo/. `cargo tree` and
#          `cargo metadata` read only manifests, so for them only the Cargo.toml files count.
#   named  every tracked FILE the code names -- by path, or by bare name (every file of that
#          name, since a bare name may be read after a `cd`) -- in the script, in a python
#          heredoc inside it, or, for an xtask subcommand, in the string literals of its module
#          and the modules it uses. These are the gate's fixed inputs: its allowlists, ratchets,
#          manifests, ledgers, pinned configs.
#
# What is NOT derived, and is not claimed: the set a gate WALKS -- a directory or a glob it names
# (`crates/nucleus-tool-proxy/src`, `crates/**/*.rs`), or a walk it does not spell at all
# (`find . -name '*.lean'`, cargo's workspace walk, a path read out of a ledger).
# That is the gate's SUBJECT corpus, and the probe plants its violation in one named member of it
# -- the target, which IS an input. check-gates-can-fail.sh ("SCOPED RUNS") says why skipping on
# the rest of the corpus is safe, what would make it unsafe, and which full run catches that.
#
# Usage:
#   scripts/gate-inputs.sh script <check-x.sh>    # print the gate's input pathspecs
#   scripts/gate-inputs.sh xtask <subcommand>
#   scripts/gate-inputs.sh --self-test            # the selection fixtures; run by the engine
#
# Sourced by check-gates-can-fail.sh; every function is prefixed `gi_`. Bash 3.2-safe (no
# associative arrays): the gauntlet runs this on macOS.

# Paths whose change must re-run EVERY probe: the engine that runs them, this derivation, and
# the workflow that defines the job they execute in (runner, toolchain, checkout). A change to
# any of these can move every answer at once, and no per-gate input set would say so.
GI_ENGINE=(
    "scripts/check-gates-can-fail.sh"
    "scripts/gate-inputs.sh"
    ".github/workflows/ci.yml"
)

# What every cargo-built gate depends on besides its packages.
GI_CARGO_COMMON=(
    "Cargo.lock"
    "Cargo.toml"
    "rust-toolchain.toml"
    ".cargo/"
)

# An inherited GI_TMP is reused, derivation cache and all: the self-test runs the engine
# several times, and each run re-deriving every gate's inputs is most of its cost. Only the
# process that created the directory removes it.
GI_TMP="${GI_TMP:-}"
GI_OWNED=0
gi_init() {
    [[ -n "$GI_TMP" && -d "$GI_TMP/cache" ]] && return 0
    GI_TMP="$(mktemp -d "${TMPDIR:-/tmp}/gate-inputs.XXXXXX")"
    GI_OWNED=1
    git ls-files > "$GI_TMP/files"
    # Every ancestor directory of every tracked file, so a named directory resolves.
    awk -F/ '{ p = ""; for (i = 1; i < NF; i++) { p = (p == "" ? $i : p "/" $i); print p } }' \
        "$GI_TMP/files" | sort -u > "$GI_TMP/dirs"
    # basename <TAB> path, for bare file names.
    awk -F/ '{ print $NF "\t" $0 }' "$GI_TMP/files" > "$GI_TMP/base"
    # package name <TAB> package dir, from every tracked manifest's [package] name. One awk over
    # all of them: a process per manifest was most of this function's second.
    grep -E '(^|/)Cargo\.toml$' "$GI_TMP/files" | tr '\n' '\0' | xargs -0 awk '
        FNR == 1       { inpkg = 0; done = 0 }
        /^\[package\]/ { inpkg = 1; next }
        /^\[/          { inpkg = 0 }
        inpkg && !done && /^name[[:space:]]*=/ {
            v = $0; sub(/^[^"]*"/, "", v); sub(/".*$/, "", v)
            d = FILENAME; sub(/\/?Cargo\.toml$/, "", d); if (d == "") d = "."
            print v "\t" d; done = 1
        }' > "$GI_TMP/pkgs"
    mkdir -p "$GI_TMP/cache"
}
gi_cleanup() {
    if [[ "$GI_OWNED" == "1" && -n "$GI_TMP" ]]; then rm -rf "$GI_TMP"; fi
    return 0
}

# Collapse `a/b/../c` and `./` segments. Paths here are repo-relative. Pure bash: it runs once
# per path dependency, and a process each was a measurable part of a scoped run.
gi_norm() {
    local IFS=/ seg out=() n
    # shellcheck disable=SC2206
    local parts=($1)
    for seg in "${parts[@]}"; do
        case "$seg" in
            ''|.) ;;
            ..) n=${#out[@]}; [[ $n -gt 0 ]] && unset "out[$((n - 1))]" && out=("${out[@]}") ;;
            *)  out+=("$seg") ;;
        esac
    done
    printf '%s\n' "${out[*]}"
}

# Candidate path tokens from one file: comment lines and trailing ` # ` comments dropped, and the
# right-hand side of a pattern match (`[[ "$f" == scripts/*.sh ]]`) dropped too -- a glob a gate
# COMPARES against is not a set of files it reads.
gi_tokens() {
    grep -vE '^[[:space:]]*(#|//)' "$1" 2>/dev/null \
        | sed -E 's/[[:space:]]#[[:space:]].*$//; s/[=!]=[[:space:]]*"?[^ ]*//g' \
        | grep -oE '(\$\(dirname "?\$0"?\)/(\.\./)?|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/)?[A-Za-z0-9_.*?-]*(/[A-Za-z0-9_.*?{}-]+)+/?|\.?[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\.(sh|py|txt|toml|json|md|lean|yml|yaml|lock|rs|writ)' \
        | sed -E 's#^\$\(dirname "?\$0"?\)/\.\./##; s#^\$\(dirname "?\$0"?\)/#scripts/#; s#^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/##; s#^\./##; s#[.]+$##' \
        | sort -u
}

# Rust string literals from one source file, comment lines dropped. `../`-relative literals
# (include_str!) are resolved against the file's own directory, and kept only if they name a file.
gi_rust_literals() {
    local src="$1" dir
    dir="$(dirname "$src")"
    grep -vE '^[[:space:]]*//' "$src" 2>/dev/null \
        | grep -oE '"([^"\\]|\\.)*"' \
        | sed -E 's/^"//; s/"$//' \
        | grep -E '^[A-Za-z0-9_./*?-]+$' \
        | while IFS= read -r lit; do
            case "$lit" in
                # `include_str!("../x")` names a file beside the source. `.join("../..")`
                # climbs from the manifest dir to the root and names no input at all, so a
                # relative literal counts only when it lands on a tracked FILE.
                ../*) lit="$(gi_norm "$dir/$lit")"
                      grep -qxF -- "$lit" "$GI_TMP/files" && printf '%s\n' "$lit" ;;
                *)    printf '%s\n' "${lit#./}" ;;
            esac
        done | sort -u
}

# Tokens on stdin -> the tracked FILES they name, on stdout.
#
# A path names that file. A BARE file name (`kani-divergence.toml`, `lakefile.lean`) names every
# tracked file with that name: it may be a fixed file read after a `cd`, or a `find -name`
# pattern, and matching every copy is the only reading that cannot miss the first.
#
# A directory or a glob names nothing here. It is a set the gate WALKS -- its subject corpus --
# and a member of it is not a fixed input of the probe; see "What is NOT derived" at the top.
# Code directories are inputs, but arrive by another route: gi_pkg_dirs adds a cargo package
# whole.
gi_resolve() {
    local toks="$GI_TMP/toks.$$"
    sed -E 's#/+$##; s#^\./##' | grep -v '^$' | sort -u > "$toks"
    grep -Fxf "$toks" "$GI_TMP/files" || true
    grep -v / "$toks" | grep -v '[*?]' \
        | awk -F'\t' 'NR == FNR { want[$0] = 1; next } ($1 in want) { print $2 }' - "$GI_TMP/base" || true
    rm -f "$toks"
}

# Tokens that look like a repo path -- they begin with a tracked top-level directory -- and
# name nothing tracked. A gate that reads a path this cannot resolve has an input this cannot
# see; the self-test fails on them for PROBED gates rather than let the set shrink silently.
gi_unresolved() {
    local f="$1" t top
    gi_tokens "$f" | while IFS= read -r t; do
        t="${t%/}"
        [[ "$t" == */* ]] || continue
        top="${t%%/*}"
        grep -qxF -- "$top" "$GI_TMP/dirs" || continue
        case "$t" in *[*?{}]*) continue ;; esac
        grep -qxF -- "$t" "$GI_TMP/files" && continue
        grep -qxF -- "$t" "$GI_TMP/dirs" && continue
        printf '%s\n' "$t"
    done
}

# A package and its path-dependency closure, as package directories. Cached per package.
gi_pkg_dirs() {
    local cache="$GI_TMP/cache/pkg.$1"
    if [[ ! -f "$cache" ]]; then
        local queue=() seen="" d m p
        d="$(awk -F'\t' -v n="$1" '$1 == n { print $2; exit }' "$GI_TMP/pkgs")"
        [[ -n "$d" ]] && queue=("$d")
        while [[ "${#queue[@]}" -gt 0 ]]; do
            d="${queue[0]}"; queue=("${queue[@]:1}")
            case "$seen" in *"<$d>"*) continue ;; esac
            seen="$seen<$d>"
            printf '%s\n' "$d"
            m="$d/Cargo.toml"
            [[ -f "$m" ]] || continue
            while IFS= read -r p; do
                p="$(gi_norm "$d/$p")"
                # `[lib] path = "src/lib.rs"` also matches; only a directory with a manifest is a dep.
                [[ -f "$p/Cargo.toml" ]] && queue+=("$p")
            done < <(grep -oE 'path[[:space:]]*=[[:space:]]*"[^"]+"' "$m" | sed -E 's/^[^"]*"//; s/"$//')
        done > "$cache"
    fi
    cat "$cache"
}

# Every package a line of shell names, with how much of it is read.
gi_cargo_inputs() {
    local f="$1" line mode pkg d
    grep -vE '^[[:space:]]*#' "$f" | grep -E '(^|[^A-Za-z0-9_-])cargo[[:space:]]' | while IFS= read -r line; do
        mode=full
        printf '%s\n' "$line" | grep -qE 'cargo[[:space:]]+(tree|metadata)' && mode=manifest
        printf '%s\n' "${GI_CARGO_COMMON[@]}"
        {
            printf '%s\n' "$line" | grep -oE '(-p|--package)[[:space:]=]+[A-Za-z0-9_-]+' | sed -E 's/^(-p|--package)[[:space:]=]+//'
            printf '%s\n' "$line" | grep -oE -- '--manifest-path[[:space:]=]+[^[:space:]]+' \
                | sed -E 's/^--manifest-path[[:space:]=]+//; s/"//g; s#^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/##' \
                | while IFS= read -r mp; do
                    awk -F'\t' -v d="$(dirname "$mp")" '$2 == d { print $1 }' "$GI_TMP/pkgs"
                done
        } | sort -u | while IFS= read -r pkg; do
            gi_pkg_dirs "$pkg" | while IFS= read -r d; do
                if [[ "$mode" == manifest ]]; then printf '%s\n' "$d/Cargo.toml"; else printf '%s/\n' "$d"; fi
            done
        done
        # `--workspace` is every package: no closure to walk.
        if printf '%s\n' "$line" | grep -qE -- '--workspace'; then
            if [[ "$mode" == manifest ]]; then
                grep -E '(^|/)Cargo\.toml$' "$GI_TMP/files"
            else
                cut -f2 "$GI_TMP/pkgs" | sed 's#$#/#'
            fi
        fi
        printf '%s\n' "$line" | grep -oE 'xtask -- [a-z][a-z-]*' | sed 's/xtask -- //' \
            | while IFS= read -r sub; do gi_xtask_inputs "$sub"; done
    done
}

# An xtask subcommand: the xtask package closure, plus the paths its module names.
#
# The module is `crates/xtask/src/<sub_with_underscores>.rs`, else the longest leading part of
# the name that is one (`scoreboard-ratchet` -> scoreboard.rs), else main.rs, where a subcommand
# with no module of its own is implemented. Every module it reaches by `crate::m` / `super::m`
# is scanned too, since that is code it runs.
gi_xtask_inputs() {
    local sub="$1" cache="$GI_TMP/cache/xtask.$1"
    if [[ ! -f "$cache" ]]; then
        {
            printf '%s\n' "${GI_CARGO_COMMON[@]}"
            gi_pkg_dirs xtask | sed 's#$#/#'
            local src="crates/xtask/src" name="${sub//-/_}" mod="" queue=() seen="" m
            while [[ -n "$name" ]]; do
                [[ -f "$src/$name.rs" ]] && { mod="$src/$name.rs"; break; }
                [[ "$name" == *_* ]] || break
                name="${name%_*}"
            done
            [[ -z "$mod" ]] && mod="$src/main.rs"
            queue=("$mod")
            while [[ "${#queue[@]}" -gt 0 ]]; do
                m="${queue[0]}"; queue=("${queue[@]:1}")
                case "$seen" in *"<$m>"*) continue ;; esac
                seen="$seen<$m>"
                [[ -f "$m" ]] || continue
                gi_rust_literals "$m" | gi_resolve
                while IFS= read -r name; do
                    [[ -f "$src/$name.rs" ]] && queue+=("$src/$name.rs")
                done < <(grep -oE '(crate|super)::[a-z_]+' "$m" | sed -E 's/^(crate|super):://' | sort -u)
            done
        } | sort -u > "$cache"
    fi
    cat "$cache"
}

# A gate script: itself, what it names, the scripts it names (transitively), its cargo packages.
gi_script_inputs() {
    local gate="$1" key cache
    key="script.$(printf '%s' "$gate" | tr '/' '_')"
    cache="$GI_TMP/cache/$key"
    if [[ ! -f "$cache" ]]; then
        local queue=("$gate") seen="" f r
        {
            while [[ "${#queue[@]}" -gt 0 ]]; do
                f="${queue[0]}"; queue=("${queue[@]:1}")
                case "$seen" in *"<$f>"*) continue ;; esac
                seen="$seen<$f>"
                [[ -f "$f" ]] || continue
                printf '%s\n' "$f"
                while IFS= read -r r; do
                    printf '%s\n' "$r"
                    case "$r" in
                        */) ;;
                        *[*?]*) ;;
                        *.sh|*.py) queue+=("$r") ;;
                    esac
                done < <(gi_tokens "$f" | gi_resolve)
                gi_cargo_inputs "$f"
            done
        } | sort -u > "$cache"
    fi
    cat "$cache"
}

# Paths the named shell functions (a probe's perturbation, its generators) name. They live in
# the engine, so they also change only with it -- but a generator that READS a file makes that
# file an input of its probe, and the engine changing is not the only way that file changes.
gi_function_inputs() {
    local fn cache
    for fn in "$@"; do
        [[ -n "$fn" ]] || continue
        cache="$GI_TMP/cache/fn.$fn"
        if [[ ! -f "$cache" ]]; then
            declare -f "$fn" > "$cache.src" 2>/dev/null || { : > "$cache"; continue; }
            { gi_tokens "$cache.src" | gi_resolve; gi_cargo_inputs "$cache.src"; } > "$cache"
        fi
        cat "$cache"
    done
}

# gi_match <pathspec> <file>: does a changed file fall under an input?
gi_match() {
    local p="$1" f="$2"
    case "$p" in
        */)     [[ "$f" == "$p"* ]] ;;
        *[*?]*) # shellcheck disable=SC2053
                [[ "$f" == $p ]] ;;
        *)      [[ "$f" == "$p" ]] ;;
    esac
}

# gi_first_hit <inputs-file> <changed-file>: print "changed<TAB>input" for the first changed
# path that falls under an input, and succeed; fail if none does.
gi_first_hit() {
    local inputs="$1" changed="$2" f p
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        while IFS= read -r p; do
            [[ -n "$p" ]] || continue
            if gi_match "$p" "$f"; then printf '%s\t%s\n' "$f" "$p"; return 0; fi
        done < "$inputs"
    done < "$changed"
    return 1
}

# ── Self-test ──────────────────────────────────────────────────────────────
#
# The selection is only worth what it has been shown to select. Fixtures, run through the
# engine's own `--plan` mode (the code path CI takes, with nothing executed):
#
#   * a diff touching ONE gate script selects exactly that gate's probes;
#   * a diff touching the engine, this file or ci.yml selects every probe;
#   * a gate-code path no probe names -- an undeclared input -- selects none on a pull request
#     and every probe in the merge-queue backstop;
#   * an empty diff selects none, with a reason printed per probe -- and `--vacuity-only` stays
#     its own unscoped step in ci.yml (read from the workflow, not assumed).
#
# Plus non-vacuity of the derivation: every probed shell gate's input set contains its own
# script, every xtask probe's contains crates/xtask/, and no probed gate names a repo path the
# resolver cannot find -- an input nobody would see change.
gi_self_test() {
    local engine="scripts/check-gates-can-fail.sh" fx out fails=0 g
    fx="$(mktemp "${TMPDIR:-/tmp}/gi-fixture.XXXXXX")"
    out="$(mktemp "${TMPDIR:-/tmp}/gi-plan.XXXXXX")"
    gi_init
    export GI_TMP

    # The probed shell gates and xtask subcommands, from the probe table itself.
    local gates subs
    gates="$(grep -oE '^probe[[:space:]]+check-[A-Za-z0-9_-]+\.sh' "$engine" | awk '{ print $2 }' | sort -u)"
    subs="$(grep -oE '^probe_xtask[a-z_]*[[:space:]]+[a-z][a-z-]*' "$engine" | awk '{ print $2 }' | sort -u)"
    if [[ "$(printf '%s\n' "$gates" | grep -c .)" -lt 10 || "$(printf '%s\n' "$subs" | grep -c .)" -lt 5 ]]; then
        echo "  FAIL  self-test: read too few probes from $engine; the fixtures would be vacuous"
        return 1
    fi

    # 1. One gate script selects exactly that gate's probes. The fixture is named rather than
    #    searched for, so the assertion is about this table and cannot be satisfied by picking
    #    whichever gate happens to pass. (`xtask portability` lints every script, but it WALKS
    #    scripts/ -- corpus, not a named input -- so it is rightly not selected.)
    local pick="check-kani-divergence.sh" want got extra
    printf 'scripts/%s\n' "$pick" > "$fx"
    bash "$engine" --plan --changed-files "$fx" > "$out" 2>&1
    want="$(grep -cE "^probe[[:space:]]+$pick([[:space:]]|$)" "$engine")"
    got="$(grep -cE "^  run   $pick " "$out")"
    extra="$(grep -E '^  run   ' "$out" | grep -vE "^  run   $pick " || true)"
    if [[ "$want" -lt 1 ]]; then
        echo "  FAIL  self-test: $pick is no longer probed; name another fixture gate"
        fails=$((fails + 1))
    elif [[ "$got" -ne "$want" ]] || [[ -n "$extra" ]]; then
        echo "  FAIL  self-test: a diff touching scripts/$pick selected $got of its $want probe(s), plus:"
        printf '%s\n' "$extra" | sed 's/^/        /'
        fails=$((fails + 1))
    else
        echo "  ok    self-test: scripts/$pick alone selects exactly its $want probe(s)"
    fi

    # 2. The engine: everything.
    local total
    total="$(grep -cE '^probe(_xtask[a-z_]*)?[[:space:]]+[a-z]' "$engine")"
    for g in "${GI_ENGINE[@]}"; do
        printf '%s\n' "$g" > "$fx"
        bash "$engine" --plan --changed-files "$fx" > "$out" 2>&1
        got="$(grep -cE '^  run   ' "$out")"
        if [[ "$got" -ne "$total" ]] || [[ "$(grep -cE '^  skip  ' "$out")" -ne 0 ]]; then
            echo "  FAIL  self-test: a diff touching $g selected $got of $total probes; the engine must select all"
            fails=$((fails + 1))
        else
            echo "  ok    self-test: $g selects all $total probes"
        fi
    done

    # 2b. The backstop. A gate-code path no probe's derivation names -- the shape of an
    #     UNDECLARED input -- is skipped by the pull-request scope and runs everything in the
    #     merge queue. That difference is the argument that such an input is caught before it
    #     lands, so it is asserted rather than described.
    local undeclared="scripts/demo.sh"
    printf '%s\n' "$undeclared" > "$fx"
    bash "$engine" --plan --changed-files "$fx" > "$out" 2>&1
    got="$(grep -cE '^  run   ' "$out")"
    bash "$engine" --plan --backstop-from fixture --changed-files "$fx" > "$out" 2>&1
    local backstop
    backstop="$(grep -cE '^  run   ' "$out")"
    if [[ ! -f "$undeclared" ]] || [[ "$got" -ne 0 ]] || [[ "$backstop" -ne "$total" ]]; then
        echo "  FAIL  self-test: $undeclared (no probe's input) selected $got scoped and $backstop of $total in the backstop;"
        echo "        want 0 and all -- the backstop is what catches an input the derivation missed"
        fails=$((fails + 1))
    else
        echo "  ok    self-test: $undeclared is no probe's input: 0 scoped, all $total in the merge-queue backstop"
    fi

    # 3. Empty: nothing, each skip with its reason, and the cheap half unaffected.
    : > "$fx"
    bash "$engine" --plan --changed-files "$fx" > "$out" 2>&1
    got="$(grep -cE '^  run   ' "$out")"
    if [[ "$got" -ne 0 ]] || [[ "$(grep -cE '^  skip  .* — none of its [0-9]+ input' "$out")" -ne "$total" ]]; then
        echo "  FAIL  self-test: an empty diff selected $got probe(s), or skipped one without a reason"
        fails=$((fails + 1))
    else
        echo "  ok    self-test: an empty diff selects none, and says why for each of $total"
    fi
    if ! grep -qE '^[[:space:]]*run: scripts/check-gates-can-fail\.sh --vacuity-only$' .github/workflows/ci.yml; then
        echo "  FAIL  self-test: ci.yml no longer runs --vacuity-only as its own unscoped step"
        fails=$((fails + 1))
    fi

    # 4. The derivation is not vacuous, and sees every path a probed gate names.
    local unres
    for g in $gates; do
        if ! gi_script_inputs "scripts/$g" | grep -qxF "scripts/$g"; then
            echo "  FAIL  self-test: the input set of $g does not contain its own script"
            fails=$((fails + 1))
        fi
        unres="$(gi_unresolved "scripts/$g" | tr '\n' ' ')"
        if [[ -n "$unres" ]]; then
            echo "  FAIL  self-test: $g names path(s) the tree does not have: $unres"
            echo "        Either the gate reads something this cannot resolve -- an input nobody"
            echo "        would see change -- or the reference is stale. Fix whichever it is."
            fails=$((fails + 1))
        fi
    done
    for g in $subs; do
        if ! gi_xtask_inputs "$g" | grep -qxF "crates/xtask/"; then
            echo "  FAIL  self-test: the input set of xtask $g does not contain crates/xtask/"
            fails=$((fails + 1))
        fi
    done

    rm -f "$fx" "$out"
    [[ "$fails" -eq 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -uo pipefail
    cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 2
    gi_init
    trap gi_cleanup EXIT
    case "${1:-}" in
        script)      gi_script_inputs "scripts/${2:?gate script}" ;;
        xtask)       gi_xtask_inputs "${2:?subcommand}" ;;
        --self-test) gi_self_test ;;
        *) echo "usage: $0 script <check-x.sh> | xtask <sub> | --self-test" >&2; exit 2 ;;
    esac
fi
