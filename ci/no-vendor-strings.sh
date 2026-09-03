#!/usr/bin/env bash
# ci/no-vendor-strings.sh
#
# Vendor-neutrality CI gate for nucleus-oidc-provider + nucleus-oidc-core
# (the public, MIT-licensed slice of the OIDC stack). Scans the source
# tree for vendor names, vendor hostnames, vendor token-prefix patterns,
# and vendor-coupled synthetic-uid prefixes.
#
# Per nucleus/CLAUDE.md:
#   "NEVER include in nucleus: Anthropic/Claude-specific code or
#    references, OpenAI-specific code or references, Any LLM vendor
#    names, SDKs, or APIs"
#
# Origin: docs/oidc-vendor-neutrality-audit.md (Task #29).
# Consumed by: Task #54 (P5.2 — CI gate).
#
# Allow-list mechanism: a grep match on a line is permitted if the same
# line carries an end-of-line comment `// vendor-allow: <reason>`.
# Reviewer enforces that the reason is genuine (negative test, RFC
# quote, threat-model attacker example).
#
# Exit codes:
#   0  — clean
#   1  — vendor strings found (CI fails)
#   2  — invocation error (no scan paths provided)

set -euo pipefail

# Default scan paths. Override by passing paths on the command line.
SCAN_PATHS=(
    "crates/nucleus-oidc-core"
    "crates/nucleus-oidc-provider"
)
if [[ $# -gt 0 ]]; then
    SCAN_PATHS=("$@")
fi

for p in "${SCAN_PATHS[@]}"; do
    if [[ ! -e "$p" ]]; then
        # Not an error if a path doesn't exist yet — the OIDC crates land
        # progressively. CI runs this script even before #32 lands.
        continue
    fi
done

# Patterns — sourced from docs/oidc-vendor-neutrality-audit.md §4.
#
# Each pattern is one extended-regex. We use `grep -E -i` for case-
# insensitive matching across all of them. Word-boundary anchors (`\b`)
# prevent false positives like "gripfly" matching "fly".

PATTERNS=(
    # Vendor crate names
    'nucleus-(fly|github|anthropic|openai|google|vercel|cloudflare)-(oidc|tool|wif)'

    # Vendor product / company names
    '\b(fly\.?io|flyio)\b'
    '\b(github(-?actions?)?|gh-?actions?)\b'
    '\b(anthropic|claude(-?code)?|sonnet|opus|haiku)\b'
    '\b(openai|gpt-?[0-9]|chatgpt|davinci|whisper)\b'
    '\b(gemini|bard|google-?ai|vertex-?ai)\b'
    '\b(vercel|cloudflare|fastly)\b'

    # Vendor hostnames + paths
    'https?://([a-z0-9-]+\.)*(fly\.io|fly\.dev|github\.com|githubusercontent\.com|anthropic\.com|openai\.com|googleusercontent\.com)'

    # Vendor token-prefix patterns (catch accidental real-token leak)
    '\bsk-(ant|or|live|test)-[A-Za-z0-9_]+'
    '\bgh[ps]_[A-Za-z0-9]+'
    '\bxoxb-[0-9-]+-[A-Za-z0-9]+'

    # Vendor-coupled synthetic-uid prefixes (nucleus-platform convention)
    '\bb-(gh|fly|anthropic|openai)-'
)

violations=0
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

for pattern in "${PATTERNS[@]}"; do
    # Filter:
    #   --include= globs limit to source/config/doc surfaces
    #   --exclude-dir= skips build artifacts and vendored deps
    #   -E extended regex, -i case-insensitive, -n line numbers, -H show filename
    # We post-filter to drop lines carrying `// vendor-allow:` annotations.
    grep -RHnE -i "$pattern" \
        --include="*.rs" \
        --include="*.toml" \
        --include="*.md" \
        --include="*.yaml" \
        --include="*.yml" \
        --include="*.json" \
        --exclude-dir=target \
        --exclude-dir=node_modules \
        --exclude-dir=.git \
        "${SCAN_PATHS[@]}" 2>/dev/null \
        | grep -v 'vendor-allow:' >>"$tmpfile" || true
done

# ---------------------------------------------------------------------------
# Repo-wide pass: hardcoded vendor MODEL IDENTIFIERS.
#
# The pattern list above is deliberately scoped to SCAN_PATHS, because names
# like `.claude/settings.json`, `CLAUDECODE` and `nucleus-claude-hook` are
# intrinsic interop that legitimately appears across the tree.
#
# A hardcoded vendor *model id* is different: it is a defect ANYWHERE. Nucleus
# does not choose which model runs -- that is the orchestrator's job
# (CLAUDE.md) -- and a pinned model id also rots the moment the vendor retires
# that model. This pattern matches `<family>-<something>-<digit>` shapes such
# as `claude-sonnet-4-20250514` or `gpt-4o`, and provably does NOT match the
# intrinsic interop names above.
MODEL_ID_PATTERN='\b(claude|gpt|gemini|llama|mistral|grok)-[a-z0-9]+([.-][a-z0-9]+)*-?[0-9]'
MODEL_SCAN_ROOTS=("crates" "ci" "scripts" "docs" ".github")

modelfile="$(mktemp)"
trap 'rm -f "$modelfile"' EXIT
for root in "${MODEL_SCAN_ROOTS[@]}"; do
    [[ -e "$root" ]] || continue
    grep -RHnE -i "$MODEL_ID_PATTERN" \
        --include="*.rs" --include="*.toml" --include="*.md" \
        --include="*.yaml" --include="*.yml" --include="*.json" \
        --exclude-dir=target --exclude-dir=node_modules --exclude-dir=.git \
        --exclude-dir=.lake \
        "$root" 2>/dev/null \
        | grep -v 'vendor-allow:' >>"$modelfile" || true
done

if [[ -s "$modelfile" ]]; then
    sort -u "$modelfile" -o "$modelfile"
    echo "FAIL: hardcoded vendor model id(s) found — $(wc -l <"$modelfile" | tr -d ' ')" >&2
    echo "" >&2
    echo "Nucleus must not name a specific vendor model. Take the value from" >&2
    echo "configuration or leave it unset so the external agent binary applies" >&2
    echo "its own default; choosing a model is the orchestrator's decision." >&2
    echo "" >&2
    echo "Allow-list a line by appending: vendor-allow: <reason>" >&2
    echo "" >&2
    cat "$modelfile" >&2
    exit 1
fi

if [[ -s "$tmpfile" ]]; then
    # Deduplicate (a line may match multiple patterns).
    sort -u "$tmpfile" >"${tmpfile}.dedup"
    mv "${tmpfile}.dedup" "$tmpfile"
    violations=$(wc -l <"$tmpfile" | tr -d ' ')

    echo "FAIL: vendor-neutrality CI gate — ${violations} violation(s) found." >&2
    echo "" >&2
    echo "Per nucleus/CLAUDE.md, the following paths must contain no vendor-specific code:" >&2
    for p in "${SCAN_PATHS[@]}"; do
        echo "  - ${p}" >&2
    done
    echo "" >&2
    echo "Allow-list a line by appending: vendor-allow: <reason>" >&2
    echo "  (in any comment form: // ..., # ..., <!-- ... -->)" >&2
    echo "" >&2
    echo "Violations:" >&2
    cat "$tmpfile" >&2
    exit 1
fi

echo "OK: vendor-neutrality CI gate clean across paths: ${SCAN_PATHS[*]}"
exit 0
