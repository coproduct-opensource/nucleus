#!/usr/bin/env bash
# The one step, in order: the binaries (checked against the release's SHA256SUMS), this run's
# key, its OIDC token traded for a tenant and a credential, the gate definition from the
# inputs, the runner, the receipt pushed to the hosted log and verified here against the
# tenant's trust and the proof that came back, the plain run for comparison, the observation
# posted, the summary. Exit 1 only when something could not be looked at; a gate that does not
# hold, or disagrees with the plain run, is reported, never a red.
set -euo pipefail

say() { echo "gatehouse: $*"; }
die() { echo "::error::gatehouse: $*"; exit 1; }
out() { echo "$1=$2" >> "$GITHUB_OUTPUT"; }

W="$(mktemp -d)"
NAME="${GH_NAME:-$GH_JOB}"
CONTROL="${GH_CONTROL%/}"

# ── 1. The binaries, from the release the caller pinned, checked before anything runs ──────
case "$(uname -m)" in
  x86_64) TARGET=x86_64-unknown-linux-musl ;;
  aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
  *) die "no gatehouse build for $(uname -m)" ;;
esac
BIN="$RUNNER_TEMP/gatehouse-$GH_VERSION/bin"
if [ -n "${GH_BIN_DIR:-}" ]; then
  BIN="$(cd "$GH_BIN_DIR" && pwd)"
  [ -x "$BIN/gate" ] && [ -x "$BIN/gatehouse-runner" ] || die "bin-dir $BIN has no gate and gatehouse-runner"
elif [ ! -x "$BIN/gate" ]; then
  mkdir -p "$BIN"
  BASE="https://github.com/$GH_BINARIES/releases/download/$GH_VERSION"
  curl -sSfL --retry 3 -o "$W/tarball.tgz" "$BASE/gatehouse-$TARGET.tar.gz" || die "cannot fetch $BASE/gatehouse-$TARGET.tar.gz"
  curl -sSfL --retry 3 -o "$W/SHA256SUMS" "$BASE/SHA256SUMS" || die "cannot fetch $BASE/SHA256SUMS"
  WANT="$(grep " gatehouse-$TARGET.tar.gz\$" "$W/SHA256SUMS" | cut -d' ' -f1)"
  [ -n "$WANT" ] || die "SHA256SUMS names no gatehouse-$TARGET.tar.gz"
  HAVE="$(sha256sum "$W/tarball.tgz" | cut -d' ' -f1)"
  [ "$WANT" = "$HAVE" ] || die "gatehouse-$TARGET.tar.gz does not match SHA256SUMS ($HAVE, want $WANT)"
  tar -C "$BIN" -xzf "$W/tarball.tgz"
fi
GATE="$BIN/gate"; RUNNER="$BIN/gatehouse-runner"
RUNNER_DIGEST="$(sha256sum "$RUNNER" | cut -d' ' -f1)"

# ── 2. This run's key, and its identity: the OIDC token GitHub minted for this audience ────
"$GATE" key new --out "$W/key.json" >/dev/null
VK="$(jq -r .verifying_key_hex "$W/key.json")"; SK="$(jq -r .signing_key_hex "$W/key.json")"
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || die "no OIDC token: the job needs 'permissions: id-token: write'"
ID_TOKEN="$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${CONTROL}" | jq -r .value)"
[ -n "$ID_TOKEN" ] && [ "$ID_TOKEN" != null ] || die "the OIDC token request returned nothing"
EXCHANGE="$(curl -sS --fail-with-body --max-time 30 -H 'content-type: application/json' -X POST \
  --data "$(jq -cn --arg t "$ID_TOKEN" --arg vk "$VK" '{id_token: $t, verifying_key_hex: $vk}')" \
  "$CONTROL/v1/github/oidc/credential")" || die "the control plane refused this run's token: $EXCHANGE"
TENANT="$(jq -r .tenant <<<"$EXCHANGE")"; KID="$(jq -r .kid <<<"$EXCHANGE")"; BEARER="$(jq -r .bearer <<<"$EXCHANGE")"
say "tenant $TENANT, key $KID (developer tier, trusted from log size $(jq -r .log.size <<<"$EXCHANGE"))"

# ── 3. The gate, from the inputs: what it reads, what it sees, what it runs, how long ──────
INCLUDE="$(printf '%s\n' "$GH_SCOPE" | sed '/^[[:space:]]*$/d' | jq -R . | jq -sc .)"
ENVJ="$(printf '%s\n' "$GH_ENV" | sed '/^[[:space:]]*$/d' | jq -Rn '[inputs | capture("^(?<k>[^=]+)=(?<v>.*)$")] | from_entries')"
for v in RUSTUP_HOME CARGO_HOME; do
  if [ -n "${!v:-}" ]; then ENVJ="$(jq -c --arg k "$v" --arg val "${!v}" '. + {($k): $val}' <<<"$ENVJ")"; fi
done
# The environment digest names this runner's image, as a Developer-tier claim about where the
# command ran; a hosted executor names an OCI image by digest instead.
IMAGE="sha256:$(printf '%s' "${ImageOS:-unknown}/${ImageVersion:-unknown}" | sha256sum | cut -d' ' -f1)"
TIMEOUT_MS=$(( GH_TIMEOUT * 1000 ))
jq -n --argjson inc "$INCLUDE" --argjson env "$ENVJ" --arg img "$IMAGE" --arg run "$GH_RUN" \
   --argjson t "$GH_TIMEOUT" --argjson tms "$TIMEOUT_MS" --argjson hist "$( [ "$GH_GIT_HISTORY" = true ] && echo true || echo false )" '
  { scope: {include: $inc, exclude: [], external: [], git_history: $hist},
    env: {image: $img, platform: "linux/amd64", toolchains: {}, env_vars: $env},
    cap: {net: "none", fs_read: $inc, fs_write: ["**"], exec: "scoped", wall_ms: $tms, cpu_ms: $tms, mem_mb: 8192, secrets: []},
    cmd: ["bash", "-c", $run], cwd: "", timeout_s: $t, outputs: [],
    resources: {cpus: 2, mem_mb: 8192, disk_mb: 16384}, falsifier: null }' > "$W/gate.json"
PLAN="$(printf 'p%.0s' $(seq 1 64))"
jq -n --arg plan "$PLAN" --arg kid "$KID" --arg sk "$SK" --arg rd "$RUNNER_DIGEST" --arg repo "$GH_REPOSITORY" \
  --slurpfile g "$W/gate.json" --arg gn "$NAME" \
  '{repo: $repo, repo_path: ".", tree_spec: "HEAD", plan: $plan, gate_name: $gn, gate: $g[0], canary: null,
    kid: $kid, signing_key_hex: $sk, substrate: "developer", credential_kind: "dev_credential",
    credential_tier: "developer", runner_digest: $rd, binding: null}' > "$W/job.json"

# ── 4. The runner: materialize, run, sign ──────────────────────────────────────────────────
# An OUTER deadline on the runner itself, above the gate's own `timeout_s`.
#
# The gate's timeout bounds the COMMAND. It says nothing about the runner
# hanging anywhere else — materializing the scope, reading a pipe, signing —
# and on 2026-09-11 exactly that happened: a deadlock in the runner's log
# reader (gatehouse F-100) hung every shadow job until GitHub cancelled it,
# which produces no receipt, no log and no diagnosis. `timeout` turns that into
# exit 124 and the message below.
#
# The slack is deliberate: the runner must be allowed to hit its own deadline,
# kill the command and write an honest `errored` receipt before this fires.
set +e; timeout --signal=TERM --kill-after=30 "$(( GH_TIMEOUT + 120 ))" \
  "$RUNNER" "$W/job.json" "$W/receipt.json"; RC=$?; set -e
case "$RC" in
  0) VERDICT=held ;;
  1) VERDICT=failed ;;
  124|137) die "the runner did not finish within $(( GH_TIMEOUT + 120 ))s and was killed: it hung somewhere outside the command's own timeout, so there is no receipt to show" ;;
  *) die "the runner errored (exit $RC): the gate could not be run" ;;
esac
say "gate $NAME: $VERDICT"

# ── 5. The receipt into the hosted log, and verified here against the tenant's trust ───────
PUSH="$(curl -sS --fail-with-body --max-time 30 -H 'content-type: application/json' -X POST \
  --data @"$W/receipt.json" "$CONTROL/v1/$TENANT/receipts")" || die "the log refused the receipt: $PUSH"
INDEX="$(jq -r .index <<<"$PUSH")"
jq -c .inclusion <<<"$PUSH" > "$W/proof.json"
curl -sSf --max-time 30 "$CONTROL/v1/$TENANT/trust" > "$W/trust.json"
"$GATE" expect "$W/gate.json" --repo . --tree HEAD --class optional --plan "$PLAN" --out "$W/expect.json" >/dev/null
set +e
# `2>&1`, and the reason is the one line this script exists to print. `$(...)` captures
# stdout; `gate receipt verify` writes its diagnosis to STDERR. So the `die` below -- the
# single place designed to explain why a receipt could not be checked -- interpolated an
# empty string, while the explanation went past it into the raw log as an unattributed line.
#
# Seen 2026-09-12 on PR #2865's fmt shadow: the job reported
#
#   could not look: ProofNotAtCheckpoint { proof_size: 693, trusted_size: 694 }
#   ##[error]gatehouse: could not verify the receipt against the log:
#
# -- the answer and the question, adjacent and unconnected, the error naming nothing. Inside
# a folded log group the first line is easy to miss entirely, and then a red that says
# exactly what happened reads as a red that says nothing.
VOUT="$("$GATE" receipt verify "$W/receipt.json" --trust "$W/trust.json" --expect "$W/expect.json" --inclusion "$W/proof.json" 2>&1)"; VC=$?
set -e
case "$VC" in
  0) VERIFIED=true; HELD=held ;;
  1) VERIFIED=true; HELD=not-held ;;
  *) die "could not verify the receipt against the log: $VOUT" ;;
esac
say "receipt $INDEX in $(jq -r .log.origin <<<"$EXCHANGE"): $VOUT"

# ── 6. The plain run, for the agreement line ───────────────────────────────────────────────
AGREE=skipped; GITHUB=unknown
if [ "$GH_COMPARE" = true ]; then
  set +e; bash -c "$GH_RUN" >/dev/null 2>&1; FC=$?; set -e
  if [ "$FC" -eq 0 ]; then GITHUB=pass; else GITHUB=fail; fi
  if { [ "$HELD" = held ] && [ "$GITHUB" = pass ]; } || { [ "$HELD" = not-held ] && [ "$GITHUB" = fail ]; }; then AGREE=true; else AGREE=false; fi
fi

# ── 7. The observation (informational; a failed post is a warning) ─────────────────────────
if [ "$GITHUB" != unknown ]; then
  BODY="$(jq -cn --argjson pr "$GH_PR" --arg head "$GH_HEAD_SHA" --arg gate "$NAME" --arg gh "$HELD" --arg github "$GITHUB" \
    --argjson attempt "$GH_RUN_ATTEMPT" --argjson idx "$INDEX" \
    '{pr: $pr, head_sha: $head, gate: $gate, gatehouse: $gh, github: $github, run_attempt: $attempt, receipt_index: $idx}')"
  curl -sS --fail-with-body --max-time 20 -H 'content-type: application/json' -H "Authorization: Bearer $BEARER" \
    -X POST --data "$BODY" "$CONTROL/v1/$TENANT/shadow" >/dev/null \
    || echo "::warning::gatehouse: the observation could not be reported (informational)"
fi

# ── 8. Outputs and the summary ─────────────────────────────────────────────────────────────
out verdict "$VERDICT"; out verified "$VERIFIED"; out receipt_index "$INDEX"; out agree "$AGREE"; out tenant "$TENANT"
{
  echo "### gatehouse: \`$NAME\` $VERDICT"
  echo
  echo "| | |"; echo "|---|---|"
  echo "| receipt | \`$INDEX\` in \`$(jq -r .log.origin <<<"$EXCHANGE")\`, proof verified on this runner: **$VERIFIED** |"
  echo "| signer | \`$KID\`, developer tier, this run's own key |"
  [ "$AGREE" != skipped ] && echo "| plain run | $GITHUB, agree: **$AGREE** |"
  echo "| attempt | $GH_RUN_ATTEMPT |"
  echo
  echo "Developer tier, trust on first use of the hosted log. Install the App for sandboxed runs at NodeAttested; adopt a witnessed checkpoint to hold your own trust."
} >> "$GITHUB_STEP_SUMMARY"
