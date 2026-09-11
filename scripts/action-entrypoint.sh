#!/usr/bin/env bash
# Nucleus Safe PR Fixer — GitHub Action entrypoint
#
# Two ways in, and the difference is the whole point of the delegation
# compiler.
#
#   NUCLEUS_GOAL set  — state the outcome. Nucleus compiles it into the
#     minimum authority that outcome needs, met with NUCLEUS_CEILING, seals
#     the result, and runs under it enforced per effect. The grant is
#     compiled from *this* issue, so a smaller issue is granted less.
#
#   NUCLEUS_GOAL empty — the profile path below, unchanged. A profile is a
#     fixed authority chosen before anyone knew what the task was.
#
# The shipped CI surface used to offer only the second. "One delegation
# model, many execution surfaces" failed at the first surface it shipped on.
#
# Under a profile, the agent runs under safe_pr_fixer, which allows:
#   - Read all files, write/edit/test with LowRisk
#   - Commit locally (git_write=LowRisk)
#   - Web fetch for docs lookup (web_fetch=LowRisk)
#
# The agent CANNOT:
#   - Push (git_push=Never)
#   - Create PRs (create_pr=Never)
#   - Web search (web_search=Never)
#
# This script handles the push and PR creation after the agent finishes.

set -euo pipefail

: "${ISSUE_NUMBER:?ISSUE_NUMBER is required}"
: "${LLM_API_TOKEN:?LLM_API_TOKEN is required}"
: "${NUCLEUS_PROFILE:=safe_pr_fixer}"
: "${NUCLEUS_GOAL:=}"
: "${NUCLEUS_CEILING:=codegen}"
: "${NUCLEUS_EXPLAIN:=plain}"
: "${NUCLEUS_TIMEOUT:=3600}"
: "${LLM_MODEL:=claude-sonnet-4-20250514}"

# Export ANTHROPIC_API_KEY so Claude CLI can authenticate.
# The action input is vendor-agnostic (api-key → LLM_API_TOKEN),
# but the Claude CLI looks for ANTHROPIC_API_KEY in the environment.
export ANTHROPIC_API_KEY="${LLM_API_TOKEN}"

BRANCH="nucleus/fix-issue-${ISSUE_NUMBER}"

echo "::group::Fetch issue details"
ISSUE_TITLE=$(gh issue view "$ISSUE_NUMBER" --json title --jq '.title')
ISSUE_BODY=$(gh issue view "$ISSUE_NUMBER" --json body --jq '.body')
echo "Issue #${ISSUE_NUMBER}: ${ISSUE_TITLE}"
echo "::endgroup::"

echo "::group::Create branch"
# Delete remote branch if it exists from a previous run (stale plan-only attempt)
if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
  echo "Branch $BRANCH exists on remote — deleting stale branch"
  git push origin --delete "$BRANCH" || true
fi
git checkout -b "$BRANCH"
echo "::endgroup::"

# The task, as the person would state it.
TASK="Fix the following GitHub issue. Read the codebase, understand the problem, implement the fix, and run tests.

Issue #${ISSUE_NUMBER}: ${ISSUE_TITLE}

${ISSUE_BODY}

After fixing, commit your changes with a clear commit message referencing issue #${ISSUE_NUMBER}."

# What the PR's Security section says about how this run was authorised.
AUTHORITY="Profile: \`${NUCLEUS_PROFILE}\`"

if [ -n "${NUCLEUS_GOAL}" ]; then
  # ── Goal path ────────────────────────────────────────────────────────────
  #
  # Sealing is the confirmation. `grant seal` compiles the goal exactly as
  # `run --goal` does, renders the five lines, and signs the result; `run
  # --grant` then executes it with no second decision. That is C(T) = 1 for
  # a new task and 0 for a repeat, on the CI surface: the sealed grant is a
  # file, and a workflow that caches it never compiles again.
  #
  # Sealed BEFORE the run, and shown from the sealed file rather than
  # scraped out of the run's output, so the summary says what the run is
  # authorised to do even when the run fails.
  GOAL="${NUCLEUS_GOAL}

${TASK}"
  GRANT_FILE="${RUNNER_TEMP:-/tmp}/nucleus-grant-${ISSUE_NUMBER}.json"

  echo "::group::Compile the goal into a grant"
  nucleus grant seal \
    --goal "$GOAL" \
    --ceiling "$NUCLEUS_CEILING" \
    --explain "$NUCLEUS_EXPLAIN" \
    --yes \
    --approver "github-actions[${GITHUB_WORKFLOW:-workflow}]" \
    -o "$GRANT_FILE"
  echo "::endgroup::"

  # The grant, in the job summary, where a reviewer reads it without
  # unfolding a log group.
  GRANT_RENDER=$(nucleus grant show "$GRANT_FILE" --explain "$NUCLEUS_EXPLAIN")
  {
    echo "### Delegated authority for issue #${ISSUE_NUMBER}"
    echo
    echo "Compiled from the goal, met with the \`${NUCLEUS_CEILING}\` ceiling."
    echo
    echo '```'
    echo "$GRANT_RENDER"
    echo '```'
  } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

  echo "grant=${GRANT_FILE}" >> "${GITHUB_OUTPUT:-/dev/null}"

  # A grant's lifetime is set by the ceiling, not by this Action, and the
  # default here (3600s) is exactly the codegen ceiling's hour. So the default
  # configuration runs the agent until the moment its authority expires, and
  # any delay between sealing and starting makes the last stretch of the run
  # certain to be denied — every tool call refused, no output, and a log that
  # blames the tool rather than the clock.
  #
  # Clamp the timeout to what the grant actually has left. Losing the tail of a
  # run is better than spending it being refused, and the warning names the
  # real constraint so the operator raises the ceiling rather than the timeout.
  NOT_AFTER=$(jq -r '.grant.not_after' "$GRANT_FILE")
  GRANT_LEFT=$(( $(date -u -d "$NOT_AFTER" +%s) - $(date -u +%s) - 30 ))
  if [ "$GRANT_LEFT" -lt 1 ]; then
    echo "::error::The sealed grant has already expired (not_after ${NOT_AFTER})."
    exit 1
  fi
  if [ "$NUCLEUS_TIMEOUT" -gt "$GRANT_LEFT" ]; then
    echo "::warning::timeout ${NUCLEUS_TIMEOUT}s exceeds the grant's remaining ${GRANT_LEFT}s (ceiling '${NUCLEUS_CEILING}' sets the lifetime); running for ${GRANT_LEFT}s."
    NUCLEUS_TIMEOUT="$GRANT_LEFT"
  fi
  AUTHORITY="Compiled grant, ceiling \`${NUCLEUS_CEILING}\`:

\`\`\`
${GRANT_RENDER}
\`\`\`"

  echo "::group::Run Nucleus agent"
  # No prompt: a sealed grant carries its own goal, and the digest binds the
  # two together so the run cannot execute a task the grant was not shown for.
  nucleus run \
    --local \
    --grant "$GRANT_FILE" \
    --timeout "$NUCLEUS_TIMEOUT" \
    --model "$LLM_MODEL" \
    --env "LLM_API_TOKEN=${LLM_API_TOKEN}"
  echo "::endgroup::"
else
  # ── Profile path ─────────────────────────────────────────────────────────
  echo "::group::Run Nucleus agent"
  nucleus run \
    --local \
    --profile "$NUCLEUS_PROFILE" \
    --timeout "$NUCLEUS_TIMEOUT" \
    --model "$LLM_MODEL" \
    --env "LLM_API_TOKEN=${LLM_API_TOKEN}" \
    "$TASK"
  echo "::endgroup::"
fi

# Check if the agent made any commits
DEFAULT_BRANCH=$(git remote show origin 2>/dev/null | grep 'HEAD branch' | awk '{print $NF}')
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
if git diff --quiet "HEAD" "origin/${DEFAULT_BRANCH}" 2>/dev/null; then
  echo "::warning::Agent made no changes. No PR created."
  exit 0
fi

echo "::group::Push and create PR"
# The TRUSTED CI script pushes — not the agent
git push origin --delete "nucleus/fix-issue-${ISSUE_NUMBER}" 2>/dev/null || true
git push origin "$BRANCH"

# Always output branch — even if PR creation fails
echo "branch=${BRANCH}" >> "$GITHUB_OUTPUT"

# PR creation is non-fatal: some orgs block Actions from creating PRs
set +e
PR_URL=$(gh pr create \
  --title "fix: ${ISSUE_TITLE} (nucleus #${ISSUE_NUMBER})" \
  --body "$(cat <<EOF
## Summary

Automated fix for #${ISSUE_NUMBER} by Nucleus safe PR fixer.

## Security

${AUTHORITY}

- The agent could read, write, edit, and commit — but could NOT push or create this PR.
- This PR was created by the trusted CI script, not the agent.
- All agent actions were audit-logged with HMAC signatures.

## Review Checklist

- [ ] Changes are scoped to the reported issue
- [ ] Tests pass
- [ ] No unexpected file modifications
EOF
)" \
  --head "$BRANCH")
PR_EXIT=$?
set -e

if [ $PR_EXIT -eq 0 ]; then
  echo "pr_url=${PR_URL}" >> "$GITHUB_OUTPUT"
  echo "Created PR: ${PR_URL}"
else
  echo "::warning::gh pr create failed (exit $PR_EXIT). Branch '${BRANCH}' was pushed — create the PR manually."
fi
echo "::endgroup::"
