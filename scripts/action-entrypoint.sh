#!/usr/bin/env bash
# Nucleus Safe PR Fixer — GitHub Action entrypoint
#
# The agent runs under the safe_pr_fixer profile, which allows:
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
: "${NUCLEUS_TIMEOUT:=3600}"
: "${LLM_MODEL:=claude-sonnet-4-20250514}"

BRANCH="nucleus/fix-issue-${ISSUE_NUMBER}"

echo "::group::Fetch issue details"
ISSUE_TITLE=$(gh issue view "$ISSUE_NUMBER" --json title --jq '.title')
ISSUE_BODY=$(gh issue view "$ISSUE_NUMBER" --json body --jq '.body')
echo "Issue #${ISSUE_NUMBER}: ${ISSUE_TITLE}"
echo "::endgroup::"

echo "::group::Create branch"
git checkout -b "$BRANCH"
echo "::endgroup::"

echo "::group::Run Nucleus agent"
# Build the prompt from the issue
PROMPT="Fix the following GitHub issue. Read the codebase, understand the problem, implement the fix, and run tests.

Issue #${ISSUE_NUMBER}: ${ISSUE_TITLE}

${ISSUE_BODY}

After fixing, commit your changes with a clear commit message referencing issue #${ISSUE_NUMBER}."

# Run under lattice enforcement
nucleus run \
  --profile "$NUCLEUS_PROFILE" \
  --timeout "$NUCLEUS_TIMEOUT" \
  --env "LLM_API_TOKEN=${LLM_API_TOKEN}" \
  --env "LLM_MODEL=${LLM_MODEL}" \
  -- \
  echo "$PROMPT"
echo "::endgroup::"

# Check if the agent made any commits
if git diff --quiet HEAD origin/main 2>/dev/null; then
  echo "::warning::Agent made no changes. No PR created."
  exit 0
fi

echo "::group::Push and create PR"
# The TRUSTED CI script pushes — not the agent
git push origin "$BRANCH"

PR_URL=$(gh pr create \
  --title "fix: ${ISSUE_TITLE} (nucleus #${ISSUE_NUMBER})" \
  --body "$(cat <<EOF
## Summary

Automated fix for #${ISSUE_NUMBER} by Nucleus safe PR fixer.

## Security

- Profile: \`${NUCLEUS_PROFILE}\`
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

echo "pr_url=${PR_URL}" >> "$GITHUB_OUTPUT"
echo "branch=${BRANCH}" >> "$GITHUB_OUTPUT"
echo "Created PR: ${PR_URL}"
echo "::endgroup::"
