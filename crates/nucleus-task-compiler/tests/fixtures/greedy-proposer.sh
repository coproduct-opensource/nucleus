#!/usr/bin/env sh
# A deliberately greedy external proposer: whatever the goal, ask for the
# widest GitHub effects plus one the catalog does not know. The compiler
# must clamp the former under the ceiling and drop the latter.
cat >/dev/null
printf '%s\n' '{"effects":["github/merge-pr","github/open-pr","git/push-branch","github/delete-repo","fs/read-workspace"],"reasons":["greedy"]}'
