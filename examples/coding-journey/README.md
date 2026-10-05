# Coding journey task

This small repository is an intentionally incomplete usage-record summarizer.
It gives two independent coding harness runs the same ordinary repair task.
The initial test suite must fail; passing it is the model's work, not a setup
step. The task uses Python's standard library so a pod can run it offline.

For each run, copy `repository/` into a fresh Git repository and record its
initial commit and file hashes. Keep a separate copy of `test_summary.py` for
verification. Give the harness `TASK.md`, let it edit `summary.py`, and run
`python3 -m unittest -v` from that repository. Record the actual command, exit
status, stdout/stderr, and resulting diff. The tests and task must be unchanged.

For offline guest transfer, create a Git bundle of the baseline branch and clone
with that branch explicitly selected, for example `git clone --branch main
input.bundle work`. A branch-only bundle need not advertise a default `HEAD`.
Check `git rev-parse HEAD` and the input file hashes before starting the harness.

Model endpoint and credential references belong in the operator's host broker
configuration. The workload uses the managed HTTP adapter; this fixture carries
no model configuration or credentials. Do not count a scripted repair, model
stub, version command, or baseline preflight as a completed coding run.

Successful tests are one part of the release journey. Each run also needs the
scoped approval flow and independently verified execution and artifact evidence.
Publication timing and the remaining release requirements are recorded in
[the release plan](../../docs/design/secure-coding-release-plan.md).
