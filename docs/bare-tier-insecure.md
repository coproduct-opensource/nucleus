# Bare tier is insecure

`nucleus-node --driver local --allow-local-driver` runs each pod's tool-proxy
as a plain host process. This is the **bare tier**, and it is a declared
**insecure mode**. Use it for development and for the repository's own
live-path checks, never for a workload you do not trust.

## There is no isolation between workloads and the node

On a non-root node every bare-tier child runs at the node's own uid. Such a
child can read every file the node can, including:

- the node's state directory, which is `0700` to the node and so to its
  children;
- the executor, task-issuer, approval and certificate-root signing keys;
- the identity CA key (`state/ca/ca-key.pem`);
- any federation issuer key.

A workload holding those keys can sign anything the node can. That includes an
execution claim that says `backend = firecracker, uid_isolated = true`. A root
node's bare-tier children drop to an unprivileged uid. They still run with no
VM, no namespace and no seccomp, so the mode is the same: it follows the
operator's flag, not the node's uid.

Nucleus does not repair this here. Real separation comes in **Program C, phase
C2**: bare-tier children run under subordinate host ids. Until then, the node
makes the mode honest.

## What the node does in insecure mode

**It refuses trusted authorities.** The node refuses to start if any of these
is configured, and names each one:

| Setting | What it would trust |
|---|---|
| `--federation-issuer` | assertions upstreams accept as this node |
| `--federation-listen` | the inbound federation exchange |
| `--upstreams` | credentialed upstreams whose credentials the node holds |
| `--cert-trust-anchors` | external roots for caller certificate chains |
| `--node-evidence-tpm`, `--node-evidence-software-tpm`, `--node-evidence-reference`, `--node-evidence-ak-pin` | TPM / node platform evidence |
| `--public-evidence-addr` | the anonymous listener that publishes the node's evidence key |
| `--decision-trust-roots` (with `--decision-tenant`, `--decision-bundles`) | owner-decision trust roots |
| `--audit-sinks`, `--audit-minter-socket` | audit sinks and their scoped-credential minter |
| `TRUST_API_URL`, `TRUST_RECEIPT_SECRET`, `TRUST_EXECUTOR_ID` | the external trust API and its secret |

`--root-minter-spiffe-id` is allowed. It names the caller this node treats as
its operator. Only this node trusts it.

**It signs with a separate insecure key.** The node never creates the executor
key. All its evidence (execution receipts, pod receipts, Article 12
attestations) is signed with an insecure key in
`state/insecure_shared_uid_signing_key.der`. Its kid starts with
`nucleus-insecure-shared-uid/`. That key is never sealed, never recorded in
the key custody statement, and never published in a JWKS, trust bundle,
federation document or evidence document.

**It marks its evidence.**

- Pod receipts carry `sandbox_tier = "insecure-shared-uid"`, and the mark is
  inside the signature.
- Execution claims carry `"sandbox_tier": "insecure-shared-uid"`. A claim from
  a separating driver omits the field, so it is byte-identical to before.

**Verifiers reject it by name.**

- `nucleus-ci-verdict`'s `verify_execution` refuses with
  `ExecutionError::InsecureSharedUid`. It does so when the pinned kid or the
  receipt's kid is an insecure kid, or when the claim declares the insecure
  tier. This happens before the signature or any other field is considered.
- `nucleus-audit verify-execution` and `verify-artifacts` go through
  `verify_execution`.
- `nucleus-audit verify-art12` refuses an attestation from an insecure kid.

The browser and Python receipt SDKs check only the envelope under a key the
caller supplies, and return the `issuer_kid`. Those SDKs see the insecure kid,
and no node publishes that key as an executor key.

A workload that signs with the insecure key it can read gains nothing a
verifier accepts. A workload that signs with any other key in the state
directory does not match the kid the node told the controller to pin.

**It keeps its state directory to itself.**

- In insecure mode, the node refuses a state directory that already holds an
  executor key.
- The node marks the directory it uses (`insecure-shared-uid.marker`).
- A node that separates its workloads refuses a marked directory, because its
  keys were readable by workloads.

**It seals itself.** On Linux, every node makes itself non-dumpable at startup
(`nucleus::seal_runtime`). A process at the node's uid then cannot read
`/proc/<node>/environ`, `mem` or `fd`, and cannot `ptrace` the node.

## What insecure mode still leaves open

The certificate-root, approval and task-issuer keys and the identity CA are
still readable by workloads. A workload can therefore impersonate the operator
**to this node**. None of those keys anchors anything outside the node, and
the refusals above make sure of that. Separation comes in phase C2.
