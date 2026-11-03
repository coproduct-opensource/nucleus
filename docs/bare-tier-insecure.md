# Bare tier: separated or insecure

`nucleus-node --driver local --allow-local-driver` runs each pod's tool-proxy
as a plain host process. This is the **bare tier**. What its children (every
`/v1/run` command and the pod's workload) run as is decided once, at node
start-up, by the local driver's **realization contract**:

- **Separated** (Program C, C2): the host delegates subordinate ids to the
  node's user, and every clause of the contract holds. Each pod's children run
  at their own subordinate host uid and gid, and cannot read the node's keys.
  The node's evidence states `separated-local`. See
  [Separated: subordinate host ids](#separated-subordinate-host-ids).
- **Insecure** (Program C, C0): any clause fails. The children share the
  node's uid, and the rest of this page applies. The node logs which clause
  failed.

Neither is a microVM. Use the bare tier for development and for the
repository's own live-path checks, never for a workload you do not trust.

## Separated: subordinate host ids

### Why a user namespace alone is not enough

An unprivileged process can create a user namespace in which it is "uid 0".
The kernel still checks file access against the **host** credentials, and that
namespace's only mapping sends its uid 0 back to the caller's own host uid. A
child in such a namespace opens every file the node can. Separation needs a
**different host uid and gid** for the child, and only the setuid helpers
`newuidmap` / `newgidmap` may map one, after checking `/etc/subuid` and
`/etc/subgid`.

### What a separated child is

Each pod gets the next offset of the node user's delegated range: host uid
`start + k` and gid `start + k` (offset 0 is the start-up probe's). An offset
is never given twice: the next one is kept in `state/subordinate-ids.next`, so
a later pod never owns files an earlier pod's children left behind.

The pod's tool-proxy is started with `--unsandboxed --subordinate-ids UID:GID`.
It checks the ids against the delegation itself, and refuses to start rather
than run its children at its own uid. Every child then, between fork and exec:

1. marks every inherited descriptor above stdio close-on-exec;
2. enters a fresh user namespace, while two forked helpers run `newuidmap` and
   `newgidmap` on it with exactly one mapping each, `id id 1`;
3. drops every supplementary group, then becomes that gid and uid;
4. reads `/proc/self/uid_map` and `gid_map` back and refuses to exec unless
   each is exactly `id id 1`. The shape `unshare -r` writes
   (`0 <node uid> 1`) is refused;
5. sets `no_new_privs` and the pod's resource limits;
6. installs the workload syscall denylist and the pod's derived classes, the
   same filter a microVM child gets. It refuses every new namespace, so no
   descendant can remap itself, and `no_new_privs` keeps every descendant
   from running a setuid helper.

### The realization contract

`nucleus::LocalRealization::check` is the one decider. Its clauses:

| Clause | How it is checked |
|---|---|
| The node's signing material is unreachable | The child's host uid is neither the node's nor 0, and the state directory is the node's, mode `0700` with no access ACL. A probe child, spawned through the real hook at offset 0, must fail to `cd` into it. |
| The child cannot impersonate, signal or ptrace the node | A distinct host uid: `SO_PEERCRED` names the subordinate uid, and `kill(2)` / `ptrace(2)` need the node's uid. The probe must fail to `kill -0` the node. |
| Protected effects stay mediated | The child installs the workload denylist and the pod's derived syscall classes. |
| It holds across child creation | The denylist refuses new namespaces, and `no_new_privs` refuses setuid helpers. |

The probe also checks the child really runs at its subordinate uid. A clause
that fails leaves the node in the insecure mode below, with the reason in its
log.

### Evidence

- Execution claims carry `"sandbox_tier": "separated-local"` and are signed by
  the node's ordinary executor key, which separated children cannot read.
  `verify_execution` refuses them as `NotProtectedMicroVm`: a separated host
  process is not a microVM, even if a claim paired it with
  `backend = firecracker`.
- Pod receipts carry `sandbox_tier = "separated-local"` inside the signature,
  under the node's certificate root.
- The node still refuses every trusted authority in the table below. Lifting
  that for the separated tier is a separate decision.
- A separated node refuses a state directory marked by an insecure one, and an
  insecure node refuses one that holds an executor key.

### The pod's proxy socket

The local driver's `proxy.sock` used to admit any process at the node's uid as
a pod peer, so another pod's proxy, or any bare-tier child at the node's uid,
could drive this pod's control plane. The node now starts each proxy with
`--node-peer-pid <its pid>`. The socket admits that process alone, and only
while it is still the proxy's parent, so a recycled pid admits nobody.

### The workspace

A separated child reaches the pod's workspace only if it is granted. The node
grants it, by POSIX ACL (access and default entries for the pod's ids, with
the owner's bits), only when all of these hold:

- the pod's `work_dir` resolves strictly inside `--workspace-root`;
- that root lies outside `--state-dir`. The default root,
  `<state-dir>/workspaces`, does not qualify, because a separated child cannot
  traverse the state directory;
- no other local pod of this node was granted an overlapping directory.

Then the pod's workload door is bound at `<work_dir>/.nucleus-door/`, where the
workload can reach it. Any other `work_dir`, including `.`, is not widened. The
child gets only what the directory's own bits give any user, and the door
stays in the pod directory, where a separated workload cannot reach it.

### Operator setup

On the host that runs the node, as root:

```sh
apt-get install uidmap          # newuidmap / newgidmap
usermod --add-subuids 200000-265535 --add-subgids 200000-265535 <node-user>
```

The kernel must let an unprivileged process create a user namespace and keep
its capabilities in it. Ubuntu 24.04 restricts this by default
(`kernel.apparmor_restrict_unprivileged_userns = 1`); then the probe fails and
the node stays insecure, by name. Either set that sysctl to 0, or give the
node binary an AppArmor profile that allows `userns`.

For a usable workspace, give the node a `--workspace-root` outside its state
directory, traversable by other users, and create pods with a `work_dir`
inside it.

For an operator client certificate, start the node with
`--operator-identity-dir <dir>` (and `--root-minter-spiffe-id`). The node
mints a certificate for that identity into the directory at start-up, mode
`0700`, as `cert.pem`, `key.pem` and `trust-bundle.pem`. Nothing outside the
node needs to read `state/ca/ca-key.pem`.

### What separation does not cover

- The tool-proxy itself still runs at the node's uid. It is the mediating
  runtime, not a workload.
- There is no network namespace. A pod's children reach the network as the
  pod's lattice and derived syscall classes allow, not through a proxy.
- A companion with its own explicit `uid` is refused: a pod has one
  subordinate uid.
- A pod's ids reveal how many local pods this state directory has started.

## Insecure: shared uid

### There is no isolation between workloads and the node

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

Where the realization contract above is unmet, nothing repairs this, and the
node makes the mode honest instead.

### What the node does in insecure mode

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

### What insecure mode still leaves open

The certificate-root, approval and task-issuer keys and the identity CA are
still readable by workloads. A workload can therefore impersonate the operator
**to this node**. None of those keys anchors anything outside the node, and
the refusals above make sure of that. On a host that can, the separated tier
above removes this exposure.
