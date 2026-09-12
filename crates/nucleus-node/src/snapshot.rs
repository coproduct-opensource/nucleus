//! Which microVMs may become a snapshot base, and why most may not.
//!
//! # The measurement that motivates this
//!
//! On an Apple M5 Pro via Lima `vz` → KVM → Firecracker 1.16.1, measured with
//! the real API:
//!
//! ```text
//! cold boot to userspace  :  79 ms
//! snapshot create         : 151 ms  (256 MiB memory file)
//! snapshot restore+resume :   7 ms   <- with the plain File backend, not UFFD
//! ```
//!
//! An 11x improvement, in the same class as the fastest agent-sandbox platforms.
//! That is worth having, and it is why the guard below exists rather than a
//! note in a design doc: the fast path is attractive enough that someone will
//! build it, and the unsafe version of it looks identical from the outside.
//!
//! # What restoring a clone actually duplicates
//!
//! Firecracker always enables **VMGenID**: on resume it changes a 16-byte
//! generation ID and notifies the guest, so a Linux ≥ 5.18 guest re-seeds its
//! in-kernel PRNG. That fixes kernel randomness and nothing else. The docs are
//! explicit that *"unique identifiers, cached random numbers, cryptographic
//! tokens, etc will still be replicated across multiple microVMs resumed from
//! the same snapshot"*, and that users must de-duplicate such state themselves.
//!
//! Nucleus USED to inject exactly that kind of state — `sandbox_token`, the
//! task token, the approval secret, the AWS audit credentials — **on the kernel
//! command line**, where it is baked into `/proc/cmdline` and into the
//! snapshot's memory image. Restoring N pods from such a base would give all N
//! the same per-pod values.
//!
//! **As of 2026-08-08 an identity-bearing pod's command line carries no per-pod
//! material at all.** Every such value now arrives after boot over the workload
//! API (task token, DLC admission, broker/audit credentials) or was replaced by
//! public config (`approval_pubkeys`) or retired (the dead Tier-3
//! `sandbox_token`). So the snapshot base built for an identity-bearing pod is
//! satisfiable by construction — see
//! `a_realistic_identity_bearing_cmdline_is_now_snapshottable`. [`SnapshotSafety`]
//! remains as a categorical GUARD: it refuses any command line that carries a
//! [`PER_POD_SECRET_KEYS`] member, so a regression that re-introduces one is
//! caught rather than silently cloned. See that list for what is genuinely
//! per-pod versus merely per-node.

// Not yet called from anywhere: the guard deliberately precedes the
// snapshot/restore path it guards, so that the fast path cannot land without
// tripping over it. The tests exercise every item below.
#![cfg_attr(not(test), allow(dead_code))]

/// Command-line keys that must never be baked into a snapshot base.
///
/// Two distinct reasons, and the distinction was got wrong in the first version
/// of this file, so it is spelled out:
///
/// * **Per-pod** — derived from the pod id or its spec, so cloning genuinely
///   duplicates something that was meant to be unique:
///   `task_token_hex` / `task_token_issuer` / `task_token_nonce` (minted by
///   `mint_task_token_for_spec(state, spec, id)`), `sandbox_token` (freshly
///   generated per VM), and the AWS credentials, which come from the spec.
/// * **Per-node** — `auth_secret` and `approval_secret` are node-level config
///   (`NUCLEUS_NODE_PROXY_AUTH_SECRET` and friends), so every pod on a node
///   already shares them and cloning *within* a node changes nothing. They are
///   still refused, because a snapshot base is a **portable artifact**: build it
///   on node A, restore it on node B, and node A's proxy secrets have travelled.
///
/// A correction to the first version's claim: sharing the task-token nonce is
/// NOT straightforwardly an authority leak, because `session_mint` documents
/// that the token is "a scoped capability plus a public issuer key — not a
/// secret", with anti-replay resting on a **host-pinned** effective nonce rather
/// than on secrecy. A host that sees two sessions claiming one nonce can reject
/// them. The duplication is still wrong — a value minted per pod should not be
/// shared — but the failure is "the host must now arbitrate", not "the guest
/// gets free authority".
///
/// `nucleus.workload_api_port` is NOT here: it is a port number, identical for
/// every pod on a node, and carries no authority by itself — the identity it
/// leads to is gated separately by `net::decide_identity_grant`.
/// # All of them are now delivered off the command line, or retired
///
/// Every per-pod value nucleus once wrote here is gone from an identity-bearing
/// pod's command line as of 2026-08-08:
///
/// * **`nucleus.auth_secret`** — deleted in Phase 1: the vsock peer check
///   (`VMADDR_CID_HOST`, set by the guest kernel) establishes origin, so the
///   HMAC tier it keyed is unreachable on the Firecracker path.
/// * **`nucleus.approval_secret`** — replaced by `nucleus.approval_pubkeys`,
///   the Ed25519 PUBLIC half of the node's approval key (classified in
///   [`SHARED_CONFIG_KEYS`]). Reading a verification key grants no forging
///   power — unlike the symmetric HMAC key it replaced, which let any
///   `/proc/cmdline` reader sign approvals.
/// * **`nucleus.task_token_hex` / `_issuer` / `_nonce`** — the token is served
///   after boot over the workload API (`FETCH_TASK_TOKEN`, per-pod socket),
///   `guest-init` fetching it before `exec_proxy`. A per-pod value fetched
///   after boot is not baked into a snapshot base.
/// * **the AWS audit credentials** — served over the workload API
///   (`FETCH_AUDIT_CREDENTIALS`, once, before any workload exists).
/// * **`nucleus.sandbox_token`** — RETIRED, not relocated. It was Tier 3 of the
///   sandbox proof, verified with an `auth_secret` the guest no longer has on
///   any shipped rootfs (`/etc/nucleus/auth.secret` is written only under
///   `build-rootfs.sh --legacy-secrets`, and the cmdline copy is gone), so on a
///   real build the HMAC could never match and the token proved nothing while
///   sitting on `/proc/cmdline` as a Secret. Identity-bearing pods prove
///   themselves from their SVID; an identity-less Firecracker pod now fails
///   closed (`NakedProcess`), which on a shipped rootfs is the outcome it
///   already had.
///
/// So an identity-bearing pod's command line carries no per-pod material at
/// all. [`PER_POD_SECRET_KEYS`] is retained as a CATEGORICAL denylist: these
/// keys are refused on any command line even though nothing emits them, so
/// re-introducing one is a caught regression.
pub const PER_POD_SECRET_KEYS: &[&str] = &[
    // No longer emitted (approvals are Ed25519-verified against
    // `nucleus.approval_pubkeys` now) but categorically refused: a shared
    // symmetric approval key on a cloned base is the forgery-enabling case.
    "nucleus.approval_secret",
    "nucleus.auth_secret",
    "nucleus.sandbox_token",
    "nucleus.task_token_hex",
    "nucleus.task_token_issuer",
    "nucleus.task_token_nonce",
    // The three audit-sink credentials are NO LONGER EMITTED (they ride
    // `FETCH_AUDIT_CREDENTIALS` over the workload API now) but stay listed:
    // the denylist is categorical, so a regression that puts them back on the
    // command line is refused here rather than silently clonable.
    "nucleus.aws_access_key_id",
    "nucleus.aws_secret_access_key",
    "nucleus.aws_session_token",
];

/// Command-line keys that are per-*node* or per-*fleet* configuration, safe to
/// bake into a shared base because every clone should have the same value.
///
/// Listed explicitly rather than implied by absence, so that a NEW key is
/// unclassified rather than silently assumed safe — see
/// `every_cmdline_key_is_classified`.
pub const SHARED_CONFIG_KEYS: &[&str] = &[
    // The Ed25519 PUBLIC half of the node's approval signing key: identical
    // for every pod on the node, and useless for forging — the guest verifies
    // with it and can do nothing else.
    "nucleus.approval_pubkeys",
    "nucleus.audit_s3_bucket",
    "nucleus.audit_s3_endpoint",
    "nucleus.audit_s3_prefix",
    "nucleus.audit_s3_region",
    "nucleus.aws_default_region",
    "nucleus.workload_api_port",
    // Networking is re-established after restore, not inherited: Firecracker
    // documents that "guest network connectivity is not guaranteed to be
    // preserved after resume".
    "nucleus.net",
];

/// Whether a booted microVM may be snapshotted as a reusable base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSafety {
    /// No per-pod material on the command line; safe to clone from.
    SafeToClone,
    /// Carries per-pod material that every clone would inherit.
    WouldDuplicateSecret {
        /// The offending key, so the refusal is actionable.
        key: String,
    },
    /// The VM has already been made one particular pod, over vsock.
    ///
    /// The failure this exists to stop is silent and total: `guest-init` fetches an SVID, a task
    /// token, a caller token, a pod certificate, a broker capability served EXACTLY ONCE, and a
    /// mediation signing key — all after boot, none of it on the kernel command line. Snapshot
    /// after that and every clone restores holding one pod's credentials, while a boot-args scan
    /// returns `SafeToClone` and is not wrong about what it looked at.
    ///
    /// Decided from the HOST's own record of what it served, never from a declaration by the
    /// guest: the guest is the thing being contained.
    PersonalizedSince,
    /// The guest never said it had reached a point worth snapshotting.
    ///
    /// Refused rather than guessed. The host can see that nothing has been served yet, but not
    /// whether the guest has finished booting — and a base taken too early is a VM that has not
    /// set itself up, restored forever after. An image that predates `SNAPSHOT_READY` lands here
    /// and stays unusable as a base, which is the honest answer for one that cannot say where
    /// its barrier is.
    NotAtBarrier,
    /// A writable scratch disk is attached, so clones would share or diverge on it.
    ///
    /// Scratch is per-pod and writable. A restored clone inherits the base's in-memory ext4
    /// state for it, so two clones pointed at one file corrupt each other, and giving each a
    /// fresh file at the same in-jail name leaves the guest's cached metadata describing a
    /// filesystem that is no longer there. Both are filesystem corruption arriving later and
    /// elsewhere, so this is refused outright rather than made an option.
    WritableScratchAttached,
}

impl SnapshotSafety {
    /// Whether a snapshot of this microVM may be restored more than once.
    pub fn is_safe_to_clone(&self) -> bool {
        matches!(self, SnapshotSafety::SafeToClone)
    }
}

impl std::fmt::Display for SnapshotSafety {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotSafety::SafeToClone => write!(f, "safe to clone"),
            SnapshotSafety::WritableScratchAttached => write!(
                f,
                "this microVM has a writable scratch disk, which clones cannot share and cannot \
                 be given fresh without stranding the guest's cached filesystem state"
            ),
            SnapshotSafety::NotAtBarrier => write!(
                f,
                "this microVM has not announced SNAPSHOT_READY, so there is no declared point at \
                 which it is booted but not yet anybody"
            ),
            SnapshotSafety::PersonalizedSince => write!(
                f,
                "this microVM has already been served per-pod material over vsock, so a snapshot \
                 of it would give every clone one pod's identity"
            ),
            SnapshotSafety::WouldDuplicateSecret { key } => write!(
                f,
                "refusing to snapshot: the kernel command line carries {key}, which every clone \
                 restored from this snapshot would inherit. VMGenID re-seeds the guest kernel \
                 PRNG on resume but does NOT de-duplicate identifiers, tokens or nonces. Build \
                 the base from a spec with no per-pod material and deliver it after restore."
            ),
        }
    }
}

/// Judge a guest kernel command line as a snapshot base.
///
/// Fails closed on the *presence* of a key, not on its value: an empty or
/// placeholder secret is still a key that will be populated later, and a base
/// built around one invites the caller to fill it in afterwards.
pub fn snapshot_safety(boot_args: &str) -> SnapshotSafety {
    for token in boot_args.split_whitespace() {
        let key = token.split('=').next().unwrap_or(token);
        if PER_POD_SECRET_KEYS.contains(&key) {
            return SnapshotSafety::WouldDuplicateSecret {
                key: key.to_string(),
            };
        }
    }
    SnapshotSafety::SafeToClone
}

/// Whether this microVM may be snapshotted for cloning, considering everything the host knows.
///
/// Two questions, and they fail in different ways, so both are asked:
///
/// 1. Does the kernel command line carry per-pod material? ([`snapshot_safety`])
/// 2. Has the host already SERVED per-pod material to this VM over vsock?
/// 3. Has the guest announced it is booted and has asked for nothing (`SNAPSHOT_READY`)?
///
/// The third is the guest's to answer and only the guest's; the second is the host's and only
/// the host's. Neither is trusted for the other's question, which is why both are asked.
///
/// The second is the one a boot-args scan cannot see, and it is the one that actually bites: the
/// per-pod secrets were deliberately moved OFF the command line and onto the post-boot workload
/// API, which is what made a shareable boot line possible — and, in the same move, made the
/// command line stop being where the answer lives.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn clone_safety(
    boot_args: &str,
    at_barrier: bool,
    personalized: bool,
    scratch: &MountState,
) -> SnapshotSafety {
    // ATTACHED is fine; MOUNTED is not, and anything unreadable is refused.
    //
    // This was "is a writable non-root drive attached", which refused every
    // jailed pod — `scratch_for_pod` auto-provisions one. Measured 2026-09-12
    // (`scripts/experiments/snapshot-deferred-mount.sh`): a scratch that is
    // attached and never mounted leaves no ext4 metadata in the snapshot, and
    // two clones restored against fresh images of identical geometry both fsck
    // clean with no cross-contamination.
    //
    // `Unknown` lands with `Mounted` deliberately. The costs are not symmetric:
    // a wrong refusal is a cold boot, and a wrong certification is a base that
    // corrupts every clone restored from it.
    match scratch {
        MountState::NeverMounted => {}
        MountState::Mounted { .. } | MountState::Unknown(_) => {
            return SnapshotSafety::WritableScratchAttached;
        }
    }
    // Order matters for the message, not the verdict: a VM that is both personalised and past
    // its barrier should say the dangerous thing, because that is the one worth reading.
    if personalized {
        return SnapshotSafety::PersonalizedSince;
    }
    if !at_barrier {
        return SnapshotSafety::NotAtBarrier;
    }
    snapshot_safety(boot_args)
}

/// Whether the guest has ever mounted the filesystem in `image`.
///
/// # Why this is a MEASUREMENT and not a guest's word
///
/// `clone_safety` refuses a writable scratch because a restored clone inherits
/// the base's in-memory ext4 state for it. Measured 2026-09-12
/// (`scripts/experiments/snapshot-deferred-mount.sh`), that refusal is about a
/// **mounted** scratch: an attached-but-never-mounted one leaves virtio-blk
/// queue state in the snapshot and no ext4 metadata, two clones restored
/// against fresh images of identical geometry both fsck clean, and neither sees
/// the other's writes.
///
/// So the predicate wants to be "mounted", not "attached". The obvious way to
/// get that is to ask the guest — it is the one that mounts things, and
/// `SNAPSHOT_READY` is already a guest report. **That would be the wrong
/// choice.** A base is restored by OTHER pods, so a guest that lies about its
/// mount state does not corrupt itself; it publishes a base that corrupts
/// everyone who restores it. A claim with that blast radius should not rest on
/// the claimant.
///
/// ext4 records it in the superblock, so the host can simply look:
///
/// ```text
/// fresh, never mounted      Mount count: 0    Last mounted on: <not available>
/// mounted and unmounted     Mount count: 1    Last mounted on: /mnt
/// ```
///
/// # What it does not establish
///
/// That the image is safe to snapshot for any other reason, and that a
/// non-ext4 filesystem is unmounted — `dumpe2fs` will simply fail on one, which
/// is [`MountState::Unknown`] and refused. A scratch this code cannot read is
/// not a scratch it may certify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountState {
    /// The superblock says mount count 0: no guest has ever mounted it.
    NeverMounted,
    /// It has been mounted at least once, so its metadata may be in a snapshot.
    Mounted { count: u64 },
    /// Could not be read. NOT folded into either: "I could not look" is never
    /// "I looked and it was fine" (ADR 0007 A-2), and here it is also never
    /// "I looked and it was dirty" — a wrong refusal costs a cold boot, while a
    /// wrong certification corrupts every clone of the base.
    Unknown(String),
}

/// Read the mount count out of an ext4 superblock with `dumpe2fs -h`.
///
/// e2fsprogs is already required to CREATE a scratch image
/// (`provision_pod_scratch` shells to `mkfs.ext4`), so this costs no new
/// dependency on any host that can make one.
// The only caller is `pod_api::snapshot_pod`, which is `#[cfg(target_os =
// "linux")]` — so on macOS there genuinely is no caller and clippy is right to
// say so. Marked rather than blanket-allowed, because "dead everywhere" and
// "dead on the host I happen to be on" are different facts.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn mount_state(image: &std::path::Path) -> MountState {
    let out = match std::process::Command::new("dumpe2fs")
        .args(["-h", &image.display().to_string()])
        .output()
    {
        Ok(out) => out,
        Err(e) => return MountState::Unknown(format!("running dumpe2fs: {e}")),
    };
    // `dumpe2fs -h` writes the header to stdout and its banner to stderr, and
    // exits non-zero on a filesystem it cannot parse. Both are checked: a
    // non-zero exit with parseable stdout is still a filesystem this code does
    // not understand well enough to certify.
    if !out.status.success() {
        return MountState::Unknown(format!(
            "dumpe2fs failed on {}: {}",
            image.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_mount_count(&String::from_utf8_lossy(&out.stdout))
}

/// The parsing half, separated so it is testable without e2fsprogs — which
/// macOS does not have, and which would otherwise make this untested on the
/// machine it is written on.
pub(crate) fn parse_mount_count(header: &str) -> MountState {
    for line in header.lines() {
        let Some(rest) = line.strip_prefix("Mount count:") else {
            continue;
        };
        return match rest.trim().parse::<u64>() {
            Ok(0) => MountState::NeverMounted,
            Ok(count) => MountState::Mounted { count },
            Err(e) => MountState::Unknown(format!("unparseable mount count {rest:?}: {e}")),
        };
    }
    MountState::Unknown("no `Mount count:` line in the superblock header".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "console=ttyS0 reboot=k panic=1 pci=off init=/init ipv6.disable=1";

    #[test]
    fn a_plain_base_cmdline_is_safe_to_clone() {
        assert!(snapshot_safety(BASE).is_safe_to_clone());
    }

    /// Every per-pod secret must be refused individually — a guard that only
    /// caught one of them would pass this suite while leaking the rest.
    #[test]
    fn every_per_pod_secret_is_refused() {
        for key in PER_POD_SECRET_KEYS {
            let args = format!("{BASE} {key}=deadbeef");
            let verdict = snapshot_safety(&args);
            assert!(
                !verdict.is_safe_to_clone(),
                "{key} must make a microVM unfit as a snapshot base"
            );
            match verdict {
                SnapshotSafety::WouldDuplicateSecret { key: found } => assert_eq!(&found, key),
                other => unreachable!("a cmdline secret must be reported as one, got {other:?}"),
            }
        }
    }

    /// The nonce is the sharpest case: reusing one across clones is the
    /// "meant to be used once, used twice" failure by definition.
    #[test]
    fn a_shared_nonce_is_refused_and_the_message_says_why() {
        let msg = snapshot_safety(&format!("{BASE} nucleus.task_token_nonce=abc")).to_string();
        assert!(msg.contains("nucleus.task_token_nonce"), "names it: {msg}");
        assert!(
            msg.contains("VMGenID"),
            "explains what is NOT covered: {msg}"
        );
    }

    /// **The two classifications PARTITION — they are disjoint.** No key is both
    /// per-pod-secret and shared-config. This is the soundness heart of
    /// `SafeToClone`: a key in BOTH lists would be refused by `snapshot_safety`
    /// (per-pod is checked first) yet read as clonable by a reviewer who added it
    /// to the shared list — an ambiguous classification is the exact seam a
    /// per-pod secret slips through onto a cloned base. It was caught only
    /// INDIRECTLY (a both-listed key would fail `shared_configuration_does_not_block_a_base`);
    /// this makes the partition a DIRECT, exhaustive property, so the two lists
    /// can never disagree about a key even as they grow. Finite domain, so the
    /// check is a complete proof of disjointness, not a sample.
    #[test]
    fn the_two_key_classifications_are_disjoint() {
        for k in PER_POD_SECRET_KEYS {
            assert!(
                !SHARED_CONFIG_KEYS.contains(k),
                "{k} is classified BOTH per-pod-secret and shared-config — a key must be \
                 exactly one, and the 'shared' reading leaks it to every clone restored \
                 from a snapshot base"
            );
        }
    }

    /// **Parity with the Lean proof** (`SnapshotCloneSafetyProofs.lean`): the
    /// `CmdKey.isPerPodSecret` / `isSharedConfig` classification the Lean
    /// disjointness / fail-closed / sound-guard theorems are proven over must
    /// equal the production key sets, so those theorems govern the SHIPPED guard.
    /// Same discipline as #2299 (bind the model to production, exhaustively). A
    /// drift in either the model or production is caught as a set-inequality.
    #[test]
    fn lean_model_classification_matches_production() {
        use std::collections::BTreeSet;
        // Mirrors the Lean `CmdKey` per-pod-secret and shared-config variants.
        const MODEL_PER_POD: &[&str] = &[
            "nucleus.approval_secret",
            "nucleus.auth_secret",
            "nucleus.sandbox_token",
            "nucleus.task_token_hex",
            "nucleus.task_token_issuer",
            "nucleus.task_token_nonce",
            "nucleus.aws_access_key_id",
            "nucleus.aws_secret_access_key",
            "nucleus.aws_session_token",
        ];
        const MODEL_SHARED: &[&str] = &[
            "nucleus.approval_pubkeys",
            "nucleus.audit_s3_bucket",
            "nucleus.audit_s3_endpoint",
            "nucleus.audit_s3_prefix",
            "nucleus.audit_s3_region",
            "nucleus.aws_default_region",
            "nucleus.workload_api_port",
            "nucleus.net",
        ];
        assert_eq!(
            MODEL_PER_POD.iter().collect::<BTreeSet<_>>(),
            PER_POD_SECRET_KEYS.iter().collect::<BTreeSet<_>>(),
            "Lean CmdKey per-pod-secret set drifted from production PER_POD_SECRET_KEYS \
             — update SnapshotCloneSafetyProofs.lean and this mirror together"
        );
        assert_eq!(
            MODEL_SHARED.iter().collect::<BTreeSet<_>>(),
            SHARED_CONFIG_KEYS.iter().collect::<BTreeSet<_>>(),
            "Lean CmdKey shared-config set drifted from production SHARED_CONFIG_KEYS \
             — update SnapshotCloneSafetyProofs.lean and this mirror together"
        );
    }

    /// Shared config must NOT block snapshotting, or no base is ever buildable
    /// and the guard is just an off switch.
    #[test]
    fn shared_configuration_does_not_block_a_base() {
        let mut args = BASE.to_string();
        for key in SHARED_CONFIG_KEYS {
            args.push_str(&format!(" {key}=x"));
        }
        assert!(
            snapshot_safety(&args).is_safe_to_clone(),
            "per-node config is identical for every clone and must not block: {args}"
        );
    }

    /// Presence, not value: a base built with an empty secret is still a base
    /// someone will populate later.
    #[test]
    fn an_empty_secret_value_is_still_refused() {
        assert!(!snapshot_safety(&format!("{BASE} nucleus.auth_secret=")).is_safe_to_clone());
    }

    /// Prefixes must not collide — `nucleus.auth_secret_hint` is not
    /// `nucleus.auth_secret`, and matching loosely would refuse bases that are
    /// fine.
    #[test]
    fn matching_is_on_whole_keys_not_prefixes() {
        assert!(snapshot_safety(&format!("{BASE} nucleus.auth_secretive=1")).is_safe_to_clone());
    }

    /// THE DRIFT GUARD, and the reason the two lists are exhaustive rather than
    /// implied.
    ///
    /// If someone adds a new `nucleus.*` key to the command-line builder and
    /// does not classify it, this fails. Without it, a new secret would default
    /// to "not in the denylist" — i.e. silently clonable — which is exactly the
    /// wrong direction for a guard whose whole job is refusing to duplicate
    /// secrets.
    #[test]
    fn every_cmdline_key_is_classified() {
        let src = include_str!("firecracker_config.rs");
        let mut emitted: Vec<String> = Vec::new();
        let mut rest = src;
        while let Some(i) = rest.find("nucleus.") {
            rest = &rest[i..];
            let key: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
                .collect();
            if key.len() > "nucleus.".len() && !emitted.contains(&key) {
                emitted.push(key);
            }
            rest = &rest["nucleus.".len()..];
        }
        assert!(
            emitted.len() >= 10,
            "the scraper found only {} keys — it has stopped matching the source",
            emitted.len()
        );
        for key in &emitted {
            let k = key.as_str();
            assert!(
                PER_POD_SECRET_KEYS.contains(&k) || SHARED_CONFIG_KEYS.contains(&k),
                "{k} is emitted onto the guest command line but is classified neither per-pod \
                 nor shared. Decide which it is: getting it wrong in the 'shared' direction \
                 leaks it to every clone restored from a snapshot."
            );
        }
    }

    /// **The guest rootfs must carry a CA bundle.**
    ///
    /// The tool-proxy builds an HTTPS client at startup when drand is enabled
    /// (the default), and a Debian slim base ships no system CA store. Without
    /// one the proxy cannot construct that client — and it is PID 1 in the
    /// guest, so the failure panicked the kernel and took the microVM down.
    ///
    /// Found by booting a pod built from this repository's own rootfs script on
    /// real KVM. No unit test could have caught it: they all run on a host that
    /// happens to have a CA store, and all 436 of them passed before and after.
    #[test]
    fn the_rootfs_script_installs_a_ca_bundle() {
        let script = include_str!("../../../scripts/firecracker/build-rootfs.sh");
        assert!(
            script.contains("ca-certificates.crt"),
            "build-rootfs.sh no longer installs a CA bundle into the guest rootfs. \
             The tool-proxy needs one to start with drand enabled, and it is PID 1 — \
             so the pod will not boot."
        );
    }

    /// **The snapshot payoff, now REALIZED (2026-08-08).** A command line built
    /// for a real identity-bearing pod carries no per-pod material at all — the
    /// AWS credentials moved to the workload API, `approval_secret` became a
    /// public `approval_pubkeys`, and the Tier-3 `sandbox_token` + task-token
    /// copy were retired — so it is SafeToClone. The warm-pool base is
    /// unblocked.
    ///
    /// This asserts the payoff behaviourally over a realistic cmdline rather
    /// than by scanning `firecracker_config.rs` source. The old source-scan
    /// ratchet (`the_remaining_distance_…`) was retired here: once the emission
    /// dropped to zero, the tests that assert the ABSENCE of each key contain
    /// its name in quoted form, which a self-referential source scan misreads
    /// as emission. The authoritative guard is now behavioural and lives beside
    /// the emitter — `firecracker_config::tests::no_pod_cmdline_carries_any_per_pod_secret`
    /// checks the REAL generated boot args (linux-only, where the emitter
    /// compiles) for every identity outcome.
    #[test]
    fn a_realistic_identity_bearing_cmdline_is_now_snapshottable() {
        // Everything a real identity-bearing pod actually gets: shared/public
        // config only. No PER_POD_SECRET_KEYS member appears.
        let realistic = format!(
            "{BASE} nucleus.workload_api_port=15012 nucleus.approval_pubkeys=aa00bb11 \
             nucleus.audit_s3_bucket=b nucleus.aws_default_region=us-east-1"
        );
        assert!(
            snapshot_safety(&realistic).is_safe_to_clone(),
            "a realistic identity-bearing pod cmdline carries no per-pod material and must be \
             snapshottable: {realistic}"
        );
    }

    /// The guard still bites: a cmdline that DOES carry a per-pod secret (a
    /// regression, or an identity-less pod under some future design) is refused,
    /// naming the offending key. The denylist is categorical and unchanged even
    /// though nothing emits these today — that is what makes re-introducing one
    /// a caught regression rather than a silent clone.
    /// A VM that has been served per-pod material is refused even with a spotless cmdline.
    ///
    /// This is the whole point of the second question. The boot args here are the SAFE ones —
    /// the same string the existing tests call clonable — and the answer still has to be no,
    /// because the identity did not arrive on the command line. It arrived afterwards.
    #[test]
    fn a_personalized_vm_is_refused_however_clean_its_boot_args_are() {
        let clean = format!("{BASE} nucleus.workload_api_port=15012");
        assert!(
            snapshot_safety(&clean).is_safe_to_clone(),
            "precondition: these boot args are the clonable ones"
        );
        assert_eq!(
            clone_safety(&clean, true, true, &MountState::NeverMounted),
            SnapshotSafety::PersonalizedSince,
            "a VM that has been handed its identity is not a base, whatever its cmdline says"
        );
    }

    /// Not personalised falls through to the cmdline question rather than passing blindly.
    #[test]
    fn an_unpersonalized_vm_is_still_judged_on_its_boot_args() {
        let clean = format!("{BASE} nucleus.workload_api_port=15012");
        assert!(clone_safety(&clean, true, false, &MountState::NeverMounted).is_safe_to_clone());

        let dirty = format!("{BASE} {}=deadbeef", PER_POD_SECRET_KEYS[0]);
        assert!(
            !clone_safety(&dirty, true, false, &MountState::NeverMounted).is_safe_to_clone(),
            "the cmdline scan must still apply when nothing has been served yet"
        );
    }

    /// A guest that never announced its barrier is not a base, however clean everything else is.
    ///
    /// This is the case an older rootfs lands in: nothing served, boot args spotless, and still
    /// refused — because "nothing has happened yet" and "the guest is ready" are different facts
    /// and only the guest knows the second.
    #[test]
    fn a_guest_that_never_announced_its_barrier_is_refused() {
        let clean = format!("{BASE} nucleus.workload_api_port=15012");
        assert_eq!(
            clone_safety(&clean, false, false, &MountState::NeverMounted),
            SnapshotSafety::NotAtBarrier
        );
        // ...and being personalised is the louder complaint of the two.
        assert_eq!(
            clone_safety(&clean, false, true, &MountState::NeverMounted),
            SnapshotSafety::PersonalizedSince,
            "when both are wrong, say the dangerous one"
        );
    }

    #[test]
    fn a_cmdline_that_carries_a_per_pod_secret_is_still_refused() {
        for key in PER_POD_SECRET_KEYS {
            let args = format!("{BASE} nucleus.workload_api_port=15012 {key}=deadbeef");
            match snapshot_safety(&args) {
                SnapshotSafety::WouldDuplicateSecret { key: found } => assert_eq!(&found, key),
                other => {
                    panic!("{key} on the cmdline must make the base unclonable, got {other:?}")
                }
            }
        }
    }
}

#[cfg(test)]
mod mount_state_tests {
    use super::*;

    /// The two superblock shapes, verbatim from `dumpe2fs -h` on 2026-09-12.
    const FRESH: &str = "Filesystem volume name:   <none>\nLast mounted on:          <not available>\nFilesystem state:         clean\nMount count:              0\nMaximum mount count:      -1\n";
    const USED: &str = "Filesystem volume name:   <none>\nLast mounted on:          /mnt\nFilesystem state:         clean\nMount count:              1\nMaximum mount count:      -1\n";

    #[test]
    fn a_never_mounted_image_reads_as_never_mounted() {
        assert_eq!(parse_mount_count(FRESH), MountState::NeverMounted);
    }

    #[test]
    fn an_image_a_guest_mounted_reads_as_mounted() {
        assert_eq!(parse_mount_count(USED), MountState::Mounted { count: 1 });
    }

    /// **Unreadable is `Unknown`, never `NeverMounted`.** A scratch this code
    /// cannot parse is not one it may certify: the costs are asymmetric, since
    /// a wrong refusal is a cold boot and a wrong certification corrupts every
    /// clone restored from the base.
    #[test]
    fn an_unparseable_superblock_is_unknown_not_clean() {
        assert!(matches!(parse_mount_count(""), MountState::Unknown(_)));
        assert!(matches!(
            parse_mount_count("Mount count:              banana\n"),
            MountState::Unknown(_)
        ));
        assert!(matches!(
            parse_mount_count("Filesystem state: clean\n"),
            MountState::Unknown(_)
        ));
    }

    const CLEAN_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off init=/init";

    /// **The change M3 turns on:** a scratch that is ATTACHED but never mounted
    /// no longer blocks a base. Measured in
    /// `scripts/experiments/snapshot-deferred-mount.sh` — two clones restored
    /// against fresh images of identical geometry both fsck clean.
    #[test]
    fn an_attached_but_unmounted_scratch_is_cloneable() {
        assert!(
            clone_safety(CLEAN_ARGS, true, false, &MountState::NeverMounted).is_safe_to_clone(),
            "an unmounted scratch must not block a base — that was the old, attachment-based \
             predicate, and it made every jailed pod unsnapshottable"
        );
    }

    /// **And the part that must NOT change:** a mounted one still blocks. Its
    /// ext4 metadata is in the snapshot, so a clone restored against a fresh
    /// image has cached metadata describing a filesystem that is not there.
    #[test]
    fn a_mounted_scratch_still_blocks_a_base() {
        assert_eq!(
            clone_safety(CLEAN_ARGS, true, false, &MountState::Mounted { count: 1 }),
            SnapshotSafety::WritableScratchAttached
        );
    }

    /// A scratch the host could not read blocks it too.
    #[test]
    fn an_unreadable_scratch_blocks_a_base() {
        assert_eq!(
            clone_safety(
                CLEAN_ARGS,
                true,
                false,
                &MountState::Unknown("no e2fsprogs".into())
            ),
            SnapshotSafety::WritableScratchAttached
        );
    }

    /// The scratch check must not mask the others: a personalised VM with a
    /// pristine scratch is still refused, and for its own reason.
    #[test]
    fn an_unmounted_scratch_does_not_excuse_a_personalised_vm() {
        assert_eq!(
            clone_safety(CLEAN_ARGS, true, true, &MountState::NeverMounted),
            SnapshotSafety::PersonalizedSince
        );
        assert_eq!(
            clone_safety(CLEAN_ARGS, false, false, &MountState::NeverMounted),
            SnapshotSafety::NotAtBarrier
        );
    }
}
