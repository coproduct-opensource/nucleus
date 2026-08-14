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
                SnapshotSafety::SafeToClone => unreachable!(),
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
    #[test]
    fn a_cmdline_that_carries_a_per_pod_secret_is_still_refused() {
        for key in PER_POD_SECRET_KEYS {
            let args = format!("{BASE} nucleus.workload_api_port=15012 {key}=deadbeef");
            match snapshot_safety(&args) {
                SnapshotSafety::WouldDuplicateSecret { key: found } => assert_eq!(&found, key),
                SnapshotSafety::SafeToClone => {
                    panic!("{key} on the cmdline must make the base unclonable")
                }
            }
        }
    }
}
