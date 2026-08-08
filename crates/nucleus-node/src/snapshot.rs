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
//! Nucleus injects exactly that kind of state — **on the kernel command line**,
//! where it is baked into `/proc/cmdline` and into the snapshot's memory image.
//! Restoring N pods from a snapshot taken after boot would give all N the same
//! `sandbox_token` and the same task token — values minted per pod, so the
//! duplication is real. See [`PER_POD_SECRET_KEYS`] for what is genuinely
//! per-pod versus merely per-node, and for why the nonce case is less severe
//! than it first appears (`session_mint` pins it host-side rather than relying
//! on secrecy).
//!
//! So a snapshot base must be built **before any per-pod material exists**, and
//! uniqueness must be delivered after restore by a channel that is not the
//! command line. This module refuses the unsafe case; it does not yet implement
//! the delivery channel, and [`SnapshotSafety`] is deliberately useless for
//! anything except saying no.

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
/// # The remaining four, each re-derived rather than inherited
///
/// `nucleus.sandbox_token` was removed for identity-bearing pods once the
/// blocking question turned out to be the wrong one — it was filed as needing a
/// booted pod to confirm attestation, when attestation only distinguishes Tier 1
/// from Tier 2 and both satisfy the proof. That is a reason to re-derive the
/// others rather than inherit their notes:
///
/// * **`nucleus.approval_secret`** — GONE (2026-08-08), replaced rather than
///   conditionally emitted. The earlier note here argued it could not simply
///   be dropped because the approval path deliberately keeps its drand anchor
///   even on a host-verified transport — true, and the replacement keeps it:
///   approvals are now Ed25519 signatures verified against
///   `nucleus.approval_pubkeys` (the node's PUBLIC approval key, classified
///   in [`SHARED_CONFIG_KEYS`]: per-node config, and reading a verification
///   key grants no forging power — unlike the HMAC key, which was symmetric
///   and let any `/proc/cmdline` reader sign its own approvals). The key
///   stays in [`PER_POD_SECRET_KEYS`] so a regression that re-emits a shared
///   approval secret is refused, not silently clonable.
/// * **`nucleus.task_token_hex` / `_issuer` / `_nonce`** — these are documented
///   at the emission site as *"a scoped capability + PUBLIC issuer key — NOT a
///   secret"*, with anti-replay resting on a host-pinned nonce. They are in
///   [`PER_POD_SECRET_KEYS`] for a different reason: they are **per-pod**, and a
///   clone that inherited them would duplicate a value minted for one pod. So
///   the fix is not to stop emitting them but to deliver them **after restore**,
///   over a channel that is not the command line. The workload API vsock bridge
///   is already that shape — it serves per-pod SVIDs over a per-pod socket — and
///   carrying the task token on it is the next real piece of work here. It is
///   architecture, not a conditional.
///
/// # The task-token delivery design, decided
///
/// Two channels could carry it, and the choice is not arbitrary:
///
/// * the **broker socket** — per-pod, identity-bound at the listener,
///   fail-closed, bounded frames, TTL'd. Better engineered, and the channel this
///   whole effort built. But its frame is a credential *request envelope*, and a
///   token fetch is not that; it would need a second operation kind.
/// * the **workload API vsock bridge** — already serves per-pod artifacts over a
///   per-pod socket, with a closed command enum (`FETCH_SVID`, `FETCH_BUNDLE`,
///   `PING`) whose docs say adding a variant is the only way to teach the host a
///   new command. A `FETCH_TASK_TOKEN` variant fits the existing shape exactly.
///
/// **The workload API bridge wins**, on the grounds that it is already the
/// per-pod artifact channel and the extension is a variant rather than a second
/// protocol inside a protocol.
///
/// ## It has to be conditional, for the same reason `sandbox_token` is
///
/// Both candidate channels are gated on identity: `workload_api_port_for` and
/// `identity_registration` are the same predicate, and the broker's listener is
/// refused for a pod with no host-established identity. So **for a pod without
/// an identity neither channel exists**, and its task token must stay on the
/// command line. The change is therefore "deliver over vsock *when the pod will
/// have an identity*", exactly the shape [`PER_POD_SECRET_KEYS`]'s
/// `sandbox_token` note landed on.
///
/// ## What has to be true before it lands — and here a boot really is required
///
/// The `sandbox_token` conditional needed no booted pod, because the question
/// was answerable in code. **This one is different**, and the difference is worth
/// being precise about rather than assuming the same shortcut applies twice:
/// it changes GUEST STARTUP ORDERING. The tool-proxy verifies its task token
/// once at startup; moving delivery from "already in the environment" to "fetch
/// over vsock first" introduces a startup dependency whose failure mode — the
/// fetch not completing before the proxy reads its environment — cannot be
/// observed from the host side or from a unit test. It needs a pod that boots.
///
/// # An earlier note, and what has to be true first
///
/// `nucleus.sandbox_token` is the strongest candidate for deletion rather than
/// relocation — the same shape as `nucleus.auth_secret`, which Phase 1 deleted
/// once the vsock peer check made it redundant. Three facts point that way:
///
/// * it is **Tier 3** of the sandbox proof — the Docker-without-SPIRE fallback —
///   and `firecracker_config.rs` says so at the emission site: *"tier 1 (SVID
///   with attestation) is preferred in Firecracker"*;
/// * it is verified with `auth_secret`, which **is no longer delivered on this
///   path**. The cmdline key is gone, and the only remaining channel is
///   `/etc/nucleus/auth.secret`, written by `build-rootfs.sh` at IMAGE BUILD
///   time — so it is either absent or shared by every pod built from that image.
///   A per-pod token whose verification key is fleet-wide is not per-pod;
/// * it is one of the five keys blocking a snapshot base.
///
/// **Not removed here, deliberately.** Deleting it makes every Firecracker pod
/// depend on Tier 1 or Tier 2 succeeding, and the tool-proxy exits fatally when
/// no tier does — `SandboxProofError::NakedProcess`. That is fail-closed and
/// correct, but it is the startup path of every pod, and the precondition is an
/// empirical one this repository cannot check by reading itself: **boot a pod on
/// the KVM box and confirm the SVID carries the attestation extension**. Until
/// someone has that observation, removing the fallback is a guess dressed as a
/// simplification.
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

    /// **How far the snapshot payoff actually is, measured rather than claimed.**
    ///
    /// The plan for this work called the snapshot payoff "a consequence, not a
    /// workstream": remove per-pod material from the guest and
    /// [`snapshot_safety`] becomes satisfiable by construction. **That was
    /// wrong**, and this test is what makes the error visible instead of
    /// discovering it when the warm pool is built. Phase 1 deleted exactly one
    /// key — `nucleus.auth_secret` — and FOUR remain.
    ///
    /// The count has been wrong before, in the dangerous direction: an earlier
    /// version of this test scanned only for `nucleus.key=` and asserted five
    /// while EIGHT were emitted. It **silently missed the three AWS
    /// audit credentials** (`nucleus.aws_access_key_id` /
    /// `_secret_access_key` / `_session_token`), because they were emitted not
    /// as a `format!("… nucleus.aws_…={val}")` literal but through a table LOOP
    /// (`for (env_key, arg_key) in [("AWS_ACCESS_KEY_ID", …), …]`),
    /// so the literal `nucleus.aws_access_key_id=` never appeared in the source.
    /// A real secret — long-lived cloud credentials — rode the world-readable
    /// `/proc/cmdline` uncounted by the very gate meant to track it. (An earlier
    /// miscount for a different reason — a shell pipeline deduplicating
    /// `nucleus.task_token_nonce` — is why this pins the SET, not a number.)
    ///
    /// So this scan matches emission in EITHER form: a direct `{key}=` literal
    /// (the `format!` sites) OR a quoted `"{key}"` table entry (the form the
    /// audit-cred loop used while it existed). Comments here use backticks, not
    /// double quotes, so the quoted-form match does not re-introduce the false
    /// positive the `=`-only scan avoided (`nucleus.auth_secret` appears only
    /// in prose and matches neither form, which is correct — it is no longer
    /// emitted).
    ///
    /// **Down to four (2026-08-08):** the three AWS audit credentials now ride
    /// the workload API (`FETCH_AUDIT_CREDENTIALS`, served once before any
    /// workload exists), and `nucleus.approval_secret` was replaced by
    /// signature-based approvals (`nucleus.approval_pubkeys` — a public
    /// verification key, classified shared). All four STAY in
    /// [`PER_POD_SECRET_KEYS`]: the denylist is categorical, so a regression
    /// that re-emits any of them is refused by `snapshot_safety` at runtime
    /// and re-counted here at test time.
    ///
    /// A ratchet in both directions, and it is also the only guard on the
    /// **confidentiality** exposure the C1 ledger row was demoted for: every key
    /// below is readable by the workload via `/proc/cmdline`. Emitting a NEW
    /// per-pod secret fails here; removing one is progress and forces this list
    /// to be re-stated rather than quietly drifting.
    #[test]
    fn the_remaining_distance_to_a_snapshottable_base_is_four_keys() {
        let src = include_str!("firecracker_config.rs");
        let mut emitted: Vec<&str> = Vec::new();
        for key in PER_POD_SECRET_KEYS {
            // Direct `{key}=` (format! sites) OR quoted `"{key}"` (a table-loop
            // entry). The second disjunct is the fix that first caught the AWS
            // credentials: emitted via a loop, the `{key}=` literal never
            // appeared in the source.
            if src.contains(&format!("{key}=")) || src.contains(&format!("\"{key}\"")) {
                emitted.push(key);
            }
        }
        emitted.sort_unstable();

        let expected = [
            "nucleus.sandbox_token",
            "nucleus.task_token_hex",
            "nucleus.task_token_issuer",
            "nucleus.task_token_nonce",
        ];
        assert_eq!(
            emitted, expected,
            "the set of per-pod secrets still riding the (world-readable) kernel command line \
             has changed. Adding one blocks the snapshot base further AND widens the C1 \
             confidentiality exposure; removing one is progress and this list should be updated \
             to match. Either way the distance must be re-stated, not silently drifted."
        );
    }

    /// The consequence of the above, stated as behaviour rather than as a count:
    /// a command line built for a REAL pod today is not snapshottable.
    ///
    /// Without this, the module reads as though the guard exists for a hazard
    /// that no longer occurs. It occurs on every pod.
    #[test]
    fn a_realistic_pod_cmdline_is_still_refused_today() {
        let realistic = format!(
            "{BASE} nucleus.workload_api_port=15012 nucleus.approval_pubkeys=aa00bb11 \
             nucleus.sandbox_token=abc123 nucleus.task_token_hex=7b7d"
        );
        match snapshot_safety(&realistic) {
            SnapshotSafety::WouldDuplicateSecret { key } => assert!(
                PER_POD_SECRET_KEYS.contains(&key.as_str()),
                "the refusal should name a classified per-pod key, got {key}"
            ),
            SnapshotSafety::SafeToClone => panic!(
                "a realistic pod command line reported safe to clone — either the per-pod \
                 material really has been removed (in which case this test and \
                 `the_remaining_distance_to_a_snapshottable_base_is_four_keys` should both be \
                 updated, and the warm pool is unblocked), or the guard has stopped matching"
            ),
        }
    }
}
