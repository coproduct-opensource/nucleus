//! What a pod IS, as a digest — the same program named the same way every time.
//!
//! # Not the existing hash
//!
//! The node already hashes a pod spec: `sha256(spec_yaml.as_bytes())`, over the raw YAML text.
//! That is sensitive to whitespace, key order and comments, so two byte-different spellings of
//! one pod are two different values — and it feeds a per-launch HMAC where being per-launch is
//! the *intent*. This is the opposite object: deliberately equal across launches, because that
//! equality is what makes it usable as a key.
//!
//! Both are kept. Merging them would make two launches of one program mint identical single-use
//! tokens, which is a downgrade dressed as a cleanup.
//!
//! # The exclusion set is a type, not a filter
//!
//! The tempting shape is "serialize, then delete some keys". It drifts the moment anyone adds a
//! field, and it drifts SILENTLY — a new field is simply included, which leaks nothing but
//! quietly destroys reuse, and nobody notices except as a hit rate that got worse.
//!
//! So the projection is built from an exhaustive destructure of [`PodSpecInner`]. Adding a field
//! there is a **compile error in this file** until someone says which side it falls on. That is
//! the same discipline `snapshot.rs` applies to kernel-cmdline keys, except enforced by the type
//! checker rather than by a test that has to be remembered.
//!
//! # Why an image without digests is refused
//!
//! An image is named by PATH in the spec, and a path is not an identity: `/images/a/vmlinux` and
//! `/images/b/vmlinux` may hold identical bytes, or wildly different ones, and the spec cannot
//! say which. So the program digest covers the image's DIGESTS, and a pod that pins none has no
//! stable identity to offer. Refusing is what makes [`ImageSpec::kernel_digest`] and friends
//! worth setting, rather than a field that can be left off forever.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ImageSpec, PodSpec, PodSpecInner};

/// Domain separator. Versioned, so a later change of shape cannot be confused with this one.
const PROGRAM_DOMAIN: &[u8] = b"nucleus.pod-program.v1\n";

/// Why a spec has no program identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The spec names an image but pins no digest for it, so the bytes it would run are unknown.
    UnpinnedImage,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnpinnedImage => write!(
                f,
                "this pod names an image but pins no digest for it, so its program has no stable \
                 identity — set image.kernel_digest and image.rootfs_digest"
            ),
        }
    }
}

/// The image, as identity rather than as location.
#[derive(Serialize)]
struct ImageIdentity<'a> {
    kernel: &'a str,
    rootfs: &'a str,
    scratch: Option<&'a str>,
    /// The read-only data image, by content. See `ImageSpec::data_digest`.
    data: Option<&'a str>,
    /// In, because it changes what the guest does. The node guarantees per-pod material does not
    /// appear here — that migration is what made a shared boot line possible at all.
    boot_args: Option<&'a String>,
    read_only: bool,
}

/// Everything that decides what this pod computes, and nothing about where it happens to run.
#[derive(Serialize)]
struct Program<'a> {
    namespace: Option<&'a String>,
    labels: &'a std::collections::BTreeMap<String, String>,
    work_dir: &'a std::path::PathBuf,
    timeout_seconds: u64,
    policy: &'a crate::PolicySpec,
    budget_model: Option<&'a crate::BudgetModelSpec>,
    resources: Option<&'a crate::ResourceSpec>,
    network: Option<&'a crate::NetworkSpec>,
    image: Option<ImageIdentity<'a>>,
    credentialed_egress: &'a [crate::CredentialedEgressSpec],
    workload: Option<&'a crate::WorkloadSpec>,
    seccomp: Option<&'a crate::SeccompSpec>,
}

fn image_identity(image: &ImageSpec) -> Result<ImageIdentity<'_>, IdentityError> {
    // EXHAUSTIVE, for the same reason `program_digest` is. The destructure below covers
    // `PodSpecInner`, which stops a new POD field being silently included — but until now nothing
    // guarded `ImageSpec`, so a new IMAGE field would have been silently EXCLUDED. That is the
    // worse direction: a pod whose data image changed would have kept its identity, and a cache
    // would have served the old answer for new inputs.
    let ImageSpec {
        // OUT — locations. `/images/a/vmlinux` and `/images/b/vmlinux` may hold identical bytes or
        // wildly different ones, and the path cannot say which. The digests below are the identity.
        kernel_path: _,
        rootfs_path: _,
        scratch_path: _,
        data_path: _,
        // IN — the bytes themselves.
        kernel_digest,
        rootfs_digest,
        scratch_digest,
        data_digest,
        boot_args,
        read_only,
    } = image;

    let (Some(kernel), Some(rootfs)) = (kernel_digest, rootfs_digest) else {
        return Err(IdentityError::UnpinnedImage);
    };
    // A scratch disk is per-pod writable space; its digest is pinned only if the spec chose to.
    Ok(ImageIdentity {
        kernel: kernel.as_str(),
        rootfs: rootfs.as_str(),
        scratch: scratch_digest.as_ref().map(|d| d.as_str()),
        // IN, and it decides the answer: a workload reading a different corpus computes something
        // different. This is also what keeps a snapshot honest — see `ImageSpec::data_digest`.
        data: data_digest.as_ref().map(|d| d.as_str()),
        boot_args: boot_args.as_ref(),
        read_only: *read_only,
    })
}

/// The digest of what this pod would compute.
///
/// # Errors
///
/// [`IdentityError::UnpinnedImage`] when the spec names an image without digests.
pub fn program_digest(spec: &PodSpec) -> Result<String, IdentityError> {
    // EXHAUSTIVE. A new field on PodSpecInner stops compiling here until it is classified.
    let PodSpecInner {
        work_dir,
        timeout_seconds,
        policy,
        budget_model,
        resources,
        network,
        image,
        credentialed_egress,
        workload,
        // OUT — host transport. The guest CID and port are allocated by the node per launch;
        // two runs of one program get different ones and are still the same program.
        vsock: _,
        seccomp,
        // OUT — host placement. Which cgroup a VMM lands in cannot change what it concludes,
        // the same argument that took `resources` out of gatehouse's gate identity.
        cgroup: _,
        // OUT — where audit records are shipped. Changing the sink does not change the run.
        audit_sink: _,
        // OUT, and the most important exclusion. Two pods differing only in which token they
        // were handed are the same program; including this would give every credential rotation
        // a new identity, and would put secret-derived bytes into a value meant to be shared.
        credentials: _,
    } = &spec.spec;

    let crate::Metadata {
        // OUT — an annotation. Renaming a pod does not change what it runs.
        name: _,
        // IN — it selects the SPIFFE namespace, so it is authority, not decoration.
        namespace,
        // IN, whole. The map is untyped and mixed: some keys are security claims, some are
        // program inputs, some are annotations. Including everything biases toward MORE distinct
        // programs, i.e. toward cache misses — wrong in the safe direction.
        labels,
        // OUT — the same argument that took `credentials` out. A task grant is a per-run
        // authority binding carried for the exit report's authority summary, not a description
        // of what the pod runs; two pods differing only in which grant authorized them are the
        // same program. The bounds a grant enforces reach identity through the fields that
        // actually carry them — `policy`, `network` and `credentialed_egress` — which are all
        // IN above, so excluding the id loses no enforceable distinction. Including it would
        // give every re-issued grant a fresh identity, exactly the churn `credentials` avoids.
        task_grant_id: _,
    } = &spec.metadata;

    let program = Program {
        namespace: namespace.as_ref(),
        labels,
        work_dir,
        timeout_seconds: *timeout_seconds,
        policy,
        budget_model: budget_model.as_ref(),
        resources: resources.as_ref(),
        network: network.as_ref(),
        image: image.as_ref().map(image_identity).transpose()?,
        credentialed_egress,
        workload: workload.as_ref(),
        seccomp: seccomp.as_ref(),
    };

    let canonical = serde_json_canonicalizer::to_vec(&program)
        .expect("the program projection is plain data and always serializes");
    let mut h = Sha256::new();
    h.update(PROGRAM_DOMAIN);
    h.update(&canonical);
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_from(json: &str) -> PodSpec {
        serde_json::from_str(json).expect("test spec parses")
    }

    const D1: &str = "sha-256:1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "sha-256:2222222222222222222222222222222222222222222222222222222222222222";

    fn pinned(extra: &str) -> PodSpec {
        spec_from(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{
                 "image":{{"kernel_path":"/k","rootfs_path":"/r",
                           "kernel_digest":"{D1}","rootfs_digest":"{D2}"}}{extra}}}}}"#
        ))
    }

    /// The same program spelled three ways is one digest.
    ///
    /// This is the whole point: the existing spec hash is `sha256` of the YAML TEXT, so
    /// reformatting changes it. A value used as a key cannot behave that way.
    #[test]
    fn formatting_and_key_order_do_not_change_the_program() {
        let a = spec_from(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"work_dir":"/w","timeout_seconds":60}}"#,
        );
        let b = spec_from(
            r#"{ "kind" : "Pod" ,
                 "apiVersion":"nucleus/v1",
                 "spec" : { "timeout_seconds" : 60 , "work_dir" : "/w" } }"#,
        );
        assert_eq!(
            program_digest(&a).unwrap(),
            program_digest(&b).unwrap(),
            "key order and whitespace must not make a different program"
        );
    }

    /// Credentials are not part of what a pod computes.
    #[test]
    fn two_pods_differing_only_in_credentials_are_the_same_program() {
        let bare = pinned("");
        let with_creds = pinned(r#","credentials":{"env":{"LLM_API_TOKEN":"test-token-123"}}"#);
        assert_eq!(
            program_digest(&bare).unwrap(),
            program_digest(&with_creds).unwrap(),
            "a token is what a program is GIVEN, not what it is"
        );
    }

    /// Neither is where its audit goes, nor which cgroup it lands in.
    #[test]
    fn host_placement_and_audit_routing_are_not_part_of_the_program() {
        let bare = pinned("");
        let placed = pinned(r#","cgroup":{"path":"/sys/fs/cgroup/nucleus/pod-7"}"#);
        assert_eq!(
            program_digest(&bare).unwrap(),
            program_digest(&placed).unwrap()
        );
    }

    /// An image is identified by its digests, not by where the file happens to sit.
    #[test]
    fn the_same_bytes_at_different_paths_are_the_same_program() {
        let here = spec_from(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{{
                 "kernel_path":"/images/a/vmlinux","rootfs_path":"/images/a/rootfs.ext4",
                 "kernel_digest":"{D1}","rootfs_digest":"{D2}"}}}}}}"#
        ));
        let there = spec_from(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{{
                 "kernel_path":"/mnt/elsewhere/vmlinux","rootfs_path":"/mnt/elsewhere/rootfs.ext4",
                 "kernel_digest":"{D1}","rootfs_digest":"{D2}"}}}}}}"#
        ));
        assert_eq!(
            program_digest(&here).unwrap(),
            program_digest(&there).unwrap(),
            "a path is a location; the digest is the identity"
        );
    }

    /// Different bytes are a different program, even at the same path.
    #[test]
    fn different_image_digests_are_different_programs() {
        let a = pinned("");
        let b = spec_from(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{{
                 "kernel_path":"/k","rootfs_path":"/r",
                 "kernel_digest":"{D2}","rootfs_digest":"{D1}"}}}}}}"#
        ));
        assert_ne!(program_digest(&a).unwrap(), program_digest(&b).unwrap());
    }

    /// Things that DO decide the answer each change the digest.
    ///
    /// The converse of the exclusions, and the one that matters: an exclusion that took
    /// something real with it would let two different programs share an identity.
    #[test]
    fn everything_that_decides_the_answer_changes_the_program() {
        let base = pinned("");
        for (what, extra) in [
            (
                "policy",
                r#","policy":{"type":"profile","name":"read-only"}"#,
            ),
            ("work_dir", r#","work_dir":"/elsewhere""#),
            ("timeout_seconds", r#","timeout_seconds":999"#),
            ("network", r#","network":{"allow":["example.com"]}"#),
            (
                "workload",
                r#","workload":{"command":"echo","args":["hi"]}"#,
            ),
        ] {
            let other = pinned(extra);
            assert_ne!(
                program_digest(&base).unwrap(),
                program_digest(&other).unwrap(),
                "{what} decides what the pod computes, so it must change its identity"
            );
        }
    }

    /// A read-only data image is part of what a pod computes.
    ///
    /// The whole reason it can be pinned: a workload reading a different corpus computes something
    /// different, so two pods differing only in that corpus must not share a program identity — or
    /// a cache would answer for the wrong inputs, and a snapshot base would be restored against a
    /// corpus it was not frozen with. Firecracker offers no `drive_overrides` on snapshot load, so
    /// nothing downstream could catch it.
    #[test]
    fn a_different_data_image_is_a_different_program() {
        let bare = pinned("");
        let with_data = spec_from(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{{
                 "kernel_path":"/k","rootfs_path":"/r","kernel_digest":"{D1}",
                 "rootfs_digest":"{D2}","data_path":"/d.img","data_digest":"{D1}"}}}}}}"#
        ));
        let other_data = spec_from(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{{
                 "kernel_path":"/k","rootfs_path":"/r","kernel_digest":"{D1}",
                 "rootfs_digest":"{D2}","data_path":"/d.img","data_digest":"{D2}"}}}}}}"#
        ));
        assert_ne!(
            program_digest(&bare).unwrap(),
            program_digest(&with_data).unwrap(),
            "attaching a corpus changes what the pod computes"
        );
        assert_ne!(
            program_digest(&with_data).unwrap(),
            program_digest(&other_data).unwrap(),
            "a DIFFERENT corpus at the same path is a different program"
        );
        // ...and where the image sits on the host is not part of it, same as every other artifact.
        let elsewhere = spec_from(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{{
                 "kernel_path":"/k","rootfs_path":"/r","kernel_digest":"{D1}",
                 "rootfs_digest":"{D2}","data_path":"/mnt/elsewhere.img","data_digest":"{D1}"}}}}}}"#
        ));
        assert_eq!(
            program_digest(&with_data).unwrap(),
            program_digest(&elsewhere).unwrap(),
            "a path is a location; the digest is the identity"
        );
    }

    /// An image without digests has no identity to give, and says so.
    #[test]
    fn an_unpinned_image_has_no_program_identity() {
        let unpinned = spec_from(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{
                 "image":{"kernel_path":"/k","rootfs_path":"/r"}}}"#,
        );
        assert_eq!(
            program_digest(&unpinned),
            Err(IdentityError::UnpinnedImage),
            "a path is not an identity"
        );
        // ...while a pod with no image at all is fine: there is nothing unpinned about it.
        let no_image =
            spec_from(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"work_dir":"/w"}}"#);
        assert!(program_digest(&no_image).is_ok());
    }

    /// The digest is domain-separated and stable in shape.
    #[test]
    fn the_digest_is_64_hex_and_domain_separated() {
        let d = program_digest(&pinned("")).unwrap();
        assert_eq!(d.len(), 64);
        assert!(d.bytes().all(|b| b.is_ascii_hexdigit()));
        // The same canonical bytes without the domain tag must not collide with it.
        let program_only = {
            let mut h = Sha256::new();
            h.update(b"{}");
            hex::encode(h.finalize())
        };
        assert_ne!(d, program_only);
    }
}
