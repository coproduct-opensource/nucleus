//! Which rootfs this node can boot, decided in one place (2026-09-29).
//!
//! `ImageSpec::rootfs` is a `RootfsSource`: a file on the node, or an OCI image. This node has
//! no image store yet, so the only rootfs it can place is a file. Rather than have every consumer
//! — jail placement, drive lowering, pin verification, attestation — match on the source and
//! invent its own reading of "no path" (ADR 0007 G), the launch path resolves the spec ONCE into
//! a [`HostImage`], and every consumer takes that. A `HostImage` has a rootfs file by
//! construction, so none of them has an OCI case to get wrong (C: the evidence is minted by the
//! checker, here `HostImage::resolve`, and its fields are private).
//!
//! [`admit`] asks the same question at pod create, for every driver and before anything is
//! spawned. The image store (a later change) plugs in at `resolve`: it is the one place an OCI
//! source becomes a file.
//!
//! The same resolution parses the spec's `boot_args` (#3124). The node owns the guest kernel
//! command line, and a spec may add only what [`SpecBootArgs::parse`] admits. `admit` refuses the
//! rest at create, and `HostImage` carries the parsed tokens, so the command line is built from
//! checked tokens and never from the raw string.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use nucleus_spec::boot_args::{BootArgRefused, SpecBootArgs};
use nucleus_spec::{ImageSpec, PodSpec, RootfsSource};

use crate::ApiError;

/// A pod named an OCI rootfs, and this node has nowhere to turn it into a file.
#[derive(Debug)]
pub(crate) struct NoImageStore {
    reference: String,
}

impl std::fmt::Display for NoImageStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "image.rootfs_oci names {}, but this node has no image store yet, so it has no \
             file to boot; give the pod an image.rootfs_path",
            self.reference
        )
    }
}

/// Why this node will not boot an image as given. The spec has to change in both cases, so both
/// are `InvalidSpec`, but they are different facts and each keeps its own payload (A-6).
#[derive(Debug)]
pub(crate) enum Unbootable {
    NoImageStore(NoImageStore),
    BootArgs(BootArgRefused),
}

impl std::fmt::Display for Unbootable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoImageStore(e) => e.fmt(f),
            Self::BootArgs(e) => e.fmt(f),
        }
    }
}

impl From<Unbootable> for ApiError {
    // A missing image store means the spec is well-formed and this node cannot serve it.
    // InvalidSpec is still the honest category: nothing was attempted, and the caller changes the
    // spec to proceed.
    fn from(e: Unbootable) -> Self {
        ApiError::InvalidSpec(e.to_string())
    }
}

impl From<NoImageStore> for ApiError {
    fn from(e: NoImageStore) -> Self {
        Unbootable::NoImageStore(e).into()
    }
}

/// The one check behind both [`admit`] and [`HostImage::resolve`]: the rootfs file, and the spec's
/// command line tokens, parsed.
fn check(image: &ImageSpec) -> Result<(&Path, SpecBootArgs), Unbootable> {
    let rootfs = host_path(image).map_err(Unbootable::NoImageStore)?;
    let boot_args = SpecBootArgs::of(image).map_err(Unbootable::BootArgs)?;
    Ok((rootfs, boot_args))
}

/// The rootfs file on this host, or the refusal. Exhaustive: a new source is a compile error here.
pub(crate) fn host_path(image: &ImageSpec) -> Result<&Path, NoImageStore> {
    match &image.rootfs {
        RootfsSource::Path(path) => Ok(path),
        RootfsSource::Oci(oci) => Err(NoImageStore {
            reference: oci.reference.to_string(),
        }),
    }
}

/// Refuse at create a pod whose rootfs this node cannot place, or whose `boot_args` include anything
/// a spec may not add. A pod with no image has neither to refuse; whether it may run without one is
/// the driver's question, not this one.
pub(crate) fn admit(spec: &PodSpec) -> Result<(), ApiError> {
    match &spec.spec.image {
        Some(image) => check(image).map(|_| ()).map_err(ApiError::from),
        None => Ok(()),
    }
}

/// An `ImageSpec` whose rootfs is a file on this host. Derefs to the spec for every other field.
///
/// No `DerefMut`: the one field a consumer may change after resolution is the scratch disk the
/// node provisions (#2789), and that has its own setter. Anything wider would let a resolved
/// image have its rootfs swapped out from under the path it was resolved to.
#[derive(Debug, Clone)]
pub(crate) struct HostImage {
    image: ImageSpec,
    rootfs: PathBuf,
    boot_args: SpecBootArgs,
}

impl HostImage {
    /// Resolve the rootfs to a host file and parse the spec's command line tokens, or refuse. The
    /// launch path is Linux-only, so this is too.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn resolve(image: &ImageSpec) -> Result<Self, Unbootable> {
        let (rootfs, boot_args) = check(image)?;
        Ok(Self {
            rootfs: rootfs.to_path_buf(),
            image: image.clone(),
            boot_args,
        })
    }

    /// The pod's image, resolved. The missing-image message is the one the launch path always
    /// gave (`api_error.rs` pins how it renders).
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn of_spec(spec: &PodSpec) -> Result<Self, ApiError> {
        let image = spec
            .spec
            .image
            .as_ref()
            .ok_or_else(|| ApiError::Driver("missing spec.image".to_string()))?;
        Ok(Self::resolve(image)?)
    }

    /// The rootfs file that will boot.
    pub(crate) fn rootfs_path(&self) -> &Path {
        &self.rootfs
    }

    /// The tokens the spec added to the guest command line, every one of them admitted. The
    /// command line is built from these and never from `image.boot_args` itself.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn spec_boot_args(&self) -> &SpecBootArgs {
        &self.boot_args
    }

    /// Attach the scratch disk the node provisioned for this pod.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_scratch_path(&mut self, path: PathBuf) {
        self.image.scratch_path = Some(path);
    }
}

impl Deref for HostImage {
    type Target = ImageSpec;

    fn deref(&self) -> &ImageSpec {
        &self.image
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(image: &str) -> PodSpec {
        serde_json::from_str(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"image":{image}}}}}"#
        ))
        .expect("test spec parses")
    }

    fn oci_spec() -> PodSpec {
        let h = "a".repeat(64);
        spec(&format!(
            r#"{{"kernel_path":"/k","rootfs_digest":"sha-256:{h}",
                 "rootfs_oci":{{"reference":"registry.example/app@sha256:{h}",
                               "manifest_digest":"sha256:{h}",
                               "guest_layer_digest":"sha-256:{h}"}}}}"#
        ))
    }

    #[test]
    fn an_oci_rootfs_is_refused_at_create_with_the_reason() {
        let Err(ApiError::InvalidSpec(msg)) = admit(&oci_spec()) else {
            panic!("an OCI rootfs must be refused as an invalid spec");
        };
        assert!(msg.contains("no image store yet"), "{msg}");
        assert!(msg.contains("registry.example/app@sha256:"), "{msg}");
    }

    #[test]
    fn an_oci_rootfs_does_not_resolve_to_a_host_image() {
        let Err(ApiError::InvalidSpec(msg)) = HostImage::of_spec(&oci_spec()) else {
            panic!("the launch path must refuse an OCI rootfs too");
        };
        assert!(msg.contains("no image store yet"), "{msg}");
    }

    #[test]
    fn a_path_rootfs_is_admitted_and_resolves_to_its_path() {
        let s = spec(r#"{"kernel_path":"/k","rootfs_path":"/r"}"#);
        assert!(admit(&s).is_ok());
        let host = HostImage::of_spec(&s).expect("a path rootfs resolves");
        assert_eq!(host.rootfs_path(), Path::new("/r"));
        assert_eq!(host.kernel_path, Path::new("/k"), "derefs to the spec");
    }

    /// #3124: a spec may not write the guest command line. Main accepted each of these. Each is now
    /// refused at create, before anything is spawned, with a message that names the token.
    #[test]
    fn a_spec_that_writes_the_guest_command_line_is_refused_at_create() {
        for (args, token) in [
            ("init=/bin/sh", "init=/bin/sh"),
            (
                "NUCLEUS_TOOL_PROXY_POLICY=permissive",
                "NUCLEUS_TOOL_PROXY_POLICY=permissive",
            ),
            (
                "nucleus.net=10.9.9.2/30,gw=10.9.9.1",
                "nucleus.net=10.9.9.2/30,gw=10.9.9.1",
            ),
            ("ipv6.disable=0", "ipv6.disable=0"),
            (
                "quiet nucleus.approval_pubkeys=00",
                "nucleus.approval_pubkeys=00",
            ),
        ] {
            let s = spec(&format!(
                r#"{{"kernel_path":"/k","rootfs_path":"/r","boot_args":"{args}"}}"#
            ));
            let Err(ApiError::InvalidSpec(msg)) = admit(&s) else {
                panic!("`{args}` must be refused at create");
            };
            assert!(msg.contains(token), "{args}: {msg}");
            assert!(msg.contains("refused"), "{args}: {msg}");
            let Err(ApiError::InvalidSpec(_)) = HostImage::of_spec(&s) else {
                panic!("`{args}` must not resolve to a bootable image either");
            };
        }
    }

    #[test]
    fn an_allowlisted_token_is_admitted_and_carried_parsed() {
        let s = spec(r#"{"kernel_path":"/k","rootfs_path":"/r","boot_args":"quiet loglevel=3"}"#);
        assert!(admit(&s).is_ok());
        let host = HostImage::of_spec(&s).expect("allowlisted tokens resolve");
        assert_eq!(host.spec_boot_args().tokens().len(), 2);
    }

    #[test]
    fn a_pod_without_an_image_is_admitted_but_does_not_resolve() {
        let s: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                .expect("parses");
        assert!(admit(&s).is_ok(), "no image, no rootfs to refuse");
        let Err(ApiError::Driver(msg)) = HostImage::of_spec(&s) else {
            panic!("the launch path still needs an image");
        };
        assert_eq!(msg, "missing spec.image");
    }
}
