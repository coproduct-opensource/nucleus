//! The rootfs a pod boots, resolved once (2026-09-29; image store 2026-09-30).
//!
//! `ImageSpec::rootfs` is a `RootfsSource`: a file on the node, or an OCI image in the node's
//! image store. Rather than have every consumer — jail placement, drive lowering, pin
//! verification, attestation — match on the source and invent its own reading of it (ADR 0007
//! G), admission (`host_paths::admit`) resolves the source ONCE into an
//! [`AdmittedImage`](crate::host_paths::AdmittedImage), and the launch path turns that into a
//! [`HostImage`], which every consumer takes. A `HostImage` has a rootfs file by construction,
//! so none of them has an OCI case to get wrong (C: the evidence is minted by the checker, and
//! its fields are private).

use std::ops::Deref;
use std::path::{Path, PathBuf};

use nucleus_spec::ImageSpec;
#[cfg(any(target_os = "linux", test))]
use nucleus_spec::PodSpec;

#[cfg(any(target_os = "linux", test))]
use crate::ApiError;
#[cfg(any(target_os = "linux", test))]
use crate::host_paths::AdmittedImage;
use crate::host_paths::ImageProvenance;

/// An `ImageSpec` whose rootfs is a file on this host. Derefs to the spec for every other field.
///
/// No `DerefMut`: the one field a consumer may change after resolution is the scratch disk the
/// node provisions (#2789), and that has its own setter. Anything wider would let a resolved
/// image have its rootfs swapped out from under the path it was resolved to.
#[derive(Debug, Clone)]
pub(crate) struct HostImage {
    image: ImageSpec,
    rootfs: PathBuf,
    provenance: Option<ImageProvenance>,
}

impl HostImage {
    /// The image, with the rootfs admission resolved. Consumes the admission (C-4).
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn new(image: &ImageSpec, admitted: AdmittedImage) -> Self {
        let (rootfs, provenance) = admitted.into_parts();
        Self {
            image: image.clone(),
            rootfs,
            provenance,
        }
    }

    /// The pod's image, resolved. The missing-image message is the one the launch path always
    /// gave (`api_error.rs` pins how it renders). Admission returns an image for every spec
    /// that has one, so the two are absent together.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn of_spec(
        spec: &PodSpec,
        admitted: Option<AdmittedImage>,
    ) -> Result<Self, ApiError> {
        match (spec.spec.image.as_ref(), admitted) {
            (Some(image), Some(admitted)) => Ok(Self::new(image, admitted)),
            (None, _) => Err(ApiError::Driver("missing spec.image".to_string())),
            (Some(_), None) => Err(ApiError::Driver(
                "spec.image was not admitted; refusing to boot an unresolved rootfs".to_string(),
            )),
        }
    }

    /// Test shorthand: a path rootfs, taken as written.
    #[cfg(test)]
    pub(crate) fn resolve(image: &ImageSpec) -> Result<Self, ApiError> {
        Ok(Self::new(image, AdmittedImage::for_test(image)))
    }

    /// The rootfs file that will boot.
    pub(crate) fn rootfs_path(&self) -> &Path {
        &self.rootfs
    }

    /// Where an OCI rootfs came from; `None` for a path rootfs.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn provenance(&self) -> Option<&ImageProvenance> {
        self.provenance.as_ref()
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

    #[test]
    fn a_path_rootfs_resolves_to_its_admitted_path() {
        let s = spec(r#"{"kernel_path":"/k","rootfs_path":"/r"}"#);
        let image = s.spec.image.as_ref().expect("image");
        let host = HostImage::of_spec(&s, Some(AdmittedImage::for_test(image)))
            .expect("a path rootfs resolves");
        assert_eq!(host.rootfs_path(), Path::new("/r"));
        assert_eq!(host.kernel_path, Path::new("/k"), "derefs to the spec");
        assert!(host.provenance().is_none());
    }

    #[test]
    fn an_unadmitted_image_does_not_resolve() {
        let s = spec(r#"{"kernel_path":"/k","rootfs_path":"/r"}"#);
        let Err(ApiError::Driver(msg)) = HostImage::of_spec(&s, None) else {
            panic!("an image admission did not resolve must not boot");
        };
        assert!(msg.contains("not admitted"), "{msg}");
    }

    #[test]
    fn a_pod_without_an_image_does_not_resolve() {
        let s: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                .expect("parses");
        let Err(ApiError::Driver(msg)) = HostImage::of_spec(&s, None) else {
            panic!("the launch path still needs an image");
        };
        assert_eq!(msg, "missing spec.image");
    }
}
