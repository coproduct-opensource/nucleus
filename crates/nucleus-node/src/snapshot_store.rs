//! Where a base snapshot lives, and what it is called.
//!
//! [`crate::snapshot`] decides whether a microVM may be a base and [`crate::snapshot_vmm`] does
//! the taking. Neither answers the question that makes a snapshot *reusable*: what is this a
//! snapshot OF, such that a later pod can ask for the same thing and get it?
//!
//! # The name is the answer, and it is a digest
//!
//! A base is named by a [`Derivation`] — the program it booted, plus everything about the machine
//! that has to be true again for restoring it to mean anything. Two nodes that agree on all of it
//! compute the same name without talking to each other, which is what makes the store a cache
//! rather than a registry.
//!
//! # Write-once falls out of the filesystem
//!
//! Files are written under `incoming/<uuid>/`, fsynced, and then `rename()`d onto
//! `by-derivation/<name>/`. `rename` onto a non-empty directory fails `ENOTEMPTY` — so the
//! "already published" check is not a check at all, it is the kernel refusing, and there is no
//! window between looking and acting for a second node to land in. Readers only ever see
//! directories that were complete before they had a name.
//!
//! # Why the host check is a refusal and not a name component
//!
//! Restoring a snapshot onto a different CPU produces a guest that runs fine and then dies on an
//! unexpected instruction some minutes later, because there are no CPU templates here yet. That
//! has to be prevented, and there are two ways: fold the host into the name, or record it and
//! refuse.
//!
//! Folding it in makes a foreign host MISS — it would quietly rebuild, and on a shared store the
//! symptom is a cache that never warms with nobody able to say why. Recording it makes a foreign
//! host [`Lookup::ForeignHost`], which names both machines. Same safety, and one of them can be
//! diagnosed. The same argument gatehouse's `Lookup` makes: an `Option` cannot say why it is
//! empty, so it should not be the return type of a question that has more than one no.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::snapshot_vmm::SnapshotArtifacts;

/// Domain separator, versioned so a later change of shape cannot be read as this one.
const DERIVATION_DOMAIN: &[u8] = b"nucleus.snapshot-derivation.v1\n";

/// The vsock barrier protocol this node speaks.
///
/// In the derivation because a base is only restorable by a host that can talk to the guest it
/// froze: bump this when `SnapshotReady`'s meaning changes, and every existing base stops being
/// offered to code that would misread it.
pub(crate) const BARRIER_PROTOCOL: u32 = 1;

/// The machine, as far as a restored guest can tell.
///
/// `cpu_model` is deliberately a raw vendor string rather than something parsed. It is compared
/// for equality and never interpreted, so parsing it would only add ways to be wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HostIdentity {
    pub arch: String,
    pub cpu_model: String,
}

impl HostIdentity {
    /// What this host is, read from the kernel.
    ///
    /// Falls back to `unknown` rather than failing: a host that cannot describe itself must still
    /// be able to *refuse*, and an `unknown` never equals another host's real answer — so the
    /// failure mode is "restores nothing", which is the safe direction.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn detect() -> Self {
        Self {
            arch: std::env::consts::ARCH.to_string(),
            cpu_model: cpu_model().unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

/// The most specific CPU identification `/proc/cpuinfo` offers on this architecture.
fn cpu_model() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    // x86 gives one "model name"; aarch64 gives implementer/part/variant/revision and no model
    // name at all, so both shapes have to be handled or every arm host is "unknown".
    let mut parts: Vec<String> = Vec::new();
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "model name" => return Some(v.to_string()),
            "CPU implementer" | "CPU part" | "CPU variant" => parts.push(format!("{k}={v}")),
            _ => {}
        }
        // One core's worth is the whole answer; the rest of the file repeats it.
        if parts.len() == 3 {
            break;
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Everything that has to hold again for a restore to mean what the snapshot meant.
///
/// Note what is NOT here: tap device name, guest MAC, vsock UDS path, guest CID, pod id. Those
/// are patched between load and resume — a base that included them would be a base of exactly
/// one pod, which is the opposite of the point. `a_derivation_names_the_program_not_the_pod`
/// asserts their absence from the preimage directly rather than trusting this comment.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Derivation {
    /// `nucleus_spec::identity::program_digest` — what the guest computes.
    pub program: String,
    /// The VMM that took it, as OBSERVED. Not `vmm_version::PINNED`: a node may legitimately run
    /// a different acceptable version, and a snapshot restored by a VMM that did not write it is
    /// exactly the drift this field exists to stop.
    pub vmm_version: String,
    /// Guest architecture.
    pub arch: String,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub smt: bool,
    pub cpu_template: Option<String>,
    pub barrier_protocol: u32,
}

impl Derivation {
    /// The content address of this base.
    pub fn name(&self) -> String {
        let canonical = serde_json_canonicalizer::to_vec(self)
            .expect("a derivation is plain data and always serializes");
        let mut h = Sha256::new();
        h.update(DERIVATION_DOMAIN);
        h.update(&canonical);
        hex::encode(h.finalize())
    }
}

/// What the snapshot path needs from a pod, captured at launch.
///
/// Captured rather than recomputed, and that is the whole point: the derivation has to name the
/// machine this microVM ACTUALLY booted on. Re-deriving it later from the spec would reintroduce
/// exactly the gap `sandbox.substrate` had in gatehouse — a field describing a run, filled in from
/// something other than the run.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct SnapshotInputs {
    /// The kernel command line as booted. Scanned for per-pod material by `clone_safety`.
    pub boot_args: String,
    /// The VMM that booted it, observed at preflight — not the pinned constant.
    pub vmm_version: String,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub smt: bool,
    /// Whether a writable scratch disk is attached, which refuses a snapshot outright: clones
    /// either share one writable file or get a fresh one their cached ext4 state does not
    /// describe. Both are filesystem corruption.
    pub writable_scratch: bool,
}

impl SnapshotInputs {
    /// The derivation for a base taken from this pod.
    pub fn derivation(&self, program: String) -> Derivation {
        Derivation {
            program,
            vmm_version: self.vmm_version.clone(),
            arch: std::env::consts::ARCH.to_string(),
            vcpu_count: self.vcpu_count,
            mem_size_mib: self.mem_size_mib,
            smt: self.smt,
            // Always `None` today: nothing sets a CPU template. It is in the derivation ANYWAY,
            // because the alternative is adding it later and having names computed without a
            // template collide with names computed with `None` — a silent cross-CPU reuse, which
            // is the one failure this whole type exists to prevent.
            cpu_template: None,
            barrier_protocol: BARRIER_PROTOCOL,
        }
    }
}

/// What a published base records about itself.
///
/// Written in the clear beside the snapshot so a human looking at a directory of 64-hex names can
/// answer "why is this one here" without a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub derivation: String,
    pub program: String,
    pub vmm_version: String,
    pub arch: String,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub smt: bool,
    pub cpu_template: Option<String>,
    pub barrier_protocol: u32,
    /// The machine that took it. Compared on lookup; see the module docs.
    pub host: HostIdentity,
    pub created_unix: u64,
    pub mem_bytes: u64,
    /// Host hardening properties that were NOT satisfied when this base was taken.
    ///
    /// Recorded, not enforced. Nothing shares memory across pods yet, so refusing to take a base
    /// on an unhardened host would block the only thing that works today for a risk that does not
    /// exist yet. But the properties are a fact ABOUT THIS ARTIFACT and cannot be recovered later
    /// — the host may be hardened tomorrow, and the base would then look safer than it was.
    ///
    /// So it travels with the base. A future sharing decision reads evidence rather than assuming,
    /// which is the `confinement.rs` discipline applied to the thing being shared: an empty list
    /// is a measurement, and a base taken before this field existed has no measurement at all,
    /// which `serde(default)` makes visibly different from a clean one only if you know to look —
    /// hence it is written on every publish from here on.
    #[serde(default)]
    pub unmet_hardening: Vec<String>,
}

/// The answer to "is there a base for this derivation", which has more than one no.
///
/// Deliberately does NOT hand back the snapshot's file paths. Nothing restores from a base yet —
/// the launch path still cold-boots — and a lookup that returned artifacts would be a reader-less
/// field dressed as an API. When restore lands it adds the accessor and this comment goes away.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum Lookup {
    /// Present, complete, and taken by this host.
    Present(Box<Manifest>),
    /// Nothing at that name. Cold boot.
    Absent,
    /// Present, and refused: it was taken on a different machine.
    ForeignHost {
        taken_on: HostIdentity,
        running_on: HostIdentity,
    },
    /// Present and unreadable — a truncated manifest, a partial `rm`. Distinct from `Absent`
    /// because a cold boot is the right response to both while only this one is a problem.
    Damaged(String),
}

/// Why a base could not be published.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum PublishError {
    /// Another writer got there first. Not an error the caller has to handle as a failure — the
    /// base it wanted exists — but it is never silently swallowed here, because "my write did
    /// nothing" and "my write landed" are different facts and only the caller knows which matters.
    AlreadyPresent,
    Io(std::io::Error),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyPresent => write!(f, "a base for this derivation is already published"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// A directory of bases, keyed by derivation.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct SnapshotStore {
    root: PathBuf,
    host: HostIdentity,
}

/// A staging directory. Dropping one without publishing removes it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Incoming {
    dir: PathBuf,
    pub artifacts: SnapshotArtifacts,
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // A failed snapshot leaves a memory-image-sized file behind, and `mem` is `mem_size_mib`
        // every time. Sweeping on drop is what keeps a crash loop from filling the disk.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl SnapshotStore {
    pub fn new(root: PathBuf, host: HostIdentity) -> Self {
        Self { root, host }
    }

    /// Where a base with this name lives, published or not yet.
    pub fn published_dir(&self, name: &str) -> PathBuf {
        self.root.join("by-derivation").join(name)
    }

    /// Is there a base for this derivation that this host may restore?
    pub fn lookup(&self, derivation: &Derivation) -> Lookup {
        let dir = self.published_dir(&derivation.name());
        let raw = match std::fs::read_to_string(dir.join("manifest.json")) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Lookup::Absent,
            Err(e) => return Lookup::Damaged(e.to_string()),
        };
        let manifest: Manifest = match serde_json::from_str(&raw) {
            Ok(m) => m,
            Err(e) => return Lookup::Damaged(format!("manifest.json: {e}")),
        };
        if manifest.host != self.host {
            return Lookup::ForeignHost {
                taken_on: manifest.host,
                running_on: self.host.clone(),
            };
        }
        // Checked, not returned: a manifest that survived while its snapshot did not is the one
        // case where "present" would be a lie, and the caller should hear about it.
        if !dir.join("vmstate").is_file() || !dir.join("mem").is_file() {
            return Lookup::Damaged("manifest present but vmstate or mem is missing".into());
        }
        Lookup::Present(Box::new(manifest))
    }

    /// Open a staging directory to snapshot into.
    pub fn begin(&self) -> std::io::Result<Incoming> {
        let dir = self
            .root
            .join("incoming")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir)?;
        Ok(Incoming {
            artifacts: SnapshotArtifacts {
                vmstate: dir.join("vmstate"),
                mem: dir.join("mem"),
            },
            dir,
        })
    }

    /// Durably publish a staged snapshot under its derivation.
    ///
    /// # Errors
    ///
    /// [`PublishError::AlreadyPresent`] if another writer published this derivation first; the
    /// staged copy is discarded and the published one stands.
    pub fn publish(
        &self,
        incoming: Incoming,
        derivation: &Derivation,
        unmet_hardening: Vec<String>,
    ) -> Result<PathBuf, PublishError> {
        let mem_bytes = std::fs::metadata(&incoming.artifacts.mem)
            .map_err(PublishError::Io)?
            .len();
        let manifest = Manifest {
            derivation: derivation.name(),
            program: derivation.program.clone(),
            vmm_version: derivation.vmm_version.clone(),
            arch: derivation.arch.clone(),
            vcpu_count: derivation.vcpu_count,
            mem_size_mib: derivation.mem_size_mib,
            smt: derivation.smt,
            cpu_template: derivation.cpu_template.clone(),
            barrier_protocol: derivation.barrier_protocol,
            host: self.host.clone(),
            created_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            mem_bytes,
            unmet_hardening,
        };
        let body = serde_json::to_vec_pretty(&manifest).map_err(|e| PublishError::Io(e.into()))?;
        std::fs::write(incoming.dir.join("manifest.json"), &body).map_err(PublishError::Io)?;

        // Durability before visibility. Without these fsyncs a crash can leave a directory that
        // was renamed into place — so it looks complete, because that is the whole contract —
        // holding a memory image whose tail never reached the platter.
        for f in ["vmstate", "mem", "manifest.json"] {
            let path = incoming.dir.join(f);
            // World-readable, because restore hard-links these into a jail that runs as an
            // unprivileged uid. Permission travels with the INODE, so this is what lets the jailed
            // VMM open the link — and it is why placement does not chown, which would change the
            // shared base's ownership for every later pod. Read is the whole requirement: a
            // restored guest maps the memory file MAP_PRIVATE and never writes it, measured.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
            }
            fsync(&path).map_err(PublishError::Io)?;
        }
        fsync(&incoming.dir).map_err(PublishError::Io)?;

        let target = self.published_dir(&derivation.name());
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(PublishError::Io)?;
        }
        match std::fs::rename(&incoming.dir, &target) {
            Ok(()) => {}
            // ENOTEMPTY (or ENOTDIR/EEXIST, which platforms disagree about) means a complete base
            // is already there. The kernel did the check, so there was no moment between looking
            // and acting.
            Err(e) if target.join("manifest.json").is_file() => {
                tracing::debug!(error = %e, "a base for this derivation was published first");
                return Err(PublishError::AlreadyPresent);
            }
            Err(e) => return Err(PublishError::Io(e)),
        }
        // The rename itself has to be durable, or a crash loses the base while leaving nothing to
        // clean up — the staging directory is gone by then.
        if let Some(parent) = target.parent() {
            let _ = fsync(parent);
        }
        // The staging directory no longer exists; suppress the Drop that would try to remove it.
        std::mem::forget(incoming);
        Ok(target)
    }

    /// `publish` with no hardening findings, for tests that are not about the host.
    #[cfg(test)]
    fn publish_test(&self, incoming: Incoming, d: &Derivation) -> Result<PathBuf, PublishError> {
        self.publish(incoming, d, Vec::new())
    }

    /// Remove staging directories a previous process left behind.
    ///
    /// `Incoming::drop` handles the ordinary abandonment; what reaches here is what a crash or a
    /// SIGKILL left, and each one is a full guest memory image. Called immediately before staging
    /// a new snapshot — the moment about to consume `mem_size_mib` of disk is exactly the moment
    /// to reclaim what previous attempts stranded.
    ///
    /// Published bases are NOT swept. Deciding which base is still worth its disk is a retention
    /// policy, and there is no evidence yet to write one from — an arbitrary rule here would be a
    /// policy nobody chose, deleting artifacts that cost 480 ms each to rebuild.
    pub fn sweep_staging(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut removed = Vec::new();
        let dir = self.root.join("incoming");
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            std::fs::remove_dir_all(entry.path())?;
            removed.push(entry.path());
        }
        Ok(removed)
    }
}

/// fsync a file or directory by path.
fn fsync(path: &Path) -> std::io::Result<()> {
    // A directory has to be opened read-only; a file may be either. Read-only works for both,
    // which is why there is one helper rather than two.
    std::fs::File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostIdentity {
        HostIdentity {
            arch: "aarch64".into(),
            cpu_model: "CPU implementer=0x61 CPU part=0x000 CPU variant=0x0".into(),
        }
    }

    fn derivation() -> Derivation {
        Derivation {
            program: "a".repeat(64),
            vmm_version: "1.16.1".into(),
            arch: "aarch64".into(),
            vcpu_count: 1,
            mem_size_mib: 256,
            smt: false,
            cpu_template: None,
            barrier_protocol: BARRIER_PROTOCOL,
        }
    }

    /// Stage a base with recognisable contents.
    fn stage(store: &SnapshotStore, body: &str) -> Incoming {
        let inc = store.begin().expect("staging directory");
        std::fs::write(&inc.artifacts.vmstate, body).unwrap();
        std::fs::write(&inc.artifacts.mem, vec![0u8; 4096]).unwrap();
        inc
    }

    /// The exclusion, asserted against the bytes rather than against the comment.
    ///
    /// This is the test the plan asked for by name: for every field the restore path patches, the
    /// derivation must not contain it. Checking the canonical preimage for the literal values is
    /// stronger than comparing two names, because it fails even if some future field smuggles one
    /// in under a different key.
    #[test]
    fn a_derivation_names_the_program_not_the_pod() {
        let d = derivation();
        let preimage = String::from_utf8(serde_json_canonicalizer::to_vec(&d).unwrap()).unwrap();
        for per_pod in [
            "tap",         // the tap device, patched at restore
            "vsock",       // the UDS path, patched at restore
            "cid",         // the guest CID, allocated per launch
            "pod",         // the pod id / name
            "credentials", // never, anywhere near a shared artifact
            "jail",        // where this one VMM was chrooted
        ] {
            assert!(
                !preimage.contains(per_pod),
                "`{per_pod}` is patched or allocated per pod, so a base that named it would be a \
                 base of exactly one pod: {preimage}"
            );
        }
    }

    /// Every field in the derivation actually changes the name.
    ///
    /// The converse of the exclusions, and the one that matters more: a field folded in but not
    /// reaching the digest would let two genuinely different machines share a base.
    #[test]
    fn every_derivation_field_changes_the_name() {
        let base = derivation().name();
        let mut mutations: Vec<(&str, Derivation)> = Vec::new();
        for (what, f) in [
            (
                "program",
                (|d: &mut Derivation| d.program = "b".repeat(64)) as fn(&mut Derivation),
            ),
            ("vmm_version", |d| d.vmm_version = "1.17.0".into()),
            ("arch", |d| d.arch = "x86_64".into()),
            ("vcpu_count", |d| d.vcpu_count = 2),
            ("mem_size_mib", |d| d.mem_size_mib = 512),
            ("smt", |d| d.smt = true),
            ("cpu_template", |d| d.cpu_template = Some("T2".into())),
            ("barrier_protocol", |d| d.barrier_protocol = 99),
        ] {
            let mut d = derivation();
            f(&mut d);
            mutations.push((what, d));
        }
        for (what, d) in mutations {
            assert_ne!(
                base,
                d.name(),
                "{what} decides whether a restore is valid, so it must change the name"
            );
        }
    }

    /// A published base is found again, and it is the one that was written.
    #[test]
    fn what_is_published_is_what_is_looked_up() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(tmp.path().to_path_buf(), host());
        let d = derivation();

        assert!(
            matches!(store.lookup(&d), Lookup::Absent),
            "an empty store has nothing"
        );

        let dir = store
            .publish_test(stage(&store, "vmstate-bytes"), &d)
            .unwrap();

        let Lookup::Present(m) = store.lookup(&d) else {
            panic!("a published base must be found");
        };
        assert_eq!(m.derivation, d.name());
        assert_eq!(m.mem_bytes, 4096, "the manifest records the size");
        assert_eq!(
            std::fs::read_to_string(dir.join("vmstate")).unwrap(),
            "vmstate-bytes",
            "and the bytes that were staged are the bytes that were published"
        );
    }

    /// Publishing twice is refused by the kernel, and the first base is untouched.
    ///
    /// This is the write-once property, and it is tested through the real `rename` rather than
    /// through a check this code performs — because the check this code performs is the part that
    /// would have a race in it.
    #[test]
    fn a_second_publish_is_refused_and_does_not_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(tmp.path().to_path_buf(), host());
        let d = derivation();

        let first = store.publish_test(stage(&store, "first"), &d).unwrap();
        let again = store.publish_test(stage(&store, "second"), &d);
        assert!(
            matches!(again, Err(PublishError::AlreadyPresent)),
            "the second publish must be refused, got {again:?}"
        );

        assert!(
            matches!(store.lookup(&d), Lookup::Present(_)),
            "the first base must survive"
        );
        assert_eq!(
            std::fs::read_to_string(first.join("vmstate")).unwrap(),
            "first",
            "a refused publish must not have overwritten anything"
        );
    }

    /// A base taken on another machine is refused, and the refusal names both.
    #[test]
    fn a_base_from_another_host_is_refused_not_silently_missed() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = HostIdentity {
            arch: "aarch64".into(),
            cpu_model: "some other silicon".into(),
        };
        let d = derivation();
        SnapshotStore::new(tmp.path().to_path_buf(), elsewhere.clone())
            .publish_test(
                stage(
                    &SnapshotStore::new(tmp.path().to_path_buf(), elsewhere),
                    "x",
                ),
                &d,
            )
            .unwrap();

        let here = SnapshotStore::new(tmp.path().to_path_buf(), host());
        match here.lookup(&d) {
            Lookup::ForeignHost {
                taken_on,
                running_on,
            } => {
                assert_eq!(taken_on.cpu_model, "some other silicon");
                assert_eq!(running_on, host());
            }
            other => panic!(
                "restoring across hosts dies on an unexpected instruction minutes later, so it \
                 must be refused with both machines named, got {other:?}"
            ),
        }
    }

    /// A staged snapshot that is never published leaves nothing behind.
    #[test]
    fn an_abandoned_staging_directory_removes_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(tmp.path().to_path_buf(), host());
        let path = {
            let inc = stage(&store, "abandoned");
            inc.dir.clone()
        };
        assert!(
            !path.exists(),
            "a memory image is mem_size_mib every time; an abandoned one must not persist"
        );
    }

    /// Sweeping reclaims what a crash stranded, and touches no published base.
    ///
    /// The second half is the one that matters: a published base costs ~480 ms to rebuild, so a
    /// sweep that took one would be a retention policy nobody wrote.
    #[test]
    fn sweeping_takes_crashed_staging_and_leaves_published_bases() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(tmp.path().to_path_buf(), host());
        let d = derivation();
        store.publish_test(stage(&store, "keep"), &d).unwrap();
        // A staged directory that outlived its process, i.e. what a crash leaves.
        let orphan = store.begin().unwrap();
        let orphan_dir = orphan.dir.clone();
        std::mem::forget(orphan);

        let removed = store.sweep_staging().unwrap();

        assert_eq!(removed, vec![orphan_dir.clone()]);
        assert!(!orphan_dir.exists(), "a crashed writer's staging is swept");
        assert!(
            matches!(store.lookup(&d), Lookup::Present(_)),
            "a published base is not a sweep's business"
        );
    }

    /// A base whose files were partly removed reads as damaged, not as absent.
    #[test]
    fn a_partial_base_is_damaged_rather_than_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SnapshotStore::new(tmp.path().to_path_buf(), host());
        let d = derivation();
        let published = store.publish_test(stage(&store, "x"), &d).unwrap();
        std::fs::remove_file(published.join("mem")).unwrap();
        assert!(
            matches!(store.lookup(&d), Lookup::Damaged(_)),
            "a cold boot is right for both, but only one of them is a problem someone should see"
        );
    }
}
