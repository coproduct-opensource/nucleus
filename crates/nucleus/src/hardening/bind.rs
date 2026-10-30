//! The workload's read-only workspace bind (`WorkloadSpec::workspace_bind`).
//!
//! Some builds embed the absolute path of their sources, so their bytes equal
//! a pinned digest only when the sources sit at the canonical builder's path.
//! nucleus's verifier SDK is one: its wasm embeds source paths, and
//! `embedded-wasm.pins` holds the bytes of a build at `/data/work/nucleus/nucleus`.
//! In a guest that path is a directory of the read-only image, and a confined
//! workload may not mount (its seccomp filter denies `unshare` and `mount`).
//!
//! So the launcher does it. Still root, in the private mount namespace it
//! already creates for the workload's PID namespace (`pidns.rs`), the init
//! binds the checked `source` over the checked `target` and remounts the bind
//! read-only, `nosuid`, `nodev` and `noexec`, before it forks the workload.
//! The runtime's own namespace never sees the bind: the init made its mount
//! tree private first.
//!
//! Everything is decided here, in the parent, by [`WorkspaceBind::compile`].
//! The forked init only reads the two NUL-terminated buffers this holds: no
//! allocation, formatting or path walk after the fork.
//!
//! What the bind does not do: grant a write or an exec. The bytes it shows are
//! already readable by the workload under its work dir; the bind is read-only;
//! and the workload's Landlock ruleset decides access by walking the path it
//! uses, so through the bind it gets what the image directory above `target`
//! grants, which is read.

use std::path::{Component, Path, PathBuf};

use nucleus_spec::guest_layout;

/// The longest path either side may have, NUL included. Both paths are short
/// in practice (`/work/src`, `/data/work/nucleus/nucleus`); a cap keeps the
/// buffers in the `Copy` value the hook carries.
const PATH_CAP: usize = 256;

/// A bind [`compile`](Self::compile) has checked, ready for the forked init.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceBind {
    source: [u8; PATH_CAP],
    source_len: usize,
    target: [u8; PATH_CAP],
    target_len: usize,
}

/// Why a requested bind was refused, in words an operator can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRefused(pub String);

impl std::fmt::Display for BindRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "workspace bind refused: {}", self.0)
    }
}

impl std::error::Error for BindRefused {}

fn refused<T>(why: impl Into<String>) -> Result<T, BindRefused> {
    Err(BindRefused(why.into()))
}

/// Whether `path` is spelled as plain names under the root (`absolute`) or
/// relative to a base: no `.`, no `..`, no doubled or trailing separator.
fn plain(path: &str, absolute: bool) -> bool {
    let p = Path::new(path);
    let mut rebuilt = PathBuf::new();
    for (i, c) in p.components().enumerate() {
        match c {
            Component::RootDir if i == 0 && absolute => rebuilt.push("/"),
            Component::Normal(_) => rebuilt.push(c),
            Component::RootDir
            | Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_) => {
                return false;
            }
        }
    }
    !path.is_empty()
        && !path.contains('\0')
        && p.is_absolute() == absolute
        && rebuilt.as_os_str() == p.as_os_str()
}

fn buffer(path: &Path, side: &str) -> Result<([u8; PATH_CAP], usize), BindRefused> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() >= PATH_CAP {
        return refused(format!(
            "the {side} {} is longer than {} bytes",
            path.display(),
            PATH_CAP - 1
        ));
    }
    let mut out = [0_u8; PATH_CAP];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok((out, bytes.len()))
}

/// Whether the filesystem holding `path` is mounted read-only.
#[cfg(target_os = "linux")]
fn read_only_filesystem(path: &Path) -> std::io::Result<bool> {
    let stat = rustix::fs::statvfs(path)?;
    Ok(stat.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY))
}

/// Only a guest binds, and a guest is Linux: anywhere else every target reads
/// as writable, so every bind is refused.
#[cfg(not(target_os = "linux"))]
fn read_only_filesystem(_: &Path) -> std::io::Result<bool> {
    Ok(false)
}

impl WorkspaceBind {
    /// Check a requested bind of `source` (relative to `work_dir`) over
    /// `target`, under the guest layer's [`guest_layout::WORKSPACE_BIND_ROOT`].
    ///
    /// # Errors
    /// [`BindRefused`], naming the first rule the request breaks.
    pub fn compile(work_dir: &Path, source: &str, target: &str) -> Result<Self, BindRefused> {
        Self::compile_under(
            work_dir,
            source,
            target,
            Path::new(guest_layout::WORKSPACE_BIND_ROOT),
            read_only_filesystem,
        )
    }

    /// [`compile`](Self::compile) with the root and the read-only test as
    /// inputs, so each refusal can be driven on a host whose `/data/work`
    /// does not exist and whose temp dirs are writable.
    pub(crate) fn compile_under(
        work_dir: &Path,
        source: &str,
        target: &str,
        root: &Path,
        read_only: impl Fn(&Path) -> std::io::Result<bool>,
    ) -> Result<Self, BindRefused> {
        if !plain(source, false) {
            return refused(format!(
                "the source {source:?} must be a relative path of plain names inside the work dir"
            ));
        }
        let work = std::fs::canonicalize(work_dir).or_else(|e| {
            refused(format!(
                "the work dir {} cannot be resolved: {e}",
                work_dir.display()
            ))
        })?;
        let wanted = work.join(source);
        let resolved = std::fs::canonicalize(&wanted).or_else(|e| {
            refused(format!(
                "the source {} does not exist: {e}",
                wanted.display()
            ))
        })?;
        if resolved != wanted {
            return refused(format!(
                "the source {} resolves to {}: a symlink on the way could leave the work dir",
                wanted.display(),
                resolved.display()
            ));
        }
        if !resolved.is_dir() {
            return refused(format!(
                "the source {} is not a directory",
                resolved.display()
            ));
        }

        if !plain(target, true) {
            return refused(format!(
                "the target {target:?} must be an absolute path of plain names"
            ));
        }
        let target_path = Path::new(target);
        if !target_path.starts_with(root) || target_path == root {
            return refused(format!(
                "the target {target} is not strictly under {}",
                root.display()
            ));
        }
        match std::fs::symlink_metadata(target_path) {
            Err(e) => return refused(format!("the target {target} does not exist: {e}")),
            Ok(m) if m.file_type().is_symlink() => {
                return refused(format!("the target {target} is a symlink"));
            }
            Ok(m) if !m.is_dir() => {
                return refused(format!("the target {target} is not a directory"));
            }
            Ok(_) => {}
        }
        match std::fs::canonicalize(target_path) {
            Ok(c) if c == target_path => {}
            Ok(c) => {
                return refused(format!(
                    "the target {target} resolves to {}: a symlink on the way",
                    c.display()
                ));
            }
            Err(e) => return refused(format!("the target {target} cannot be resolved: {e}")),
        }
        let mut entries = std::fs::read_dir(target_path)
            .or_else(|e| refused(format!("the target {target} cannot be listed: {e}")))?;
        if entries.next().is_some() {
            return refused(format!(
                "the target {target} is not empty, and a bind would hide what is in it"
            ));
        }
        match read_only(target_path) {
            Ok(true) => {}
            Ok(false) => {
                return refused(format!(
                    "the target {target} is on a writable filesystem, so its emptiness could \
                     change before the launch"
                ));
            }
            Err(e) => return refused(format!("the target {target} cannot be examined: {e}")),
        }
        if target_path.starts_with(&resolved) || resolved.starts_with(target_path) {
            return refused(format!(
                "the source {} and the target {target} overlap",
                resolved.display()
            ));
        }
        let (source_buf, source_len) = buffer(&resolved, "source")?;
        let (target_buf, target_len) = buffer(target_path, "target")?;
        Ok(Self {
            source: source_buf,
            source_len,
            target: target_buf,
            target_len,
        })
    }

    /// The resolved absolute source.
    #[must_use]
    pub fn source(&self) -> &str {
        std::str::from_utf8(&self.source[..self.source_len]).unwrap_or("?")
    }

    /// The target, as the workload sees the bind.
    #[must_use]
    pub fn target(&self) -> &str {
        std::str::from_utf8(&self.target[..self.target_len]).unwrap_or("?")
    }

    /// The spelling a launch receipt's preimage carries.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!("{}:{}:ro", self.source(), self.target())
    }

    /// NUL-terminated source, for the forked init.
    #[cfg(target_os = "linux")]
    pub(super) fn source_ptr(&self) -> *const libc::c_char {
        self.source.as_ptr().cast()
    }

    /// NUL-terminated target, for the forked init.
    #[cfg(target_os = "linux")]
    pub(super) fn target_ptr(&self) -> *const libc::c_char {
        self.target.as_ptr().cast()
    }
}

impl std::fmt::Debug for WorkspaceBind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceBind")
            .field("source", &self.source())
            .field("target", &self.target())
            .finish()
    }
}

impl serde::Serialize for WorkspaceBind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("WorkspaceBind", 3)?;
        st.serialize_field("source", self.source())?;
        st.serialize_field("target", self.target())?;
        st.serialize_field("read_only", &true)?;
        st.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A work dir with `src/marker`, and an image root with an empty `ws`.
    struct Fixture {
        _dir: tempfile::TempDir,
        work: PathBuf,
        root: PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let work = base.join("work");
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(work.join("src/marker"), b"m").unwrap();
        let root = base.join("data-work");
        std::fs::create_dir_all(root.join("owner/ws")).unwrap();
        Fixture {
            _dir: dir,
            work,
            root,
        }
    }

    fn ro(_: &Path) -> std::io::Result<bool> {
        Ok(true)
    }

    fn compile(f: &Fixture, source: &str, target: &Path) -> Result<WorkspaceBind, BindRefused> {
        WorkspaceBind::compile_under(&f.work, source, target.to_str().unwrap(), &f.root, ro)
    }

    #[test]
    fn a_relative_source_onto_an_empty_read_only_image_directory_compiles() {
        let f = fixture();
        let target = f.root.join("owner/ws");
        let bind = compile(&f, "src", &target).unwrap();
        assert_eq!(bind.source(), f.work.join("src").to_str().unwrap());
        assert_eq!(bind.target(), target.to_str().unwrap());
        assert_eq!(bind.source.get(bind.source_len), Some(&0));
        assert_eq!(bind.target.get(bind.target_len), Some(&0));
        assert!(bind.canonical().ends_with(":ro"));
    }

    /// Why `compile` need not ask the guest layer about each target: the root
    /// is the image's, and nothing the guest layer reserves lies at or under it.
    #[test]
    fn nothing_the_guest_layer_reserves_is_at_or_under_the_bind_root() {
        let root = guest_layout::WORKSPACE_BIND_ROOT;
        assert!(guest_layout::reserved_by(root).is_none());
        assert!(guest_layout::reserved_at(root).is_none());
        for r in guest_layout::RESERVED {
            let p = Path::new(r.path.trim_end_matches('/'));
            assert!(
                !p.starts_with(root),
                "{} is reserved under the bind root",
                r.path
            );
            assert!(
                !Path::new(root).starts_with(p) || p == Path::new("/"),
                "the bind root lies under reserved {}",
                r.path
            );
        }
    }

    #[test]
    fn a_missing_target_is_refused() {
        let f = fixture();
        let e = compile(&f, "src", &f.root.join("owner/absent")).unwrap_err();
        assert!(e.0.contains("does not exist"), "{e}");
    }

    #[test]
    fn a_non_empty_target_is_refused() {
        let f = fixture();
        let target = f.root.join("owner/ws");
        std::fs::write(target.join("left-behind"), b"x").unwrap();
        let e = compile(&f, "src", &target).unwrap_err();
        assert!(e.0.contains("is not empty"), "{e}");
    }

    #[test]
    fn a_target_outside_the_root_or_at_it_is_refused() {
        let f = fixture();
        let outside = f.work.parent().unwrap().join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        for target in [outside, f.root.clone()] {
            let e = compile(&f, "src", &target).unwrap_err();
            assert!(e.0.contains("not strictly under"), "{e}");
        }
        // The production root: a guest path outside /data/work, reserved or not.
        for target in ["/work/x", "/run/x", "/etc/nucleus/x", "/data/workx/y"] {
            let e = WorkspaceBind::compile_under(
                &f.work,
                "src",
                target,
                Path::new(guest_layout::WORKSPACE_BIND_ROOT),
                ro,
            )
            .unwrap_err();
            assert!(e.0.contains("not strictly under"), "{target}: {e}");
        }
    }

    #[test]
    fn a_target_on_a_writable_filesystem_is_refused() {
        let f = fixture();
        let e = WorkspaceBind::compile_under(
            &f.work,
            "src",
            f.root.join("owner/ws").to_str().unwrap(),
            &f.root,
            |_| Ok(false),
        )
        .unwrap_err();
        assert!(e.0.contains("writable filesystem"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_target_is_refused() {
        let f = fixture();
        let link = f.root.join("owner/link");
        std::os::unix::fs::symlink(f.root.join("owner/ws"), &link).unwrap();
        let e = compile(&f, "src", &link).unwrap_err();
        assert!(e.0.contains("is a symlink"), "{e}");
        std::os::unix::fs::symlink(f.root.join("owner"), f.root.join("alias")).unwrap();
        let e = compile(&f, "src", &f.root.join("alias/ws")).unwrap_err();
        assert!(e.0.contains("a symlink on the way"), "{e}");
    }

    #[test]
    fn a_source_outside_the_work_dir_is_refused() {
        let f = fixture();
        let target = f.root.join("owner/ws");
        let outside = f.work.parent().unwrap().to_str().unwrap().to_owned();
        for source in [
            "../src",
            "/etc",
            outside.as_str(),
            "./src",
            "src/../src",
            "",
        ] {
            let e = compile(&f, source, &target).unwrap_err();
            assert!(
                e.0.contains("relative path of plain names"),
                "{source:?}: {e}"
            );
        }
        let e = compile(&f, "absent", &target).unwrap_err();
        assert!(e.0.contains("does not exist"), "{e}");
        let e = compile(&f, "src/marker", &target).unwrap_err();
        assert!(e.0.contains("is not a directory"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn a_source_that_leaves_the_work_dir_through_a_symlink_is_refused() {
        let f = fixture();
        std::os::unix::fs::symlink(f.root.join("owner"), f.work.join("escape")).unwrap();
        let e = compile(&f, "escape", &f.root.join("owner/ws")).unwrap_err();
        assert!(
            e.0.contains("a symlink on the way could leave the work dir"),
            "{e}"
        );
    }

    #[test]
    fn overlapping_source_and_target_are_refused() {
        let f = fixture();
        // A work dir under the root, so the target lies inside the source.
        let work = f.root.join("owner/ws-parent");
        std::fs::create_dir_all(work.join("src/inner")).unwrap();
        let e = WorkspaceBind::compile_under(
            &work,
            "src",
            work.join("src/inner").to_str().unwrap(),
            &f.root,
            ro,
        )
        .unwrap_err();
        assert!(e.0.contains("overlap"), "{e}");
    }
}
