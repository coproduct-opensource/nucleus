//! A directory as a normalized tar, every entry owned by one uid:gid.
//!
//! This is how a seeded workspace comes to be owned by the workload rather than
//! by whoever ran the seed. `mke2fs -d <dir>` copies host ownership verbatim and
//! `-E root_owner=` reaches only the root inode, so a root-staged tree seeded
//! that way can be read by the workload and not edited (the Apple-container
//! spike: `rm: cannot remove '/work/src/main.rs': Permission denied`). A tar
//! carries ownership per entry, so rewriting it here reaches every inode, and
//! mke2fs never looks at the host's.
//!
//! The same step removes the rest of the host from the image: entries are
//! sorted by name bytes (a parent before its children), every mtime is
//! [`super::FIXED_EPOCH`], and no user name, group name or pax record is
//! written. Two seeds of the same tree from two checkouts, made at two times,
//! produce the same tar and therefore the same image.
//!
//! TODO(OCI-E): `nucleus-oci-rootfs` (#3079) emits a tar under the same
//! normalization for an OCI image, and one emitter should serve both so the
//! normalization has one definition (G-1). Not a drop-in swap: its
//! `write_tree` holds every file's bytes in memory, stamps mtime 0 rather than
//! [`super::FIXED_EPOCH`], and its `AuthoredTree` fixes the owner at `0:0`,
//! has no symlinks and refuses setuid/setgid/sticky, all of which a workspace
//! seed needs. The fold is that writer gaining a streamed-file input, an owner
//! and a symlink, with this module's digests pinned across the change.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use tar::{EntryType, Header};

use super::{Ext4Error, FIXED_EPOCH, RootOwner};

/// What one entry of the tree is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File { size: u64 },
    Symlink { target: PathBuf },
}

/// One entry, by its path relative to the tree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) rel: PathBuf,
    pub(crate) kind: Kind,
    /// Permission bits, including setuid/setgid/sticky, and nothing else.
    pub(crate) mode: u32,
}

/// Every entry under `tree` (not `tree` itself), sorted so a parent precedes
/// its children and siblings are in name-byte order.
///
/// A FIFO, socket or device has no place in a workspace, and dropping one
/// silently would make the image differ from the tree without saying so; each
/// is refused by path.
pub(crate) fn walk(tree: &Path) -> Result<Vec<Entry>, Ext4Error> {
    let mut out = Vec::new();
    walk_into(tree, Path::new(""), &mut out)?;
    Ok(out)
}

fn walk_into(root: &Path, rel: &Path, out: &mut Vec<Entry>) -> Result<(), Ext4Error> {
    let dir = root.join(rel);
    let io = |e: io::Error| Ext4Error::Io(format!("reading {}: {e}", dir.display()));
    let mut names: Vec<OsString> = std::fs::read_dir(&dir)
        .map_err(io)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<Result<_, _>>()
        .map_err(io)?;
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for name in names {
        let rel = rel.join(&name);
        let path = root.join(&rel);
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| Ext4Error::Io(format!("stat {}: {e}", path.display())))?;
        let mode = meta.permissions().mode() & 0o7777;
        let ft = meta.file_type();
        let kind = if ft.is_dir() {
            Kind::Dir
        } else if ft.is_file() {
            Kind::File { size: meta.len() }
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&path)
                .map_err(|e| Ext4Error::Io(format!("readlink {}: {e}", path.display())))?;
            Kind::Symlink { target }
        } else {
            return Err(Ext4Error::Unrepresentable {
                path,
                what: "not a directory, regular file or symlink".to_string(),
            });
        };
        let is_dir = kind == Kind::Dir;
        out.push(Entry {
            rel: rel.clone(),
            kind,
            mode,
        });
        if is_dir {
            walk_into(root, &rel, out)?;
        }
    }
    Ok(())
}

/// Write `entries` (from [`walk`] of `tree`) as a tar to `out`, every entry
/// owned by `owner`, and return the tar's sha256.
///
/// A file whose length changed between [`walk`] and now is refused: the header
/// already promised a size, and writing fewer bytes would shift every entry
/// after it.
pub(crate) fn emit<W: Write>(
    tree: &Path,
    entries: &[Entry],
    owner: RootOwner,
    out: W,
) -> Result<[u8; 32], Ext4Error> {
    let emit_err = |e: io::Error| Ext4Error::Io(format!("writing the seed tar: {e}"));
    let mut builder = tar::Builder::new(Hashing {
        inner: out,
        hash: Sha256::new(),
    });
    for entry in entries {
        let mut header = Header::new_gnu();
        header.set_mode(entry.mode);
        header.set_uid(u64::from(owner.uid));
        header.set_gid(u64::from(owner.gid));
        header.set_mtime(FIXED_EPOCH);
        header.set_size(0);
        match &entry.kind {
            Kind::Dir => {
                header.set_entry_type(EntryType::Directory);
                builder
                    .append_data(&mut header, &entry.rel, io::empty())
                    .map_err(emit_err)?;
            }
            Kind::Symlink { target } => {
                header.set_entry_type(EntryType::Symlink);
                builder
                    .append_link(&mut header, &entry.rel, target)
                    .map_err(emit_err)?;
            }
            Kind::File { size } => {
                let path = tree.join(&entry.rel);
                let file = std::fs::File::open(&path)
                    .map_err(|e| Ext4Error::Io(format!("opening {}: {e}", path.display())))?;
                let now = file
                    .metadata()
                    .map_err(|e| Ext4Error::Io(format!("stat {}: {e}", path.display())))?
                    .len();
                if now != *size {
                    return Err(Ext4Error::Io(format!(
                        "{} changed size while seeding ({size} bytes, now {now})",
                        path.display()
                    )));
                }
                header.set_entry_type(EntryType::Regular);
                header.set_size(*size);
                let exact = Exact {
                    inner: file.take(*size),
                    left: *size,
                };
                builder
                    .append_data(&mut header, &entry.rel, exact)
                    .map_err(|e| {
                        Ext4Error::Io(format!("{} while seeding it: {e}", path.display()))
                    })?;
            }
        }
    }
    let hashing = builder.into_inner().map_err(emit_err)?;
    let Hashing { mut inner, hash } = hashing;
    inner.flush().map_err(emit_err)?;
    Ok(hash.finalize().into())
}

/// A writer that hashes what passes through it.
struct Hashing<W> {
    inner: W,
    hash: Sha256,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hash.update(buf.get(..n).unwrap_or_default());
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A reader that is an error, not a short read, if it ends before `left`.
///
/// `tar::Builder` pads to the bytes it actually copied, not to the size in the
/// header, so a file that shrank mid-seed would otherwise yield a well-formed
/// looking tar with every later entry misaligned.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && self.left > 0 && !buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("the file shrank; {} promised bytes are missing", self.left),
            ));
        }
        self.left = self
            .left
            .saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: RootOwner = RootOwner {
        uid: 65534,
        gid: 65534,
    };

    #[test]
    fn walk_sorts_by_name_bytes_with_parents_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let t = dir.path();
        std::fs::create_dir_all(t.join("b/z")).expect("dirs");
        std::fs::write(t.join("a"), b"x").expect("file");
        std::fs::write(t.join("b/z/f"), b"y").expect("file");
        std::fs::write(t.join("Z"), b"y").expect("file");
        std::os::unix::fs::symlink("b/z/f", t.join("c")).expect("symlink");
        let rels: Vec<_> = walk(t)
            .expect("walk")
            .into_iter()
            .map(|e| e.rel.display().to_string())
            .collect();
        assert_eq!(rels, ["Z", "a", "b", "b/z", "b/z/f", "c"]);
    }

    #[test]
    fn a_fifo_is_refused_by_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success());
        match walk(dir.path()) {
            Err(Ext4Error::Unrepresentable { path, .. }) => assert_eq!(path, fifo),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_tar_is_the_same_from_two_checkouts_at_two_times() {
        let one = tempfile::tempdir().expect("tempdir");
        let two = tempfile::tempdir().expect("tempdir");
        for (i, root) in [one.path(), two.path()].into_iter().enumerate() {
            std::fs::create_dir_all(root.join("src")).expect("dirs");
            std::fs::write(root.join("src/lib.rs"), b"pub fn f() {}\n").expect("file");
            if i == 1 {
                // A different mtime on the second copy.
                std::thread::sleep(std::time::Duration::from_millis(1100));
                std::fs::write(root.join("src/lib.rs"), b"pub fn f() {}\n").expect("file");
            }
        }
        let tar = |root: &Path| {
            let mut bytes = Vec::new();
            let digest = emit(root, &walk(root).expect("walk"), OWNER, &mut bytes).expect("emit");
            (digest, bytes)
        };
        let (d1, b1) = tar(one.path());
        let (d2, b2) = tar(two.path());
        assert_eq!(b1, b2);
        assert_eq!(d1, d2);
        let direct: [u8; 32] = Sha256::digest(&b1).into();
        assert_eq!(d1, direct, "the returned digest is of the bytes written");

        // Ownership is rewritten on every entry, not just the root.
        let mut archive = tar::Archive::new(b1.as_slice());
        let mut seen = 0;
        for entry in archive.entries().expect("entries") {
            let header = entry.expect("entry").header().clone();
            assert_eq!(header.uid().expect("uid"), 65534);
            assert_eq!(header.gid().expect("gid"), 65534);
            assert_eq!(header.mtime().expect("mtime"), FIXED_EPOCH);
            seen += 1;
        }
        assert_eq!(seen, 2, "src/ and src/lib.rs");
    }

    #[test]
    fn a_file_that_changed_since_the_walk_is_an_error_not_a_short_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("f"), b"0123456789").expect("file");
        let mut entries = walk(dir.path()).expect("walk");
        // As if the file had been 20 bytes when walked.
        entries[0].kind = Kind::File { size: 20 };
        let err = emit(dir.path(), &entries, OWNER, Vec::new()).expect_err("refused");
        assert!(err.to_string().contains("changed size"), "{err}");

        // And the reader itself refuses a short read the size check raced past.
        let mut exact = Exact {
            inner: &b"0123456789"[..],
            left: 20,
        };
        let err = std::io::copy(&mut exact, &mut std::io::sink()).expect_err("short");
        assert!(err.to_string().contains("shrank"), "{err}");
    }
}
