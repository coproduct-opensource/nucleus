//! A tree the caller writes itself, emitted through the same normalizer.
//!
//! The guest layer — `/init`, the `nucleus-*` binaries, the CA bundle — is not
//! an image: it is exactly the paths the reserved table keeps images *out* of,
//! so it cannot go through [`crate::Flattener`], which exists to refuse them.
//! It still has to come out byte-for-byte deterministic, and a second tar
//! writer would be a second opinion on what "normalized" means (ADR 0007 G-1).
//! So [`AuthoredTree`] builds the same in-memory tree the flattener does and
//! [`AuthoredTree::emit`] hands it to the one writer.
//!
//! It yields a [`RootfsRecord`], never a [`crate::Flattened`]: a `Flattened` is
//! the flattener's evidence that a tree was checked against the reserved table
//! (C-1), and an authored tree was not.
//!
//! Everything is explicit, because the caller is the only author: every
//! directory is declared (no implied parents), every mode is given, and the
//! owner is always `0:0`.

use std::collections::BTreeMap;
use std::io::Write;

use crate::emit::write_tree;
use crate::error::ImportError;
use crate::flatten::{Inode, Meta, Node};
use crate::path::{self, Normalized};
use crate::record::RootfsRecord;

/// Permission bits an authored entry may carry. setuid, setgid and sticky are
/// refused rather than stripped: here nobody else wrote them, so one is a bug.
const PERMISSION_BITS: u32 = 0o777;

/// Why an authored entry was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorError {
    /// The path has no normal form, or normalizes to the root.
    #[error("`{path}` is not a path below the root")]
    InvalidPath {
        /// The path as given.
        path: String,
    },
    /// The parent directory was not declared first.
    #[error("`{path}`: parent directory `{parent}` was not declared")]
    MissingParent {
        /// The entry.
        path: String,
        /// The directory it needs.
        parent: String,
    },
    /// The path was already declared.
    #[error("`{path}` declared twice")]
    Duplicate {
        /// The entry.
        path: String,
    },
    /// The mode has bits beyond `0o777`.
    #[error("`{path}`: mode {mode:#o} has bits beyond 0o777")]
    Mode {
        /// The entry.
        path: String,
        /// The mode given.
        mode: u32,
    },
}

/// A tree of directories and regular files, all owned by `0:0`.
#[derive(Debug, Default)]
pub struct AuthoredTree {
    tree: BTreeMap<Vec<u8>, Node>,
    inodes: BTreeMap<u64, Inode>,
    next_inode: u64,
}

impl AuthoredTree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a directory.
    pub fn dir(&mut self, path: &str, mode: u32) -> Result<(), AuthorError> {
        let (p, meta) = self.admit(path, mode)?;
        self.tree.insert(p, Node::Dir(meta));
        Ok(())
    }

    /// Declare a regular file.
    pub fn file(&mut self, path: &str, mode: u32, content: Vec<u8>) -> Result<(), AuthorError> {
        let (p, meta) = self.admit(path, mode)?;
        let ino = self.next_inode;
        self.next_inode = ino.saturating_add(1);
        self.inodes.insert(ino, Inode::single(meta, content));
        self.tree.insert(p, Node::File(ino));
        Ok(())
    }

    /// The normalized paths declared so far, in emission order.
    pub fn paths(&self) -> impl Iterator<Item = &[u8]> {
        self.tree.keys().map(Vec::as_slice)
    }

    /// Write the tree as one normalized tar to `out`, consuming it.
    pub fn emit<W: Write>(self, out: W) -> Result<RootfsRecord, ImportError> {
        write_tree(&self.tree, &self.inodes, out)
    }

    fn admit(&self, path: &str, mode: u32) -> Result<(Vec<u8>, Meta), AuthorError> {
        let invalid = || AuthorError::InvalidPath {
            path: path.to_owned(),
        };
        let p = match path::normalize(path.as_bytes(), u64::MAX) {
            Ok(Normalized::Path(p)) => p,
            Ok(Normalized::Root) | Err(_) => return Err(invalid()),
        };
        if mode & !PERMISSION_BITS != 0 {
            return Err(AuthorError::Mode {
                path: path.to_owned(),
                mode,
            });
        }
        if self.tree.contains_key(&p) {
            return Err(AuthorError::Duplicate {
                path: path.to_owned(),
            });
        }
        if let Some(slash) = p.iter().rposition(|b| *b == b'/') {
            let parent = p.get(..slash).ok_or_else(invalid)?;
            match self.tree.get(parent) {
                Some(Node::Dir(_)) => {}
                Some(Node::File(_) | Node::Symlink { .. } | Node::Fifo(_)) | None => {
                    return Err(AuthorError::MissingParent {
                        path: path.to_owned(),
                        parent: String::from_utf8_lossy(parent).into_owned(),
                    });
                }
            }
        }
        Ok((
            p,
            Meta {
                mode,
                uid: 0,
                gid: 0,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> AuthoredTree {
        let mut t = AuthoredTree::new();
        t.dir("etc", 0o755).unwrap();
        t.file("etc/a", 0o644, b"a".to_vec()).unwrap();
        t.file("init", 0o755, b"init".to_vec()).unwrap();
        t
    }

    #[test]
    fn declaration_order_does_not_change_the_bytes() {
        let mut other = AuthoredTree::new();
        other.file("init", 0o755, b"init".to_vec()).unwrap();
        other.dir("/etc/", 0o755).unwrap();
        other.file("./etc/a", 0o644, b"a".to_vec()).unwrap();
        let (mut x, mut y) = (Vec::new(), Vec::new());
        let rx = tree().emit(&mut x).unwrap();
        let ry = other.emit(&mut y).unwrap();
        assert_eq!(x, y);
        assert_eq!(rx, ry);
        assert_eq!(rx.entries, 3);
    }

    #[test]
    fn every_entry_is_root_owned_with_its_declared_mode_and_no_mtime() {
        let mut bytes = Vec::new();
        tree().emit(&mut bytes).unwrap();
        let mut archive = tar::Archive::new(bytes.as_slice());
        let seen: Vec<(String, u32, u64, u64, u64)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                (
                    String::from_utf8_lossy(&e.path_bytes()).into_owned(),
                    h.mode().unwrap(),
                    h.uid().unwrap(),
                    h.gid().unwrap(),
                    h.mtime().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                ("etc/".into(), 0o755, 0, 0, 0),
                ("etc/a".into(), 0o644, 0, 0, 0),
                ("init".into(), 0o755, 0, 0, 0),
            ]
        );
    }

    #[test]
    fn a_parent_must_be_declared_first() {
        let mut t = AuthoredTree::new();
        assert!(matches!(
            t.file("usr/bin/x", 0o755, Vec::new()),
            Err(AuthorError::MissingParent { .. })
        ));
    }

    #[test]
    fn duplicates_setid_and_the_root_are_refused() {
        let mut t = tree();
        assert!(matches!(
            t.file("etc/a", 0o644, Vec::new()),
            Err(AuthorError::Duplicate { .. })
        ));
        assert!(matches!(
            t.file("etc/b", 0o4755, Vec::new()),
            Err(AuthorError::Mode { .. })
        ));
        assert!(matches!(
            t.dir("/", 0o755),
            Err(AuthorError::InvalidPath { .. })
        ));
        assert!(matches!(
            t.dir("etc/../x", 0o755),
            Err(AuthorError::InvalidPath { .. })
        ));
    }
}
