//! Apply OCI layers, bottom first, to one in-memory tree.
//!
//! Nothing here touches the host filesystem. A layer is a tar *stream*; each
//! entry is classified, checked, and folded into a map from normalized path to
//! node. The map is the rootfs; [`crate::emit`] writes it out.
//!
//! The OCI rules applied, per the image-spec "Applying Changesets" section:
//!
//! - `.wh.<name>` removes `<name>` and its subtree from **lower** layers;
//!   `<dir>/.wh..wh..opq` removes `<dir>`'s lower children. Both apply before
//!   the same layer's own entries, which they never hide. Neither is emitted.
//! - A non-directory replaces whatever was at its path, subtree included; a
//!   directory over a directory updates its metadata and keeps its children.
//! - A hardlink names an entry already in the tree; the two share an inode, so a
//!   later whiteout of the original leaves the link holding the content.

use std::collections::BTreeMap;
use std::io::{self, Read};

use tar::EntryType;

use crate::error::{ImportError, lossy};
use crate::limits::{Bounded, ImportLimits};
use crate::path::{self, Normalized, PathDefect};
use crate::record::{
    DroppedEntry, DroppedKind, FlattenReport, RecordedPath, StrippedSetId, StrippedXattr,
};
use crate::reserved::ReservedPaths;

/// Ownership and permission bits, as the layer declared them (setuid/setgid removed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Meta {
    pub(crate) mode: u32,
    pub(crate) uid: u64,
    pub(crate) gid: u64,
}

/// A directory the layers imply (a child with no parent entry) but never declare.
const IMPLICIT_DIR: Meta = Meta {
    mode: 0o755,
    uid: 0,
    gid: 0,
};

const SETID_BITS: u32 = 0o6000;
const CAPABILITY_XATTR: &[u8] = b"security.capability";

/// One node of the flattened tree.
#[derive(Debug)]
pub(crate) enum Node {
    Dir(Meta),
    /// A regular file: an index into the inode table, shared by hardlinks.
    File(u64),
    Symlink {
        meta: Meta,
        target: Vec<u8>,
    },
    Fifo(Meta),
}

/// A regular file's content and metadata, shared by every path linked to it.
#[derive(Debug)]
pub(crate) struct Inode {
    pub(crate) meta: Meta,
    pub(crate) content: Vec<u8>,
    links: u64,
}

/// One layer entry after classification, before it is applied.
enum Op {
    Whiteout(Vec<u8>),
    Opaque(Vec<u8>),
    Dir(Vec<u8>, Meta),
    File(Vec<u8>, Meta, Vec<u8>),
    Symlink(Vec<u8>, Meta, Vec<u8>),
    HardLink(Vec<u8>, Vec<u8>),
    Fifo(Vec<u8>, Meta),
    /// A device node: dropped (reported at classification), but it still
    /// replaces whatever the lower layers had at its path.
    Dropped(Vec<u8>),
}

/// Folds layers into one tree.
pub struct Flattener<'r> {
    reserved: &'r ReservedPaths,
    limits: ImportLimits,
    bytes_remaining: u64,
    entries_seen: u64,
    layer: usize,
    tree: BTreeMap<Vec<u8>, Node>,
    inodes: BTreeMap<u64, Inode>,
    next_inode: u64,
    report: FlattenReport,
}

/// The flattened tree, checked against the reserved-path table.
///
/// Only [`Flattener::finish`] makes one (ADR 0007 C-1), and [`Flattened::emit`]
/// takes it by value (C-4): a tree is written once.
#[derive(Debug)]
pub struct Flattened {
    pub(crate) tree: BTreeMap<Vec<u8>, Node>,
    pub(crate) inodes: BTreeMap<u64, Inode>,
    pub(crate) report: FlattenReport,
}

impl Flattened {
    /// The content of a regular file (or hardlink) at a normalized path, e.g. `etc/passwd`.
    pub fn regular_file(&self, path: &str) -> Option<&[u8]> {
        match self.tree.get(path.as_bytes()) {
            Some(Node::File(ino)) => self.inodes.get(ino).map(|i| i.content.as_slice()),
            Some(Node::Dir(_) | Node::Symlink { .. } | Node::Fifo(_)) | None => None,
        }
    }

    /// Everything flattening changed or removed.
    pub fn report(&self) -> &FlattenReport {
        &self.report
    }
}

impl<'r> Flattener<'r> {
    /// An empty tree governed by `reserved` and `limits`.
    pub fn new(reserved: &'r ReservedPaths, limits: ImportLimits) -> Self {
        Self {
            reserved,
            limits,
            bytes_remaining: limits.max_uncompressed_bytes,
            entries_seen: 0,
            layer: 0,
            tree: BTreeMap::new(),
            inodes: BTreeMap::new(),
            next_inode: 0,
            report: FlattenReport::empty(),
        }
    }

    /// Apply the next layer, given its **uncompressed** tar stream.
    ///
    /// The stream is read to its end, trailing bytes included, so a caller hashing
    /// underneath sees every byte. The stream is returned for that caller to finish.
    pub fn apply_layer<R: Read>(&mut self, stream: R) -> Result<R, ImportError> {
        let layer = self.layer;
        let limit = self.limits.max_uncompressed_bytes;
        let mut archive = tar::Archive::new(Bounded::new(stream, self.bytes_remaining));
        let ops = self.read_ops(layer, &mut archive);
        let mut bounded = archive.into_inner();
        if bounded.exhausted() {
            return Err(ImportError::UncompressedLimitExceeded { limit });
        }
        let ops = ops?;
        if let Err(source) = io::copy(&mut bounded, &mut io::sink()) {
            return Err(if bounded.exhausted() {
                ImportError::UncompressedLimitExceeded { limit }
            } else {
                ImportError::LayerRead { layer, source }
            });
        }
        self.bytes_remaining = bounded.remaining();
        self.apply(layer, ops)?;
        self.layer = layer.saturating_add(1);
        Ok(bounded.into_inner())
    }

    /// Check the finished tree against the reserved table and seal it.
    pub fn finish(self) -> Result<Flattened, ImportError> {
        let Self {
            reserved,
            limits: _,
            bytes_remaining: _,
            entries_seen: _,
            layer: _,
            tree,
            inodes,
            next_inode: _,
            report,
        } = self;
        for (dir, anchor) in reserved.required_directories() {
            match tree.get(dir) {
                None | Some(Node::Dir(_)) => {}
                Some(Node::File(_) | Node::Symlink { .. } | Node::Fifo(_)) => {
                    return Err(ImportError::ReservedAncestorNotDirectory {
                        path: lossy(dir),
                        reserved: lossy(anchor),
                    });
                }
            }
        }
        Ok(Flattened {
            tree,
            inodes,
            report,
        })
    }

    fn read_ops<R: Read>(
        &mut self,
        layer: usize,
        archive: &mut tar::Archive<R>,
    ) -> Result<Vec<Op>, ImportError> {
        let entries = archive
            .entries()
            .map_err(|source| ImportError::LayerRead { layer, source })?;
        let mut ops = Vec::new();
        for entry in entries {
            let mut entry = entry.map_err(|source| ImportError::LayerRead { layer, source })?;
            self.entries_seen = self.entries_seen.saturating_add(1);
            if self.entries_seen > self.limits.max_entries {
                return Err(ImportError::TooManyEntries {
                    limit: self.limits.max_entries,
                });
            }
            if let Some(op) = self.classify(layer, &mut entry)? {
                ops.push(op);
            }
        }
        Ok(ops)
    }

    fn normalized(&self, layer: usize, raw: &[u8]) -> Result<Normalized, ImportError> {
        path::normalize(raw, self.limits.max_path_bytes).map_err(|defect| match defect {
            PathDefect::Empty => ImportError::EmptyPath { layer },
            PathDefect::Nul => ImportError::PathHasNul {
                layer,
                path: lossy(raw),
            },
            PathDefect::DotDot => ImportError::DotDotComponent {
                layer,
                path: lossy(raw),
            },
            PathDefect::TooLong(len) => ImportError::PathTooLong {
                layer,
                len,
                limit: self.limits.max_path_bytes,
            },
        })
    }

    /// Classify one tar entry into an [`Op`], or `None` for header noise.
    fn classify<R: Read>(
        &mut self,
        layer: usize,
        entry: &mut tar::Entry<'_, R>,
    ) -> Result<Option<Op>, ImportError> {
        let kind = entry.header().entry_type();
        let raw_path = entry.path_bytes().into_owned();
        let unsupported = |type_byte: u8| ImportError::UnsupportedEntryType {
            layer,
            path: lossy(&raw_path),
            type_byte,
        };
        match kind {
            // A global pax header carries no file; its fields are header noise.
            EntryType::XGlobalHeader => return Ok(None),
            // The tar reader folds these into the entry they describe; one that
            // surfaces is malformed. Sparse files are not imported.
            EntryType::GNUSparse
            | EntryType::GNULongName
            | EntryType::GNULongLink
            | EntryType::XHeader
            | EntryType::__Nonexhaustive(_) => return Err(unsupported(kind.as_byte())),
            EntryType::Regular
            | EntryType::Continuous
            | EntryType::Link
            | EntryType::Symlink
            | EntryType::Char
            | EntryType::Block
            | EntryType::Directory
            | EntryType::Fifo => {}
        }

        let path = match self.normalized(layer, &raw_path)? {
            Normalized::Path(p) => p,
            Normalized::Root => {
                return match kind {
                    // The root's metadata is the runtime's, not the image's.
                    EntryType::Directory => Ok(None),
                    EntryType::Regular
                    | EntryType::Continuous
                    | EntryType::Link
                    | EntryType::Symlink
                    | EntryType::Char
                    | EntryType::Block
                    | EntryType::Fifo
                    | EntryType::GNUSparse
                    | EntryType::GNULongName
                    | EntryType::GNULongLink
                    | EntryType::XGlobalHeader
                    | EntryType::XHeader
                    | EntryType::__Nonexhaustive(_) => Err(ImportError::RootNotDirectory { layer }),
                };
            }
        };

        if let Some(op) = self.whiteout(layer, &path)? {
            return Ok(Some(op));
        }
        if let Some(hit) = self.reserved.occupies(&path) {
            return Err(ImportError::ReservedPath {
                layer,
                path: lossy(&path),
                reserved: lossy(hit.reserved),
            });
        }

        let invalid_header = |source: io::Error| ImportError::InvalidHeader {
            layer,
            path: lossy(&path),
            source,
        };
        let header = entry.header();
        let raw_mode = header.mode().map_err(invalid_header)?;
        let uid = header.uid().map_err(invalid_header)?;
        let gid = header.gid().map_err(invalid_header)?;
        let mut meta = Meta {
            mode: raw_mode & 0o7777,
            uid,
            gid,
        };

        let op = match kind {
            EntryType::Char | EntryType::Block => {
                let dropped = if kind == EntryType::Char {
                    DroppedKind::CharDevice
                } else {
                    DroppedKind::BlockDevice
                };
                self.report.dropped.push(DroppedEntry {
                    layer,
                    path: RecordedPath::from_bytes(&path),
                    kind: dropped,
                });
                return Ok(Some(Op::Dropped(path)));
            }
            EntryType::Link => {
                let raw_target =
                    entry
                        .link_name_bytes()
                        .map(|t| t.into_owned())
                        .ok_or_else(|| ImportError::MissingLinkTarget {
                            layer,
                            path: lossy(&path),
                        })?;
                let target = match self.normalized(layer, &raw_target)? {
                    Normalized::Path(t) => t,
                    Normalized::Root => {
                        return Err(ImportError::HardlinkTargetNotRegular {
                            layer,
                            path: lossy(&path),
                            target: lossy(&raw_target),
                        });
                    }
                };
                // A hardlink's metadata is its target's; nothing to strip here.
                return Ok(Some(Op::HardLink(path, target)));
            }
            EntryType::Symlink => {
                let target = entry
                    .link_name_bytes()
                    .map(|t| t.into_owned())
                    .ok_or_else(|| ImportError::MissingLinkTarget {
                        layer,
                        path: lossy(&path),
                    })?;
                if target.is_empty() {
                    return Err(ImportError::MissingLinkTarget {
                        layer,
                        path: lossy(&path),
                    });
                }
                if u64::try_from(target.len()).unwrap_or(u64::MAX) > self.limits.max_path_bytes {
                    return Err(ImportError::PathTooLong {
                        layer,
                        len: target.len(),
                        limit: self.limits.max_path_bytes,
                    });
                }
                if target.contains(&0) {
                    return Err(ImportError::PathHasNul {
                        layer,
                        path: lossy(&target),
                    });
                }
                meta.mode = 0o777;
                self.record_xattrs(layer, &path, entry)?;
                Op::Symlink(path, meta, target)
            }
            EntryType::Directory => {
                self.strip_setid(layer, &path, &mut meta);
                self.record_xattrs(layer, &path, entry)?;
                Op::Dir(path, meta)
            }
            EntryType::Fifo => {
                self.strip_setid(layer, &path, &mut meta);
                self.record_xattrs(layer, &path, entry)?;
                Op::Fifo(path, meta)
            }
            EntryType::Regular | EntryType::Continuous => {
                self.strip_setid(layer, &path, &mut meta);
                self.record_xattrs(layer, &path, entry)?;
                let hint = usize::try_from(entry.size().min(65_536)).unwrap_or(0);
                let mut content = Vec::with_capacity(hint);
                entry
                    .read_to_end(&mut content)
                    .map_err(|source| ImportError::LayerRead { layer, source })?;
                Op::File(path, meta, content)
            }
            EntryType::GNUSparse
            | EntryType::GNULongName
            | EntryType::GNULongLink
            | EntryType::XGlobalHeader
            | EntryType::XHeader
            | EntryType::__Nonexhaustive(_) => return Err(unsupported(kind.as_byte())),
        };
        Ok(Some(op))
    }

    /// A whiteout or opaque marker at `path`, checked against the reserved table.
    fn whiteout(&self, layer: usize, path: &[u8]) -> Result<Option<Op>, ImportError> {
        let (parent, name) = path::split_last(path);
        let invalid = || ImportError::InvalidWhiteout {
            layer,
            path: lossy(path),
        };
        if parent
            .split(|b| *b == b'/')
            .any(|component| component.starts_with(b".wh."))
        {
            return Err(invalid());
        }
        let (op, removed) = if name == b".wh..wh..opq" {
            (Op::Opaque(parent.to_vec()), parent.to_vec())
        } else if let Some(target) = name.strip_prefix(b".wh.") {
            if target.is_empty() || target.starts_with(b".wh.") {
                return Err(invalid());
            }
            let full = path::join(parent, target);
            (Op::Whiteout(full.clone()), full)
        } else {
            return Ok(None);
        };
        if let Some(hit) = self.reserved.removal_reaches(&removed) {
            return Err(ImportError::WhiteoutOverReserved {
                layer,
                path: lossy(&removed),
                reserved: lossy(hit.reserved),
            });
        }
        Ok(Some(op))
    }

    fn strip_setid(&mut self, layer: usize, path: &[u8], meta: &mut Meta) {
        let bits = meta.mode & SETID_BITS;
        if bits != 0 {
            meta.mode &= !SETID_BITS;
            self.report.stripped_setid.push(StrippedSetId {
                layer,
                path: RecordedPath::from_bytes(path),
                bits,
            });
        }
    }

    fn record_xattrs<R: Read>(
        &mut self,
        layer: usize,
        path: &[u8],
        entry: &mut tar::Entry<'_, R>,
    ) -> Result<(), ImportError> {
        let invalid_header = |source: io::Error| ImportError::InvalidHeader {
            layer,
            path: lossy(path),
            source,
        };
        let Some(extensions) = entry.pax_extensions().map_err(invalid_header)? else {
            return Ok(());
        };
        for extension in extensions {
            let extension = extension.map_err(invalid_header)?;
            let key = extension.key_bytes();
            let Some(name) = key
                .strip_prefix(b"SCHILY.xattr.")
                .or_else(|| key.strip_prefix(b"LIBARCHIVE.xattr."))
            else {
                continue;
            };
            let stripped = StrippedXattr {
                layer,
                path: RecordedPath::from_bytes(path),
                name: RecordedPath::from_bytes(name),
            };
            if name == CAPABILITY_XATTR {
                self.report.stripped_capabilities.push(stripped);
            } else {
                self.report.dropped_xattrs.push(stripped);
            }
        }
        Ok(())
    }

    fn apply(&mut self, layer: usize, ops: Vec<Op>) -> Result<(), ImportError> {
        // Whiteouts and opaque markers apply to the lower layers only, so all of
        // them go before any of this layer's own entries.
        let (removals, additions): (Vec<Op>, Vec<Op>) = ops
            .into_iter()
            .partition(|op| matches!(op, Op::Whiteout(_) | Op::Opaque(_)));
        for op in removals.into_iter().chain(additions) {
            match op {
                Op::Whiteout(p) => self.remove_subtree(&p),
                Op::Opaque(dir) => {
                    for key in self.children_keys(&dir) {
                        self.remove_key(&key);
                    }
                }
                Op::Dropped(p) => self.remove_subtree(&p),
                Op::Dir(p, meta) => {
                    self.ensure_parents(layer, &p)?;
                    match self.tree.get_mut(&p) {
                        Some(Node::Dir(existing)) => *existing = meta,
                        Some(Node::File(_) | Node::Symlink { .. } | Node::Fifo(_)) | None => {
                            self.remove_subtree(&p);
                            self.tree.insert(p, Node::Dir(meta));
                        }
                    }
                }
                Op::File(p, meta, content) => {
                    self.ensure_parents(layer, &p)?;
                    self.remove_subtree(&p);
                    let ino = self.next_inode;
                    self.next_inode = ino.saturating_add(1);
                    self.inodes.insert(
                        ino,
                        Inode {
                            meta,
                            content,
                            links: 1,
                        },
                    );
                    self.tree.insert(p, Node::File(ino));
                }
                Op::Symlink(p, meta, target) => {
                    self.ensure_parents(layer, &p)?;
                    self.remove_subtree(&p);
                    self.tree.insert(p, Node::Symlink { meta, target });
                }
                Op::Fifo(p, meta) => {
                    self.ensure_parents(layer, &p)?;
                    self.remove_subtree(&p);
                    self.tree.insert(p, Node::Fifo(meta));
                }
                Op::HardLink(p, target) => {
                    let ino = match self.tree.get(&target) {
                        Some(Node::File(ino)) => *ino,
                        Some(Node::Dir(_) | Node::Symlink { .. } | Node::Fifo(_)) => {
                            return Err(ImportError::HardlinkTargetNotRegular {
                                layer,
                                path: lossy(&p),
                                target: lossy(&target),
                            });
                        }
                        None => {
                            return Err(ImportError::HardlinkTargetMissing {
                                layer,
                                path: lossy(&p),
                                target: lossy(&target),
                            });
                        }
                    };
                    if p == target {
                        continue;
                    }
                    self.ensure_parents(layer, &p)?;
                    self.remove_subtree(&p);
                    if let Some(inode) = self.inodes.get_mut(&ino) {
                        inode.links = inode.links.saturating_add(1);
                    }
                    self.tree.insert(p, Node::File(ino));
                }
            }
        }
        Ok(())
    }

    /// Create missing parents as implicit directories; refuse a parent that is not one.
    fn ensure_parents(&mut self, layer: usize, p: &[u8]) -> Result<(), ImportError> {
        for ancestor in path::strict_ancestors(p) {
            match self.tree.get(ancestor) {
                Some(Node::Dir(_)) => {}
                Some(Node::File(_) | Node::Symlink { .. } | Node::Fifo(_)) => {
                    return Err(ImportError::AncestorNotDirectory {
                        layer,
                        path: lossy(p),
                        ancestor: lossy(ancestor),
                    });
                }
                None => {
                    self.tree.insert(ancestor.to_vec(), Node::Dir(IMPLICIT_DIR));
                }
            }
        }
        Ok(())
    }

    /// Every key strictly below `dir` (everything, for the root).
    fn children_keys(&self, dir: &[u8]) -> Vec<Vec<u8>> {
        if dir.is_empty() {
            return self.tree.keys().cloned().collect();
        }
        // Every key beginning `dir/` sorts in [`dir/`, `dir0`): `0` follows `/`.
        let mut lo = dir.to_vec();
        lo.push(b'/');
        let mut hi = dir.to_vec();
        hi.push(b'0');
        self.tree.range(lo..hi).map(|(k, _)| k.clone()).collect()
    }

    fn remove_subtree(&mut self, p: &[u8]) {
        for key in self.children_keys(p) {
            self.remove_key(&key);
        }
        self.remove_key(p);
    }

    fn remove_key(&mut self, key: &[u8]) {
        if let Some(Node::File(ino)) = self.tree.remove(key) {
            let orphaned = match self.inodes.get_mut(&ino) {
                Some(inode) => {
                    inode.links = inode.links.saturating_sub(1);
                    inode.links == 0
                }
                None => false,
            };
            if orphaned {
                self.inodes.remove(&ino);
            }
        }
    }
}
