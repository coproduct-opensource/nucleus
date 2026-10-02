//! Write the flattened tree as one normalized tar.
//!
//! Determinism is by construction rather than by care: the tree is a
//! `BTreeMap` keyed by path bytes, so entries come out sorted and a parent
//! precedes its children; every header is built from the node alone (no
//! mtime, no user or group name, no pax record); and a hardlink group is
//! written as its lexicographically first path followed by links to it. Two
//! flattenings of the same tree are therefore byte-identical, whatever the
//! layer order or header noise that produced it.

use std::collections::BTreeMap;
use std::io::{self, Write};

use tar::{EntryType, Header};

use crate::digest::HashingWriter;
use crate::error::ImportError;
use crate::flatten::{Flattened, Meta, Node};
use crate::record::{FlattenReport, RootfsRecord};

/// The mtime every emitted entry carries (the Unix epoch, as `SOURCE_DATE_EPOCH=0`).
pub const NORMALIZED_MTIME: u64 = 0;

/// The longest name a ustar/GNU header holds inline; longer names get a GNU long-name record.
const INLINE_NAME: usize = 100;

/// What [`Flattened::emit`] wrote.
#[derive(Debug)]
pub struct Emitted {
    /// The tar's digest, length and entry count.
    pub rootfs: RootfsRecord,
    /// Everything flattening changed or removed.
    pub report: FlattenReport,
}

impl Flattened {
    /// Write the tree as a tar to `out`, consuming it.
    pub fn emit<W: Write>(self, out: W) -> Result<Emitted, ImportError> {
        let Flattened {
            tree,
            inodes,
            report,
        } = self;
        let emit_err = |source: io::Error| ImportError::Emit { source };
        let mut builder = tar::Builder::new(HashingWriter::new(out));
        let mut primary: BTreeMap<u64, &[u8]> = BTreeMap::new();
        let mut entries: u64 = 0;
        for (path, node) in &tree {
            match node {
                Node::Dir(meta) => {
                    let mut name = path.clone();
                    name.push(b'/');
                    append(&mut builder, EntryType::Directory, &name, None, *meta, &[])
                }
                Node::File(ino) => {
                    let inode = inodes.get(ino).ok_or_else(|| {
                        emit_err(io::Error::other("flattened tree names an absent inode"))
                    })?;
                    match primary.get(ino) {
                        Some(first) => append(
                            &mut builder,
                            EntryType::Link,
                            path,
                            Some(first),
                            inode.meta,
                            &[],
                        ),
                        None => {
                            primary.insert(*ino, path);
                            append(
                                &mut builder,
                                EntryType::Regular,
                                path,
                                None,
                                inode.meta,
                                &inode.content,
                            )
                        }
                    }
                }
                Node::Symlink { meta, target } => append(
                    &mut builder,
                    EntryType::Symlink,
                    path,
                    Some(target),
                    *meta,
                    &[],
                ),
                Node::Fifo(meta) => append(&mut builder, EntryType::Fifo, path, None, *meta, &[]),
            }
            .map_err(emit_err)?;
            entries = entries.saturating_add(1);
        }
        let hashing = builder.into_inner().map_err(emit_err)?;
        let (mut out, digest, bytes) = hashing.finish();
        out.flush().map_err(emit_err)?;
        Ok(Emitted {
            rootfs: RootfsRecord {
                digest,
                bytes,
                entries,
            },
            report,
        })
    }
}

fn len64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// Copy `src` into a fixed header field, truncating; the rest stays NUL.
fn fill(field: &mut [u8], src: &[u8]) {
    for (dst, byte) in field.iter_mut().zip(src) {
        *dst = *byte;
    }
}

/// A header with every field this crate does not set zeroed.
fn base_header(kind: EntryType, meta: Meta, size: u64) -> Header {
    let mut header = Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(meta.mode);
    header.set_uid(meta.uid);
    header.set_gid(meta.gid);
    header.set_mtime(NORMALIZED_MTIME);
    header.set_size(size);
    header
}

/// A GNU `././@LongLink` record carrying a name that does not fit inline.
fn long_record<W: Write>(
    builder: &mut tar::Builder<W>,
    kind: EntryType,
    name: &[u8],
) -> io::Result<()> {
    let mut data = Vec::with_capacity(name.len().saturating_add(1));
    data.extend_from_slice(name);
    data.push(0);
    let meta = Meta {
        mode: 0,
        uid: 0,
        gid: 0,
    };
    let mut header = base_header(kind, meta, len64(&data));
    fill(&mut header.as_old_mut().name, b"././@LongLink");
    header.set_cksum();
    builder.append(&header, data.as_slice())
}

fn append<W: Write>(
    builder: &mut tar::Builder<W>,
    kind: EntryType,
    name: &[u8],
    link: Option<&[u8]>,
    meta: Meta,
    data: &[u8],
) -> io::Result<()> {
    if name.len() > INLINE_NAME {
        long_record(builder, EntryType::GNULongName, name)?;
    }
    if let Some(link) = link {
        if link.len() > INLINE_NAME {
            long_record(builder, EntryType::GNULongLink, link)?;
        }
    }
    let mut header = base_header(kind, meta, len64(data));
    fill(&mut header.as_old_mut().name, name);
    if let Some(link) = link {
        fill(&mut header.as_old_mut().linkname, link);
    }
    header.set_cksum();
    builder.append(&header, data)
}
