//! Test support: build layers and images in-test. No binary fixtures.
//!
//! Layers are written with raw headers, so a test can put any bytes in a name
//! (`..`, an absolute path, a NUL via pax) — the tar crate's own path setters
//! refuse exactly the inputs these tests exist to feed in.

#![allow(dead_code)]

use std::io::Write;
use std::path::Path;

use nucleus_oci_rootfs::{
    Flattened, Flattener, ImportError, ImportLimits, ReservedPath, ReservedPaths,
};
use sha2::{Digest, Sha256};
use tar::{EntryType, Header};

pub fn reserved() -> ReservedPaths {
    ReservedPaths::new([
        ReservedPath::Exact(b"init".to_vec()),
        ReservedPath::Prefix(b"etc/nucleus".to_vec()),
        ReservedPath::Exact(b"usr/local/bin/nucleus-tool-proxy".to_vec()),
    ])
    .unwrap()
}

pub fn limits() -> ImportLimits {
    ImportLimits::standard()
}

/// One pax record: `LEN key=value\n`, LEN counting itself.
fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let body = key.len() + value.len() + 3; // ' ', '=', '\n'
    let mut len = body + 1;
    while len != body + len.to_string().len() {
        len = body + len.to_string().len();
    }
    let mut out = format!("{len} ").into_bytes();
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

#[derive(Clone)]
pub struct E {
    pub kind: EntryType,
    pub name: Vec<u8>,
    pub link: Option<Vec<u8>>,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub data: Vec<u8>,
    pub pax: Vec<(Vec<u8>, Vec<u8>)>,
    pub mtime: u64,
    pub uname: Vec<u8>,
    pub dev: (u32, u32),
}

impl E {
    fn new(kind: EntryType, name: &[u8]) -> Self {
        Self {
            kind,
            name: name.to_vec(),
            link: None,
            mode: 0o644,
            uid: 0,
            gid: 0,
            data: Vec::new(),
            pax: Vec::new(),
            mtime: 1_700_000_000,
            uname: b"root".to_vec(),
            dev: (0, 0),
        }
    }
    pub fn file(name: &[u8], data: &[u8]) -> Self {
        let mut e = Self::new(EntryType::Regular, name);
        e.data = data.to_vec();
        e
    }
    pub fn dir(name: &[u8]) -> Self {
        let mut e = Self::new(EntryType::Directory, name);
        e.mode = 0o755;
        e
    }
    pub fn symlink(name: &[u8], target: &[u8]) -> Self {
        let mut e = Self::new(EntryType::Symlink, name);
        e.link = Some(target.to_vec());
        e.mode = 0o777;
        e
    }
    pub fn hardlink(name: &[u8], target: &[u8]) -> Self {
        let mut e = Self::new(EntryType::Link, name);
        e.link = Some(target.to_vec());
        e
    }
    pub fn char_dev(name: &[u8]) -> Self {
        let mut e = Self::new(EntryType::Char, name);
        e.dev = (1, 3);
        e
    }
    pub fn block_dev(name: &[u8]) -> Self {
        let mut e = Self::new(EntryType::Block, name);
        e.dev = (8, 0);
        e
    }
    pub fn fifo(name: &[u8]) -> Self {
        Self::new(EntryType::Fifo, name)
    }
    /// An empty regular file: how whiteouts are written.
    pub fn whiteout(name: &[u8]) -> Self {
        Self::file(name, b"")
    }
    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }
    pub fn owner(mut self, uid: u64, gid: u64) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }
    pub fn pax(mut self, key: &[u8], value: &[u8]) -> Self {
        self.pax.push((key.to_vec(), value.to_vec()));
        self
    }
    pub fn noise(mut self, mtime: u64, uname: &[u8]) -> Self {
        self.mtime = mtime;
        self.uname = uname.to_vec();
        self
    }
}

fn fill(field: &mut [u8], src: &[u8]) {
    for (d, s) in field.iter_mut().zip(src) {
        *d = *s;
    }
}

/// A layer tar (uncompressed) from entries, headers written raw.
pub fn layer(entries: &[E]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for e in entries {
        if !e.pax.is_empty() {
            let mut data = Vec::new();
            for (k, v) in &e.pax {
                data.extend(pax_record(k, v));
            }
            let mut h = Header::new_ustar();
            h.set_entry_type(EntryType::XHeader);
            fill(&mut h.as_old_mut().name, b"PaxHeaders/x");
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_cksum();
            b.append(&h, data.as_slice()).unwrap();
        }
        let mut h = Header::new_ustar();
        h.set_entry_type(e.kind);
        fill(&mut h.as_old_mut().name, &e.name);
        if let Some(link) = &e.link {
            fill(&mut h.as_old_mut().linkname, link);
        }
        h.set_mode(e.mode);
        h.set_uid(e.uid);
        h.set_gid(e.gid);
        h.set_mtime(e.mtime);
        h.set_username(std::str::from_utf8(&e.uname).unwrap())
            .unwrap();
        h.set_size(e.data.len() as u64);
        if matches!(e.kind, EntryType::Char | EntryType::Block) {
            h.set_device_major(e.dev.0).unwrap();
            h.set_device_minor(e.dev.1).unwrap();
        }
        h.set_cksum();
        b.append(&h, e.data.as_slice()).unwrap();
    }
    b.into_inner().unwrap()
}

/// Flatten uncompressed layers, bottom first.
pub fn flatten(layers: &[Vec<u8>]) -> Result<Flattened, ImportError> {
    let reserved = reserved();
    flatten_with(layers, &reserved, limits())
}

pub fn flatten_with(
    layers: &[Vec<u8>],
    reserved: &ReservedPaths,
    limits: ImportLimits,
) -> Result<Flattened, ImportError> {
    let mut f = Flattener::new(reserved, limits);
    for l in layers {
        f.apply_layer(l.as_slice())?;
    }
    f.finish()
}

/// An emitted tar, parsed back: (name, type, link, mode, uid, gid, data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub name: Vec<u8>,
    pub kind: EntryType,
    pub link: Option<Vec<u8>>,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub uname: Vec<u8>,
    pub data: Vec<u8>,
}

pub fn emit(f: Flattened) -> Vec<u8> {
    let mut out = Vec::new();
    f.emit(&mut out).unwrap();
    out
}

pub fn read_back(tar_bytes: &[u8]) -> Vec<Out> {
    let mut a = tar::Archive::new(tar_bytes);
    let mut out = Vec::new();
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        assert!(
            e.pax_extensions().unwrap().is_none(),
            "emitted tar carries a pax record"
        );
        let h = e.header().clone();
        let name = e.path_bytes().into_owned();
        let link = e.link_name_bytes().map(|l| l.into_owned());
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut e, &mut data).unwrap();
        out.push(Out {
            name,
            kind: h.entry_type(),
            link,
            mode: h.mode().unwrap(),
            uid: h.uid().unwrap(),
            gid: h.gid().unwrap(),
            mtime: h.mtime().unwrap(),
            uname: h.username_bytes().unwrap_or_default().to_vec(),
            data,
        });
    }
    out
}

pub fn names(out: &[Out]) -> Vec<String> {
    out.iter()
        .map(|o| String::from_utf8_lossy(&o.name).into_owned())
        .collect()
}

pub fn find<'a>(out: &'a [Out], name: &str) -> Option<&'a Out> {
    out.iter().find(|o| o.name == name.as_bytes())
}

// ── images ───────────────────────────────────────────────────────────────

pub fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub const LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
pub const LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

pub fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(bytes, 3).unwrap()
}

/// A layer as it goes into an image.
pub struct LayerBlob {
    pub media_type: &'static str,
    pub blob: Vec<u8>,
    pub uncompressed: Vec<u8>,
}

impl LayerBlob {
    pub fn plain(tar: Vec<u8>) -> Self {
        Self {
            media_type: LAYER_TAR,
            blob: tar.clone(),
            uncompressed: tar,
        }
    }
    pub fn gzip(tar: Vec<u8>) -> Self {
        Self {
            media_type: LAYER_GZIP,
            blob: gzip(&tar),
            uncompressed: tar,
        }
    }
    pub fn zstd(tar: Vec<u8>) -> Self {
        Self {
            media_type: LAYER_ZSTD,
            blob: zstd(&tar),
            uncompressed: tar,
        }
    }
}

/// Digests of what [`write_image`] wrote.
pub struct Written {
    pub manifest: String,
    pub config: String,
    pub layers: Vec<String>,
    pub index: Option<String>,
}

pub fn put_blob(root: &Path, bytes: &[u8]) -> String {
    let d = sha(bytes);
    let dir = root.join("blobs/sha256");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(d.trim_start_matches("sha256:")), bytes).unwrap();
    d
}

pub fn blob_path(root: &Path, digest: &str) -> std::path::PathBuf {
    root.join("blobs/sha256")
        .join(digest.trim_start_matches("sha256:"))
}

pub fn config_json(arch: &str, user: &str, diff_ids: &[String]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "architecture": arch,
        "os": "linux",
        "config": {
            "User": user,
            "Env": ["PATH=/usr/bin:/bin", "LLM_API_TOKEN=test-token-123"],
            "Entrypoint": ["/usr/bin/agent"],
            "Cmd": ["--serve"],
            "WorkingDir": "/work"
        },
        "rootfs": { "type": "layers", "diff_ids": diff_ids }
    }))
    .unwrap()
}

/// Write the manifest (and its config and layers) as blobs; return its digest and size.
pub fn write_manifest(
    root: &Path,
    layers: &[LayerBlob],
    arch: &str,
    user: &str,
) -> (Written, usize) {
    let diff_ids: Vec<String> = layers.iter().map(|l| sha(&l.uncompressed)).collect();
    let config = config_json(arch, user, &diff_ids);
    let config_digest = put_blob(root, &config);
    let layer_digests: Vec<String> = layers.iter().map(|l| put_blob(root, &l.blob)).collect();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config.len()
        },
        "layers": layers.iter().zip(&layer_digests).map(|(l, d)| serde_json::json!({
            "mediaType": l.media_type,
            "digest": d,
            "size": l.blob.len()
        })).collect::<Vec<_>>()
    }))
    .unwrap();
    let manifest_digest = put_blob(root, &manifest);
    (
        Written {
            manifest: manifest_digest,
            config: config_digest,
            layers: layer_digests,
            index: None,
        },
        manifest.len(),
    )
}

pub fn write_layout_files(root: &Path, manifests: serde_json::Value) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("index.json"),
        serde_json::to_vec(&serde_json::json!({ "schemaVersion": 2, "manifests": manifests }))
            .unwrap(),
    )
    .unwrap();
}

/// A single-platform image layout whose index.json names the manifest directly.
pub fn write_image(root: &Path, layers: &[LayerBlob], user: &str) -> Written {
    let (w, size) = write_manifest(root, layers, "amd64", user);
    write_layout_files(
        root,
        serde_json::json!([{
            "mediaType": MANIFEST,
            "digest": w.manifest,
            "size": size,
            "annotations": { "org.opencontainers.image.ref.name": "latest" }
        }]),
    );
    w
}

/// Tar a layout directory into an oci-archive file.
pub fn archive_of(layout: &Path, dest: &Path) {
    let f = std::fs::File::create(dest).unwrap();
    let mut b = tar::Builder::new(f);
    b.append_dir_all(".", layout).unwrap();
    b.finish().unwrap();
}

/// A passwd/group pair layer plus a root dir, the usual base.
pub fn base_layer() -> Vec<u8> {
    layer(&[
        E::dir(b"./"),
        E::dir(b"etc"),
        E::file(
            b"etc/passwd",
            b"root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\nsvc:x:1001:1002::/:/bin/false\n",
        ),
        E::file(b"etc/group", b"root:x:0:\napp:x:1000:\nwheel:x:10:\n"),
        E::dir(b"usr"),
        E::dir(b"usr/bin"),
        E::file(b"usr/bin/agent", b"#!/bin/sh\n").mode(0o755),
    ])
}
