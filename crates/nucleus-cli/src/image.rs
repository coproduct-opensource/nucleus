//! `nucleus image` — bring an OCI image in as a flattened, verified rootfs.
//!
//! ```text
//! nucleus image resolve registry.example/team/app:v1       → registry.example/team/app@sha256:…
//! nucleus image import  registry.example/team/app@sha256:…  (fetch, verify, flatten)
//! nucleus image import  --oci-layout DIR   sha256:…
//! nucleus image import  --oci-archive FILE sha256:…
//! ```
//!
//! Every source ends in the same call, `nucleus_oci_rootfs::import`, so the rootfs
//! bytes have one decider however the image arrived. A registry is read through
//! [`source::RegistrySource`], which fetches blobs on demand into the cache's blob
//! store and verifies each one while it streams.
//!
//! The result is filed as `<cache>/rootfs/sha256/<tar digest>/{rootfs.tar, import.json}`.
//! With `--guest-layer`, stage two follows ([`store::stage_two`]): the runtime's guest
//! layer is overlaid, a deterministic ext4 is built, and it is filed in the node's
//! image store under its own digest — on Linux here, elsewhere by the printed
//! `nucleus-hostctl image build` command on the node host. `nucleus run --image`
//! then names it by reference ([`store::find`]).

mod auth;
mod cache;
mod reference;
mod registry;
mod source;
pub(crate) mod store;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};

use nucleus_oci_rootfs::{
    Arch, BlobSource, ImportLimits, ImportRecord, OciArchive, PinnedReference, ReservedPath,
    ReservedPaths, Sha256Digest,
};

use cache::ImageCache;
use reference::{PinnedImage, TaggedImage};
use registry::{FetchLimits, RegistryClient};

#[derive(Args, Debug)]
pub struct ImageArgs {
    #[command(subcommand)]
    pub command: ImageCommand,
}

#[derive(Subcommand, Debug)]
pub enum ImageCommand {
    /// Fetch (from a registry) or read (from a local layout/archive) an image pinned
    /// by digest, verify it, and flatten it into a rootfs tar in the image cache
    Import(ImportArgs),
    /// Print the digest a registry currently serves for a tag, as a pinned reference
    Resolve(ResolveArgs),
}

/// The guest architecture to import for.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ArchArg {
    Amd64,
    Arm64,
}

impl From<ArchArg> for Arch {
    fn from(a: ArchArg) -> Self {
        match a {
            ArchArg::Amd64 => Arch::Amd64,
            ArchArg::Arm64 => Arch::Arm64,
        }
    }
}

#[derive(Args, Debug)]
pub struct RegistryOpts {
    /// Allow plain http to this `host[:port]` (repeatable). Without it, http is refused
    #[arg(long = "insecure-registry", value_name = "HOST[:PORT]")]
    pub insecure_registry: Vec<String>,

    /// Docker-format config.json to read `auths` from
    /// [default: $DOCKER_CONFIG/config.json, else ~/.docker/config.json]
    #[arg(long, value_name = "FILE")]
    pub registry_config: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// `registry/repository@sha256:…` for a registry; `sha256:…` (or `name@sha256:…`)
    /// with --oci-layout / --oci-archive. A tag-only reference is refused
    pub reference: String,

    /// Read the image from this OCI layout directory instead of a registry
    #[arg(long, value_name = "DIR", conflicts_with = "oci_archive")]
    pub oci_layout: Option<PathBuf>,

    /// Read the image from this oci-archive tar instead of a registry
    #[arg(long, value_name = "FILE")]
    pub oci_archive: Option<PathBuf>,

    /// Guest architecture [default: this host's]
    #[arg(long, value_enum)]
    pub arch: Option<ArchArg>,

    /// Image cache directory [default: <data dir>/nucleus/images]
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,

    /// The runtime guest layer tar to overlay. With it, stage two builds the ext4
    /// and files it in the node's image store; without it, import stops at the tar
    #[arg(long, value_name = "TAR")]
    pub guest_layer: Option<PathBuf>,

    /// The node's image store (its `--image-root`)
    /// [default: /var/lib/nucleus/state/images]
    #[arg(long, value_name = "DIR", env = "NUCLEUS_NODE_IMAGE_ROOT")]
    pub image_root: Option<PathBuf>,

    #[command(flatten)]
    pub registry: RegistryOpts,
}

#[derive(Args, Debug)]
pub struct ResolveArgs {
    /// `registry/repository:tag`
    pub reference: String,

    #[command(flatten)]
    pub registry: RegistryOpts,
}

/// The guest paths the runtime owns, which no image layer may occupy.
///
/// PROVISIONAL COPY: these are the paths `nucleus-guest-init` writes or execs
/// (`POD_SPEC_PATH`, `PROXY_BIN`, `EGRESS_PROBE_BIN`, `GUEST_NET_SH`, `init=/init`).
/// The table belongs with the guest layout it describes (`nucleus_spec::guest_layout`,
/// not yet on main); when that lands this function becomes a call to it (G-1).
fn reserved_guest_paths() -> Result<ReservedPaths> {
    Ok(ReservedPaths::new([
        ReservedPath::Exact(b"init".to_vec()),
        ReservedPath::Exact(b"pod.yaml".to_vec()),
        ReservedPath::Prefix(b"etc/nucleus".to_vec()),
        ReservedPath::Exact(b"usr/local/bin/nucleus-tool-proxy".to_vec()),
        ReservedPath::Exact(b"usr/local/bin/nucleus-egress-probe".to_vec()),
        ReservedPath::Exact(b"usr/local/bin/guest-net.sh".to_vec()),
    ])?)
}

fn host_arch() -> Result<Arch> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Arch::Amd64),
        "aarch64" => Ok(Arch::Arm64),
        other => bail!("no guest architecture for host `{other}`; pass --arch"),
    }
}

/// Where an import reads its image from.
enum Source {
    Registry(PinnedImage),
    Layout(PathBuf, PinnedReference),
    Archive(PathBuf, PinnedReference),
}

/// A flattened rootfs filed in the cache: the input to stage two ([`store::stage_two`]).
#[derive(Debug)]
pub struct StagedRootfs {
    /// `<cache>/rootfs/sha256/<hex>`, holding `rootfs.tar` and `import.json`.
    pub dir: PathBuf,
    /// What was imported, and everything changed on the way.
    pub record: ImportRecord,
}

impl StagedRootfs {
    pub fn tar(&self) -> PathBuf {
        self.dir.join("rootfs.tar")
    }
}

/// Everything `import` needs, resolved from flags and environment.
pub struct ImportPlan {
    pub cache: ImageCache,
    pub arch: Arch,
    pub limits: ImportLimits,
    pub insecure: Vec<String>,
    pub credentials: auth::CredentialLookup,
}

/// Import `pinned` from `source` into the cache. The one path every source takes.
fn import_from(
    source: &dyn BlobSource,
    pinned: &PinnedReference,
    plan: &ImportPlan,
) -> Result<StagedRootfs> {
    let reserved = reserved_guest_paths()?;
    let (dir, record) = plan.cache.stage_rootfs(|file| {
        let imported =
            nucleus_oci_rootfs::import(source, pinned, plan.arch, &reserved, plan.limits, file)?;
        let json = serde_json::to_vec_pretty(&imported.record)?;
        Ok((imported.record.rootfs.digest, json, imported.record))
    })?;
    Ok(StagedRootfs { dir, record })
}

fn run_import(source: Source, plan: &ImportPlan) -> Result<StagedRootfs> {
    match source {
        Source::Layout(dir, pinned) => {
            import_from(&nucleus_oci_rootfs::LayoutDir::new(dir), &pinned, plan)
        }
        Source::Archive(file, pinned) => {
            let archive = OciArchive::open(&file, &plan.limits)
                .with_context(|| format!("indexing {}", file.display()))?;
            import_from(&archive, &pinned, plan)
        }
        Source::Registry(image) => {
            let client = RegistryClient::new(
                image.name.clone(),
                &plan.insecure,
                plan.credentials.clone(),
                FetchLimits::from_import(&plan.limits),
            )?;
            let src = source::RegistrySource::prepare(&client, &plan.cache, image.pinned.digest())?;
            import_from(&src, &image.pinned, plan)
        }
    }
}

fn lookup_credentials(registry: &str, opts: &RegistryOpts) -> Result<auth::CredentialLookup> {
    let env = |k: &str| std::env::var(k).ok();
    let config = match &opts.registry_config {
        Some(p) => Some(p.clone()),
        None => auth::default_config_path(&env),
    };
    Ok(auth::lookup(registry, &env, config.as_deref())?)
}

fn print_staged(staged: &StagedRootfs, reference: &str) {
    let r = &staged.record;
    println!("imported   {reference}");
    if let Some(index) = r.index_digest {
        println!("index      {index}");
    }
    println!("manifest   {}", r.manifest_digest);
    println!("platform   linux/{}", r.platform.architecture.oci_name());
    println!("rootfs     {} ({} bytes)", r.rootfs.digest, r.rootfs.bytes);
    println!("tar        {}", staged.tar().display());
    println!("record     {}", staged.dir.join("import.json").display());
}

fn cache_root(dir: Option<&Path>) -> Result<PathBuf> {
    match dir {
        Some(d) => Ok(d.to_owned()),
        None => ImageCache::default_root()
            .context("no data directory for the image cache; pass --cache-dir"),
    }
}

/// Stage one: fetch or read, verify, and flatten into the cache.
fn stage_one(args: &ImportArgs) -> Result<StagedRootfs> {
    let arch = match args.arch {
        Some(a) => a.into(),
        None => host_arch()?,
    };
    let (source, registry) = match (&args.oci_layout, &args.oci_archive) {
        (Some(dir), None) => (
            Source::Layout(dir.clone(), PinnedReference::parse(&args.reference)?),
            None,
        ),
        (None, Some(file)) => (
            Source::Archive(file.clone(), PinnedReference::parse(&args.reference)?),
            None,
        ),
        (None, None) => {
            let image = PinnedImage::parse(&args.reference)?;
            let registry = image.name.registry().to_owned();
            (Source::Registry(image), Some(registry))
        }
        (Some(_), Some(_)) => bail!("--oci-layout and --oci-archive are exclusive"),
    };
    let credentials = match &registry {
        Some(r) => lookup_credentials(r, &args.registry)?,
        None => auth::CredentialLookup::None,
    };
    let plan = ImportPlan {
        cache: ImageCache::open(cache_root(args.cache_dir.as_deref())?)?,
        arch,
        limits: ImportLimits::standard(),
        insecure: args.registry.insecure_registry.clone(),
        credentials,
    };
    run_import(source, &plan)
}

/// Stage one, then stage two when a guest layer is given.
pub(crate) fn import_to_store(args: &ImportArgs) -> Result<Option<store::StageTwo>> {
    let staged = stage_one(args)?;
    print_staged(&staged, &args.reference);
    let image_root = args
        .image_root
        .clone()
        .unwrap_or_else(store::default_image_root);
    let Some(guest_layer) = &args.guest_layer else {
        println!(
            "next       stage two, on the node host:\n  {}",
            store::hostctl_command(&staged, Path::new("<guest-layer.tar>"), &image_root)
        );
        return Ok(None);
    };
    let two = store::stage_two(&staged, guest_layer, &image_root)?;
    match &two {
        store::StageTwo::Filed(s) => {
            println!("rootfs_digest {}", s.rootfs_digest.as_str());
            println!("guest layer   {}", s.record.guest_layer_digest.as_str());
            println!("mke2fs        {}", s.record.mke2fs);
            let how = if s.reused { "already present" } else { "filed" };
            println!("store         {} ({how})", s.dir.display());
        }
        store::StageTwo::RunOnNodeHost(cmd) => {
            println!("stage two runs on the node host (this is not Linux):\n  {cmd}");
        }
    }
    Ok(Some(two))
}

fn import(args: ImportArgs) -> Result<()> {
    import_to_store(&args).map(|_| ())
}

fn resolve(args: ResolveArgs) -> Result<()> {
    let tagged = TaggedImage::parse(&args.reference)?;
    let credentials = lookup_credentials(tagged.name.registry(), &args.registry)?;
    let digest = resolve_with(&tagged, &args.registry.insecure_registry, credentials)?;
    println!("{}", tagged.name.pinned(digest));
    Ok(())
}

fn resolve_with(
    tagged: &TaggedImage,
    insecure: &[String],
    credentials: auth::CredentialLookup,
) -> Result<Sha256Digest> {
    let client = RegistryClient::new(
        tagged.name.clone(),
        insecure,
        credentials,
        FetchLimits::from_import(&ImportLimits::standard()),
    )?;
    Ok(client.resolve_tag(&tagged.tag)?)
}

pub fn execute(args: ImageArgs) -> Result<()> {
    // The registry client is `reqwest::blocking` (the importer's `BlobSource` is a
    // sync trait), which must not run on an async worker: see `twosafety_boot`.
    tokio::task::block_in_place(|| match args.command {
        ImageCommand::Import(a) => import(a),
        ImageCommand::Resolve(a) => resolve(a),
    })
}
