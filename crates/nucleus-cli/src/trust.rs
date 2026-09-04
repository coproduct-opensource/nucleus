//! `nucleus trust` — the operator-controlled root of trust for signed MCP
//! tool manifests (#1637).
//!
//! The store is `<dir>/.nucleus/trust/*.pub`: one hex-encoded 32-byte Ed25519
//! public key per file. `portcullis::manifest_registry::TrustStore` reads it,
//! `mcp-guard --manifests` and `nucleus manifest verify` enforce under it.
//! Nothing here touches a keychain: the signing seed is a file the publisher
//! keeps, and only the public half enters the store.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommand,
}

#[derive(Subcommand)]
pub enum TrustCommand {
    /// Generate a publisher signing key. Writes the hex seed to `--out`
    /// (mode 0600) and the public key to `<out>.pub`; the `.pub` is what
    /// goes into a trust store.
    Keygen {
        /// Where to write the seed. Refuses to overwrite.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Add a publisher public key (a `.pub` file or a 64-char hex string) to
    /// `<dir>/.nucleus/trust/<name>.pub`.
    Add {
        /// Path to a `.pub` file, or the hex key itself.
        key: String,
        /// Name for the stored key (default: the file's stem, or `key-<prefix>`).
        #[arg(long)]
        name: Option<String>,
        /// Project directory holding `.nucleus/`.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// List the trusted publisher keys.
    List {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Remove a trusted publisher key by name.
    Remove {
        /// The stored name (the file stem under `.nucleus/trust/`).
        name: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

pub fn execute(args: TrustArgs) -> Result<()> {
    match args.command {
        TrustCommand::Keygen { out } => keygen(&out),
        TrustCommand::Add { key, name, dir } => {
            let stored = add(&dir, &key, name.as_deref())?;
            eprintln!("trusted: {}", stored.display());
            Ok(())
        }
        TrustCommand::List { dir } => {
            let keys = list(&dir)?;
            if keys.is_empty() {
                eprintln!(
                    "no trusted keys in {} (a guard run with --manifests will refuse to start)",
                    trust_dir(&dir).display()
                );
            }
            for (name, hex) in keys {
                println!("{name}\t{hex}");
            }
            Ok(())
        }
        TrustCommand::Remove { name, dir } => {
            remove(&dir, &name)?;
            eprintln!("removed: {name}");
            Ok(())
        }
    }
}

fn trust_dir(dir: &Path) -> PathBuf {
    dir.join(".nucleus").join("trust")
}

/// A 32-byte key from hex, or a clear error.
fn parse_pubkey_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).context("public key is not hex")?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes ({} given)", bytes.len()))
}

fn keygen(out: &Path) -> Result<()> {
    use ring::rand::SecureRandom as _;
    if out.exists() {
        bail!(
            "{} exists; refusing to overwrite a signing key",
            out.display()
        );
    }
    let mut seed = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| anyhow::anyhow!("system randomness unavailable"))?;
    let public = portcullis::manifest_registry::public_key_for_seed(&seed);

    write_private(out, &hex::encode(seed))?;
    let pub_path = out.with_extension("pub");
    std::fs::write(&pub_path, hex::encode(public))
        .with_context(|| format!("writing {}", pub_path.display()))?;
    eprintln!(
        "seed:   {} (keep private)\npublic: {}\n{}",
        out.display(),
        pub_path.display(),
        hex::encode(public)
    );
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, content: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("creating {}", path.display()))
}

/// Add a key to the store; returns the path written.
pub fn add(dir: &Path, key: &str, name: Option<&str>) -> Result<PathBuf> {
    let key_path = Path::new(key);
    let (hex, default_name) = if key_path.is_file() {
        let content = std::fs::read_to_string(key_path)
            .with_context(|| format!("reading {}", key_path.display()))?;
        let stem = key_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("key")
            .to_string();
        (content, stem)
    } else {
        (
            key.to_string(),
            format!("key-{}", &key.trim()[..key.trim().len().min(8)]),
        )
    };
    let bytes = parse_pubkey_hex(&hex)?;
    let name = name.map(str::to_string).unwrap_or(default_name);
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("key name `{name}` must be [A-Za-z0-9._-]");
    }
    let store = trust_dir(dir);
    std::fs::create_dir_all(&store).with_context(|| format!("creating {}", store.display()))?;
    let path = store.join(format!("{name}.pub"));
    std::fs::write(&path, hex::encode(bytes))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// `(name, hex)` for every valid key in the store, sorted by name.
pub fn list(dir: &Path) -> Result<Vec<(String, String)>> {
    let store = trust_dir(dir);
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&store) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "pub")
            && let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(bytes) = parse_pubkey_hex(&content)
        {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            out.push((name, hex::encode(bytes)));
        }
    }
    out.sort();
    Ok(out)
}

pub fn remove(dir: &Path, name: &str) -> Result<()> {
    let path = trust_dir(dir).join(format!("{name}.pub"));
    if !path.is_file() {
        bail!(
            "no trusted key named `{name}` in {}",
            trust_dir(dir).display()
        );
    }
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_list_remove_round_trip_and_the_store_is_what_portcullis_reads() {
        let dir = tempfile::tempdir().unwrap();
        let hex_key = "ab".repeat(32);

        let path = add(dir.path(), &hex_key, Some("publisher")).unwrap();
        assert!(path.ends_with(".nucleus/trust/publisher.pub"));
        assert_eq!(
            list(dir.path()).unwrap(),
            vec![("publisher".to_string(), hex_key.clone())]
        );

        // The same store, read by the verifier's own loader.
        let store = portcullis::manifest_registry::TrustStore::load_from_dir(dir.path());
        assert_eq!(store.key_count(), 1);

        remove(dir.path(), "publisher").unwrap();
        assert!(list(dir.path()).unwrap().is_empty());
        assert!(
            remove(dir.path(), "publisher").is_err(),
            "removing twice is an error"
        );
    }

    #[test]
    fn a_malformed_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(add(dir.path(), "not-hex", None).is_err());
        assert!(
            add(dir.path(), &"ab".repeat(31), None).is_err(),
            "31 bytes is not a key"
        );
        assert!(add(dir.path(), &"ab".repeat(32), Some("../escape")).is_err());
    }

    #[test]
    fn keygen_writes_a_seed_and_its_public_half() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("publisher.key");
        keygen(&out).unwrap();
        let seed_hex = std::fs::read_to_string(&out).unwrap();
        let pub_hex = std::fs::read_to_string(dir.path().join("publisher.pub")).unwrap();
        let seed: [u8; 32] = hex::decode(seed_hex.trim()).unwrap().try_into().unwrap();
        assert_eq!(
            hex::encode(portcullis::manifest_registry::public_key_for_seed(&seed)),
            pub_hex
        );
        assert!(keygen(&out).is_err(), "never overwrite a key");
    }
}
