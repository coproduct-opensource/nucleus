//! The census of every TLS acceptor in the workspace (ADR 0016 D4, S4).
//!
//! D4: every mTLS path that grants authority on a pod SVID runs the launch
//! decision (`nucleus_identity::admit_peer_launch`) before anything is granted.
//! The shipping way to get that is to build the acceptor through
//! `TlsServerConfig` (directly, or through `MtlsConfig`/`MtlsListener`), whose
//! client verifier is `tls::LaunchCheckingClientVerifier`. This test holds the
//! closed list of every source site that constructs a TLS acceptor or a client
//! certificate verifier, each with the reason it satisfies D4, and reds on a
//! site that is not listed, or a listed one that is gone.
//!
//! # How a site is found
//!
//! Text, over every `.rs` file under `crates/`, counting the [`NEEDLES`] in the
//! part of each file before its first column-0 `#[cfg(test)]`. Test files
//! (`tests/`, `*_tests.rs`, `tests.rs`), examples and benches are skipped: a
//! test that builds a raw acceptor grants nothing. Comments and doc examples
//! count too, which errs toward listing a site, never toward missing one.
//!
//! # Adding an acceptor
//!
//! Build it through `TlsServerConfig` and add its row as [`Gate::Handshake`].
//! A listener that asks for no client certificate is [`Gate::ServerAuthOnly`],
//! and must not take authority from a pod SVID. Anything else needs its reason
//! written here and in ADR 0016's S4 row.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What constructs a TLS acceptor, a client-certificate verifier, or an
/// authenticated peer protocol.
const NEEDLES: &[&str] = &[
    "ServerConfig::builder",
    "TlsServerConfig::new",
    "MtlsListener::new",
    "ServerTlsConfig::new",
    "client_ca_root",
    "with_client_cert_verifier",
    "WebPkiClientVerifier::builder",
    "ClientCertVerifier for",
    "TlsAcceptor::from",
    "impl ProtocolHandler for",
];

/// How a site meets D4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// The acceptor is built through `TlsServerConfig`, so the handshake runs
    /// `LaunchCheckingClientVerifier`.
    Handshake,
    /// The verifier itself, or the builder every `Handshake` site goes through.
    TheVerifier,
    /// Client certificates are verified by the transport (tonic), and the
    /// launch decision runs per request in the interceptor, before any handler.
    /// D4's runner-up; moving it to the handshake is S4's remaining work.
    PerRequest,
    /// The peer is authenticated by a hail the caller checks with
    /// `admit_peer_launch`, after a transport that authenticates no SVID.
    CallerChecks,
    /// No client certificate is asked for; authority comes from elsewhere (a
    /// bearer token, or nothing: a public, content-addressed document).
    ServerAuthOnly,
    /// A `ClientCertVerifier` no acceptor in the workspace is built with. A site
    /// that starts using it reds this census by its `with_client_cert_verifier`.
    UnusedVerifier,
}

/// One row: the file, the needle, how many times it appears, and why the site
/// meets D4.
struct Site {
    file: &'static str,
    needle: &'static str,
    count: usize,
    gate: Gate,
    why: &'static str,
}

const SITES: &[Site] = &[
    Site {
        file: "crates/nucleus-identity/src/tls.rs",
        needle: "ServerConfig::builder",
        count: 2,
        gate: Gate::TheVerifier,
        why: "TlsServerConfig::build and build_with_resolver, each with LaunchCheckingClientVerifier",
    },
    Site {
        file: "crates/nucleus-identity/src/tls.rs",
        needle: "with_client_cert_verifier",
        count: 2,
        gate: Gate::TheVerifier,
        why: "the two builders above install LaunchCheckingClientVerifier",
    },
    Site {
        file: "crates/nucleus-identity/src/tls.rs",
        needle: "WebPkiClientVerifier::builder",
        count: 1,
        gate: Gate::TheVerifier,
        why: "the chain half of LaunchCheckingClientVerifier",
    },
    Site {
        file: "crates/nucleus-identity/src/tls.rs",
        needle: "ClientCertVerifier for",
        count: 1,
        gate: Gate::TheVerifier,
        why: "LaunchCheckingClientVerifier: chain, then admit_peer_launch",
    },
    Site {
        file: "crates/nucleus-identity/src/tls.rs",
        needle: "TlsServerConfig::new",
        count: 1,
        gate: Gate::TheVerifier,
        why: "the module's doc example",
    },
    Site {
        file: "crates/nucleus-identity/src/tls.rs",
        needle: "TlsAcceptor::from",
        count: 1,
        gate: Gate::TheVerifier,
        why: "TlsServerConfig::build_acceptor",
    },
    Site {
        file: "crates/nucleus-identity/src/mtls.rs",
        needle: "TlsServerConfig::new",
        count: 2,
        gate: Gate::Handshake,
        why: "MtlsConfig::build_acceptor and build_rotating_acceptor",
    },
    Site {
        file: "crates/nucleus-identity/src/mtls.rs",
        needle: "TlsAcceptor::from",
        count: 1,
        gate: Gate::Handshake,
        why: "the rotating acceptor over a TlsServerConfig config",
    },
    Site {
        file: "crates/nucleus-identity/src/mtls.rs",
        needle: "MtlsListener::new",
        count: 1,
        gate: Gate::Handshake,
        why: "serve_mtls, over MtlsConfig",
    },
    Site {
        file: "crates/nucleus-node/src/identity.rs",
        needle: "MtlsListener::new",
        count: 1,
        gate: Gate::Handshake,
        why: "the node's HTTPS API (auth::spiffe_context_for_request reads its peer)",
    },
    Site {
        file: "crates/nucleus-tool-proxy/src/main.rs",
        needle: "MtlsListener::new",
        count: 1,
        gate: Gate::Handshake,
        why: "the tool-proxy's mTLS listener (auth::verify_spiffe_mtls reads its peer)",
    },
    Site {
        file: "crates/nucleus-node/src/grpc_tls.rs",
        needle: "ServerTlsConfig::new",
        count: 1,
        gate: Gate::PerRequest,
        why: "the node's gRPC API: auth::authenticate_grpc_request runs admit_peer_launch",
    },
    Site {
        file: "crates/nucleus-node/src/grpc_tls.rs",
        needle: "client_ca_root",
        count: 1,
        gate: Gate::PerRequest,
        why: "the gRPC listener's client CA, read from the bundle the interceptor admits against",
    },
    Site {
        file: "crates/nucleus-spiffe-hail/src/lib.rs",
        needle: "impl ProtocolHandler for",
        count: 1,
        gate: Gate::CallerChecks,
        why: "serves the hail; authenticate_hail runs admit_peer_launch on it",
    },
    Site {
        file: "crates/nucleus-node/src/tls_ingress.rs",
        needle: "ServerConfig::builder",
        count: 2,
        gate: Gate::ServerAuthOnly,
        why: "federation ingress and the public evidence listener: with_no_client_auth",
    },
    Site {
        file: "crates/nucleus-node/src/tls_ingress.rs",
        needle: "TlsAcceptor::from",
        count: 1,
        gate: Gate::ServerAuthOnly,
        why: "the server-auth-only acceptor above",
    },
    Site {
        file: "crates/nucleus-identity/src/verifier.rs",
        needle: "WebPkiClientVerifier::builder",
        count: 1,
        gate: Gate::UnusedVerifier,
        why: "TrustDomainVerifier's chain half",
    },
    Site {
        file: "crates/nucleus-identity/src/verifier.rs",
        needle: "ClientCertVerifier for",
        count: 1,
        gate: Gate::UnusedVerifier,
        why: "TrustDomainVerifier: exported, built into no acceptor",
    },
];

fn workspace_crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn is_test_or_example(rel: &str) -> bool {
    let file = rel.rsplit('/').next().unwrap_or(rel);
    rel.split('/')
        .any(|c| matches!(c, "tests" | "examples" | "benches" | "target"))
        || file.ends_with("_tests.rs")
        || file == "tests.rs"
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The text of `src` before its first column-0 `#[cfg(test)]`.
fn production_part(src: &str) -> &str {
    let mut at = 0;
    for line in src.split_inclusive('\n') {
        if line.trim_end() == "#[cfg(test)]" {
            return &src[..at];
        }
        at += line.len();
    }
    src
}

/// `(file, needle) → count` over the workspace's production sources.
fn found() -> BTreeMap<(String, &'static str), usize> {
    let crates = workspace_crates();
    let root = crates.parent().expect("the workspace root");
    let mut files = Vec::new();
    walk(&crates, &mut files);
    // A census whose population is empty passes everything: it must have read
    // the workspace (every crate's sources), not an empty directory.
    assert!(files.len() > 500, "read only {} .rs files", files.len());
    let mut found = BTreeMap::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .expect("under the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_or_example(&rel) {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let prod = production_part(&src);
        for needle in NEEDLES {
            let count = prod.matches(needle).count();
            if count > 0 {
                found.insert((rel.clone(), *needle), count);
            }
        }
    }
    found
}

#[test]
fn every_tls_acceptor_is_listed_with_how_it_meets_d4() {
    let found = found();
    let listed: BTreeMap<(String, &'static str), usize> = SITES
        .iter()
        .map(|s| ((s.file.to_string(), s.needle), s.count))
        .collect();
    assert_eq!(listed.len(), SITES.len(), "a site is listed twice");

    let unlisted: Vec<String> = found
        .iter()
        .filter(|(k, n)| listed.get(*k) != Some(n))
        .map(|((file, needle), n)| format!("{file}: `{needle}` x{n}"))
        .collect();
    let stale: Vec<String> = listed
        .iter()
        .filter(|(k, n)| found.get(*k) != Some(n))
        .map(|((file, needle), n)| format!("{file}: `{needle}` x{n}"))
        .collect();
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "TLS acceptor census (ADR 0016 D4) differs from the source.\n\
         unlisted or recounted (build it through TlsServerConfig, then list it):\n  {}\n\
         listed but not found:\n  {}",
        unlisted.join("\n  "),
        stale.join("\n  ")
    );
}

/// Each row's gate is checked against the file it names, as far as text can:
/// a server-auth-only site asks for no client certificate, a per-request site
/// runs the decision in its interceptor, and every other row says why.
#[test]
fn each_listed_gate_holds_in_its_file() {
    let root = workspace_crates();
    let root = root.parent().expect("the workspace root");
    for site in SITES {
        assert!(!site.why.is_empty(), "{}: `{}`", site.file, site.needle);
        let src = std::fs::read_to_string(root.join(site.file))
            .unwrap_or_else(|e| panic!("{}: {e}", site.file));
        let prod = production_part(&src);
        // Exhaustive (E-2): a gate added later says here what it checks.
        let (evidence, at_least) = match site.gate {
            Gate::ServerAuthOnly if site.needle == "ServerConfig::builder" => {
                ("with_no_client_auth", site.count)
            }
            Gate::TheVerifier if site.needle == "ServerConfig::builder" => {
                ("LaunchCheckingClientVerifier::new", site.count)
            }
            Gate::PerRequest => ("admit_peer_launch", 0),
            Gate::CallerChecks => ("admit_peer_launch", 1),
            Gate::Handshake | Gate::TheVerifier | Gate::ServerAuthOnly | Gate::UnusedVerifier => {
                continue;
            }
        };
        assert!(
            prod.matches(evidence).count() >= at_least,
            "{} ({:?}, {}): expected `{evidence}` at least {at_least}x",
            site.file,
            site.gate,
            site.why
        );
    }
    // The per-request site's decision lives in the node's auth module.
    let auth = std::fs::read_to_string(root.join("crates/nucleus-node/src/auth.rs")).unwrap();
    assert!(
        production_part(&auth).contains("nucleus_identity::admit_peer_launch"),
        "the gRPC interceptor (auth::authenticate_grpc_request) runs admit_peer_launch"
    );
}
