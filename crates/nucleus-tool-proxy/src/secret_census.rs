//! Everything this proxy holds or reads that a child must not reach (#3461).
//!
//! [`held`] destructures [`crate::Args`] with no `..` (ADR 0007 E-1). A new
//! flag therefore does not compile until it is classified here: held (and
//! how), or not held (and why). [`ENV_SECRETS`] is the same answer for the
//! secrets this process reads straight from its environment, outside clap.
//! The one decider of whether a child reaches an item is
//! [`crate::child_reach::ChildReach::admit`]. This module only says what
//! there is.
//!
//! An item is held only when this process reads it. A key path that is
//! passed but never read (`--identity-key` with no node client to use it)
//! is the launcher's file, not this process's secret. No launcher in this
//! repository writes one any more (#3471): the local driver delivers an
//! orchestrator's key on stdin (`--identity-key-on-stdin`), and every other
//! pod is handed none.

use std::path::Path;

use clap::parser::ValueSource;

use crate::child_reach::{At, Exposure, Held};

/// Secrets this process reads from its environment by name, outside clap.
/// Each is held when the variable is set and not empty.
pub(crate) const ENV_SECRETS: [&str; 9] = [
    // The host broker's capability key (`egress::broker_capability`).
    "NUCLEUS_TOOL_PROXY_BROKER_SECRET",
    // The pod's mediation signing seed (`art12_sink::mediation_seed_from_env`).
    "NUCLEUS_MEDIATION_SIGNING_KEY",
    // An orchestrator pod's caller token to the node (`node_client`).
    "NUCLEUS_POD_CALLER_TOKEN",
    // Orchestrator credentials passed through to sub-pods (`main`).
    "LLM_API_TOKEN",
    "GITHUB_TOKEN",
    // The audit uploader's minted object-store credential (`audit_log`).
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
];

/// What else the census needs to know: facts decided from the spec, which
/// the census does not re-decide (G-1).
pub(crate) struct Facts<'a> {
    /// `guest_request_proof::Config::from_spec` found a configuration, so
    /// the proxy keeps a request-proof replay ledger beside its audit log.
    pub(crate) guest_proof: bool,
    /// The pod has a workload, so with `guest_proof` the proxy provisions
    /// the workload-proof master key (`workload_request_proof`).
    pub(crate) workload: bool,
    /// Whether an environment variable is set and not empty.
    pub(crate) env_set: &'a dyn Fn(&str) -> bool,
}

/// A clap-parsed secret: on the command line or in the environment, as clap
/// found it, and nothing when it was left at its default.
fn sourced(matches: &clap::ArgMatches, id: &str, name: &'static str) -> Option<Held> {
    let at = match matches.value_source(id)? {
        ValueSource::CommandLine => At::Argv,
        ValueSource::EnvVariable => At::Env,
        ValueSource::DefaultValue => return None,
        // `ValueSource` is non-exhaustive: an unknown source is held as the
        // most reachable place (A-1), never as absent.
        _ => At::Argv,
    };
    Some(Held {
        name,
        exposure: Exposure::Secret,
        at,
    })
}

fn path(name: &'static str, exposure: Exposure, p: &Path) -> Held {
    Held {
        name,
        exposure,
        at: At::Path(p.to_path_buf()),
    }
}

/// The census: every item [`crate::Args`] makes this process hold or read.
/// One line per flag is the point: E-1 makes a new flag a compile error here.
pub(crate) fn held(args: &crate::Args, matches: &clap::ArgMatches, facts: &Facts<'_>) -> Vec<Held> {
    let crate::Args {
        // Decided against the opened file by `MemoryStoreArgs::open` (#3454).
        memory: _,
        decisions,
        spec,
        // A listen address.
        listen: _,
        announce_path,
        listen_unix,
        peer_uids,
        // The workload's own door: the workload is meant to reach it.
        workload_door: _,
        vsock_cid: _,
        vsock_port: _,
        // Refused by name before this runs (`retired::refuse_auth_secret`).
        auth_secret: _,
        auth_max_skew_secs: _,
        audit_log,
        workload_proof_state,
        audit_secret,
        art12_log,
        // A URL; the channel's key is `audit_secret`.
        art12_ship_url: _,
        approval_secret,
        // Verification keys: public, and a child cannot change this
        // process's argv or environment.
        approval_pubkeys: _,
        audit_webhook: _,
        // The destination; its credential is in `ENV_SECRETS`.
        #[cfg(feature = "remote-audit")]
            audit_s3_bucket: _,
        #[cfg(feature = "remote-audit")]
            audit_s3_prefix: _,
        #[cfg(feature = "remote-audit")]
            audit_s3_region: _,
        #[cfg(feature = "remote-audit")]
            audit_s3_endpoint: _,
        web_fetch_timeout_secs: _,
        web_fetch_max_bytes: _,
        require_attestation: _,
        unsandboxed: _,
        workload_without_landlock: _,
        allowed_kernel_hashes: _,
        allowed_rootfs_hashes: _,
        allowed_config_hashes: _,
        min_assurance: _,
        // A certificate: public.
        identity_cert: _,
        // SPIRE attests each caller itself: a child that connects is issued
        // its own identity, never this process's.
        spire_socket: _,
        mtls,
        tls_cert: _,
        tls_key,
        trust_bundle,
        trust_domain: _,
        policy_file,
        zero_prompt: _,
        drand_enabled: _,
        drand_url: _,
        drand_tolerance: _,
        drand_fail_mode: _,
        enable_pod_mgmt,
        node_url: _,
        node_grpc_url,
        identity_key,
        identity_key_on_stdin,
        identity_trust_bundle,
        delegation_ceiling: _,
        clearing,
        clearing_window_ms: _,
        authority_ledger,
        cert_root_pubkey: _,
        // This pod's own ceiling, verified against the pinned root and
        // presented nowhere: a child that reads it learns what the pod may
        // do, and gains none of it.
        pod_cert: _,
        // Only ever makes a refusal more informative, never an allow.
        pod_grant: _,
        // Verified once and presented nowhere (`session_token`); the node
        // provisions it as a scoped capability, not a secret. Every launcher
        // passes all three in the environment, none on the command line
        // (#3471), so the nonce is not in `/proc/<pid>/cmdline` should a
        // later consumer make it one.
        task_token: _,
        task_token_nonce: _,
        task_token_issuer: _,
        require_approval_bundle: _,
        #[cfg(feature = "mcp")]
            mcp: _,
    } = args;

    let mut held = vec![
        path("--spec", Exposure::Session, spec),
        path("--audit-log", Exposure::Session, audit_log),
    ];
    held.extend(
        announce_path
            .as_deref()
            .map(|p| path("--announce-path", Exposure::Session, p)),
    );
    held.extend(
        listen_unix
            .as_deref()
            .map(|p| path("--listen-unix", Exposure::Session, p)),
    );
    held.extend(peer_uids.iter().map(|uid| Held {
        name: "--peer-uids",
        exposure: Exposure::Session,
        at: At::FrontDoorPeer(*uid),
    }));
    if facts.guest_proof {
        held.push(path(
            "--audit-log (its request-proof replay ledger)",
            Exposure::Durable,
            &audit_log.with_extension("request-proofs.olog"),
        ));
        if facts.workload {
            held.push(path(
                "--workload-proof-state",
                Exposure::Secret,
                workload_proof_state,
            ));
        }
    }
    held.extend(
        sourced(matches, "audit_secret", "NUCLEUS_TOOL_PROXY_AUDIT_SECRET")
            .filter(|_| audit_secret.as_deref().is_some_and(|s| !s.is_empty())),
    );
    held.extend(
        sourced(
            matches,
            "approval_secret",
            "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
        )
        .filter(|_| !approval_secret.trim().is_empty()),
    );
    if let Some(log) = art12_log.as_deref() {
        held.push(path("--art12-log", Exposure::Session, log));
        held.push(path(
            "--art12-log (its mediation receipt log)",
            Exposure::Session,
            &log.with_file_name("mediation-receipts.jsonl"),
        ));
    }
    if *mtls {
        held.extend(
            tls_key
                .as_deref()
                .map(|p| path("--tls-key", Exposure::Secret, p)),
        );
    }
    held.extend(
        trust_bundle
            .as_deref()
            .map(|p| path("--trust-bundle", Exposure::Session, p)),
    );
    held.extend(
        identity_trust_bundle
            .as_deref()
            .map(|p| path("--identity-trust-bundle", Exposure::Session, p)),
    );
    held.extend(
        policy_file
            .as_deref()
            .map(|p| path("--policy-file", Exposure::Session, p)),
    );
    // Read only by the node clients (`node_identity::require`).
    if *enable_pod_mgmt || node_grpc_url.is_some() {
        held.extend(
            identity_key
                .as_deref()
                .map(|p| path("--identity-key", Exposure::Secret, p)),
        );
    }
    // Read from stdin at startup whether or not a node client uses it
    // (`node_identity::DeliveredKey::from_stdin`), so held whenever delivered.
    if *identity_key_on_stdin {
        held.push(Held {
            name: "--identity-key-on-stdin",
            exposure: Exposure::Secret,
            at: At::Delivered,
        });
    }
    // Opened only when a dimension clears (`authority_round::build`).
    if !clearing.is_empty() {
        held.extend(
            authority_ledger
                .as_deref()
                .map(|p| path("--authority-ledger", Exposure::Durable, p)),
        );
    }
    // The roots are the operator's; the bundles beside them are untrusted
    // bytes, verified against the roots on every read.
    held.extend(
        decisions
            .trust_roots()
            .map(|p| path("--decision-trust-roots", Exposure::Durable, p)),
    );
    held.extend(
        ENV_SECRETS
            .into_iter()
            .filter(|name| (facts.env_set)(name))
            .map(|name| Held {
                name,
                exposure: Exposure::Secret,
                at: At::Env,
            }),
    );
    held
}
