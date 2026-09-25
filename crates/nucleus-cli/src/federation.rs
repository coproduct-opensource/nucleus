//! `nucleus federation` — publish, inspect and rotate a node's federation
//! issuer key (ADR 0010, profile `docs/federated-upstream-profile.md`).
//!
//! A node signs the ES256 assertions its pods' upstream credentials are
//! exchanged for. A provider accepts them only after the operator has told it
//! about this issuer: where its keys are (discovery, a JWKS URL, or a JWKS
//! pasted inline) and which claims a rule should require. This command is how
//! the operator gets those facts out of the node, and how the key is changed
//! without any provider refusing an assertion along the way.
//!
//! # Why here, and not a `nucleus-node` subcommand
//!
//! It is an operator action on a node host, like `nucleus trust` and
//! `nucleus identity`, and those live in this CLI. `nucleus-node` is a daemon
//! whose single flat `Args` is the daemon's configuration (and whose `main.rs`
//! is at its line ceiling); a subcommand there would share a parser with
//! secrets it has no use for. What must NOT be duplicated — which files hold
//! which key, how rotation is sequenced, what the discovery document says —
//! lives in `nucleus_federation::keyring`, which the node's signer and this
//! command both call. The flags take the node's own environment variables
//! (`NUCLEUS_NODE_STATE_DIR`, `NUCLEUS_FEDERATION_ISSUER`,
//! `NUCLEUS_NODE_UPSTREAMS`), so run in the node's environment the command
//! describes the node that is actually running.
//!
//! # What it never prints
//!
//! Private key material. Every output is built from `PublicJwk` values; the
//! private key is read (read-only, after the same permission and owner checks
//! the node applies) only to derive its public half, and `ring` does not hand
//! the scalar back at all. The tests assert on every byte written.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use nucleus_federation::keyring::{
    self, DISCOVERY_PATH, JWKS_PATH, KeyDir, KeyState, RotationPolicy, Transition,
};

#[derive(Args)]
pub struct FederationArgs {
    #[command(subcommand)]
    pub command: FederationCommand,
}

#[derive(Subcommand)]
pub enum FederationCommand {
    /// Publish the issuer's discovery document and JWKS, or print the claims a
    /// provider rule should require.
    Issuer(IssuerArgs),
    /// Rotate the assertion-signing key: stage, promote, retire.
    Rotate(RotateArgs),
}

#[derive(Args)]
#[command(group(ArgGroup::new("output").required(true).args(["export", "jwks", "claims_for"])))]
pub struct IssuerArgs {
    /// The node's `--federation-issuer`, byte for byte: providers compare it
    /// to every assertion's `iss` exactly.
    #[arg(long, env = "NUCLEUS_FEDERATION_ISSUER")]
    issuer: Option<String>,
    /// The node's state directory (where its issuer key lives).
    #[arg(long, env = "NUCLEUS_NODE_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Write `.well-known/openid-configuration` and `.well-known/jwks.json`
    /// under this directory, for static hosting at the issuer URL.
    #[arg(long, value_name = "OUT_DIR")]
    export: Option<PathBuf>,
    /// Print the JWKS, for a provider that takes it inline.
    #[arg(long)]
    jwks: bool,
    /// Print the claim matchers a provider rule for this upstream (a registry
    /// `[[upstream]]` name) should require.
    #[arg(long, value_name = "UPSTREAM", requires = "upstreams")]
    claims_for: Option<String>,
    /// The node's upstream registry (`--upstreams`).
    #[arg(long, env = "NUCLEUS_NODE_UPSTREAMS")]
    upstreams: Option<PathBuf>,
    /// With `--claims-for`: also require this `nucleus_tenant` (when one
    /// provider account serves one tenant).
    #[arg(long, requires = "claims_for")]
    tenant: Option<String>,
}

#[derive(Args)]
#[command(group(ArgGroup::new("step").required(true).args(["stage", "promote", "retire", "status"])))]
pub struct RotateArgs {
    /// The node's state directory (where its issuer key lives).
    #[arg(long, env = "NUCLEUS_NODE_STATE_DIR")]
    state_dir: PathBuf,
    /// Generate the next key and publish it beside the current one.
    #[arg(long)]
    stage: bool,
    /// Make the staged key current (refused until it has been published for
    /// the overlap). The running node picks it up at its next assertion.
    #[arg(long)]
    promote: bool,
    /// Stop publishing the previous key (refused until its last assertion
    /// can no longer be accepted).
    #[arg(long)]
    retire: bool,
    /// Show the keys and when the next step is allowed.
    #[arg(long)]
    status: bool,
    /// How long providers cache this issuer's JWKS.
    #[arg(long, default_value_t = keyring::DEFAULT_JWKS_CACHE_TTL.as_secs())]
    jwks_cache_ttl_secs: u64,
    /// The longest assertion the node signs. Must be at least the registry's
    /// largest `assertion_ttl_secs`.
    #[arg(long, default_value_t = nucleus_federation::MAX_TTL.as_secs())]
    max_assertion_ttl_secs: u64,
    /// The node's upstream registry; when given, `--max-assertion-ttl-secs` is
    /// checked against it.
    #[arg(long, env = "NUCLEUS_NODE_UPSTREAMS")]
    upstreams: Option<PathBuf>,
}

pub fn execute(args: FederationArgs) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before 1970")?
        .as_secs();
    run(
        args,
        now,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

/// The command with its clock and streams injected, so tests can drive a
/// rotation across hours in one run and inspect every byte it wrote.
fn run(args: FederationArgs, now: u64, out: &mut dyn Write, err: &mut dyn Write) -> Result<()> {
    match args.command {
        FederationCommand::Issuer(a) => issuer(a, now, out, err),
        FederationCommand::Rotate(a) => rotate(a, now, out, err),
    }
}

fn need_issuer(issuer: Option<&str>) -> Result<&str> {
    let issuer = issuer.context("--issuer (or NUCLEUS_FEDERATION_ISSUER) is required")?;
    if !nucleus_federation::is_valid_issuer(issuer) {
        bail!("--issuer must be an https URL with a host, got {issuer:?}");
    }
    Ok(issuer)
}

fn need_state(state_dir: Option<&Path>, now: u64) -> Result<KeyState> {
    let dir = state_dir.context("--state-dir (or NUCLEUS_NODE_STATE_DIR) is required")?;
    Ok(KeyDir::new(dir).state(now)?)
}

fn issuer(a: IssuerArgs, now: u64, out: &mut dyn Write, err: &mut dyn Write) -> Result<()> {
    if let Some(name) = &a.claims_for {
        let issuer = need_issuer(a.issuer.as_deref())?;
        let registry = a
            .upstreams
            .as_deref()
            .context("--claims-for needs --upstreams")?;
        let rule = claims_for(issuer, &read_registry(registry)?, name, a.tenant.as_deref())?;
        writeln!(out, "{}", serde_json::to_string_pretty(&rule)?)?;
        writeln!(
            err,
            "warning: every pod on this node signs under the same `iss`. A provider rule that \
             matches `iss` alone, or a `sub` prefix, matches EVERY pod on the node (THREAT_MODEL \
             T05). Require `aud` and `nucleus_upstream` exactly as printed; add `nucleus_tenant` \
             when one provider account serves one tenant. Never match on `sub`: it is per pod."
        )?;
        return Ok(());
    }

    let state = need_state(a.state_dir.as_deref(), now)?;
    if a.jwks {
        writeln!(out, "{}", serde_json::to_string_pretty(&state.jwks())?)?;
        return Ok(());
    }
    if let Some(dir) = &a.export {
        let issuer = need_issuer(a.issuer.as_deref())?;
        let discovery = keyring::discovery_document(issuer)?;
        let d = write_public(dir, DISCOVERY_PATH, &discovery)?;
        let j = write_public(dir, JWKS_PATH, &state.jwks())?;
        writeln!(err, "wrote {}", d.display())?;
        writeln!(err, "wrote {}", j.display())?;
        writeln!(
            err,
            "serve both over https at {}/{DISCOVERY_PATH} and {}",
            issuer.trim_end_matches('/'),
            keyring::jwks_uri(issuer)
        )?;
        for k in state.published() {
            writeln!(err, "  published kid {}", k.kid)?;
        }
    }
    Ok(())
}

/// Write a public JSON document under `root`: a temporary beside it, then a
/// rename, so a static host serving `root` never sees a half-written JWKS.
fn write_public(root: &Path, rel: &str, doc: &serde_json::Value) -> Result<PathBuf> {
    let path = root.join(rel);
    let parent = path.parent().context("export path has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("doc"),
        std::process::id()
    ));
    let mut bytes = serde_json::to_vec_pretty(doc)?;
    bytes.push(b'\n');
    std::fs::write(&tmp, &bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(path)
}

/// The recommended provider-rule matchers for `name`.
///
/// Exact `iss`, exact `aud` (the registry's audience for that upstream — the
/// only audience the node will ever put on its assertions), and
/// `nucleus_upstream`; `nucleus_tenant` if asked. The node's mint decision is
/// the real gate (ADR 0010); these make the provider's rule a second one.
fn claims_for(
    issuer: &str,
    registry: &toml::Table,
    name: &str,
    tenant: Option<&str>,
) -> Result<serde_json::Value> {
    let entry = upstream_entries(registry)
        .find(|e| e.get("name").and_then(toml::Value::as_str) == Some(name))
        .with_context(|| format!("no [[upstream]] named {name:?} in the registry"))?;
    let audience = entry
        .get("credential")
        .and_then(|c| c.get("federated"))
        .and_then(|f| f.get("audience"))
        .and_then(toml::Value::as_str)
        .with_context(|| {
            format!("upstream {name:?} has no [upstream.credential.federated] audience: it is not federated")
        })?;
    let mut require = serde_json::Map::new();
    require.insert("iss".into(), issuer.into());
    require.insert("aud".into(), audience.into());
    require.insert("nucleus_upstream".into(), name.into());
    if let Some(t) = tenant {
        require.insert("nucleus_tenant".into(), t.into());
    }
    Ok(serde_json::json!({
        "issuer": issuer,
        "discovery": format!("{}/{DISCOVERY_PATH}", issuer.trim_end_matches('/')),
        "jwks_uri": keyring::jwks_uri(issuer),
        "require": require,
        "never_match": ["sub"],
    }))
}

/// Parse the registry as plain TOML. Only the fields this command reads are
/// looked at; the node's own parser (`nucleus-node/src/upstreams.rs`, which
/// refuses unknown fields) decides whether the file is valid at all, so an
/// entry this accepts and the node refuses is refused where it matters.
fn read_registry(path: &Path) -> Result<toml::Table> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    text.parse::<toml::Table>()
        .with_context(|| format!("parse {}", path.display()))
}

fn upstream_entries(registry: &toml::Table) -> impl Iterator<Item = &toml::Table> {
    registry
        .get("upstream")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
}

/// The longest assertion any federated upstream in the registry is signed
/// for (`assertion_ttl_secs`, default 300 as in the node).
fn registry_max_assertion_ttl(registry: &toml::Table) -> u64 {
    upstream_entries(registry)
        .filter_map(|e| e.get("credential")?.get("federated"))
        .map(|f| {
            f.get("assertion_ttl_secs")
                .and_then(toml::Value::as_integer)
                .and_then(|n| u64::try_from(n).ok())
                .unwrap_or(nucleus_federation::DEFAULT_TTL.as_secs())
        })
        .max()
        .unwrap_or(0)
}

fn rotate(a: RotateArgs, now: u64, out: &mut dyn Write, err: &mut dyn Write) -> Result<()> {
    let policy = RotationPolicy::new(
        Duration::from_secs(a.jwks_cache_ttl_secs),
        Duration::from_secs(a.max_assertion_ttl_secs),
    )?;
    if let Some(path) = &a.upstreams {
        let longest = registry_max_assertion_ttl(&read_registry(path)?);
        if a.max_assertion_ttl_secs < longest {
            bail!(
                "--max-assertion-ttl-secs {} is shorter than the registry's longest \
                 assertion_ttl_secs ({longest}): the retire window would end while an \
                 assertion signed by the old key is still valid",
                a.max_assertion_ttl_secs
            );
        }
    }
    let keys = KeyDir::new(&a.state_dir);
    let (step, transition) = if a.stage {
        ("stage", Some(keys.stage(now)?))
    } else if a.promote {
        ("promote", Some(keys.promote(now, &policy)?))
    } else if a.retire {
        ("retire", Some(keys.retire(now, &policy)?))
    } else {
        ("status", None)
    };
    let state = match &transition {
        Some(t) => t.after.clone(),
        None => keys.state(now)?,
    };
    report(step, transition.as_ref(), &state, &policy, out, err)
}

fn when(unix: u64) -> String {
    i64::try_from(unix)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map_or_else(|| unix.to_string(), |t| t.to_rfc3339())
}

/// stdout: one JSON object (the state, the diff, the JWKS to publish) for
/// scripts. stderr: the same for a person, including what to re-register.
fn report(
    step: &str,
    t: Option<&Transition>,
    state: &KeyState,
    policy: &RotationPolicy,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<()> {
    let promote_at = state.promote_allowed_at(policy);
    let retire_at = state.retire_allowed_at(policy);
    let (added, removed) = t.map_or((vec![], vec![]), |t| (t.added(), t.removed()));
    let doc = serde_json::json!({
        "step": step,
        "current": state.current.kid,
        "next": state.next.as_ref().map(|n| serde_json::json!({
            "kid": n.jwk.kid, "staged_at": n.staged_at, "promote_allowed_at": promote_at,
        })),
        "prev": state.prev.as_ref().map(|p| serde_json::json!({
            "kid": p.jwk.kid, "promoted_at": p.promoted_at, "retire_allowed_at": retire_at,
        })),
        "jwks_added": added,
        "jwks_removed": removed,
        "jwks": state.jwks(),
    });
    writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?;

    writeln!(err, "current  {}  (signing)", state.current.kid)?;
    if let (Some(n), Some(at)) = (&state.next, promote_at) {
        writeln!(
            err,
            "next     {}  staged {}; promote allowed from {} (overlap {} s)",
            n.jwk.kid,
            when(n.staged_at),
            when(at),
            policy.promote_overlap().as_secs()
        )?;
    }
    if let (Some(p), Some(at)) = (&state.prev, retire_at) {
        writeln!(
            err,
            "prev     {}  promoted {}; retire allowed from {}",
            p.jwk.kid,
            when(p.promoted_at),
            when(at)
        )?;
    }
    if t.is_some() {
        if added.is_empty() && removed.is_empty() {
            writeln!(err, "JWKS unchanged: nothing to re-register.")?;
        } else {
            writeln!(
                err,
                "JWKS changed. Where the JWKS is registered INLINE, replace it with the `jwks` \
                 above now; for static hosting, re-run `nucleus federation issuer --export` and \
                 publish it:"
            )?;
            for k in &added {
                writeln!(err, "  + {k}")?;
            }
            for k in &removed {
                writeln!(err, "  - {k}")?;
            }
        }
    }
    if step == "stage" {
        writeln!(
            err,
            "The overlap is counted from the stage. If publishing the new JWKS takes longer \
             than a moment, wait that much longer before --promote."
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    const ISSUER: &str = "https://federation.nodes.example.invalid";
    const T0: u64 = 1_790_000_000;

    const REGISTRY: &str = r#"
[[upstream]]
name         = "model-api"
base_url     = "https://api.model.example.invalid"
header       = "authorization"
value_prefix = "Bearer "

[upstream.credential.federated]
token_endpoint     = "https://auth.model.example.invalid/oauth/token"
grant              = "token-exchange"
encoding           = "form"
audience           = "https://auth.model.example.invalid"
assertion_ttl_secs = 600

[upstream.credential.federated.params]
policy_id = "example-policy-0001"

[[upstream]]
name         = "search-api"
base_url     = "https://search.example.invalid"
header       = "x-api-key"
value_prefix = ""

[upstream.credential.env]
var = "SEARCH_API_TOKEN"
"#;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: Top,
    }
    #[derive(Subcommand)]
    enum Top {
        Federation(FederationArgs),
    }

    /// Run `nucleus federation <argv>` at `now`; (ok, stdout, stderr).
    fn cli(argv: &[&str], now: u64) -> (Result<()>, Vec<u8>, Vec<u8>) {
        let mut full = vec!["nucleus", "federation"];
        full.extend_from_slice(argv);
        let Top::Federation(args) = Cli::try_parse_from(full).expect("parses").cmd;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let r = run(args, now, &mut out, &mut err);
        (r, out, err)
    }

    fn ok(argv: &[&str], now: u64) -> (Vec<u8>, Vec<u8>) {
        let (r, out, err) = cli(argv, now);
        if let Err(e) = r {
            panic!("{argv:?} failed: {e:#}");
        }
        (out, err)
    }

    fn json(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).expect("stdout is JSON")
    }

    fn node_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        KeyDir::new(dir.path()).create_current().unwrap();
        dir
    }

    fn kids(jwks: &serde_json::Value) -> Vec<String> {
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn export_writes_a_discovery_document_for_exactly_this_issuer() {
        let node = node_dir();
        let state = node.path().to_str().unwrap();
        let site = tempfile::tempdir().unwrap();
        let out_dir = site.path().to_str().unwrap();
        for iss in [ISSUER, "https://federation.nodes.example.invalid/node-7"] {
            ok(
                &[
                    "issuer",
                    "--issuer",
                    iss,
                    "--state-dir",
                    state,
                    "--export",
                    out_dir,
                ],
                T0,
            );
            let disco: serde_json::Value = serde_json::from_slice(
                &std::fs::read(site.path().join(".well-known/openid-configuration")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                disco["issuer"].as_str(),
                Some(iss),
                "issuer must be byte-for-byte"
            );
            let jwks_uri = disco["jwks_uri"].as_str().unwrap();
            assert_eq!(jwks_uri, format!("{iss}/.well-known/jwks.json"));
            assert_eq!(
                disco["id_token_signing_alg_values_supported"],
                serde_json::json!([nucleus_federation::SIGNING_ALG])
            );
        }
        let exported: serde_json::Value = serde_json::from_slice(
            &std::fs::read(site.path().join(".well-known/jwks.json")).unwrap(),
        )
        .unwrap();
        let (printed, _) = ok(&["issuer", "--state-dir", state, "--jwks"], T0);
        assert_eq!(
            exported,
            json(&printed),
            "--export and --jwks publish the same JWKS"
        );
        assert_eq!(kids(&exported).len(), 1);

        // An issuer the node would refuse is refused here too.
        let (r, _, _) = cli(
            &[
                "issuer",
                "--issuer",
                "http://x.example.invalid",
                "--state-dir",
                state,
                "--export",
                out_dir,
            ],
            T0,
        );
        assert!(r.is_err());
    }

    #[test]
    fn the_jwks_carries_current_and_next_once_staged() {
        let node = node_dir();
        let state = node.path().to_str().unwrap();
        let (before, _) = ok(&["issuer", "--state-dir", state, "--jwks"], T0);
        let current = kids(&json(&before));
        let (staged, err) = ok(&["rotate", "--state-dir", state, "--stage"], T0);
        let staged = json(&staged);
        let next = staged["next"]["kid"].as_str().unwrap().to_string();
        assert_eq!(staged["jwks_added"], serde_json::json!([next]));
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains(&format!("+ {next}"))
        );

        let (after, _) = ok(&["issuer", "--state-dir", state, "--jwks"], T0);
        let after = json(&after);
        assert_eq!(kids(&after), vec![current[0].clone(), next]);
        for k in after["keys"].as_array().unwrap() {
            assert_eq!(k["kty"], "EC");
            assert_eq!(k["crv"], "P-256");
            assert_eq!(k["use"], "sig");
            assert!(k.get("d").is_none(), "a JWK carried a private member");
        }
    }

    #[test]
    fn claims_for_prints_exact_matchers_from_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let reg = dir.path().join("upstreams.toml");
        std::fs::write(&reg, REGISTRY).unwrap();
        let reg = reg.to_str().unwrap();
        let (out, err) = ok(
            &[
                "issuer",
                "--issuer",
                ISSUER,
                "--claims-for",
                "model-api",
                "--upstreams",
                reg,
                "--tenant",
                "tenant-a.example.invalid",
            ],
            T0,
        );
        let rule = json(&out);
        assert_eq!(
            rule["require"],
            serde_json::json!({
                "iss": ISSUER,
                "aud": "https://auth.model.example.invalid",
                "nucleus_upstream": "model-api",
                "nucleus_tenant": "tenant-a.example.invalid",
            })
        );
        assert_eq!(rule["never_match"], serde_json::json!(["sub"]));
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("matches EVERY pod on the node"), "{err}");

        // Without --tenant, no tenant matcher.
        let (out, _) = ok(
            &[
                "issuer",
                "--issuer",
                ISSUER,
                "--claims-for",
                "model-api",
                "--upstreams",
                reg,
            ],
            T0,
        );
        assert!(json(&out)["require"].get("nucleus_tenant").is_none());

        // A static-credential upstream has no audience to match; an unknown
        // name is not in the registry.
        for name in ["search-api", "nope"] {
            let (r, out, _) = cli(
                &[
                    "issuer",
                    "--issuer",
                    ISSUER,
                    "--claims-for",
                    name,
                    "--upstreams",
                    reg,
                ],
                T0,
            );
            assert!(r.is_err(), "{name}");
            assert!(out.is_empty());
        }
    }

    /// Through the CLI, with the clock injected: promote refused one second
    /// before the overlap, allowed at it; retire likewise.
    #[test]
    fn a_rotation_waits_out_both_windows() {
        let node = node_dir();
        let state = node.path().to_str().unwrap();
        ok(&["rotate", "--state-dir", state, "--stage"], T0);
        let overlap = RotationPolicy::default().promote_overlap().as_secs();
        let (r, _, _) = cli(
            &["rotate", "--state-dir", state, "--promote"],
            T0 + overlap - 1,
        );
        assert!(format!("{:#}", r.unwrap_err()).contains("too early to promote"));

        let (out, err) = ok(&["rotate", "--state-dir", state, "--promote"], T0 + overlap);
        let promoted = json(&out);
        assert_eq!(promoted["jwks_added"], serde_json::json!([]));
        assert_eq!(promoted["jwks_removed"], serde_json::json!([]));
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("nothing to re-register")
        );
        let prev = promoted["prev"]["kid"].as_str().unwrap().to_string();

        let window = RotationPolicy::default().retire_after().as_secs();
        let at = T0 + overlap;
        let (r, _, _) = cli(
            &["rotate", "--state-dir", state, "--retire"],
            at + window - 1,
        );
        assert!(r.is_err());
        let (out, _) = ok(&["rotate", "--state-dir", state, "--retire"], at + window);
        assert_eq!(json(&out)["jwks_removed"], serde_json::json!([prev]));
    }

    #[test]
    fn a_max_assertion_ttl_below_the_registry_is_refused() {
        let node = node_dir();
        let state = node.path().to_str().unwrap();
        let reg = node.path().join("upstreams.toml");
        std::fs::write(&reg, REGISTRY).unwrap();
        let reg = reg.to_str().unwrap();
        let (r, _, _) = cli(
            &[
                "rotate",
                "--state-dir",
                state,
                "--status",
                "--upstreams",
                reg,
                "--max-assertion-ttl-secs",
                "300",
            ],
            T0,
        );
        assert!(format!("{:#}", r.unwrap_err()).contains("longest assertion_ttl_secs (600)"));
        ok(
            &[
                "rotate",
                "--state-dir",
                state,
                "--status",
                "--upstreams",
                reg,
                "--max-assertion-ttl-secs",
                "600",
            ],
            T0,
        );
    }

    /// The P-256 private scalar inside a ring PKCS#8 document: the 32 bytes
    /// after ECPrivateKey's `INTEGER 1, OCTET STRING (32)` header.
    fn private_scalar(der: &[u8]) -> Vec<u8> {
        let hdr = [0x02, 0x01, 0x01, 0x04, 0x20];
        let at = der
            .windows(hdr.len())
            .position(|w| w == hdr)
            .expect("ECPrivateKey header");
        der[at + hdr.len()..at + hdr.len() + 32].to_vec()
    }

    fn encodings(secret: &[u8]) -> Vec<Vec<u8>> {
        use base64::Engine as _;
        use base64::engine::general_purpose::{
            STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
        };
        vec![
            secret.to_vec(),
            hex::encode(secret).into_bytes(),
            hex::encode_upper(secret).into_bytes(),
            STANDARD.encode(secret).into_bytes(),
            STANDARD_NO_PAD.encode(secret).into_bytes(),
            URL_SAFE.encode(secret).into_bytes(),
            URL_SAFE_NO_PAD.encode(secret).into_bytes(),
        ]
    }

    /// Every byte every subcommand writes — stdout, stderr and the exported
    /// files — through a whole rotation, searched for every key's private
    /// scalar and PKCS#8 document in raw, hex and base64 forms.
    #[test]
    fn no_output_ever_carries_private_key_material() {
        let node = node_dir();
        let state = node.path().to_str().unwrap();
        let site = tempfile::tempdir().unwrap();
        let reg = node.path().join("upstreams.toml");
        std::fs::write(&reg, REGISTRY).unwrap();
        let reg = reg.to_str().unwrap();
        let overlap = RotationPolicy::default().promote_overlap().as_secs();
        let window = RotationPolicy::default().retire_after().as_secs();

        let mut written: Vec<u8> = Vec::new();
        let mut secrets: Vec<Vec<u8>> = Vec::new();
        let collect_secrets = |secrets: &mut Vec<Vec<u8>>| {
            for f in [
                keyring::CURRENT_KEY_FILE,
                keyring::NEXT_KEY_FILE,
                keyring::PREV_KEY_FILE,
            ] {
                if let Ok(der) = std::fs::read(node.path().join(f)) {
                    secrets.extend(encodings(&private_scalar(&der)));
                    secrets.extend(encodings(&der));
                }
            }
        };
        let steps: Vec<(Vec<&str>, u64)> = vec![
            (vec!["issuer", "--state-dir", state, "--jwks"], T0),
            (
                vec![
                    "issuer",
                    "--issuer",
                    ISSUER,
                    "--state-dir",
                    state,
                    "--export",
                    site.path().to_str().unwrap(),
                ],
                T0,
            ),
            (
                vec![
                    "issuer",
                    "--issuer",
                    ISSUER,
                    "--claims-for",
                    "model-api",
                    "--upstreams",
                    reg,
                ],
                T0,
            ),
            (vec!["rotate", "--state-dir", state, "--stage"], T0),
            (vec!["rotate", "--state-dir", state, "--status"], T0),
            (vec!["issuer", "--state-dir", state, "--jwks"], T0),
            (vec!["rotate", "--state-dir", state, "--promote"], T0 + 1),
            (
                vec!["rotate", "--state-dir", state, "--promote"],
                T0 + overlap,
            ),
            (
                vec![
                    "issuer",
                    "--issuer",
                    ISSUER,
                    "--state-dir",
                    state,
                    "--export",
                    site.path().to_str().unwrap(),
                ],
                T0 + overlap,
            ),
            (
                vec!["rotate", "--state-dir", state, "--retire"],
                T0 + overlap + window,
            ),
        ];
        for (argv, now) in steps {
            collect_secrets(&mut secrets);
            let (_, out, err) = cli(&argv, now);
            written.extend(out);
            written.extend(err);
        }
        for f in [".well-known/openid-configuration", ".well-known/jwks.json"] {
            written.extend(std::fs::read(site.path().join(f)).unwrap());
        }
        assert!(!written.is_empty());
        assert!(secrets.len() >= 3 * 14, "collected every key's encodings");
        for s in &secrets {
            assert!(
                !written.windows(s.len()).any(|w| w == s.as_slice()),
                "private key material appeared in the command's output"
            );
        }
        assert!(!String::from_utf8_lossy(&written).contains("\"d\""));
    }
}
