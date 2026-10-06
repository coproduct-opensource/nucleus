//! The agent's declared upstreams: what a pod run asks the node to perform for
//! it, and how the agent in the pod is told where to send those calls (#3031).
//!
//! # Off unless declared
//!
//! A model call is a credentialed egress the HOST performs for the pod (owner
//! decision D3). Without `--egress` this module adds nothing: the pod spec
//! names no upstream, the runtime gives the agent no egress URL, and nothing
//! the agent sends can reach one.
//!
//! # What crosses, and what does not
//!
//! For each `--egress NAME`, the pod spec carries the operator registry
//! entry's PROJECTION (`CredentialedEgressSpec::registry_projection`, the one
//! function the node's admission ceiling is built with): name, base URL,
//! header, prefix, and the NAME of the node variable that holds the
//! credential. Never a value. The node admits the pod only when each entry
//! equals one in its own registry, so a stale or hand-edited registry file
//! here is refused at the node, not trusted.
//!
//! The agent is started under `nucleus-egress-http`, which runs as the
//! workload uid, refuses an upstream the pod was not admitted, and tells the
//! agent a loopback URL per upstream. The agent holds at most a placeholder
//! credential. The host swaps in the real one at egress: the pattern sandboxed
//! agent platforms converged on, with the swap done outside the sandbox.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use nucleus_spec::guest_layout::GuestBinary;
use nucleus_spec::tier2_artifacts::{self, GuestSkew, GuestUse};
use nucleus_spec::{CredentialedEgressSpec, WorkloadSpec};
use portcullis::profile::ProfileRegistry;
use portcullis::{CapabilityLevel, Operation, PermissionLattice};

/// The operator's `--egress*` flags, before they are checked.
pub(super) struct EgressFlags<'a> {
    pub upstreams: &'a [String],
    pub registry: Option<&'a Path>,
    pub exports: &'a [String],
    pub placeholders: &'a [String],
}

/// Declared upstreams, resolved against the registry. Built only by
/// [`declare`], and consumed by [`PodEgress::wrap`].
#[derive(Debug)]
#[must_use = "declared upstreams that are never wrapped reach neither the spec nor the agent"]
pub(super) struct PodEgress {
    specs: Vec<CredentialedEgressSpec>,
    exports: Vec<String>,
    placeholders: Vec<String>,
}

/// Resolve `--egress` against the registry, or `None` when nothing is
/// declared.
///
/// # Errors
/// `--egress-export` / `--egress-placeholder` without `--egress`, a missing or
/// unreadable registry, a name it does not define (named), or an entry the
/// node would not load.
pub(super) fn declare(flags: &EgressFlags<'_>) -> Result<Option<PodEgress>> {
    if flags.upstreams.is_empty() {
        if !flags.exports.is_empty() || !flags.placeholders.is_empty() {
            bail!("--egress-export and --egress-placeholder need an --egress upstream");
        }
        return Ok(None);
    }
    let path = flags.registry.ok_or_else(|| {
        anyhow!("--egress needs the node's upstream registry (--upstreams / NUCLEUS_UPSTREAMS)")
    })?;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the upstream registry {}", path.display()))?;
    let registry: toml::Table = text
        .parse()
        .with_context(|| format!("parsing the upstream registry {}", path.display()))?;
    let mut specs = Vec::new();
    for name in flags.upstreams {
        if specs
            .iter()
            .any(|s: &CredentialedEgressSpec| &s.name == name)
        {
            bail!("--egress {name} is named twice");
        }
        specs.push(projection(&registry, name)?);
    }
    Ok(Some(PodEgress {
        specs,
        exports: flags.exports.to_vec(),
        placeholders: flags.placeholders.to_vec(),
    }))
}

/// The registry entry `name`, projected as the node projects it.
fn projection(registry: &toml::Table, name: &str) -> Result<CredentialedEgressSpec> {
    let entries: Vec<&toml::Table> = registry
        .get("upstream")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .collect();
    let entry = entries
        .iter()
        .find(|e| e.get("name").and_then(toml::Value::as_str) == Some(name))
        .ok_or_else(|| {
            let defined: Vec<&str> = entries
                .iter()
                .filter_map(|e| e.get("name").and_then(toml::Value::as_str))
                .collect();
            anyhow!(
                "--egress {name}: the registry defines no [[upstream]] named {name:?} (defined: {})",
                if defined.is_empty() {
                    "none".to_string()
                } else {
                    defined.join(", ")
                }
            )
        })?;
    let field = |key: &str| -> Result<String> {
        entry
            .get(key)
            .and_then(toml::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("--egress {name}: the registry entry has no `{key}`"))
    };
    let credential = entry
        .get("credential")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("--egress {name}: the registry entry has no `credential`"))?;
    let env_var = match (credential.get("env"), credential.get("federated")) {
        (Some(env), None) => Some(
            env.get("var")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| anyhow!("--egress {name}: `credential.env` has no `var`"))?
                .to_string(),
        ),
        (None, Some(_)) => None,
        _ => bail!("--egress {name}: `credential` must be exactly one of `env` or `federated`"),
    };
    // The operator's effect table (#3229), read into the node's own types and
    // validated by the node's own constructor, so the projection here is the
    // one admission compares against.
    let kind = entry
        .get("kind")
        .cloned()
        .map(toml::Value::try_into::<nucleus_spec::UpstreamKind>)
        .transpose()
        .with_context(|| format!("--egress {name}: `kind`"))?;
    let effects = entry
        .get("effects")
        .cloned()
        .map(toml::Value::try_into::<Vec<nucleus_spec::DeclaredEffect>>)
        .transpose()
        .with_context(|| format!("--egress {name}: `effects`"))?
        .unwrap_or_default();
    let effects = nucleus_spec::EffectTable::from_parts(kind, effects)
        .with_context(|| format!("--egress {name}: `effects`"))?;
    Ok(CredentialedEgressSpec::registry_projection(
        field("name")?,
        field("base_url")?,
        field("header")?,
        entry
            .get("value_prefix")
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        env_var,
        effects,
    ))
}

impl PodEgress {
    /// Refuse a guest that cannot read an upstream's effect table (#3229),
    /// when a declared upstream carries one. Known only once the registry is
    /// read, so after [`declare`]; an upstream with no table demands nothing
    /// beyond [`refuse_guest_skew`]. The 2.4.0 guest predates the table, so
    /// `--guest-release 2.4.0` refuses by name rather than letting the pod fail
    /// on a spec its guest cannot parse; the pin (2.6.0) ships it.
    ///
    /// # Errors
    /// When a declared upstream has an effect table and the guest lacks
    /// `EgressEffectTable`, or its release cannot be ordered.
    pub(super) fn refuse_guest_skew(&self, guest: Option<&str>) -> Result<()> {
        if self.specs.iter().all(|s| s.effects.is_unclassified()) {
            return Ok(());
        }
        refuse_skew_for(guest, &[GuestUse::AgentEgress, GuestUse::EffectTableEgress])
    }

    /// Start `agent` under the guest's egress adapter, and return the spec's
    /// `credentialed_egress` beside it. The adapter's argv is the flags, `--`,
    /// then the agent's own argv unchanged; the workload's env stays empty.
    pub(super) fn wrap(self, agent: WorkloadSpec) -> (WorkloadSpec, Vec<CredentialedEgressSpec>) {
        let mut args = Vec::new();
        for spec in &self.specs {
            args.extend(["--upstream".to_string(), spec.name.clone()]);
        }
        for export in self.exports {
            args.extend(["--export".to_string(), export]);
        }
        for var in self.placeholders {
            args.extend(["--placeholder".to_string(), var]);
        }
        args.push("--".to_string());
        args.push(agent.command);
        args.extend(agent.args);
        let workload = WorkloadSpec {
            command: GuestBinary::EgressHttp.path().to_string(),
            args,
            ..agent
        };
        (workload, self.specs)
    }
}

/// What `--guest-release` takes for a guest built from this checkout.
pub(super) const GUEST_FROM_THIS_TREE: &str = "local";

/// Refuse, before anything is started, a run that declares an upstream when the
/// guest it boots cannot start the agent under the egress adapter that way.
///
/// `guest` is `--guest-release`: `None` for the pinned release `setup`
/// installs, [`GUEST_FROM_THIS_TREE`] for a guest built from this checkout
/// (which carries every capability this build depends on), or a release
/// version. The decision is `guest_skew_for`, the one decider for guest skew
/// (#3075); this only names it for `--egress`. Without `--egress` nothing is
/// checked: the capability is demanded only for that use.
///
/// The pinned release (2.6.0) ships the adapter (#3211, since 2.4.0), so a run on the pin
/// passes. `--guest-release` remains a user assertion the CLI cannot verify,
/// since the node does not report which guest it boots (#3223); this checks
/// the claim, not the guest.
///
/// # Errors
/// When `upstreams` is non-empty and the guest lacks a capability the use
/// demands, or its release cannot be ordered.
pub(super) fn refuse_guest_skew(upstreams: &[String], guest: Option<&str>) -> Result<()> {
    if upstreams.is_empty() {
        return Ok(());
    }
    refuse_skew_for(guest, &[GuestUse::AgentEgress])
}

/// The one guest-skew refusal for `--egress`, for the `uses` a run makes.
fn refuse_skew_for(guest: Option<&str>, uses: &[GuestUse]) -> Result<()> {
    let (release, which) = match guest {
        None => (tier2_artifacts::GUEST_RELEASE, "the pinned guest release"),
        Some(GUEST_FROM_THIS_TREE) => return Ok(()),
        Some(release) => (release, "guest release"),
    };
    tier2_artifacts::guest_skew_for(release, uses).map_err(|skew| {
        let cause = match &skew {
            GuestSkew::Lacks { missing, .. } => {
                let names: Vec<String> = missing.iter().map(|c| format!("{c:?}")).collect();
                format!("{which} does not ship {}", names.join(", "))
            }
            GuestSkew::Unorderable { .. } => format!("{which} cannot be checked"),
        };
        anyhow!(
            "--egress: {cause}; {skew}\nIf the node boots a guest built from this checkout, \
             pass --guest-release {GUEST_FROM_THIS_TREE}."
        )
    })
}

/// Refuse, before anything is started, a run whose policy could never admit a
/// call to an upstream it declares (#3218).
///
/// Without this the contradiction surfaced only at the agent's first model
/// call, inside the running pod, as `WithinDelegationCeiling: requested
/// WebFetch@LowRisk exceeds available Never`. The check is the guest's own:
/// [`CredentialedEgressSpec::call_term`] is the term the guest's broker
/// admission decides, and `exceeds_ceiling` is the comparison its preflight
/// makes (ADR 0007 G-1). Nothing here names the operation or the level.
///
/// This is a necessary condition, not a promise: the node may still narrow a
/// pod below `policy`, and a call that passes the ceiling is still subject to
/// every other gate at the time it is made.
///
/// `source` says where `policy` came from, for the refusal (`profile
/// 'codegen'`). The refusal names the built-in profiles that grant the call
/// and are no wider than `policy` in any other capability, and only those: a
/// suggestion that also widened, say, `git_push` would trade one surprise for
/// a worse one.
///
/// # Errors
/// When `upstreams` is non-empty and `policy` cannot reach them.
pub(super) fn refuse_unreachable(
    upstreams: &[String],
    policy: &PermissionLattice,
    source: &str,
) -> Result<()> {
    let Some(first) = upstreams.first() else {
        return Ok(());
    };
    let term = CredentialedEgressSpec::call_term(first);
    let request = &term.authority;
    let Some(available) = request.exceeds_ceiling(&policy.capabilities) else {
        return Ok(());
    };
    let operation = request.operation;
    let needed = request.requested_level;
    let registry = ProfileRegistry::default();
    let mut grants: Vec<(CapabilityLevel, &str)> = registry
        .names()
        .into_iter()
        .filter_map(|name| {
            let candidate = registry.resolve(name).ok()?;
            let caps = &candidate.capabilities;
            let reaches = request.exceeds_ceiling(caps).is_none();
            let no_wider_elsewhere = Operation::ALL
                .into_iter()
                .filter(|op| *op != operation)
                .all(|op| caps.level_for(op) <= policy.capabilities.level_for(op));
            (reaches && no_wider_elsewhere).then_some((caps.level_for(operation), name))
        })
        .collect();
    grants.sort_unstable();
    let suggestion = if grants.is_empty() {
        format!(
            "No built-in profile adds only {operation} to this policy; use one that sets \
             {operation}: {needed} or higher."
        )
    } else {
        let named: Vec<String> = grants
            .iter()
            .map(|(level, name)| format!("{name} ({operation}: {level})"))
            .collect();
        format!(
            "A profile that grants it and is no wider in any other capability: {}.",
            named.join(", ")
        )
    };
    bail!(
        "--egress {names}: {source} sets {operation}: {available}, and a call to a declared \
         upstream is admitted only at {operation}: {needed} or above, so the agent's first call \
         would be denied inside the pod. {suggestion}",
        names = upstreams.join(", "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// The node's own documented example (`nucleus-node/src/upstreams.rs`),
    /// trimmed: one federated entry and one env entry.
    const REGISTRY: &str = r#"
[[upstream]]
name         = "model-api"
base_url     = "https://model-api.example/v1"
header       = "authorization"
value_prefix = "Bearer "
call_charge_micro_usd = 1000

[upstream.credential.federated]
token_endpoint     = "https://auth.model-api.example/oauth/token"
grant              = "token-exchange"
encoding           = "form"
audience           = "https://auth.model-api.example"

[[upstream]]
name         = "search-api"
base_url     = "https://search.example"
header       = "x-api-key"
call_charge_micro_usd = 1000

[upstream.credential.env]
var = "SEARCH_API_TOKEN"
"#;

    fn registry_file() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), REGISTRY).unwrap();
        file
    }

    fn strings(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| (*s).to_string()).collect()
    }

    fn agent() -> WorkloadSpec {
        WorkloadSpec {
            command: "/opt/agent".into(),
            args: strings(&["--lead", "task"]),
            env: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            uid: None,
        }
    }

    /// **Off by default (D3).** No `--egress`, nothing declared.
    #[test]
    fn nothing_is_declared_without_egress() {
        let none = declare(&EgressFlags {
            upstreams: &[],
            registry: None,
            exports: &[],
            placeholders: &[],
        })
        .unwrap();
        assert!(none.is_none());
        assert!(
            declare(&EgressFlags {
                upstreams: &[],
                registry: None,
                exports: &strings(&["V=model-api"]),
                placeholders: &[],
            })
            .is_err()
        );
    }

    /// The projection is the node's: field for field what its admission
    /// ceiling holds, the federated entry with an empty variable.
    #[test]
    fn declared_upstreams_project_as_the_node_projects_them() {
        let file = registry_file();
        let ups = strings(&["model-api", "search-api"]);
        let egress = declare(&EgressFlags {
            upstreams: &ups,
            registry: Some(file.path()),
            exports: &[],
            placeholders: &[],
        })
        .unwrap()
        .unwrap();
        let (_, specs) = egress.wrap(agent());
        assert_eq!(
            specs,
            vec![
                CredentialedEgressSpec::registry_projection(
                    "model-api".into(),
                    "https://model-api.example/v1".into(),
                    "authorization".into(),
                    "Bearer ".into(),
                    None,
                    nucleus_spec::EffectTable::unclassified(),
                ),
                CredentialedEgressSpec::registry_projection(
                    "search-api".into(),
                    "https://search.example".into(),
                    "x-api-key".into(),
                    String::new(),
                    Some("SEARCH_API_TOKEN".into()),
                    nucleus_spec::EffectTable::unclassified(),
                ),
            ]
        );
    }

    /// **A forge entry projects its effect table (#3229)**, built by the
    /// node's own constructor, so the spec carries what admission compares
    /// against; an invalid table is refused here, by name, before a pod.
    #[test]
    fn a_forge_entry_projects_its_effect_table() {
        let forge = |effects: &str| {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(
                file.path(),
                format!(
                    "[[upstream]]\nname = \"forge-api\"\nbase_url = \"https://forge.example/\"\n\
                     header = \"authorization\"\nkind = \"forge\"\neffects = {effects}\n\
                     [upstream.credential.env]\nvar = \"FORGE_API_TOKEN\"\n"
                ),
            )
            .unwrap();
            let ups = strings(&["forge-api"]);
            declare(&EgressFlags {
                upstreams: &ups,
                registry: Some(file.path()),
                exports: &[],
                placeholders: &[],
            })
            .map(|egress| egress.unwrap().wrap(agent()).1)
        };
        let specs =
            forge(r#"[{ method = "POST", path = "/repos/*/*/pulls", operation = "create_pr" }]"#)
                .unwrap();
        let expected = nucleus_spec::EffectTable::from_parts(
            Some(nucleus_spec::UpstreamKind::Forge),
            vec![nucleus_spec::DeclaredEffect {
                method: nucleus_spec::EgressMethod::Post,
                path: "/repos/*/*/pulls".into(),
                operation: nucleus_spec::EgressOperation::CreatePr,
            }],
        )
        .unwrap();
        assert_eq!(specs[0].effects, expected);

        // 2.4.0 predates effect tables: refused by name, where the same
        // upstream without a table is not (#3229). The pin (2.6.0) ships them.
        let declared_forge = |effects: &str| {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(
                file.path(),
                format!(
                    "[[upstream]]\nname = \"forge-api\"\nbase_url = \"https://forge.example/\"\n\
                     header = \"authorization\"\n{effects}\n\
                     [upstream.credential.env]\nvar = \"FORGE_API_TOKEN\"\n"
                ),
            )
            .unwrap();
            let ups = strings(&["forge-api"]);
            declare(&EgressFlags {
                upstreams: &ups,
                registry: Some(file.path()),
                exports: &[],
                placeholders: &[],
            })
            .unwrap()
            .unwrap()
        };
        let with_table = declared_forge(
            "kind = \"forge\"\neffects = [{ method = \"POST\", path = \"/repos/*/*/pulls\", \
             operation = \"create_pr\" }]",
        );
        let err = with_table
            .refuse_guest_skew(Some("2.4.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not ship EgressEffectTable"), "{err}");
        with_table.refuse_guest_skew(None).unwrap();
        with_table
            .refuse_guest_skew(Some(GUEST_FROM_THIS_TREE))
            .unwrap();
        declared_forge("").refuse_guest_skew(Some("2.4.0")).unwrap();
        let err = forge(r#"[{ method = "POST", path = "repos/*x", operation = "create_pr" }]"#)
            .unwrap_err();
        assert!(format!("{err:#}").contains("forge-api"), "{err:#}");
    }

    #[test]
    fn an_upstream_the_registry_lacks_is_refused_by_name() {
        let file = registry_file();
        let ups = strings(&["git-remote"]);
        let err = declare(&EgressFlags {
            upstreams: &ups,
            registry: Some(file.path()),
            exports: &[],
            placeholders: &[],
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("no [[upstream]] named \"git-remote\""),
            "{err}"
        );
        assert!(err.contains("defined: model-api, search-api"), "{err}");
    }

    /// The agent runs under the adapter with its own argv intact, and its
    /// environment stays empty: no URL, placeholder or credential is put there
    /// by the host. The guest runtime and the adapter supply the URLs.
    #[test]
    fn the_agent_is_wrapped_and_receives_no_host_environment() {
        let file = registry_file();
        let ups = strings(&["model-api"]);
        let (workload, _) = declare(&EgressFlags {
            upstreams: &ups,
            registry: Some(file.path()),
            exports: &strings(&["HARNESS_BASE_URL=model-api"]),
            placeholders: &strings(&["HARNESS_TOKEN"]),
        })
        .unwrap()
        .unwrap()
        .wrap(agent());
        assert_eq!(workload.command, "/usr/local/bin/nucleus-egress-http");
        assert_eq!(
            workload.args,
            strings(&[
                "--upstream",
                "model-api",
                "--export",
                "HARNESS_BASE_URL=model-api",
                "--placeholder",
                "HARNESS_TOKEN",
                "--",
                "/opt/agent",
                "--lead",
                "task",
            ])
        );
        assert!(workload.env.is_empty());
    }

    fn profile(name: &str) -> PermissionLattice {
        ProfileRegistry::default()
            .resolve(name)
            .unwrap_or_else(|e| panic!("profile {name}: {e}"))
    }

    /// #3218: a profile whose ceiling can never admit a call to a declared
    /// upstream is refused before anything starts, by name, with the profile
    /// that grants only what is missing.
    #[test]
    fn a_profile_that_can_never_call_the_upstream_is_refused_up_front() {
        let ups = strings(&["model-api"]);
        let err = refuse_unreachable(&ups, &profile("codegen"), "profile 'codegen'")
            .unwrap_err()
            .to_string();
        assert!(err.contains("profile 'codegen'"), "{err}");
        assert!(err.contains("web_fetch: never"), "{err}");
        assert!(err.contains("safe-pr-fixer (web_fetch: low_risk)"), "{err}");
        // Nothing that also widens another capability is offered.
        assert!(!err.contains("research-web"), "{err}");
        assert!(!err.contains("release"), "{err}");

        let err = refuse_unreachable(
            &ups,
            &PermissionLattice::restrictive().normalize(),
            "profile 'restrictive'",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("profile 'restrictive'"), "{err}");
        assert!(err.contains("web_fetch: never"), "{err}");
    }

    /// The guest check for `--egress`: the pin (2.6.0) ships the adapter and
    /// is accepted, 2.3.0 is refused by name, a guest built from this checkout
    /// is accepted, a named release is checked as given, and a run declaring
    /// nothing is never checked.
    #[test]
    fn the_guest_is_checked_for_the_adapter_only_when_egress_is_declared() {
        let ups = strings(&["model-api"]);
        refuse_guest_skew(&ups, None).unwrap();
        let err = refuse_guest_skew(&ups, Some("2.3.0"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("guest release does not ship EgressAdapterUpstreams"),
            "{err}"
        );
        assert!(err.contains("#3211"), "{err}");
        assert!(err.contains("--guest-release local"), "{err}");
        refuse_guest_skew(&ups, Some(GUEST_FROM_THIS_TREE)).unwrap();
        let err = refuse_guest_skew(&ups, Some("2.2.0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("guest release does not ship"), "{err}");
        let err = refuse_guest_skew(&ups, Some("latest"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be checked"), "{err}");
        refuse_guest_skew(&[], None).unwrap();
    }

    #[test]
    fn a_profile_that_grants_the_call_is_accepted() {
        let ups = strings(&["model-api"]);
        refuse_unreachable(&ups, &profile("safe-pr-fixer"), "profile 'safe-pr-fixer'").unwrap();
        // Nothing declared, nothing to refuse.
        refuse_unreachable(&[], &profile("codegen"), "profile 'codegen'").unwrap();
    }

    /// The early refusal is the guest preflight's own decision, made sooner:
    /// for every built-in profile, it refuses exactly when the preflight of a
    /// call's term fails `WithinDelegationCeiling`. Both outcomes must occur,
    /// or the agreement says nothing.
    #[test]
    fn the_early_refusal_agrees_with_the_guest_preflight_for_every_profile() {
        use portcullis::{PreflightContext, ProofObligation, preflight_action};
        let ups = strings(&["model-api"]);
        let registry = ProfileRegistry::default();
        let names = registry.names();
        assert!(names.len() >= 10, "registry read nothing: {names:?}");
        let (mut refused, mut admitted) = (0, 0);
        for name in names {
            let policy = registry.resolve(name).unwrap();
            let early = refuse_unreachable(&ups, &policy, name).is_err();
            let term = CredentialedEgressSpec::call_term("https://model-api.example/v1");
            let late = preflight_action(&term, &PreflightContext::new(&policy))
                .failures
                .iter()
                .any(|f| f.obligation == ProofObligation::WithinDelegationCeiling);
            assert_eq!(early, late, "{name}");
            if early {
                refused += 1;
            } else {
                admitted += 1;
            }
        }
        assert!(
            refused > 0 && admitted > 0,
            "{refused} refused, {admitted} admitted"
        );
    }
}
