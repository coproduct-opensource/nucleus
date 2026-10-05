//! Which upstreams this adapter exposes, and what the managed command is told.
//!
//! # Declared, or refused by name
//!
//! The runtime tells the workload which credentialed upstreams its pod was
//! admitted, one `NUCLEUS_EGRESS_<NAME>_URL` per upstream, pointing into the
//! workload door (`nucleus_spec::workload_egress`). That set is the operator's
//! decision, made on the host. An `--upstream` outside it would only be refused
//! later by the door, one request at a time and minutes into a run; here it is
//! refused before the command starts, by name, with the declared set beside
//! it. Nothing reaches an upstream that was not declared: model calls are off
//! unless a pod declares one (owner decision D3).
//!
//! # What the managed command is told
//!
//! For each exposed upstream, `NUCLEUS_EGRESS_<NAME>_URL` is REPLACED with the
//! origin of the adapter's loopback listener for it (`http://127.0.0.1:<port>`),
//! which any HTTP client can use as its base URL; the runtime's `unix://` value
//! names a socket and an ordinary client cannot dial it. Each upstream has its
//! own listener, so a request path is the upstream's own path: `/v1/x` on that
//! listener is `/v1/egress/<name>/v1/x` at the door, and no request can name
//! another upstream. `--export VAR=NAME` also writes that URL under a name the command's own
//! configuration reads, so nucleus never has to know a harness's variable
//! names. `--placeholder VAR` sets `VAR` to [`PLACEHOLDER`]: a fixed,
//! non-secret value for a harness that will not start without a credential
//! variable. The adapter never forwards it (only `Content-Type` and the
//! approval-wait header cross), and the host injects the real credential.
//!
//! A command never learns a credential from any of this, because none of it
//! carries one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddrV4;

use nucleus_spec::workload_egress::{upstream_url, url_env};

/// The value `--placeholder` gives a variable. Says what it is, so nobody
/// mistakes it for a credential, and nothing checks it for one.
pub(crate) const PLACEHOLDER: &str = "nucleus-egress-placeholder-not-a-credential";

/// The single-upstream URL variable this adapter has always set.
pub(crate) const SINGLE_URL_ENV: &str = "NUCLEUS_EGRESS_HTTP_URL";

/// A checked launch: what to listen for and what to tell the command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    upstreams: Vec<String>,
    listen: Option<SocketAddrV4>,
    exports: Vec<(String, String)>,
    placeholders: Vec<String>,
}

/// The operator's flags, before they are checked.
pub(crate) struct Flags<'a> {
    pub door: &'a str,
    pub upstreams: &'a [String],
    pub listen: Option<SocketAddrV4>,
    pub exports: &'a [String],
    pub placeholders: &'a [String],
}

/// The upstreams the runtime declared on `door`, read from `env`.
fn declared(door: &str, env: &BTreeMap<String, String>) -> BTreeSet<String> {
    let prefix = upstream_url(door, "");
    env.iter()
        .filter_map(|(key, value)| {
            let name = value.strip_prefix(&prefix)?;
            (!name.is_empty() && url_env(name) == *key).then(|| name.to_string())
        })
        .collect()
}

/// A variable name a shell would accept, and not one the runtime owns.
fn settable(var: &str) -> Result<(), String> {
    let mut bytes = var.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    if !first_ok || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(format!("`{var}` is not an environment variable name"));
    }
    if var.starts_with("NUCLEUS_") {
        return Err(format!(
            "`{var}` is in the runtime's NUCLEUS_ namespace; export to the harness's own variable"
        ));
    }
    Ok(())
}

impl Plan {
    /// Check the flags against what the runtime declared in `env`.
    ///
    /// # Errors
    /// An undeclared or repeated upstream (named, with the declared set), a
    /// `--listen` given for more than one upstream, or a malformed or reserved
    /// `--export` / `--placeholder`.
    pub(crate) fn new(flags: &Flags<'_>, env: &BTreeMap<String, String>) -> Result<Self, String> {
        if flags.upstreams.is_empty() {
            return Err("name at least one --upstream the pod declared".into());
        }
        let declared = declared(flags.door, env);
        let mut seen = BTreeSet::new();
        for name in flags.upstreams {
            if !seen.insert(name.as_str()) {
                return Err(format!("upstream `{name}` is named twice"));
            }
            if !declared.contains(name) {
                let listed = if declared.is_empty() {
                    "none: this pod declared no credentialed upstream".to_string()
                } else {
                    declared.iter().cloned().collect::<Vec<_>>().join(", ")
                };
                return Err(format!(
                    "upstream `{name}` is not declared for this pod: the runtime gave no {} on \
                     {} (declared: {listed}). An upstream is reachable only when the pod spec \
                     declares it and the operator's registry admits it.",
                    url_env(name),
                    upstream_url(flags.door, name),
                ));
            }
        }
        if flags.listen.is_some() && flags.upstreams.len() > 1 {
            return Err(
                "--listen fixes one address, so it can serve only one --upstream; omit it to \
                 give each upstream its own loopback port"
                    .into(),
            );
        }
        let mut exports = Vec::new();
        let mut vars = BTreeSet::new();
        for export in flags.exports {
            let (var, name) = export
                .split_once('=')
                .ok_or_else(|| format!("--export `{export}` is not VAR=UPSTREAM"))?;
            settable(var)?;
            if !seen.contains(name) {
                return Err(format!(
                    "--export `{export}` names `{name}`, which this adapter does not expose"
                ));
            }
            if !vars.insert(var.to_string()) {
                return Err(format!("`{var}` is set twice"));
            }
            exports.push((var.to_string(), name.to_string()));
        }
        for var in flags.placeholders {
            settable(var)?;
            if !vars.insert(var.clone()) {
                return Err(format!("`{var}` is set twice"));
            }
        }
        Ok(Self {
            upstreams: flags.upstreams.to_vec(),
            listen: flags.listen,
            exports,
            placeholders: flags.placeholders.to_vec(),
        })
    }

    /// The upstreams to expose, in flag order.
    pub(crate) fn upstreams(&self) -> &[String] {
        &self.upstreams
    }

    /// Where to listen: `--listen` for a single upstream, otherwise an
    /// ephemeral loopback port for each.
    pub(crate) fn listen(&self) -> SocketAddrV4 {
        self.listen
            .unwrap_or_else(|| SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0))
    }

    /// What the managed command's environment gains, given each exposed
    /// upstream's bound `http://` origin. These override what it inherited.
    pub(crate) fn child_env(&self, bound: &BTreeMap<String, String>) -> Vec<(String, String)> {
        let url = |name: &str| bound.get(name).cloned().unwrap_or_default();
        let mut env: Vec<(String, String)> = self
            .upstreams
            .iter()
            .map(|name| (url_env(name), url(name)))
            .collect();
        if let [only] = self.upstreams.as_slice() {
            // The single-upstream variable this adapter shipped with.
            env.push((SINGLE_URL_ENV.to_string(), url(only)));
        }
        env.extend(
            self.exports
                .iter()
                .map(|(var, name)| (var.clone(), url(name))),
        );
        env.extend(
            self.placeholders
                .iter()
                .map(|var| (var.clone(), PLACEHOLDER.to_string())),
        );
        env
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOOR: &str = "unix:///run/nucleus-door/workload.sock";

    fn runtime_env(names: &[&str]) -> BTreeMap<String, String> {
        let mut env: BTreeMap<String, String> = names
            .iter()
            .map(|n| (url_env(n), upstream_url(DOOR, n)))
            .collect();
        env.insert("NUCLEUS_TOOL_PROXY_URL".into(), DOOR.into());
        env.insert("PATH".into(), "/usr/bin".into());
        env
    }

    fn flags<'a>(
        upstreams: &'a [String],
        exports: &'a [String],
        placeholders: &'a [String],
    ) -> Flags<'a> {
        Flags {
            door: DOOR,
            upstreams,
            listen: None,
            exports,
            placeholders,
        }
    }

    fn strings(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| (*s).to_string()).collect()
    }

    /// **An undeclared upstream is refused by name**, with the declared set,
    /// before the command starts.
    #[test]
    fn an_undeclared_upstream_is_refused_by_name() {
        let ups = strings(&["git-remote"]);
        let err = Plan::new(&flags(&ups, &[], &[]), &runtime_env(&["model-api"])).unwrap_err();
        assert!(err.contains("`git-remote` is not declared"), "{err}");
        assert!(err.contains("NUCLEUS_EGRESS_GIT_REMOTE_URL"), "{err}");
        assert!(err.contains("declared: model-api"), "{err}");
        let err = Plan::new(&flags(&ups, &[], &[]), &runtime_env(&[])).unwrap_err();
        assert!(err.contains("declared no credentialed upstream"), "{err}");
    }

    /// A value pointing anywhere but this door, or under a key that does not
    /// spell its name, does not declare anything.
    #[test]
    fn only_the_runtimes_own_spelling_declares() {
        let ups = strings(&["model-api"]);
        let mut env = runtime_env(&[]);
        env.insert(
            url_env("model-api"),
            upstream_url("unix:///elsewhere.sock", "model-api"),
        );
        env.insert(
            "NUCLEUS_EGRESS_OTHER_URL".into(),
            upstream_url(DOOR, "model-api"),
        );
        assert!(Plan::new(&flags(&ups, &[], &[]), &env).is_err());
    }

    /// The control: declared upstreams pass, and the managed command is told
    /// loopback URLs under the same keys, its own variable, and a placeholder.
    #[test]
    fn a_declared_upstream_is_told_by_loopback_url() {
        let ups = strings(&["model-api", "search"]);
        let exports = strings(&["HARNESS_BASE_URL=model-api"]);
        let placeholders = strings(&["HARNESS_TOKEN"]);
        let plan = Plan::new(
            &flags(&ups, &exports, &placeholders),
            &runtime_env(&["model-api", "search"]),
        )
        .unwrap();
        let bound = BTreeMap::from([
            ("model-api".to_string(), "http://127.0.0.1:4001".to_string()),
            ("search".to_string(), "http://127.0.0.1:4002".to_string()),
        ]);
        let env: BTreeMap<_, _> = plan.child_env(&bound).into_iter().collect();
        assert_eq!(
            env,
            BTreeMap::from([
                (
                    "NUCLEUS_EGRESS_MODEL_API_URL".to_string(),
                    "http://127.0.0.1:4001".to_string()
                ),
                (
                    "NUCLEUS_EGRESS_SEARCH_URL".to_string(),
                    "http://127.0.0.1:4002".to_string()
                ),
                (
                    "HARNESS_BASE_URL".to_string(),
                    "http://127.0.0.1:4001".to_string()
                ),
                ("HARNESS_TOKEN".to_string(), PLACEHOLDER.to_string()),
            ])
        );
    }

    #[test]
    fn one_upstream_keeps_the_single_url_contract() {
        let ups = strings(&["model-api"]);
        let plan = Plan::new(&flags(&ups, &[], &[]), &runtime_env(&["model-api"])).unwrap();
        let bound = BTreeMap::from([("model-api".to_string(), "http://127.0.0.1:4001".into())]);
        let env: BTreeMap<_, _> = plan.child_env(&bound).into_iter().collect();
        assert_eq!(env[SINGLE_URL_ENV], "http://127.0.0.1:4001");
    }

    #[test]
    fn malformed_and_reserved_settings_are_refused() {
        let ups = strings(&["model-api"]);
        let env = runtime_env(&["model-api"]);
        for bad in [
            "NOEQUALS",
            "1BAD=model-api",
            "NUCLEUS_TOOL_PROXY_URL=model-api",
            "OK=undeclared",
        ] {
            let exports = strings(&[bad]);
            assert!(
                Plan::new(&flags(&ups, &exports, &[]), &env).is_err(),
                "{bad}"
            );
        }
        let twice = strings(&["A=model-api"]);
        assert!(Plan::new(&flags(&ups, &twice, &strings(&["A"])), &env).is_err());
        assert!(
            Plan::new(
                &flags(&strings(&["model-api", "model-api"]), &[], &[]),
                &env
            )
            .is_err()
        );
        assert!(Plan::new(&flags(&[], &[], &[]), &env).is_err());
        let mut listen_two = flags(&[], &[], &[]);
        let two = strings(&["model-api", "search"]);
        listen_two.upstreams = &two;
        listen_two.listen = Some("127.0.0.1:18081".parse().unwrap());
        assert!(Plan::new(&listen_two, &runtime_env(&["model-api", "search"])).is_err());
    }
}
