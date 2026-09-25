//! The operator's upstream registry: which credentialed upstreams exist on this
//! node at all.
//!
//! # The hole this closes
//!
//! A `CredentialedEgressSpec` names a destination (`upstream`) and **which of the
//! node's environment variables** is attached to it (`credential_env`), and the
//! broker's store is built by reading exactly that variable
//! (`broker_launch::store_from_node_environment`). Until this module existed the
//! node took both from the pod spec, verbatim, from any caller of
//! `POST /v1/pods`. The only clamp was the in-guest tool-proxy's, on the
//! sub-pod path — so a caller that reached the node directly (an external
//! mTLS caller, or a guest workload holding its own pod's SVID key, #2724) could
//! name any node variable and any URL: "read any node secret and post it where
//! I like".
//!
//! # The model
//!
//! The pod spec SELECTS; the operator DEFINES. An entry here is the whole
//! `CredentialedEgressSpec` — name, base URL, variable, header, prefix — and a
//! pod may hold an upstream only when its requested entry equals one of these
//! field for field (`CredentialedEgressSpec::admitted_by`, the same comparison
//! the tool-proxy's sub-pod clamp uses). Admission applies it per case in
//! `pod_authority`; the broker then takes its entries from here, so the text of
//! `credential_env` that reaches `std::env::var` came out of this file and not
//! out of anything a caller wrote.
//!
//! # No registry means no credentialed egress
//!
//! Fail-closed, deliberately. Without `--upstreams`, admission drops every
//! requested entry for every caller, the root minter included. The alternative —
//! trusting the root minter's spec verbatim when no registry is configured —
//! would keep a node with no registry working exactly as before, but it would
//! keep a pod spec, rather than the operator's file, as the author of which node
//! variable is read, on the one path where the spec's author is least checked.
//! Nothing in the tree depended on it (no test, script or documented workflow
//! creates a pod with `credentialed_egress` through the node), so there was no
//! compatibility to buy with it.
//!
//! # File format
//!
//! TOML, one `[[upstream]]` table per entry, with exactly the fields of
//! `CredentialedEgressSpec` (unknown fields are refused, so a typo cannot
//! silently become a default):
//!
//! ```toml
//! [[upstream]]
//! name = "model-api"
//! upstream = "https://model-api.example/v1"
//! credential_env = "LLM_API_TOKEN"
//! header = "authorization"
//! value_prefix = "Bearer "
//! ```

use std::path::Path;

use nucleus_spec::CredentialedEgressSpec;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    #[serde(default)]
    upstream: Vec<CredentialedEgressSpec>,
}

/// The upstreams an operator has defined for this node. See the module docs.
#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamRegistry {
    entries: Vec<CredentialedEgressSpec>,
}

impl UpstreamRegistry {
    /// Load and validate the registry at `path`.
    ///
    /// # Errors
    /// An unreadable file, malformed TOML, or an entry [`Self::from_toml_str`]
    /// refuses. The node refuses to START on any of these: a registry that
    /// half-loaded would be a smaller ceiling than the operator wrote, which is
    /// safe, but silently so, and "my upstream is refused" is a worse way to
    /// learn about a typo than "the node will not start".
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("upstream registry {}: {e}", path.display()))?;
        Self::from_toml_str(&text).map_err(|e| format!("upstream registry {}: {e}", path.display()))
    }

    /// Parse and validate a registry.
    ///
    /// Names must be unique, because the broker's store and `PerformRequest.target`
    /// are keyed by name: two entries sharing one would make which credential a
    /// request gets depend on iteration order. The base URL must be an absolute
    /// `http(s)` URL with a host, and the variable and header must be non-empty,
    /// so an entry cannot be valid-looking and unusable.
    ///
    /// # Errors
    /// Names the offending entry by `name`, never by the variable's value (this
    /// never reads the variable at all).
    pub fn from_toml_str(text: &str) -> Result<Self, String> {
        let file: RegistryFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut seen = std::collections::BTreeSet::new();
        for up in &file.upstream {
            if up.name.trim().is_empty() {
                return Err("an [[upstream]] entry has an empty name".into());
            }
            if !seen.insert(up.name.as_str()) {
                return Err(format!("upstream {:?} is defined twice", up.name));
            }
            let url = reqwest::Url::parse(&up.upstream)
                .map_err(|e| format!("upstream {:?}: base URL: {e}", up.name))?;
            if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
                return Err(format!(
                    "upstream {:?}: base URL must be absolute http(s) with a host",
                    up.name
                ));
            }
            if up.credential_env.trim().is_empty() || up.header.trim().is_empty() {
                return Err(format!(
                    "upstream {:?}: credential_env and header must be set",
                    up.name
                ));
            }
        }
        Ok(Self {
            entries: file.upstream,
        })
    }

    /// Every entry, for admission to clamp against.
    pub fn entries(&self) -> &[CredentialedEgressSpec] {
        &self.entries
    }

    /// The registry's OWN entries for an admitted set: each admitted entry that
    /// equals one here, as this registry holds it.
    ///
    /// Admission has already clamped the set to equality with these entries, so
    /// on the ordinary path this returns values identical to its input. It
    /// exists so the broker does not rely on that: what reaches
    /// `store_from_node_environment` is copied out of the operator's file, and a
    /// pod whose admitted set somehow disagrees with the registry (a node
    /// restarted onto a narrower file, say) loses the entry rather than keeping
    /// a definition the operator no longer has.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn resolve(&self, admitted: &[CredentialedEgressSpec]) -> Vec<CredentialedEgressSpec> {
        self.entries
            .iter()
            .filter(|entry| entry.admitted_by(admitted))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"
[[upstream]]
name = "model-api"
upstream = "https://model-api.invalid/v1"
credential_env = "LLM_API_TOKEN"
header = "authorization"
value_prefix = "Bearer "
"#;

    #[test]
    fn a_registry_loads_its_entries_whole() {
        let reg = UpstreamRegistry::from_toml_str(ONE).expect("a valid registry loads");
        assert_eq!(reg.entries().len(), 1);
        let e = &reg.entries()[0];
        assert_eq!(
            (
                e.name.as_str(),
                e.credential_env.as_str(),
                e.value_prefix.as_str()
            ),
            ("model-api", "LLM_API_TOKEN", "Bearer ")
        );
    }

    #[test]
    fn an_empty_file_is_an_empty_registry_not_an_error() {
        assert!(
            UpstreamRegistry::from_toml_str("")
                .unwrap()
                .entries()
                .is_empty()
        );
    }

    /// Each of these would otherwise be a registry that loads and then refuses,
    /// or worse, one whose meaning depends on which duplicate wins.
    #[test]
    fn malformed_registries_refuse_to_load() {
        let dup = format!("{ONE}\n{ONE}");
        let cases = [
            (dup.as_str(), "a duplicated name"),
            (
                "[[upstream]]\nname='x'\nupstream='https://a.invalid'\ncredential_env='V'\nheader='h'\ntypo=1\n",
                "an unknown field",
            ),
            (
                "[[upstream]]\nname='x'\nupstream='/relative'\ncredential_env='V'\nheader='h'\n",
                "a relative base URL",
            ),
            (
                "[[upstream]]\nname='x'\nupstream='file:///etc/passwd'\ncredential_env='V'\nheader='h'\n",
                "a non-http scheme",
            ),
            (
                "[[upstream]]\nname='x'\nupstream='https://a.invalid'\ncredential_env=''\nheader='h'\n",
                "an empty credential_env",
            ),
        ];
        for (text, what) in cases {
            assert!(
                UpstreamRegistry::from_toml_str(text).is_err(),
                "{what} must refuse to load"
            );
        }
    }

    /// The broker's entries come from the registry, and only for what was
    /// admitted: an admitted set that names something the registry lacks
    /// contributes nothing.
    #[test]
    fn resolve_returns_only_registry_entries_that_were_admitted() {
        let reg = UpstreamRegistry::from_toml_str(ONE).unwrap();
        assert_eq!(reg.resolve(reg.entries()), reg.entries());
        assert!(reg.resolve(&[]).is_empty());
        let mut forged = reg.entries()[0].clone();
        forged.credential_env = "SOME_OTHER_NODE_VAR".into();
        assert!(
            reg.resolve(&[forged]).is_empty(),
            "an entry differing from the registry's must not reach the store"
        );
    }
}
