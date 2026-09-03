//! A proof that the pod's egress policy admits a host.
//!
//! # The bug this exists to make unwritable
//!
//! A pod runs under **default-deny egress**. The audit log anchored every entry
//! to the drand beacon by fetching `https://api.drand.sh/public/latest` with a
//! 5-second timeout — a request the pod's own network policy forbids. It could
//! not succeed. Not "usually failed": *could not succeed*. Measured on an M5
//! Pro, that single call was **5044 ms of a 5497 ms tool-proxy startup**, paid
//! by every pod, forever, before it would serve a single request.
//!
//! Nothing was broken. Nothing logged. The call compiled because
//! `reqwest::Client` is **ambient authority**: its type says nothing about where
//! it may connect, and the policy that forbade the destination was a runtime
//! value living in another crate.
//!
//! # The shape of the fix
//!
//! [`Admitted`] has **no public constructor**. The only way to obtain one is
//! [`EgressPolicy::admit`], which consults the pod's resolved allowlists. A
//! client that takes an `Admitted` therefore cannot be built for a host the
//! policy forbids — there is no term to pass.
//!
//! This is the idiom the repo already uses for authority elsewhere:
//! `SessionCleanseToken` is "unforgeable outside `nucleus-ifc-kernel`, mintable
//! only with a `DischargedBundle`", and `Authority::spend` refuses an
//! unwitnessed authority. Egress had no equivalent, so the drand call was
//! well-typed.
//!
//! # What this does and does not buy
//!
//! It does not make the fetch fast, and it does not replace the deadline that
//! now bounds the boot report — an *admitted* host can still be slow. What it
//! removes is the case where the destination was never reachable in the first
//! place, which is the one that cost five seconds a boot.
//!
//! It is also not airtight on its own: `reqwest::Client::builder()` remains
//! callable by anyone. Closing that needs the companion source check
//! (`no_unpoliced_http_clients`) that refuses raw client construction outside
//! the blessed constructors. The witness is the type; the check is what makes
//! the type the only door.

/// Proof that the egress policy admits a host.
///
/// Construct only via [`EgressPolicy::admit`]. The private field is what makes
/// this unforgeable from outside this module — a `pub struct` with all-public
/// fields would be a comment, not a guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    host: String,
}

impl Admitted {
    /// The host this proof is about.
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// The pod's resolved egress allowlists.
///
/// Built from `nucleus_spec::NetworkSpec`'s `dns_allow` / `url_allow` by the
/// caller that has them; this crate is a leaf and deliberately does not depend
/// on the spec types.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    dns_allow: Vec<String>,
}

impl EgressPolicy {
    /// A policy admitting exactly these hosts.
    ///
    /// An empty allowlist admits **nothing**. That is the default-deny posture a
    /// pod actually runs under, and making it the natural reading of an empty
    /// `Vec` is deliberate: the alternative — empty means "unrestricted" — is
    /// how allowlists become decorative.
    pub fn new(dns_allow: Vec<String>) -> Self {
        Self { dns_allow }
    }

    /// A policy admitting everything, for a caller that is **not** under pod
    /// egress policy.
    ///
    /// The node process is the host: it is not sandboxed, and its outbound
    /// calls (OIDC, JWKS, the beacon it serves to pods) are not what
    /// default-deny constrains. Naming that explicitly is the point — an
    /// unrestricted policy should be a visible decision at the call site, not
    /// the accidental default that ambient `reqwest::Client` gave everyone.
    ///
    /// Do NOT use this inside the guest tool-proxy.
    pub fn unrestricted_host_process() -> Self {
        Self {
            dns_allow: vec!["*".to_string()],
        }
    }

    /// Mint a proof that `host` is admitted, or `None`.
    ///
    /// Matching is exact or single-level wildcard (`*.example.com`), case
    /// insensitive. It deliberately does NOT accept a bare `*` as "everything"
    /// unless the operator wrote `*`, and a leading-dot suffix match is not
    /// supported, because `evilexample.com` must not match `example.com`.
    pub fn admit(&self, host: &str) -> Option<Admitted> {
        let host = host.trim().to_lowercase();
        if host.is_empty() {
            return None;
        }
        for pattern in &self.dns_allow {
            let p = pattern.trim().to_lowercase();
            if p == "*" || p == host {
                return Some(Admitted { host });
            }
            if let Some(suffix) = p.strip_prefix("*.") {
                // `*.example.com` matches `api.example.com`, and must NOT match
                // `example.com` itself nor `notexample.com`.
                if let Some(rest) = host.strip_suffix(suffix)
                    && rest.ends_with('.')
                    && rest.len() > 1
                {
                    return Some(Admitted { host });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drand case, exactly: a default-deny pod cannot mint a proof for the
    /// beacon, so a client requiring one cannot be built.
    #[test]
    fn a_default_deny_pod_admits_nothing() {
        let policy = EgressPolicy::default();
        assert!(policy.admit("api.drand.sh").is_none());
        assert!(policy.admit("example.com").is_none());
    }

    /// Non-vacuity: an operator who allows the beacon gets a proof, so the
    /// refusal above is about the policy and not about `admit` always failing.
    #[test]
    fn an_allowed_host_is_admitted() {
        let policy = EgressPolicy::new(vec!["api.drand.sh".into()]);
        let a = policy.admit("api.drand.sh").expect("explicitly allowed");
        assert_eq!(a.host(), "api.drand.sh");
    }

    #[test]
    fn wildcards_match_a_subdomain_but_not_the_apex_or_a_prefix_collision() {
        let policy = EgressPolicy::new(vec!["*.example.com".into()]);
        assert!(policy.admit("api.example.com").is_some());
        assert!(
            policy.admit("example.com").is_none(),
            "`*.example.com` must not admit the apex"
        );
        assert!(
            policy.admit("notexample.com").is_none(),
            "a suffix match would admit an attacker-registered lookalike"
        );
        assert!(
            policy.admit("evil.com").is_none(),
            "an unrelated host must not be admitted"
        );
    }

    #[test]
    fn matching_is_case_and_whitespace_insensitive() {
        let policy = EgressPolicy::new(vec!["  API.Example.COM ".into()]);
        assert!(policy.admit("api.example.com").is_some());
    }

    #[test]
    fn an_empty_host_is_never_admitted() {
        let policy = EgressPolicy::new(vec!["*".into()]);
        assert!(policy.admit("").is_none());
        assert!(policy.admit("   ").is_none());
    }

    /// `Admitted` must be unforgeable outside this module. This test documents
    /// the property; the compiler enforces it, because the field is private and
    /// there is no other constructor.
    #[test]
    fn admitted_has_no_public_constructor() {
        let policy = EgressPolicy::new(vec!["a.example".into()]);
        let a = policy.admit("a.example").unwrap();
        // The only way to get here was through `admit`. A caller outside this
        // module cannot write `Admitted { host: .. }`.
        assert_eq!(a.host(), "a.example");
    }
}
