//! How a workload is told about its credentialed upstreams, written once.
//!
//! # Two writers, one spelling
//!
//! The tool-proxy WRITES `NUCLEUS_EGRESS_<NAME>_URL` into the workload's
//! environment: the workload door's `unix://` URL followed by the upstream's
//! egress route. `nucleus-egress-http`, which runs as the workload, READS that
//! variable to learn which upstreams the pod declared, and then OVERWRITES it
//! for the command it manages with the loopback `http://` URL an ordinary HTTP
//! client can dial. If each of the three spelled the key or the route itself,
//! the first to disagree would make a declared upstream look undeclared, or
//! the reverse, far from the cause (ADR 0007 G-1). So the key and the route are
//! functions here, and every party calls them.
//!
//! # What is never here
//!
//! A credential, or anything naming one. These are names and local addresses;
//! the credential stays on the host, which performs the call.

/// The door route every credentialed call is made on, up to the upstream
/// name: `/v1/egress/<name>/<path>`.
pub const ROUTE_PREFIX: &str = "/v1/egress/";

/// The environment variable a workload finds upstream `name`'s URL in:
/// `NUCLEUS_EGRESS_<NAME>_URL`, upper-cased, `-` read as `_`.
#[must_use]
pub fn url_env(name: &str) -> String {
    format!(
        "NUCLEUS_EGRESS_{}_URL",
        name.to_uppercase().replace('-', "_")
    )
}

/// The URL the runtime gives the workload for upstream `name`, under the
/// endpoint `base` (the door's `unix://` URL, or a loopback `http://` origin):
/// `<base>/v1/egress/<name>`.
#[must_use]
pub fn upstream_url(base: &str, name: &str) -> String {
    format!("{}{ROUTE_PREFIX}{name}", base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_and_the_url_are_spelled_as_the_runtime_has_always_spelled_them() {
        assert_eq!(url_env("model-api"), "NUCLEUS_EGRESS_MODEL_API_URL");
        assert_eq!(
            upstream_url("unix:///run/nucleus-door/workload.sock", "model-api"),
            "unix:///run/nucleus-door/workload.sock/v1/egress/model-api"
        );
        assert_eq!(
            upstream_url("http://127.0.0.1:9/", "git"),
            "http://127.0.0.1:9/v1/egress/git"
        );
    }
}
