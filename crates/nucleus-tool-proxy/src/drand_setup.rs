//! Building the drand client, and the egress proof it now requires.
//!
//! Extracted from `main` when the client gained an egress admission argument:
//! `main.rs` sits on its line ratchet, so the policy check had to buy its own
//! room — which is what the ratchet is for.
//!
//! The substance is the `admit` call. A pod runs under default-deny egress, so
//! the beacon at `api.drand.sh` is unreachable by construction; the old code
//! built a client anyway and spent a five-second timeout per boot discovering
//! it (measured on an M5 Pro: 5044 ms of a 5497 ms startup). Now the pod's own
//! allowlist decides, and without an `Admitted` there is no client to build.

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use nucleus_client::drand::{DrandClient, DrandConfig, DrandFailMode};

use crate::Args;

/// Build the audit log's drand client, if the pod is allowed to reach the beacon.
pub(crate) fn build_drand_client(args: &Args, dns_allow: &[String]) -> Option<Arc<DrandClient>> {
    // Set up drand client for cryptographic time anchoring if drand is enabled
    if !args.drand_enabled {
        return None;
    }
    {
        let fail_mode = match args.drand_fail_mode.to_lowercase().as_str() {
            "cached" => DrandFailMode::Cached,
            _ => DrandFailMode::Strict,
        };
        let config = DrandConfig {
            enabled: true,
            api_url: args.drand_url.clone(),
            round_tolerance: args.drand_tolerance,
            cache_ttl: Duration::from_secs(25),
            fail_mode,
            chain_hash: None, // Use default
            public_key: None, // Use default
        };
        info!(
            "drand anchoring enabled for audit logs (url={}, tolerance={})",
            args.drand_url, args.drand_tolerance
        );
        // Exit with the reason rather than panicking. In a microVM this process
        // is PID 1: a panic here kills init and panics the kernel, so the
        // operator sees a reqwest error inside a kernel backtrace instead of the
        // one sentence that tells them what to do.
        //
        // Refusing to start (rather than degrading to `None`) is deliberate: the
        // operator asked for drand anchoring, and a pod that ran without it
        // while reporting success would be a claim outrunning its wiring. The
        // escalation path already refuses when drand is absent; this makes the
        // refusal legible at the moment it is decided.
        // The pod's OWN egress policy decides whether the beacon is reachable.
        // Under default-deny it is not, and there is then no `Admitted` to pass
        // — so the client cannot be built, rather than being built and spending
        // five seconds per boot discovering it (measured: 5044ms of 5497ms).
        let beacon_host = config
            .api_url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default()
            .to_string();
        let admitted =
            nucleus_client::egress::EgressPolicy::new(dns_allow.to_vec()).admit(&beacon_host);
        match admitted {
            None => {
                warn!(
                    host = %beacon_host,
                    "drand anchoring requested, but this pod's egress policy does not \
                     admit the beacon host, so anchoring is unavailable. Add the host \
                     to dns_allow if the workload genuinely needs anchored approvals."
                );
                None
            }
            Some(admitted) => match DrandClient::new(config, admitted) {
                Ok(c) => Some(Arc::new(c)),
                Err(why) => {
                    error!("{why}");
                    eprintln!("FATAL: {why}");
                    std::process::exit(1);
                }
            },
        }
    }
}
