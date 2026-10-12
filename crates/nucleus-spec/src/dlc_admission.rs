//! Pod-scoped DLC-D verified-admission provisioning: which PodSpec label becomes
//! which tool-proxy environment variable, declared once.
//!
//! # Why this module exists
//!
//! The mapping `dlc_trusted_keys -> NUCLEUS_DLC_TRUSTED_KEYS` (and its two
//! siblings) used to be written out by hand at every hop it crosses:
//!
//! - the CLI wrote the label names into `verify --tier2`'s PodSpec;
//! - the node read them in `DlcAdmissionMaterial::from_labels` (Firecracker)
//!   and again, as a `(label, env)` table, in `spawn_local_pod`;
//! - the node and guest-init each declared the `FETCH_DLC_ADMISSION` wire
//!   struct;
//! - guest-init and the tool-proxy each spelled the env names.
//!
//! That is one fact written six times (ADR 0007 G-1). The copies agreed, so
//! nothing went red, and the one that was never written was invisible: the
//! container driver runs the same tool-proxy in proxy mode and forwarded no
//! `NUCLEUS_DLC_*` at all, so a container pod's labels were accepted, shown by
//! `nucleus node pods`, and never reached the gate (#2903).
//!
//! Every hop now reads [`DlcField`] and [`DlcProvisioning`]. The wire struct is
//! derived (F-1) with the field names the node has always served, so a guest
//! built before this module parses the reply unchanged.
//!
//! # What does not travel this way
//!
//! The kernel command line. On Firecracker these values reach the guest over
//! the workload API (`FETCH_DLC_ADMISSION`, served once), never as `KEY=VALUE`
//! tokens for PID 1: the command line is world-readable inside the guest and
//! node-owned, and a credential set does not belong on it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The prefix every provisioning variable shares.
///
/// The tool-proxy's workload-env classifier keys on it, so a field whose
/// [`DlcField::env`] did not start with it would reach the workload unscrubbed.
/// `every_env_name_carries_the_prefix` holds the two together.
pub const ENV_PREFIX: &str = "NUCLEUS_DLC_";

/// One component of the provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlcField {
    /// Comma-separated 64-hex Ed25519 issuer public keys: the trust anchors.
    /// Its presence is what turns the gate on.
    TrustedKeys,
    /// 64-hex public key of the issuer whose credentials this pod presents.
    Issuer,
    /// Comma-separated `operation=hex_signature` credentials.
    Credentials,
}

impl DlcField {
    /// Every field, in wire order.
    pub const ALL: [DlcField; 3] = [
        DlcField::TrustedKeys,
        DlcField::Issuer,
        DlcField::Credentials,
    ];

    /// The PodSpec `metadata.labels` key that carries this field.
    pub const fn label(self) -> &'static str {
        match self {
            DlcField::TrustedKeys => "dlc_trusted_keys",
            DlcField::Issuer => "dlc_issuer",
            DlcField::Credentials => "dlc_credentials",
        }
    }

    /// The environment variable the tool-proxy reads this field from.
    pub const fn env(self) -> &'static str {
        match self {
            DlcField::TrustedKeys => "NUCLEUS_DLC_TRUSTED_KEYS",
            DlcField::Issuer => "NUCLEUS_DLC_ISSUER",
            DlcField::Credentials => "NUCLEUS_DLC_CREDENTIALS",
        }
    }
}

/// A pod's provisioning, verbatim from its labels.
///
/// Values are NOT validated here: the tool-proxy's parser owns that and fails
/// closed, so a malformed value narrows what the pod may do and never widens
/// it. This is also the `FETCH_DLC_ADMISSION` reply body, so the field names
/// are a wire format the published guests already parse.
///
/// No `Debug`: `credentials` are this pod's signed admission credentials, and a
/// derived `Debug` would put them one `{:?}` away from a log line.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlcProvisioning {
    /// [`DlcField::TrustedKeys`].
    pub trusted_keys: String,
    /// [`DlcField::Issuer`].
    pub issuer: String,
    /// [`DlcField::Credentials`].
    pub credentials: String,
}

impl DlcProvisioning {
    /// The provisioning a PodSpec's labels ask for, or `None` when they ask for
    /// none.
    ///
    /// Present exactly when `dlc_trusted_keys` is: without trust anchors the
    /// gate is inert whatever else is set. A missing issuer or credential set is
    /// still provisioned (as empty), because the proxy then denies rather than
    /// skips — misconfiguration narrows.
    pub fn from_labels(labels: &BTreeMap<String, String>) -> Option<Self> {
        let field = |f: DlcField| labels.get(f.label()).cloned();
        Some(Self {
            trusted_keys: field(DlcField::TrustedKeys)?,
            issuer: field(DlcField::Issuer).unwrap_or_default(),
            credentials: field(DlcField::Credentials).unwrap_or_default(),
        })
    }

    /// The node's own provisioning, from its environment's [`DlcField::env`] names: present exactly
    /// when the trust anchors are, as [`Self::from_labels`] reads the labels.
    ///
    /// A local tool-proxy used to inherit these variables from the node (`Command` does not
    /// `env_clear`), so the guest gated on them while the host, reading labels only, did not.
    /// The node now reads them once, at start-up, and [`Self::admitted`] decides with them.
    pub fn from_env(read: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let field = |f: DlcField| read(f.env());
        Some(Self {
            trusted_keys: field(DlcField::TrustedKeys)?,
            issuer: field(DlcField::Issuer).unwrap_or_default(),
            credentials: field(DlcField::Credentials).unwrap_or_default(),
        })
    }

    /// The provisioning a pod is admitted under: its labels' whole, when they ask for one, and
    /// otherwise the node's own. The one decider of which DLC-D admission a pod runs under
    /// (ADR 0007 G-1): the node records the result in the pod's authority, the host's kernel is
    /// provisioned from that record, and every driver delivers that record to the guest, so the
    /// two kernels decide from the same value.
    ///
    /// Labels win whole, never field by field: this is the precedence the local driver always
    /// had (the labels' three variables overwrote the inherited three).
    pub fn admitted(labels: &BTreeMap<String, String>, node: Option<&Self>) -> Option<Self> {
        Self::from_labels(labels).or_else(|| node.cloned())
    }

    /// The value of one field.
    pub fn get(&self, field: DlcField) -> &str {
        match field {
            DlcField::TrustedKeys => &self.trusted_keys,
            DlcField::Issuer => &self.issuer,
            DlcField::Credentials => &self.credentials,
        }
    }

    /// The labels that ask for this provisioning — what a PodSpec author writes.
    pub fn labels(&self) -> BTreeMap<String, String> {
        DlcField::ALL
            .iter()
            .map(|&f| (f.label().to_string(), self.get(f).to_string()))
            .collect()
    }

    /// The `(name, value)` environment the tool-proxy is started with.
    ///
    /// Every driver that runs a tool-proxy injects exactly this: the local
    /// driver on the child it spawns, the container driver in proxy mode, and
    /// guest-init on the proxy it execs from what `FETCH_DLC_ADMISSION` served.
    pub fn env(&self) -> [(&'static str, &str); 3] {
        DlcField::ALL.map(|f| (f.env(), self.get(f)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provisioning() -> DlcProvisioning {
        DlcProvisioning {
            trusted_keys: "aa".repeat(32),
            issuer: "bb".repeat(32),
            credentials: "read_files=cc".to_string(),
        }
    }

    /// A pod's labels win whole over the node's own provisioning, never field by field, and a pod
    /// that asks for none runs under the node's: the precedence the local driver's child saw when
    /// the labels' variables overwrote the inherited ones.
    #[test]
    fn admitted_is_the_labels_whole_else_the_nodes() {
        let node = provisioning();
        let env: BTreeMap<String, String> = node
            .env()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let from_env = DlcProvisioning::from_env(|name| env.get(name).cloned());
        assert!(from_env.as_ref() == Some(&node), "the env reads back whole");
        assert!(DlcProvisioning::from_env(|_| None).is_none());

        let none = BTreeMap::new();
        assert!(DlcProvisioning::admitted(&none, Some(&node)) == Some(node.clone()));
        assert!(DlcProvisioning::admitted(&none, None).is_none());

        let mut labels = BTreeMap::new();
        labels.insert(DlcField::TrustedKeys.label().to_string(), "dd".repeat(32));
        let admitted = DlcProvisioning::admitted(&labels, Some(&node)).expect("labels ask");
        assert_eq!(admitted.get(DlcField::TrustedKeys), "dd".repeat(32));
        assert_eq!(
            admitted.get(DlcField::Issuer),
            "",
            "no field leaks from the node"
        );
        assert_eq!(admitted.get(DlcField::Credentials), "");
    }

    /// `ALL` names every variant: a variant added without a row here is a
    /// field no driver forwards. The `match` breaks the build when one is added.
    #[test]
    fn all_lists_every_field() {
        for f in DlcField::ALL {
            let next = match f {
                DlcField::TrustedKeys => DlcField::Issuer,
                DlcField::Issuer => DlcField::Credentials,
                DlcField::Credentials => DlcField::TrustedKeys,
            };
            assert!(DlcField::ALL.contains(&next), "{next:?} missing from ALL");
        }
    }

    #[test]
    fn every_env_name_carries_the_prefix() {
        for f in DlcField::ALL {
            assert!(f.env().starts_with(ENV_PREFIX), "{}", f.env());
        }
    }

    /// The labels a spec author writes come back as the env the proxy reads,
    /// value for value — the whole mapping, through the one declaration.
    #[test]
    fn labels_round_trip_to_the_proxy_env() {
        let p = provisioning();
        let back = DlcProvisioning::from_labels(&p.labels()).expect("trusted keys present");
        assert!(back == p);
        let env: BTreeMap<_, _> = back.env().into_iter().collect();
        assert_eq!(env["NUCLEUS_DLC_TRUSTED_KEYS"], "aa".repeat(32));
        assert_eq!(env["NUCLEUS_DLC_ISSUER"], "bb".repeat(32));
        assert_eq!(env["NUCLEUS_DLC_CREDENTIALS"], "read_files=cc");
    }

    #[test]
    fn no_trust_anchors_means_no_provisioning() {
        let mut labels = provisioning().labels();
        labels.remove(DlcField::TrustedKeys.label());
        assert!(DlcProvisioning::from_labels(&labels).is_none());
    }

    /// Partial labels still provision, so the proxy denies rather than skips.
    #[test]
    fn trust_anchors_alone_still_provision() {
        let labels = BTreeMap::from([(DlcField::TrustedKeys.label().to_string(), "aa".repeat(32))]);
        let p = DlcProvisioning::from_labels(&labels).expect("provisioned");
        assert_eq!(p.issuer, "");
        assert_eq!(p.credentials, "");
    }

    /// The reply body published guests parse. Pinned as text: renaming a field
    /// here would compile everywhere in this tree and break every guest
    /// already released.
    #[test]
    fn the_wire_body_is_the_one_released_guests_parse() {
        let body = serde_json::to_value(provisioning()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "trusted_keys": "aa".repeat(32),
                "issuer": "bb".repeat(32),
                "credentials": "read_files=cc",
            })
        );
    }
}
