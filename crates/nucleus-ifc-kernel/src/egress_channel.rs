//! C6 phase 0 — the **closed egress-channel inventory** as a gated object.
//!
//! # Why this exists
//!
//! C6 is the North Star clause "*every mediated channel*"
//! (`docs/north-star.md`). C1 made the **inbound** half tractable with a closed
//! [`ChannelKind`](crate::extracted::channel::ChannelKind) enum the completeness
//! theorem quantifies over — a new inbound channel forces a `match` arm or the
//! flagship will not compile. C6's **outbound/effect** half is the harder one:
//! the ways an agent workload can move data out or reach a sink were, until now,
//! prose in `docs/architecture/mediated-set.md` with no gated object behind
//! them, so "a new transport bypasses the model by never entering the taxonomy"
//! was an argument, not a checked fact.
//!
//! This module makes the inventory a **closed enum**. [`EgressChannel`]
//! enumerates every documented egress/transport channel; the parity test below
//! asserts the enum variants ≡ the channel rows in `mediated-set.md`, so adding
//! a channel forces BOTH a new enum arm AND a doc-table edit — the categorical
//! gate. Each variant carries its [`MediationStatus`] (type-enforced /
//! backstopped-only / partial / open-hole / infra-out-of-set), and the parity
//! test also pins the status against the documented one, so a status change is
//! likewise a doc+code event.
//!
//! # Scope of this brick (phase 0 — additive, verdict-neutral)
//!
//! The enum is **not consumed by any runtime path yet**. It changes no egress
//! verdict, no ledger row, no ratchet. Phase 1 proves the Tier-A total-mediation
//! theorem over the `SinkClass`/`Operation` enums; this brick only turns the
//! inventory into an object a gate can hold. It is deliberately a **plain closed
//! enum outside `extracted/`** — the Aeneas slice is untouched.

/// How thoroughly a channel's egress is mediated.
///
/// The five statuses are the vocabulary the `mediated-set.md` inventory tags
/// each channel with. They are ordered from strongest to weakest fence, but the
/// numeric rank is *not* a lattice — it exists only so the discriminant is
/// stable for the parity test.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediationStatus {
    /// The effect is admitted only past a `preflight_action → DischargedBundle`
    /// and the type system makes an un-preflighted call a **compile error**
    /// (the effect method takes an owned `Authority` by value).
    TypeEnforced = 0,
    /// Not mediated by the sink lattice; physically confined by the
    /// netns/Firecracker **default-deny** network policy only.
    BackstoppedOnly = 1,
    /// Some frames on this transport are mediated, others rest on a structural
    /// property (peer-CID pin, identity refusal) rather than a token.
    Partial = 2,
    /// A known unmediated path with no fence beyond "tracked open". No channel
    /// currently carries this status; `no_channel_is_an_open_hole` asserts the
    /// set stays empty — the machine meaning of C6's "every mediated channel".
    OpenHole = 3,
    /// Out of the mediated set by construction: operator/host authority, never
    /// agent-controlled (see `mediated-set.md` exclusions).
    InfraOutOfSet = 4,
}

impl MediationStatus {
    /// The stable lowercase token used in the `mediated-set.md` status column.
    /// This string is the parity contract with the doc — do not reword it
    /// without editing the table in the same change.
    pub const fn doc_token(self) -> &'static str {
        match self {
            MediationStatus::TypeEnforced => "type-enforced",
            MediationStatus::BackstoppedOnly => "backstopped-only",
            MediationStatus::Partial => "partial",
            MediationStatus::OpenHole => "open-hole",
            MediationStatus::InfraOutOfSet => "infra-out-of-set",
        }
    }
}

/// One documented way an agent workload can move data out or reach a sink.
///
/// This is the **closed** outbound analogue of
/// [`ChannelKind`](crate::extracted::channel::ChannelKind). It is exhaustive
/// over the `mediated-set.md` §"egress channel inventory" table; the
/// `documented_inventory_equals_the_enum` test enforces that equivalence. A new
/// egress or transport channel MUST add both a variant here and a row there, or
/// a gate reds.
///
/// Not `#[non_exhaustive]` — being closed is the entire point: downstream code
/// (and, in phase 1, the theorem) must be forced to handle every channel.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressChannel {
    /// Agent process spawn (sync/async) through the Executor →
    /// `ShellEffect::run_argv[_async]`. Raw spawn allowlist is empty; an
    /// un-preflighted spawn is a compile error.
    AgentSpawn = 0,
    /// Agent HTTP egress (`web_fetch`/`web_search`) → `NetEffect::fetch`.
    AgentHttpEgress = 1,
    /// Agent filesystem write → `Sandbox::write(_proof)`; all `Sandbox` methods
    /// take an owned `Authority`.
    AgentFsWrite = 2,
    /// Credentialed egress via the broker (host performs the call);
    /// `perform_line` takes an `Authority`, vsock frame grep-gated.
    BrokerCredentialedEgress = 3,
    /// In-shell egress (`bash -c curl`, `/dev/tcp`, `python`, `nc`) inside the
    /// spawned child. Sink label `BashExec` is a heuristic, not a physical
    /// fact; fenced by the netns default-deny only.
    InShellEgress = 4,
    /// DNS (tunnel/exfil vector) via the guest dnsmasq config — `no-resolv`, no
    /// upstream, so an unlisted name fails locally.
    Dns = 5,
    /// vsock transport for broker/task-token/SVID frames. Broker perform is
    /// mediated; other frames are host-issued, peer-CID pinned to
    /// `VMADDR_CID_HOST`.
    VsockTransport = 6,
    /// pod-dir Unix socket (container broker). Refuses container-runtime
    /// sockets; the container path registers no identity, so the broker refuses
    /// — a structural refusal, not a token.
    PodDirSocket = 7,
    /// node gRPC control plane — operator-provisioned endpoint, never
    /// agent-controlled.
    NodeGrpc = 8,
    /// netns raw socket (`std::net`, any linked lib) anywhere in the guest —
    /// same open class as in-shell egress.
    NetnsRawSocket = 9,
    /// Audit / Article-12 egress (S3, webhook) — the runtime's record OF the
    /// agent, an operator sink.
    AuditEgress = 10,
    /// The unmediated-effects escape hatch (#1248). The old raw
    /// `NucleusRuntime::effects()` accessor is gone; the only path to a raw
    /// bundle, `NucleusRuntime::unmediated_effects`, now requires a builder
    /// opt-in `UnmediatedAccess` token, a `DischargedBundle` discharged against
    /// the STRICTEST sink (`HTTPEgress`/`Untrusted` — fails on a tainted
    /// session), and a `FlowTracker` observation. Its effect methods take an
    /// owned `Authority` by value, so an un-preflighted call is a compile error.
    EffectsEscapeHatch = 11,
}

// Compile-time invariant: discriminants match declaration order (so a future
// Aeneas lift, or the phase-1 theorem, sees a dense `#[repr(u8)]` scalar — the
// same shape `channel.rs`/`ifc_ops.rs` rely on).
const _: () = {
    assert!(EgressChannel::AgentSpawn as u8 == 0);
    assert!(EgressChannel::AgentHttpEgress as u8 == 1);
    assert!(EgressChannel::AgentFsWrite as u8 == 2);
    assert!(EgressChannel::BrokerCredentialedEgress as u8 == 3);
    assert!(EgressChannel::InShellEgress as u8 == 4);
    assert!(EgressChannel::Dns as u8 == 5);
    assert!(EgressChannel::VsockTransport as u8 == 6);
    assert!(EgressChannel::PodDirSocket as u8 == 7);
    assert!(EgressChannel::NodeGrpc as u8 == 8);
    assert!(EgressChannel::NetnsRawSocket as u8 == 9);
    assert!(EgressChannel::AuditEgress as u8 == 10);
    assert!(EgressChannel::EffectsEscapeHatch as u8 == 11);
};

impl EgressChannel {
    /// All 12 egress channels, in discriminant order.
    pub const ALL: [EgressChannel; 12] = [
        EgressChannel::AgentSpawn,
        EgressChannel::AgentHttpEgress,
        EgressChannel::AgentFsWrite,
        EgressChannel::BrokerCredentialedEgress,
        EgressChannel::InShellEgress,
        EgressChannel::Dns,
        EgressChannel::VsockTransport,
        EgressChannel::PodDirSocket,
        EgressChannel::NodeGrpc,
        EgressChannel::NetnsRawSocket,
        EgressChannel::AuditEgress,
        EgressChannel::EffectsEscapeHatch,
    ];

    /// Numeric rank == discriminant, spelled out so no derived comparison is
    /// relied on (mirrors `channel.rs::chanrank`).
    pub const fn rank(self) -> u8 {
        match self {
            EgressChannel::AgentSpawn => 0,
            EgressChannel::AgentHttpEgress => 1,
            EgressChannel::AgentFsWrite => 2,
            EgressChannel::BrokerCredentialedEgress => 3,
            EgressChannel::InShellEgress => 4,
            EgressChannel::Dns => 5,
            EgressChannel::VsockTransport => 6,
            EgressChannel::PodDirSocket => 7,
            EgressChannel::NodeGrpc => 8,
            EgressChannel::NetnsRawSocket => 9,
            EgressChannel::AuditEgress => 10,
            EgressChannel::EffectsEscapeHatch => 11,
        }
    }

    /// The stable machine key used in the `mediated-set.md` inventory `Key`
    /// column. This string is the parity contract with the doc.
    pub const fn doc_key(self) -> &'static str {
        match self {
            EgressChannel::AgentSpawn => "agent_spawn",
            EgressChannel::AgentHttpEgress => "agent_http_egress",
            EgressChannel::AgentFsWrite => "agent_fs_write",
            EgressChannel::BrokerCredentialedEgress => "broker_credentialed_egress",
            EgressChannel::InShellEgress => "in_shell_egress",
            EgressChannel::Dns => "dns",
            EgressChannel::VsockTransport => "vsock_transport",
            EgressChannel::PodDirSocket => "pod_dir_socket",
            EgressChannel::NodeGrpc => "node_grpc",
            EgressChannel::NetnsRawSocket => "netns_raw_socket",
            EgressChannel::AuditEgress => "audit_egress",
            EgressChannel::EffectsEscapeHatch => "effects_escape_hatch",
        }
    }

    /// The channel's mediation status, as documented in the inventory table.
    pub const fn status(self) -> MediationStatus {
        match self {
            EgressChannel::AgentSpawn
            | EgressChannel::AgentHttpEgress
            | EgressChannel::AgentFsWrite
            | EgressChannel::BrokerCredentialedEgress => MediationStatus::TypeEnforced,
            EgressChannel::InShellEgress | EgressChannel::Dns | EgressChannel::NetnsRawSocket => {
                MediationStatus::BackstoppedOnly
            }
            EgressChannel::VsockTransport | EgressChannel::PodDirSocket => MediationStatus::Partial,
            EgressChannel::NodeGrpc | EgressChannel::AuditEgress => MediationStatus::InfraOutOfSet,
            // #1248 closed: unmediated_effects requires opt-in token + strictest-
            // sink discharge + FlowTracker observe, and the effect methods take
            // Authority by value (compile-error on an un-preflighted call).
            EgressChannel::EffectsEscapeHatch => MediationStatus::TypeEnforced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// `as u8` parity with the explicit rank, so a future extraction never sees
    /// a derived discriminant.
    #[test]
    fn rank_matches_the_discriminant() {
        for c in EgressChannel::ALL {
            assert_eq!(c.rank(), c as u8);
        }
    }

    /// `ALL` is complete and in discriminant order — the array cannot silently
    /// drop a variant (a shrinkable list would let a channel leave the gated
    /// set unnoticed).
    #[test]
    fn all_is_dense_and_ordered() {
        for (i, c) in EgressChannel::ALL.iter().enumerate() {
            assert_eq!(c.rank() as usize, i, "ALL[{i}] = {c:?} out of order");
        }
    }

    /// **THE MACHINE MEANING OF "EVERY".** C6 is "*every mediated channel*". A
    /// channel tagged `open-hole` is, by that status's own definition, a path
    /// with no fence — so "every" cannot hold while any channel carries it. This
    /// asserts the closed inventory contains ZERO open holes; it reds if any
    /// channel regresses to `OpenHole` (e.g. the #1248 unmediated-effects guard
    /// being reverted and the status honestly following). It is the regression
    /// guard behind moving C6 off NOT-YET.
    #[test]
    fn no_channel_is_an_open_hole() {
        let holes: Vec<&str> = EgressChannel::ALL
            .iter()
            .filter(|c| c.status() == MediationStatus::OpenHole)
            .map(|c| c.doc_key())
            .collect();
        assert!(
            holes.is_empty(),
            "these egress channels are open holes, so C6's \"every mediated channel\" \
             does not hold: {holes:?}"
        );
    }

    /// Keys are unique — the parity contract depends on the key being an
    /// identity, not a repeated label.
    #[test]
    fn doc_keys_are_unique() {
        let mut seen = BTreeMap::new();
        for c in EgressChannel::ALL {
            assert!(
                seen.insert(c.doc_key(), c).is_none(),
                "duplicate doc_key {:?}",
                c.doc_key()
            );
        }
    }

    // ── The categorical gate: documented inventory ≡ the enum ────────────────

    /// Path to the inventory doc, relative to this crate's manifest dir.
    fn mediated_set_md() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/mediated-set.md"
        ))
        .expect("mediated-set.md must be readable from the crate manifest dir")
    }

    /// Parse the fenced inventory table into `key -> status token`.
    ///
    /// Robust form (per the task's fallback guidance): the table is bounded by
    /// explicit `<!-- C6-INVENTORY-{START,END} -->` markers, and column values
    /// are located by their HEADER NAME (`Key`, `Status`), not by fixed
    /// position — so reordering or inserting a human column cannot silently
    /// desync the gate. The machine cells are the only backticked tokens in
    /// their column.
    fn parse_documented_inventory() -> BTreeMap<String, String> {
        let doc = mediated_set_md();
        let start = doc
            .find("<!-- C6-INVENTORY-START -->")
            .expect("inventory START marker present in mediated-set.md");
        let end = doc
            .find("<!-- C6-INVENTORY-END -->")
            .expect("inventory END marker present in mediated-set.md");
        assert!(start < end, "inventory markers out of order");
        let block = &doc[start..end];

        let rows: Vec<Vec<String>> = block
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('|'))
            // drop the separator row (|---|---|)
            .filter(|l| !l.trim_start_matches('|').trim_start().starts_with('-'))
            .map(|l| {
                l.trim_matches('|')
                    .split('|')
                    .map(|c| c.trim().to_string())
                    .collect()
            })
            .collect();

        assert!(rows.len() >= 2, "inventory table must have a header + rows");
        let header = &rows[0];
        let col = |name: &str| -> usize {
            header
                .iter()
                .position(|h| h.eq_ignore_ascii_case(name))
                .unwrap_or_else(|| panic!("inventory header must have a '{name}' column"))
        };
        let key_col = col("Key");
        let status_col = col("Status");

        // Backticked token extractor: `agent_spawn` -> agent_spawn.
        let untick = |cell: &str| -> String { cell.trim().trim_matches('`').trim().to_string() };

        let mut out = BTreeMap::new();
        for r in &rows[1..] {
            let key = untick(&r[key_col]);
            let status = untick(&r[status_col]);
            assert!(
                !key.is_empty(),
                "inventory row has an empty Key cell: {r:?}"
            );
            assert!(
                out.insert(key.clone(), status).is_none(),
                "duplicate documented channel key: {key}"
            );
        }
        out
    }

    /// **THE C6 PHASE-0 GATE.** The documented channel set in `mediated-set.md`
    /// equals the `EgressChannel` enum variants, key for key, AND each row's
    /// status matches the variant's `status()`. Adding a channel therefore
    /// forces a new enum arm AND a doc row; changing a status forces both too.
    #[test]
    fn documented_inventory_equals_the_enum() {
        let documented = parse_documented_inventory();

        let enum_keys: std::collections::BTreeSet<&str> =
            EgressChannel::ALL.iter().map(|c| c.doc_key()).collect();
        let doc_keys: std::collections::BTreeSet<&str> =
            documented.keys().map(String::as_str).collect();

        let missing_from_doc: Vec<&&str> = enum_keys.difference(&doc_keys).collect();
        let missing_from_enum: Vec<&&str> = doc_keys.difference(&enum_keys).collect();
        assert!(
            missing_from_doc.is_empty(),
            "enum variants with no mediated-set.md row (add the row): {missing_from_doc:?}"
        );
        assert!(
            missing_from_enum.is_empty(),
            "mediated-set.md rows with no EgressChannel arm (add the variant): {missing_from_enum:?}"
        );

        // Count parity — belt-and-braces against duplicate keys collapsing.
        assert_eq!(
            documented.len(),
            EgressChannel::ALL.len(),
            "documented channel count ({}) != enum variant count ({})",
            documented.len(),
            EgressChannel::ALL.len()
        );

        // Status parity, per channel.
        for c in EgressChannel::ALL {
            let doc_status = &documented[c.doc_key()];
            assert_eq!(
                doc_status,
                c.status().doc_token(),
                "channel {} documented status {:?} != enum status {:?}",
                c.doc_key(),
                doc_status,
                c.status().doc_token()
            );
        }
    }
}
