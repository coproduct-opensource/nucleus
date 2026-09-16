//! The guest surface of the command walk — `docs/design/command-walk.md`.
//!
//! A random sequence of guest commands is run against a pod provisioned at
//! random, through [`serve_frame`], the same function a vsock connection reaches.
//! Beside it runs a model of what the host must do, and every step is checked
//! against the model. Two laws from the design are asserted here:
//!
//! - **A2, one-shot absorption.** `v ; v = v ; Refusal(AlreadyServed)` for the
//!   broker secret, the mediation key and the audit credentials, and the refusal
//!   carries **none of the secret's bytes**. A walk that only checked "the second
//!   call errors" would miss the failure that matters: a refusal that leaks the
//!   value in its diagnostic.
//! - **A5, personalisation and snapshot do not commute.** After any command that
//!   personalises the VM, `clone_safety` must say `PersonalizedSince`, whatever
//!   else happened; before it, the verdict follows `SNAPSHOT_READY`.
//!
//! # The disabled set is the oracle
//!
//! Commands are drawn whether or not the model says they may succeed, and a
//! refused command must be refused for the **specific** [`Refusal`] the model
//! names, compared as a value. That is what [`Refusal`] exists for.
//!
//! # What the model borrows, and what it does not
//!
//! Which commands personalise is read from `personalizes_the_vm`, not restated:
//! that match is exhaustive, and a second copy here would be a parity test
//! (ADR 0007 G). What the walk checks is that `serve_frame` *records* it, for
//! every command, in every order. Everything else the model decides itself.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use proptest::prelude::*;

use super::*;
use crate::snapshot::{MountState, SnapshotSafety, clone_safety};
use crate::workload_api_protocol::{CommandParseError, WorkloadApiCommand as Cmd};

/// Values distinctive enough that finding one in a refusal is a leak, not a
/// coincidence.
const BROKER_SECRET: &str = "walk-broker-secret-5d1f0c";
const MEDIATION_KEY: &str = "walk-mediation-key-a93b27";
const AUDIT_SECRET: &str = "walk-audit-secret-7e40d8";
const LEAKABLE: [&str; 3] = [BROKER_SECRET, MEDIATION_KEY, AUDIT_SECRET];

/// A kernel command line `snapshot_safety` accepts, so the verdict turns only
/// on what the walk changes.
const CLEAN_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off init=/init";

/// Every command. [`ordinal`] is an exhaustive match, so adding a command to the
/// protocol stops this file compiling until the walk can draw it.
const COMMANDS: [Cmd; 14] = [
    Cmd::FetchSvid,
    Cmd::FetchBundle,
    Cmd::Ping,
    Cmd::FetchTaskToken,
    Cmd::FetchDlcAdmission,
    Cmd::FetchBrokerSecret,
    Cmd::FetchPodCallerToken,
    Cmd::FetchPodCertificate,
    Cmd::FetchAuditCredentials,
    Cmd::FetchMediationKey,
    Cmd::PodList,
    Cmd::FetchPodSpec,
    Cmd::ShipReceipt,
    Cmd::SnapshotReady,
];

fn ordinal(c: Cmd) -> usize {
    match c {
        Cmd::FetchSvid => 0,
        Cmd::FetchBundle => 1,
        Cmd::Ping => 2,
        Cmd::FetchTaskToken => 3,
        Cmd::FetchDlcAdmission => 4,
        Cmd::FetchBrokerSecret => 5,
        Cmd::FetchPodCallerToken => 6,
        Cmd::FetchPodCertificate => 7,
        Cmd::FetchAuditCredentials => 8,
        Cmd::FetchMediationKey => 9,
        Cmd::PodList => 10,
        Cmd::FetchPodSpec => 11,
        Cmd::ShipReceipt => 12,
        Cmd::SnapshotReady => 13,
    }
}

fn wire_name(c: Cmd) -> &'static str {
    match c {
        Cmd::FetchSvid => "FETCH_SVID",
        Cmd::FetchBundle => "FETCH_BUNDLE",
        Cmd::Ping => "PING",
        Cmd::FetchTaskToken => "FETCH_TASK_TOKEN",
        Cmd::FetchDlcAdmission => "FETCH_DLC_ADMISSION",
        Cmd::FetchBrokerSecret => "FETCH_BROKER_SECRET",
        Cmd::FetchPodCallerToken => "FETCH_POD_CALLER_TOKEN",
        Cmd::FetchPodCertificate => "FETCH_POD_CERTIFICATE",
        Cmd::FetchAuditCredentials => "FETCH_AUDIT_CREDENTIALS",
        Cmd::FetchMediationKey => "FETCH_MEDIATION_KEY",
        Cmd::PodList => "POD_LIST",
        Cmd::FetchPodSpec => "FETCH_POD_SPEC",
        Cmd::ShipReceipt => "SHIP_RECEIPT",
        Cmd::SnapshotReady => "SNAPSHOT_READY",
    }
}

/// One step of the walk: a real command, or a token the parser must refuse.
#[derive(Debug, Clone)]
enum Op {
    Command(Cmd),
    Unknown,
}

/// What the host was given for this pod. Each item independently present or not.
#[derive(Debug, Clone, Copy)]
struct Provision {
    broker_secret: bool,
    mediation_key: bool,
    mediation_spiffe_id: bool,
    audit_creds: bool,
    pod_spec: bool,
    dlc_admission: bool,
    pod_certificate: bool,
    task_token: bool,
    caller_token: bool,
    receipts: bool,
}

/// What must happen when a command is issued in the current model state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expect {
    Served,
    Refused(Refusal),
}

/// The reference state: `pre` says what a command must do, `eff` advances it.
#[derive(Debug, Clone)]
struct Model {
    provision: Provision,
    broker_served: bool,
    mediation_key_served: bool,
    audit_served: bool,
    personalized: bool,
    at_barrier: bool,
}

impl Model {
    fn new(provision: Provision) -> Self {
        Model {
            provision,
            broker_served: false,
            mediation_key_served: false,
            audit_served: false,
            personalized: false,
            at_barrier: false,
        }
    }

    fn pre(&self, op: &Op) -> Expect {
        let p = &self.provision;
        let present = |held: bool, m: Material| {
            if held {
                Expect::Served
            } else {
                Expect::Refused(Refusal::NotProvisioned(m))
            }
        };
        // A refusal for absence comes BEFORE the one-shot check, and so never
        // spends it: a pod with nothing to serve must not be able to burn the
        // capability before a real provision exists.
        let once = |held: bool, served: bool, m: Material, o: OneShot| match (held, served) {
            (false, _) => Expect::Refused(Refusal::NotProvisioned(m)),
            (true, true) => Expect::Refused(Refusal::AlreadyServed(o)),
            (true, false) => Expect::Served,
        };
        match op {
            Op::Unknown => Expect::Refused(Refusal::Parse(CommandParseError::Unknown(
                UNKNOWN_TOKEN.to_string(),
            ))),
            Op::Command(c) => match c {
                Cmd::FetchSvid | Cmd::FetchBundle | Cmd::Ping | Cmd::PodList => Expect::Served,
                Cmd::SnapshotReady => Expect::Served,
                Cmd::FetchBrokerSecret => once(
                    p.broker_secret,
                    self.broker_served,
                    Material::BrokerSecret,
                    OneShot::BrokerSecret,
                ),
                Cmd::FetchMediationKey => once(
                    p.mediation_key && p.mediation_spiffe_id,
                    self.mediation_key_served,
                    Material::MediationKey,
                    OneShot::MediationKey,
                ),
                Cmd::FetchAuditCredentials => once(
                    p.audit_creds,
                    self.audit_served,
                    Material::AuditCredentials,
                    OneShot::AuditCredentials,
                ),
                Cmd::FetchPodSpec => present(p.pod_spec, Material::PodSpec),
                Cmd::FetchDlcAdmission => present(p.dlc_admission, Material::DlcAdmission),
                Cmd::FetchPodCertificate => present(p.pod_certificate, Material::PodCertificate),
                Cmd::FetchTaskToken => present(p.task_token, Material::TaskToken),
                Cmd::FetchPodCallerToken => present(p.caller_token, Material::CallerToken),
                Cmd::ShipReceipt => {
                    if p.receipts {
                        Expect::Served
                    } else {
                        Expect::Refused(Refusal::ReceiptCollectionNotConfigured)
                    }
                }
            },
        }
    }

    fn eff(&mut self, op: &Op, expect: &Expect) {
        let Op::Command(c) = op else { return };
        // Personalisation is recorded on the REQUEST, served or refused: a guest
        // that asked for its SVID is treated as one pod whether or not the host
        // had one to give, because the host cannot see what the guest did next.
        if c.personalizes_the_vm() {
            self.personalized = true;
        }
        let served = *expect == Expect::Served;
        match c {
            Cmd::FetchBrokerSecret => self.broker_served |= served,
            Cmd::FetchMediationKey => self.mediation_key_served |= served,
            Cmd::FetchAuditCredentials => self.audit_served |= served,
            Cmd::SnapshotReady => self.at_barrier = true,
            Cmd::FetchSvid
            | Cmd::FetchBundle
            | Cmd::Ping
            | Cmd::FetchTaskToken
            | Cmd::FetchDlcAdmission
            | Cmd::FetchPodCallerToken
            | Cmd::FetchPodCertificate
            | Cmd::PodList
            | Cmd::FetchPodSpec
            | Cmd::ShipReceipt => {}
        }
    }

    /// A5, stated from the model's own flags.
    fn snapshot_verdict(&self) -> SnapshotSafety {
        if self.personalized {
            SnapshotSafety::PersonalizedSince
        } else if !self.at_barrier {
            SnapshotSafety::NotAtBarrier
        } else {
            SnapshotSafety::SafeToClone
        }
    }
}

const UNKNOWN_TOKEN: &str = "FETCH_EVERYTHING";

/// The host's material for a provision. Every field named, no `..`: a field
/// added to `PodMaterial` stops this compiling until the walk decides whether it
/// is provisioned (ADR 0007 E).
fn material_for(p: Provision, receipt_dir: &std::path::Path) -> PodMaterial {
    PodMaterial {
        task_token: p.task_token.then(|| crate::session_mint::MintedTaskToken {
            token_json: r#"{"task":"walk"}"#.to_string(),
            nonce_hex: "00".repeat(16),
            issuer_hex: "11".repeat(32),
        }),
        pod_certificate: p
            .pod_certificate
            .then(|| crate::pod_authority::BootCertificate {
                token_b64: "d2Fsaw==".to_string(),
                root_pubkey_hex: "22".repeat(32),
            }),
        caller_token: p.caller_token.then(|| "walk-caller-token".to_string()),
        dlc_admission: p.dlc_admission.then(|| DlcAdmissionMaterial {
            trusted_keys: "33".repeat(32),
            issuer: "44".repeat(32),
            credentials: String::new(),
        }),
        broker_secret: p.broker_secret.then(|| BROKER_SECRET.to_string()),
        broker_port: 1027,
        broker_secret_served: Arc::default(),
        audit_creds: p.audit_creds.then(|| AuditCredentials {
            access_key_id: "walk-access-key-id".to_string(),
            secret_access_key: AUDIT_SECRET.to_string(),
            session_token: None,
        }),
        audit_creds_served: Arc::default(),
        pod_spec_yaml: p.pod_spec.then(|| "kind: Pod".to_string()),
        mediation_signing_key: p.mediation_key.then(|| MEDIATION_KEY.to_string()),
        mediation_spiffe_id: p
            .mediation_spiffe_id
            .then(|| "spiffe://walk.local/mediator".to_string()),
        at_snapshot_barrier: Arc::default(),
        personalized: Arc::default(),
        mediation_key_served: Arc::default(),
        receipt_dir: p.receipts.then(|| receipt_dir.to_path_buf()),
        pod_registry: crate::pod_api::PodRegistry::default(),
    }
}

fn provision() -> impl Strategy<Value = Provision> {
    proptest::collection::vec(any::<bool>(), 10).prop_map(|b| Provision {
        broker_secret: b[0],
        mediation_key: b[1],
        mediation_spiffe_id: b[2],
        audit_creds: b[3],
        pod_spec: b[4],
        dlc_admission: b[5],
        pod_certificate: b[6],
        task_token: b[7],
        caller_token: b[8],
        receipts: b[9],
    })
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        // One unknown token per ~30 draws: enough to keep the parse refusal in
        // every long walk, not so many that it crowds out the one-shots.
        29 => (0..COMMANDS.len()).prop_map(|i| Op::Command(COMMANDS[i])),
        1 => Just(Op::Unknown),
    ]
}

/// Run one walk. `Err` names the first step where the host and the model disagree.
fn walk(provision: Provision, ops: &[Op]) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(async {
        let receipts = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let manager = IdentityManager::new("walk.local", std::time::Duration::from_secs(3600))
            .map_err(|e| format!("identity manager: {e}"))?;
        let pod_id = uuid::Uuid::new_v4();
        let material = material_for(provision, receipts.path());
        let mut model = Model::new(provision);

        for (step, op) in ops.iter().enumerate() {
            let expect = model.pre(op);
            let frame = match op {
                Op::Command(c) => format!("{}\n", wire_name(*c)),
                Op::Unknown => format!("{UNKNOWN_TOKEN}\n"),
            };
            // SHIP_RECEIPT reads its body from the same connection.
            let mut rest: &[u8] = b"{\"receipt\":\"walk\"}\n";
            let reply = serve_frame(frame.as_bytes(), &mut rest, &manager, pod_id, &material).await;
            let at = || format!("step {step} {op:?} (expected {expect:?})");

            match (&expect, &reply) {
                (Expect::Served, Ok(body)) => {
                    serde_json::from_str::<serde_json::Value>(body)
                        .map_err(|e| format!("{}: served a non-JSON body: {e}", at()))?;
                }
                (Expect::Refused(want), Err(got)) if want == got => {}
                (_, _) => return Err(format!("{}: host replied {reply:?}", at())),
            }

            // A2: a refusal carries no secret bytes, on the wire, ever.
            if reply.is_err() {
                let bytes = wire(&reply);
                if let Some(leak) = LEAKABLE.iter().find(|s| bytes.contains(*s)) {
                    return Err(format!("{}: refusal leaked {leak}: {bytes}", at()));
                }
            }

            model.eff(op, &expect);

            // A5: the host's own record, and the snapshot decision made from it.
            let personalized = material.personalized.load(Ordering::SeqCst);
            let at_barrier = material.at_snapshot_barrier.load(Ordering::SeqCst);
            if (personalized, at_barrier) != (model.personalized, model.at_barrier) {
                return Err(format!(
                    "{}: host recorded personalized={personalized} at_barrier={at_barrier}, \
                     model says {} / {}",
                    at(),
                    model.personalized,
                    model.at_barrier
                ));
            }
            let verdict = clone_safety(
                CLEAN_BOOT_ARGS,
                at_barrier,
                personalized,
                &MountState::NeverMounted,
            );
            if verdict != model.snapshot_verdict() {
                return Err(format!(
                    "{}: snapshot verdict {verdict:?}, model says {:?}",
                    at(),
                    model.snapshot_verdict()
                ));
            }
        }
        Ok(())
    })
}

proptest! {
    // Each case builds an identity manager (a CA); 128 cases of up to 40 steps
    // keeps the walk to a few seconds while reaching every one-shot repeatedly.
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn the_guest_surface_agrees_with_its_model(
        provision in provision(),
        ops in proptest::collection::vec(op(), 1..40),
    ) {
        if let Err(disagreement) = walk(provision, &ops) {
            prop_assert!(false, "{}", disagreement);
        }
    }
}

/// Non-vacuity, before trusting the property: the generators reach what the
/// laws are about. A walk that never served a one-shot twice, never refused one,
/// and never personalised would pass while checking nothing.
#[test]
fn the_walk_reaches_every_outcome_it_asserts() {
    let everything = Provision {
        broker_secret: true,
        mediation_key: true,
        mediation_spiffe_id: true,
        audit_creds: true,
        pod_spec: true,
        dlc_admission: true,
        pod_certificate: true,
        task_token: true,
        caller_token: true,
        receipts: true,
    };
    let mut model = Model::new(everything);
    let mut refused = Vec::new();
    let script: Vec<Op> = [Cmd::SnapshotReady]
        .into_iter()
        .chain(COMMANDS)
        .chain(COMMANDS)
        .map(Op::Command)
        .chain([Op::Unknown])
        .collect();
    for op in &script {
        let expect = model.pre(op);
        if let Expect::Refused(r) = &expect {
            refused.push(r.clone());
        }
        model.eff(op, &expect);
    }
    for o in [
        OneShot::BrokerSecret,
        OneShot::MediationKey,
        OneShot::AuditCredentials,
    ] {
        assert!(
            refused.contains(&Refusal::AlreadyServed(o)),
            "{o:?} never absorbed"
        );
    }
    assert!(model.personalized, "no command personalised the VM");
    assert_eq!(walk(everything, &script), Ok(()));

    // And the ordinal table is the command list, in order.
    for (i, c) in COMMANDS.iter().enumerate() {
        assert_eq!(ordinal(*c), i);
        assert_eq!(parse_command(wire_name(*c).as_bytes()), Ok(*c));
    }
}

/// A2 under concurrency: the one-shot is an atomic swap, so of many requests
/// racing on separate connections, exactly one is served.
#[test]
fn racing_requests_for_a_one_shot_serve_exactly_one() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let all = Provision {
            broker_secret: true,
            mediation_key: true,
            mediation_spiffe_id: true,
            audit_creds: true,
            pod_spec: false,
            dlc_admission: false,
            pod_certificate: false,
            task_token: false,
            caller_token: false,
            receipts: false,
        };
        let material = Arc::new(material_for(all, dir.path()));
        let manager =
            IdentityManager::new("walk.local", std::time::Duration::from_secs(3600)).unwrap();
        for command in [
            "FETCH_BROKER_SECRET\n",
            "FETCH_MEDIATION_KEY\n",
            "FETCH_AUDIT_CREDENTIALS\n",
        ] {
            let tasks: Vec<_> = (0..16)
                .map(|_| {
                    let material = Arc::clone(&material);
                    let manager = manager.clone();
                    tokio::spawn(async move {
                        let mut rest: &[u8] = b"";
                        serve_frame(
                            command.as_bytes(),
                            &mut rest,
                            &manager,
                            uuid::Uuid::nil(),
                            &material,
                        )
                        .await
                    })
                })
                .collect();
            let mut served = 0;
            for t in tasks {
                if t.await.unwrap().is_ok() {
                    served += 1;
                }
            }
            assert_eq!(served, 1, "{command:?} served {served} times");
        }
    });
}
