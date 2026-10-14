//! The registry's decisions over real journals, with the clock and the receipts in the test's
//! hands: who is bound to what, what each run is given, and when a publish is refused.
use super::*;
use crate::memory_space::{
    Audience, Ceiling, PodLabels, PolicyRequest, PolicyState, SchemaAtom, SpaceRequest, ViewSpec,
};
use nucleus_provenance_memory::recompute::derive_label;
use nucleus_provenance_memory::{MemoryDerivation, SchemaType, SourceClass};
use std::collections::{BTreeMap, BTreeSet};

const OWNER: &str = "spiffe://test.local/ns/system/sa/tenant-a";
const NOW: u64 = 1_900_000_000;

fn tenant() -> TenantKey {
    TenantKey::of(OWNER)
}

fn name(n: &str) -> SpaceName {
    SpaceName::new(n).unwrap()
}

/// Excludes no one: the reach a test's stand-in proxy opens its branch under.
struct Anyone;
impl ReachCheck for Anyone {
    fn admit(&self, _: JournalPart, _: u32) -> Result<(), String> {
        Ok(())
    }
}

fn record(value: &str, schema: SchemaType) -> MemoryRecord {
    let derivation = MemoryDerivation::RawIngest {
        source_class: SourceClass::Web,
        source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
    };
    let label = derive_label(&derivation, &[]);
    MemoryRecord::new(value, schema, label, derivation)
}

fn raw(value: &str) -> MemoryRecord {
    record(value, SchemaType::String)
}

fn derived(value: &str, parent: &MemoryRecord) -> MemoryRecord {
    let derivation = MemoryDerivation::OpaqueLlm {
        input_hashes: vec![parent.content_hash()],
        model_tag: "fixture-model".into(),
    };
    let label = derive_label(&derivation, &[parent]);
    MemoryRecord::new(value, SchemaType::String, label, derivation)
}

/// Run a test body in a process of its own: the test binary re-executed for exactly this test.
///
/// A journal's writer lock is a `flock`, which belongs to the open file description, so a
/// child that a SIBLING test's thread forks holds every descriptor open at that instant until it
/// execs. Under a single-process runner (`cargo test`, `cargo llvm-cov`) a lock the registry
/// just released can then look held, and a re-open is refused as "already owned by another
/// writer". That fails closed, and is not retried: the body runs where nothing else forks.
/// The child must report exactly one passed test, so a name that matches nothing is a failure.
pub(crate) fn in_own_process(module: &str, name: &str, body: impl FnOnce()) {
    const ISOLATED: &str = "NUCLEUS_MEMORY_TEST_ISOLATED";
    if std::env::var_os(ISOLATED).is_some() {
        body();
        return;
    }
    let path = module.split_once("::").map_or(module, |(_, rest)| rest);
    let test = format!("{path}::{name}");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--test-threads=1"])
        .env(ISOLATED, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{test} in its own process:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A memory root, its registry, and every receipt the registry asked to keep.
struct Lab {
    _dir: tempfile::TempDir,
    root: PathBuf,
    registry: Registry,
    receipts: Vec<serde_json::Value>,
    /// The event kind the recorder refuses to keep, to drive receipt-before-effect.
    refuse: Option<&'static str>,
}

impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("memory");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let registry = Registry::load(&root).unwrap();
        Self {
            _dir: dir,
            root,
            registry,
            receipts: Vec::new(),
            refuse: None,
        }
    }

    /// The node restarted: the registry is read back from its file.
    fn restart(&mut self) {
        self.registry = Registry::load(&self.root).unwrap();
    }

    fn bind_with(
        &mut self,
        space: &str,
        lineage: Uuid,
        labels: PodLabels<'_>,
        now: u64,
        citer: Option<&dyn DecisionCiter>,
    ) -> Result<Delivered, ApiError> {
        let (receipts, refuse) = (&mut self.receipts, self.refuse);
        self.registry.bind(
            BindRequest {
                tenant: &tenant(),
                name: &name(space),
                pod: Uuid::new_v4(),
                matched: PodMatch { lineage, labels },
                run_ends: now + 3600,
                now,
            },
            citer,
            &mut |claim: &FlowClaim<'_>| keep(receipts, refuse, claim),
        )
    }

    fn bind(&mut self, space: &str, lineage: Uuid) -> Result<Delivered, ApiError> {
        self.bind_with(space, lineage, PodLabels::PodAuthored, NOW, None)
    }

    fn bind_labelled(
        &mut self,
        space: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<Delivered, ApiError> {
        self.bind_with(
            space,
            Uuid::new_v4(),
            PodLabels::TenantAuthenticated(labels),
            NOW,
            None,
        )
    }

    fn publish_at(
        &mut self,
        binding: Uuid,
        expected: Pin,
        now: u64,
        citer: Option<&dyn DecisionCiter>,
    ) -> Result<Pin, ApiError> {
        let t = tenant();
        let admitted =
            self.registry
                .admit_publish(binding, Publisher::TenantRoot(&t), now, citer)?;
        let (receipts, refuse) = (&mut self.receipts, self.refuse);
        self.registry
            .publish(admitted, expected, now, &mut |claim: &FlowClaim<'_>| {
                keep(receipts, refuse, claim)
            })
    }

    fn publish(&mut self, binding: Uuid) -> Result<Pin, ApiError> {
        let expected = self.head(&self.registry.bindings[&binding].space.clone());
        self.publish_at(binding, expected, NOW, None)
    }

    fn declare(&mut self, space: &str, quota_bytes: u64) -> SpaceId {
        let (receipts, refuse) = (&mut self.receipts, self.refuse);
        self.registry
            .create_space(
                &tenant(),
                SpaceRequest {
                    name: name(space),
                    schema: SchemaAtom::ALL.into_iter().collect(),
                    quota_bytes,
                },
                NOW,
                &mut |claim: &FlowClaim<'_>| keep(receipts, refuse, claim),
            )
            .unwrap()
    }

    fn policy(&mut self, space: &SpaceId, request: PolicyRequest) -> Result<Uuid, ApiError> {
        let (receipts, refuse) = (&mut self.receipts, self.refuse);
        self.registry
            .create_policy(&tenant(), space, request, NOW, &mut |claim: &FlowClaim<
                '_,
            >| {
                keep(receipts, refuse, claim)
            })
    }

    /// A policy an earlier node recorded (before C0 any audience could be created), read back
    /// after a restart: what an upgraded node finds in its registry.
    fn recorded_policy(&mut self, space: &SpaceId, audience: Audience) -> Uuid {
        let id = Uuid::new_v4();
        let epoch = self.registry.space(&tenant(), space).unwrap().epoch;
        self.registry.policies.insert(
            id,
            BindingPolicy {
                id,
                tenant: tenant(),
                space: space.clone(),
                audience,
                mode: Mode::ReadPropose,
                view: ViewSpec::everything(),
                may_publish: true,
                allocation_bytes: 1 << 20,
                expiry: Expiry::UntilRevoked,
                epoch,
                state: PolicyState::Live,
                authority: PolicyAuthority::TenantRoot,
                issued_unix: NOW,
            },
        );
        self.registry.persist().unwrap();
        self.restart();
        id
    }

    fn revoke_space(&mut self, space: &SpaceId) -> u32 {
        let (receipts, refuse) = (&mut self.receipts, self.refuse);
        self.registry
            .revoke_space(&tenant(), space, NOW, &mut |claim: &FlowClaim<'_>| {
                keep(receipts, refuse, claim)
            })
            .unwrap()
    }

    fn revoke_policy(&mut self, space: &SpaceId, policy: Uuid) {
        let (receipts, refuse) = (&mut self.receipts, self.refuse);
        self.registry
            .revoke_policy(&tenant(), space, policy, NOW, &mut |claim: &FlowClaim<
                '_,
            >| {
                keep(receipts, refuse, claim)
            })
            .unwrap();
    }

    fn space_location(&self, space: &SpaceId) -> JournalLocation {
        let held = self.registry.space(&tenant(), space).unwrap();
        self.registry.space_location(held).unwrap()
    }

    fn head(&self, space: &SpaceId) -> Pin {
        PublishedJournal::open(
            self.space_location(space),
            &Anyone,
            &TransformRegistry::new(),
        )
        .unwrap()
        .head()
        .unwrap()
    }

    fn binding(&self, delivered: &Delivered) -> &Binding {
        &self.registry.bindings[&delivered.binding]
    }

    fn kinds(&self) -> Vec<String> {
        self.receipts
            .iter()
            .map(|r| r["event"]["kind"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn keep(
    receipts: &mut Vec<serde_json::Value>,
    refuse: Option<&'static str>,
    claim: &FlowClaim<'_>,
) -> Result<(), ApiError> {
    let value = serde_json::to_value(claim).unwrap();
    if refuse.is_some_and(|kind| value["event"]["kind"] == kind) {
        return Err(ApiError::Driver("the receipt log is unavailable".into()));
    }
    receipts.push(value);
    Ok(())
}

fn location(delivered: &Delivered) -> JournalLocation {
    JournalLocation::new(&delivered.directory.join(JOURNAL), &delivered.namespace).unwrap()
}

/// What the run was given: every record of its delivered journal.
fn given(delivered: &Delivered) -> Vec<MemoryRecord> {
    read_unlocked(&location(delivered), &Anyone, &TransformRegistry::new()).unwrap()
}

/// The run's proxy writes `records` to its journal, as the proxy commits a write.
fn write(delivered: &Delivered, records: &[MemoryRecord]) {
    let transforms = TransformRegistry::new();
    let mut journal = PublishedJournal::open(location(delivered), &Anyone, &transforms).unwrap();
    for record in records {
        let head = journal.head().unwrap();
        journal
            .publish(
                &Patch::new(head, vec![record.clone()]),
                head,
                PublisherBinding::operator_direct(),
                Epoch::PRE_BINDING,
                &StoreInvariants::new(usize::MAX, MAX_JOURNAL_BYTES),
                &transforms,
            )
            .unwrap();
    }
}

fn values(records: &[MemoryRecord]) -> BTreeSet<String> {
    records.iter().map(|r| r.value.clone()).collect()
}

fn workspace(team: &str) -> Audience {
    Audience::Workspace {
        selector: BTreeMap::from([("team".to_owned(), team.to_owned())]),
    }
}

fn read_propose(audience: Audience, allocation_bytes: u64) -> PolicyRequest {
    PolicyRequest {
        audience,
        mode: Mode::ReadPropose,
        view: ViewSpec::everything(),
        may_publish: true,
        allocation_bytes,
        expiry: Expiry::UntilRevoked,
        authority: PolicyAuthority::TenantRoot,
    }
}

fn labels(team: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("team".to_owned(), team.to_owned())])
}

/// The refusal names cross-run memory as unavailable, and why, and the reach it refused.
fn assert_cross_run(refused: &ApiError, reach: &str) {
    let text = refused.to_string();
    assert!(
        text.contains("CrossRunMemoryUnavailable: record labels are not yet dependency-stamped")
            && text.contains(reach),
        "{text}"
    );
}

/// The lineage default, stated precisely: runs of one lineage (siblings under one parent) are
/// given the same base and write private branches. Nothing one writes reaches the other, nor a
/// later run, until it is published; after that a new run is given it and an existing run's
/// pinned snapshot does not change.
#[test]
fn sibling_runs_share_the_base_and_never_each_others_writes() {
    in_own_process(
        module_path!(),
        "sibling_runs_share_the_base_and_never_each_others_writes",
        || {
            let mut lab = Lab::new();
            let lineage = Uuid::new_v4();
            let parent = lab.bind("notes", lineage).unwrap();
            write(&parent, &[raw("base")]);
            lab.publish(parent.binding).unwrap();

            let first = lab.bind("notes", lineage).unwrap();
            let second = lab.bind("notes", lineage).unwrap();
            assert_ne!(
                first.directory, second.directory,
                "each run has its own branch"
            );
            assert_eq!(values(&given(&first)), values(&[raw("base")]));
            assert_eq!(given(&first), given(&second), "siblings share the base");
            assert_eq!(lab.binding(&first).base, lab.binding(&second).base);

            write(&first, &[raw("first's")]);
            assert_eq!(
                values(&given(&second)),
                values(&[raw("base")]),
                "a sibling's write is not in the other's branch"
            );
            let later = lab.bind("notes", lineage).unwrap();
            assert_eq!(
                values(&given(&later)),
                values(&[raw("base")]),
                "nor in a later run's base, until published"
            );

            lab.publish(first.binding).unwrap();
            let after = lab.bind("notes", lineage).unwrap();
            assert_eq!(
                values(&given(&after)),
                values(&[raw("base"), raw("first's")])
            );
            assert_eq!(
                values(&given(&second)),
                values(&[raw("base")]),
                "an existing run's snapshot is pinned"
            );
        },
    );
}

/// Separate lineages of one tenant are separate spaces by default: #3451's isolation, which the
/// owner-keyed layout did not have (it handed both `sha256(owner)/notes`).
#[test]
fn separate_lineages_are_bound_to_separate_spaces_by_default() {
    in_own_process(
        module_path!(),
        "separate_lineages_are_bound_to_separate_spaces_by_default",
        || {
            let mut lab = Lab::new();
            let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
            let first = lab.bind("notes", a).unwrap();
            write(&first, &[raw("a's")]);
            lab.publish(first.binding).unwrap();
            let other = lab.bind("notes", b).unwrap();
            assert!(
                given(&other).is_empty(),
                "another lineage sees nothing of a's"
            );
            assert_ne!(lab.binding(&first).space, lab.binding(&other).space);
        },
    );
}

/// Program C, C0: a workspace policy would deliver one run's records to runs of other
/// lineages, and a record's label does not yet say what its writer had read. So the tenant root
/// cannot create one, and one an earlier node recorded mints no binding: refused by name before
/// anything is delivered or receipted. A pod outside the selector is still refused as unadmitted,
/// and a declared space is never swapped for a lineage store the pod did not ask for.
#[test]
fn a_workspace_policy_is_refused_until_labels_are_stamped() {
    in_own_process(
        module_path!(),
        "a_workspace_policy_is_refused_until_labels_are_stamped",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            let refused = lab
                .policy(&notes, read_propose(workspace("a"), 1 << 20))
                .unwrap_err();
            assert_cross_run(&refused, "a workspace audience");
            assert!(lab.registry.policies.is_empty(), "nothing was recorded");

            lab.recorded_policy(&notes, workspace("a"));
            let receipts = lab.receipts.len();
            let refused = lab.bind_labelled("notes", &labels("a")).unwrap_err();
            assert_cross_run(&refused, "a workspace audience");
            assert!(lab.registry.bindings.is_empty(), "no binding was minted");
            assert_eq!(lab.receipts.len(), receipts, "no delivery was receipted");
            assert!(
                !lab.root.join("bindings").exists(),
                "no snapshot was written"
            );
            let refused = lab.bind_labelled("notes", &labels("b")).unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains("no binding policy of memory space notes admits"),
                "{refused}"
            );
            assert!(
                lab.bind("notes", Uuid::new_v4()).is_err(),
                "a declared space is never swapped for a lineage store the pod did not ask for"
            );
        },
    );
}

/// Program C, C0: a `TenantAll` policy is refused at creation (and the legacy audience is still
/// for migration only). A binding an earlier node minted under one cannot publish — refused by
/// name, nothing appended, nothing receipted — and mints no new binding.
#[test]
fn a_tenant_all_policy_is_refused_at_creation_bind_and_publish() {
    in_own_process(
        module_path!(),
        "a_tenant_all_policy_is_refused_at_creation_bind_and_publish",
        || {
            let mut lab = Lab::new();
            let shared = lab.declare("shared", MAX_JOURNAL_BYTES);
            let owner = Uuid::new_v4();
            let policy = lab
                .policy(
                    &shared,
                    read_propose(Audience::Lineage { root: owner }, 1 << 20),
                )
                .unwrap();
            let held = lab.bind("shared", owner).unwrap();
            assert!(lab.bind("shared", Uuid::new_v4()).is_err());
            let refused = lab
                .policy(&shared, read_propose(Audience::TenantAll, 1 << 20))
                .unwrap_err();
            assert_cross_run(&refused, "a tenant-wide audience");
            let refused = lab
                .policy(&shared, read_propose(Audience::TenantAllLegacy, 1 << 20))
                .unwrap_err();
            assert!(
                refused.to_string().contains("only migration records"),
                "{refused}"
            );

            // The binding was minted by an earlier node, under a policy it recorded as TenantAll.
            write(&held, &[raw("written before the upgrade")]);
            lab.registry.policies.get_mut(&policy).unwrap().audience = Audience::TenantAll;
            lab.registry.persist().unwrap();
            lab.restart();
            let journal = lab.space_location(&shared);
            let before = std::fs::read(journal.path()).unwrap();
            let refused = lab.publish(held.binding).unwrap_err();
            assert_cross_run(&refused, "a tenant-wide audience");
            assert_eq!(
                std::fs::read(journal.path()).unwrap(),
                before,
                "nothing was published"
            );
            assert!(!lab.kinds().contains(&"publish_authorized".to_owned()));
            assert_eq!(lab.binding(&held).spent_bytes, 0);
            let refused = lab.bind("shared", Uuid::new_v4()).unwrap_err();
            assert_cross_run(&refused, "a tenant-wide audience");
        },
    );
}

/// Lineage audiences keep working under C0: a later run of the lineage is given what an earlier
/// one published, over a declared space. A policy admitting a second lineage is refused at
/// creation, and one an earlier node recorded refuses both lineages at bind and at publish,
/// since the space may already hold the other lineage's writes.
#[test]
fn lineage_policies_still_bind_and_publish_and_never_reach_another_lineage() {
    in_own_process(
        module_path!(),
        "lineage_policies_still_bind_and_publish_and_never_reach_another_lineage",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            let owner = Uuid::new_v4();
            lab.policy(
                &notes,
                read_propose(Audience::Lineage { root: owner }, 1 << 20),
            )
            .unwrap();
            let first = lab.bind("notes", owner).unwrap();
            write(&first, &[raw("first run's")]);
            lab.publish(first.binding).unwrap();
            let second = lab.bind("notes", owner).unwrap();
            assert_eq!(
                values(&given(&second)),
                values(&[raw("first run's")]),
                "a later run of the lineage is given what an earlier one published"
            );

            let other = Uuid::new_v4();
            let beyond = "whose policies admit another lineage";
            let refused = lab
                .policy(
                    &notes,
                    read_propose(Audience::Lineage { root: other }, 1 << 20),
                )
                .unwrap_err();
            assert_cross_run(&refused, beyond);

            lab.recorded_policy(&notes, Audience::Lineage { root: other });
            write(&second, &[raw("second run's")]);
            assert_cross_run(&lab.publish(second.binding).unwrap_err(), beyond);
            assert_cross_run(&lab.bind("notes", other).unwrap_err(), beyond);
            assert_cross_run(&lab.bind("notes", owner).unwrap_err(), beyond);
        },
    );
}

/// A child is minted its own binding and never holds its parent's: a pod-created child's
/// labels match no workspace selector, and in its lineage's space it is pinned at the head,
/// without the parent's unpublished writes.
#[test]
fn a_child_is_never_handed_its_parents_binding() {
    in_own_process(
        module_path!(),
        "a_child_is_never_handed_its_parents_binding",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            lab.recorded_policy(&notes, workspace("a"));
            let team = labels("a");
            // C0: the parent itself is refused a workspace binding (see
            // `a_workspace_policy_is_refused_until_labels_are_stamped`); its child is not even
            // admitted, since a pod wrote its labels.
            assert_cross_run(
                &lab.bind_labelled("notes", &team).unwrap_err(),
                "a workspace audience",
            );
            let lineage = Uuid::new_v4();
            let refused = lab
                .bind_with("notes", lineage, PodLabels::PodAuthored, NOW, None)
                .unwrap_err();
            assert!(refused.to_string().contains("admits this pod"), "{refused}");

            let root = Uuid::new_v4();
            let parent = lab.bind("scratch", root).unwrap();
            write(&parent, &[raw("parent's unpublished")]);
            let child = lab.bind("scratch", root).unwrap();
            assert_ne!(child.binding, parent.binding);
            assert!(given(&child).is_empty());
        },
    );
}

/// The binding holds its pin, and the space remembers the highest one, so a journal rolled
/// back below it (truncated) or rewritten under it is refused by name — at bind and at
/// publish — rather than read as a shorter history. It survives a restart.
#[test]
fn a_journal_truncated_below_a_pin_is_refused_by_name() {
    in_own_process(
        module_path!(),
        "a_journal_truncated_below_a_pin_is_refused_by_name",
        || {
            let mut lab = Lab::new();
            let root = Uuid::new_v4();
            let first = lab.bind("notes", root).unwrap();
            write(&first, &[raw("one")]);
            lab.publish(first.binding).unwrap();
            let pinned = lab.bind("notes", root).unwrap();
            write(&pinned, &[raw("two")]);
            let space = lab.binding(&pinned).space.clone();
            let journal = lab.space_location(&space);
            let header = std::fs::read(journal.path()).unwrap();
            let header_len = header.iter().position(|b| *b == b'\n').unwrap() + 1;
            lab.restart();

            std::fs::write(journal.path(), &header[..header_len]).unwrap();
            let refused = lab.bind("notes", root).unwrap_err();
            assert!(
                refused.to_string().contains("was truncated"),
                "a rolled-back journal is refused at bind: {refused}"
            );
            let refused = lab
                .publish_at(pinned.binding, Pin::genesis(journal.namespace()), NOW, None)
                .unwrap_err();
            assert!(
                refused.to_string().contains("was truncated"),
                "and at publish, by the binding's own pin: {refused}"
            );

            // Rewritten: the same version, a different head.
            std::fs::write(journal.path(), &header[..header_len]).unwrap();
            {
                let transforms = TransformRegistry::new();
                let mut rewritten =
                    PublishedJournal::open(journal.clone(), &Anyone, &transforms).unwrap();
                let head = rewritten.head().unwrap();
                rewritten
                    .publish(
                        &Patch::new(head, vec![raw("forged")]),
                        head,
                        PublisherBinding::operator_direct(),
                        Epoch::PRE_BINDING,
                        &StoreInvariants::new(usize::MAX, MAX_JOURNAL_BYTES),
                        &transforms,
                    )
                    .unwrap();
            }
            let refused = lab.bind("notes", root).unwrap_err();
            assert!(refused.to_string().contains("was rewritten"), "{refused}");
        },
    );
}

/// Revoking a space moves it to the next epoch: a binding of the old epoch is refused for a
/// new mediated op as `ForeignEpoch`, by name, and nothing new is minted from the old policies.
/// What the run was already given stays where it was: revocation does not erase disclosure.
#[test]
fn an_old_epoch_binding_is_refused_and_what_it_was_given_stays() {
    in_own_process(
        module_path!(),
        "an_old_epoch_binding_is_refused_and_what_it_was_given_stays",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            let root = Uuid::new_v4();
            let policy = lab
                .policy(&notes, read_propose(Audience::Lineage { root }, 1 << 20))
                .unwrap();
            let seed = lab.bind("notes", root).unwrap();
            write(&seed, &[raw("disclosed")]);
            lab.publish(seed.binding).unwrap();
            let held = lab.bind("notes", root).unwrap();
            write(&held, &[raw("late")]);
            let before = given(&held);
            assert_eq!(lab.revoke_space(&notes), 1);
            let refused = lab.publish(held.binding).unwrap_err();
            assert!(
                refused.to_string().contains("minted at epoch 0")
                    && refused.to_string().contains("is at epoch 1"),
                "{refused}"
            );
            assert_eq!(given(&held), before, "the delivered snapshot is untouched");
            assert!(lab.kinds().contains(&"snapshot_delivery".to_owned()));
            let refused = lab.bind("notes", root).unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains(&format!("binding policy {policy} is revoked")),
                "{refused}"
            );
        },
    );
}

/// Revoking one policy refuses its bindings by name and mints nothing new from it.
#[test]
fn a_revoked_policy_refuses_its_bindings_by_name() {
    in_own_process(
        module_path!(),
        "a_revoked_policy_refuses_its_bindings_by_name",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            let root = Uuid::new_v4();
            let policy = lab
                .policy(&notes, read_propose(Audience::Lineage { root }, 1 << 20))
                .unwrap();
            let held = lab.bind("notes", root).unwrap();
            write(&held, &[raw("x")]);
            lab.revoke_policy(&notes, policy);
            let refused = lab.publish(held.binding).unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains(&format!("binding policy {policy} is revoked")),
                "{refused}"
            );
            assert!(lab.bind("notes", root).is_err());
        },
    );
}

/// A binding is valid up to `not_after` inclusive and refused by name after it.
#[test]
fn an_expired_binding_is_refused_by_name() {
    in_own_process(
        module_path!(),
        "an_expired_binding_is_refused_by_name",
        || {
            let mut lab = Lab::new();
            let held = lab.bind("notes", Uuid::new_v4()).unwrap();
            write(&held, &[raw("x")]);
            let not_after = lab.binding(&held).not_after;
            assert_eq!(not_after, NOW + 3600);
            let space = lab.binding(&held).space.clone();
            let head = lab.head(&space);
            let refused = lab
                .publish_at(held.binding, head, not_after + 1, None)
                .unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains(&format!("binding {} expired at {not_after}", held.binding)),
                "{refused}"
            );
            assert!(lab.publish_at(held.binding, head, not_after, None).is_ok());
        },
    );
}

/// Receipt before effect: a snapshot whose delivery receipt is not kept is never handed out —
/// no binding is recorded, its directory is removed, and the space's high-water mark is as it
/// was. Kept, the receipt names the bytes the run is handed.
#[test]
fn a_delivery_whose_receipt_is_not_kept_leaves_no_binding() {
    in_own_process(
        module_path!(),
        "a_delivery_whose_receipt_is_not_kept_leaves_no_binding",
        || {
            let mut lab = Lab::new();
            let root = Uuid::new_v4();
            lab.bind("notes", root).unwrap();
            let bindings = lab.registry.bindings.len();
            lab.refuse = Some("snapshot_delivery");
            let refused = lab.bind("notes", root).unwrap_err();
            assert!(refused.to_string().contains("receipt log"), "{refused}");
            assert_eq!(lab.registry.bindings.len(), bindings);
            assert_eq!(
                std::fs::read_dir(lab.root.join("bindings"))
                    .unwrap()
                    .count(),
                bindings,
                "the refused binding's snapshot was removed"
            );
            lab.restart();
            assert_eq!(
                lab.registry.bindings.len(),
                bindings,
                "nor was it persisted"
            );

            lab.refuse = None;
            let kept = lab.bind("notes", root).unwrap();
            let receipt = lab.receipts.last().unwrap().clone();
            assert_eq!(receipt["event"]["kind"], "snapshot_delivery");
            assert_eq!(receipt["event"]["binding"], kept.binding.to_string());
            let bytes = std::fs::read(location(&kept).path()).unwrap();
            assert_eq!(
                receipt["event"]["bytes_sha256"],
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes))
            );
            assert_eq!(
                receipt["event"]["view_digest"],
                ViewSpec::everything().digest()
            );
        },
    );
}

/// A publish whose receipt is not kept appends nothing and spends nothing.
#[test]
fn a_publish_whose_receipt_is_not_kept_appends_nothing() {
    in_own_process(
        module_path!(),
        "a_publish_whose_receipt_is_not_kept_appends_nothing",
        || {
            let mut lab = Lab::new();
            let held = lab.bind("notes", Uuid::new_v4()).unwrap();
            write(&held, &[raw("x")]);
            let space = lab.binding(&held).space.clone();
            let before = std::fs::read(lab.space_location(&space).path()).unwrap();
            lab.refuse = Some("publish_authorized");
            assert!(lab.publish(held.binding).is_err());
            assert_eq!(
                std::fs::read(lab.space_location(&space).path()).unwrap(),
                before
            );
            assert_eq!(lab.binding(&held).spent_bytes, 0);
            lab.refuse = None;
            let head = lab.publish(held.binding).unwrap();
            let receipt = lab.receipts.last().unwrap();
            assert_eq!(receipt["event"]["kind"], "publish_authorized");
            assert_eq!(receipt["event"]["head"]["version"], head.version());
            assert!(lab.binding(&held).spent_bytes > 0);
        },
    );
}

/// The quota is split, so a publish's accept/refuse depends only on the binding's own
/// allocation. Two cells differ only in what ANOTHER binding of the space published: nothing,
/// or over a third of the space. B's verdicts on the same two patches (one that fits its own
/// allocation with little to spare, one that does not) are the same in both cells, and the
/// refusal names B's own allocation. Counted against the space instead, the first patch would
/// be refused only where the other binding had published: a channel.
#[test]
fn a_publish_verdict_depends_only_on_the_bindings_own_allocation() {
    in_own_process(
        module_path!(),
        "a_publish_verdict_depends_only_on_the_bindings_own_allocation",
        || {
            let allocation = 8192;
            let mut verdicts = Vec::new();
            for other_publishes in [false, true] {
                let mut lab = Lab::new();
                let notes = lab.declare("notes", 4 * allocation);
                let root = Uuid::new_v4();
                lab.policy(&notes, read_propose(Audience::Lineage { root }, allocation))
                    .unwrap();
                let other = lab.bind("notes", root).unwrap();
                let b = lab.bind("notes", root).unwrap();
                if other_publishes {
                    let filler: Vec<MemoryRecord> =
                        (0..6).map(|i| raw(&format!("other{i:0>300}"))).collect();
                    write(&other, &filler);
                    lab.publish(other.binding).unwrap();
                    assert!(lab.registry.bindings[&other.binding].spent_bytes > allocation / 3);
                }
                let fits: Vec<MemoryRecord> =
                    (0..10).map(|i| raw(&format!("fits{i:0>300}"))).collect();
                write(&b, &fits);
                let first = lab.publish(b.binding).map(|_| ());
                let spent = lab.registry.bindings[&b.binding].spent_bytes;
                let over: Vec<MemoryRecord> =
                    (0..20).map(|i| raw(&format!("over{i:0>300}"))).collect();
                write(&b, &over);
                let second = lab.publish(b.binding).map(|_| ());
                verdicts.push((
                    first.map_err(|e| e.to_string()),
                    spent,
                    second.map_err(|e| e.to_string().contains("left")),
                ));
            }
            assert_eq!(
                verdicts[0], verdicts[1],
                "B cannot tell whether the other binding published"
            );
            let (first, spent, second) = &verdicts[0];
            assert_eq!(first, &Ok(()));
            assert!(
                *spent > allocation / 2,
                "the first patch nearly fills B's allocation: {spent}"
            );
            assert_eq!(
                second,
                &Err(true),
                "overspending its own allocation is refused by name"
            );
        },
    );
}

/// The 6 + 6 > 10 counterexample, on bytes: two branches each within its own allocation are
/// both accepted and the journal never exceeds the space's quota, because the allocations are
/// reserved against the quota when the bindings are minted. A third binding the quota cannot
/// cover is refused at bind, by name: the declared, bind-time side of the split.
#[test]
fn allocations_never_exceed_the_space_quota() {
    in_own_process(
        module_path!(),
        "allocations_never_exceed_the_space_quota",
        || {
            let mut lab = Lab::new();
            let allocation = 8192;
            let notes = lab.declare("notes", 2 * allocation + 512);
            let root = Uuid::new_v4();
            lab.policy(&notes, read_propose(Audience::Lineage { root }, allocation))
                .unwrap();
            let first = lab.bind("notes", root).unwrap();
            let second = lab.bind("notes", root).unwrap();
            let refused = lab.bind("notes", root).unwrap_err();
            assert!(refused.to_string().contains("fully allocated"), "{refused}");
            for (run, tag) in [(&first, "a"), (&second, "b")] {
                let patch: Vec<MemoryRecord> =
                    (0..10).map(|i| raw(&format!("{tag}{i:0>300}"))).collect();
                write(run, &patch);
                lab.publish(run.binding)
                    .expect("each branch is within its own allocation");
            }
            let size = std::fs::metadata(lab.space_location(&notes).path())
                .unwrap()
                .len();
            assert!(size > allocation, "both publishes landed: {size}");
            assert!(size <= 2 * allocation + 512, "{size}");
        },
    );
}

/// The bind-time quota refusal is one bit: it names the policy's own allocation and no
/// unreserved byte count, which is the quota less every reservation and every published record,
/// Secret ones included (Program C, C0).
#[test]
fn a_fully_allocated_refusal_names_no_byte_count() {
    in_own_process(
        module_path!(),
        "a_fully_allocated_refusal_names_no_byte_count",
        || {
            let mut lab = Lab::new();
            let allocation = 8192;
            let notes = lab.declare("notes", 2 * allocation + 512);
            let root = Uuid::new_v4();
            lab.policy(&notes, read_propose(Audience::Lineage { root }, allocation))
                .unwrap();
            let first = lab.bind("notes", root).unwrap();
            write(&first, &[raw("published, and counted against the quota")]);
            lab.publish(first.binding).unwrap();
            lab.bind("notes", root).unwrap();
            let refused = lab.bind("notes", root).unwrap_err().to_string();
            assert!(
                refused.contains("QuotaFullyAllocated") && refused.contains("fully allocated"),
                "{refused}"
            );
            let rest = refused.replace(&allocation.to_string(), "");
            assert!(
                !rest.bytes().any(|b| b.is_ascii_digit()),
                "the refusal states no byte count but the policy's own allocation: {refused}"
            );
        },
    );
}

/// A Read binding is given the snapshot, and nothing it writes can be published.
#[test]
fn a_read_binding_cannot_publish_and_its_writes_stay_in_its_copy() {
    in_own_process(
        module_path!(),
        "a_read_binding_cannot_publish_and_its_writes_stay_in_its_copy",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            let root = Uuid::new_v4();
            lab.policy(
                &notes,
                PolicyRequest {
                    audience: Audience::Lineage { root },
                    mode: Mode::Read,
                    view: ViewSpec::everything(),
                    may_publish: false,
                    allocation_bytes: 0,
                    expiry: Expiry::UntilRevoked,
                    authority: PolicyAuthority::TenantRoot,
                },
            )
            .unwrap();
            let reader = lab.bind("notes", root).unwrap();
            write(&reader, &[raw("scribble")]);
            let refused = lab.publish(reader.binding).unwrap_err();
            assert!(refused.to_string().contains("may not publish"), "{refused}");
            assert!(given(&lab.bind("notes", root).unwrap()).is_empty());
            let refused = lab
                .policy(
                    &notes,
                    PolicyRequest {
                        mode: Mode::Read,
                        ..read_propose(Audience::Lineage { root }, 1)
                    },
                )
                .unwrap_err();
            assert!(
                refused.to_string().contains("a Read policy cannot publish"),
                "a Read policy that may publish is refused: {refused}"
            );
        },
    );
}

/// `set` with the stored confidentiality of the record valued `value` replaced by `level`: the
/// shape of a set read back from a store, whose labels are whatever was persisted.
fn relabelled(set: &ProvenanceMemorySet, value: &str, level: &str) -> ProvenanceMemorySet {
    let mut json = serde_json::to_value(set).unwrap();
    let records = json["records"].as_object_mut().unwrap();
    let mut found = 0;
    for record in records.values_mut() {
        if record["value"] == value {
            record["label"]["confidentiality"] = serde_json::Value::from(level);
            found += 1;
        }
    }
    assert_eq!(found, 1, "the record to relabel is in the set");
    serde_json::from_value(json).unwrap()
}

/// The view's ceiling is decided on each record's STORED confidentiality: a Secret or Internal
/// record is withheld from a Public-ceiling view, as is a record derived from it, and an
/// Internal ceiling sees the Internal record and not the Secret one. (Every record admitted by
/// provenance replay today is labelled Public — `derive_label` assigns no other confidentiality —
/// so this is driven over a set read back with the labels a store holds.)
#[test]
fn a_view_ceiling_withholds_records_by_their_stored_confidentiality() {
    let secret = raw("secret note");
    let internal = raw("internal note");
    let child = derived("summary of the secret", &secret);
    let mut set = ProvenanceMemorySet::new();
    for record in [raw("public note"), secret, internal, child] {
        assert!(
            set.verified_admit(&record, &TransformRegistry::new())
                .is_match()
        );
    }
    let set = relabelled(&set, "secret note", "secret");
    let set = relabelled(&set, "summary of the secret", "secret");
    let set = relabelled(&set, "internal note", "internal");
    let view = |ceiling| ViewSpec {
        schema: SchemaAtom::ALL.into_iter().collect(),
        ceiling,
    };
    assert_eq!(
        values(&deliverable(&set, &view(Ceiling::Public))),
        values(&[raw("public note")])
    );
    assert_eq!(
        values(&deliverable(&set, &view(Ceiling::Internal))),
        values(&[raw("public note"), raw("internal note")])
    );
    assert_eq!(deliverable(&set, &view(Ceiling::Secret)).len(), 4);
}

/// A view gives a run only the schema classes it names, and withholds a record derived from a
/// withheld one (it could not be re-derived without it). A publish writing outside the view is
/// refused by name.
#[test]
fn a_view_withholds_records_outside_it_and_what_derives_from_them() {
    in_own_process(
        module_path!(),
        "a_view_withholds_records_outside_it_and_what_derives_from_them",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            let root = Uuid::new_v4();
            let wide = lab
                .policy(&notes, read_propose(Audience::Lineage { root }, 1 << 20))
                .unwrap();
            let json = record("{\"k\":1}", SchemaType::Json);
            let writer = lab.bind("notes", root).unwrap();
            write(
                &writer,
                &[raw("text"), json.clone(), derived("summary", &json)],
            );
            lab.publish(writer.binding).unwrap();
            lab.revoke_policy(&notes, wide);
            let text_only = ViewSpec {
                schema: BTreeSet::from([SchemaAtom::String]),
                ceiling: Ceiling::Secret,
            };
            lab.policy(
                &notes,
                PolicyRequest {
                    view: text_only,
                    ..read_propose(Audience::Lineage { root }, 1 << 20)
                },
            )
            .unwrap();
            let narrow = lab.bind("notes", root).unwrap();
            assert_eq!(values(&given(&narrow)), values(&[raw("text")]));
            write(&narrow, &[record("{\"k\":2}", SchemaType::Json)]);
            let refused = lab.publish(narrow.binding).unwrap_err();
            assert!(
                refused.to_string().contains("outside the publisher's view"),
                "{refused}"
            );
        },
    );
}

/// Compare-and-swap: a publish onto a head that moved is refused with the current head, and
/// publishing again on that head rebases (the whole candidate is validated again).
#[test]
fn a_stale_base_is_refused_with_the_head_and_rebases() {
    in_own_process(
        module_path!(),
        "a_stale_base_is_refused_with_the_head_and_rebases",
        || {
            let mut lab = Lab::new();
            let root = Uuid::new_v4();
            let a = lab.bind("notes", root).unwrap();
            let b = lab.bind("notes", root).unwrap();
            let space = lab.binding(&a).space.clone();
            let base = lab.head(&space);
            write(&a, &[raw("a")]);
            write(&b, &[raw("b")]);
            let moved = lab.publish_at(a.binding, base, NOW, None).unwrap();
            let refused = lab.publish_at(b.binding, base, NOW, None).unwrap_err();
            assert!(
                refused.to_string().contains(&moved.head().to_hex()),
                "the refusal names the head to rebase on: {refused}"
            );
            let rebased = lab.publish_at(b.binding, moved, NOW, None).unwrap();
            assert_eq!(rebased.version(), 2);
            let latest = lab.bind("notes", root).unwrap();
            assert_eq!(values(&given(&latest)), values(&[raw("a"), raw("b")]));
        },
    );
}

/// A citer that answers as the test says.
struct Citer {
    covers: std::cell::Cell<bool>,
    not_after: u64,
}
impl DecisionCiter for Citer {
    fn cite(&self, decision: &str, capability: &str, _now: u64) -> Result<u64, String> {
        assert_eq!(decision, "d".repeat(64));
        assert!(capability.starts_with("memory."));
        if self.covers.get() {
            Ok(self.not_after)
        } else {
            Err(format!("decision does not cover {capability}"))
        }
    }
}

/// A policy that rests on a decision is re-cited at every bind and every publish: a decision
/// that stops covering it refuses both, by name, and its window bounds the binding.
#[test]
fn a_decision_policy_is_re_cited_at_every_bind_and_publish() {
    in_own_process(
        module_path!(),
        "a_decision_policy_is_re_cited_at_every_bind_and_publish",
        || {
            let mut lab = Lab::new();
            let notes = lab.declare("notes", MAX_JOURNAL_BYTES);
            let root = Uuid::new_v4();
            let policy = lab
                .policy(
                    &notes,
                    PolicyRequest {
                        authority: PolicyAuthority::Decision { id: "d".repeat(64) },
                        ..read_propose(Audience::Lineage { root }, 1 << 20)
                    },
                )
                .unwrap();
            let citer = Citer {
                covers: std::cell::Cell::new(true),
                not_after: NOW + 60,
            };
            let held = lab
                .bind_with("notes", root, PodLabels::PodAuthored, NOW, Some(&citer))
                .unwrap();
            assert_eq!(
                lab.binding(&held).not_after,
                NOW + 60,
                "the decision's window bounds it"
            );
            let refused = lab.bind("notes", root).unwrap_err();
            assert!(
                refused.to_string().contains("verifies no owner decisions"),
                "a node that verifies no decisions cannot bind under one: {refused}"
            );
            write(&held, &[raw("x")]);
            citer.covers.set(false);
            let head = lab.head(&notes);
            let refused = lab
                .publish_at(held.binding, head, NOW, Some(&citer))
                .unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains(&format!("binding policy {policy}'s owner decision")),
                "{refused}"
            );
            let refused = lab
                .bind_with("notes", root, PodLabels::PodAuthored, NOW, Some(&citer))
                .unwrap_err();
            assert!(
                refused.to_string().contains("no longer covers"),
                "{refused}"
            );
            citer.covers.set(true);
            assert!(
                lab.publish_at(held.binding, head, NOW, Some(&citer))
                    .is_ok()
            );
        },
    );
}

fn legacy_store(root: &Path, space: &str, records: &[MemoryRecord]) -> PathBuf {
    let dir = root.join(tenant().as_str()).join(space);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&dir)
        .unwrap();
    let loc = JournalLocation::new(
        &dir.join(JOURNAL),
        &format!("{}/{space}", tenant().as_str()),
    )
    .unwrap();
    write_delivery(&loc, records, &TransformRegistry::new()).unwrap();
    dir
}

/// The owner-keyed layout gave every lineage of a tenant the same store. Migration declares
/// each such store a space, in place, under one `TenantAll-legacy` policy, and says so in a
/// receipt, once. Program C, C0: the store records no lineage that owns it and its labels are
/// not dependency-stamped, so until C1 it is delivered to NO run — every bind is refused by name,
/// nothing is receipted, and the store stays in place untouched. (Before C0 its reach was kept
/// across lineages.) A second migration changes nothing, and a revoked migrated policy stays
/// revoked rather than being re-migrated.
#[test]
fn migration_declares_each_legacy_store_once_and_delivers_it_to_no_run_until_stamped() {
    in_own_process(
        module_path!(),
        "migration_declares_each_legacy_store_once_and_delivers_it_to_no_run_until_stamped",
        || {
            let mut lab = Lab::new();
            let store = legacy_store(&lab.root, "project-a", &[raw("legacy")]);
            let kept = std::fs::read(store.join(JOURNAL)).unwrap();
            let migrated = lab.registry.migrate(NOW).unwrap();
            let [event] = migrated.as_slice() else {
                panic!("one migration, got {migrated:?}");
            };
            let policy = event.policy.unwrap();
            assert_eq!(
                lab.registry.policies[&policy].audience,
                Audience::TenantAllLegacy
            );
            let claim = serde_json::to_value(lab.registry.migration_claim(event, NOW)).unwrap();
            assert_eq!(claim["event"]["kind"], "migrated");
            assert_eq!(claim["event"]["audience"]["kind"], "tenant_all_legacy");
            lab.registry.commit_migration(&migrated).unwrap();
            lab.restart();
            assert!(lab.registry.migrate(NOW).unwrap().is_empty(), "idempotent");

            let receipts = lab.receipts.len();
            for _ in 0..2 {
                assert_cross_run(
                    &lab.bind("project-a", Uuid::new_v4()).unwrap_err(),
                    "records no lineage that owns it",
                );
            }
            assert!(lab.registry.bindings.is_empty(), "no run was bound to it");
            assert_eq!(lab.receipts.len(), receipts, "nothing was delivered");
            assert_eq!(
                std::fs::read(store.join(JOURNAL)).unwrap(),
                kept,
                "the legacy store is kept in place, untouched"
            );
            assert!(
                lab.bind("project-b", Uuid::new_v4())
                    .map(|d| lab.binding(&d).space.clone())
                    .unwrap()
                    != (SpaceId::Named {
                        name: name("project-b")
                    }),
                "a name with no legacy store stays lineage-scoped"
            );

            let space = SpaceId::Named {
                name: name("project-a"),
            };
            lab.revoke_policy(&space, policy);
            lab.restart();
            assert!(lab.registry.migrate(NOW).unwrap().is_empty());
            let refused = lab.bind("project-a", Uuid::new_v4()).unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains(&format!("binding policy {policy} is revoked")),
                "a revoked migrated policy is refused by name, not re-migrated: {refused}"
            );
        },
    );
}

/// A store of the held lineage-scoped layout becomes its lineage's space, in place, and stays
/// that lineage's alone; a store colliding with a space the tenant already declared is not
/// migrated (which would merge two stores) and stays unreachable.
#[test]
fn held_lineage_stores_stay_their_lineages_and_collisions_are_not_merged() {
    in_own_process(
        module_path!(),
        "held_lineage_stores_stay_their_lineages_and_collisions_are_not_merged",
        || {
            let mut lab = Lab::new();
            let root = Uuid::new_v4();
            let dir = lab
                .root
                .join("lineage")
                .join(tenant().as_str())
                .join(root.to_string())
                .join("notes");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&dir)
                .unwrap();
            let loc = JournalLocation::new(
                &dir.join(JOURNAL),
                &format!("lineage/{}/{root}/notes", tenant().as_str()),
            )
            .unwrap();
            write_delivery(&loc, &[raw("held")], &TransformRegistry::new()).unwrap();
            lab.declare("project-a", MAX_JOURNAL_BYTES);
            legacy_store(&lab.root, "project-a", &[raw("collides")]);

            let migrated = lab.registry.migrate(NOW).unwrap();
            assert_eq!(migrated.len(), 2, "{migrated:?}");
            let skipped = migrated.iter().find(|m| m.policy.is_none()).unwrap();
            assert_eq!(
                skipped.space,
                SpaceId::Named {
                    name: name("project-a")
                }
            );
            let claim = serde_json::to_value(lab.registry.migration_claim(skipped, NOW)).unwrap();
            assert_eq!(claim["event"]["kind"], "migration_skipped");
            lab.registry.commit_migration(&migrated).unwrap();
            assert_eq!(
                values(&given(&lab.bind("notes", root).unwrap())),
                values(&[raw("held")])
            );
            assert!(given(&lab.bind("notes", Uuid::new_v4()).unwrap()).is_empty());
        },
    );
}

/// The held branch's SharedMemory registry has no faithful translation: the node refuses to
/// start rather than guess who may reach its shares.
#[test]
fn a_held_share_registry_refuses_the_start() {
    in_own_process(
        module_path!(),
        "a_held_share_registry_refuses_the_start",
        || {
            let lab = Lab::new();
            std::fs::write(lab.root.join("shares.json"), b"{}").unwrap();
            let refused = Registry::load(&lab.root).unwrap_err();
            assert!(refused.to_string().contains("shares.json"), "{refused}");
        },
    );
}
