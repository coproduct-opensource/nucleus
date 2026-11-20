//! C2 on a real Firecracker boot: two pods on one node, and each sees only its own lineage.
//! Live: Linux, KVM, root. Invoked by `cargo xtask cross-pod-live`. It replaces
//! `scripts/firecracker/podlist-boot-check.sh`.
//!
//! # What runs
//!
//! One node, three Firecracker pods booted from the CI podlist rootfs:
//! - A, an orchestrator;
//! - C, A's child, with lineage set by the operator through
//!   `x-nucleus-parent-pod-id`;
//! - B, a sibling of A that is not in A's lineage.
//!
//! Every guest runs the trusted CI-only lineage probe beside its proxy. Over the
//! pod's own workload-API vsock it calls `POD_LIST`, the guest's ordinary
//! management call, which the socket authenticates. It prints the ids it was
//! served. There is no attack or escape probe here: every call is one a pod
//! makes in normal operation, and the host only reads what came back.
//!
//! # The property, for both views
//!
//! - `A ∈ view(A)`, `C ∈ view(A)`, `B ∉ view(A)`. C's inclusion is the tooth
//!   that a self-only filter cannot satisfy.
//! - `B ∈ view(B)`, `A ∉ view(B)`, `C ∉ view(B)`. This is the symmetric half the
//!   script never checked.
//! - The two roots are served DISTINCT ids: each view holds its own pod and not
//!   the other root. A node that bound both sockets to one id fails here.
//! - Both views are strict subsets of the operator's, and the operator's holds
//!   all three. So exclusion means filtered, not absent.
//!
//! A node whose filter returns every pod fails the B-exclusion half and the
//! strict-subset half. That is the A-19 red.

use super::node::Node;
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

const SENTINEL: &str = "NUCLEUS_PODLIST_PROBE: ";
const PASS: &str = "NUCLEUS_PODLIST_PROBE: PASS ids=";
const FAIL: &str = "NUCLEUS_PODLIST_PROBE: FAIL";

/// The scoped view the guest's probe reports for one pod.
#[derive(Debug)]
enum Reported {
    Ids(BTreeSet<Uuid>),
    /// The probe's own FAIL verdict.
    Failed(String),
    /// A sentinel was on the console but no whole record was: a line still
    /// being written when the log was read, one split by another console
    /// writer, or whole copies that disagree. It is neither a pass nor the
    /// probe's FAIL: the harness could not read the verdict (ADR 0007 A-2).
    Torn(String),
}

/// The ids of one PASS record, if it is whole: newline-terminated, and
/// nothing but a non-empty, comma-separated list of hyphenated UUIDs after
/// `ids=`. Anything else is a fragment, never a shorter list.
fn whole_pass(record: &str, terminated: bool) -> Option<Vec<Uuid>> {
    let ids = record.strip_prefix(PASS)?.trim_end();
    if !terminated || ids.is_empty() {
        return None;
    }
    ids.split(',')
        .map(|id| Uuid::parse_str(id).ok().filter(|_| id.len() == 36))
        .collect()
}

/// Read the probe's verdict from a pod's console log.
///
/// The serial console has more than one writer (#3403): the probe's line can
/// be read before it is fully written, or have a kernel or guest-init message
/// spliced into it. So every sentinel is a candidate, wherever it starts in a
/// line; a record runs to the next sentinel or the end of its line, and only a
/// newline-terminated record that parses whole counts. The probe prints its
/// line twice (stdout and stderr), so one torn copy beside a whole one still
/// reads. Whole copies must agree, except that one may be a prefix of the
/// longest (cut at a comma by a spliced newline); the longest is taken, so a
/// cut never removes an id the probe reported.
fn reported(log: &str) -> Option<Reported> {
    let mut whole: Vec<Vec<Uuid>> = Vec::new();
    let mut torn: Option<String> = None;
    for line in log.split_inclusive('\n') {
        let terminated = line.ends_with('\n');
        let starts: Vec<usize> = line.match_indices(SENTINEL).map(|(at, _)| at).collect();
        for (n, &start) in starts.iter().enumerate() {
            let next = starts.get(n + 1).copied();
            let record = &line[start..next.unwrap_or(line.len())];
            if record.starts_with(FAIL) {
                return Some(Reported::Failed(record.trim().to_string()));
            }
            match whole_pass(record, terminated && next.is_none()) {
                Some(ids) => whole.push(ids),
                None => torn = Some(record.trim_end().to_string()),
            }
        }
    }
    let Some(longest) = whole.iter().max_by_key(|ids| ids.len()) else {
        return torn.map(Reported::Torn);
    };
    if whole.iter().all(|ids| longest.starts_with(ids)) {
        Some(Reported::Ids(longest.iter().copied().collect()))
    } else {
        Some(Reported::Torn(format!(
            "the probe's whole console records disagree: {whole:?}"
        )))
    }
}

fn spec(name: &str, kernel: &Path, rootfs: &Path) -> serde_json::Value {
    json!({
        "apiVersion": "nucleus/v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {"enable_pod_mgmt": "true"}},
        "spec": {
            "work_dir": "/work", "timeout_seconds": 300,
            "policy": {"type": "profile", "name": "orchestrator"},
            "image": {"kernel_path": kernel, "rootfs_path": rootfs, "read_only": true},
            "vsock": {"guest_cid": 3, "port": 5005}
        }
    })
}

async fn create(node: &Node, spec: &serde_json::Value, parent: Option<Uuid>) -> Result<Uuid> {
    let mut request = node
        .client
        .post(format!("{}/v1/pods", node.url))
        .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
        .json(spec);
    if let Some(parent) = parent {
        request = request.header("x-nucleus-parent-pod-id", parent.to_string());
    }
    let created: super::Created =
        serde_json::from_slice(&super::body(request.send().await?).await?)?;
    Ok(created.id)
}

async fn operator_view(node: &Node) -> Result<BTreeSet<Uuid>> {
    let bytes = super::body(
        node.client
            .get(format!("{}/v1/pods", node.url))
            .send()
            .await?,
    )
    .await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let pods = value
        .as_array()
        .or_else(|| value.get("pods").and_then(serde_json::Value::as_array))
        .context("the operator listing is neither a list nor {pods: [...]}")?;
    pods.iter()
        .map(|p| {
            let id = p["id"].as_str().context("a listed pod has no id")?;
            Ok(Uuid::parse_str(id)?)
        })
        .collect()
}

/// Every `firecracker.log` under `root` whose path names `pod`.
fn console_logs(root: &Path, pod: Uuid, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            console_logs(&path, pod, out);
        } else if path.file_name().is_some_and(|n| n == "firecracker.log")
            && path.to_string_lossy().contains(&pod.to_string())
        {
            out.push(path);
        }
    }
}

/// Wait for `pod`'s probe to report, up to `within`. A torn record is read
/// again on the next poll, since the line may still be being written; it is
/// returned only if nothing whole arrives by the deadline.
async fn wait_reported(node: &Node, pod: Uuid, within: Duration) -> Result<Reported> {
    let deadline = tokio::time::Instant::now() + within;
    let mut torn = None;
    loop {
        let mut logs = Vec::new();
        console_logs(&node.state, pod, &mut logs);
        console_logs(node.jail_base(), pod, &mut logs);
        for log in &logs {
            let text =
                String::from_utf8_lossy(&std::fs::read(log).unwrap_or_default()).into_owned();
            match reported(&text) {
                Some(Reported::Torn(record)) => torn = Some(record),
                Some(r) => return Ok(r),
                None => {}
            }
        }
        if tokio::time::Instant::now() >= deadline {
            if let Some(record) = torn {
                return Ok(Reported::Torn(record));
            }
            bail!(
                "pod {pod}'s probe never reported within {within:?} (searched {} console log(s))",
                logs.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn view(name: &str, r: Reported) -> Result<BTreeSet<Uuid>> {
    match r {
        Reported::Ids(ids) => Ok(ids),
        Reported::Failed(why) => {
            bail!("{name}'s probe did not settle on a scoped listing over its vsock: {why}")
        }
        Reported::Torn(record) => bail!(
            "{name}'s probe verdict is torn or unreadable on the console \
             (neither a pass nor the probe's FAIL): {record}"
        ),
    }
}

/// The property, as a list of named failures. Empty is a pass.
fn judge(
    (a, b, c): (Uuid, Uuid, Uuid),
    view_a: &BTreeSet<Uuid>,
    view_b: &BTreeSet<Uuid>,
    operator: &BTreeSet<Uuid>,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut need = |ok: bool, what: &str| {
        if !ok {
            failures.push(what.to_string());
        }
    };
    need(operator.contains(&a), "the operator view is missing A");
    need(
        operator.contains(&b),
        "the operator view is missing B, so B's exclusion would mean nothing",
    );
    need(
        operator.contains(&c),
        "the operator view is missing C, so C's inclusion would mean nothing",
    );
    need(
        view_a.contains(&a),
        "A is not in its own view: A's socket was not served A's id",
    );
    need(
        view_a.contains(&c),
        "A's child C is not in A's view: the filter is self-only, not lineage",
    );
    need(
        !view_a.contains(&b),
        "sibling B IS in A's view: cross-pod isolation failed over vsock",
    );
    need(
        view_b.contains(&b),
        "B is not in its own view: B's socket was not served B's id",
    );
    need(
        !view_b.contains(&a),
        "A IS in B's view: cross-pod isolation failed over vsock",
    );
    need(
        !view_b.contains(&c),
        "A's child C IS in B's view: cross-pod isolation failed over vsock",
    );
    need(
        view_a.is_subset(operator) && view_a != operator,
        "A's view is not a strict subset of the operator's: no scoping occurred",
    );
    need(
        view_b.is_subset(operator) && view_b != operator,
        "B's view is not a strict subset of the operator's: no scoping occurred",
    );
    failures
}

/// The node's artifacts root for this run: the kernel, and one rootfs copy per
/// pod. A pod may name an image only inside `--artifacts-root`. The directory
/// lives in `/var/tmp`, on the same filesystem as the fixture's jail base,
/// because the jailer hard-links each drive into its jail.
struct Artifacts {
    _dir: tempfile::TempDir,
    kernel: PathBuf,
    root: PathBuf,
}

impl Artifacts {
    fn stage(kernel: &Path, rootfs: &Path) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .prefix("xp")
            .tempdir_in("/var/tmp")?;
        let root = dir.path().to_path_buf();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
        let place = |from: &Path, name: &str| -> Result<PathBuf> {
            let to = root.join(name);
            std::fs::copy(from, &to).with_context(|| format!("copying {}", from.display()))?;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o644))?;
            Ok(to)
        };
        let kernel = place(kernel, "vmlinux")?;
        for pod in ["a", "b", "c"] {
            place(rootfs, &format!("rootfs-{pod}.ext4"))?;
        }
        Ok(Self {
            _dir: dir,
            kernel,
            root,
        })
    }
    fn rootfs(&self, pod: &str) -> PathBuf {
        self.root.join(format!("rootfs-{pod}.ext4"))
    }
}

async fn scenario(node: &Node, artifacts: &Artifacts) -> Result<Vec<String>> {
    let kernel = artifacts.kernel.as_path();
    let a = create(node, &spec("orch-a", kernel, &artifacts.rootfs("a")), None).await?;
    let spec_c = spec("child-c", kernel, &artifacts.rootfs("c"));
    let spec_b = spec("sibling-b", kernel, &artifacts.rootfs("b"));
    let (c, b) = tokio::try_join!(create(node, &spec_c, Some(a)), create(node, &spec_b, None),)?;
    println!("cross-pod-live: A={a} C={c} (child of A) B={b} (sibling)");
    let operator = operator_view(node).await?;
    let view_a = view("A", wait_reported(node, a, Duration::from_secs(180)).await?)?;
    let view_b = view("B", wait_reported(node, b, Duration::from_secs(180)).await?)?;
    let show = |s: &BTreeSet<Uuid>| s.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
    println!("cross-pod-live: view(A)=[{}]", show(&view_a));
    println!("cross-pod-live: view(B)=[{}]", show(&view_b));
    println!("cross-pod-live: operator=[{}]", show(&operator));
    for pod in [c, b, a] {
        let _ = node
            .client
            .post(format!("{}/v1/pods/{pod}/cancel", node.url))
            .send()
            .await;
    }
    Ok(judge((a, b, c), &view_a, &view_b, &operator))
}

#[tokio::test]
#[ignore = "requires a Linux KVM host and the CI podlist rootfs; run cargo xtask cross-pod-live"]
async fn two_pods_each_see_only_their_own_lineage() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "cross-pod-live requires Linux");
    let var = |k: &str| {
        std::env::var_os(k)
            .map(PathBuf::from)
            .with_context(|| format!("missing {k}"))
    };
    let bins = var("NUCLEUS_HOST_EVIDENCE_BIN_DIR")?;
    let witness = var("NUCLEUS_HOST_EVIDENCE_WITNESS")?;
    let kernel = var("NUCLEUS_CROSS_POD_KERNEL")?;
    let rootfs = var("NUCLEUS_CROSS_POD_ROOTFS")?;
    let nonce = std::env::var("NUCLEUS_HOST_EVIDENCE_NONCE")?;
    ensure!(!nonce.is_empty(), "missing nonce");
    let artifacts = Artifacts::stage(&kernel, &rootfs)?;
    let root = artifacts.root.to_string_lossy().into_owned();
    let mut node = Node::start_with(
        &bins.join("nucleus-node"),
        &nonce,
        &["--artifacts-root".to_string(), root],
    )
    .await?;
    let result = scenario(&node, &artifacts).await;
    let diagnostics = node.diagnostics();
    let _ = node.stop().await;
    let failures = result.with_context(|| diagnostics.clone())?;
    for failure in &failures {
        println!("cross-pod-live: FAIL {failure}");
    }
    ensure!(
        failures.is_empty(),
        "cross-pod isolation did not hold on the real boot ({} failure(s))",
        failures.len()
    );
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(witness)?;
    file.write_all(nonce.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod judge_tests {
    use super::*;

    fn ids() -> (Uuid, Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
    }

    /// The live boot's expected answer passes.
    #[test]
    fn scoped_views_pass() {
        let (a, b, c) = ids();
        let op: BTreeSet<_> = [a, b, c].into();
        assert!(judge((a, b, c), &[a, c].into(), &[b].into(), &op).is_empty());
    }

    /// A filter that returns every pod is caught on both halves, which is the
    /// red the live run is driven to on purpose.
    #[test]
    fn an_unfiltered_node_fails() {
        let (a, b, c) = ids();
        let op: BTreeSet<_> = [a, b, c].into();
        let failures = judge((a, b, c), &op, &op, &op);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("sibling B IS in A's view"))
        );
        assert!(failures.iter().any(|f| f.contains("A IS in B's view")));
        assert!(failures.iter().any(|f| f.contains("strict subset")));
    }

    /// A self-only filter, and one that binds both sockets to A's id, each
    /// fail by name.
    #[test]
    fn self_only_and_one_id_for_both_fail() {
        let (a, b, c) = ids();
        let op: BTreeSet<_> = [a, b, c].into();
        let self_only = judge((a, b, c), &[a].into(), &[b].into(), &op);
        assert!(self_only.iter().any(|f| f.contains("self-only")));
        let one_id = judge((a, b, c), &[a, c].into(), &[a, c].into(), &op);
        assert!(
            one_id
                .iter()
                .any(|f| f.contains("B is not in its own view"))
        );
    }

    /// The sentinel parser reads a whole report and refuses a FAIL.
    #[test]
    fn the_console_report_is_parsed() {
        let (a, _, c) = ids();
        let log = format!("noise\n{PASS}{a}\r\n{PASS}{a},{c}\r\n");
        match reported(&log) {
            Some(Reported::Ids(got)) => assert_eq!(got, [a, c].into()),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            reported(&format!("{FAIL}: refused\n")),
            Some(Reported::Failed(_))
        ));
        assert!(reported("nothing here").is_none());
    }

    // #3403, from run 38330748070: pod A = 1168f421-…-bbe15e840084, child
    // C = a71ac778-…-a8e0f9d0ff6f. The harness read the console while the
    // probe's line was still arriving and reported "unparseable ids" as the
    // probe failing; the node's own diagnostics later showed the same line
    // grown to `…084,` and still unterminated.
    const RUN_A: &str = "1168f421-2d04-4ddb-b593-bbe15e840084";
    const RUN_C: &str = "a71ac778-5a55-4ece-ac89-a8e0f9d0ff6f";
    const RUN_PREFIX: &str = "[    1.071710] NUCLEUS-HOST-DECIDE-TELEMETRY {\"agree\":0}\n";

    fn run_ids() -> BTreeSet<Uuid> {
        [RUN_A, RUN_C].map(|id| Uuid::parse_str(id).unwrap()).into()
    }

    /// The two reads CI took of the line while it was being written are torn,
    /// not a FAIL and not a shorter listing.
    #[test]
    fn a_line_still_being_written_is_torn() {
        for read in [
            format!("{RUN_PREFIX}{PASS}1168f421-2d04-4ddb-b593-bbe"),
            format!("{RUN_PREFIX}{PASS}{RUN_A},"),
            // Cut exactly after an id: still not whole without its newline.
            format!("{RUN_PREFIX}{PASS}{RUN_A}"),
        ] {
            assert!(
                matches!(reported(&read), Some(Reported::Torn(_))),
                "{read:?} read as {:?}",
                reported(&read)
            );
        }
        // Once the line is finished, the same log reads whole.
        let finished = format!("{RUN_PREFIX}{PASS}{RUN_A},{RUN_C}\r\n");
        assert!(matches!(reported(&finished), Some(Reported::Ids(ids)) if ids == run_ids()));
    }

    /// Another writer splicing into the record makes that copy torn; the
    /// probe's second copy (stdout, then stderr) still reads whole.
    #[test]
    fn a_spliced_copy_is_torn_and_the_whole_copy_reads() {
        let spliced = format!(
            "{PASS}1168f421-2d04-4ddb-b593-bbe[    1.2] random: crng init done\n\
             15e840084,{RUN_C}\r\n"
        );
        assert!(matches!(reported(&spliced), Some(Reported::Torn(_))));
        let both = format!("{spliced}{PASS}{RUN_A},{RUN_C}\r\n");
        assert!(matches!(reported(&both), Some(Reported::Ids(ids)) if ids == run_ids()));
        // The two copies glued on one line, the first cut short.
        let glued = format!("{PASS}1168f421-2d04{PASS}{RUN_A},{RUN_C}\r\n");
        assert!(matches!(reported(&glued), Some(Reported::Ids(ids)) if ids == run_ids()));
    }

    /// A sentinel that starts mid-line, after another writer's unterminated
    /// output, is still found.
    #[test]
    fn a_sentinel_mid_line_is_found() {
        let log = format!("nucleus-startup-phase vsock_bind=0ms{PASS}{RUN_A},{RUN_C}\n");
        assert!(matches!(reported(&log), Some(Reported::Ids(ids)) if ids == run_ids()));
    }

    /// A copy cut at a comma by a spliced newline reads as a shorter whole
    /// list. Beside the full copy, the longest is taken, so the cut never
    /// drops an id the probe printed (a dropped id could hide a leak).
    #[test]
    fn a_copy_cut_at_a_comma_never_shortens_the_view() {
        let log = format!("{PASS}{RUN_A}\n[    1.3] message\n{RUN_C}\n{PASS}{RUN_A},{RUN_C}\n");
        assert!(matches!(reported(&log), Some(Reported::Ids(ids)) if ids == run_ids()));
    }

    /// Whole copies that disagree are torn: the harness cannot tell which is
    /// the probe's.
    #[test]
    fn whole_copies_that_disagree_are_torn() {
        let log = format!("{PASS}{RUN_C}\n{PASS}{RUN_A},{RUN_C}\n");
        assert!(matches!(reported(&log), Some(Reported::Torn(_))));
    }

    /// A torn record is reported as torn by name, never as the probe's FAIL.
    #[test]
    fn a_torn_view_is_named_torn() {
        let err = view("A", Reported::Torn(format!("{PASS}{RUN_A},"))).unwrap_err();
        assert!(err.to_string().contains("torn or unreadable"), "{err}");
        assert!(!err.to_string().contains("did not settle"), "{err}");
    }
}
