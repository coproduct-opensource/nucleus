//! Kill the VMMs a killed node stranded, at startup, found by their jail's cgroup (#3204).
//!
//! # Why this exists
//!
//! `reclaim_orphaned_jails` (#2970) removes the jail DIRECTORIES a previous life left, on the
//! premise that a pod cannot outlive the node. That premise is false for a node stopped by a
//! signal: SIGKILL runs no code at all, and the VMM is a separate process that keeps running.
//! Deleting its jail directory then leaves a live, unsupervised microVM with its netns, host veth,
//! host firewall rules and dnsmasq — and nothing in the new life that knows it exists.
//!
//! # How a stranded VMM is identified
//!
//! By kernel membership, never by process name. Two handles, both derived from the jail id this
//! node gave the pod, which is the directory name under `<chroot base>/<exec>/`:
//!
//! - **The jail's cgroup.** The jailer places Firecracker in `<cgroup root>/<exec>/<id>` on
//!   cgroup v2 (its default `--parent-cgroup` is the exec file's name, and the node passes none),
//!   before `exec`, so the VMM cannot run outside it. [`jailer_cgroup_dir`] derives that path from
//!   the [`JailLayout`] alone, so it cannot disagree with where the jail was placed.
//! - **The pod's network namespace.** The jailer joins it with `--netns`, and the pod's dnsmasq
//!   runs under `ip netns exec`, so `ip netns pids` lists both.
//!
//! A process named `firecracker` that belongs to another node, or to anything else, is in
//! neither, and is never touched.
//!
//! # Why not a parent-death signal
//!
//! `PR_SET_PDEATHSIG` is the obvious tie between a VMM and its node, and it would be decorative
//! here. The kernel clears it when a process's effective uid or gid changes (`commit_creds`), and
//! the jailer drops to `--uid`/`--gid` before it `exec`s Firecracker — so the signal is gone by
//! the time the VMM exists. It also fires on the death of the spawning THREAD, not the process,
//! and a tokio worker or blocking thread can exit while the node lives, which would kill a
//! healthy VM. So the tie is the cgroup, enforced by the next life, before it serves anything:
//! `cgroup.kill` kills every member at once, including any it forked, without a race against the
//! process table.
//!
//! # What is fatal
//!
//! A stranded process that is still alive after it was killed, or a membership that could not be
//! read, refuses startup by name. Either means an unsupervised microVM may still be running, and
//! serving next to it would hand its subnet and its pod id's resources to a new life. Leftover
//! network or cgroup residue after the VMM is confirmed dead is logged and the node starts: that
//! is cleanup owed, not isolation lost.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::time::Duration;

use uuid::Uuid;

use crate::ApiError;
use crate::firecracker_config::{self, JailLayout};

/// Where the node reads cgroup membership. A parameter everywhere below so tests can stand in a
/// directory for it.
pub(crate) const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// How long a killed stranded VMM has to leave its cgroup and namespace before startup refuses.
const KILL_CONFIRM: Duration = Duration::from_secs(10);

/// The jailer's cgroup v2 directory for the pod laid out at `layout`: `<root>/<exec>/<id>`.
///
/// Derived from the layout rather than from the firecracker path a second time: the layout's path
/// is `<chroot base>/<exec>/<id>/root`, written by `JailLayout::new` from `jail_exec_name`, which
/// is the same name the jailer uses for its default parent cgroup.
pub(crate) fn jailer_cgroup_dir(cgroup_root: &Path, layout: &JailLayout) -> Option<PathBuf> {
    let pod = layout.jail_root.parent()?;
    let id = pod.file_name()?;
    let exec = pod.parent()?.file_name()?;
    Some(cgroup_root.join(exec).join(id))
}

/// Who is in a cgroup. "No such cgroup" is a fact of its own, not an empty list.
#[derive(Debug, PartialEq, Eq)]
enum Members {
    Absent,
    Pids(Vec<i32>),
}

fn cgroup_members(dir: &Path) -> std::io::Result<Members> {
    match std::fs::read_to_string(dir.join("cgroup.procs")) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| {
                l.parse::<i32>()
                    .map_err(|_| std::io::Error::other(format!("invalid pid {l:?}")))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Members::Pids),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !dir.exists() => Ok(Members::Absent),
        Err(e) => Err(e),
    }
}

/// SIGKILL every member of `dir` at once with `cgroup.kill` (Linux 5.14+), which also catches a
/// member forked mid-kill. A kernel without the file is not an error: every member is also
/// killed by pid, in [`reclaim_one`].
fn kill_cgroup(dir: &Path) -> std::io::Result<()> {
    // Open without create: on a kernel without `cgroup.kill` the file is absent, and writing it
    // must not be mistaken for a kill.
    let kill = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("cgroup.kill"))
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"1"));
    match kill {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// SIGKILL one pid with `kill(1)`, as the node runs `ip` and `iptables`, rather than through a
/// signal binding or an `unsafe` libc call. A pid that is already gone is not an error; whether
/// the process actually left is decided by the membership re-read, never by this exit code.
async fn kill_pid(pid: i32) -> std::io::Result<()> {
    let status = tokio::process::Command::new("kill")
        .args(["-s", "KILL", "--", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;
    if status.success() || !Path::new("/proc").join(pid.to_string()).exists() {
        return Ok(());
    }
    Err(std::io::Error::other(format!("kill exited {status}")))
}

/// Remove an EMPTY cgroup leaf. Its last member can take a moment to leave after exiting, so a
/// busy leaf is retried briefly; an absent one is already gone.
pub(crate) async fn remove_cgroup_leaf(dir: &Path) -> std::io::Result<()> {
    let mut attempts = 0;
    loop {
        match tokio::fs::remove_dir(dir).await {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::ResourceBusy && attempts < 40 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// How the reclaim reaches a stranded pod's network. The node's runs `ip`; tests' is a fixture.
#[tonic::async_trait]
pub(crate) trait StrandedNet: Send + Sync {
    async fn pids(&self, pod: Uuid) -> Result<Option<Vec<i32>>, ApiError>;
    async fn release(&self, pod: Uuid) -> Result<(), ApiError>;
}

pub(crate) struct HostNet;

#[tonic::async_trait]
impl StrandedNet for HostNet {
    async fn pids(&self, pod: Uuid) -> Result<Option<Vec<i32>>, ApiError> {
        crate::net::netns_pids(&crate::net::netns_name(pod)).await
    }
    async fn release(&self, pod: Uuid) -> Result<(), ApiError> {
        crate::net::reclaim_stranded_link(pod).await
    }
}

/// What the reclaim did with one stranded pod that it may start next to.
#[derive(Debug)]
pub(crate) struct Reclaimed {
    pub(crate) jail_id: String,
    /// Processes that were still alive and were killed. Zero is a pod whose VMM had already died.
    pub(crate) killed: usize,
    /// Cleanup that could not be confirmed after the processes were confirmed dead.
    pub(crate) residue: Vec<String>,
}

/// Why startup refuses.
#[derive(Debug)]
enum Refusal {
    Survived { jail_id: String, pids: Vec<i32> },
    Unobservable { jail_id: String, reason: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Survived { jail_id, pids } => {
                write!(
                    f,
                    "jail {jail_id}: pid(s) {pids:?} still alive after SIGKILL"
                )
            }
            Refusal::Unobservable { jail_id, reason } => {
                write!(f, "jail {jail_id}: membership could not be read: {reason}")
            }
        }
    }
}

/// The live members of a stranded pod: its jail cgroup's and its namespace's.
async fn live_members(
    cgroup: Option<&Path>,
    pod: Option<Uuid>,
    net: &dyn StrandedNet,
) -> Result<Vec<i32>, String> {
    let mut pids = Vec::new();
    if let Some(dir) = cgroup {
        match cgroup_members(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            Members::Absent => {}
            Members::Pids(found) => pids.extend(found),
        }
    }
    if let Some(pod) = pod {
        match net.pids(pod).await.map_err(|e| e.to_string())? {
            None => {}
            Some(found) => pids.extend(found),
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

/// Kill, confirm and release one stranded pod.
async fn reclaim_one(
    jail_id: &str,
    cgroup: Option<PathBuf>,
    net: &dyn StrandedNet,
    confirm_within: Duration,
) -> Result<Reclaimed, Refusal> {
    // A jail the node made is named by a pod id; anything else has no namespace to look in.
    let pod = Uuid::parse_str(jail_id).ok();
    let unobservable = |reason: String| Refusal::Unobservable {
        jail_id: jail_id.to_owned(),
        reason,
    };
    let alive = live_members(cgroup.as_deref(), pod, net)
        .await
        .map_err(unobservable)?;
    if !alive.is_empty() {
        if let Some(dir) = cgroup.as_deref()
            && dir.exists()
        {
            kill_cgroup(dir).map_err(|e| unobservable(format!("cgroup.kill: {e}")))?;
        }
        for pid in &alive {
            kill_pid(*pid)
                .await
                .map_err(|e| unobservable(format!("kill {pid}: {e}")))?;
        }
        let deadline = tokio::time::Instant::now() + confirm_within;
        loop {
            let left = live_members(cgroup.as_deref(), pod, net)
                .await
                .map_err(unobservable)?;
            if left.is_empty() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Refusal::Survived {
                    jail_id: jail_id.to_owned(),
                    pids: left,
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let mut residue = Vec::new();
    if let Some(pod) = pod
        && let Err(e) = net.release(pod).await
    {
        residue.push(format!("network: {e}"));
    }
    if let Some(dir) = cgroup.as_deref()
        && let Err(e) = remove_cgroup_leaf(dir).await
    {
        residue.push(format!("cgroup {}: {e}", dir.display()));
    }
    Ok(Reclaimed {
        jail_id: jail_id.to_owned(),
        killed: alive.len(),
        residue,
    })
}

/// The jail ids a previous life left: the directories under `<chroot base>/<exec>/`. A base that
/// does not exist is first boot; one that cannot be read is an error, not "nothing stranded".
fn stranded_jail_ids(chroot_base: &Path, firecracker_path: &Path) -> std::io::Result<Vec<String>> {
    let base = chroot_base.join(firecracker_config::jail_exec_name(firecracker_path));
    let entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            ids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    ids.sort();
    Ok(ids)
}

/// Kill every VMM a previous life of this node stranded, and release its network and cgroup.
///
/// Runs BEFORE `reclaim_orphaned_jails` removes the jail directories, and before the node serves:
/// a refusal returns here, and the jails stay for an operator to inspect. `cgroup_v2` is false on a
/// cgroup v1 host, where the jailer's per-controller hierarchies are not read and a stranded VMM is
/// found only through its namespace (said in the log, not assumed).
pub(crate) async fn reclaim_stranded_vms(
    chroot_base: &Path,
    firecracker_path: &Path,
    cgroup_root: &Path,
    cgroup_v2: bool,
    net: &dyn StrandedNet,
) -> Result<Vec<Reclaimed>, ApiError> {
    let ids = stranded_jail_ids(chroot_base, firecracker_path).map_err(|e| {
        ApiError::Driver(format!(
            "cannot list jails a previous node may have stranded under {}: {e}",
            chroot_base.display()
        ))
    })?;
    if !ids.is_empty() && !cgroup_v2 {
        tracing::warn!(
            "cgroup v1 host: stranded VMMs are found only through their network namespace"
        );
    }
    let mut reclaimed = Vec::new();
    let mut refused = Vec::new();
    for id in ids {
        let cgroup = cgroup_v2
            .then(|| {
                jailer_cgroup_dir(
                    cgroup_root,
                    &JailLayout::new(chroot_base, firecracker_path, &id),
                )
            })
            .flatten();
        match reclaim_one(&id, cgroup, net, KILL_CONFIRM).await {
            Ok(done) => reclaimed.push(done),
            Err(refusal) => refused.push(refusal),
        }
    }
    for done in &reclaimed {
        if !done.residue.is_empty() {
            tracing::warn!(
                jail = %done.jail_id,
                residue = ?done.residue,
                "stranded pod's VMM is dead; some of its host resources could not be released"
            );
        }
    }
    match refused.as_slice() {
        [] => Ok(reclaimed),
        _ => Err(ApiError::Driver(format!(
            "refusing to start: a previous node's microVM(s) could not be confirmed stopped: \
             {}",
            refused
                .iter()
                .map(Refusal::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ))),
    }
}

/// Write `pod_reclaimed` to each reclaimed pod's lifecycle log, when the pod is this state
/// directory's. A pod whose node was SIGKILLed otherwise ends its record at `pod_started`, and
/// "what stopped it" is the first question its log is read to answer.
pub(crate) async fn record(state_dir: &Path, reclaimed: &[Reclaimed]) {
    for done in reclaimed {
        let Ok(pod) = Uuid::parse_str(&done.jail_id) else {
            continue;
        };
        let pod_dir = crate::lifecycle::pod_dir(state_dir, pod);
        if !pod_dir.is_dir() {
            continue;
        }
        let detail = match done.residue.as_slice() {
            [] => format!(
                "node startup: killed {} process(es) a previous node life stranded; released",
                done.killed
            ),
            residue => format!(
                "node startup: killed {} process(es) a previous node life stranded; NOT released: {}",
                done.killed,
                residue.join("; ")
            ),
        };
        crate::lifecycle::write_lifecycle_audit(&pod_dir, "pod_reclaimed", &done.jail_id, &detail)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A namespace fixture: a fixed member list per pod, and a record of what was released.
    #[derive(Default)]
    struct Net {
        members: Mutex<Vec<i32>>,
        unreadable: bool,
        released: Mutex<Vec<Uuid>>,
    }

    #[tonic::async_trait]
    impl StrandedNet for Net {
        async fn pids(&self, _pod: Uuid) -> Result<Option<Vec<i32>>, ApiError> {
            if self.unreadable {
                return Err(ApiError::Driver("ip netns list exited 1".into()));
            }
            Ok(Some(self.members.lock().unwrap().clone()))
        }
        async fn release(&self, pod: Uuid) -> Result<(), ApiError> {
            self.released.lock().unwrap().push(pod);
            Ok(())
        }
    }

    /// The jailer's own rule: `<cgroup root>/<exec file name>/<id>`. If the layout ever nested
    /// pods differently the reclaim would read a cgroup no VMM was placed in — and, finding it
    /// absent, kill nothing while reporting the jail reclaimed.
    #[test]
    fn the_cgroup_is_where_the_jailer_puts_it() {
        let layout = JailLayout::new(
            Path::new("/srv/jailer"),
            Path::new("/usr/local/bin/firecracker-v1.16"),
            "6f1c0e4e-2c55-4d1e-9a51-6b0d2f3a7c11",
        );
        assert_eq!(
            jailer_cgroup_dir(Path::new(CGROUP_ROOT), &layout).unwrap(),
            Path::new("/sys/fs/cgroup/firecracker-v1.16/6f1c0e4e-2c55-4d1e-9a51-6b0d2f3a7c11")
        );
    }

    /// A stand-in cgroup is a plain directory holding a `cgroup.procs` FILE, so `rmdir` refuses
    /// it where cgroupfs would not. That one residue is the fixture's; the live check
    /// (`cargo xtask node-stop-live`) asserts the real leaf is removed.
    fn only_fake_cgroup_residue(done: &Reclaimed) {
        assert!(
            done.residue.iter().all(|r| r.starts_with("cgroup ")),
            "{:?}",
            done.residue
        );
    }

    fn stage_cgroup(root: &Path, id: &str, pids: &[u32]) -> PathBuf {
        let dir = root.join("firecracker").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let procs: String = pids.iter().map(|p| format!("{p}\n")).collect();
        std::fs::write(dir.join("cgroup.procs"), procs).unwrap();
        dir
    }

    /// A stranded VMM is killed through its cgroup's membership, and the reclaim waits to SEE the
    /// membership empty before calling it reclaimed. The fixture stands in for the kernel: it
    /// empties `cgroup.procs` only once the process has actually died.
    #[tokio::test]
    async fn a_live_stranded_process_is_killed_and_confirmed_gone() {
        let root = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4().to_string();
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let dir = stage_cgroup(root.path(), &id, &[pid]);
        let kernel = {
            let procs = dir.join("cgroup.procs");
            tokio::spawn(async move {
                let status = child.wait().await.unwrap();
                std::fs::write(&procs, b"").unwrap();
                status
            })
        };
        let net = Net::default();
        let done = reclaim_one(&id, Some(dir.clone()), &net, Duration::from_secs(5))
            .await
            .expect("a killed process that left is reclaimed");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(kernel.await.unwrap().signal(), Some(9), "killed by SIGKILL");
        assert_eq!(done.killed, 1);
        only_fake_cgroup_residue(&done);
        assert_eq!(
            *net.released.lock().unwrap(),
            vec![Uuid::parse_str(&id).unwrap()]
        );
    }

    /// The falsifier for "reclaimed": a member that never leaves must refuse startup, not be
    /// reported gone because a kill was SENT (ADR 0007 A-2).
    #[tokio::test]
    async fn a_member_that_never_leaves_refuses_startup() {
        let root = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4().to_string();
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let dir = stage_cgroup(root.path(), &id, &[pid]);
        let refusal = reclaim_one(
            &id,
            Some(dir.clone()),
            &Net::default(),
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&refusal, Refusal::Survived { pids, .. } if *pids == vec![i32::try_from(pid).unwrap()]),
            "{refusal:?}"
        );
        assert!(
            dir.exists(),
            "a refused jail keeps its cgroup for inspection"
        );
        let _ = child.wait().await;
    }

    /// A namespace member counts too (a stranded dnsmasq lives in the netns, not the jail cgroup),
    /// and a namespace that cannot be read refuses rather than reads as empty.
    #[tokio::test]
    async fn namespace_members_are_killed_and_an_unreadable_namespace_refuses() {
        let id = Uuid::new_v4().to_string();
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id().unwrap()).unwrap();
        let net = std::sync::Arc::new(Net::default());
        net.members.lock().unwrap().push(pid);
        let kernel = {
            let net = net.clone();
            tokio::spawn(async move {
                let status = child.wait().await.unwrap();
                net.members.lock().unwrap().clear();
                status
            })
        };
        let done = reclaim_one(&id, None, &*net, Duration::from_secs(5))
            .await
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(kernel.await.unwrap().signal(), Some(9));
        assert_eq!(done.killed, 1);

        let blind = Net {
            unreadable: true,
            ..Net::default()
        };
        assert!(matches!(
            reclaim_one(&id, None, &blind, Duration::from_secs(1)).await,
            Err(Refusal::Unobservable { .. })
        ));
    }

    /// A jail whose VMM had already died is reclaimed with nothing killed, and listing reads only
    /// the jailer's own directory; a base that does not exist is first boot.
    #[tokio::test]
    async fn dead_stranded_pods_are_released_and_first_boot_is_empty() {
        let base = tempfile::tempdir().unwrap();
        let cgroups = tempfile::tempdir().unwrap();
        let fc = Path::new("/usr/local/bin/firecracker");
        let id = Uuid::new_v4().to_string();
        std::fs::create_dir_all(JailLayout::new(base.path(), fc, &id).jail_root).unwrap();
        std::fs::create_dir_all(base.path().join("not-firecracker").join("keep")).unwrap();
        let dir = stage_cgroup(cgroups.path(), &id, &[]);
        let net = Net::default();
        let done = reclaim_stranded_vms(base.path(), fc, cgroups.path(), true, &net)
            .await
            .unwrap();
        assert_eq!(done.len(), 1, "{done:?}");
        assert_eq!(done[0].jail_id, id);
        assert_eq!(done[0].killed, 0);
        only_fake_cgroup_residue(&done[0]);
        assert!(
            dir.exists(),
            "the stand-in is a plain directory, not cgroupfs"
        );
        let state = tempfile::tempdir().unwrap();
        let pod_dir = crate::lifecycle::pod_dir(state.path(), Uuid::parse_str(&id).unwrap());
        std::fs::create_dir_all(&pod_dir).unwrap();
        record(state.path(), &done).await;
        let log = std::fs::read_to_string(pod_dir.join("lifecycle.log")).unwrap();
        assert!(log.contains("\"pod_reclaimed\""), "{log}");
        let empty = tempfile::tempdir().unwrap();
        assert!(
            reclaim_stranded_vms(empty.path(), fc, cgroups.path(), true, &net)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
