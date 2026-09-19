//! A [`Substrate`] backed by local virtual machines, and a [`Forge`] that serves several
//! repositories from one pool.
//!
//! # Why this exists
//!
//! The Fly substrate assumes machines a paid API creates on demand. When that API is not
//! available — an unpaid account, an air-gapped box, a laptop — the planner is still exactly
//! right; only `create/start/destroy` change. So this is a second [`Substrate`] and nothing else
//! moves.
//!
//! # Why several repositories need JIT rather than an org runner
//!
//! A CONFIGURED runner is locked to the repository it was configured against, so serving two
//! repositories from one pool would normally mean an organization-level runner — which needs the
//! `admin:org` scope. A JIT registration is minted per job, so the pool is not configured against
//! anything: [`MultiForge`] mints against whichever repository queued the job. The label is what
//! says which, because a pool is per label and a label belongs to one repository.
//!
//! # Why the box's size is a refusal rather than a comment
//!
//! `POOLS` may declare more workers than a machine can run. On Fly that costs money; on one box
//! it costs correctness — five runners on eight cores oversubscribed a VM on 2026-09-18 and
//! fifty-one gate probes failed with "could not run the gate", which reads like a logic error and
//! is not one. [`Capacity::admits`] is the same shape as the volume check the Fly pools already
//! carry: a declaration the manager refuses rather than a number a reader has to notice.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::api::{Error, Forge, Registration, Run, Substrate};
use crate::{Job, Machine, Runner};

/// Running a command. Injected so the backend is testable on a box with no hypervisor, the way
/// [`crate::api::Transport`] makes the HTTP backends testable with no network.
pub trait Exec: Send + Sync {
    /// stdout on success; the program's stderr on failure.
    fn run(&self, program: &str, args: &[&str]) -> Result<String, Error>;
}

/// The real one: `std::process::Command`.
pub struct Process;

impl Exec for Process {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, Error> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| Error::Unreachable {
                path: format!("{program} {}", args.join(" ")),
                cause: e.to_string(),
            })?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(Error::Unreachable {
                path: format!("{program} {}", args.join(" ")),
                cause: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            })
        }
    }
}

/// Local VMs through a CLI that speaks clone/run/stop/delete — `tart` by default.
///
/// `tart` rather than `lima` on purpose: it exists for this, its images are distributed by
/// digest through an OCI registry, and an image with the toolchain already in it is the
/// difference between a cold Mathlib build and a warm one. The CLI name is a parameter so a
/// deployment can point at something else without touching the planner.
pub struct LocalVms<E: Exec> {
    exec: E,
    cli: String,
    /// The image a worker is cloned from, by digest where the CLI supports one.
    image: String,
}

impl<E: Exec> LocalVms<E> {
    pub fn new(exec: E, cli: &str, image: &str) -> Self {
        Self {
            exec,
            cli: cli.to_string(),
            image: image.to_string(),
        }
    }
}

impl<E: Exec> Substrate for LocalVms<E> {
    fn machines(&self) -> Result<Vec<Machine>, Error> {
        let out = self.exec.run(&self.cli, &["list", "--format", "json"])?;
        let rows: Vec<Value> = serde_json::from_str(&out).map_err(|_| Error::Malformed {
            path: format!("{} list", self.cli),
            field: "json",
        })?;
        Ok(rows
            .iter()
            .map(|r| {
                let name = r["Name"].as_str().unwrap_or_default().to_string();
                Machine {
                    // A local VM's name IS its identity: there is no separate handle to lose.
                    id: name.clone(),
                    name,
                    state: match r["Running"].as_bool() {
                        Some(true) => "started".to_string(),
                        _ => "stopped".to_string(),
                    },
                    config: json!({}),
                    events: Vec::new(),
                }
            })
            .collect())
    }

    /// Cloned, not booted. `region` is ignored — one box is one place — and kept in the signature
    /// because it is the [`Substrate`] contract, not this backend's business.
    fn create(&self, name: &str, _region: &str, _config: &Value) -> Result<Machine, Error> {
        self.exec.run(&self.cli, &["clone", &self.image, name])?;
        Ok(Machine {
            id: name.to_string(),
            name: name.to_string(),
            state: "stopped".to_string(),
            config: json!({}),
            events: Vec::new(),
        })
    }

    /// A local VM carries its configuration in its image, so there is nothing to rewrite. Saying
    /// so explicitly beats a silent `Ok`: the planner calls this before a first boot, and a
    /// backend that quietly did nothing when it was meant to would be a wrong machine that starts.
    fn update(&self, _id: &str, _config: &Value) -> Result<(), Error> {
        Ok(())
    }

    fn wait_for(&self, id: &str, state: &str, timeout_s: u64) -> Result<(), Error> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
        loop {
            if self
                .machines()?
                .iter()
                .any(|m| m.id == id && m.state == state)
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Unreachable {
                    path: format!("{} list ({id})", self.cli),
                    cause: format!("did not reach {state} in {timeout_s}s"),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    fn start(&self, id: &str) -> Result<(), Error> {
        self.exec.run(&self.cli, &["run", "--no-graphics", id])?;
        Ok(())
    }

    fn destroy(&self, id: &str) -> Result<(), Error> {
        self.exec.run(&self.cli, &["delete", id])?;
        Ok(())
    }
}

/// Several repositories behind one [`Forge`], routed by label.
///
/// A pool is per label and a label belongs to one repository, so the label is the routing key and
/// no new configuration is needed to say which repository a job came from.
pub struct MultiForge<F: Forge> {
    by_label: BTreeMap<String, F>,
}

impl<F: Forge> MultiForge<F> {
    pub fn new(by_label: BTreeMap<String, F>) -> Self {
        Self { by_label }
    }

    fn for_label(&self, label: &str) -> Result<&F, Error> {
        self.by_label.get(label).ok_or(Error::Malformed {
            path: String::from("pools"),
            field: "label",
        })
    }
}

impl<F: Forge> Forge for MultiForge<F> {
    /// Every repository's active runs. A failure in ONE repository is returned rather than
    /// swallowed: a pass that silently saw half the demand would under-provision and look healthy,
    /// which is the failure mode this whole manager is written against.
    fn active_runs(&self, limit: usize) -> Result<Vec<Run>, Error> {
        let mut all = Vec::new();
        for f in self.by_label.values() {
            all.extend(f.active_runs(limit)?);
        }
        Ok(all)
    }

    fn jobs(&self, run: u64) -> Result<Vec<Job>, Error> {
        // A run id is not unique across repositories, so every repository is asked and the
        // answers concatenated. A job that does not exist in a repository simply yields none.
        let mut all = Vec::new();
        for f in self.by_label.values() {
            all.extend(f.jobs(run)?);
        }
        Ok(all)
    }

    fn runners(&self) -> Result<Vec<Runner>, Error> {
        let mut all = Vec::new();
        for f in self.by_label.values() {
            all.extend(f.runners()?);
        }
        Ok(all)
    }

    fn register(&self, label: &str, name: &str) -> Result<Registration, Error> {
        self.for_label(label)?.register(label, name)
    }

    /// Runner ids are per repository, so removal is attempted against each until one accepts.
    /// Ugly, and the alternative is worse: carrying a side table of id→repository that can go
    /// stale between passes and delete the wrong runner.
    fn remove_runner(&self, id: u64) -> Result<(), Error> {
        let mut last = None;
        for f in self.by_label.values() {
            match f.remove_runner(id) {
                Ok(()) => return Ok(()),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or(Error::Malformed {
            path: String::from("repositories"),
            field: "repos",
        }))
    }
}

/// What one box can actually run at once.
///
/// The Fly pools already refuse a `requires_volume` pool whose size exceeds its volume count. On
/// a single box the equivalent is cores and memory, and the equivalent failure is worse: machines
/// that start and then cannot do their work. On 2026-09-18 five runners on an eight-core VM made
/// fifty-one gate probes report "could not run the gate", which reads like a logic error.
#[derive(Debug, Clone, Copy)]
pub struct Capacity {
    pub cores: usize,
    pub mem_mib: usize,
    /// Cores one worker needs to make progress rather than thrash.
    pub cores_per_worker: usize,
    /// Memory one worker needs.
    pub mem_mib_per_worker: usize,
}

impl Capacity {
    /// The most workers this box admits, by the scarcer of the two resources.
    #[must_use]
    pub fn max_workers(&self) -> usize {
        let by_cores = self.cores / self.cores_per_worker.max(1);
        let by_mem = self.mem_mib / self.mem_mib_per_worker.max(1);
        by_cores.min(by_mem)
    }

    /// `Ok` when the declared workers fit, and the reason when they do not. The reason names both
    /// numbers, because "too many" without them is what a reader cannot act on.
    ///
    /// # Errors
    /// When `declared` exceeds [`Capacity::max_workers`].
    pub fn admits(&self, declared: usize) -> Result<(), String> {
        let max = self.max_workers();
        if declared <= max {
            return Ok(());
        }
        Err(format!(
            "{declared} worker(s) declared and this box admits {max}: {} core(s) at {} per worker, \
             {} MiB at {} per worker. Lower the pool sizes or give the box more.",
            self.cores, self.cores_per_worker, self.mem_mib, self.mem_mib_per_worker
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records what was run and answers from a script, so the backend is exercised on a box with
    /// no hypervisor — the same reason `Transport` is injected for the HTTP backends.
    struct FakeExec {
        answers: Mutex<Vec<Result<String, Error>>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeExec {
        fn new(answers: Vec<Result<String, Error>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Exec for FakeExec {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            let mut a = self.answers.lock().unwrap();
            if a.is_empty() {
                Ok(String::new())
            } else {
                a.remove(0)
            }
        }
    }

    #[test]
    fn a_local_vm_is_cloned_stopped_and_its_name_is_its_identity() {
        let fake = FakeExec::new(vec![Ok(String::new())]);
        let vms = LocalVms::new(fake, "tart", "ghcr.io/example/runner@sha256:abc");
        let m = vms.create("worker-1", "ignored", &json!({})).unwrap();
        assert_eq!((m.id.as_str(), m.state.as_str()), ("worker-1", "stopped"));
        assert_eq!(
            vms.exec.calls.lock().unwrap()[0],
            "tart clone ghcr.io/example/runner@sha256:abc worker-1",
            "the image must be passed by digest, not by tag"
        );
    }

    #[test]
    fn listing_maps_running_to_started_because_the_planner_speaks_fly() {
        let fake = FakeExec::new(vec![Ok(
            r#"[{"Name":"w1","Running":true},{"Name":"w2","Running":false}]"#.to_string(),
        )]);
        let vms = LocalVms::new(fake, "tart", "img");
        let ms = vms.machines().unwrap();
        assert_eq!(
            ms.iter()
                .map(|m| (m.name.as_str(), m.state.as_str()))
                .collect::<Vec<_>>(),
            vec![("w1", "started"), ("w2", "stopped")]
        );
    }

    #[test]
    fn a_failing_command_is_unreachable_and_carries_the_stderr_not_the_stdout() {
        let fake = FakeExec::new(vec![Err(Error::Unreachable {
            path: "tart clone".into(),
            cause: "image not found".into(),
        })]);
        let vms = LocalVms::new(fake, "tart", "img");
        let e = vms.create("w", "r", &json!({})).unwrap_err();
        assert!(format!("{e}").contains("image not found"), "{e}");
    }

    /// **The refusal that tonight needed.** Five runners were put on an eight-core, 15 GiB VM and
    /// fifty-one gate probes reported "could not run the gate" — a resource failure wearing a
    /// logic failure's clothes.
    #[test]
    fn a_box_refuses_more_workers_than_it_can_run() {
        let box_ = Capacity {
            cores: 8,
            mem_mib: 15_000,
            cores_per_worker: 2,
            mem_mib_per_worker: 4_000,
        };
        // Memory is the scarcer of the two here: 8/2 = 4 by cores, 15000/4000 = 3 by memory.
        assert_eq!(box_.max_workers(), 3);
        assert!(box_.admits(3).is_ok());
        // Exactly one over the ceiling, which is the case that pins the comparison. Asking for
        // five is refused by a `<=` that is off by one as readily as by a correct one, so a suite
        // that only tries three and five cannot tell them apart; four can.
        assert!(
            box_.admits(4).is_err(),
            "one over the ceiling must be refused"
        );
        let why = box_.admits(5).unwrap_err();
        assert!(why.contains("5 worker(s) declared"), "{why}");
        assert!(why.contains("admits 3"), "{why}");
        // The reason must carry BOTH numbers, or a reader cannot tell which to change.
        assert!(
            why.contains("8 core(s)") && why.contains("15000 MiB"),
            "{why}"
        );
    }

    #[test]
    fn capacity_never_divides_by_zero() {
        let silly = Capacity {
            cores: 8,
            mem_mib: 16_000,
            cores_per_worker: 0,
            mem_mib_per_worker: 0,
        };
        // A zero per-worker ask is read as one, so the box is bounded by whichever dimension is
        // smaller rather than by a division that would panic: here the 8 cores, not the 16 000
        // MiB. Asserting the number itself and not `8.min(16_000)`, because restating the
        // implementation's own formula only repeats it back — and clippy folds it anyway, which
        // is how this was found.
        assert_eq!(silly.max_workers(), 8);
    }

    struct OneRepo {
        label: &'static str,
        runs: Vec<Run>,
        removed: Mutex<Vec<u64>>,
        remove_ok: bool,
    }

    impl Forge for OneRepo {
        fn active_runs(&self, _limit: usize) -> Result<Vec<Run>, Error> {
            Ok(self.runs.clone())
        }
        fn jobs(&self, _run: u64) -> Result<Vec<Job>, Error> {
            Ok(vec![Job {
                id: 1,
                status: "queued".into(),
                labels: vec![self.label.to_string()],
            }])
        }
        fn runners(&self) -> Result<Vec<Runner>, Error> {
            Ok(Vec::new())
        }
        fn register(&self, label: &str, name: &str) -> Result<Registration, Error> {
            Ok(Registration {
                id: 1,
                encoded: format!("{}|{label}|{name}", self.label),
            })
        }
        fn remove_runner(&self, id: u64) -> Result<(), Error> {
            self.removed.lock().unwrap().push(id);
            if self.remove_ok {
                Ok(())
            } else {
                Err(Error::Malformed {
                    path: "runners".into(),
                    field: "id",
                })
            }
        }
    }

    fn one(label: &'static str, run_id: u64, remove_ok: bool) -> OneRepo {
        OneRepo {
            label,
            runs: vec![Run {
                id: run_id,
                created_at: String::new(),
            }],
            removed: Mutex::new(Vec::new()),
            remove_ok,
        }
    }

    #[test]
    fn demand_is_read_from_every_repository_and_registration_is_routed_by_label() {
        let mut m = BTreeMap::new();
        m.insert("gatehouse-assure".to_string(), one("gatehouse", 10, true));
        m.insert("olog-ci".to_string(), one("olog", 20, true));
        let forge = MultiForge::new(m);

        let ids: Vec<u64> = forge.active_runs(5).unwrap().iter().map(|r| r.id).collect();
        assert_eq!(
            ids,
            vec![10, 20],
            "a pass must see BOTH repositories' demand"
        );

        // The label is the routing key, which is why no extra configuration is needed.
        let r = forge.register("olog-ci", "w-1").unwrap();
        assert_eq!(r.encoded, "olog|olog-ci|w-1");
    }

    #[test]
    fn a_label_no_repository_claims_is_refused_rather_than_guessed() {
        let mut m = BTreeMap::new();
        m.insert("gatehouse-assure".to_string(), one("gatehouse", 10, true));
        let forge = MultiForge::new(m);
        assert!(
            forge.register("typo-ci", "w-1").is_err(),
            "registering against an arbitrary repository would put a worker where no job is"
        );
    }

    #[test]
    fn removal_tries_each_repository_because_runner_ids_are_per_repository() {
        let mut m = BTreeMap::new();
        m.insert("a".to_string(), one("a", 1, false));
        m.insert("b".to_string(), one("b", 2, true));
        let forge = MultiForge::new(m);
        assert!(
            forge.remove_runner(7).is_ok(),
            "the second repository owns it"
        );
    }
}
