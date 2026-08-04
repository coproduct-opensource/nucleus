//! Completeness by 2-safety: boot twice, differ only in a secret, compare.
//!
//! # Why this exists, and why it is not another leak scan
//!
//! A security property is an uninhabitedness claim, and it splits in two.
//! *Soundness* — every mechanism in the flow model has an implementation — is
//! greppable, lintable, and increasingly type-level. *Completeness* — every
//! mechanism that moves information appears IN the model — is not reachable by
//! any static analysis, because the whole problem is that nobody wrote the edge
//! down. That is what missed `execve`'s environment inheritance, and an
//! unchowned socket, and a leak-site dump that could not run.
//!
//! Noninterference is not a property. It is a **2-safety hyperproperty**: any
//! two executions agreeing on low inputs must agree on low outputs. Such a
//! property reduces to a safety property of the self-composition — run the
//! system twice and compare. So this module stops enumerating mechanisms and
//! compares two executions instead. **A channel nobody thought of shows up as a
//! difference.**
//!
//! Completeness stops being an unbounded list and becomes a property of one
//! object: the observation function below.
//!
//! # The honest bound, stated here rather than in a footnote
//!
//! This is complete **relative to what [`Observation`] captures**. seL4's
//! information-flow proof — the strongest result of this kind — records the same
//! shape of limitation: its machine model does not model time, so it says little
//! about covert timing channels. Anything outside the observation (timing, cache
//! residency, power) is outside this too.
//!
//! That is still a large advance on a mechanism list, because the bound is ONE
//! reviewable object rather than an open-ended enumeration nobody maintains.

use std::fmt;

/// Everything the host holds that the guest could have influenced or seen.
///
/// Deliberately a struct of named components rather than one opaque blob: a
/// divergence must be attributable to a component, and a component that stops
/// being collected should be visible as a field, not as a silently shorter
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The Firecracker machine configuration as serialised for this pod —
    /// devices, drives, vsock, and the kernel command line. `sandbox-trusted-base.txt`
    /// already pins this surface (`firecracker_device_surface_is_exactly_pinned`).
    pub machine_config: String,
    /// The guest console, i.e. what the guest actually emitted.
    pub console: String,
}

/// An [`Observation`] with run-to-run nondeterminism normalised away.
///
/// A distinct type from `Observation` on purpose: comparing two raw observations
/// is always a false positive, and comparing a raw against a canonical one is a
/// mistake the type system can prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    machine_config: String,
    console: String,
}

/// Structural facts about a run that differ between boots and carry no secret.
///
/// Passed in rather than discovered, so the canonicaliser erases only what a
/// caller has explicitly declared to be run-scoped.
#[derive(Debug, Clone)]
pub struct RunFacts {
    /// The pod's UUID. Minted before any secret is read, so it cannot encode one.
    pub pod_id: String,
    /// The guest CID. Allocated from a counter, not derived from pod content.
    pub guest_cid: u32,
}

/// Where two runs disagreed. Carries the component and a bounded excerpt of the
/// FIRST differing line — never the whole content, and never a value the caller
/// supplied as secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// Which component of the observation differed.
    pub component: &'static str,
    /// The first differing line number within that component.
    pub line: usize,
    /// A bounded excerpt, for locating the difference in a log.
    pub excerpt: String,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "two runs differing only in a secret produced different {} at line {}: {}",
            self.component, self.line, self.excerpt
        )
    }
}

/// How much of a differing line to report.
const EXCERPT_BYTES: usize = 120;

/// Normalise run-to-run nondeterminism.
///
/// # The signature is the security property
///
/// **This does not take the secret.** It cannot, and that is deliberate: a
/// canonicaliser with access to the secret could erase exactly the bytes that
/// would have revealed a leak, and no test of its output would notice. Every
/// erasure here is therefore blind — it removes a syntactic class, not a value.
///
/// This is the same construction as `store_from_node_environment` not taking a
/// `PodSpec`: the guarantee is that a function cannot reach what it cannot name.
///
/// # Every rule is an erasure, so every rule needs a reason
///
/// Anything normalised away is something this harness can no longer see. A
/// canonicaliser that erased enough would make the whole comparison pass
/// vacuously — which is why `a_planted_secret_survives_canonicalisation` exists
/// and runs on every execution.
///
/// The rules, each with why the erased field cannot carry a secret:
///
/// * **pod UUID** — minted by the node before any secret is read.
/// * **guest CID** — allocated from a counter; `lowering_preserves_distinct_cids`
///   pins that it is a function of allocation order, not pod content.
/// * **leading log timestamps** — wall clock. NOT a blanket timestamp strip:
///   only a leading `[...]` or ISO-8601 prefix, so a secret that happened to
///   contain digits is untouched.
/// * **socket paths under the pod dir** — contain the pod UUID, already covered.
///
/// Nothing else is erased. In particular the kernel command line is compared in
/// full, because it is where `nucleus.auth_secret` already rides and is the most
/// likely place for a real leak.
#[must_use]
pub fn canonicalise(obs: &Observation, facts: &RunFacts) -> Canonical {
    Canonical {
        machine_config: scrub(&obs.machine_config, facts),
        console: scrub(&obs.console, facts),
    }
}

fn scrub(s: &str, facts: &RunFacts) -> String {
    s.lines()
        .map(|line| {
            let line = strip_leading_timestamp(line);
            // The pod UUID is long and structurally unique, so a plain
            // replacement is safe.
            let line = line.replace(&facts.pod_id, "<POD-ID>");
            // The CID is a SMALL INTEGER, so replacing it bare would corrupt any
            // text that happens to contain that digit — including a secret. It
            // is erased only in the structural position it occupies.
            // `a_secret_containing_the_cid_digit_survives` pins this; the first
            // version replaced the bare digit and would have gone blind to any
            // secret containing it.
            line.replace(
                &format!("\"guest_cid\":{}", facts.guest_cid),
                "\"guest_cid\":<CID>",
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove only a LEADING timestamp, in the two forms this runtime emits.
///
/// Narrow on purpose. A blanket "strip anything that looks like a number" would
/// erase parts of a leaked secret, and the harness would go quiet exactly when
/// it mattered.
fn strip_leading_timestamp(line: &str) -> &str {
    // `[   1.234567] ...` — the kernel's printk clock.
    if let Some(rest) = line.strip_prefix('[') {
        if let Some((clock, tail)) = rest.split_once(']') {
            if !clock.is_empty()
                && clock
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == ' ')
            {
                return tail.trim_start();
            }
        }
    }
    // `2026-08-03T12:34:56.789Z ...` — the node's structured logs.
    let b = line.as_bytes();
    if b.len() > 20 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' {
        if let Some(sp) = line.find(' ') {
            return line[sp + 1..].trim_start();
        }
    }
    line
}

/// Compare two canonical observations from runs differing only in a secret.
///
/// # Errors
/// The first component and line at which they disagree.
pub fn compare(a: &Canonical, b: &Canonical) -> Result<(), Divergence> {
    for (component, x, y) in [
        ("machine_config", &a.machine_config, &b.machine_config),
        ("console", &a.console, &b.console),
    ] {
        if let Some(d) = first_difference(component, x, y) {
            return Err(d);
        }
    }
    Ok(())
}

fn first_difference(component: &'static str, x: &str, y: &str) -> Option<Divergence> {
    let (mut xl, mut yl) = (x.lines(), y.lines());
    let mut n = 0usize;
    loop {
        n += 1;
        match (xl.next(), yl.next()) {
            (None, None) => return None,
            (a, b) if a == b => continue,
            (a, b) => {
                let shown = a.or(b).unwrap_or("<absent>");
                let mut excerpt: String = shown.chars().take(EXCERPT_BYTES).collect();
                if shown.len() > excerpt.len() {
                    excerpt.push('…');
                }
                return Some(Divergence {
                    component,
                    line: n,
                    excerpt,
                });
            }
        }
    }
}

/// Read an [`Observation`] off a pod the host has already run.
///
/// # The two components, and where they come from
///
/// * `config.json` inside the jail — the machine configuration Firecracker was
///   launched with (`--config-file`, see `firecracker_config.rs`). It carries the
///   kernel command line, the drives, and the vsock device: everything the guest
///   is handed at boot.
/// * `firecracker.log` under the pod's state directory — what the guest actually
///   emitted, which is the channel `check_guest_facts` already reads.
///
/// # A missing component is an ERROR, never an empty string
///
/// An observation that silently defaulted to `""` would compare equal to another
/// empty one, and two failed boots would report "no divergence" — the
/// absence-satisfied-by-silence shape that has produced four separate defects in
/// this repo. If a component cannot be read, this fails and says which.
///
/// # Errors
/// If either component is missing or unreadable.
pub fn collect(
    config_path: &std::path::Path,
    console_path: &std::path::Path,
) -> std::io::Result<Observation> {
    let read = |p: &std::path::Path, what: &str| -> std::io::Result<String> {
        let body = std::fs::read_to_string(p).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("cannot read the {what} at {}: {e}", p.display()),
            )
        })?;
        if body.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the {what} at {} is empty; an empty observation compares equal to \
                     another empty one, so two failed boots would report no divergence",
                    p.display()
                ),
            ));
        }
        Ok(body)
    };
    Ok(Observation {
        machine_config: read(config_path, "machine config")?,
        console: read(console_path, "guest console")?,
    })
}

/// What one boot leaves behind for collection.
pub struct RunArtifacts {
    /// Path to the machine configuration Firecracker was launched with.
    pub config: std::path::PathBuf,
    /// Path to the guest console log.
    pub console: std::path::PathBuf,
    /// The run-scoped facts to canonicalise against.
    pub facts: RunFacts,
}

/// Why a 2-safety check failed.
#[derive(Debug)]
pub enum TwoSafetyError {
    /// A boot or collection failed. Distinguished from a divergence because
    /// "the experiment did not run" and "the experiment found a leak" are
    /// different answers and only one is about the system.
    Harness(String),
    /// Two runs differing only in a secret produced different observations.
    Leak(Divergence),
    /// The positive control did NOT find a planted secret, so the comparison is
    /// blind and every passing result above it is meaningless.
    ControlDidNotFire,
}

impl fmt::Display for TwoSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TwoSafetyError::Harness(m) => write!(f, "the 2-safety harness could not run: {m}"),
            TwoSafetyError::Leak(d) => write!(f, "{d}"),
            TwoSafetyError::ControlDidNotFire => write!(
                f,
                "the positive control did not fire: a secret planted directly in the kernel \
                 command line was NOT detected. The comparison is blind, so a clean result \
                 from it means nothing."
            ),
        }
    }
}

/// Boot once with the given secret and hand back what it left.
///
/// Injected rather than called directly so the orchestration below is testable
/// without `/dev/kvm` — the same reason `handle_perform` takes its upstream
/// caller. Only the actual boot is CI-only; the logic is not.
pub trait Boot {
    /// Run a pod whose node environment carries `secret`, optionally planting it
    /// into the kernel command line.
    ///
    /// # Errors
    /// If the pod could not be booted or its artifacts are unavailable.
    fn boot(&mut self, secret: &str, plant_in_cmdline: bool) -> std::io::Result<RunArtifacts>;
}

fn observe(b: &mut dyn Boot, secret: &str, plant: bool) -> Result<Canonical, TwoSafetyError> {
    let a = b
        .boot(secret, plant)
        .map_err(|e| TwoSafetyError::Harness(e.to_string()))?;
    let obs = collect(&a.config, &a.console).map_err(|e| TwoSafetyError::Harness(e.to_string()))?;
    Ok(canonicalise(&obs, &a.facts))
}

/// **The positive control, and it runs FIRST.**
///
/// Plants the secret directly into the kernel command line — `image.boot_args`,
/// which is host-consumed by `firecracker_config.rs` and reaches `/proc/cmdline`
/// — and requires the comparison to find it.
///
/// Without this, a canonicaliser that erased too much, an observation that
/// collected the wrong files, or a comparison with an inverted condition would
/// all report "no leak" forever. Running it first means a blind harness is
/// reported as blind rather than as clean.
///
/// # Errors
/// [`TwoSafetyError::ControlDidNotFire`] if the planted secret is not detected.
pub fn control(b: &mut dyn Boot) -> Result<(), TwoSafetyError> {
    let a = observe(b, "twosafety-control-aaaaaaaa", true)?;
    let c = observe(b, "twosafety-control-bbbbbbbb", true)?;
    match compare(&a, &c) {
        Err(_) => Ok(()),
        Ok(()) => Err(TwoSafetyError::ControlDidNotFire),
    }
}

/// The check itself: two runs differing only in a secret must be indistinguishable.
///
/// Enumerates no mechanisms. A channel nobody wrote down shows up as a
/// difference, which is the whole reason this is a hyperproperty test and not
/// another leak scan.
///
/// # Errors
/// [`TwoSafetyError::Leak`] with the differing component, or `Harness` if a boot
/// or collection failed.
pub fn check(b: &mut dyn Boot) -> Result<(), TwoSafetyError> {
    let a = observe(b, "twosafety-secret-aaaaaaaa", false)?;
    let c = observe(b, "twosafety-secret-bbbbbbbb", false)?;
    compare(&a, &c).map_err(TwoSafetyError::Leak)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: &str = "nucleus-e2e-canary-aaaaaaaaaaaa";
    const SECRET_B: &str = "nucleus-e2e-canary-bbbbbbbbbbbb";

    fn facts() -> RunFacts {
        RunFacts {
            pod_id: "11111111-2222-3333-4444-555555555555".into(),
            guest_cid: 3,
        }
    }

    fn other_facts() -> RunFacts {
        RunFacts {
            pod_id: "99999999-8888-7777-6666-555555555555".into(),
            guest_cid: 4,
        }
    }

    /// The machine config must reflect the RunFacts it will be canonicalised
    /// against — a fixture whose cid disagrees with its facts makes every
    /// comparison diverge for a reason that has nothing to do with the secret.
    /// The control test caught exactly that.
    fn obs_for(f: &RunFacts, cmdline: &str, console: &str) -> Observation {
        Observation {
            machine_config: format!(
                "{{\"boot_args\":\"{cmdline}\",\"vsock\":{{\"guest_cid\":{}}}}}",
                f.guest_cid
            ),
            console: console.into(),
        }
    }

    /// **The control, and it must come first.** Everything below asserts a
    /// divergence IS found; a comparator that reported one unconditionally would
    /// satisfy all of them while being useless.
    #[test]
    fn two_clean_runs_compare_equal() {
        let a = canonicalise(
            &obs_for(
                &facts(),
                "console=ttyS0",
                "[    0.100000] boot\n[    1.200000] ready",
            ),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(
                &other_facts(),
                "console=ttyS0",
                "[    0.999999] boot\n[    2.500000] ready",
            ),
            &other_facts(),
        );
        assert_eq!(compare(&a, &b), Ok(()), "only nondeterminism differed");
    }

    /// **The property.** A secret reaching the kernel command line — where
    /// `nucleus.auth_secret` already rides — must surface as a divergence, with
    /// no enumeration of mechanisms anywhere in this module.
    #[test]
    fn a_secret_in_the_kernel_cmdline_is_caught() {
        let a = canonicalise(
            &obs_for(&facts(), &format!("console=ttyS0 x={SECRET_A}"), "boot"),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(
                &other_facts(),
                &format!("console=ttyS0 x={SECRET_B}"),
                "boot",
            ),
            &other_facts(),
        );
        let d = compare(&a, &b).expect_err("the secret differs between runs");
        assert_eq!(d.component, "machine_config");
    }

    /// A secret reaching the guest console is caught too — the channel is not
    /// named anywhere, only the observation is.
    #[test]
    fn a_secret_on_the_console_is_caught() {
        let a = canonicalise(
            &obs_for(&facts(), "console=ttyS0", &format!("leaked {SECRET_A}")),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(
                &other_facts(),
                "console=ttyS0",
                &format!("leaked {SECRET_B}"),
            ),
            &other_facts(),
        );
        let d = compare(&a, &b).expect_err("the secret differs");
        assert_eq!(d.component, "console");
    }

    /// **NON-VACUITY OF THE CANONICALISER — the one this design can die on.**
    ///
    /// Every rule in `canonicalise` is an erasure, so a canonicaliser that
    /// normalised too much would make every comparison pass. This asserts a
    /// planted secret SURVIVES canonicalisation, in each component.
    #[test]
    fn a_planted_secret_survives_canonicalisation() {
        let c = canonicalise(
            &obs_for(
                &facts(),
                &format!("console=ttyS0 x={SECRET_A}"),
                &format!("s={SECRET_A}"),
            ),
            &facts(),
        );
        assert!(
            c.machine_config.contains(SECRET_A),
            "canonicalisation erased the secret from the machine config; the harness \
             would now be blind to a real leak there"
        );
        assert!(
            c.console.contains(SECRET_A),
            "canonicalisation erased the secret from the console"
        );
    }

    /// **A secret containing the CID digit must survive.**
    ///
    /// The first canonicaliser replaced `guest_cid.to_string()` — a bare "3" —
    /// everywhere, so a secret containing a 3 would have been partially erased
    /// and the harness would have gone quiet about a real leak. The erasure is
    /// context-bound now, and this is what holds it there.
    #[test]
    fn a_secret_containing_the_cid_digit_survives() {
        let f = facts(); // guest_cid = 3
        let secret = "canary-3333-with-threes";
        let c = canonicalise(&obs_for(&f, &format!("x={secret}"), secret), &f);
        assert!(
            c.machine_config.contains(secret) && c.console.contains(secret),
            "erasing the bare CID digit corrupted a secret containing it: {} / {}",
            c.machine_config,
            c.console
        );
        assert!(
            c.machine_config.contains("\"guest_cid\":<CID>"),
            "and the structural CID must still be normalised"
        );
    }

    /// The canonicaliser CANNOT target the secret, because it never receives it.
    ///
    /// Checked against the signature rather than the behaviour: a behavioural
    /// test passes for as long as nobody adds the parameter and says nothing the
    /// moment somebody does.
    #[test]
    fn the_canonicaliser_cannot_name_the_secret() {
        let src = include_str!("twosafety.rs");
        let sig = src
            .split("pub fn canonicalise(")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .expect("canonicalise signature");
        assert!(
            !sig.contains("secret") && !sig.contains("canary"),
            "canonicalise can now name the secret, so it could erase exactly the bytes \
             that would reveal a leak: {sig}"
        );
    }

    /// A timestamp difference alone is not a leak. Narrow stripping, so a secret
    /// containing digits is untouched.
    #[test]
    fn timestamps_are_stripped_but_digits_inside_a_secret_are_not() {
        assert_eq!(strip_leading_timestamp("[    1.234567] hello"), "hello");
        assert_eq!(
            strip_leading_timestamp("2026-08-03T12:34:56.789Z hello"),
            "hello"
        );
        // Not a timestamp: left alone in full.
        assert_eq!(strip_leading_timestamp("x=12345 hello"), "x=12345 hello");
        assert_eq!(
            strip_leading_timestamp("[not-a-clock] hello"),
            "[not-a-clock] hello"
        );
    }

    /// A truncated run must not compare equal to a complete one — otherwise a
    /// crashed boot passes.
    #[test]
    fn a_truncated_run_is_a_divergence() {
        let a = canonicalise(
            &obs_for(&facts(), "console=ttyS0", "boot\nready\ndone"),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(&other_facts(), "console=ttyS0", "boot\nready"),
            &other_facts(),
        );
        assert!(compare(&a, &b).is_err(), "a short run is not a clean run");
    }

    /// The report names the section and does not print the secret.
    #[test]
    fn a_divergence_report_locates_without_disclosing() {
        let long = format!("{SECRET_A}{}", "z".repeat(400));
        let a = canonicalise(&obs_for(&facts(), "console=ttyS0", &long), &facts());
        let b = canonicalise(
            &obs_for(&other_facts(), "console=ttyS0", "clean"),
            &other_facts(),
        );
        let d = compare(&a, &b).expect_err("differs");
        assert!(d.excerpt.chars().count() <= EXCERPT_BYTES + 1, "bounded");
        assert!(format!("{d}").contains("console"), "names the component");
    }
}

#[cfg(test)]
mod collection {
    use super::*;

    fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("write fixture");
        p
    }

    /// The control: a complete pair reads back exactly.
    #[test]
    fn a_complete_pair_is_collected() {
        let d = tempfile::tempdir().expect("tempdir");
        let c = write(d.path(), "config.json", "{\"boot_args\":\"console=ttyS0\"}");
        let l = write(d.path(), "firecracker.log", "[    0.1] boot");
        let o = collect(&c, &l).expect("both present");
        assert!(o.machine_config.contains("boot_args"));
        assert!(o.console.contains("boot"));
    }

    /// **A missing component must fail, not default to empty.** Two failed boots
    /// both yielding `""` would compare equal and report no divergence — which is
    /// the failure shape this whole harness exists to avoid.
    #[test]
    fn a_missing_component_is_an_error() {
        let d = tempfile::tempdir().expect("tempdir");
        let l = write(d.path(), "firecracker.log", "boot");
        let err = collect(&d.path().join("absent.json"), &l).expect_err("no config");
        assert!(
            format!("{err}").contains("machine config"),
            "names which: {err}"
        );
    }

    /// An EMPTY component is the same hazard wearing a different hat: the file
    /// exists, so a naive read succeeds, and the comparison goes quiet.
    #[test]
    fn an_empty_component_is_an_error() {
        let d = tempfile::tempdir().expect("tempdir");
        let c = write(d.path(), "config.json", "   \n");
        let l = write(d.path(), "firecracker.log", "boot");
        let err = collect(&c, &l).expect_err("empty config");
        assert!(
            format!("{err}").contains("no divergence"),
            "says why: {err}"
        );
    }

    /// End to end on fixtures: two runs differing only in a planted secret are
    /// collected, canonicalised, and the divergence is found. This is S4's
    /// positive control at the file level — the booted-pod version lands with
    /// the harness.
    #[test]
    fn a_planted_secret_is_found_end_to_end() {
        let d = tempfile::tempdir().expect("tempdir");
        let mk = |n: &str, secret: &str, cid: u32| {
            let c = write(
                d.path(),
                &format!("config{n}.json"),
                &format!("{{\"boot_args\":\"console=ttyS0 nucleus.x={secret}\",\"vsock\":{{\"guest_cid\":{cid}}}}}"),
            );
            let l = write(d.path(), &format!("log{n}.log"), "[    0.1] boot");
            (c, l)
        };
        let (ca, la) = mk("a", "secret-aaaa", 3);
        let (cb, lb) = mk("b", "secret-bbbb", 4);
        let fa = RunFacts {
            pod_id: "aaaaaaaa-0000-0000-0000-000000000000".into(),
            guest_cid: 3,
        };
        let fb = RunFacts {
            pod_id: "bbbbbbbb-0000-0000-0000-000000000000".into(),
            guest_cid: 4,
        };
        let a = canonicalise(&collect(&ca, &la).expect("a"), &fa);
        let b = canonicalise(&collect(&cb, &lb).expect("b"), &fb);
        let dv = compare(&a, &b).expect_err("the planted secret differs");
        assert_eq!(dv.component, "machine_config");
    }
}

#[cfg(test)]
mod orchestration {
    use super::*;
    use std::io;

    /// A booter backed by fixtures. `leak` decides whether the secret reaches
    /// the console — i.e. whether the system under test is broken.
    struct Fake {
        dir: tempfile::TempDir,
        n: u32,
        leak: bool,
        honour_plant: bool,
    }

    impl Fake {
        fn new(leak: bool, honour_plant: bool) -> Self {
            Fake {
                dir: tempfile::tempdir().expect("tempdir"),
                n: 0,
                leak,
                honour_plant,
            }
        }
    }

    impl Boot for Fake {
        fn boot(&mut self, secret: &str, plant: bool) -> io::Result<RunArtifacts> {
            self.n += 1;
            let cid = 2 + self.n;
            let cmd = if plant && self.honour_plant {
                format!("console=ttyS0 nucleus.x={secret}")
            } else {
                "console=ttyS0".to_string()
            };
            let config = self.dir.path().join(format!("c{}.json", self.n));
            std::fs::write(
                &config,
                format!("{{\"boot_args\":\"{cmd}\",\"vsock\":{{\"guest_cid\":{cid}}}}}"),
            )?;
            let console = self.dir.path().join(format!("l{}.log", self.n));
            let body = if self.leak {
                format!("[    0.1] boot\n[    0.2] cred={secret}")
            } else {
                format!("[    0.{}] boot\n[    0.2] ready", self.n)
            };
            std::fs::write(&console, body)?;
            Ok(RunArtifacts {
                config,
                console,
                facts: RunFacts {
                    pod_id: format!("{:08}-0000-0000-0000-000000000000", self.n),
                    guest_cid: cid,
                },
            })
        }
    }

    /// **The control, first.** A sound system passes the check.
    #[test]
    fn a_system_that_does_not_leak_passes() {
        let mut b = Fake::new(false, true);
        assert!(check(&mut b).is_ok());
    }

    /// A system that puts the secret on the console fails, with no mechanism
    /// named anywhere in this module.
    #[test]
    fn a_leak_to_the_console_is_caught() {
        let mut b = Fake::new(true, true);
        match check(&mut b) {
            Err(TwoSafetyError::Leak(d)) => assert_eq!(d.component, "console"),
            other => panic!("expected a Leak, got {other:?}"),
        }
    }

    /// The positive control fires when the plant works.
    #[test]
    fn the_control_fires_on_a_planted_secret() {
        let mut b = Fake::new(false, true);
        assert!(control(&mut b).is_ok(), "a planted secret must be detected");
    }

    /// **The meta-check, and the reason `control` exists at all.** If planting is
    /// broken, the control must report BLINDNESS rather than passing — otherwise
    /// a harness that sees nothing looks exactly like a system that leaks
    /// nothing.
    #[test]
    fn a_broken_plant_is_reported_as_blindness_not_as_clean() {
        let mut b = Fake::new(false, /* honour_plant */ false);
        match control(&mut b) {
            Err(TwoSafetyError::ControlDidNotFire) => {}
            other => panic!("a blind harness must not look clean, got {other:?}"),
        }
    }

    /// A boot failure is a HARNESS error, not a clean result. "The experiment did
    /// not run" and "the experiment found nothing" are different answers.
    #[test]
    fn a_failed_boot_is_not_a_pass() {
        struct Broken;
        impl Boot for Broken {
            fn boot(&mut self, _: &str, _: bool) -> io::Result<RunArtifacts> {
                Err(io::Error::other("no /dev/kvm"))
            }
        }
        match check(&mut Broken) {
            Err(TwoSafetyError::Harness(m)) => assert!(m.contains("kvm")),
            other => panic!("expected Harness, got {other:?}"),
        }
    }
}
