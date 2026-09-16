//! `nucleus-perf stress` — nucleus stressed as an IFC-enforcing web server, every
//! mode with an oracle.
//!
//! # `--mode linearize`
//!
//! A real `nucleus-tool-proxy` is spawned under a compiled, sealed grant
//! (`agency::spawn_local_under_grant`, the path `nucleus run --local` uses) over a
//! small fixed workspace. `--clients` threads send random calls from a closed
//! vocabulary; every call's invocation and return instants and its normalised
//! result are recorded; the history must be **linearizable** against
//! [`model::Session`] — some sequential order of the calls must explain every
//! result.
//!
//! With `--clients 1` the history is sequential, so a failure there is the MODEL
//! disagreeing with the proxy, not a race: that run calibrates the model. With more
//! clients, a failure is a concurrent history no sequential order explains.
//!
//! # Exit status
//!
//! `0` held; `1` violated; `2` could not look (the proxy did not start, a window
//! was too large to search, or nothing was exercised).

pub mod hyper;
pub mod linearize;
pub mod mock_web;
pub mod model;

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};

use linearize::{Call, Verdict};
use model::{File, Op, Out, Session};

#[derive(clap::Parser)]
pub struct Args {
    /// Concurrent clients. `1` calibrates the model against a sequential history.
    #[arg(long, default_value = "1")]
    pub clients: usize,
    /// Calls per client.
    #[arg(long, default_value = "40")]
    pub ops: usize,
    #[arg(long, default_value = "1")]
    pub seed: u64,
    /// Goal the grant is compiled from.
    #[arg(long, default_value = "fix the failing tests")]
    pub goal: String,
    #[arg(long, default_value = "codegen")]
    pub ceiling: String,
    /// Path to the tool-proxy binary.
    #[arg(long, default_value = "nucleus-tool-proxy")]
    pub proxy_bin: String,
    /// What the proxy runs under. `grant`: a compiled, sealed grant (no taint
    /// source reachable). `trifecta`: `research-web` plus writes — private data,
    /// untrusted content AND an exfiltration vector in one session, fetching from a
    /// local server, which is where information flow control has to decide.
    #[arg(long, value_enum, default_value = "grant")]
    pub policy: Policy,
    /// `linearize`: concurrent calls against a model. `hyper`: noninterference —
    /// the same program twice with different private file contents, compared by
    /// what the network and the verdict stream saw.
    #[arg(long, value_enum, default_value = "linearize")]
    pub mode: Mode,
    /// `--mode hyper` only: which input is high. `web`: the untrusted page body
    /// (integrity). `files`: workspace file contents (confidentiality).
    #[arg(long, value_enum, default_value = "web")]
    pub high: hyper::High,
    /// `--mode hyper` only: how many programs, from consecutive seeds.
    #[arg(long, default_value_t = 20)]
    pub trials: u64,
    /// `--mode hyper` only: whether the pod declares the local web server as an
    /// egress host (`declared`) or declares none (`open`).
    #[arg(long, value_enum, default_value = "declared")]
    pub hosts: hyper::Hosts,
    /// On a violation, write every call of the history here (one line each:
    /// invoke, return, op, status, code) so the counterexample can be analysed —
    /// a concurrent failure does not reproduce on demand.
    #[arg(long)]
    pub history: Option<std::path::PathBuf>,
    /// Print every call and its result.
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    Linearize,
    Hyper,
}

/// `research-web` plus writing and editing: private data, untrusted content and an
/// exfiltration vector in one session.
pub(crate) fn trifecta_lattice() -> Result<portcullis::PermissionLattice> {
    let mut lattice = portcullis::profile::ProfileRegistry::default()
        .resolve("research-web")
        .context("the research-web profile")?;
    lattice.capabilities.write_files = portcullis::CapabilityLevel::Always;
    lattice.capabilities.edit_files = portcullis::CapabilityLevel::Always;
    Ok(lattice)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum Policy {
    Grant,
    Trifecta,
}

/// A tiny deterministic generator (xorshift64*): reproducible from `--seed`, and no
/// dependency for four random choices.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) % n.max(1)
    }
}

fn random_op(rng: &mut Rng, fetch: bool) -> Op {
    if fetch && rng.below(8) == 0 {
        return Op::Fetch;
    }
    let file = |r: &mut Rng| match r.below(3) {
        0 => File::A,
        1 => File::B,
        _ => File::Key,
    };
    match rng.below(10) {
        0..=3 => Op::Read(file(rng)),
        4..=6 => Op::Write(
            if rng.below(2) == 0 { File::A } else { File::B },
            u8::try_from(rng.below(4)).unwrap_or(0),
        ),
        7 => Op::Glob,
        _ => Op::Run,
    }
}

/// The request an op is sent as; `None` for a model-only event, never sent.
fn request(op: &Op) -> Option<(&'static str, serde_json::Value)> {
    Some(match op {
        Op::Read(f) => ("read", serde_json::json!({"path": f.path()})),
        Op::Write(f, v) => (
            "write",
            serde_json::json!({"path": f.path(), "contents": model::contents(*v)}),
        ),
        Op::Glob => ("glob", serde_json::json!({"pattern": "*.txt"})),
        Op::Fetch => (
            "web_fetch",
            serde_json::json!({"url": format!("http://{}/page", model::mock_addr())}),
        ),
        Op::Delivered => return None,
        Op::Run => (
            "run",
            serde_json::json!({"args": ["echo", "nucleus-stress"]}),
        ),
    })
}

/// Why the proxy refused, from its reply body: `kind`, qualified by `deny_code` for
/// a kernel decision. Two refusals for different reasons are different results.
pub(crate) fn refusal_code(v: &serde_json::Value) -> Option<String> {
    let error = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
    // Before #2945 the denial circuit breaker's lockdown was reported as `400
    // body_error` ("request body error: LOCKDOWN ACTIVE ..."); classified by its
    // message so the model can name it on either proxy.
    if error.contains("LOCKDOWN ACTIVE") {
        return Some("lockdown".to_owned());
    }
    match (
        v.get("kind").and_then(|c| c.as_str()),
        v.get("deny_code").and_then(|c| c.as_str()),
    ) {
        (Some(kind), Some(deny)) => Some(format!("{kind}/{deny}")),
        (Some(kind), None) => Some(kind.to_owned()),
        (None, _) => None,
    }
}

fn normalise(op: &Op, status: u16, body: &str) -> Out {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    let code = refusal_code(&v);
    let contents = match op {
        Op::Read(_) if (200..300).contains(&status) => v
            .get("contents")
            .and_then(|c| c.as_str())
            .map(str::to_owned),
        Op::Read(_) | Op::Write(..) | Op::Glob | Op::Run | Op::Fetch | Op::Delivered => None,
    };
    Out {
        status,
        code,
        contents,
    }
}

fn workspace() -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("nucleus-stress-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".ssh"))?;
    std::fs::write(dir.join(File::A.path()), model::INITIAL_A)?;
    std::fs::write(dir.join(File::B.path()), model::INITIAL_B)?;
    std::fs::write(dir.join(File::Key.path()), "-----BEGIN PRIVATE KEY-----\n")?;
    Ok(dir)
}

/// Nanoseconds since `t0`. A u64 of nanoseconds is 584 years; saturating keeps
/// the order of any two readings, which is all a history uses.
fn nanos_since(t0: std::time::Instant) -> u64 {
    u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

pub fn run(a: Args) -> Result<i32> {
    if a.mode == Mode::Hyper {
        return hyper::run(&a);
    }
    let work = workspace().context("building the workspace")?;
    let web = mock_web::MockWeb::start().context("starting the local web server")?;
    model::set_mock_addr(web.addr);
    let (proxy_url, auth_secret, _keep) = match a.policy {
        Policy::Grant => {
            let run = crate::agency::spawn_local_under_grant(
                &a.goal,
                &a.ceiling,
                &a.proxy_bin,
                &work,
                &std::collections::BTreeSet::new(),
            )
            .context("spawning the tool-proxy")?;
            (
                run.proxy_url.clone(),
                run.auth_secret.clone(),
                Box::new(run) as Box<dyn std::any::Any>,
            )
        }
        Policy::Trifecta => {
            let lattice = trifecta_lattice()?;
            let run = crate::agency::spawn_local_proxy(&crate::agency::LocalProxyConfig {
                run_id: format!("stress-{}", std::process::id()),
                name: "stress-trifecta",
                proxy_bin: &a.proxy_bin,
                work_dir: &work,
                lattice,
                network: serde_json::json!({ "dns_allow": [web.addr.to_string()] }),
                duration_secs: 600,
                certificate: None,
            })
            .context("spawning the tool-proxy")?;
            (
                run.proxy_url.clone(),
                run.auth_secret.clone(),
                Box::new(run) as Box<dyn std::any::Any>,
            )
        }
    };
    let url = Arc::new(proxy_url);
    let secret = Arc::new(auth_secret);
    let fetch = a.policy == Policy::Trifecta;
    let t0 = Instant::now();

    let handles: Vec<_> = (0..a.clients)
        .map(|client| {
            let (url, secret) = (Arc::clone(&url), Arc::clone(&secret));
            let ops = a.ops;
            let verbose = a.verbose;
            let seed = a.seed.wrapping_add(client as u64);
            std::thread::spawn(move || -> Result<Vec<Call<Op, Out>>> {
                let mut rng = Rng::new(seed);
                let mut calls = Vec::with_capacity(ops);
                for _ in 0..ops {
                    let op = random_op(&mut rng, fetch);
                    let Some((route, body)) = request(&op) else {
                        continue;
                    };
                    let invoke = nanos_since(t0);
                    let (status, text, _) =
                        crate::signed_tool_call(&url, &secret, "nucleus-stress", route, body)?;
                    let ret = nanos_since(t0);
                    let out = normalise(&op, status, &text);
                    if verbose {
                        println!(
                            "{op:?} -> {status} {}",
                            text.chars().take(200).collect::<String>()
                        );
                    }
                    calls.push(Call {
                        invoke,
                        ret,
                        op,
                        out,
                    });
                }
                Ok(calls)
            })
        })
        .collect();
    let mut history: Vec<Call<Op, Out>> = Vec::new();
    for h in handles {
        match h.join() {
            Ok(Ok(calls)) => history.extend(calls),
            Ok(Err(e)) => {
                eprintln!("could not look: a client failed: {e:#}");
                return Ok(2);
            }
            Err(_) => {
                eprintln!("could not look: a client panicked");
                return Ok(2);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    if let Ok(reqs) = web.requests.lock() {
        println!(
            "egress: {} request(s) reached the local web server",
            reqs.len()
        );
    }
    drop(_keep);

    // What was exercised, by operation and result.
    let mut tally: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for c in &history {
        let key = format!(
            "{:<12} -> {} {}",
            format!("{:?}", c.op),
            c.out.status,
            c.out.code.as_deref().unwrap_or("-")
        );
        *tally.entry(key).or_default() += 1;
        if a.verbose {
            println!(
                "[{:>12}..{:>12}] {:?} => {:?}",
                c.invoke, c.ret, c.op, c.out
            );
        }
    }
    for (k, n) in &tally {
        println!("{n:>5}  {k}");
    }

    // Each admitted fetch also delivers untrusted content, somewhere in its own
    // interval: the model's taint event.
    let delivered: Vec<Call<Op, Out>> = history
        .iter()
        .filter(|c| matches!(c.op, Op::Fetch) && (200..300).contains(&c.out.status))
        .map(|c| Call {
            invoke: c.invoke,
            ret: c.ret,
            op: Op::Delivered,
            out: c.out.clone(),
        })
        .collect();
    let admitted_fetches = delivered.len();
    history.extend(delivered);
    println!("fetches admitted: {admitted_fetches}");
    match linearize::check(&Session::initial(a.policy), &history) {
        Verdict::Linearizable => {
            println!(
                "linearizable: {} calls from {} client(s) explained by the model",
                history.len(),
                a.clients
            );
            Ok(0)
        }
        Verdict::NotLinearizable { window, explained } => {
            if let Some(path) = &a.history {
                let mut lines: Vec<&Call<Op, Out>> = history.iter().collect();
                lines.sort_by_key(|c| c.invoke);
                let text: String = lines
                    .iter()
                    .map(|c| {
                        format!(
                            "{} {} {:?} {} {} {}\n",
                            c.invoke,
                            c.ret,
                            c.op,
                            c.out.status,
                            c.out.code.as_deref().unwrap_or("-"),
                            c.out.contents.as_deref().unwrap_or("-")
                        )
                    })
                    .collect();
                std::fs::write(path, text).context("writing the history")?;
            }
            println!(
                "NOT LINEARIZABLE: a window of {} calls, at most {explained} explained by any order:",
                window.len()
            );
            for c in &window {
                println!(
                    "  [{:>12}..{:>12}] {:?} => {:?}",
                    c.invoke, c.ret, c.op, c.out
                );
            }
            Ok(1)
        }
        Verdict::BudgetExceeded { window_len } => {
            println!(
                "could not look: the search over a window of {window_len} overlapping calls ran out of budget"
            );
            Ok(2)
        }
    }
}
