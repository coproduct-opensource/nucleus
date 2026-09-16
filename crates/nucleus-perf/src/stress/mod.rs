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

pub mod linearize;
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
    /// Print every call and its result.
    #[arg(long)]
    pub verbose: bool,
}

/// A tiny deterministic generator (xorshift64*): reproducible from `--seed`, and no
/// dependency for four random choices.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) % n.max(1)
    }
}

fn random_op(rng: &mut Rng) -> Op {
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

fn request(op: &Op) -> (&'static str, serde_json::Value) {
    match op {
        Op::Read(f) => ("read", serde_json::json!({"path": f.path()})),
        Op::Write(f, v) => (
            "write",
            serde_json::json!({"path": f.path(), "contents": model::contents(*v)}),
        ),
        Op::Glob => ("glob", serde_json::json!({"pattern": "*.txt"})),
        Op::Run => (
            "run",
            serde_json::json!({"args": ["echo", "nucleus-stress"]}),
        ),
    }
}

fn normalise(op: &Op, status: u16, body: &str) -> Out {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    // The proxy's refusal carries `kind` (e.g. `kernel_denied`) and, for a kernel
    // decision, a `deny_code` naming the obligation that failed. Both are part of
    // the result: two refusals for different reasons are different results.
    let code = match (
        v.get("kind").and_then(|c| c.as_str()),
        v.get("deny_code").and_then(|c| c.as_str()),
    ) {
        (Some(kind), Some(deny)) => Some(format!("{kind}/{deny}")),
        (Some(kind), None) => Some(kind.to_owned()),
        (None, _) => None,
    };
    let contents = match op {
        Op::Read(_) if (200..300).contains(&status) => v
            .get("contents")
            .and_then(|c| c.as_str())
            .map(str::to_owned),
        Op::Read(_) | Op::Write(..) | Op::Glob | Op::Run => None,
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

pub fn run(a: Args) -> Result<i32> {
    let work = workspace().context("building the workspace")?;
    let proxy = crate::agency::spawn_local_under_grant(
        &a.goal,
        &a.ceiling,
        &a.proxy_bin,
        &work,
        &std::collections::BTreeSet::new(),
    )
    .context("spawning the tool-proxy")?;
    let url = Arc::new(proxy.proxy_url.clone());
    let secret = Arc::new(proxy.auth_secret.clone());
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
                    let op = random_op(&mut rng);
                    let (route, body) = request(&op);
                    let invoke = t0.elapsed().as_nanos() as u64;
                    let (status, text, _) =
                        crate::signed_tool_call(&url, &secret, "nucleus-stress", route, body)?;
                    let ret = t0.elapsed().as_nanos() as u64;
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
    let mut history = Vec::new();
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

    match linearize::check(&Session::initial(), &history) {
        Verdict::Linearizable => {
            println!(
                "linearizable: {} calls from {} client(s) explained by the model",
                history.len(),
                a.clients
            );
            Ok(0)
        }
        Verdict::NotLinearizable { window, explained } => {
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
