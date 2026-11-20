//! `nucleus-link-probe` — the links gauntlet's in-guest workload (ADR 0017 §10).
//!
//! ```text
//! nucleus-link-probe serve <port>... [--slow-ms N]
//! nucleus-link-probe send <dst-uuid> <port> <n> <seed> [--refused-port P] [--tls] [--gap-ms N]
//! nucleus-link-probe adversary <dst-uuid> <seed>
//! ```
//!
//! Every report is a sentinel line (`nucleus_link_probe::line`) on stdout AND
//! stderr; stderr reaches the guest console log. The probe decides nothing:
//! the host harness reads both ends and judges.

use nucleus_link_probe::{
    AttemptOutcome, Event, ID_HEADER, body_digest, line, link_host, parse_head, request_id,
    status_of,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const READY_DEADLINE: Duration = Duration::from_secs(180);

fn report(event: &Event) {
    let l = line(event);
    println!("{l}");
    eprintln!("{l}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]),
        Some("send") => send(&args[1..]),
        Some("adversary") => adversary(&args[1..]),
        _ => Err("usage: nucleus-link-probe serve|send|adversary ...".into()),
    };
    if let Err(e) = result {
        report(&Event::Attempt {
            name: "probe".into(),
            outcome: AttemptOutcome::NotRun,
            detail: e,
            id: None,
        });
        std::process::exit(2);
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Read until the end of the head (`\r\n\r\n`) or EOF; returns the head bytes
/// and whatever followed it.
fn read_head(stream: &mut impl Read) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((buf, rest));
        }
        if buf.len() > 64 * 1024 {
            return Ok((buf, Vec::new()));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok((buf, Vec::new()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

// ---------------------------------------------------------------- serve

fn serve(args: &[String]) -> Result<(), String> {
    let slow = flag(args, "--slow-ms")
        .map(|v| v.parse::<u64>().map_err(|e| e.to_string()))
        .transpose()?
        .unwrap_or(0);
    let ports: Vec<u16> = args
        .iter()
        .take_while(|a| !a.starts_with("--"))
        .map(|p| p.parse().map_err(|e| format!("port {p}: {e}")))
        .collect::<Result<_, String>>()?;
    if ports.is_empty() {
        return Err("serve needs at least one port".into());
    }
    let mut handles = Vec::new();
    for port in ports {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => handles.push(std::thread::spawn(move || accept(listener, port, slow))),
            Err(e) => report(&Event::BindFailed {
                port,
                error: e.to_string(),
            }),
        }
    }
    for h in handles {
        let _ = h.join();
    }
    report(&Event::Done {
        mode: "serve".into(),
    });
    Ok(())
}

fn accept(listener: TcpListener, port: u16, slow_ms: u64) {
    for stream in listener.incoming().flatten() {
        std::thread::spawn(move || {
            let _ = answer(stream, port, slow_ms);
        });
    }
}

fn answer(mut stream: TcpStream, port: u16, slow_ms: u64) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    let (head, mut body) = read_head(&mut stream)?;
    let Some(h) = parse_head(&String::from_utf8_lossy(&head)) else {
        return Ok(());
    };
    while body.len() < h.content_length {
        let mut chunk = vec![0u8; h.content_length - body.len()];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    report(&Event::Received {
        id: h.id.unwrap_or_default(),
        method: h.method,
        path: h.path,
        port,
        body_sha256: body_digest(&body),
    });
    if slow_ms > 0 {
        std::thread::sleep(Duration::from_millis(slow_ms));
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
}

// ---------------------------------------------------------------- send

fn proxy_addr() -> Result<String, String> {
    let v = std::env::var("NUCLEUS_LINK_PROXY").map_err(|_| "NUCLEUS_LINK_PROXY unset")?;
    Ok(v.trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned())
}

fn connect(proxy: &str) -> std::io::Result<TcpStream> {
    let s = TcpStream::connect(proxy)?;
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(s)
}

/// One plain-HTTP request over the link proxy; the response status.
fn plain(proxy: &str, host: &str, port: u32, id: &str) -> Result<u16, String> {
    let mut s = connect(proxy).map_err(|e| format!("connect: {e}"))?;
    let req = format!(
        "GET http://{host}:{port}/r/{id} HTTP/1.1\r\nHost: {host}:{port}\r\n{ID_HEADER}: {id}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let (head, _) = read_head(&mut s).map_err(|e| e.to_string())?;
    status_of(&head).ok_or_else(|| "no response status (connection closed)".into())
}

fn roots(trusted: Option<&str>) -> Result<rustls::RootCertStore, String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let mut store = rustls::RootCertStore::empty();
    if let Some(path) = trusted {
        for cert in CertificateDer::pem_file_iter(path).map_err(|e| e.to_string())? {
            store
                .add(cert.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(store)
}

/// One request over TLS terminated by the link proxy (ADR 0015 E3): CONNECT,
/// then the handshake trusting `store`, then the request in the tunnel.
fn tls(proxy: &str, host: &str, id: &str, store: rustls::RootCertStore) -> Result<u16, String> {
    let mut tcp = connect(proxy).map_err(|e| format!("connect: {e}"))?;
    tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let (head, _) = read_head(&mut tcp).map_err(|e| e.to_string())?;
    match status_of(&head) {
        Some(200) => {}
        Some(other) => return Ok(other),
        None => return Err("CONNECT got no status".into()),
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    let req = format!(
        "GET /r/{id} HTTP/1.1\r\nHost: {host}\r\n{ID_HEADER}: {id}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("handshake or write: {e}"))?;
    let (head, _) = read_head(&mut stream).map_err(|e| format!("read: {e}"))?;
    status_of(&head).ok_or_else(|| "no response status in the tunnel".into())
}

fn send(args: &[String]) -> Result<(), String> {
    let [dst, port, n, seed, ..] = args else {
        return Err("send <dst> <port> <n> <seed> [...]".into());
    };
    let port: u32 = port.parse().map_err(|e| format!("port: {e}"))?;
    let n: u64 = n.parse().map_err(|e| format!("n: {e}"))?;
    let seed: u64 = seed.parse().map_err(|e| format!("seed: {e}"))?;
    let refused = flag(args, "--refused-port")
        .map(|p| p.parse::<u32>().map_err(|e| e.to_string()))
        .transpose()?;
    let gap = Duration::from_millis(
        flag(args, "--gap-ms")
            .and_then(|g| g.parse().ok())
            .unwrap_or(0),
    );
    let with_tls = args.iter().any(|a| a == "--tls");
    let proxy = proxy_addr()?;
    let host = link_host(dst);
    let start = Instant::now();

    // Wait until the link carries a request: the harness links after boot.
    let mut k = 0;
    loop {
        let id = request_id(seed, "ready", k);
        if plain(&proxy, &host, port, &id).is_ok_and(|s| (200..300).contains(&s)) {
            break;
        }
        if start.elapsed() > READY_DEADLINE {
            return Err("the link never carried a request".into());
        }
        k += 1;
        std::thread::sleep(Duration::from_millis(500));
    }

    let record = |id: String, port: u32, tls: bool, r: Result<u16, String>| {
        let (status, error) = match r {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        };
        report(&Event::Sent {
            id,
            port,
            tls,
            status,
            error,
            at_ms: start.elapsed().as_millis() as u64,
        });
    };
    let trusted = std::env::var("NUCLEUS_EGRESS_TRUST_BUNDLE").ok();
    for i in 0..n {
        let id = request_id(seed, "linked", i);
        record(id.clone(), port, false, plain(&proxy, &host, port, &id));
        if let Some(p) = refused {
            let id = request_id(seed, "refused", i);
            record(id.clone(), p, false, plain(&proxy, &host, p, &id));
        }
        if with_tls {
            let id = request_id(seed, "tls", i);
            let r = roots(trusted.as_deref()).and_then(|s| tls(&proxy, &host, &id, s));
            record(id, 443, true, r);
        }
        std::thread::sleep(gap);
    }
    report(&Event::Done {
        mode: "send".into(),
    });
    Ok(())
}

// ---------------------------------------------------------------- adversary

fn attempt(name: &str, outcome: AttemptOutcome, detail: impl Into<String>, id: Option<String>) {
    report(&Event::Attempt {
        name: name.into(),
        outcome,
        detail: detail.into(),
        id,
    });
}

/// The outcome of an HTTP attempt from its status.
fn by_status(r: &Result<u16, String>) -> AttemptOutcome {
    match r {
        Ok(s) if (200..300).contains(s) => AttemptOutcome::Answered,
        _ => AttemptOutcome::Refused,
    }
}

/// Send `raw` bytes to the link proxy; every status line that came back.
fn raw(proxy: &str, raw: &[u8]) -> Result<Vec<u16>, String> {
    let mut s = connect(proxy).map_err(|e| e.to_string())?;
    s.write_all(raw).map_err(|e| e.to_string())?;
    let mut all = Vec::new();
    let _ = s.read_to_end(&mut all);
    let text = String::from_utf8_lossy(&all);
    Ok(text
        .match_indices("HTTP/1.")
        .filter_map(|(i, _)| status_of(&all[i..]))
        .collect())
}

#[cfg(target_os = "linux")]
fn vsock_attempts() {
    for (cid, port) in [(2u32, 1030u32), (2, 1029), (3, 1031), (4, 1031), (5, 1031)] {
        let name = format!("raw_vsock_cid{cid}_port{port}");
        match vsock::VsockStream::connect_with_cid_port(cid, port) {
            Ok(_) => attempt(&name, AttemptOutcome::Reached, "connected", None),
            Err(e) => attempt(&name, AttemptOutcome::Refused, e.to_string(), None),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn vsock_attempts() {
    attempt(
        "raw_vsock",
        AttemptOutcome::NotRun,
        "AF_VSOCK exists only on Linux",
        None,
    );
}

fn adversary(args: &[String]) -> Result<(), String> {
    let [dst, seed, ..] = args else {
        return Err("adversary <dst> <seed>".into());
    };
    let seed: u64 = seed.parse().map_err(|e| format!("seed: {e}"))?;
    let proxy = proxy_addr()?;
    let host = link_host(dst);
    let id = |tag: &str| request_id(seed, tag, 0);

    vsock_attempts();

    // A link name for a pod this one is not linked to.
    let fid = id("forged");
    let r = plain(&proxy, &host, 8080, &fid);
    attempt("forged_link", by_status(&r), format!("{r:?}"), Some(fid));

    // Content-Length and Transfer-Encoding together (request smuggling).
    let cid = id("clte");
    let req = format!(
        "POST http://{host}:8080/r/{cid} HTTP/1.1\r\nHost: {host}:8080\r\n{ID_HEADER}: {cid}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
    );
    let r = raw(&proxy, req.as_bytes());
    let outcome = match &r {
        Ok(s) if s.iter().any(|s| (200..300).contains(s)) => AttemptOutcome::Answered,
        _ => AttemptOutcome::Refused,
    };
    attempt("cl_te_smuggling", outcome, format!("{r:?}"), Some(cid));

    // Two requests in one write: the second must never reach anyone undecided.
    let (p1, p2) = (id("pipe1"), id("pipe2"));
    let req = format!(
        "GET http://{host}:8080/r/{p1} HTTP/1.1\r\nHost: {host}:8080\r\n{ID_HEADER}: {p1}\r\n\r\nGET http://{host}:8080/r/{p2} HTTP/1.1\r\nHost: {host}:8080\r\n{ID_HEADER}: {p2}\r\nConnection: close\r\n\r\n"
    );
    let r = raw(&proxy, req.as_bytes());
    let outcome = match &r {
        Ok(s) if s.len() > 1 => AttemptOutcome::Answered,
        Ok(s) if s.iter().any(|s| (200..300).contains(s)) => AttemptOutcome::Answered,
        _ => AttemptOutcome::Refused,
    };
    attempt(
        "pipelined_second_request",
        outcome,
        format!("{r:?}"),
        Some(p2),
    );

    // Upgrade to an opaque protocol.
    let uid = id("upgrade");
    let req = format!(
        "GET http://{host}:8080/r/{uid} HTTP/1.1\r\nHost: {host}:8080\r\n{ID_HEADER}: {uid}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    );
    let r = raw(&proxy, req.as_bytes());
    let outcome = match &r {
        Ok(s) if s.iter().any(|s| (100..300).contains(s)) => AttemptOutcome::Answered,
        _ => AttemptOutcome::Refused,
    };
    attempt("upgrade", outcome, format!("{r:?}"), Some(uid));

    // CONNECT, then plaintext instead of a ClientHello.
    let nid = id("connect-plain");
    let req = format!(
        "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\nGET /r/{nid} HTTP/1.1\r\nHost: {host}\r\n{ID_HEADER}: {nid}\r\n\r\n"
    );
    let r = raw(&proxy, req.as_bytes());
    let outcome = match &r {
        Ok(s) if s.iter().any(|s| (200..300).contains(s) && *s != 200) => AttemptOutcome::Answered,
        Ok(s) if s.iter().filter(|s| (200..300).contains(*s)).count() > 1 => {
            AttemptOutcome::Answered
        }
        _ => AttemptOutcome::Refused,
    };
    attempt("connect_not_tls", outcome, format!("{r:?}"), Some(nid));

    // TLS trusting no root the proxy can satisfy (a foreign CA).
    let tid = id("foreign-ca");
    let r = tls(&proxy, &host, &tid, rustls::RootCertStore::empty());
    attempt("tls_foreign_ca", by_status(&r), format!("{r:?}"), Some(tid));

    // More connections than the relay's per-pod cap (64).
    let mut held = Vec::new();
    let mut refused = 0usize;
    for _ in 0..80 {
        match connect(&proxy) {
            Ok(mut s) => {
                let _ = s.write_all(b"GET http://");
                held.push(s);
            }
            Err(_) => refused += 1,
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    let mut closed = 0usize;
    for s in &mut held {
        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
        let mut b = [0u8; 1];
        if matches!(s.read(&mut b), Ok(0)) {
            closed += 1;
        }
    }
    let outcome = if refused + closed >= 80 - 64 {
        AttemptOutcome::Refused
    } else {
        AttemptOutcome::Answered
    };
    attempt(
        "connection_cap",
        outcome,
        format!(
            "opened={} refused_at_connect={refused} closed_by_relay={closed}",
            held.len()
        ),
        None,
    );
    drop(held);

    report(&Event::Done {
        mode: "adversary".into(),
    });
    Ok(())
}
