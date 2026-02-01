use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 1500;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut target: Option<String> = None;

    while let Some(arg) = args.next() {
        if arg == "--timeout-ms" {
            let value = args
                .next()
                .ok_or_else(|| "missing value for --timeout-ms".to_string())?;
            timeout_ms = value
                .parse::<u64>()
                .map_err(|_| "invalid timeout value".to_string())?;
        } else if arg.starts_with("--timeout-ms=") {
            let value = arg
                .split_once('=')
                .map(|(_, v)| v)
                .ok_or_else(|| "invalid timeout value".to_string())?;
            timeout_ms = value
                .parse::<u64>()
                .map_err(|_| "invalid timeout value".to_string())?;
        } else if target.is_none() {
            target = Some(arg);
        } else {
            return Err("unexpected extra argument".to_string());
        }
    }

    let target =
        target.ok_or_else(|| "usage: nucleus-net-probe HOST:PORT [--timeout-ms N]".to_string())?;
    let timeout = Duration::from_millis(timeout_ms);
    let addr = resolve_addr(&target)?;

    TcpStream::connect_timeout(&addr, timeout)
        .map(|_| ())
        .map_err(|err| format!("connect to {addr} failed: {err}"))
}

fn resolve_addr(target: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = target
        .to_socket_addrs()
        .map_err(|_| "failed to resolve address".to_string())?;
    addrs
        .next()
        .ok_or_else(|| "no addresses resolved".to_string())
}
