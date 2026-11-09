//! Local read-only browser fixture. Exact asset names and Host only; no app
//! credentials, filesystem browsing, writes or authority-bearing endpoints.
use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    path::PathBuf,
    time::Duration,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = match std::env::args().nth(2).as_deref() {
        None => false,
        Some("--encoded") => true,
        _ => return Err("unknown preview transport option".into()),
    };
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("usage: studio-proof-preview CRATE_DIR")?,
    )
    .canonicalize()?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let host = listener.local_addr()?.to_string();
    let certificate_path = format!("/cap/v1/{}/certificate", "0".repeat(64));
    println!("http://{host}/");
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut header = vec![];
        let mut chunk = [0u8; 2048];
        while !header.ends_with(b"\r\n\r\n") && header.len() < 16384 {
            let n = match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            header.extend_from_slice(&chunk[..n]);
        }
        let request = String::from_utf8_lossy(&header);
        let mut lines = request.split("\r\n");
        let line = lines.next().ok_or("request line missing")?;
        let mut parts = line.split_whitespace();
        let method = parts.next();
        let path = parts.next();
        let valid_host = lines
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>()
            == vec![host.as_str()];
        let asset=match (method,path,valid_host) {
            (Some("GET"),Some("/"),true)=>Some((b"<!doctype html><html lang='en'><meta charset='utf-8'><title>Studio proof fixture</title><h1>Studio proof fixture</h1><p>Read-only assets for the offline browser acceptance test.</p></html>".to_vec(),"text/html")),
            (Some("GET"),Some("/proof/verify"),true)=>Some((nucleus_studio_proof::page::html(None).into_bytes(),"text/html")),
            (Some("GET"),Some("/proof/example"),true)=>Some((nucleus_studio_proof::page::html(Some(&certificate_path)).replace("https://nucleus.coproduct.one","https://studio.example").replace("value=\"nucleus.coproduct.one\"","value=\"studio.example\"").replace("Equipment · identity migration","Fictional Equipment example").into_bytes(),"text/html")),
            (Some("GET"),Some(path),true) if path==certificate_path=>Some((fs::read(root.join("fixtures/equipment.signed.json"))?,"application/json")),
            (Some("GET"),Some(path),true)=>match path {
                "/proof/assets/boot.js"=>Some((nucleus_studio_proof::page::BOOT.as_bytes().to_vec(),"text/javascript")),
                "/proof/assets/nucleus_studio_proof.js"=>Some((fs::read(root.join("pkg/nucleus_studio_proof.js"))?,"text/javascript")),
                "/proof/assets/nucleus_studio_proof_bg.wasm"=>Some((fs::read(root.join("pkg/nucleus_studio_proof_bg.wasm"))?,"application/wasm")),
                "/proof/assets/base.ndjson.gz"=>Some((fs::read(root.join("fixtures/base.ndjson.gz"))?,"application/gzip")),
                "/pkg/nucleus_studio_proof.js"=>Some((fs::read(root.join("pkg/nucleus_studio_proof.js"))?,"text/javascript")),
                "/pkg/nucleus_studio_proof_bg.wasm"=>Some((fs::read(root.join("pkg/nucleus_studio_proof_bg.wasm"))?,"application/wasm")),
                "/fixtures/base.ndjson.gz"=>Some((fs::read(root.join("fixtures/base.ndjson.gz"))?,"application/gzip")),
                "/fixtures/equipment.delta.ndjson.gz"=>Some((fs::read(root.join("fixtures/equipment.delta.ndjson.gz"))?,"application/gzip")),
                "/fixtures/equipment.packet.json"=>Some((fs::read(root.join("fixtures/equipment.packet.json"))?,"application/json")),
                _=>None,
            },
            _=>None,
        };
        let (status, bytes, kind) = match asset {
            Some((bytes, kind)) => ("200 OK", bytes, kind),
            None => ("404 Not Found", vec![], "text/plain"),
        };
        let (bytes, transport) = if encoded {
            let mut gzip =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gzip.write_all(&bytes)?;
            (gzip.finish()?, "Content-Encoding: gzip\r\n".to_owned())
        } else {
            let header = format!("Content-Length: {}\r\n", bytes.len());
            (bytes, header)
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\n{transport}Connection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: {}\r\n\r\n",
            nucleus_studio_proof::page::CSP
        )?;
        stream.write_all(&bytes)?;
    }
    Ok(())
}
