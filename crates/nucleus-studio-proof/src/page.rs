//! Inert page structure. Runtime behavior is the Rust Wasm module.
pub const BOOT: &str = "import init from './nucleus_studio_proof.js';await init();\n";
pub const CSP: &str = "default-src 'none'; script-src 'self' blob: 'wasm-unsafe-eval'; worker-src blob:; connect-src 'self' blob:; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
pub fn valid_certificate_path(path: &str) -> bool {
    path.strip_prefix("/cap/v1/")
        .and_then(|p| p.strip_suffix("/certificate"))
        .is_some_and(|token| {
            token.len() == 64
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
pub fn html(certificate_url: Option<&str>) -> String {
    let source = certificate_url
        .map(|url| {
            format!(
                "data-certificate-url=\"{}\"",
                url.replace('&', "&amp;")
                    .replace('"', "&quot;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            )
        })
        .unwrap_or_default();
    include_str!("web.html").replace("{{CERTIFICATE_SOURCE}}", &source)
}
