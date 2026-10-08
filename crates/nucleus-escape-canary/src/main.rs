//! Runs only by explicit request inside a disposable test guest.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

#[cfg(target_os = "linux")]
mod runtime;

fn main() {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--in-disposable-guest"] {
        eprintln!("usage: nucleus-escape-canary --in-disposable-guest");
        std::process::exit(2);
    }
    #[cfg(target_os = "linux")]
    std::process::exit(i32::from(runtime::run()));
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("could-not-look: canary requires a Linux guest");
        std::process::exit(2);
    }
}
