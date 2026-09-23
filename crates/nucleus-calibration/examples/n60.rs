//! The n=60 case, printed.
//!
//! A perfectly calibrated synthetic model, assessed at n=60 and at n=5000
//! against a 0.02 tolerance. The observed ECE is small in both. Only one of
//! the two samples can vouch for it.
//!
//! ```sh
//! cargo run -q -p nucleus-calibration --example n60
//! ```

use nucleus_calibration::{FloorParams, MICRO, Prediction, issue, verify};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn calibrated(n: usize) -> Vec<Prediction> {
    let mut r = Rng(7);
    (0..n)
        .map(|_| {
            let p = r.next() % (MICRO + 1);
            let outcome = r.next() % MICRO < p;
            Prediction {
                p_micro: p,
                outcome,
            }
        })
        .collect()
}

/// Render a micro-unit integer to four decimal places WITHOUT f64.
///
/// This crate's claim is that the measurement is integer-exact, so a float in
/// its own printer is exactly the cast the ratchet is right to count: the
/// numbers it prints are the numbers the receipt carries, and a rounding step
/// on the way to the terminal is a second opinion nobody asked for.
fn four_dp(micro: u64) -> String {
    // Round to nearest rather than truncate. Truncating renders a floor one
    // digit LOW, which understates the region where no observed ECE can
    // establish calibration -- the wrong direction for the one number here
    // whose job is to say "could not look".
    let step = MICRO / 10_000;
    let ten_thousandths = (micro + step / 2) / step;
    format!(
        "{}.{:04}",
        ten_thousandths / 10_000,
        ten_thousandths % 10_000
    )
}

fn main() {
    let tolerance = 20_000; // ECE < 0.02
    for n in [60usize, 5000] {
        let claim = match issue(calibrated(n), FloorParams::DEFAULT, tolerance) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("could not assess: {e}");
                std::process::exit(2);
            }
        };
        let a = claim.claimed;
        println!("n = {n}");
        println!("  ECE observed   {}", four_dp(a.ece_micro));
        println!(
            "  noise floor    {}  (95th pct of a perfect model at this n)",
            four_dp(a.floor_micro)
        );
        println!("  tolerance      {}", four_dp(tolerance));
        println!("  verdict        {}", a.verdict.tag());
        println!("  gate on it?    {}", a.verdict.supports_gating());
        println!("  recomputes?    {:?}", verify(&claim));
        println!();
    }
}
