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
        println!("  ECE observed   {:.4}", a.ece_micro as f64 / MICRO as f64);
        println!(
            "  noise floor    {:.4}  (95th pct of a perfect model at this n)",
            a.floor_micro as f64 / MICRO as f64
        );
        println!("  tolerance      {:.4}", tolerance as f64 / MICRO as f64);
        println!("  verdict        {}", a.verdict.tag());
        println!("  gate on it?    {}", a.verdict.supports_gating());
        println!("  recomputes?    {:?}", verify(&claim));
        println!();
    }
}
