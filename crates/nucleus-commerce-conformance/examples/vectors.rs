//! Emit the conformance vectors as JSON.
//!
//! ```text
//! cargo run -p nucleus-commerce-conformance --example vectors > vectors.json
//! ```
//!
//! This is the artifact behind the open-commerce claim. A runtime written in any
//! language reads these, runs its own checks over each `input`, and compares its
//! verdict to `expect` (and to `expect_reason_contains` where present). It never
//! executes nucleus code, never calls a nucleus service, and needs nobody's
//! permission to demonstrate that it conforms.
fn main() {
    println!("{}", nucleus_commerce_conformance::export_vectors());
}
