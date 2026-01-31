#![no_main]

use libfuzzer_sys::fuzz_target;
use lattice_guard::PermissionLattice;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<PermissionLattice>(s);
    }
});
