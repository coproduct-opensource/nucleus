#![no_main]

use libfuzzer_sys::fuzz_target;
use lattice_guard::CommandLattice;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let lattice = CommandLattice::permissive();
    let _ = lattice.can_execute(&s);
});
