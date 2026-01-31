#![no_main]

use libfuzzer_sys::fuzz_target;
use lattice_guard::PathLattice;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let lattice = PathLattice::block_sensitive();
    let _ = lattice.can_access(Path::new(&*s));
});
