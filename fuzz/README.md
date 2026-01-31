# Fuzzing Targets

This directory contains `cargo-fuzz` targets for lattice-guard invariants.

## Setup

```
cargo install cargo-fuzz
```

## Run

```
cargo fuzz list
cargo fuzz run path_can_access -- -max_total_time=60
cargo fuzz run command_can_execute -- -max_total_time=60
cargo fuzz run permission_serde -- -max_total_time=60
```

Notes:
- Targets use `lattice-guard` with `serde` enabled.
- Add seed corpora under `fuzz/corpus/<target>/` to improve coverage.
