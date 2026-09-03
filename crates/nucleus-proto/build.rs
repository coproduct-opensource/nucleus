fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hand the vendored protoc to prost directly rather than exporting PROTOC.
    // The env round-trip was only ever a way to reach prost's config, and
    // edition 2024 makes `set_var` unsafe because mutating the environment
    // races any concurrent reader. `Config::protoc_executable` is the same
    // instruction with no process-global state and no `unsafe`.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);

    let crates_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();

    // nucleus-node service.
    let node_dir = crates_root.join("nucleus-node/proto");
    let node_proto = node_dir.join("nucleus_node.proto");
    println!("cargo:rerun-if-changed={}", node_proto.display());

    // nucleus-control-plane JobService.
    let cp_dir = crates_root.join("nucleus-control-plane/proto");
    let cp_proto = cp_dir.join("job_service.proto");
    println!("cargo:rerun-if-changed={}", cp_proto.display());

    // SPIFFE Workload API (X.509-SVID profile). Its proto has NO package
    // declaration on purpose — the standard method path is
    // `/SpiffeWorkloadAPI/FetchX509SVID` and real clients hard-code it — so
    // prost emits it as `_.rs`.
    let spiffe_dir = crates_root.join("nucleus-identity/proto");
    let spiffe_proto = spiffe_dir.join("workload.proto");
    println!("cargo:rerun-if-changed={}", spiffe_proto.display());

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(
            config,
            &[node_proto, cp_proto, spiffe_proto],
            &[node_dir, cp_dir, spiffe_dir],
        )?;
    Ok(())
}
