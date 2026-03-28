fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    // Proto source lives in nucleus-node/proto/
    let proto_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("nucleus-node/proto");

    let proto_file = proto_dir.join("nucleus_node.proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_file], &[proto_dir])?;
    Ok(())
}
