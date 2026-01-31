fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    tonic_build::configure()
        .build_server(true)
        .protoc_path(protoc)
        .compile(&["proto/nucleus_node.proto"], &["proto"])?;
    Ok(())
}
