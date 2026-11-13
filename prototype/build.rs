fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut prost = tonic_prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_client(true)
        .compile_with_config(
            prost,
            &[
                "proto/handler.proto",
                "proto/stats.proto",
                "proto/router.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
