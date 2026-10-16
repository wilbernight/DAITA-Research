// protox compiles the proto in pure Rust, so no system `protoc` is needed.
fn main() {
    let fds = protox::compile(["proto/ephemeralpeer.proto"], ["proto/"]).unwrap();
    tonic_prost_build::configure()
        .build_client(false)
        .compile_fds(fds)
        .unwrap();
    println!("cargo:rerun-if-changed=proto/ephemeralpeer.proto");
}
