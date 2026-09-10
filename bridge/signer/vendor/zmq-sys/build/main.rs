pub fn configure() {
    println!("cargo:rerun-if-changed=build/main.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");

    // Require system ZeroMQ. The bridge security suite verifies CURVE support;
    // do not silently fall back to the upstream bundled non-CURVE build.
    system_deps::Config::new().probe().expect(
        "install system libzmq development files with CURVE support (e.g. libzmq3-dev)",
    );
}

fn main() {
    configure()
}
