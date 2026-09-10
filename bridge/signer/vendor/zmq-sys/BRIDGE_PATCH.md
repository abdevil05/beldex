# Local build correction

Source: crates.io `zmq-sys` 0.12.0 (MIT OR Apache-2.0), copied from the
previously locked crate. Rust bindings are unchanged. The only functional
patch replaces the build call in `build/main.rs` with the existing
`system-deps` probe.

Upstream's `zeromq_src::Build::with_libsodium(None)` compiles without CURVE.
This patch requires system libzmq instead of silently using that build.
Install development headers/library and pkg-config before building. The
mandatory `two_node_curve_roundtrip` regression fails if CURVE is unavailable.
System libzmq is not pinned by Cargo.lock; OS package patching and provenance
remain an operator responsibility. No global Cargo registry source was edited.
