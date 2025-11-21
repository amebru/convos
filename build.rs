fn main() {
    let bridge = vec!["src/ffi.rs"];

    swift_bridge_build::parse_bridges(bridge)
        .write_all_concatenated(
            std::env::var("OUT_DIR").unwrap(),
            env!("CARGO_PKG_NAME")
        );
}
