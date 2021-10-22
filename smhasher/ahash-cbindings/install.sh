RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C codegen-units=1" cargo build --release && sudo cp target/release/libahash_c.a /usr/local/lib/
