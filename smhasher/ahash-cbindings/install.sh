
# check if args contains vaes
if [[ $* == *vaes* ]]; then
    export CARGO_OPTS="--features=vaes"
else
    export CARGO_OPTS=""
fi

RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C codegen-units=1" cargo build ${CARGO_OPTS} --release && sudo cp target/release/libahash_c.a /usr/local/lib/
