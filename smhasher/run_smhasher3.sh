#!/bin/sh
# Runs the SMHasher3 test suite (https://gitlab.com/fwojcik/smhasher3) on aHash, and writes the output to this
# directory.
#
#   ./run_smhasher3.sh aes        # The AES hasher                      -> ahashOutput.txt
#   ./run_smhasher3.sh fallback   # The fallback hasher                 -> fallbackOutput.txt
#   ./run_smhasher3.sh nofold     # The fallback without 128 bit multiplication (as on 32 bit targets)
#                                 #                                     -> fallbackNoFoldedOutput.txt
#
# Any further arguments are passed on to SMHasher3, for example `--test=Speed`, and the output is then only printed.
# NCPU sets the number of threads. (Default 4.)
# Everything is built in ../target/smhasher3 (or in $WORK). Nothing is installed.
# This needs git, cmake, a C++ compiler and cargo, and a CPU with AES for `aes`.
set -e

variant=${1:-aes}
[ $# -gt 0 ] && shift
here=$(cd "$(dirname "$0")" && pwd)
work=${WORK:-$here/../target/smhasher3}
flags="-C opt-level=3 -C target-cpu=native -C codegen-units=1"
bindings=$here/ahash-cbindings

case $variant in
    aes)
        output=$here/ahashOutput.txt ;;
    fallback)
        flags="$flags -C target-feature=-aes"
        output=$here/fallbackOutput.txt ;;
    nofold)
        flags="$flags -C target-feature=-aes"
        output=$here/fallbackNoFoldedOutput.txt
        # Whether the 128 bit multiplication is used is decided by build.rs from the architecture. So this
        # variant is built from a copy of the crate in which that has been taken out.
        rm -rf "$work/nofold-src"
        mkdir -p "$work/nofold-src/smhasher"
        cp -r "$here/../src" "$here/../build.rs" "$here/../Cargo.toml" "$here/../README.md" "$work/nofold-src/"
        cp -r "$bindings" "$work/nofold-src/smhasher/"
        rm -rf "$work/nofold-src/smhasher/ahash-cbindings/target"
        grep -q 'cargo:rustc-cfg=folded_multiply' "$work/nofold-src/build.rs"
        sed -i.bak '/cargo:rustc-cfg=folded_multiply/d' "$work/nofold-src/build.rs"
        bindings=$work/nofold-src/smhasher/ahash-cbindings ;;
    *)
        echo "Usage: $0 [aes|fallback|nofold] [arguments for SMHasher3]" >&2
        exit 1 ;;
esac

mkdir -p "$work"
CARGO_TARGET_DIR="$work/cargo-$variant" RUSTFLAGS="$flags" cargo build --release --manifest-path "$bindings/Cargo.toml"
library=$work/cargo-$variant/release/libahash_c.a

if [ ! -d "$work/smhasher3" ]; then
    git clone https://gitlab.com/fwojcik/smhasher3.git "$work/smhasher3"
fi
cd "$work/smhasher3"
# Add the hash which calls the crate, and link the bindings. (Only once.)
cp "$here/rust-ahash-crate.cpp" hashes/
if ! grep -q 'rust-ahash-crate.cpp' hashes/Hashsrc.cmake; then
    sed -i.bak 's|^  hashes/rust-ahash.cpp$|  hashes/rust-ahash.cpp\n  hashes/rust-ahash-crate.cpp|' hashes/Hashsrc.cmake
    grep -q 'rust-ahash-crate.cpp' hashes/Hashsrc.cmake
    echo 'target_link_libraries(SMHasher3 ${AHASH_C_LIB} ${CMAKE_DL_LIBS} pthread m)' >> CMakeLists.txt
fi
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAHASH_C_LIB="$library" > "$work/cmake.log"
cmake --build build --parallel > "$work/build.log" 2>&1

echo "SMHasher3 $(git rev-parse --short HEAD), aHash variant: $variant" >&2
if [ $# -eq 0 ]; then
    # `--extra` adds the longer tests. It is what the results which SMHasher3 publishes are run with.
    ./build/SMHasher3 --ncpu="${NCPU:-4}" --extra rust-ahash-crate | tee "$output"
else
    # Only a full run replaces the output which is checked in.
    ./build/SMHasher3 --ncpu="${NCPU:-4}" "$@" rust-ahash-crate
fi
