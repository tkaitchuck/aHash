/*
 * aHash, as the Rust crate itself, for SMHasher3 (https://gitlab.com/fwojcik/smhasher3).
 *
 * SMHasher3 comes with a port of an old version of aHash to C++ (rust-ahash.cpp). This instead calls the crate
 * through its C bindings (ahash-cbindings), so that what is tested is the code which is in use.
 * run_smhasher3.sh adds this file to SMHasher3 and links the bindings.
 *
 * Licensed under either of the Apache License, Version 2.0 or the MIT license, at your option.
 */
#include "Platform.h"
#include "Hashlib.h"

// Hashes the bytes the way a `&[u8]` is hashed, with keys which are all derived from the one seed.
extern "C" uint64_t ahash64( const void * buf, size_t len, uint64_t seed );

template <bool bswap>
static void rust_ahash_crate( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash = ahash64(in, len, (uint64_t)seed);

    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

REGISTER_FAMILY(rust_ahash_crate,
   $.src_url    = "https://github.com/tkaitchuck/aHash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

// aHash does not have a fixed output, so there is no verification value, and SMHasher3 skips that check.
REGISTER_HASH(rust_ahash_crate,
   $.desc            = "aHash (the Rust crate, called through its C bindings)",
   $.hash_flags      =
         FLAG_HASH_XL_SEED,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = rust_ahash_crate<false>,
   $.hashfn_bswap    = rust_ahash_crate<true>
 );
