use ahash::*;
use core::slice;
use std::hash::{BuildHasher, Hasher};

#[no_mangle]
pub extern "C" fn ahash64(buf: *const (), len: usize, seed: u64) -> u64 {
    let buf: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, len) };
    let mut hasher = RandomState::with_seeds(
        0x243f_6a88_85a3_08d3_u64.wrapping_add(seed),
        0x1319_8a2e_0370_7344_u64 ^ seed,
        0xa409_3822_299f_31d0,
        0x082e_fa98_ec4e_6c89,
    )
    .build_hasher();
    hasher.write(buf);
    hasher.finish()
}
