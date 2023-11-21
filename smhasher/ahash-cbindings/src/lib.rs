use ahash::*;
use core::slice;

#[no_mangle]
pub extern "C" fn ahash64(buf: *const (), len: usize, seed: u64) -> u64 {
    let buf: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, len) };
    let build_hasher = RandomState::with_seeds(seed, seed, seed, seed);
    build_hasher.hash_one(&buf)
}
