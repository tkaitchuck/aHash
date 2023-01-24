use ahash::*;
use core::slice;
use std::hash::{BuildHasher, Hasher};

#[no_mangle]
pub extern "C" fn ahash64(buf: *const (), len: usize, seed: u64) -> u64 {
    let buf: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, len) };
    let build_hasher = RandomState::with_seed(seed as usize);
    <[u8]>::get_hash(&buf, &build_hasher)
}
