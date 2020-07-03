use core::slice;
use ahash::*;
use std::hash::{Hasher, BuildHasher};

#[no_mangle]
pub extern "C" fn ahash64(buf: *const (), len: usize, seed: u64) -> u64 {
    let buf: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, len) };
    let mut hasher = RandomState::with_seeds(std::f64::consts::PI as u64 ^ seed, std::f64::consts::E as u64 ^ seed).build_hasher();
    hasher.write(buf);
    hasher.finish()
}

