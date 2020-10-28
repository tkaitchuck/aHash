use ahash::*;
use core::slice;
use std::hash::{BuildHasher, Hasher};

#[no_mangle]
pub extern "C" fn ahash64(buf: *const (), len: usize, seed: u64) -> u64 {
    let buf: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, len) };
    let mut hasher = RandomState::with_seeds(
        seed,
        std::f64::consts::PI as u64,
        std::f64::consts::E as u64,
        std::f64::consts::SQRT_2 as u64,
    )
    .build_hasher();
    hasher.write(buf);
    hasher.finish()
}
