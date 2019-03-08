//! # aHash
//!
//! This hashing algorithm is intended to be a high performance, (hardware specific), keyed hash function.
//! This can be seen as a DOS resistant alternative to FxHash, or a fast equivalent to SipHash.
//! It provides a high speed hash algorithm, but where the result is not predictable without knowing a Key.
//! This allows it to be used in a HashMap without allowing for the possibility that an malicious user can
//! induce a collision.
//!
//! # How aHash works
//!
//! aHash uses the hardware AES instruction on x86 processors to provide a keyed hash function.
//! It uses two rounds of AES per hash. So it should not be considered cryptographically secure.
extern crate const_random;

#[macro_use]
mod convert;

mod fallback_hash;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
mod aes_hash;
#[cfg(test)]
mod hash_quality_test;

use std::collections::HashMap;
use std::hash::{BuildHasherDefault};

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
pub use crate::aes_hash::AHasher;

#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
pub use crate::fallback_hash::AHasher;

/// A `HashMap` using a `BuildHasherDefault` BuildHasher to hash the items.
pub type AHashMap<K, V> = HashMap<K, V, BuildHasherDefault<AHasher>>;

#[cfg(test)]
mod test {
    use crate::convert::Convert;
    use crate::*;

    #[test]
    fn test_builder() {
        let mut map = HashMap::<u32, u64, BuildHasherDefault<AHasher>>::default();
        map.insert(1, 3);
    }

    #[test]
    fn test_conversion() {
        let input: &[u8] = "dddddddd".as_bytes();
        let bytes: u64 = as_array!(input, 8).convert();
        assert_eq!(bytes, 0x6464646464646464);
    }
}
