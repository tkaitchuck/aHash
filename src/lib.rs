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
extern crate arrayref;

#[macro_use]
mod convert;

mod fallback_hash;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
mod aes_hash;
#[cfg(test)]
mod hash_quality_test;

use const_random::const_random;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault};

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
pub use crate::aes_hash::AHasher;

#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
pub use crate::fallback_hash::AHasher;

/// A `HashMap` using a `BuildHasherDefault` BuildHasher to hash the items.
pub type AHashMap<K, V> = HashMap<K, V, BuildHasherDefault<AHasher>>;

///Const random provides randomzied keys with no runtime cost.
const DEFAULT_KEYS: [u64;2] = [const_random!(u64), const_random!(u64)];

/// Provides a [Hasher] is typically used (e.g. by [HashMap]) to create
/// [AHasher]s for each key such that they are hashed independently of one
/// another, since [AHasher]s contain state.
///
/// Constructs a new [AHasher] with compile time generated constants keys.
/// So the key will be the same from one instance to another,
/// but different from build to the next. So if it is possible for a potential
/// attacker to have access to your compiled binary it would be better
/// to specify keys generated at runtime.
///
/// # Examples
///
/// ```
/// use ahash::AHasher;
/// use std::hash::Hasher;
///
/// let mut hasher_1 = AHasher::default();
/// let mut hasher_2 = AHasher::default();
///
/// hasher_1.write_u32(8128);
/// hasher_2.write_u32(8128);
///
/// assert_eq!(hasher_1.finish(), hasher_2.finish());
/// ```
/// [Hasher]: std::hash::Hasher
/// [HashMap]: std::collections::HashMap
impl Default for AHasher {
    #[inline]
    fn default() -> AHasher {
        AHasher::new_with_keys(DEFAULT_KEYS[0], DEFAULT_KEYS[1])
    }
}

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
