//! # aHash
//!
//! This hashing algorithm is intended to be a high performance, (hardware specific), keyed hash function.
//! This can be seen as a DOS resistant alternative to `FxHash`, or a fast equivalent to `SipHash`.
//! It provides a high speed hash algorithm, but where the result is not predictable without knowing a Key.
//! This allows it to be used in a `HashMap` without allowing for the possibility that an malicious user can
//! induce a collision.
//!
//! # How aHash works
//!
//! aHash uses the hardware AES instruction on x86 processors to provide a keyed hash function.
//! It uses two rounds of AES per hash. So it should not be considered cryptographically secure.
#![cfg_attr(not(test), no_std)]
//#![feature(core_intrinsics)]
extern crate const_random;
#[cfg(test)]
extern crate no_panic;

#[macro_use]
mod convert;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
mod aes_hash;
mod fallback_hash;
#[cfg(test)]
mod hash_quality_test;

use const_random::const_random;
use core::hash::BuildHasher;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
#[cfg(test)]
use no_panic::no_panic;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
pub use crate::aes_hash::AHasher;

#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
pub use crate::fallback_hash::AHasher;

/// A `HashMap` using `ABuildHasher` to hash the items.
//pub type AHashMap<K, V> = HashMap<K, V, ABuildHasher>;

///This constant come from Kunth's prng
const MULTIPLE: u64 = 6364136223846793005;

///Const random provides randomized starting key with no runtime cost.
static SEED: AtomicUsize = AtomicUsize::new(const_random!(u64));

/// Provides a default [Hasher] compile time generated constants for keys.
/// This is typically used in conjunction with [`BuildHasherDefault`] to create
/// [AHasher]s in order to hash the keys of the map.
///
/// # Example
/// ```
/// use std::hash::BuildHasherDefault;
/// use ahash::{AHasher, ABuildHasher};
/// use std::collections::HashMap;
///
/// let mut map: HashMap<i32, i32, ABuildHasher> = HashMap::default();
/// map.insert(12, 34);
/// ```
///
/// [BuildHasherDefault]: std::hash::BuildHasherDefault
/// [Hasher]: std::hash::Hasher
/// [HashMap]: std::collections::HashMap
impl Default for AHasher {
    /// Constructs a new [AHasher] with compile time generated constants for keys.
    /// This means the keys will be the same from one instance to another,
    /// but different from build to the next. So if it is possible for a potential
    /// attacker to have access to the compiled binary it would be better
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
    /// hasher_1.write_u32(1234);
    /// hasher_2.write_u32(1234);
    ///
    /// assert_eq!(hasher_1.finish(), hasher_2.finish());
    /// ```
    #[inline]
    fn default() -> AHasher {
        AHasher::new_with_keys(const_random!(u64), const_random!(u64))
    }
}

/// Provides a [Hasher] factory. This is typically used (e.g. by [`HashMap`]) to create
/// [AHasher]s in order to hash the keys of the map. See `build_hasher` below.
///
/// [build_hasher]: ahash::
/// [Hasher]: std::hash::Hasher
/// [BuildHasher]: std::hash::BuildHasher
/// [HashMap]: std::collections::HashMap
#[derive(Clone)]
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
pub struct ABuildHasher {
    k0: u64,
    k1: u64,
}

/// Provides a [Hasher] factory. This is typically used (e.g. by [HashMap]) to create
/// [AHasher]s in order to hash the keys of the map. See `build_hasher` below.
///
/// [build_hasher]: ahash::
/// [Hasher]: std::hash::Hasher
/// [BuildHasher]: std::hash::BuildHasher
#[derive(Clone)]
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
pub struct ABuildHasher {
    key: u64,
}

impl ABuildHasher {
    #[inline]
    pub fn new() -> ABuildHasher {
        //Using a self pointer. When running with ASLR this is a random value.
        let previous = SEED.load(Ordering::Relaxed) as u64;
        let stack_mem_loc = &previous as *const _ as u64;
        //This is similar to the update function in the fallback.
        //only one multiply is needed because memory locations are not under an attackers control.
        let current_seed = (previous ^ stack_mem_loc).wrapping_mul(MULTIPLE).rotate_left(31);
        SEED.store(current_seed as usize, Ordering::Relaxed);

        //Scramble seeds (based on xoroshiro128+)
        //This is intentionally not similar the hash algorithm
        let mut k0 = &SEED as *const _ as u64;
        let mut k1 = current_seed ^ k0;
        k0 = k0.rotate_left(24) ^ k1 ^ (k1 << 16);
        k1 = k1.rotate_left(37);

        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
        return ABuildHasher { k0, k1 };
        #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
        return ABuildHasher {
            key: k0.wrapping_add(k1),
        };
    }
}

impl Default for ABuildHasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl BuildHasher for ABuildHasher {
    type Hasher = AHasher;

    /// Constructs a new [AHasher] with keys based on compile time generated constants and the location
    /// of the this object in memory. This means that two different [BuildHasher]s will will generate
    /// [AHasher]s that will return different hashcodes, but [Hasher]s created from the same [BuildHasher]
    /// will generate the same hashes for the same input data.
    ///
    /// # Examples
    ///
    /// ```
    /// use ahash::{AHasher, ABuildHasher};
    /// use std::hash::{Hasher, BuildHasher};
    ///
    /// let build_hasher = ABuildHasher::new();
    /// let mut hasher_1 = build_hasher.build_hasher();
    /// let mut hasher_2 = build_hasher.build_hasher();
    ///
    /// hasher_1.write_u32(1234);
    /// hasher_2.write_u32(1234);
    ///
    /// assert_eq!(hasher_1.finish(), hasher_2.finish());
    ///
    /// let other_build_hasher = ABuildHasher::new();
    /// let mut different_hasher = other_build_hasher.build_hasher();
    /// different_hasher.write_u32(1234);
    /// assert_ne!(different_hasher.finish(), hasher_1.finish());
    /// ```
    /// [Hasher]: std::hash::Hasher
    /// [BuildHasher]: std::hash::BuildHasher
    /// [HashMap]: std::collections::HashMap
    #[inline]
    fn build_hasher(&self) -> AHasher {
        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
        return AHasher::new_with_keys(self.k0, self.k1);
        #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
        return AHasher::new_with_key(self.key);
    }
}

#[cfg(test)]
#[inline(never)]
#[no_panic]
#[no_mangle]
fn hash_test_final(num: i32, string: &str) -> (u64, u64) {
    use core::hash::Hasher;
    let builder = ABuildHasher::default();
    let mut hasher1 = builder.build_hasher();
    let mut hasher2 = builder.build_hasher();
    hasher1.write_i32(num);
    hasher2.write(string.as_bytes());
    (hasher1.finish(), hasher2.finish())
}

#[cfg(test)]
mod test {
    use crate::convert::Convert;
    use crate::*;
    use core::hash::BuildHasherDefault;
    use std::collections::HashMap;

    #[test]
    fn test_no_panic() {
        hash_test_final(2, "");
    }

    #[test]
    fn test_default_builder() {
        let mut map = HashMap::<u32, u64, BuildHasherDefault<AHasher>>::default();
        map.insert(1, 3);
    }
    #[test]
    fn test_builder() {
        let mut map = HashMap::<u32, u64, ABuildHasher>::default();
        map.insert(1, 3);
    }

    #[test]
    fn test_conversion() {
        let input: &[u8] = "dddddddd".as_bytes();
        let bytes: u64 = as_array!(input, 8).convert();
        assert_eq!(bytes, 0x6464646464646464);
    }
}
