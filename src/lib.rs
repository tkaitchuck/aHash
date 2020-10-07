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
#![deny(clippy::correctness, clippy::complexity, clippy::perf)]
#![allow(clippy::pedantic, clippy::cast_lossless, clippy::unreadable_literal)]

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

#[macro_use]
mod convert;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
mod aes_hash;
mod fallback_hash;
#[cfg(test)]
mod hash_quality_test;

#[cfg(feature = "std")]
mod hash_map;
#[cfg(feature = "std")]
mod hash_set;

#[cfg(feature = "compile-time-rng")]
use const_random::const_random;

use core::hash::BuildHasher;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
pub use crate::aes_hash::AHasher;

#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")))]
pub use crate::fallback_hash::AHasher;

#[cfg(feature = "std")]
pub use crate::hash_map::AHashMap;
#[cfg(feature = "std")]
pub use crate::hash_set::AHashSet;

///This constant come from Kunth's prng
const MULTIPLE: u64 = 6364136223846793005;

// Const random provides randomized starting key with no runtime cost.
#[cfg(feature = "compile-time-rng")]
static SEED: AtomicUsize = AtomicUsize::new(const_random!(u64) as usize);

#[cfg(not(feature = "compile-time-rng"))]
static SEED: AtomicUsize = AtomicUsize::new(MULTIPLE as usize);

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
#[cfg(feature = "compile-time-rng")]
impl Default for AHasher {
    /// Constructs a new [AHasher] with compile time generated constants for keys.
    /// This means the keys will be the same from one instance to another,
    /// but different from build to the next. So if it is possible for a potential
    /// attacker to have access to the compiled binary it would be better
    /// to specify keys generated at runtime.
    ///
    /// This is defined only if the `compile-time-rng` feature is enabled.
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
pub struct ABuildHasher {
    k0: u64,
    k1: u64,
}

impl ABuildHasher {
    #[inline]
    pub fn new() -> ABuildHasher {
        //Using a self pointer. When running with ASLR this is a random value.
        let previous = SEED.load(Ordering::Relaxed) as u64;
        let stack_mem_loc = &previous as *const _ as u64;
        //This is similar to the update function in the fallback.
        //only one multiply is needed because memory locations are not under an attackers control.
        let current_seed = previous.wrapping_mul(MULTIPLE).wrapping_add(stack_mem_loc).rotate_left(31);
        SEED.store(current_seed as usize, Ordering::Relaxed);
        ABuildHasher {
            k0: &SEED as *const _ as u64,
            k1: current_seed
        }
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

    /// Constructs a new [AHasher] with keys based on compile time generated constants** and the location
    /// of the this object in memory. This means that two different [BuildHasher]s will will generate
    /// [AHasher]s that will return different hashcodes, but [Hasher]s created from the same [BuildHasher]
    /// will generate the same hashes for the same input data.
    ///
    /// ** - only if the `compile-time-rng` feature is enabled.
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
        let (k0, k1) = scramble_keys(self.k0, self.k1);
        AHasher::new_with_keys(k0, k1)
    }
}

pub(crate) fn scramble_keys(k0: u64, k1: u64) -> (u64, u64) {
    //Scramble seeds (based on xoroshiro128+)
    //This is intentionally not similar the hash algorithm
    let result1 = k0.wrapping_add(k1);
    let k1 = k1 ^ k0;
    let k0 = k0.rotate_left(24) ^ k1 ^ (k1.wrapping_shl(16));
    let result2 = k0.wrapping_add(k1.rotate_left(37));
    (result2, result1)
}

#[cfg(test)]
mod test {
    use crate::convert::Convert;
    use crate::*;
    use core::hash::BuildHasherDefault;
    use std::collections::HashMap;

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
        let input: &[u8] = b"dddddddd";
        let bytes: u64 = as_array!(input, 8).convert();
        assert_eq!(bytes, 0x6464646464646464);
    }

    #[test]
    fn test_ahasher_construction() {
        let _ = AHasher::new_with_keys(1245, 5678);
    }
}
