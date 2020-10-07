use crate::convert::Convert;
use crate::{AHasher};
use core::fmt;
use core::hash::BuildHasher;
use core::hash::Hasher;
#[cfg(feature = "std")]
use lazy_static::*;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "std")]
lazy_static! {
    static ref SEEDS: [u64; 8] = {
        let mut result: [u8; 64] = [0; 64];
        getrandom::getrandom(&mut result).expect("getrandom::getrandom() failed.");
        result.convert()
    };
}
static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(crate) const PI: [u64;4] = [0x243f_6a88_85a3_08d3, 0x1319_8a2e_0370_7344, 0xA409_3822_299F_31D0, 0x082E_FA98_EC4E_6C89];

/// Provides a [Hasher] factory. This is typically used (e.g. by [HashMap]) to create
/// [AHasher]s in order to hash the keys of the map. See `build_hasher` below.
///
/// [build_hasher]: ahash::
/// [Hasher]: std::hash::Hasher
/// [BuildHasher]: std::hash::BuildHasher
/// [HashMap]: std::collections::HashMap
#[derive(Clone)]
pub struct RandomState {
    pub(crate) k0: u64,
    pub(crate) k1: u64,
    pub(crate) k2: u64,
    pub(crate) k3: u64,
}

impl fmt::Debug for RandomState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("RandomState { .. }")
    }
}

impl RandomState {
    #[inline]
    #[cfg(feature = "std")]
    pub fn new() -> RandomState {
        let seeds = *SEEDS;
        let mut hasher = AHasher::from_random_state(&RandomState{k0: seeds[0], k1: seeds[1], k2: seeds[2], k3: seeds[3]});
        let stack_mem_loc = &hasher as *const _ as usize;
        hasher.write_usize(COUNTER.fetch_add(stack_mem_loc, Ordering::Relaxed));
        let mix = |k: u64| {
            let mut h = hasher.clone();
            h.write_u64(k);
            h.finish()
        };
        RandomState { k0: mix(seeds[4]), k1: mix(seeds[5]), k2: mix(seeds[6]), k3: mix(seeds[7]) }
    }

    #[inline]
    #[cfg(all(not(feature = "std"), feature = "compile-time-rng"))]
    pub fn new() -> RandomState {
        let mut hasher = AHasher::from_random_state(&RandomState::with_fixed_keys());
        let stack_mem_loc = &hasher as *const _ as usize;
        hasher.write_usize(COUNTER.fetch_add(stack_mem_loc, Ordering::Relaxed));
        let mix = |k: u64| {
            let mut h = hasher.clone();
            h.write_u64(k);
            h.finish()
        };
        RandomState { k0: mix(const_random!(u64)), k1: mix(const_random!(u64)), k2: mix(const_random!(u64)), k3: mix(const_random!(u64)) }
    }

    #[inline]
    pub(crate) fn with_fixed_keys() -> RandomState {
        #[cfg(feature = "std")]
        {
            let seeds = *SEEDS;
            RandomState { k0: seeds[4], k1: seeds[5], k2: seeds[6], k3: seeds[7] }
        }
        #[cfg(all(not(feature = "std"), feature = "compile-time-rng"))]
        {
            RandomState { k0: const_random!(u64), k1: const_random!(u64), k2: const_random!(u64), k3: const_random!(u64) }
        }
        #[cfg(all(not(feature = "std"), not(feature = "compile-time-rng")))]
        {
            RandomState { k0: PI[3], k1: PI[2], k2: PI[1], k3: PI[0] }
        }        
    }

    /// Allows for explicitly setting the seeds to used.
    pub const fn with_seeds(k0: u64, k1: u64, k2: u64, k3: u64) -> RandomState {
        RandomState { k0, k1, k2, k3 }
    }
}

#[cfg(any(feature = "std", feature = "compile-time-rng"))]
impl Default for RandomState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl BuildHasher for RandomState {
    type Hasher = AHasher;

    /// Constructs a new [AHasher] with keys based on this [RandomState] object.
    /// This means that two different [RandomState]s will will generate
    /// [AHasher]s that will return different hashcodes, but [Hasher]s created from the same [BuildHasher]
    /// will generate the same hashes for the same input data.
    ///
    /// # Examples
    ///
    /// ```
    /// use ahash::{AHasher, RandomState};
    /// use std::hash::{Hasher, BuildHasher};
    ///
    /// let build_hasher = RandomState::new();
    /// let mut hasher_1 = build_hasher.build_hasher();
    /// let mut hasher_2 = build_hasher.build_hasher();
    ///
    /// hasher_1.write_u32(1234);
    /// hasher_2.write_u32(1234);
    ///
    /// assert_eq!(hasher_1.finish(), hasher_2.finish());
    ///
    /// let other_build_hasher = RandomState::new();
    /// let mut different_hasher = other_build_hasher.build_hasher();
    /// different_hasher.write_u32(1234);
    /// assert_ne!(different_hasher.finish(), hasher_1.finish());
    /// ```
    /// [Hasher]: std::hash::Hasher
    /// [BuildHasher]: std::hash::BuildHasher
    /// [HashMap]: std::collections::HashMap
    #[inline]
    fn build_hasher(&self) -> AHasher {
        AHasher::from_random_state(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn test_unique() {
        let a = RandomState::new();
        let b = RandomState::new();
        assert_ne!(a.build_hasher().finish(), b.build_hasher().finish());
    }

    #[test]
    fn test_with_seeds_const() {
        const _CONST_RANDOM_STATE: RandomState = RandomState::with_seeds(17, 19, 21, 23);
    }
}
