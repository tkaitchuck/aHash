use core::hash::Hash;
cfg_if::cfg_if! {
    if #[cfg(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)),
        all(target_arch = "aarch64", target_feature = "aes", not(miri)),
        all(target_arch = "arm", target_feature = "aes", not(miri)),
    ))] {
        use crate::aes_hash::*;
    } else {
        use crate::fallback_hash::*;
    }
}
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        extern crate std as alloc;
    } else {
        extern crate alloc;
    }
}

#[cfg(feature = "atomic-polyfill")]
use atomic_polyfill as atomic;
#[cfg(not(feature = "atomic-polyfill"))]
use core::sync::atomic;

use alloc::boxed::Box;
use atomic::{AtomicUsize, Ordering};
use core::any::{Any, TypeId};
use core::fmt;
use core::hash::BuildHasher;
use core::hash::Hasher;
use core::marker::PhantomData;
use crate::convert::Convert;
use crate::operations::{folded_multiply};

pub(crate) const PI: [u64; 4] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
];

pub(crate) const PI2: [u64; 4] = [
    0x4528_21e6_38d0_1377,
    0xbe54_66cf_34e9_0c6c,
    0xc0ac_29b7_c97c_50dd,
    0x3f84_d5b5_b547_0917,
];

cfg_if::cfg_if! {
    if #[cfg(all(feature = "compile-time-rng", any(test, fuzzing)))] {
        #[inline]
        fn get_fixed_seeds() -> &'static [[u64; 4]; 2] {
            use const_random::const_random;

            const RAND: [[u64; 4]; 2] = [
                [
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                ], [
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                ]
            ];
            &RAND
        }
    } else if #[cfg(all(feature = "runtime-rng", not(fuzzing)))] {
        #[inline]
        fn get_fixed_seeds() -> &'static [[u64; 4]; 2] {
            use crate::convert::Convert;

            static SEEDS: OnceBox<[[u64; 4]; 2]> = OnceBox::new();

            SEEDS.get_or_init(|| {
                let mut result: [u8; 64] = [0; 64];
                getrandom::getrandom(&mut result).expect("getrandom::getrandom() failed.");
                Box::new(result.convert())
            })
        }
    } else if #[cfg(feature = "compile-time-rng")] {
        #[inline]
        fn get_fixed_seeds() -> &'static [[u64; 4]; 2] {
            use const_random::const_random;

            const RAND: [[u64; 4]; 2] = [
                [
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                ], [
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                    const_random!(u64),
                ]
            ];
            &RAND
        }
    } else {
        #[inline]
        fn get_fixed_seeds() -> &'static [[u64; 4]; 2] {
            &[PI, PI2]
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(all(target_arch = "arm", target_os = "none")))] {
        use once_cell::race::OnceBox;

        static RAND_SOURCE: OnceBox<Box<dyn RandomSource + Send + Sync>> = OnceBox::new();
    }
}
/// A supplier of Randomness used for different hashers.
/// See [set_random_source].
///
/// If [set_random_source] aHash will default to the best available source of randomness.
/// In order this is:
/// 1. OS provided random number generator (available if the `runtime-rng` flag is enabled which it is by default) - This should be very strong.
/// 2. Strong compile time random numbers used to permute a static "counter". (available if `compile-time-rng` is enabled.
/// __Enabling this is recommended if `runtime-rng` is not possible__)
/// 3. A static counter that adds the memory address of each [RandomState] created permuted with fixed constants.
/// (Similar to above but with fixed keys) - This is the weakest option. The strength of this heavily depends on whether or not ASLR is enabled.
/// (Rust enables ASLR by default)
pub trait RandomSource {
    fn gen_hasher_seed(&self) -> usize;
}

struct DefaultRandomSource {
    counter: AtomicUsize,
}

impl DefaultRandomSource {
    fn new() -> DefaultRandomSource {
        DefaultRandomSource {
            counter: AtomicUsize::new(&PI as *const _ as usize),
        }
    }

    #[cfg(all(target_arch = "arm", target_os = "none"))]
    const fn default() -> DefaultRandomSource {
        DefaultRandomSource {
            counter: AtomicUsize::new(PI[3] as usize),
        }
    }
}

impl RandomSource for DefaultRandomSource {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "arm", target_os = "none"))] {
            fn gen_hasher_seed(&self) -> usize {
                let stack = self as *const _ as usize;
                let previous = self.counter.load(Ordering::Relaxed);
                let new = previous.wrapping_add(stack | 1);
                self.counter.store(new, Ordering::Relaxed);
                new
            }
        } else {
            fn gen_hasher_seed(&self) -> usize {
                let stack = self as *const _ as usize;
                self.counter.fetch_add(stack | 1, Ordering::Relaxed)
            }
        }
    }
}

cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "arm", target_os = "none"))] {
            #[inline]
            fn get_src() -> &'static dyn RandomSource {
                static RAND_SOURCE: DefaultRandomSource = DefaultRandomSource::default();
                &RAND_SOURCE
            }
        } else {
            /// Provides an optional way to manually supply a source of randomness for Hasher keys.
            ///
            /// The provided [RandomSource] will be used to be used as a source of randomness by [RandomState] to generate new states.
            /// If this method is not invoked the standard source of randomness is used as described in the Readme.
            ///
            /// The source of randomness can only be set once, and must be set before the first RandomState is created.
            /// If the source has already been specified `Err` is returned with a `bool` indicating if the set failed because
            /// method was previously invoked (true) or if the default source is already being used (false).
            #[cfg(not(all(target_arch = "arm", target_os = "none")))]
            pub fn set_random_source(source: impl RandomSource + Send + Sync + 'static) -> Result<(), bool> {
                RAND_SOURCE.set(Box::new(Box::new(source))).map_err(|s| s.as_ref().type_id() != TypeId::of::<&DefaultRandomSource>())
            }

            #[inline]
            fn get_src() -> &'static dyn RandomSource {
                RAND_SOURCE.get_or_init(|| Box::new(Box::new(DefaultRandomSource::new()))).as_ref()
            }
        }
}

/// Provides a [Hasher] factory. This is typically used (e.g. by [HashMap]) to create
/// [AHasher]s in order to hash the keys of the map. See `build_hasher` below.
///
/// [Hasher]: std::hash::Hasher
/// [BuildHasher]: std::hash::BuildHasher
/// [HashMap]: std::collections::HashMap
///
/// # Type parameter
/// `RandomState<T>` takes a type parameter `T`. This type is used to determine which hashing 
/// algorithm will be used. Normally this is the type of the items to be hashed.
/// However, it is also possible hash other types provided their implementation of [Hash] is
/// functionally the same as the `T`'s implementation of [Hash]. 
/// (Or if one derefs into the other). 
/// 
/// For example, it is possible to use a `RandomState<String>` to hash not only `String`s but also 
/// `&str`s, `Box<str>`s, or `&Box<String>`:
/// ```
/// use std::hash::BuildHasher;
/// use ahash::RandomState;
/// 
/// let state = RandomState::<String>::new();
/// let v1 = state.hash_one("foo");
/// let v2 = state.hash_one(&Box::new("foo"));
/// assert_eq!(v1, v2);
/// ```
/// This is convenient because it avoids the need to declare lifetimes.
/// 
/// Similarly, it is possible to use a `RandomState<u64>` to hash a `&u64` or a `Box<u64>` etc.
/// 
/// If you wish to hash items of heterogeneous types use `RandomState<()>`. This will use a generic 
/// algorithm which will work for any type.
/// ```
/// use std::hash::BuildHasher;
/// use ahash::RandomState;
/// 
/// let state = RandomState::<()>::new();
/// let foo_hash = state.hash_one("foo");
/// let num_hash = state.hash_one(1234);
/// ```
///
/// # Constructors
/// There are multiple constructors each is documented in more detail below:
///
/// | Constructor   | Dynamically random? | Seed |
/// |---------------|---------------------|------|
/// |`new`          | Each instance unique|_[RandomSource]_|
/// |`generate_with`| Each instance unique|`u64` x 4 + [RandomSource]|
/// |`with_seed`    | Fixed per process   |`u64` + static random number|
/// |`with_seeds`   | Fixed               |`u64` x 4|
///
#[derive(Clone)]
pub struct RandomState<T> {
    pub(crate) k0: u64,
    pub(crate) k1: u64,
    pub(crate) k2: u64,
    pub(crate) k3: u64,
    _h: PhantomData<T>,
}

/// Provides a Hasher factory similar to [RandomState] that uses less memory at the cost
/// of a slower `build_hasher` function. (Which is generally called once per item hashed)
/// In general [RandomState] should be preferred unless there is a need for reduced memory use.
#[derive(Clone)]
pub struct SmallState<T> {
    key: u64,
    _h: PhantomData<T>,
}

impl <T> fmt::Debug for RandomState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("RandomState { .. }")
    }
}

impl <T> fmt::Debug for SmallState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("SmallState { .. }")
    }
}

impl <T> RandomState<T> {
    /// Create a new `RandomState` `BuildHasher` using random keys.
    ///
    /// Each instance will have a unique set of keys derived from [RandomSource].
    ///
    #[inline]
    pub fn new() -> RandomState<T> {
        let src = get_src();
        let fixed = get_fixed_seeds();
        let mixed = Self::pre_mix_key(&fixed[0], src.gen_hasher_seed());
        Self::from_keys(&fixed[0], &fixed[1], mixed)
    }

    /// Create a new `RandomState` `BuildHasher` based on the provided seeds, but in such a way
    /// that each time it is called the resulting state will be different and of high quality.
    /// This allows fixed constant or poor quality seeds to be provided without the problem of different
    /// `BuildHasher`s being identical or weak.
    ///
    /// This is done via permuting the provided values with the value of a static counter and memory address.
    /// (This makes this method somewhat more expensive than `with_seeds` below which does not do this).
    ///
    /// The provided values (k0-k3) do not need to be of high quality but they should not all be the same value.
    #[inline]
    pub fn generate_with(k0: u64, k1: u64, k2: u64, k3: u64) -> RandomState<T> {
        let src = get_src();
        let fixed = get_fixed_seeds();
        let mixed = Self::pre_mix_key(&fixed[0], src.gen_hasher_seed());
        RandomState::from_keys(&fixed[0], &[k0, k1, k2, k3], mixed)
    }

    #[inline]
    fn pre_mix_key(a: &[u64; 4], c: usize) -> u64 {
        let &[k0, k1, _k2, _k3] = a;
        folded_multiply(k0 ^ c as u64, k1)
    }

    #[inline]
    fn from_keys(a: &[u64; 4], b: &[u64; 4], pre_mixed_key: u64) -> RandomState<T> {
        let &[_k0, _k1, k2, k3] = a;
        let c1 = folded_multiply(pre_mixed_key, k2);
        let c2 = folded_multiply(pre_mixed_key, k3);
        RandomState {
            k0: (c1 ^ b[0]).wrapping_add(b[2]),
            k1: (c1 ^ b[1]).wrapping_add(b[3]),
            k2: (c2 ^ b[2]).wrapping_add(b[1]),
            k3: (c2 ^ b[3]).wrapping_add(b[0]),
            _h: PhantomData::default(),
        }
    }
    
    /// Internal. Used by Default.
    #[inline]
    pub(crate) fn with_fixed_keys() -> RandomState<T> {
        let [k0, k1, k2, k3] = get_fixed_seeds()[0];
        RandomState { k0, k1, k2, k3, _h: PhantomData::default() }
    }

    /// Build a `RandomState` from a single key. The provided key does not need to be of high quality,
    /// but all `RandomState`s created from the same key will produce identical hashers.
    /// (In contrast to `generate_with` above)
    ///
    /// This allows for explicitly setting the seed to be used.
    ///
    /// Note: This method does not require the provided seed to be strong.
    #[inline]
    pub fn with_seed(key: usize) -> RandomState<T> {
        let fixed = get_fixed_seeds();
        let mixed = RandomState::<T>::pre_mix_key(&fixed[0], key);
        RandomState::from_keys(&fixed[0], &fixed[1], mixed)
    }

    /// Allows for explicitly setting the seeds to used.
    /// All `RandomState`s created with the same set of keys key will produce identical hashers.
    /// (In contrast to `generate_with` above)
    ///
    /// Note: If DOS resistance is desired one of these should be a decent quality random number.
    /// If 4 high quality random number are not cheaply available this method is robust against 0s being passed for
    /// one or more of the parameters or the same value being passed for more than one parameter.
    /// It is recommended to pass numbers in order from highest to lowest quality (if there is any difference).
    #[inline]
    pub const fn with_seeds(k0: u64, k1: u64, k2: u64, k3: u64) -> RandomState<T> {
        RandomState {
            k0: k0 ^ PI2[0],
            k1: k1 ^ PI2[1],
            k2: k2 ^ PI2[2],
            k3: k3 ^ PI2[3],
            _h: PhantomData,
        }
    }


    #[inline]
    #[cfg(feature = "specialize")]
    pub(crate) fn hash_as_u64<V: Hash + ?Sized>(&self, value: &V) -> u64 {
        let mut hasher = AHasherU64 {
            buffer: self.k0,
            pad: self.k1,
        };
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[inline]
    #[cfg(feature = "specialize")]
    pub(crate) fn hash_as_fixed_length<V: Hash + ?Sized>(&self, value: &V) -> u64 {
        let mut hasher = AHasherFixed(self.build_hasher());
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[inline]
    #[cfg(feature = "specialize")]
    pub(crate) fn hash_as_str<V: Hash + ?Sized>(&self, value: &V) -> u64 {
        let mut hasher = AHasherStr(self.build_hasher());
        value.hash(&mut hasher);
        hasher.finish()
    }
}

impl <T> SmallState<T> {
    /// Create a new `SmallState` `BuildHasher` using random keys.
    ///
    /// Each instance will have a unique set of keys derived from [RandomSource].
    ///
    #[inline]
    pub fn new() -> SmallState<T> {
        let fixed = get_fixed_seeds();
        let mixed = RandomState::<T>::pre_mix_key(&fixed[0], get_src().gen_hasher_seed());
        SmallState {
            key: mixed,
            _h: Default::default(),
        }
    }

    /// Build a `SmallState` from a single key. The provided key does not need to be of high quality,
    /// but all `SmallState`s created from the same key will produce identical hashers.
    /// (In contrast to `new` above)
    ///
    /// This allows for explicitly setting the seed to be used.
    ///
    /// Note: This method does not require the provided seed to be strong.
    #[inline]
    pub fn with_seed(key: usize) -> SmallState<T> {
        let fixed = get_fixed_seeds();
        let mixed = RandomState::<T>::pre_mix_key(&fixed[0], key);
        SmallState {
            key: mixed,
            _h: Default::default(),
        }
    }
}

/// Creates an instance of RandomState using keys obtained from the random number generator.
/// Each instance created in this way will have a unique set of keys. (But the resulting instance
/// can be used to create many hashers each or which will have the same keys.)
///
/// This is the same as [RandomState::new()]
///
/// NOTE: For safety this trait impl is only available available if either of the flags `runtime-rng` (on by default) or
/// `compile-time-rng` are enabled. This is to prevent weakly keyed maps from being accidentally created. Instead one of
/// constructors for [RandomState] must be used.
#[cfg(any(feature = "compile-time-rng", feature = "runtime-rng", feature = "no-rng"))]
impl <T> Default for RandomState<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Creates an instance of SmallState using keys obtained from the random number generator.
/// Each instance created in this way will have a unique set of keys. (But the resulting instance
/// can be used to create many hashers each or which will have the same keys.)
///
/// This is the same as [SmallState::new()]
#[cfg(any(feature = "compile-time-rng", feature = "runtime-rng", feature = "no-rng"))]
impl <T> Default for SmallState<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl <T> BuildHasher for RandomState<T> {
    type Hasher = AHasher;

    /// Constructs a new [AHasher] with keys based on this [RandomState] object.
    /// This means that two different [RandomState]s will will generate
    /// [AHasher]s that will return different hashcodes, but [Hasher]s created from the same [BuildHasher]
    /// will generate the same hashes for the same input data.
    ///
    #[cfg_attr(
        feature = "std",
        doc = r##" # Examples
```
        use ahash::{AHasher, RandomState};
        use std::hash::{Hasher, BuildHasher};
    
        let build_hasher = RandomState::<u32>::new();
        let mut hasher_1 = build_hasher.build_hasher();
        let mut hasher_2 = build_hasher.build_hasher();
    
        hasher_1.write_u32(1234);
        hasher_2.write_u32(1234);
    
        assert_eq!(hasher_1.finish(), hasher_2.finish());
    
        let other_build_hasher = RandomState::<u32>::new();
        let mut different_hasher = other_build_hasher.build_hasher();
        different_hasher.write_u32(1234);
        assert_ne!(different_hasher.finish(), hasher_1.finish());
```
    "##
    )]
    /// [Hasher]: std::hash::Hasher
    /// [BuildHasher]: std::hash::BuildHasher
    /// [HashMap]: std::collections::HashMap
    #[inline]
    fn build_hasher(&self) -> AHasher {
        AHasher::from_random_state(self)
    }

    /// Calculates the hash of a single value. This provides a more convenient (and faster) way to obtain a hash:
    /// For example:
    #[cfg_attr(
        feature = "std",
        doc = r##" # Examples
```
    use std::hash::BuildHasher;
    use ahash::RandomState;

    let hash_builder = RandomState::<String>::new();
    let hash = hash_builder.hash_one("Some Data");
```
    "##
    )]
    /// This is similar to:
    #[cfg_attr(
        feature = "std",
        doc = r##" # Examples
```
    use std::hash::{BuildHasher, Hash, Hasher};
    use ahash::RandomState;

    let hash_builder = RandomState::<String>::new();
    let mut hasher = hash_builder.build_hasher();
    "Some Data".hash(&mut hasher);
    let hash = hasher.finish();
```
    "##
    )]
    /// (Note that these two ways to get a hash may not produce the same value for the same data)
    ///
    /// This is intended as a convenience for code which *consumes* hashes, such
    /// as the implementation of a hash table or in unit tests that check
    /// whether a custom [`Hash`] implementation behaves as expected.
    ///
    /// This must not be used in any code which *creates* hashes, such as in an
    /// implementation of [`Hash`].  The way to create a combined hash of
    /// multiple values is to call [`Hash::hash`] multiple times using the same
    /// [`Hasher`], not to call this method repeatedly and combine the results.
    #[inline]
    fn hash_one<V: Hash>(&self, x: V) -> u64 {
        use crate::specialize::CallHasher;
        T::get_hash(&x, self)
    }
}

impl <T> BuildHasher for SmallState<T> {
    type Hasher = AHasher;

    /// Constructs a new [AHasher] with keys based on this [SmallState] object.
    /// This means that two different [SmallState]s will will generate
    /// [AHasher]s that will return different hashcodes, but [Hasher]s created from the same [BuildHasher]
    /// will generate the same hashes for the same input data.
    ///
    #[cfg_attr(
    feature = "std",
    doc = r##" # Examples
```
        use ahash::{AHasher, SmallState};
        use std::hash::{Hasher, BuildHasher};

        let build_hasher = SmallState::<u32>::new();
        let mut hasher_1 = build_hasher.build_hasher();
        let mut hasher_2 = build_hasher.build_hasher();

        hasher_1.write_u32(1234);
        hasher_2.write_u32(1234);

        assert_eq!(hasher_1.finish(), hasher_2.finish());

        let other_build_hasher = SmallState::<u32>::new();
        let mut different_hasher = other_build_hasher.build_hasher();
        different_hasher.write_u32(1234);
        assert_ne!(different_hasher.finish(), hasher_1.finish());
```
    "##
    )]
    /// [Hasher]: std::hash::Hasher
    /// [BuildHasher]: std::hash::BuildHasher
    /// [HashMap]: std::collections::HashMap
    #[inline]
    fn build_hasher(&self) -> AHasher {
        let fixed = get_fixed_seeds();
        AHasher::from_random_state(&RandomState::<T>::from_keys(&fixed[0], &fixed[1], self.key))
    }

    /// Calculates the hash of a single value. This provides a more convenient (and faster) way to obtain a hash:
    /// For example:
    #[cfg_attr(
    feature = "std",
    doc = r##" # Examples
```
    use std::hash::BuildHasher;
    use ahash::SmallState;

    let hash_builder = SmallState::<String>::new();
    let hash = hash_builder.hash_one("Some Data");
```
    "##
    )]
    /// This is similar to:
    #[cfg_attr(
    feature = "std",
    doc = r##" # Examples
```
    use std::hash::{BuildHasher, Hash, Hasher};
    use ahash::SmallState;

    let hash_builder = SmallState::<String>::new();
    let mut hasher = hash_builder.build_hasher();
    "Some Data".hash(&mut hasher);
    let hash = hasher.finish();
```
    "##
    )]
    /// (Note that these two ways to get a hash may not produce the same value for the same data)
    ///
    /// This is intended as a convenience for code which *consumes* hashes, such
    /// as the implementation of a hash table or in unit tests that check
    /// whether a custom [`Hash`] implementation behaves as expected.
    ///
    /// This must not be used in any code which *creates* hashes, such as in an
    /// implementation of [`Hash`].  The way to create a combined hash of
    /// multiple values is to call [`Hash::hash`] multiple times using the same
    /// [`Hasher`], not to call this method repeatedly and combine the results.
    #[inline]
    fn hash_one<V: Hash>(&self, x: V) -> u64 {
        use crate::specialize::CallHasher;
        let fixed = get_fixed_seeds();
        T::get_hash(&x, &RandomState::<T>::from_keys(&fixed[0], &fixed[1], self.key))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_unique() {
        let a = RandomState::<()>::generate_with(1, 2, 3, 4);
        let b = RandomState::<()>::generate_with(1, 2, 3, 4);
        assert_ne!(a.build_hasher().finish(), b.build_hasher().finish());
    }

    #[cfg(all(feature = "runtime-rng", not(all(feature = "compile-time-rng", test))))]
    #[test]
    fn test_not_pi() {
        assert_ne!(PI, get_fixed_seeds()[0]);
    }

    #[cfg(all(feature = "compile-time-rng", any(not(feature = "runtime-rng"), test)))]
    #[test]
    fn test_not_pi_const() {
        assert_ne!(PI, get_fixed_seeds()[0]);
    }

    #[cfg(all(not(feature = "runtime-rng"), not(feature = "compile-time-rng")))]
    #[test]
    fn test_pi() {
        assert_eq!(PI, get_fixed_seeds()[0]);
    }

    #[test]
    fn test_with_seeds_const() {
        const _CONST_RANDOM_STATE: RandomState<String> = RandomState::with_seeds(17, 19, 21, 23);
    }
}
