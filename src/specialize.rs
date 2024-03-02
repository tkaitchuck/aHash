use core::hash::BuildHasher;
use core::hash::Hash;
use core::hash::Hasher;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std as alloc;

#[cfg(feature = "specialize")]
use alloc::string::String;
#[cfg(feature = "specialize")]
use alloc::vec::Vec;
use crate::RandomState;

/// Provides a way to get an optimized hasher for a given data type.
/// Rather than using a Hasher generically which can hash any value, this provides a way to get a specialized hash
/// for a specific type. So this may be faster for primitive types.
pub(crate) trait CallHasher<T> {
    fn get_hash<H: Hash + ?Sized>(value: &H, build_hasher: &RandomState<T>) -> u64;
}

#[cfg(not(feature = "specialize"))]
impl<T> CallHasher<T> for T {
    #[inline]
    fn get_hash<H: Hash + ?Sized>(value: &H, build_hasher: &RandomState<T>) -> u64 {
        let mut hasher = build_hasher.build_hasher();
        value.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(feature = "specialize")]
impl<T> CallHasher<T> for T {
    #[inline]
    default fn get_hash<H: Hash + ?Sized>(value: &H, build_hasher: &RandomState<T>) -> u64 {
        let mut hasher = build_hasher.build_hasher();
        value.hash(&mut hasher);
        hasher.finish()
    }
}

macro_rules! call_hasher_impl_u64 {
    ($typ:ty) => {
        #[cfg(feature = "specialize")]
        impl CallHasher<$typ> for $typ {
            #[inline]
            fn get_hash<H: Hash + ?Sized>(value: &H, build_hasher: &RandomState<$typ>) -> u64 {
                build_hasher.hash_as_u64(value)
            }
        }
    };
}
call_hasher_impl_u64!(u8);
call_hasher_impl_u64!(u16);
call_hasher_impl_u64!(u32);
call_hasher_impl_u64!(u64);
call_hasher_impl_u64!(i8);
call_hasher_impl_u64!(i16);
call_hasher_impl_u64!(i32);
call_hasher_impl_u64!(i64);

macro_rules! call_hasher_impl_fixed_length{
    ($typ:ty) => {
        #[cfg(feature = "specialize")]
        impl CallHasher<$typ> for $typ {
            #[inline]
            fn get_hash<H: Hash + ?Sized>(value: &H, build_hasher: &RandomState<$typ>) -> u64 {
                build_hasher.hash_as_fixed_length(value)
            }
        }
    };
}

call_hasher_impl_fixed_length!(u128);
call_hasher_impl_fixed_length!(i128);
call_hasher_impl_fixed_length!(usize);
call_hasher_impl_fixed_length!(isize);

#[cfg(feature = "specialize")]
impl CallHasher<Vec<u8>> for Vec<u8> {
    #[inline]
    fn get_hash<H: Hash + ?Sized>(value: &H, build_hasher: &RandomState<Vec<u8>>) -> u64 {
        build_hasher.hash_as_str(value)
    }
}

#[cfg(all(feature = "specialize"))]
impl CallHasher<String> for String {
    #[inline]
    fn get_hash<H: Hash + ?Sized>(value: &H, build_hasher: &RandomState<String>) -> u64 {
        build_hasher.hash_as_str(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::*;

    #[test]
    #[cfg(feature = "specialize")]
    pub fn test_specialized_invoked() {
        let build_hasher = RandomState::with_seeds(1, 2, 3, 4);
        let shortened = u64::get_hash(&0, &build_hasher);
        let mut hasher = AHasher::new_with_keys(1, 2);
        0_u64.hash(&mut hasher);
        assert_ne!(hasher.finish(), shortened);
    }

    /// Tests that some non-trivial transformation takes place.
    #[test]
    pub fn test_input_processed() {
        let build_hasher = RandomState::with_fixed_keys();
        assert_ne!(0, u64::get_hash(&0, &build_hasher));
        assert_ne!(1, u64::get_hash(&0, &build_hasher));
        assert_ne!(2, u64::get_hash(&0, &build_hasher));
        assert_ne!(3, u64::get_hash(&0, &build_hasher));
        assert_ne!(4, u64::get_hash(&0, &build_hasher));
        assert_ne!(5, u64::get_hash(&0, &build_hasher));

        assert_ne!(0, u64::get_hash(&1, &build_hasher));
        assert_ne!(1, u64::get_hash(&1, &build_hasher));
        assert_ne!(2, u64::get_hash(&1, &build_hasher));
        assert_ne!(3, u64::get_hash(&1, &build_hasher));
        assert_ne!(4, u64::get_hash(&1, &build_hasher));
        assert_ne!(5, u64::get_hash(&1, &build_hasher));

        let xored = u64::get_hash(&0, &build_hasher) ^ u64::get_hash(&1, &build_hasher);
        assert_ne!(0, xored);
        assert_ne!(1, xored);
        assert_ne!(2, xored);
        assert_ne!(3, xored);
        assert_ne!(4, xored);
        assert_ne!(5, xored);
    }

    #[test]
    pub fn test_ref_independent() {
        let build_hasher = RandomState::<u8>::with_seed(1);
        assert_eq!(u8::get_hash(&&1, &build_hasher), u8::get_hash(&1, &build_hasher));
        assert_eq!(build_hasher.hash_one(1_u8), build_hasher.hash_one(&1_u8));

        let build_hasher = RandomState::<u16>::with_seed(1);
        assert_eq!(u16::get_hash(&&2_u16, &build_hasher), u16::get_hash(&2_u16, &build_hasher));
        assert_eq!(build_hasher.hash_one(2_u16), build_hasher.hash_one(&2_u16));

        let build_hasher = RandomState::<u32>::with_seed(1);
        assert_eq!(u32::get_hash(&&3_u32, &build_hasher), u32::get_hash(&3_u32, &build_hasher));
        assert_eq!(build_hasher.hash_one(3_u32), build_hasher.hash_one(&3_u32));

        let build_hasher = RandomState::<u64>::with_seed(1);
        assert_eq!(u64::get_hash(&&4_u64, &build_hasher), u64::get_hash(&4_u64, &build_hasher));
        assert_eq!(build_hasher.hash_one(4_u64), build_hasher.hash_one(&4_u64));

        let build_hasher = RandomState::<u128>::with_seed(1);
        assert_eq!(u128::get_hash(&&5, &build_hasher), u128::get_hash(&5, &build_hasher));
        assert_eq!(build_hasher.hash_one(5_u128), build_hasher.hash_one(&5_u128));


        let build_hasher = RandomState::<String>::with_seed(1);

        assert_eq!(
            build_hasher.hash_one(&"test"),
            build_hasher.hash_one("test")
        );
        assert_eq!(
            build_hasher.hash_one(&"test"),
            build_hasher.hash_one(&"test".to_string())
        );
        assert_eq!(
            build_hasher.hash_one(&"test"),
            build_hasher.hash_one("test".as_bytes())
        );

        let build_hasher = RandomState::<u8>::with_seed(1);
        assert_eq!(u8::get_hash(&&&1, &build_hasher), u8::get_hash(&1, &build_hasher));
        assert_eq!(build_hasher.hash_one(1_u8), build_hasher.hash_one(&1_u8));

        let build_hasher = RandomState::<u16>::with_seed(1);
        assert_eq!(u16::get_hash(&&&2_u16, &build_hasher), u16::get_hash(&2_u16, &build_hasher));
        assert_eq!(build_hasher.hash_one(&&&2_u16), build_hasher.hash_one(&2_u16));

        let build_hasher = RandomState::<u32>::with_seed(1);
        assert_eq!(u32::get_hash(&&&3_u32, &build_hasher), u32::get_hash(&3_u32, &build_hasher));
        assert_eq!(build_hasher.hash_one(&&&3_u32), build_hasher.hash_one(&3_u32));

        let build_hasher = RandomState::<u64>::with_seed(1);
        assert_eq!(u64::get_hash(&&&4_u64, &build_hasher), u64::get_hash(&4_u64, &build_hasher));
        assert_eq!(build_hasher.hash_one(&&&4_u64), build_hasher.hash_one(&4_u64));

        let build_hasher = RandomState::<u128>::with_seed(1);
        assert_eq!(u128::get_hash(&&&5, &build_hasher), u128::get_hash(&5, &build_hasher));
        assert_eq!(build_hasher.hash_one(&&&5_u128), build_hasher.hash_one(&5_u128));


        let build_hasher = RandomState::<String>::with_seeds(1, 2, 3, 4);

        assert_eq!(
            build_hasher.hash_one(&&"test"),
            build_hasher.hash_one("test")
        );
        assert_eq!(
            build_hasher.hash_one(&&"test"),
            build_hasher.hash_one(&"test".to_string())
        );
        assert_eq!(
            build_hasher.hash_one(&&"test"),
            build_hasher.hash_one(&"test".to_string().into_bytes())
        );
    }
}
