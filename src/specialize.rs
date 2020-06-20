use crate::HasherExt;
use core::hash::Hash;

pub trait CallHasher: Hash {
    fn get_hash<H: HasherExt>(&self, hasher: H) -> u64;
}

#[cfg(not(feature = "specialize"))]
impl<T> CallHasher for T where T: Hash {
    fn get_hash<H: HasherExt>(&self, mut hasher: H) -> u64 {
        self.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(feature = "specialize")]
impl<T> CallHasher for T where T: Hash {
    default fn get_hash<H: HasherExt>(&self, mut hasher: H) -> u64 {
        self.hash(&mut hasher);
        hasher.finish()
    }
}

macro_rules! call_hasher_impl {
    ($typ:ty) => {
        #[cfg(feature = "specialize")]
        impl CallHasher for $typ {
            fn get_hash<H: HasherExt>(&self, mut hasher: H) -> u64 {
                self.hash(&mut hasher);
                hasher.short_finish()
            }
        }
    };
}
call_hasher_impl!(u64);
call_hasher_impl!(u32);
call_hasher_impl!(u16);
call_hasher_impl!(u8);

#[cfg(test)]
mod test {
    use super::*;
    use crate::*;

    #[test]
    #[cfg(feature = "specialize")]
    pub fn test_specialized_invoked() {
        let shortened = 0_u64.get_hash(AHasher::new_with_keys(1, 2));
        let mut hasher = AHasher::new_with_keys(1, 2);
        0_u64.hash(&mut hasher);
        assert_ne!(hasher.finish(), shortened);
    }

    /// Tests that some non-trivial transformation takes place.
    #[test]
    pub fn test_input_processed() {
        let hasher = || AHasher::new_with_keys(1, 2);
        assert_ne!(0, 0_u64.get_hash(hasher()));
        assert_ne!(1, 0_u64.get_hash(hasher()));
        assert_ne!(2, 0_u64.get_hash(hasher()));
        assert_ne!(3, 0_u64.get_hash(hasher()));

        assert_ne!(0, 1_u64.get_hash(hasher()));
        assert_ne!(1, 1_u64.get_hash(hasher()));
        assert_ne!(2, 1_u64.get_hash(hasher()));
        assert_ne!(3, 1_u64.get_hash(hasher()));

        let xored = 0_u64.get_hash(hasher()) ^ 1_u64.get_hash(hasher());
        assert_ne!(0, xored);
        assert_ne!(1, xored);
        assert_ne!(2, xored);
        assert_ne!(3, xored);
    }
}
