use crate::folded_multiply::FoldedMultiply;
use crate::{AHasher, RandomState};
use core::hash::Hash;
use core::hash::Hasher;

pub struct PrimitiveHasher {
    value: u64,
}

impl PrimitiveHasher {
    fn update(&mut self, value: u64) {
        self.value = (value ^ self.value).folded_multiply(&crate::random_state::MULTIPLE);
    }
}

impl Hasher for PrimitiveHasher {
    fn finish(&self) -> u64 {
        self.value
    }

    fn write(&mut self, _bytes: &[u8]) {
        unimplemented!()
    }

    fn write_u8(&mut self, i: u8) {
        self.update(i as u64);
    }

    fn write_u16(&mut self, i: u16) {
        self.update(i as u64);
    }

    fn write_u32(&mut self, i: u32) {
        self.update(i as u64);
    }

    fn write_u64(&mut self, i: u64) {
        self.update(i);
    }

    fn write_u128(&mut self, _i: u128) {
        unimplemented!()
    }

    fn write_usize(&mut self, i: usize) {
        self.update(i as u64);
    }

    fn write_i8(&mut self, i: i8) {
        self.update(i as u64);
    }

    fn write_i16(&mut self, i: i16) {
        self.update(i as u64);
    }

    fn write_i32(&mut self, i: i32) {
        self.update(i as u64);
    }

    fn write_i64(&mut self, i: i64) {
        self.update(i as u64);
    }

    fn write_i128(&mut self, _i: i128) {
        unimplemented!()
    }

    fn write_isize(&mut self, i: isize) {
        self.update(i as u64);
    }
}

pub trait Specialize<H: Hasher> {
    fn get_specialized_hasher(&self, state: &RandomState) -> H;
}

pub trait IsPrimitive: Hash {}
impl IsPrimitive for u8 {}
impl IsPrimitive for u16 {}
impl IsPrimitive for u32 {}
impl IsPrimitive for u64 {}
impl IsPrimitive for usize {}
impl IsPrimitive for i8 {}
impl IsPrimitive for i16 {}
impl IsPrimitive for i32 {}
impl IsPrimitive for i64 {}
impl IsPrimitive for isize {}

impl<T: Hash> Specialize<AHasher> for &T {
    fn get_specialized_hasher(&self, state: &RandomState) -> AHasher {
        AHasher::new_with_keys(state.k0, state.k1)
    }
}

impl<T: IsPrimitive> Specialize<PrimitiveHasher> for T {
    fn get_specialized_hasher(&self, state: &RandomState) -> PrimitiveHasher {
        PrimitiveHasher {
            value: state.k0.wrapping_add(state.k1),
        }
    }
}
