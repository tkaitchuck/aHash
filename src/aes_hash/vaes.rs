use crate::convert::Convert;
use crate::operations::{add_by_64s, aesenc};

use super::AHasher;

mod intrinsic {
    #[cfg(target_arch = "x86")]
    pub use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    pub use core::arch::x86_64::*;
}

const SHUFFLE_MASKS: [u64; 2] = [0x020a0700_0c01030e_u64, 0x050f0d08_06090b04_u64];

#[derive(Copy, Clone)]
#[repr(transparent)]
struct Avx256(intrinsic::__m256i);

trait ReadFromSliceExt {
    fn read_last_avx256x4(&self) -> [Avx256; 4];
    fn read_avx256x4(&self) -> ([Avx256; 4], &Self);
}

impl ReadFromSliceExt for [u8] {
    #[inline(always)]
    fn read_last_avx256x4(&self) -> [Avx256; 4] {
        use intrinsic::_mm256_loadu_si256;
        let ptr = self.as_ptr();
        let offset = self.len() as isize - 128;
        unsafe {
            [
                Avx256(_mm256_loadu_si256(ptr.offset(offset + 0 * 32) as *const _)),
                Avx256(_mm256_loadu_si256(ptr.offset(offset + 1 * 32) as *const _)),
                Avx256(_mm256_loadu_si256(ptr.offset(offset + 2 * 32) as *const _)),
                Avx256(_mm256_loadu_si256(ptr.offset(offset + 3 * 32) as *const _)),
            ]
        }
    }

    #[inline(always)]
    fn read_avx256x4(&self) -> ([Avx256; 4], &Self) {
        use intrinsic::_mm256_loadu_si256;
        let (value, rest) = self.split_at(128);
        let ptr = value.as_ptr();
        let array = unsafe {
            [
                Avx256(_mm256_loadu_si256(ptr.offset(0 * 32) as *const _)),
                Avx256(_mm256_loadu_si256(ptr.offset(1 * 32) as *const _)),
                Avx256(_mm256_loadu_si256(ptr.offset(2 * 32) as *const _)),
                Avx256(_mm256_loadu_si256(ptr.offset(3 * 32) as *const _)),
            ]
        };
        (array, rest)
    }
}

// Rust is confused with targets supporting VAES without AVX512 extensions.
// We need to manually specify the underlying intrinsic; otherwise the compiler
// will have trouble inlining the code.
#[allow(improper_ctypes)]
extern "C" {
    #[link_name = "llvm.x86.aesni.aesenc.256"]
    fn aesenc_256(a: Avx256, round_key: Avx256) -> Avx256;
}

impl Avx256 {
    #[inline(always)]
    fn aesenc(self, xor: Self) -> Self {
        unsafe { aesenc_256(self, xor) }
    }
    #[inline(always)]
    fn add_by_64s(self, other: Self) -> Self {
        use intrinsic::_mm256_add_epi64;
        Self(unsafe { _mm256_add_epi64(self.0, other.0) })
    }
    #[inline(always)]
    fn shuffle(self) -> Self {
        use intrinsic::{_mm256_set_epi64x, _mm256_shuffle_epi8};
        unsafe {
            let mask = _mm256_set_epi64x(
                SHUFFLE_MASKS[0] as _,
                SHUFFLE_MASKS[1] as _,
                SHUFFLE_MASKS[0] as _,
                SHUFFLE_MASKS[1] as _,
            );
            Self(_mm256_shuffle_epi8(self.0, mask))
        }
    }
    #[inline(always)]
    fn shuffle_and_add(self, other: Self) -> Self {
        self.shuffle().add_by_64s(other)
    }
    #[inline(always)]
    fn from_u128(data: u128) -> Self {
        use core::mem::transmute;
        use intrinsic::_mm256_set_m128i;
        Self(unsafe { _mm256_set_m128i(transmute(data), transmute(data)) })
    }
    #[inline(always)]
    fn to_u128x2(self) -> [u128; 2] {
        use core::mem::transmute;
        use intrinsic::_mm256_extracti128_si256;
        unsafe {
            [
                transmute(_mm256_extracti128_si256::<0>(self.0)),
                transmute(_mm256_extracti128_si256::<1>(self.0)),
            ]
        }
    }
}

#[inline(never)]
pub(crate) fn hash_batch_128b(data: &mut &[u8], hasher: &mut AHasher) {
    let tail = data.read_last_avx256x4();
    let duplicated_key = Avx256::from_u128(hasher.key);
    let mut current: [Avx256; 4] = [duplicated_key; 4];
    current[0] = current[0].aesenc(tail[0]);
    current[1] = current[1].aesenc(tail[1]);
    current[2] = current[2].aesenc(tail[2]);
    current[3] = current[3].aesenc(tail[3]);
    let mut sum: [Avx256; 2] = [duplicated_key, duplicated_key];
    sum[0] = sum[0].add_by_64s(tail[0]);
    sum[0] = sum[0].shuffle_and_add(tail[1]);
    sum[1] = sum[1].add_by_64s(tail[2]);
    sum[1] = sum[1].shuffle_and_add(tail[3]);
    while data.len() > 128 {
        let (blocks, rest) = data.read_avx256x4();
        current[0] = current[0].aesenc(blocks[0]);
        current[1] = current[1].aesenc(blocks[1]);
        current[2] = current[2].aesenc(blocks[2]);
        current[3] = current[3].aesenc(blocks[3]);
        sum[0] = sum[0].shuffle_and_add(blocks[0]);
        sum[1] = sum[1].shuffle_and_add(blocks[1]);
        sum[0] = sum[0].shuffle_and_add(blocks[2]);
        sum[1] = sum[1].shuffle_and_add(blocks[3]);
        *data = rest;
    }
    let current = [
        current[0].to_u128x2(),
        current[1].to_u128x2(),
        current[2].to_u128x2(),
        current[3].to_u128x2(),
    ];
    let sum = [sum[0].to_u128x2(), sum[1].to_u128x2()];

    hasher.hash_in_2(
        aesenc(current[0][0], current[0][1]),
        aesenc(current[1][0], current[1][1]),
    );
    hasher.hash_in(add_by_64s(sum[0][0].convert(), sum[0][1].convert()).convert());
    hasher.hash_in_2(
        aesenc(current[2][0], current[2][1]),
        aesenc(current[3][0], current[3][1]),
    );
    hasher.hash_in(add_by_64s(sum[1][0].convert(), sum[1][1].convert()).convert());
}
