use crate::convert::*;
#[allow(unused)]
use zerocopy::transmute;

// The vector paths below keep `u128`s in vector registers instead of a round trip through general ones. zerocopy
// has no traits for 32-bit ARM's NEON types, so the ARM paths use `core::mem::transmute` (16 bytes either way, and
// every bit pattern is valid).
cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86")] {
        #[allow(unused_imports)]
        use core::arch::x86::*;
    } else if #[cfg(target_arch = "x86_64")] {
        #[allow(unused_imports)]
        use core::arch::x86_64::*;
    } else if #[cfg(target_arch = "aarch64")] {
        #[allow(unused_imports)]
        use core::arch::aarch64::*;
    } else if #[cfg(all(target_arch = "arm", aes_hash))] {
        use core::arch::arm::*;
    }
}

///This constant comes from Knuth's prng (Empirically it works better than those from splitmix32).
pub(crate) const MULTIPLE: u64 = 6364136223846793005;

/// Xors together the two halves returned by [multiply_halves].
#[inline(always)]
pub(crate) const fn folded_multiply(s: u64, by: u64) -> u64 {
    let [low, high] = multiply_halves(s, by);
    low ^ high
}

/// Returns the low and high halves of the 128 bit product.
///
/// Xoring the two halves of a product is not safe when both operands are derived from the input:
/// The xor of the halves is unchanged by complementing both of them, and this is approximately what
/// complementing an operand does to the product. (`!x` is `-x` modulo `2^64 - 1` and the high half of a
/// product carries a weight of `2^64`, which is `1` modulo `2^64 - 1`.) So the complement of an input
/// collided with the original for roughly one key in 2^26. Callers in that position should combine the
/// halves in a way that is not symmetric. See `hash_in` in `fallback_hash.rs`.
#[inline(always)]
#[cfg(folded_multiply)]
pub(crate) const fn multiply_halves(s: u64, by: u64) -> [u64; 2] {
    let result = (s as u128).wrapping_mul(by as u128);
    [(result & 0xffff_ffff_ffff_ffff) as u64, (result >> 64) as u64]
}

/// The same product from four multiplies of 32 bits by 32, for targets where a 128 bit product is a call into
/// a library.
#[inline(always)]
#[cfg(not(folded_multiply))]
pub(crate) const fn multiply_halves(s: u64, by: u64) -> [u64; 2] {
    multiply_halves_by_32s(s, by)
}

/// Returns the same halves as a 128 bit product, from four multiplies of 32 bits by 32.
/// (It is built on every target so that it can be tested on every target.)
#[inline(always)]
#[cfg_attr(folded_multiply, allow(dead_code))]
pub(crate) const fn multiply_halves_by_32s(s: u64, by: u64) -> [u64; 2] {
    const LOW: u64 = 0xffff_ffff;
    let low_low = (s & LOW) * (by & LOW);
    let low_high = (s & LOW) * (by >> 32);
    let high_low = (s >> 32) * (by & LOW);
    let high_high = (s >> 32) * (by >> 32);
    // (Neither sum can overflow: The square of `2^32 - 1` leaves room for twice `2^32 - 1`.)
    let middle = low_high + (low_low >> 32);
    let middle_low = high_low + (middle & LOW);
    [
        (middle_low << 32) | (low_low & LOW),
        high_high + (middle >> 32) + (middle_low >> 32),
    ]
}

/// Given a small (less than 8 byte slice) returns the same data stored in two u32s.
/// (order of and non-duplication of bytes is NOT guaranteed)
#[inline(always)]
pub(crate) fn read_small(data: &[u8]) -> [u64; 2] {
    debug_assert!(data.len() <= 8);
    if data.len() >= 2 {
        if data.len() >= 4 {
            //len 4-8
            [data.read_u32().0 as u64, data.read_last_u32() as u64]
        } else {
            //len 2-3
            [data.read_u16().0 as u64, data[data.len() - 1] as u64]
        }
    } else {
        if data.len() > 0 {
            [data[0] as u64, data[0] as u64]
        } else {
            [0, 0]
        }
    }
}

/// One AES encryption round of `value` (SubBytes, ShiftRows, MixColumns), then xor with `xor`.
#[cfg(aes_hash)]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc(value: u128, xor: u128) -> u128 {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            unsafe { transmute!(_mm_aesenc_si128(transmute!(value), transmute!(xor))) }
        } else {
            unsafe {
                let round = vaesmcq_u8(vaeseq_u8(core::mem::transmute(value), core::mem::transmute(0_u128)));
                core::mem::transmute(veorq_u8(round, core::mem::transmute(xor)))
            }
        }
    }
}

/// Returns the same as [aesenc], but `xor` is applied after the round, so the round can start before it is known.
#[cfg(aes_hash)]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc_late(value: u128, xor: u128) -> u128 {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            unsafe {
                let round = _mm_aesenc_si128(transmute!(value), _mm_setzero_si128());
                transmute!(_mm_xor_si128(round, transmute!(xor)))
            }
        } else {
            // (ARM's [aesenc] already applies `xor` after the round.)
            aesenc(value, xor)
        }
    }
}

/// One AES decryption round of `value` (InvShiftRows, InvSubBytes, InvMixColumns), then xor with `xor`.
#[cfg(aes_hash)]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesdec(value: u128, xor: u128) -> u128 {
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            unsafe { transmute!(_mm_aesdec_si128(transmute!(value), transmute!(xor))) }
        } else {
            unsafe {
                let round = vaesimcq_u8(vaesdq_u8(core::mem::transmute(value), core::mem::transmute(0_u128)));
                core::mem::transmute(veorq_u8(round, core::mem::transmute(xor)))
            }
        }
    }
}

/// Returns `a ^ b`, computed in a vector register where there is one.
#[allow(unused)]
#[inline(always)]
pub(crate) fn xor(a: u128, b: u128) -> u128 {
    cfg_if::cfg_if! {
        if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", not(miri)))] {
            unsafe { transmute!(_mm_xor_si128(transmute!(a), transmute!(b))) }
        } else if #[cfg(any(all(target_arch = "aarch64", target_feature = "neon", not(miri)), all(target_arch = "arm", aes_hash)))] {
            unsafe { core::mem::transmute(veorq_u8(core::mem::transmute(a), core::mem::transmute(b))) }
        } else {
            a ^ b
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(vaes)] {
        /// Returns `[aesenc(value[0], xor[0]), aesenc(value[1], xor[1])]`.
        #[allow(unused)]
        #[inline(always)]
        pub(crate) fn aesenc_x2(value: [u128; 2], xor: [u128; 2]) -> [u128; 2] {
            unsafe { transmute!(_mm256_aesenc_epi128(transmute!(value), transmute!(xor))) }
        }

        /// Returns `[aesdec(value[0], xor[0]), aesdec(value[1], xor[1])]`.
        #[allow(unused)]
        #[inline(always)]
        pub(crate) fn aesdec_x2(value: [u128; 2], xor: [u128; 2]) -> [u128; 2] {
            unsafe { transmute!(_mm256_aesdec_epi128(transmute!(value), transmute!(xor))) }
        }
    } else if #[cfg(aes_hash)] {
        /// Returns `[aesenc(value[0], xor[0]), aesenc(value[1], xor[1])]`.
        #[allow(unused)]
        #[inline(always)]
        pub(crate) fn aesenc_x2(value: [u128; 2], xor: [u128; 2]) -> [u128; 2] {
            [aesenc(value[0], xor[0]), aesenc(value[1], xor[1])]
        }

        /// Returns `[aesdec(value[0], xor[0]), aesdec(value[1], xor[1])]`.
        #[allow(unused)]
        #[inline(always)]
        pub(crate) fn aesdec_x2(value: [u128; 2], xor: [u128; 2]) -> [u128; 2] {
            [aesdec(value[0], xor[0]), aesdec(value[1], xor[1])]
        }
    }
}

/// Returns the last 15 bytes of `value` followed by the first byte of `next`.
#[allow(unused)]
#[inline(always)]
pub(crate) fn shift_in_byte(value: u128, next: u128) -> u128 {
    cfg_if::cfg_if! {
        if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", not(miri)))] {
            unsafe {
                transmute!(_mm_or_si128(
                    _mm_srli_si128(transmute!(value), 1),
                    _mm_slli_si128(transmute!(next), 15)
                ))
            }
        } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))] {
            unsafe { transmute!(vextq_u8(transmute!(value), transmute!(next), 1)) }
        } else {
            let (value, next): ([u8; 16], [u8; 16]) = (value.convert(), next.convert());
            let mut bytes = [0_u8; 16];
            bytes[..15].copy_from_slice(&value[1..]);
            bytes[15] = next[0];
            bytes.convert()
        }
    }
}

/// Adds `len` to the first 64 bits of `enc`, wrapping. The other 64 bits are left as they are.
#[allow(unused)]
#[inline(always)]
pub(crate) fn add_in_length(enc: &mut u128, len: u64) {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "x86_64", target_feature = "sse2", not(miri)))] {
            unsafe {
                let enc = enc as *mut u128;
                let sum = _mm_add_epi64(_mm_loadu_si128(enc.cast()), _mm_cvtsi64_si128(len as i64));
                _mm_storeu_si128(enc.cast(), sum);
            }
        } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))] {
            unsafe { *enc = transmute!(vaddq_u64(transmute!(*enc), transmute!([len, 0_u64]))) }
        } else {
            let mut t: [u64; 2] = enc.convert();
            t[0] = t[0].wrapping_add(len);
            *enc = t.convert();
        }
    }
}

/// Returns bytes 0, 4, 8, 12, 1, 5, 9 and 13 of `x`, in that order. Only where there is a byte shuffle.
#[cfg(all(
    aes_hash,
    any(
        all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3"),
        target_arch = "aarch64"
    )
))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn spread_low64(x: u128) -> u64 {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "aarch64")] {
            unsafe {
                let order = vld1q_u8([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15].as_ptr());
                vgetq_lane_u64(vreinterpretq_u64_u8(vqtbl1q_u8(transmute!(x), order)), 0)
            }
        } else {
            unsafe {
                let order = _mm_set_epi8(15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0);
                let spread: [u64; 2] = transmute!(_mm_shuffle_epi8(transmute!(x), order));
                spread[0]
            }
        }
    }
}

/// Adds each 64 bit half of `a` to the same half of `b`, wrapping.
#[allow(unused)]
#[inline(always)]
pub(crate) fn add_by_64s(a: u128, b: u128) -> u128 {
    cfg_if::cfg_if! {
        if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", not(miri)))] {
            unsafe { transmute!(_mm_add_epi64(transmute!(a), transmute!(b))) }
        } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))] {
            unsafe { transmute!(vaddq_u64(transmute!(a), transmute!(b))) }
        } else {
            let a: [u64; 2] = a.convert();
            let b: [u64; 2] = b.convert();
            [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])].convert()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(aes_hash)]
    #[test]
    fn test_aes_variants_agree() {
        let mut x = 1_u128;
        let mut next = || {
            x = x.wrapping_mul(0x2360_ed05_1fc6_5da4_4385_df64_9fcc_f645) + 1;
            x ^ (x >> 64)
        };
        for _ in 0..1000 {
            let (value, xor) = ([next(), next()], [next(), next()]);
            assert_eq!(aesenc(value[0], xor[0]), aesenc_late(value[0], xor[0]));
            assert_eq!(
                [aesenc(value[0], xor[0]), aesenc(value[1], xor[1])],
                aesenc_x2(value, xor)
            );
            assert_eq!(
                [aesdec(value[0], xor[0]), aesdec(value[1], xor[1])],
                aesdec_x2(value, xor)
            );
        }
    }

    #[test]
    fn test_shift_in_byte() {
        let value = u128::from_ne_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let next = u128::from_ne_bytes([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
        assert_eq!(
            shift_in_byte(value, next).to_ne_bytes(),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn test_add_length() {
        let enc: [u64; 2] = [50, u64::MAX];
        let mut enc: u128 = enc.convert();
        add_in_length(&mut enc, u64::MAX);
        let enc: [u64; 2] = enc.convert();
        assert_eq!(enc[1], u64::MAX);
        assert_eq!(enc[0], 49);
    }
}
