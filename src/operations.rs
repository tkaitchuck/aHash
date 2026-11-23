use crate::convert::*;
#[allow(unused)]
use zerocopy::transmute;

///This constant comes from Knuth's prng (Empirically it works better than those from splitmix32).
pub(crate) const MULTIPLE: u64 = 6364136223846793005;

/// Xors together the two halves returned by [multiply_halves].
#[inline(always)]
pub(crate) const fn folded_multiply(s: u64, by: u64) -> u64 {
    let [low, high] = multiply_halves(s, by);
    low ^ high
}

/// Returns the low and high halves of the product (or of its substitute where there is no 128 bit product).
///
/// Xoring the two halves of a product is not safe when both operands are derived from the input:
/// The xor of the halves is unchanged by complementing both of them, and this is approximately what
/// complementing an operand does to the product. (`!x` is `-x` modulo `2^64 - 1` and the high half of a
/// product carries a weight of `2^64`, which is `1` modulo `2^64 - 1`.) So the complement of an input
/// collided with the original for roughly one key in 2^26. Callers in that position should combine the
/// halves in a way that is not symmetric. See `large_update` in `fallback_hash.rs`.
#[inline(always)]
#[cfg(folded_multiply)]
pub(crate) const fn multiply_halves(s: u64, by: u64) -> [u64; 2] {
    let result = (s as u128).wrapping_mul(by as u128);
    [(result & 0xffff_ffff_ffff_ffff) as u64, (result >> 64) as u64]
}

#[inline(always)]
#[cfg(not(folded_multiply))]
pub(crate) const fn multiply_halves(s: u64, by: u64) -> [u64; 2] {
    let b1 = s.wrapping_mul(by.swap_bytes());
    let b2 = s.swap_bytes().wrapping_mul(!by);
    [b1, b2.swap_bytes()]
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
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    unsafe {
        let value = transmute!(value);
        transmute!(_mm_aesenc_si128(value, transmute!(xor)))
    }
}

/// Returns the same as [aesenc]. The round is computed from `value` alone and `xor` is applied to its result, so
/// the round can start before `xor` is known.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc_late(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    unsafe {
        let round = _mm_aesenc_si128(transmute!(value), _mm_setzero_si128());
        transmute!(_mm_xor_si128(round, transmute!(xor)))
    }
}

/// One AES encryption round of `value` (SubBytes, ShiftRows, MixColumns), then xor with `xor`.
#[cfg(any(
    all(feature = "nightly-arm-aes", target_arch = "aarch64", target_feature = "aes", not(miri)),
    all(feature = "nightly-arm-aes", target_arch = "arm", target_feature = "aes", not(miri)),
))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "aarch64")]
    use core::arch::aarch64::*;
    #[cfg(target_arch = "arm")]
    use core::arch::arm::*;
    // (The xor is done on the vector type so the result does not make a round trip through general registers.)
    unsafe {
        let res = vaesmcq_u8(vaeseq_u8(transmute!(value), transmute!(0u128)));
        transmute!(veorq_u8(res, transmute!(xor)))
    }
}

/// Returns the same as [aesenc], which on this architecture already applies `xor` after the round.
#[cfg(any(
    all(feature = "nightly-arm-aes", target_arch = "aarch64", target_feature = "aes", not(miri)),
    all(feature = "nightly-arm-aes", target_arch = "arm", target_feature = "aes", not(miri)),
))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc_late(value: u128, xor: u128) -> u128 {
    aesenc(value, xor)
}

/// One AES decryption round of `value` (InvShiftRows, InvSubBytes, InvMixColumns), then xor with `xor`.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesdec(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    unsafe {
        let value = transmute!(value);
        transmute!(_mm_aesdec_si128(value, transmute!(xor)))
    }
}

/// One AES decryption round of `value` (InvShiftRows, InvSubBytes, InvMixColumns), then xor with `xor`.
#[cfg(any(
    all(feature = "nightly-arm-aes", target_arch = "aarch64", target_feature = "aes", not(miri)),
    all(feature = "nightly-arm-aes", target_arch = "arm", target_feature = "aes", not(miri)),
))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesdec(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "aarch64")]
    use core::arch::aarch64::*;
    #[cfg(target_arch = "arm")]
    use core::arch::arm::*;
    unsafe {
        let res = vaesimcq_u8(vaesdq_u8(transmute!(value), transmute!(0u128)));
        transmute!(veorq_u8(res, transmute!(xor)))
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(vaes, not(miri)))] {
        /// Returns `[aesenc(value[0], xor[0]), aesenc(value[1], xor[1])]`.
        #[allow(unused)]
        #[inline(always)]
        pub(crate) fn aesenc_x2(value: [u128; 2], xor: [u128; 2]) -> [u128; 2] {
            use core::arch::x86_64::*;
            unsafe { transmute!(_mm256_aesenc_epi128(transmute!(value), transmute!(xor))) }
        }

        /// Returns `[aesdec(value[0], xor[0]), aesdec(value[1], xor[1])]`.
        #[allow(unused)]
        #[inline(always)]
        pub(crate) fn aesdec_x2(value: [u128; 2], xor: [u128; 2]) -> [u128; 2] {
            use core::arch::x86_64::*;
            unsafe { transmute!(_mm256_aesdec_epi128(transmute!(value), transmute!(xor))) }
        }
    } else if #[cfg(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)),
        all(feature = "nightly-arm-aes", target_arch = "aarch64", target_feature = "aes", not(miri)),
        all(feature = "nightly-arm-aes", target_arch = "arm", target_feature = "aes", not(miri)),
    ))] {
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
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", not(miri)))]
    {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        // (On the vector type, so the value does not make a round trip through general registers.)
        unsafe {
            transmute!(_mm_or_si128(
                _mm_srli_si128(transmute!(value), 1),
                _mm_slli_si128(transmute!(next), 15)
            ))
        }
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "neon", not(miri)))]
    {
        use core::arch::aarch64::*;
        unsafe { transmute!(vextq_u8(transmute!(value), transmute!(next), 1)) }
    }
    #[cfg(not(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", not(miri)),
        all(target_arch = "aarch64", target_feature = "neon", not(miri)),
    )))]
    {
        let (value, next): ([u8; 16], [u8; 16]) = (value.convert(), next.convert());
        let mut bytes = [0_u8; 16];
        bytes[..15].copy_from_slice(&value[1..]);
        bytes[15] = next[0];
        bytes.convert()
    }
}

/// Adds `len` to the first 64 bits of `enc`, wrapping. The other 64 bits are left as they are.
#[allow(unused)]
#[inline(always)]
pub(crate) fn add_in_length(enc: &mut u128, len: u64) {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2", not(miri)))]
    {
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        unsafe {
            let enc = enc as *mut u128;
            let len = _mm_cvtsi64_si128(len as i64);
            let data = _mm_loadu_si128(enc.cast());
            let sum = _mm_add_epi64(data, len);
            _mm_storeu_si128(enc.cast(), sum);
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2", not(miri))))]
    {
        let mut t: [u64; 2] = enc.convert();
        t[0] = t[0].wrapping_add(len);
        *enc = t.convert();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)),
        all(feature = "nightly-arm-aes", target_arch = "aarch64", target_feature = "aes", not(miri)),
        all(feature = "nightly-arm-aes", target_arch = "arm", target_feature = "aes", not(miri)),
    ))]
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
