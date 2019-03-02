use criterion::*;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use ahash::*;
use ahash::fallback::{FallbackHasher};
use fxhash::{FxHasher};

#[cfg(all(
any(target_arch = "x86", target_arch = "x86_64"),
target_feature = "aes"
))]
pub fn ahash<H: Hash>(b: H) -> u64 {
    let mut hasher = AHasher::default();
    b.hash(&mut hasher);
    hasher.finish()
}

fn fallbackhash<H: Hash>(b: H) -> u64 {
    let mut hasher = FallbackHasher::default();
    b.hash(&mut hasher);
    hasher.finish()
}

fn fnvhash<H: Hash>(b: H) -> u64 {
    let mut hasher = fnv::FnvHasher::default();
    b.hash(&mut hasher);
    hasher.finish()
}

fn siphash<H: Hash>(b: H) -> u64 {
    let mut hasher = DefaultHasher::default();
    b.hash(&mut hasher);
    hasher.finish()
}

fn fxhash<H: Hash>(b: H) -> u64 {
    let mut hasher = FxHasher::default();
    b.hash(&mut hasher);
    hasher.finish()
}

fn seahash<H: Hash>(b: H) -> u64 {
    let mut hasher = seahash::SeaHasher::default();
    b.hash(&mut hasher);
    hasher.finish()
}

const VALUES: [&str; 5] = ["1",
    "123",
//    "1234",
//    "1234567",
//    "12345678",
//    "123456789012345",
//    "1234567890123456",
    "123456789012345678901234",
    "12345678901234567890123456789012345678901234567890123456789012345678",
    "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012"];

const U8_VALUES: [u32; 1] = [8];
const U16_VALUES: [u16; 1] = [16];
const U32_VALUES: [u32; 1] = [32];
const U64_VALUES: [u64; 1] = [64];
const U128_VALUES: [u128; 1] = [128];

#[cfg(all(
any(target_arch = "x86", target_arch = "x86_64"),
target_feature = "aes"
))]
fn bench_ahash(c: &mut Criterion) {
    c.bench(
        "ahash",
        ParameterizedBenchmark::new("u8", |b, s| b.iter(|| black_box(ahash(&s))), &U8_VALUES),
    );
    c.bench(
        "ahash",
        ParameterizedBenchmark::new("u16", |b, s| b.iter(|| black_box(ahash(&s))), &U16_VALUES),
    );
    c.bench(
        "ahash",
        ParameterizedBenchmark::new("u32", |b, s| b.iter(|| black_box(ahash(&s))), &U32_VALUES),
    );
    c.bench(
        "ahash",
        ParameterizedBenchmark::new("u64", |b, s| b.iter(|| black_box(ahash(&s))), &U64_VALUES),
    );
    c.bench(
        "ahash",
        ParameterizedBenchmark::new("u128", |b, s| b.iter(|| black_box(ahash(&s))), &U128_VALUES),
    );
    c.bench(
        "ahash",
        ParameterizedBenchmark::new("string", |b, s| b.iter(|| black_box(ahash(&s))), &VALUES),
    );
}

fn bench_fallback(c: &mut Criterion) {
//    c.bench(
//        "fallback",
//        ParameterizedBenchmark::new("u8", |b, s| b.iter(|| black_box(fallbackhash(&s))), &U8_VALUES),
//    );
//    c.bench(
//        "fallback",
//        ParameterizedBenchmark::new("u16", |b, s| b.iter(|| black_box(fallbackhash(&s))), &U16_VALUES),
//    );
//    c.bench(
//        "fallback",
//        ParameterizedBenchmark::new("u32", |b, s| b.iter(|| black_box(fallbackhash(&s))), &U32_VALUES),
//    );
//    c.bench(
//        "fallback",
//        ParameterizedBenchmark::new("u64", |b, s| b.iter(|| black_box(fallbackhash(&s))), &U64_VALUES),
//    );
//    c.bench(
//        "fallback",
//        ParameterizedBenchmark::new("u128", |b, s| b.iter(|| black_box(fallbackhash(&s))), &U128_VALUES),
//    );
    c.bench(
        "fallback",
        ParameterizedBenchmark::new("string", |b, s| b.iter(|| black_box(fallbackhash(&s))), &VALUES),
    );
}

fn bench_fx(c: &mut Criterion) {
    c.bench(
        "fx",
        ParameterizedBenchmark::new("u8", |b, s| b.iter(|| black_box(fxhash(&s))), &U8_VALUES),
    );
    c.bench(
        "fx",
        ParameterizedBenchmark::new("u16", |b, s| b.iter(|| black_box(fxhash(&s))), &U16_VALUES),
    );
    c.bench(
        "fx",
        ParameterizedBenchmark::new("u32", |b, s| b.iter(|| black_box(fxhash(&s))), &U32_VALUES),
    );
    c.bench(
        "fx",
        ParameterizedBenchmark::new("u64", |b, s| b.iter(|| black_box(fxhash(&s))), &U64_VALUES),
    );
    c.bench(
        "fx",
        ParameterizedBenchmark::new("u128", |b, s| b.iter(|| black_box(fxhash(&s))), &U128_VALUES),
    );
    c.bench(
        "fx",
        ParameterizedBenchmark::new("string", |b, s| b.iter(|| black_box(fxhash(&s))), &VALUES),
    );
}

fn bench_fnv(c: &mut Criterion) {
    c.bench(
        "fnv",
        ParameterizedBenchmark::new("u8", |b, s| b.iter(|| black_box(fnvhash(&s))), &U8_VALUES),
    );
    c.bench(
        "fnv",
        ParameterizedBenchmark::new("u16", |b, s| b.iter(|| black_box(fnvhash(&s))), &U16_VALUES),
    );
    c.bench(
        "fnv",
        ParameterizedBenchmark::new("u32", |b, s| b.iter(|| black_box(fnvhash(&s))), &U32_VALUES),
    );
    c.bench(
        "fnv",
        ParameterizedBenchmark::new("u64", |b, s| b.iter(|| black_box(fnvhash(&s))), &U64_VALUES),
    );
    c.bench(
        "fnv",
        ParameterizedBenchmark::new("u128", |b, s| b.iter(|| black_box(fnvhash(&s))), &U128_VALUES),
    );
    c.bench(
        "fnv",
        ParameterizedBenchmark::new("string", |b, s| b.iter(|| black_box(fnvhash(&s))), &VALUES),
    );
}

fn bench_sea(c: &mut Criterion) {
    c.bench(
        "sea",
        ParameterizedBenchmark::new("string", |b, s| b.iter(|| black_box(seahash(&s))), &VALUES),
    );
}

fn bench_sip(c: &mut Criterion) {
    c.bench(
        "sip",
        ParameterizedBenchmark::new("u8", |b, s| b.iter(|| black_box(siphash(&s))), &U8_VALUES),
    );
    c.bench(
        "sip",
        ParameterizedBenchmark::new("u16", |b, s| b.iter(|| black_box(siphash(&s))), &U16_VALUES),
    );
    c.bench(
        "sip",
        ParameterizedBenchmark::new("u32", |b, s| b.iter(|| black_box(siphash(&s))), &U32_VALUES),
    );
    c.bench(
        "sip",
        ParameterizedBenchmark::new("u64", |b, s| b.iter(|| black_box(siphash(&s))), &U64_VALUES),
    );
    c.bench(
        "sip",
        ParameterizedBenchmark::new("u128", |b, s| b.iter(|| black_box(siphash(&s))), &U128_VALUES),
    );
    c.bench(
        "sip",
        ParameterizedBenchmark::new("string", |b, s| b.iter(|| black_box(siphash(&s))), &VALUES),
    );
}

criterion_main!(benches);
criterion_group!(benches, bench_ahash, bench_fallback, bench_fx, bench_fnv, bench_sea, bench_sip);
