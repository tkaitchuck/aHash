//! Compares the speed of aHash with other hashers which are available in Rust.
//!
//! Every hasher is used the way a `HashMap` uses it: Through `BuildHasher::hash_one`, with a reference to the key.
//! This matters for aHash: `hash_one` is what selects its specialized hashers. Building a hasher and calling `finish`
//! on it does not use them.
//!
//! aHash only uses AES if the instructions are enabled at compile time. So to measure the AES version:
//! ```text
//! RUSTFLAGS="-C target-cpu=native" cargo +nightly bench --features nightly
//! ```
//! and to measure the fallback:
//! ```text
//! RUSTFLAGS="-C target-cpu=native -C target-feature=-aes" cargo +nightly bench --features nightly -- aHash
//! ```
//! The two runs use different names for aHash, so the results of both are kept in `target/criterion`.
//! `summarize.py` turns them into the tables and the chart in the readme.
//!
//! The lookups in a map are measured as well, but they are not in the tables: Their times depend more on how the
//! compiler fits the lookup together than on the hasher.

use criterion::*;
use std::hash::{BuildHasher, BuildHasherDefault};
use std::hint::black_box;
use std::time::Duration;

const STRING_LENGTHS: [usize; 16] = [
    1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535,
];

/// The number of keys in the maps. Small enough that the map stays in the L1 cache, so the hasher is what is
/// being measured and not the memory.
const MAP_KEYS: usize = 1000;

fn create_string(len: usize) -> String {
    let mut string = String::default();
    for pos in 1..=len {
        let c = (48 + (pos % 10) as u8) as char;
        string.push(c);
    }
    string
}

/// A small fixed generator (splitmix64), so every hasher and every run gets the same keys.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn int_keys() -> Vec<u64> {
    let mut rng = Rng(1);
    (0..MAP_KEYS).map(|_| rng.next()).collect()
}

/// Keys of 4 to 24 bytes, in no particular order. So unlike in the `string` benchmarks the length of the next key
/// cannot be predicted.
fn string_keys() -> Vec<String> {
    let mut rng = Rng(2);
    (0..MAP_KEYS)
        .map(|_| {
            let len = 4 + (rng.next() % 21) as usize;
            (0..len).map(|_| (b'a' + (rng.next() % 26) as u8) as char).collect()
        })
        .collect()
}

fn bench_hasher<B: BuildHasher>(c: &mut Criterion, name: &str, new_builder: impl Fn() -> B) {
    let builder = new_builder();
    let int: u64 = 0x1234_5678_9abc_def0;
    c.benchmark_group("u64")
        .bench_function(name, |bencher| bencher.iter(|| builder.hash_one(black_box(&int))));

    let mut group = c.benchmark_group("string");
    for len in STRING_LENGTHS {
        let string = create_string(len);
        group.bench_with_input(BenchmarkId::new(name, len), &string, |bencher, s| {
            bencher.iter(|| builder.hash_one(black_box(s)));
        });
    }
    group.finish();

    // One iteration looks up every key once, so these times are for `MAP_KEYS` lookups.
    let keys = int_keys();
    let mut map = hashbrown::HashMap::with_hasher(new_builder());
    map.extend(keys.iter().map(|k| (*k, *k)));
    c.benchmark_group("map-u64").bench_function(name, |bencher| {
        bencher.iter(|| {
            let mut sum = 0_u64;
            for key in black_box(&keys) {
                sum = sum.wrapping_add(map[key]);
            }
            sum
        })
    });

    let keys = string_keys();
    let mut map = hashbrown::HashMap::with_hasher(new_builder());
    map.extend(keys.iter().map(|k| (k.clone(), k.len())));
    c.benchmark_group("map-string").bench_function(name, |bencher| {
        bencher.iter(|| {
            let mut sum = 0_usize;
            for key in black_box(&keys) {
                sum = sum.wrapping_add(map[key.as_str()]);
            }
            sum
        })
    });
}

fn compare(c: &mut Criterion) {
    // (On 32-bit ARM aHash also needs the `nightly-arm-aes` feature to use AES.)
    let ahash_name = if cfg!(target_feature = "aes") {
        "aHash"
    } else {
        "aHash-fallback"
    };
    bench_hasher(c, ahash_name, || ahash::RandomState::new());
    bench_hasher(c, "foldhash-fast", || foldhash::fast::RandomState::default());
    bench_hasher(c, "foldhash-quality", || foldhash::quality::RandomState::default());
    bench_hasher(c, "rapidhash-fast", || rapidhash::fast::RandomState::default());
    bench_hasher(c, "rapidhash-quality", || rapidhash::quality::RandomState::default());
    bench_hasher(c, "rustc-hash", || rustc_hash::FxBuildHasher);
    bench_hasher(c, "fxhash", || fxhash::FxBuildHasher::default());
    bench_hasher(c, "fnv", || fnv::FnvBuildHasher::default());
    bench_hasher(c, "xxh3", || xxhash_rust::xxh3::Xxh3Builder::default());
    // The default hasher of the standard library.
    bench_hasher(c, "siphash-1-3", || std::collections::hash_map::RandomState::new());
    bench_hasher(c, "siphash-2-4", || {
        BuildHasherDefault::<siphasher::sip::SipHasher24>::default()
    });
    bench_hasher(c, "seahash", || BuildHasherDefault::<seahash::SeaHasher>::default());
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = compare
}
criterion_main!(benches);
