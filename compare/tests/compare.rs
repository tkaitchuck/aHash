use ahash::{CallHasher, RandomState};
use criterion::*;
use farmhash::FarmHasher;
use fnv::{FnvBuildHasher};
use fxhash::FxBuildHasher;
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};

fn ahash<K: Hash>(k: &K, builder: &RandomState) -> u64 {
    let hasher = builder.build_hasher();
    k.get_hash(hasher)
}

fn generic_hash<K: Hash, B: BuildHasher>(key: &K, builder: &B) -> u64 {
    let mut hasher = builder.build_hasher();
    key.hash(&mut hasher);
    hasher.finish()
}

fn create_string(len: usize) -> String {
    let mut string = String::default();
    for pos in 1..=len {
        let c = (48 + (pos % 10) as u8) as char;
        string.push(c);
    }
    string
}

fn compare_ahash(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = RandomState::new();
    c.bench_with_input(BenchmarkId::new("compare_ahash", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(ahash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_ahash", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(ahash(&i, &builder));
        });
    });
}

fn compare_farmhash(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = BuildHasherDefault::<FarmHasher>::default();
    c.bench_with_input(BenchmarkId::new("compare_farmhash", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_farmhash", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_fnvhash(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = FnvBuildHasher::default();
    c.bench_with_input(BenchmarkId::new("compare_fnvhash", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_fnvhash", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_fxhash(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = FxBuildHasher::default();
    c.bench_with_input(BenchmarkId::new("compare_fxhash", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_fxhash", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_highway(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = highway::HighwayBuildHasher::default();
    c.bench_with_input(BenchmarkId::new("compare_highway", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_highway", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_metro(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = metrohash::MetroBuildHasher::default();
    c.bench_with_input(BenchmarkId::new("compare_metro", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_metro", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_t1ha(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = t1ha::T1haBuildHasher::default();
    c.bench_with_input(BenchmarkId::new("compare_t1ha", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_t1ha", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_sip13(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = BuildHasherDefault::<siphasher::sip::SipHasher13>::default();
    c.bench_with_input(BenchmarkId::new("compare_sip13", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_sip13", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_sip24(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = BuildHasherDefault::<siphasher::sip::SipHasher24>::default();
    c.bench_with_input(BenchmarkId::new("compare_sip24", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_sip24", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_wyhash(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = BuildHasherDefault::<wyhash::WyHash>::default();
    c.bench_with_input(BenchmarkId::new("compare_wyhash", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_wyhash", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

fn compare_xxhash(c: &mut Criterion) {
    let int: u64 = 1234;
    let string = create_string(1024);
    let builder = twox_hash::RandomXxHashBuilder64::default();
    c.bench_with_input(BenchmarkId::new("compare_xxhash", "string"), &string, |bencher, s| {
        bencher.iter(|| {
            black_box(generic_hash(&s, &builder))
        });
    });
    c.bench_with_input(BenchmarkId::new("compare_xxhash", "int"), &int, |bencher, i| {
        bencher.iter(|| {
            black_box(generic_hash(&i, &builder))
        });
    });
}

criterion_main!(compare);
criterion_group!(
    compare,
    compare_ahash,
    compare_farmhash,
    compare_fnvhash,
    compare_fxhash,
    compare_highway,
    compare_metro,
    compare_t1ha,
    compare_sip13,
    compare_sip24,
    compare_wyhash,
    compare_xxhash,
);
