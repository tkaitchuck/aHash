use std::io::Error;
use std::fs::File;
use std::io::Write;
use std::hash::BuildHasher;
use pcg_mwc::Mwc256XXA64;
use ahash::RandomState;
use std::io::BufWriter;
use std::path::Path;
use rand_core::SeedableRng;
use rand::Rng;
use std::time::Instant;


fn main() -> Result<(), Error> {
    let mut r = Mwc256XXA64::seed_from_u64(0xe786_c22b_119c_1479);

    let path = Path::new("hash_output");

    let mut file = BufWriter::new(File::create(path)?);
    let hasher = RandomState::<String>::with_seeds(r.gen(), r.gen(), r.gen(), r.gen());
    let start = Instant::now();
    let mut sum: u64 = 0;
    for i in 0..5*1024*1024*1024_u64 {
        let value = hasher.hash_one(i);
        sum = sum.wrapping_add(value);
        let value: [u8; 8] = value.to_ne_bytes();
        file.write_all(&value)?;
    }
    let elapsed = start.elapsed();
    println!("Sum {} Elapsed time: {}", sum, elapsed.as_millis());
    file.flush()?;
    Ok(())
}