#![feature(buf_read_has_data_left)]

mod persisting_hasher;
mod data_reader;

use persisting_hasher::*;
use data_reader::*;
use std::collections::HashMap;
use std::fs::File;
use std::time::SystemTime;
use std::alloc::System;

fn capture_output_example() {
    let builder = PersistingHasherBuilder::default();
    let mut map = HashMap::with_capacity_and_hasher(10, builder);
    map.insert(1, 2);
    map.insert(3, 4);
    let builder = PersistingHasherBuilder::default();
    let mut map = HashMap::with_capacity_and_hasher(10, builder);
    map.insert("1", 2);
    map.insert("3", 4);
    PersistingHasherBuilder::default().flush();
}

fn main() {
    // capture_output_example();

    //Given a previously captured set of hashed data, time how long it takes using a different algorithm.
    let file = File::open("hash_output-295253").unwrap();
    let rand = ahash::RandomState::new();
    let start_time = SystemTime::now();
    let result = test_hasher(file, rand).unwrap();
    println!("Completed after {:?} with result: {:x}", SystemTime::now().duration_since(start_time).unwrap(), result)
}
