use ahash::*;
use std::hash::{BuildHasher, Hash, Hasher};

#[derive(Hash)]
struct Value(u32, u32);

#[test]
fn test_specialization() {
    let init_state = RandomState::new();
    let to_hash = 1u32;
    let mut special_hasher = (&to_hash).get_specialized_hasher(&init_state);
    to_hash.hash(&mut special_hasher);
    let mut normal_hasher = init_state.build_hasher();
    to_hash.hash(&mut normal_hasher);
    assert_ne!(special_hasher.finish(), normal_hasher.finish());
    let _is_primitive: PrimitiveHasher = special_hasher;

    let v = Value(1, 2);
    let mut special_hasher = (&v).get_specialized_hasher(&init_state);
    v.hash(&mut special_hasher);
    let mut normal_hasher = init_state.build_hasher();
    v.hash(&mut normal_hasher);
    assert_eq!(special_hasher.finish(), normal_hasher.finish());
    let _is_not_primitive: AHasher = special_hasher;
}
