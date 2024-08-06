#![no_std]
#![feature(start)]

use ahash::RandomState;

use talc::*;

extern crate alloc;
extern crate panic_abort;

static mut ARENA: [u8; 1024*1024] = [0; 1024*1024];

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ClaimOnOom> = Talc::new(unsafe {
    // if we're in a hosted environment, the Rust runtime may allocate before
    // main() is called, so we need to initialize the arena automatically
    ClaimOnOom::new(Span::from_const_array(core::ptr::addr_of!(ARENA)))
}).lock();


#[start]
fn start(_argc: isize, _argv: *const *const u8) -> isize {
    // let state = RandomState::with_seeds(1, 2, 3, 4);
    //let mut sum: u64 = 0;
    // let mut payload: [u8; 8196] = [0; 8196];
    // for i in 0..1024 {
    //     payload.fill(i as u8);
    //     sum = sum.wrapping_add(state.hash_one(&payload));
    // }
    0 as isize
}
