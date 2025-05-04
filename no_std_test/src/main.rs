//! This is a bare-bones `no-std` application that hashes a value and
//! uses the hash value as the return value.
#![no_main]
#![no_std]
#![feature(alloc_error_handler)]

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use core::hash::{Hash, Hasher};

// NB: Rust needs a CRT runtime on Windows MSVC.
#[cfg(all(windows, target_env = "msvc"))]
#[link(name = "msvcrt")]
#[link(name = "libcmt")]
extern "C" {}

#[no_mangle]
fn main(_argc: isize, _argv: *const *const u8) -> isize {
	let mut h: ahash::AHasher = Default::default();
	42_i32.hash(&mut h);
	return h.finish() as isize;
}


#[alloc_error_handler]
fn foo(_: core::alloc::Layout) -> ! {
    core::intrinsics::abort();
}

#[panic_handler]
#[lang = "panic_impl"]
fn rust_begin_panic(_: &core::panic::PanicInfo) -> ! {
    core::intrinsics::abort();
}

#[no_mangle]
extern "C" fn _rust_eh_personality() {}

#[no_mangle]
extern "C" fn rust_eh_personality() {}

#[no_mangle]
extern "C" fn rust_eh_register_frames() {}

#[no_mangle]
extern "C" fn rust_eh_unregister_frames() {}

#[no_mangle]
extern "C" fn _Unwind_Resume() {}
