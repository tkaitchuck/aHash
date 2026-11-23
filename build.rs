#![deny(warnings)]

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(specialize)");
    if let Some(true) = version_check::supports_feature("specialize") {
        println!("cargo:rustc-cfg=specialize");
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH was not set");
    println!("cargo:rustc-check-cfg=cfg(folded_multiply)");
    if arch.eq_ignore_ascii_case("x86_64")
        || arch.eq_ignore_ascii_case("aarch64")
        || arch.eq_ignore_ascii_case("mips64")
        || arch.eq_ignore_ascii_case("powerpc64")
        || arch.eq_ignore_ascii_case("riscv64gc")
        || arch.eq_ignore_ascii_case("s390x")
    {
        println!("cargo:rustc-cfg=folded_multiply");
    }
    // The 256 bit AES instructions can be used if they are enabled and the compiler is new enough to have them.
    println!("cargo:rustc-check-cfg=cfg(vaes)");
    let features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let enabled = |feature: &str| features.split(',').any(|f| f == feature);
    if arch.eq_ignore_ascii_case("x86_64")
        && enabled("aes")
        && enabled("vaes")
        && enabled("avx2")
        && version_check::is_min_version("1.89.0") == Some(true)
    {
        println!("cargo:rustc-cfg=vaes");
    }
}
