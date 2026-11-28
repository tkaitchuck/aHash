#![deny(warnings)]

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(specialize)");
    println!("cargo:rustc-check-cfg=cfg(fuzzing)");
    if let Some(true) = version_check::supports_feature("specialize") {
        println!("cargo:rustc-cfg=specialize");
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH was not set");
    println!("cargo:rustc-check-cfg=cfg(folded_multiply)");
    if arch.eq_ignore_ascii_case("x86_64")
        || arch.eq_ignore_ascii_case("aarch64")
        || arch.eq_ignore_ascii_case("mips64")
        || arch.eq_ignore_ascii_case("powerpc64")
        || arch.eq_ignore_ascii_case("riscv64")
        || arch.eq_ignore_ascii_case("s390x")
    {
        println!("cargo:rustc-cfg=folded_multiply");
    }
    let features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let enabled = |feature: &str| features.split(',').any(|f| f == feature);
    // `aes_hash` is set when the AES hasher is used, so this is the only place that decides it. The ARM intrinsics
    // are nightly only, so they need the `nightly-arm-aes` feature. Miri does not run the AES intrinsics.
    println!("cargo:rustc-check-cfg=cfg(aes_hash)");
    let nightly_arm_aes = env::var_os("CARGO_FEATURE_NIGHTLY_ARM_AES").is_some();
    let aes_hash = env::var_os("CARGO_CFG_MIRI").is_none()
        && enabled("aes")
        && match arch.as_str() {
            "x86" | "x86_64" | "aarch64" => true,
            "arm" => nightly_arm_aes,
            _ => false,
        };
    if aes_hash {
        println!("cargo:rustc-cfg=aes_hash");
    }
    // The 256 bit AES instructions can be used if they are enabled and the compiler is new enough to have them.
    println!("cargo:rustc-check-cfg=cfg(vaes)");
    if aes_hash
        && arch == "x86_64"
        && enabled("vaes")
        && enabled("avx2")
        && version_check::is_min_version("1.89.0") == Some(true)
    {
        println!("cargo:rustc-cfg=vaes");
    }
}
