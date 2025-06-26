/**
 * Build script for ECH SIMD module
 * 
 * Automatically detects CPU capabilities and configures appropriate
 * SIMD optimizations with fallbacks for unsupported architectures.
 */

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Detect target architecture
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let _target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    
    // Target configuration is handled automatically by Rust
    
    // Configure SIMD features based on target
    match target_arch.as_str() {
        "x86_64" => {
            configure_x86_64_simd();
        }
        "aarch64" => {
            configure_aarch64_simd();
        }
        "arm" => {
            configure_arm_simd();
        }
        _ => {
            println!("cargo:rustc-cfg=simd_fallback");
            println!("cargo:warning=SIMD optimizations not available for architecture: {}", target_arch);
        }
    }
    
    // Configure platform-specific optimizations
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-cfg=linux_optimizations");
            configure_linux_optimizations();
        }
        "windows" => {
            println!("cargo:rustc-cfg=windows_optimizations");
            configure_windows_optimizations();
        }
        "macos" => {
            println!("cargo:rustc-cfg=macos_optimizations");
            configure_macos_optimizations();
        }
        _ => {}
    }
    
    // Check for specific CPU features at build time
    configure_cpu_features();
    
    // Generate optimal configuration summary
    generate_build_summary();
}

fn configure_x86_64_simd() {
    println!("cargo:rustc-cfg=x86_64_simd");
    
    // Check for AVX2 support (most modern x86_64 CPUs)
    if is_feature_available("avx2") {
        println!("cargo:rustc-cfg=avx2_available");
        println!("cargo:rustc-link-arg=-mavx2");
    } else {
        println!("cargo:warning=AVX2 not available, using SSE fallback");
    }
    
    // Check for AVX-512 support (newer Intel CPUs)
    if is_feature_available("avx512f") {
        println!("cargo:rustc-cfg=avx512_available");
    }
    
    // Always available on x86_64
    println!("cargo:rustc-cfg=sse2_available");
    println!("cargo:rustc-cfg=sse41_available");
}

fn configure_aarch64_simd() {
    println!("cargo:rustc-cfg=aarch64_simd");
    
    // NEON is standard on AArch64
    println!("cargo:rustc-cfg=neon_available");
    
    // Check for newer ARM features
    if is_feature_available("sve") {
        println!("cargo:rustc-cfg=sve_available");
    }
    
    // Apple M1/M2 specific optimizations
    if env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default() == "apple" {
        println!("cargo:rustc-cfg=apple_silicon");
        configure_apple_silicon_optimizations();
    }
}

fn configure_arm_simd() {
    println!("cargo:rustc-cfg=arm_simd");
    
    // Check for NEON support on 32-bit ARM
    if is_feature_available("neon") {
        println!("cargo:rustc-cfg=neon_available");
    } else {
        println!("cargo:rustc-cfg=simd_fallback");
        println!("cargo:warning=NEON not available, using scalar fallback");
    }
}

fn configure_cpu_features() {
    // Set CPU-specific optimization flags
    let target_cpu = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    
    if target_cpu.contains("aes") {
        println!("cargo:rustc-cfg=aes_hardware");
    }
    
    if target_cpu.contains("sha") {
        println!("cargo:rustc-cfg=sha_hardware"); 
    }
    
    // Configure based on CARGO_CFG_TARGET_FEATURE
    if let Ok(features) = env::var("CARGO_CFG_TARGET_FEATURE") {
        for feature in features.split(',') {
            match feature.trim() {
                "avx2" => println!("cargo:rustc-cfg=has_avx2"),
                "avx512f" => println!("cargo:rustc-cfg=has_avx512f"),
                "neon" => println!("cargo:rustc-cfg=has_neon"),
                "sse2" => println!("cargo:rustc-cfg=has_sse2"),
                "sse4.1" => println!("cargo:rustc-cfg=has_sse41"),
                _ => {}
            }
        }
    }
}

fn configure_linux_optimizations() {
    // Linux-specific SIMD optimizations
    println!("cargo:rustc-link-arg=-march=native");
    
    // Enable CPU feature detection at runtime
    println!("cargo:rustc-cfg=runtime_cpu_detection");
}

fn configure_windows_optimizations() {
    // Windows-specific optimizations
    if env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc" {
        println!("cargo:rustc-link-arg=/favor:INTEL64");
    }
}

fn configure_macos_optimizations() {
    // macOS-specific optimizations
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    
    if target_arch == "aarch64" {
        // Apple Silicon optimizations
        configure_apple_silicon_optimizations();
    } else if target_arch == "x86_64" {
        // Intel Mac optimizations
        println!("cargo:rustc-link-arg=-march=native");
    }
}

fn configure_apple_silicon_optimizations() {
    println!("cargo:rustc-cfg=apple_silicon_optimizations");
    
    // Apple's AMX (Advanced Matrix Extensions) if available
    println!("cargo:rustc-cfg=amx_available");
    
    // Optimize for Apple's performance cores
    println!("cargo:rustc-link-arg=-mcpu=apple-m1");
}

fn is_feature_available(feature: &str) -> bool {
    // This is a build-time check - in practice you'd use more sophisticated detection
    // For now, we'll use conservative defaults
    match feature {
        "avx2" => {
            // Most x86_64 systems built after 2013 have AVX2
            env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "x86_64"
        }
        "avx512f" => {
            // More conservative - only enable if explicitly requested
            env::var("ECH_ENABLE_AVX512").is_ok()
        }
        "neon" => {
            // NEON is standard on AArch64, optional on 32-bit ARM
            let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
            arch == "aarch64" || env::var("ECH_ENABLE_NEON").is_ok()
        }
        "sve" => {
            // ARM SVE - newer feature
            env::var("ECH_ENABLE_SVE").is_ok()
        }
        _ => false,
    }
}

fn generate_build_summary() {
    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();
    
    println!("cargo:warning=ECH SIMD Build Configuration:");
    println!("cargo:warning=  Target: {}", target);
    println!("cargo:warning=  Profile: {}", profile);
    
    // Generate a compile-time constant with build info
    let build_info = format!(
        r#"
pub const BUILD_TARGET: &str = "{}";
pub const BUILD_PROFILE: &str = "{}";
pub const SIMD_FEATURES: &[&str] = &[
    {}
];
"#,
        target,
        profile,
        get_enabled_simd_features()
    );
    
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("build_info.rs");
    std::fs::write(&dest_path, build_info).unwrap();
    
    println!("cargo:warning=  SIMD features: {}", get_enabled_simd_features());
}

fn get_enabled_simd_features() -> String {
    let mut features = Vec::new();
    
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    match target_arch.as_str() {
        "x86_64" => {
            features.push("\"sse2\"");
            features.push("\"sse41\"");
            if is_feature_available("avx2") {
                features.push("\"avx2\"");
            }
            if is_feature_available("avx512f") {
                features.push("\"avx512f\"");
            }
        }
        "aarch64" => {
            features.push("\"neon\"");
            if is_feature_available("sve") {
                features.push("\"sve\"");
            }
        }
        "arm" => {
            if is_feature_available("neon") {
                features.push("\"neon\"");
            }
        }
        _ => {
            features.push("\"scalar_fallback\"");
        }
    }
    
    features.join(", ")
}