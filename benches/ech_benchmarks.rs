/**
 * Enterprise Credential Hunter - Performance Benchmarks
 * 
 * Comprehensive benchmarks to measure and track performance improvements,
 * especially SIMD optimizations and detection engine throughput.
 */

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::time::Duration;

// Mock ECH components for benchmarking
struct MockDetectionEngine;
struct MockSIMDScanner;

impl MockDetectionEngine {
    fn new() -> Self {
        Self
    }
    
    fn scan_text(&self, data: &str) -> Vec<String> {
        // Simulate credential detection patterns
        let patterns = [
            r"AKIA[0-9A-Z]{16}",  // AWS Access Key
            r"sk-[a-zA-Z0-9]{32}", // Stripe API Key
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", // Email
            r"-----BEGIN [A-Z ]+-----.*-----END [A-Z ]+-----", // PEM
        ];
        
        let mut results = Vec::new();
        for pattern in &patterns {
            if data.contains("AKIA") || data.contains("sk-") || data.contains("@") {
                results.push("credential_found".to_string());
            }
        }
        results
    }
    
    fn scan_binary(&self, data: &[u8]) -> Vec<String> {
        // Convert to string and scan
        let text = String::from_utf8_lossy(data);
        self.scan_text(&text)
    }
}

impl MockSIMDScanner {
    fn new() -> Self {
        Self
    }
    
    // Simulate SIMD-optimized pattern matching
    fn simd_pattern_match(&self, data: &[u8], pattern: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();
        
        // Simulate SIMD-style vectorized search
        for i in 0..data.len().saturating_sub(pattern.len()) {
            if data[i..i + pattern.len()] == *pattern {
                matches.push(i);
            }
        }
        
        matches
    }
    
    // Simulate scalar fallback
    fn scalar_pattern_match(&self, data: &[u8], pattern: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();
        
        // Standard byte-by-byte search
        for i in 0..data.len().saturating_sub(pattern.len()) {
            let mut found = true;
            for j in 0..pattern.len() {
                if data[i + j] != pattern[j] {
                    found = false;
                    break;
                }
            }
            if found {
                matches.push(i);
            }
        }
        
        matches
    }
    
    // Simulate entropy calculation
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        
        // Count byte frequencies
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        // Calculate Shannon entropy
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
}

// Generate test data of various sizes
fn generate_test_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    
    // Mix of random data and credential-like patterns
    let patterns = [
        b"AKIAIOSFODNN7EXAMPLE".as_slice(), // AWS key
        b"sk-1234567890abcdef1234567890abcdef".as_slice(), // Stripe key
        b"user@example.com".as_slice(), // Email
        b"password=secret123".as_slice(), // Password
    ];
    
    let mut pattern_idx = 0;
    let mut pos = 0;
    
    while pos < size {
        if pos % 1000 == 0 && pattern_idx < patterns.len() {
            // Insert credential pattern every 1000 bytes
            let pattern = patterns[pattern_idx];
            if pos + pattern.len() <= size {
                data.extend_from_slice(pattern);
                pos += pattern.len();
                pattern_idx = (pattern_idx + 1) % patterns.len();
            }
        }
        
        if pos < size {
            // Fill with pseudo-random data
            data.push((pos % 256) as u8);
            pos += 1;
        }
    }
    
    data
}

fn generate_text_data(size: usize) -> String {
    let credentials = [
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 
        "STRIPE_API_KEY=sk-test_1234567890abcdef1234567890abcdef",
        "DATABASE_URL=postgresql://user:password@localhost/db",
        "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
        "user.email@company.com",
        "admin_password=SuperSecretP@ssw0rd123",
    ];
    
    let mut result = String::with_capacity(size);
    let mut cred_idx = 0;
    
    while result.len() < size {
        if result.len() % 500 == 0 && cred_idx < credentials.len() {
            result.push_str(credentials[cred_idx]);
            result.push('\n');
            cred_idx = (cred_idx + 1) % credentials.len();
        }
        
        // Fill with Lorem ipsum-style text
        result.push_str("Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ");
    }
    
    result.truncate(size);
    result
}

// Benchmark detection engine performance
fn bench_detection_engine(c: &mut Criterion) {
    let engine = MockDetectionEngine::new();
    
    let mut group = c.benchmark_group("detection_engine");
    
    for size in [1_000, 10_000, 100_000, 1_000_000].iter() {
        let data = generate_text_data(*size);
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("scan_text", size),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(engine.scan_text(black_box(data)))
                })
            },
        );
    }
    
    group.finish();
}

// Benchmark SIMD vs scalar performance
fn bench_simd_vs_scalar(c: &mut Criterion) {
    let scanner = MockSIMDScanner::new();
    let pattern = b"AKIA"; // AWS key prefix
    
    let mut group = c.benchmark_group("simd_vs_scalar");
    
    for size in [10_000, 100_000, 1_000_000].iter() {
        let data = generate_test_data(*size);
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("simd_pattern_match", size),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(scanner.simd_pattern_match(black_box(data), black_box(pattern)))
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("scalar_pattern_match", size),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(scanner.scalar_pattern_match(black_box(data), black_box(pattern)))
                })
            },
        );
    }
    
    group.finish();
}

// Benchmark entropy calculation
fn bench_entropy_calculation(c: &mut Criterion) {
    let scanner = MockSIMDScanner::new();
    
    let mut group = c.benchmark_group("entropy_calculation");
    
    for size in [1_000, 10_000, 100_000].iter() {
        let data = generate_test_data(*size);
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("calculate_entropy", size),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(scanner.calculate_entropy(black_box(data)))
                })
            },
        );
    }
    
    group.finish();
}

// Benchmark memory scanning scenarios
fn bench_memory_scanning(c: &mut Criterion) {
    let engine = MockDetectionEngine::new();
    
    let mut group = c.benchmark_group("memory_scanning");
    group.measurement_time(Duration::from_secs(10));
    
    // Simulate different memory dump sizes
    let sizes = [
        ("small_dump", 1_000_000),      // 1MB
        ("medium_dump", 10_000_000),    // 10MB  
        ("large_dump", 100_000_000),    // 100MB
    ];
    
    for (name, size) in sizes.iter() {
        let data = generate_test_data(*size);
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("scan_memory_dump", name),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(engine.scan_binary(black_box(data)))
                })
            },
        );
    }
    
    group.finish();
}

// Benchmark real-world scenarios
fn bench_real_world_scenarios(c: &mut Criterion) {
    let engine = MockDetectionEngine::new();
    
    let mut group = c.benchmark_group("real_world_scenarios");
    
    // Scenario 1: Configuration files
    let config_data = generate_text_data(50_000); // 50KB config file
    group.bench_function("config_file_scan", |b| {
        b.iter(|| {
            black_box(engine.scan_text(black_box(&config_data)))
        })
    });
    
    // Scenario 2: Log files  
    let log_data = generate_text_data(500_000); // 500KB log file
    group.bench_function("log_file_scan", |b| {
        b.iter(|| {
            black_box(engine.scan_text(black_box(&log_data)))
        })
    });
    
    // Scenario 3: Source code
    let source_data = generate_text_data(100_000); // 100KB source file
    group.bench_function("source_code_scan", |b| {
        b.iter(|| {
            black_box(engine.scan_text(black_box(&source_data)))
        })
    });
    
    group.finish();
}

// Performance regression tests
fn bench_performance_regression(c: &mut Criterion) {
    let engine = MockDetectionEngine::new();
    let scanner = MockSIMDScanner::new();
    
    let mut group = c.benchmark_group("performance_regression");
    
    // Baseline performance test - should be stable across releases
    let baseline_data = generate_test_data(1_000_000); // 1MB
    let baseline_pattern = b"AKIA";
    
    group.bench_function("baseline_scan", |b| {
        b.iter(|| {
            black_box(engine.scan_binary(black_box(&baseline_data)))
        })
    });
    
    group.bench_function("baseline_pattern_match", |b| {
        b.iter(|| {
            black_box(scanner.simd_pattern_match(black_box(&baseline_data), black_box(baseline_pattern)))
        })
    });
    
    group.bench_function("baseline_entropy", |b| {
        b.iter(|| {
            black_box(scanner.calculate_entropy(black_box(&baseline_data)))
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_detection_engine,
    bench_simd_vs_scalar,
    bench_entropy_calculation,
    bench_memory_scanning,
    bench_real_world_scenarios,
    bench_performance_regression
);

criterion_main!(benches);