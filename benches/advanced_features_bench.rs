use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use enterprise_credential_hunter::detection::webauthn_simple::WebAuthnHunter;
use enterprise_credential_hunter::stealth::advanced_evasion::AdvancedEvasionEngine;
use tokio::runtime::Runtime;

fn webauthn_hunting_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("webauthn_hunter_creation", |b| {
        b.to_async(&rt).iter(|| async {
            let hunter = WebAuthnHunter::new().await.unwrap();
            criterion::black_box(hunter);
        });
    });
    
    c.bench_function("webauthn_credential_hunting", |b| {
        b.to_async(&rt).iter(|| async {
            let hunter = WebAuthnHunter::new().await.unwrap();
            let results = hunter.hunt_credentials().await.unwrap();
            criterion::black_box(results);
        });
    });
}

fn stealth_engine_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    c.bench_function("stealth_engine_creation", |b| {
        b.iter(|| {
            let engine = AdvancedEvasionEngine::new();
            criterion::black_box(engine);
        });
    });
    
    c.bench_function("stealth_engine_initialization", |b| {
        b.to_async(&rt).iter(|| async {
            let mut engine = AdvancedEvasionEngine::new();
            engine.initialize_advanced_evasion().await.unwrap();
            criterion::black_box(engine);
        });
    });
    
    c.bench_function("stealth_status_check", |b| {
        b.to_async(&rt).iter(|| async {
            let mut engine = AdvancedEvasionEngine::new();
            engine.initialize_advanced_evasion().await.unwrap();
            let status = engine.get_evasion_status();
            criterion::black_box(status);
        });
    });
}

fn pattern_matching_benchmark(c: &mut Criterion) {
    let test_data = vec![
        ("small", "credentials".repeat(10)),
        ("medium", "credentials".repeat(100)),
        ("large", "credentials".repeat(1000)),
    ];
    
    let mut group = c.benchmark_group("pattern_matching");
    
    for (size, data) in test_data {
        group.bench_with_input(BenchmarkId::new("webauthn_pattern", size), &data, |b, data| {
            b.iter(|| {
                // Simulate pattern matching
                let matches = data.matches("credential").count();
                criterion::black_box(matches);
            });
        });
    }
    
    group.finish();
}

fn memory_efficiency_benchmark(c: &mut Criterion) {
    c.bench_function("memory_allocation_pattern", |b| {
        b.iter(|| {
            let mut data = Vec::new();
            for i in 0..1000 {
                data.push(format!("credential_{}", i));
            }
            criterion::black_box(data);
        });
    });
}

criterion_group!(
    benches,
    webauthn_hunting_benchmark,
    stealth_engine_benchmark,
    pattern_matching_benchmark,
    memory_efficiency_benchmark
);
criterion_main!(benches);