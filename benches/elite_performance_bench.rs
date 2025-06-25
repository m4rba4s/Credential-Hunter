use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use std::io::Write;

use enterprise_credential_hunter::core::{
    zero_copy::{ZeroCopyScanner, CredentialPatterns},
    lockfree::{LockFreeQueue, LockFreeHashMap, ConcurrentCredentialBuffer},
};
use enterprise_credential_hunter::memory::secure_allocator::{SecureAllocator, SecureBuffer};
use enterprise_credential_hunter::processing::distributed::{
    DistributedEngine, WorkerPool, ProcessingTask, TaskType, Priority, PatternMatchProcessor
};
use enterprise_credential_hunter::stealth::hardware::HardwareStealth;

fn bench_zero_copy_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy_scanning");
    
    for size in [1024, 10240, 102400, 1024000].iter() {
        group.benchmark_with_input(BenchmarkId::new("file_scan", size), size, |b, &size| {
            let mut scanner = ZeroCopyScanner::new();
            let patterns = CredentialPatterns::get_optimized_patterns();
            scanner.add_credential_patterns(&patterns);
            
            let test_data = "x".repeat(size - 100) + "AKIA1234567890ABCDEF" + &"y".repeat(80);
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(test_data.as_bytes()).unwrap();
            
            scanner.map_file(temp_file.path()).unwrap();
            
            b.iter(|| {
                let matches = scanner.scan_all_regions().unwrap();
                black_box(matches);
            });
        });
    }
    
    group.finish();
}

fn bench_lock_free_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("lock_free_operations");
    
    group.bench_function("queue_enqueue_dequeue", |b| {
        let queue = LockFreeQueue::new();
        
        b.iter(|| {
            for i in 0..1000 {
                queue.enqueue(black_box(i));
            }
            
            for _ in 0..1000 {
                black_box(queue.dequeue());
            }
        });
    });
    
    group.bench_function("hashmap_insert_get", |b| {
        let map = LockFreeHashMap::new();
        
        b.iter(|| {
            for i in 0..100 {
                let key = format!("key_{}", i);
                let value = format!("value_{}", i);
                map.insert(black_box(key.clone()), black_box(value));
                black_box(map.get(&key));
            }
        });
    });
    
    group.bench_function("credential_buffer_concurrent", |b| {
        let buffer = ConcurrentCredentialBuffer::new(1000);
        
        b.iter(|| {
            for i in 0..500 {
                let credential = format!("AKIA{:016x}", i);
                buffer.add_credential(black_box(credential));
            }
            
            black_box(buffer.len());
            
            let drained = buffer.drain();
            black_box(drained);
        });
    });
    
    group.finish();
}

fn bench_secure_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_memory");
    
    for size in [1024, 4096, 16384, 65536].iter() {
        group.benchmark_with_input(BenchmarkId::new("secure_buffer_create", size), size, |b, &size| {
            b.iter(|| {
                let buffer = SecureBuffer::new(black_box(size)).unwrap();
                black_box(buffer);
            });
        });
    }
    
    group.bench_function("secure_buffer_operations", |b| {
        let mut buffer = SecureBuffer::new(4096).unwrap();
        
        b.iter(|| {
            let data = b"AKIA1234567890ABCDEF_sensitive_credential_data";
            buffer.as_mut_slice()[..data.len()].copy_from_slice(black_box(data));
            
            let found = buffer.as_slice()
                .windows(data.len())
                .any(|window| window == data);
            
            black_box(found);
        });
    });
    
    group.finish();
}

fn bench_distributed_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("distributed_processing");
    
    for workers in [1, 2, 4, 8].iter() {
        group.benchmark_with_input(BenchmarkId::new("task_processing", workers), workers, |b, &workers| {
            let mut engine = DistributedEngine::new();
            
            let mut pool = WorkerPool::new(workers);
            for _ in 0..workers {
                pool.add_processor(Arc::new(PatternMatchProcessor));
            }
            
            engine.add_worker_pool(TaskType::PatternMatch, pool);
            
            b.iter(|| {
                for i in 0..50 {
                    let task = ProcessingTask {
                        id: uuid::Uuid::new_v4(),
                        task_type: TaskType::PatternMatch,
                        data: format!("test data {}", i).into_bytes(),
                        priority: Priority::Normal,
                        deadline: None,
                        retry_count: 0,
                        max_retries: 1,
                    };
                    
                    engine.submit_task(black_box(task)).unwrap();
                }
                
                std::thread::sleep(Duration::from_millis(100));
                
                let results = engine.get_results();
                black_box(results);
            });
            
            engine.shutdown();
        });
    }
    
    group.finish();
}

fn bench_hardware_stealth(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_stealth");
    
    group.bench_function("stealth_initialization", |b| {
        b.iter(|| {
            let stealth = HardwareStealth::new();
            black_box(stealth);
        });
    });
    
    group.bench_function("stealth_techniques", |b| {
        let stealth = HardwareStealth::new().unwrap();
        if stealth.initialize().is_ok() {
            b.iter(|| {
                let _ = stealth.apply_stealth_techniques();
                let _ = stealth.randomize_execution_timing();
                let _ = stealth.manipulate_cache_behavior();
                
                black_box(());
            });
            
            let _ = stealth.shutdown();
        } else {
            b.iter(|| {
                black_box(());
            });
        }
    });
    
    group.finish();
}

fn bench_pattern_matching_simd(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_matching_simd");
    
    for pattern_count in [10, 50, 100, 200].iter() {
        group.benchmark_with_input(BenchmarkId::new("multi_pattern_scan", pattern_count), pattern_count, |b, &pattern_count| {
            let mut scanner = ZeroCopyScanner::new();
            
            let mut patterns = vec![];
            for i in 0..*pattern_count {
                patterns.push(format!("PATTERN{:04}", i).into_bytes());
            }
            
            let pattern_refs: Vec<&[u8]> = patterns.iter().map(|p| p.as_slice()).collect();
            scanner.add_credential_patterns(&pattern_refs);
            
            let test_data = "x".repeat(50000) + "PATTERN0050" + &"y".repeat(50000);
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(test_data.as_bytes()).unwrap();
            
            scanner.map_file(temp_file.path()).unwrap();
            
            b.iter(|| {
                let matches = scanner.scan_all_regions().unwrap();
                black_box(matches);
            });
        });
    }
    
    group.finish();
}

fn bench_concurrent_credential_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_credential_processing");
    
    for threads in [1, 2, 4, 8].iter() {
        group.benchmark_with_input(BenchmarkId::new("concurrent_buffer", threads), threads, |b, &threads| {
            let buffer = Arc::new(ConcurrentCredentialBuffer::new(10000));
            
            b.iter(|| {
                let mut handles = vec![];
                
                for thread_id in 0..*threads {
                    let buffer_clone = buffer.clone();
                    
                    let handle = std::thread::spawn(move || {
                        for i in 0..100 {
                            let credential = format!("AKIA{}{}_{:08x}", thread_id, i, i * 12345);
                            buffer_clone.add_credential(credential);
                        }
                    });
                    
                    handles.push(handle);
                }
                
                for handle in handles {
                    handle.join().unwrap();
                }
                
                let count = buffer.len();
                black_box(count);
                
                let drained = buffer.drain();
                black_box(drained);
            });
        });
    }
    
    group.finish();
}

fn bench_memory_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_throughput");
    
    for size_mb in [1, 10, 50, 100].iter() {
        group.benchmark_with_input(BenchmarkId::new("scan_throughput", size_mb), size_mb, |b, &size_mb| {
            let mut scanner = ZeroCopyScanner::new();
            let patterns = CredentialPatterns::get_optimized_patterns();
            scanner.add_credential_patterns(&patterns);
            
            let size_bytes = size_mb * 1024 * 1024;
            let credential_position = size_bytes / 2;
            
            let mut test_data = vec![b'x'; size_bytes];
            let credential = b"AKIA1234567890ABCDEF";
            test_data[credential_position..credential_position + credential.len()]
                .copy_from_slice(credential);
            
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(&test_data).unwrap();
            
            scanner.map_file(temp_file.path()).unwrap();
            
            b.iter(|| {
                let matches = scanner.scan_all_regions().unwrap();
                black_box(matches);
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_zero_copy_scanning,
    bench_lock_free_operations,
    bench_secure_memory_operations,
    bench_distributed_processing,
    bench_hardware_stealth,
    bench_pattern_matching_simd,
    bench_concurrent_credential_processing,
    bench_memory_throughput
);

criterion_main!(benches);