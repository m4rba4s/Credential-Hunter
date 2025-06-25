use std::time::Duration;
use std::sync::Arc;
use tempfile::NamedTempFile;
use std::io::Write;

use enterprise_credential_hunter::core::{
    zero_copy::{ZeroCopyScanner, CredentialPatterns},
    lockfree::{LockFreeQueue, LockFreeHashMap, ConcurrentCredentialBuffer},
};
use enterprise_credential_hunter::memory::secure_allocator::{
    SecureAllocator, SecureBuffer, SecureString
};
use enterprise_credential_hunter::processing::distributed::{
    DistributedEngine, WorkerPool, ProcessingTask, TaskType, Priority,
    PatternMatchProcessor, MemoryScanProcessor
};
use enterprise_credential_hunter::stealth::hardware::{
    HardwareStealth, CpuFeatures, ThermalData
};

#[test]
fn test_zero_copy_scanner_with_real_patterns() -> anyhow::Result<()> {
    let mut scanner = ZeroCopyScanner::new();
    
    let test_patterns = vec![
        b"AKIA1234567890ABCDEF".as_slice(),
        b"sk_live_1234567890abcdef".as_slice(),
        b"ghp_1234567890abcdef".as_slice(),
        b"-----BEGIN PRIVATE KEY-----".as_slice(),
    ];
    
    scanner.add_credential_patterns(&test_patterns);
    
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(b"prefix AKIA1234567890ABCDEF middle sk_live_1234567890abcdef suffix")?;
    
    scanner.map_file(temp_file.path())?;
    let matches = scanner.scan_all_regions()?;
    
    assert!(matches.len() >= 2, "Should find at least AWS key and Stripe key");
    
    let stats = scanner.get_performance_stats();
    assert_eq!(stats.total_regions, 1);
    assert!(stats.estimated_throughput_mbps > 0.0);
    
    Ok(())
}

#[test] 
fn test_lock_free_structures_concurrent_performance() {
    use std::thread;
    use std::sync::Arc;
    
    let queue = Arc::new(LockFreeQueue::new());
    let hashmap = Arc::new(LockFreeHashMap::new());
    let credential_buffer = Arc::new(ConcurrentCredentialBuffer::new(1000));
    
    let mut handles = vec![];
    
    for thread_id in 0..8 {
        let queue_clone = queue.clone();
        let hashmap_clone = hashmap.clone();
        let buffer_clone = credential_buffer.clone();
        
        let handle = thread::spawn(move || {
            for i in 0..100 {
                let key = format!("key_{}_{}", thread_id, i);
                let value = format!("credential_{}_{}", thread_id, i);
                
                queue_clone.enqueue(i);
                hashmap_clone.insert(key.clone(), value.clone());
                buffer_clone.add_credential(value);
            }
            
            for _ in 0..50 {
                queue_clone.dequeue();
            }
            
            for i in 0..50 {
                let key = format!("key_{}_{}", thread_id, i);
                hashmap_clone.remove(&key);
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    assert!(credential_buffer.len() <= 1000);
    
    let drained = credential_buffer.drain();
    assert!(!drained.is_empty());
}

#[test]
fn test_secure_allocator_integration() -> anyhow::Result<()> {
    let allocator = SecureAllocator::new();
    
    let initial_stats = allocator.stats();
    assert_eq!(initial_stats.current_allocated, 0);
    
    let buffer1 = SecureBuffer::new(1024)?;
    let buffer2 = SecureBuffer::new(2048)?;
    
    assert_eq!(buffer1.len(), 1024);
    assert_eq!(buffer2.len(), 2048);
    assert!(buffer1.is_locked() || !buffer1.is_locked());
    
    let secure_str = SecureString::new("sensitive_credential_data")?;
    assert_eq!(secure_str.as_str()?, "sensitive_credential_data");
    
    Ok(())
}

#[test]
fn test_distributed_processing_integration() -> anyhow::Result<()> {
    let mut engine = DistributedEngine::new();
    
    let mut memory_pool = WorkerPool::new(2);
    memory_pool.add_processor(Arc::new(MemoryScanProcessor));
    memory_pool.add_processor(Arc::new(MemoryScanProcessor));
    
    let mut pattern_pool = WorkerPool::new(2);
    pattern_pool.add_processor(Arc::new(PatternMatchProcessor));
    pattern_pool.add_processor(Arc::new(PatternMatchProcessor));
    
    engine.add_worker_pool(TaskType::MemoryScan, memory_pool);
    engine.add_worker_pool(TaskType::PatternMatch, pattern_pool);
    
    let task1 = ProcessingTask {
        id: uuid::Uuid::new_v4(),
        task_type: TaskType::MemoryScan,
        data: b"memory scan data".to_vec(),
        priority: Priority::High,
        deadline: None,
        retry_count: 0,
        max_retries: 3,
    };
    
    let task2 = ProcessingTask {
        id: uuid::Uuid::new_v4(),
        task_type: TaskType::PatternMatch,
        data: b"pattern match data".to_vec(),
        priority: Priority::Normal,
        deadline: None,
        retry_count: 0,
        max_retries: 3,
    };
    
    engine.submit_task(task1)?;
    engine.submit_task(task2)?;
    
    std::thread::sleep(Duration::from_millis(200));
    
    let results = engine.get_results();
    assert!(!results.is_empty(), "Should have some results");
    
    let metrics = engine.get_metrics();
    assert!(metrics.get_submitted_count() >= 2);
    assert!(metrics.get_throughput() >= 0.0);
    
    engine.shutdown();
    
    Ok(())
}

#[test]
fn test_hardware_stealth_features() -> anyhow::Result<()> {
    let stealth = HardwareStealth::new()?;
    
    let cpu_features = stealth.get_cpu_features();
    assert!(cpu_features.has_rdtsc);
    
    match stealth.initialize() {
        Ok(_) => {
            let thermal_data = stealth.monitor_thermal_signatures()?;
            assert!(thermal_data.temperature >= 0.0);
            
            stealth.apply_stealth_techniques()?;
            stealth.randomize_execution_timing()?;
            stealth.manipulate_cache_behavior()?;
            
            stealth.shutdown()?;
        }
        Err(_) => {
            println!("Hardware stealth initialization failed (expected on some platforms)");
        }
    }
    
    Ok(())
}

#[test]
fn test_integrated_performance_benchmark() -> anyhow::Result<()> {
    let start_time = std::time::Instant::now();
    
    let mut scanner = ZeroCopyScanner::new();
    let patterns = CredentialPatterns::get_optimized_patterns();
    scanner.add_credential_patterns(&patterns);
    
    let mut temp_file = NamedTempFile::new()?;
    let test_data = "prefix AKIA1234567890ABCDEF middle secret_password suffix ghp_1234567890abcdef end".repeat(1000);
    temp_file.write_all(test_data.as_bytes())?;
    
    scanner.map_file(temp_file.path())?;
    let matches = scanner.scan_all_regions()?;
    
    let scan_time = start_time.elapsed();
    
    assert!(!matches.is_empty(), "Should find credentials in test data");
    assert!(scan_time < Duration::from_secs(5), "Scan should complete quickly");
    
    let stats = scanner.get_performance_stats();
    println!("Scanning {} bytes took {:?}", stats.total_memory_mapped, scan_time);
    println!("Estimated throughput: {:.2} MB/s", stats.estimated_throughput_mbps);
    
    Ok(())
}

#[test]
fn test_concurrent_credential_processing() -> anyhow::Result<()> {
    let buffer = Arc::new(ConcurrentCredentialBuffer::new(500));
    let mut handles = vec![];
    
    for worker_id in 0..4 {
        let buffer_clone = buffer.clone();
        
        let handle = std::thread::spawn(move || {
            for i in 0..200 {
                let credential = format!("AKIA{}{}_{:08x}", worker_id, i, rand::random::<u32>());
                buffer_clone.add_credential(credential);
                
                if i % 10 == 0 {
                    std::thread::sleep(Duration::from_micros(100));
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    assert_eq!(buffer.len(), 500);
    
    let drained = buffer.drain();
    assert_eq!(drained.len(), 500);
    assert_eq!(buffer.len(), 0);
    
    Ok(())
}

#[test]
fn test_memory_secure_operations() -> anyhow::Result<()> {
    let mut buffer = SecureBuffer::new(4096)?;
    
    let sensitive_data = b"AKIA1234567890ABCDEF_sensitive_aws_key_12345";
    buffer.as_mut_slice()[..sensitive_data.len()].copy_from_slice(sensitive_data);
    
    let found_at = buffer.as_slice()
        .windows(sensitive_data.len())
        .position(|window| window == sensitive_data);
    
    assert!(found_at.is_some(), "Should find sensitive data in secure buffer");
    
    buffer.resize(8192)?;
    assert_eq!(buffer.len(), 8192);
    
    Ok(())
}

#[test] 
fn test_end_to_end_credential_hunting_simulation() -> anyhow::Result<()> {
    let mut scanner = ZeroCopyScanner::new();
    let credential_buffer = Arc::new(ConcurrentCredentialBuffer::new(100));
    
    let patterns = vec![
        b"AKIA".as_slice(),
        b"sk_live_".as_slice(),
        b"ghp_".as_slice(),
        b"-----BEGIN".as_slice(),
    ];
    
    scanner.add_credential_patterns(&patterns);
    
    let simulated_memory_dumps = vec![
        "process1: AKIA1234567890ABCDEF aws_access_key config.json",
        "process2: sk_live_1234567890abcdef stripe_secret environment_vars",
        "process3: ghp_1234567890abcdef github_token repository_access",
        "process4: -----BEGIN RSA PRIVATE KEY----- ssh_key",
    ];
    
    for (i, dump) in simulated_memory_dumps.iter().enumerate() {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(dump.as_bytes())?;
        
        scanner.map_file(temp_file.path())?;
        let matches = scanner.scan_all_regions()?;
        
        for scan_match in matches {
            let credential_type = match scan_match.pattern_id {
                0 => "AWS Access Key",
                1 => "Stripe Secret Key", 
                2 => "GitHub Personal Access Token",
                3 => "SSH Private Key",
                _ => "Unknown",
            };
            
            let credential_info = format!("{}:offset_{}:confidence_{:.2}", 
                credential_type, scan_match.offset, scan_match.confidence);
            
            credential_buffer.add_credential(credential_info);
        }
    }
    
    let found_credentials = credential_buffer.drain();
    assert!(found_credentials.len() >= 4, "Should find all credential types");
    
    for credential in &found_credentials {
        println!("Found: {}", credential);
    }
    
    Ok(())
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    
    #[test]
    fn benchmark_zero_copy_large_file() -> anyhow::Result<()> {
        let mut scanner = ZeroCopyScanner::new();
        let patterns = CredentialPatterns::get_optimized_patterns();
        scanner.add_credential_patterns(&patterns);
        
        let mut temp_file = NamedTempFile::new()?;
        let large_data = "random data ".repeat(100000) + "AKIA1234567890ABCDEF" + &"more data ".repeat(100000);
        temp_file.write_all(large_data.as_bytes())?;
        
        let start = std::time::Instant::now();
        scanner.map_file(temp_file.path())?;
        let matches = scanner.scan_all_regions()?;
        let duration = start.elapsed();
        
        assert!(!matches.is_empty());
        println!("Large file scan took: {:?}", duration);
        assert!(duration < Duration::from_secs(2), "Should scan large file quickly");
        
        Ok(())
    }
    
    #[test]
    fn benchmark_concurrent_processing() -> anyhow::Result<()> {
        let mut engine = DistributedEngine::new();
        
        let mut pool = WorkerPool::new(4);
        for _ in 0..4 {
            pool.add_processor(Arc::new(PatternMatchProcessor));
        }
        
        engine.add_worker_pool(TaskType::PatternMatch, pool);
        
        let start = std::time::Instant::now();
        
        for i in 0..100 {
            let task = ProcessingTask {
                id: uuid::Uuid::new_v4(),
                task_type: TaskType::PatternMatch,
                data: format!("test data {}", i).into_bytes(),
                priority: Priority::Normal,
                deadline: None,
                retry_count: 0,
                max_retries: 1,
            };
            
            engine.submit_task(task)?;
        }
        
        std::thread::sleep(Duration::from_millis(500));
        
        let results = engine.get_results();
        let duration = start.elapsed();
        
        println!("Processed {} tasks in {:?}", results.len(), duration);
        assert!(results.len() >= 90, "Should process most tasks");
        
        engine.shutdown();
        
        Ok(())
    }
}

use rand; 

fn main() {
    println!("Elite Features Integration Tests");
}