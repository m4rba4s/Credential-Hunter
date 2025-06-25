use enterprise_credential_hunter::core::{
    lockfree::{LockFreeQueue, AtomicCounter, ConcurrentCredentialBuffer},
    zero_copy::{ZeroCopyScanner, CredentialPatterns},
};
use enterprise_credential_hunter::memory::secure_allocator::SecureAllocator;
use std::sync::Arc;
use std::thread;

#[test]
fn test_lock_free_queue_basic() {
    let queue = LockFreeQueue::new();
    
    queue.enqueue(42);
    queue.enqueue(100);
    
    assert_eq!(queue.dequeue(), Some(42));
    assert_eq!(queue.dequeue(), Some(100));
    assert_eq!(queue.dequeue(), None);
    assert!(queue.is_empty());
}

#[test]
fn test_atomic_counter() {
    let counter = AtomicCounter::new(0);
    
    assert_eq!(counter.load(), 0);
    
    counter.increment();
    assert_eq!(counter.load(), 1);
    
    counter.increment();
    counter.increment();
    assert_eq!(counter.load(), 3);
    
    counter.decrement();
    assert_eq!(counter.load(), 2);
}

#[test]
fn test_concurrent_credential_buffer() {
    let buffer = ConcurrentCredentialBuffer::new(100);
    
    assert!(buffer.add_credential("test_credential_1".to_string()));
    assert!(buffer.add_credential("test_credential_2".to_string()));
    assert_eq!(buffer.len(), 2);
    
    assert!(!buffer.add_credential("test_credential_1".to_string())); // duplicate
    assert_eq!(buffer.len(), 2);
    
    let drained = buffer.drain();
    assert_eq!(drained.len(), 2);
    assert_eq!(buffer.len(), 0);
}

#[test]
fn test_zero_copy_scanner_creation() {
    let scanner = ZeroCopyScanner::new();
    let stats = scanner.get_performance_stats();
    
    assert_eq!(stats.total_regions, 0);
    assert_eq!(stats.active_patterns, 0);
    assert!(stats.estimated_throughput_mbps > 0.0);
}

#[test]
fn test_credential_patterns() {
    let patterns = CredentialPatterns::get_optimized_patterns();
    assert!(!patterns.is_empty());
    
    let high_entropy = CredentialPatterns::get_high_entropy_patterns();
    assert!(!high_entropy.is_empty());
    
    // Check that AWS key pattern exists
    assert!(patterns.iter().any(|p| *p == b"AKIA"));
}

#[test]
fn test_secure_allocator_stats() {
    let allocator = SecureAllocator::new();
    let stats = allocator.stats();
    
    assert_eq!(stats.total_allocations, 0);
    assert_eq!(stats.current_allocated, 0);
    assert!(stats.max_allocation_size > 0);
}

#[test]
fn test_concurrent_queue_operations() {
    let queue = Arc::new(LockFreeQueue::new());
    let mut handles = vec![];
    
    // Producer threads
    for i in 0..4 {
        let queue_clone = queue.clone();
        let handle = thread::spawn(move || {
            for j in 0..25 {
                queue_clone.enqueue(i * 100 + j);
            }
        });
        handles.push(handle);
    }
    
    // Wait for producers
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Consumer thread
    let mut count = 0;
    while queue.dequeue().is_some() {
        count += 1;
    }
    
    assert_eq!(count, 100); // 4 threads * 25 items each
}

#[test]
fn test_credential_buffer_capacity() {
    let buffer = ConcurrentCredentialBuffer::new(3);
    
    assert!(buffer.add_credential("cred1".to_string()));
    assert!(buffer.add_credential("cred2".to_string()));
    assert!(buffer.add_credential("cred3".to_string()));
    assert_eq!(buffer.len(), 3);
    
    // Adding beyond capacity should still work (it evicts old items)
    assert!(buffer.add_credential("cred4".to_string()));
    assert_eq!(buffer.len(), 3);
}

#[test]
fn test_pattern_scanner_with_patterns() {
    let mut scanner = ZeroCopyScanner::new();
    let patterns = vec![
        b"AKIA".as_slice(),
        b"secret".as_slice(),
        b"password".as_slice(),
    ];
    
    scanner.add_credential_patterns(&patterns);
    
    let stats = scanner.get_performance_stats();
    assert_eq!(stats.active_patterns, 3);
}

#[test]
fn test_concurrent_counter_stress() {
    let counter = Arc::new(AtomicCounter::new(0));
    let mut handles = vec![];
    
    for _ in 0..8 {
        let counter_clone = counter.clone();
        let handle = thread::spawn(move || {
            for _ in 0..1000 {
                counter_clone.increment();
            }
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    assert_eq!(counter.load(), 8000);
}