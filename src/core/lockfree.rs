use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::ptr::{null_mut, NonNull};
use std::mem::{align_of, size_of, MaybeUninit};
use std::alloc::{alloc, dealloc, Layout};
use crossbeam_epoch::{self as epoch, Atomic, Owned, Shared, Guard};
use anyhow::Result;

#[repr(align(64))]
pub struct CacheLinePadded<T> {
    value: T,
}

impl<T> CacheLinePadded<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
    
    pub fn get(&self) -> &T {
        &self.value
    }
    
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

pub struct LockFreeQueue<T> {
    head: Atomic<Node<T>>,
    tail: Atomic<Node<T>>,
}

struct Node<T> {
    data: MaybeUninit<T>,
    next: Atomic<Node<T>>,
}

impl<T> Node<T> {
    fn new() -> Self {
        Self {
            data: MaybeUninit::uninit(),
            next: Atomic::null(),
        }
    }
    
    fn new_with_data(data: T) -> Self {
        Self {
            data: MaybeUninit::new(data),
            next: Atomic::null(),
        }
    }
}

impl<T> LockFreeQueue<T> {
    pub fn new() -> Self {
        let dummy = Owned::new(Node::new());
        let dummy_ptr = dummy.into_shared(unsafe { epoch::unprotected() });
        
        Self {
            head: Atomic::from(dummy_ptr),
            tail: Atomic::from(dummy_ptr),
        }
    }
    
    pub fn enqueue(&self, data: T) {
        let new_node = Owned::new(Node::new_with_data(data));
        let guard = &epoch::pin();
        
        loop {
            let tail = self.tail.load(Ordering::Acquire, guard);
            let next = unsafe { tail.deref() }.next.load(Ordering::Acquire, guard);
            
            if next.is_null() {
                match unsafe { tail.deref() }.next.compare_exchange_weak(
                    Shared::null(),
                    new_node.clone(),
                    Ordering::Release,
                    Ordering::Relaxed,
                    guard,
                ) {
                    Ok(_) => {
                        let _ = self.tail.compare_exchange_weak(
                            tail,
                            new_node.into_shared(guard),
                            Ordering::Release,
                            Ordering::Relaxed,
                            guard,
                        );
                        break;
                    }
                    Err(e) => {
                        new_node = e.new;
                    }
                }
            } else {
                let _ = self.tail.compare_exchange_weak(
                    tail,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                    guard,
                );
            }
        }
    }
    
    pub fn dequeue(&self) -> Option<T> {
        let guard = &epoch::pin();
        
        loop {
            let head = self.head.load(Ordering::Acquire, guard);
            let tail = self.tail.load(Ordering::Acquire, guard);
            let next = unsafe { head.deref() }.next.load(Ordering::Acquire, guard);
            
            if head == tail {
                if next.is_null() {
                    return None;
                }
                let _ = self.tail.compare_exchange_weak(
                    tail,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                    guard,
                );
            } else {
                if next.is_null() {
                    continue;
                }
                
                let data = unsafe { next.deref().data.as_ptr().read() };
                
                match self.head.compare_exchange_weak(
                    head,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                    guard,
                ) {
                    Ok(_) => {
                        unsafe { guard.defer_destroy(head) };
                        return Some(data);
                    }
                    Err(_) => {
                        std::mem::forget(data);
                    }
                }
            }
        }
    }
    
    pub fn is_empty(&self) -> bool {
        let guard = &epoch::pin();
        let head = self.head.load(Ordering::Acquire, guard);
        let tail = self.tail.load(Ordering::Acquire, guard);
        head == tail && unsafe { head.deref() }.next.load(Ordering::Acquire, guard).is_null()
    }
}

pub struct LockFreeHashMap<K, V> {
    buckets: Vec<CacheLinePadded<Atomic<HashNode<K, V>>>>,
    bucket_count: usize,
}

struct HashNode<K, V> {
    key: K,
    value: V,
    hash: u64,
    next: Atomic<HashNode<K, V>>,
}

impl<K, V> HashNode<K, V> {
    fn new(key: K, value: V, hash: u64) -> Self {
        Self {
            key,
            value,
            hash,
            next: Atomic::null(),
        }
    }
}

impl<K: Clone + PartialEq, V: Clone> LockFreeHashMap<K, V> {
    pub fn new() -> Self {
        Self::with_capacity(16)
    }
    
    pub fn with_capacity(capacity: usize) -> Self {
        let bucket_count = capacity.next_power_of_two();
        let mut buckets = Vec::with_capacity(bucket_count);
        
        for _ in 0..bucket_count {
            buckets.push(CacheLinePadded::new(Atomic::null()));
        }
        
        Self {
            buckets,
            bucket_count,
        }
    }
    
    fn hash(&self, key: &K) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
    
    fn get_bucket_index(&self, hash: u64) -> usize {
        (hash as usize) & (self.bucket_count - 1)
    }
    
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let hash = self.hash(&key);
        let bucket_index = self.get_bucket_index(hash);
        let bucket = &self.buckets[bucket_index];
        let guard = &epoch::pin();
        
        let new_node = Owned::new(HashNode::new(key.clone(), value, hash));
        
        loop {
            let head = bucket.get().load(Ordering::Acquire, guard);
            
            let mut current = head;
            while !current.is_null() {
                let node = unsafe { current.deref() };
                if node.hash == hash && node.key == key {
                    let old_value = node.value.clone();
                    return Some(old_value);
                }
                current = node.next.load(Ordering::Acquire, guard);
            }
            
            new_node.next.store(head, Ordering::Relaxed);
            
            match bucket.get().compare_exchange_weak(
                head,
                new_node.clone(),
                Ordering::Release,
                Ordering::Relaxed,
                guard,
            ) {
                Ok(_) => {
                    new_node.into_shared(guard);
                    return None;
                }
                Err(e) => {
                    new_node = e.new;
                }
            }
        }
    }
    
    pub fn get(&self, key: &K) -> Option<V> {
        let hash = self.hash(key);
        let bucket_index = self.get_bucket_index(hash);
        let bucket = &self.buckets[bucket_index];
        let guard = &epoch::pin();
        
        let mut current = bucket.get().load(Ordering::Acquire, guard);
        
        while !current.is_null() {
            let node = unsafe { current.deref() };
            if node.hash == hash && node.key == *key {
                return Some(node.value.clone());
            }
            current = node.next.load(Ordering::Acquire, guard);
        }
        
        None
    }
    
    pub fn remove(&self, key: &K) -> Option<V> {
        let hash = self.hash(key);
        let bucket_index = self.get_bucket_index(hash);
        let bucket = &self.buckets[bucket_index];
        let guard = &epoch::pin();
        
        loop {
            let head = bucket.get().load(Ordering::Acquire, guard);
            
            if head.is_null() {
                return None;
            }
            
            let first_node = unsafe { head.deref() };
            if first_node.hash == hash && first_node.key == *key {
                let next = first_node.next.load(Ordering::Acquire, guard);
                match bucket.get().compare_exchange_weak(
                    head,
                    next,
                    Ordering::Release,
                    Ordering::Relaxed,
                    guard,
                ) {
                    Ok(_) => {
                        let value = first_node.value.clone();
                        unsafe { guard.defer_destroy(head) };
                        return Some(value);
                    }
                    Err(_) => continue,
                }
            }
            
            let mut prev = head;
            let mut current = first_node.next.load(Ordering::Acquire, guard);
            
            while !current.is_null() {
                let node = unsafe { current.deref() };
                if node.hash == hash && node.key == *key {
                    let next = node.next.load(Ordering::Acquire, guard);
                    match unsafe { prev.deref() }.next.compare_exchange_weak(
                        current,
                        next,
                        Ordering::Release,
                        Ordering::Relaxed,
                        guard,
                    ) {
                        Ok(_) => {
                            let value = node.value.clone();
                            unsafe { guard.defer_destroy(current) };
                            return Some(value);
                        }
                        Err(_) => break,
                    }
                }
                prev = current;
                current = node.next.load(Ordering::Acquire, guard);
            }
            
            return None;
        }
    }
}

pub struct AtomicCounter {
    value: CacheLinePadded<AtomicUsize>,
}

impl AtomicCounter {
    pub fn new(initial: usize) -> Self {
        Self {
            value: CacheLinePadded::new(AtomicUsize::new(initial)),
        }
    }
    
    pub fn increment(&self) -> usize {
        self.value.get().fetch_add(1, Ordering::SeqCst)
    }
    
    pub fn decrement(&self) -> usize {
        self.value.get().fetch_sub(1, Ordering::SeqCst)
    }
    
    pub fn load(&self) -> usize {
        self.value.get().load(Ordering::SeqCst)
    }
    
    pub fn store(&self, value: usize) {
        self.value.get().store(value, Ordering::SeqCst);
    }
    
    pub fn compare_exchange(&self, current: usize, new: usize) -> Result<usize, usize> {
        self.value.get().compare_exchange(
            current,
            new,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
    }
}

pub struct LockFreeStack<T> {
    head: Atomic<StackNode<T>>,
}

struct StackNode<T> {
    data: T,
    next: Atomic<StackNode<T>>,
}

impl<T> StackNode<T> {
    fn new(data: T) -> Self {
        Self {
            data,
            next: Atomic::null(),
        }
    }
}

impl<T> LockFreeStack<T> {
    pub fn new() -> Self {
        Self {
            head: Atomic::null(),
        }
    }
    
    pub fn push(&self, data: T) {
        let new_node = Owned::new(StackNode::new(data));
        let guard = &epoch::pin();
        
        loop {
            let head = self.head.load(Ordering::Acquire, guard);
            new_node.next.store(head, Ordering::Relaxed);
            
            match self.head.compare_exchange_weak(
                head,
                new_node.clone(),
                Ordering::Release,
                Ordering::Relaxed,
                guard,
            ) {
                Ok(_) => {
                    new_node.into_shared(guard);
                    break;
                }
                Err(e) => {
                    new_node = e.new;
                }
            }
        }
    }
    
    pub fn pop(&self) -> Option<T> {
        let guard = &epoch::pin();
        
        loop {
            let head = self.head.load(Ordering::Acquire, guard);
            
            if head.is_null() {
                return None;
            }
            
            let next = unsafe { head.deref() }.next.load(Ordering::Acquire, guard);
            
            match self.head.compare_exchange_weak(
                head,
                next,
                Ordering::Release,
                Ordering::Relaxed,
                guard,
            ) {
                Ok(_) => {
                    let data = unsafe { std::ptr::read(&head.deref().data) };
                    unsafe { guard.defer_destroy(head) };
                    return Some(data);
                }
                Err(_) => continue,
            }
        }
    }
    
    pub fn is_empty(&self) -> bool {
        let guard = &epoch::pin();
        self.head.load(Ordering::Acquire, guard).is_null()
    }
}

pub struct ConcurrentCredentialBuffer {
    queue: LockFreeQueue<String>,
    hash_map: LockFreeHashMap<String, u64>,
    counter: AtomicCounter,
    capacity: usize,
}

impl ConcurrentCredentialBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: LockFreeQueue::new(),
            hash_map: LockFreeHashMap::with_capacity(capacity),
            counter: AtomicCounter::new(0),
            capacity,
        }
    }
    
    pub fn add_credential(&self, credential: String) -> bool {
        if self.counter.load() >= self.capacity {
            self.queue.dequeue();
            self.counter.decrement();
        }
        
        let hash = self.calculate_hash(&credential);
        
        if self.hash_map.get(&credential).is_some() {
            return false;
        }
        
        self.queue.enqueue(credential.clone());
        self.hash_map.insert(credential, hash);
        self.counter.increment();
        
        true
    }
    
    pub fn contains(&self, credential: &str) -> bool {
        self.hash_map.get(&credential.to_string()).is_some()
    }
    
    pub fn drain(&self) -> Vec<String> {
        let mut results = Vec::new();
        
        while let Some(credential) = self.queue.dequeue() {
            results.push(credential);
            self.counter.decrement();
        }
        
        results
    }
    
    pub fn len(&self) -> usize {
        self.counter.load()
    }
    
    fn calculate_hash(&self, data: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;
    
    #[test]
    fn test_lock_free_queue() {
        let queue = LockFreeQueue::new();
        
        queue.enqueue(1);
        queue.enqueue(2);
        queue.enqueue(3);
        
        assert_eq!(queue.dequeue(), Some(1));
        assert_eq!(queue.dequeue(), Some(2));
        assert_eq!(queue.dequeue(), Some(3));
        assert_eq!(queue.dequeue(), None);
    }
    
    #[test]
    fn test_lock_free_hash_map() {
        let map = LockFreeHashMap::new();
        
        assert_eq!(map.insert("key1".to_string(), "value1".to_string()), None);
        assert_eq!(map.get(&"key1".to_string()), Some("value1".to_string()));
        
        assert_eq!(map.insert("key1".to_string(), "value2".to_string()), Some("value1".to_string()));
        assert_eq!(map.get(&"key1".to_string()), Some("value1".to_string()));
        
        assert_eq!(map.remove(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(map.get(&"key1".to_string()), None);
    }
    
    #[test]
    fn test_concurrent_queue_operations() {
        let queue = Arc::new(LockFreeQueue::new());
        let mut handles = vec![];
        
        for i in 0..10 {
            let queue_clone = queue.clone();
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    queue_clone.enqueue(i * 100 + j);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let mut count = 0;
        while queue.dequeue().is_some() {
            count += 1;
        }
        
        assert_eq!(count, 1000);
    }
    
    #[test]
    fn test_atomic_counter() {
        let counter = Arc::new(AtomicCounter::new(0));
        let mut handles = vec![];
        
        for _ in 0..10 {
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
        
        assert_eq!(counter.load(), 10000);
    }
    
    #[test]
    fn test_concurrent_credential_buffer() {
        let buffer = Arc::new(ConcurrentCredentialBuffer::new(100));
        let mut handles = vec![];
        
        for i in 0..5 {
            let buffer_clone = buffer.clone();
            let handle = thread::spawn(move || {
                for j in 0..20 {
                    let credential = format!("credential_{}_{}", i, j);
                    buffer_clone.add_credential(credential);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(buffer.len(), 100);
        
        let drained = buffer.drain();
        assert_eq!(drained.len(), 100);
        assert_eq!(buffer.len(), 0);
    }
    
    #[test]
    fn test_lock_free_stack() {
        let stack = LockFreeStack::new();
        
        stack.push(1);
        stack.push(2);
        stack.push(3);
        
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert_eq!(stack.pop(), None);
        assert!(stack.is_empty());
    }
}