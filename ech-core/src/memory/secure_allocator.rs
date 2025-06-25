use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr::{null_mut, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::mem::{align_of, size_of};
use libc::{mprotect, PROT_READ, PROT_WRITE, PROT_NONE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FAILED};
use zeroize::{Zeroize, ZeroizeOnDrop};
use anyhow::{Result, anyhow};

#[cfg(target_os = "linux")]
use libc::{mmap, munmap, mlock, munlock, MAP_LOCKED};

#[cfg(target_os = "windows")]
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, VirtualProtect};

#[cfg(target_os = "windows")]
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE, PAGE_NOACCESS};

const CANARY_SIZE: usize = 16;
const GUARD_PAGE_SIZE: usize = 4096;
const MAX_ALLOCATION_SIZE: usize = 1024 * 1024 * 16;

#[repr(C, align(64))]
struct AllocationHeader {
    size: usize,
    canary: [u8; CANARY_SIZE],
    magic: u64,
    allocation_id: u64,
}

impl AllocationHeader {
    const MAGIC: u64 = 0xDEADBEEFCAFEBABE;
    
    fn new(size: usize, allocation_id: u64) -> Self {
        let mut header = Self {
            size,
            canary: [0; CANARY_SIZE],
            magic: Self::MAGIC,
            allocation_id,
        };
        
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        size.hash(&mut hasher);
        allocation_id.hash(&mut hasher);
        let hash = hasher.finish();
        
        for (i, byte) in header.canary.iter_mut().enumerate() {
            *byte = ((hash >> (i * 8)) & 0xFF) as u8;
        }
        
        header
    }
    
    fn verify(&self) -> bool {
        if self.magic != Self::MAGIC {
            return false;
        }
        
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.size.hash(&mut hasher);
        self.allocation_id.hash(&mut hasher);
        let expected_hash = hasher.finish();
        
        for (i, &byte) in self.canary.iter().enumerate() {
            let expected_byte = ((expected_hash >> (i * 8)) & 0xFF) as u8;
            if byte != expected_byte {
                return false;
            }
        }
        
        true
    }
}

pub struct SecureAllocator {
    allocation_counter: AtomicUsize,
    total_allocated: AtomicUsize,
    max_allocation_size: usize,
}

impl SecureAllocator {
    pub const fn new() -> Self {
        Self {
            allocation_counter: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
            max_allocation_size: MAX_ALLOCATION_SIZE,
        }
    }
    
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            allocation_counter: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
            max_allocation_size: max_size,
        }
    }
    
    fn allocate_secure(&self, layout: Layout) -> *mut u8 {
        if layout.size() > self.max_allocation_size {
            return null_mut();
        }
        
        let allocation_id = self.allocation_counter.fetch_add(1, Ordering::SeqCst) as u64;
        
        let total_size = layout.size() + size_of::<AllocationHeader>() + GUARD_PAGE_SIZE * 2;
        let aligned_size = (total_size + GUARD_PAGE_SIZE - 1) & !(GUARD_PAGE_SIZE - 1);
        
        #[cfg(target_os = "linux")]
        let ptr = unsafe {
            mmap(
                null_mut(),
                aligned_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        
        #[cfg(target_os = "windows")]
        let ptr = unsafe {
            VirtualAlloc(
                null_mut(),
                aligned_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        
        #[cfg(target_os = "linux")]
        if ptr == MAP_FAILED {
            return null_mut();
        }
        
        #[cfg(target_os = "windows")]
        if ptr.is_null() {
            return null_mut();
        }
        
        let guard_start = ptr as *mut u8;
        let data_start = unsafe { guard_start.add(GUARD_PAGE_SIZE) };
        let guard_end = unsafe { data_start.add(layout.size() + size_of::<AllocationHeader>()) };
        
        #[cfg(target_os = "linux")]
        unsafe {
            mprotect(guard_start as *mut _, GUARD_PAGE_SIZE, PROT_NONE);
            mprotect(guard_end as *mut _, GUARD_PAGE_SIZE, PROT_NONE);
            mlock(data_start as *mut _, layout.size() + size_of::<AllocationHeader>());
        }
        
        #[cfg(target_os = "windows")]
        unsafe {
            let mut old_protect = 0;
            VirtualProtect(guard_start as *mut _, GUARD_PAGE_SIZE, PAGE_NOACCESS, &mut old_protect);
            VirtualProtect(guard_end as *mut _, GUARD_PAGE_SIZE, PAGE_NOACCESS, &mut old_protect);
            VirtualLock(data_start as *mut _, layout.size() + size_of::<AllocationHeader>());
        }
        
        let header = unsafe { &mut *(data_start as *mut AllocationHeader) };
        *header = AllocationHeader::new(layout.size(), allocation_id);
        
        let user_ptr = unsafe { data_start.add(size_of::<AllocationHeader>()) };
        
        self.total_allocated.fetch_add(layout.size(), Ordering::SeqCst);
        
        user_ptr
    }
    
    fn deallocate_secure(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        
        let header_ptr = unsafe { ptr.sub(size_of::<AllocationHeader>()) };
        let header = unsafe { &*(header_ptr as *const AllocationHeader) };
        
        if !header.verify() {
            panic!("Heap corruption detected: invalid canary or magic number");
        }
        
        if header.size != layout.size() {
            panic!("Heap corruption detected: size mismatch");
        }
        
        unsafe {
            std::ptr::write_bytes(ptr, 0xDEu8, layout.size());
        }
        
        let guard_start = unsafe { header_ptr.sub(GUARD_PAGE_SIZE) };
        let total_size = layout.size() + size_of::<AllocationHeader>() + GUARD_PAGE_SIZE * 2;
        let aligned_size = (total_size + GUARD_PAGE_SIZE - 1) & !(GUARD_PAGE_SIZE - 1);
        
        #[cfg(target_os = "linux")]
        unsafe {
            munlock(header_ptr as *mut _, layout.size() + size_of::<AllocationHeader>());
            munmap(guard_start as *mut _, aligned_size);
        }
        
        #[cfg(target_os = "windows")]
        unsafe {
            VirtualUnlock(header_ptr as *mut _, layout.size() + size_of::<AllocationHeader>());
            VirtualFree(guard_start as *mut _, 0, MEM_RELEASE);
        }
        
        self.total_allocated.fetch_sub(layout.size(), Ordering::SeqCst);
    }
    
    pub fn stats(&self) -> AllocatorStats {
        AllocatorStats {
            total_allocations: self.allocation_counter.load(Ordering::SeqCst),
            current_allocated: self.total_allocated.load(Ordering::SeqCst),
            max_allocation_size: self.max_allocation_size,
        }
    }
}

unsafe impl GlobalAlloc for SecureAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate_secure(layout)
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.deallocate_secure(ptr, layout);
    }
}

#[derive(Debug, Clone)]
pub struct AllocatorStats {
    pub total_allocations: usize,
    pub current_allocated: usize,
    pub max_allocation_size: usize,
}

pub struct SecureBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Result<Self> {
        let mut data = vec![0u8; size];
        
        #[cfg(target_os = "linux")]
        let lock_result = unsafe {
            mlock(data.as_mut_ptr() as *mut _, size)
        };
        
        #[cfg(target_os = "windows")]
        let lock_result = unsafe {
            if VirtualLock(data.as_mut_ptr() as *mut _, size) != 0 { 0 } else { -1 }
        };
        
        let locked = lock_result == 0;
        
        Ok(Self { data, locked })
    }
    
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let mut buffer = Self::new(slice.len())?;
        buffer.data.copy_from_slice(slice);
        Ok(buffer)
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    pub fn is_locked(&self) -> bool {
        self.locked
    }
    
    pub fn resize(&mut self, new_size: usize) -> Result<()> {
        if self.locked {
            #[cfg(target_os = "linux")]
            unsafe {
                munlock(self.data.as_mut_ptr() as *mut _, self.data.len());
            }
            
            #[cfg(target_os = "windows")]
            unsafe {
                VirtualUnlock(self.data.as_mut_ptr() as *mut _, self.data.len());
            }
        }
        
        self.data.resize(new_size, 0);
        
        if self.locked {
            #[cfg(target_os = "linux")]
            let lock_result = unsafe {
                mlock(self.data.as_mut_ptr() as *mut _, new_size)
            };
            
            #[cfg(target_os = "windows")]
            let lock_result = unsafe {
                if VirtualLock(self.data.as_mut_ptr() as *mut _, new_size) != 0 { 0 } else { -1 }
            };
            
            self.locked = lock_result == 0;
        }
        
        Ok(())
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        
        if self.locked {
            #[cfg(target_os = "linux")]
            unsafe {
                munlock(self.data.as_mut_ptr() as *mut _, self.data.len());
            }
            
            #[cfg(target_os = "windows")]
            unsafe {
                VirtualUnlock(self.data.as_mut_ptr() as *mut _, self.data.len());
            }
        }
    }
}

pub struct SecureString {
    buffer: SecureBuffer,
}

impl SecureString {
    pub fn new(s: &str) -> Result<Self> {
        let buffer = SecureBuffer::from_slice(s.as_bytes())?;
        Ok(Self { buffer })
    }
    
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.buffer.as_slice())
            .map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }
    
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

pub static SECURE_ALLOCATOR: SecureAllocator = SecureAllocator::new();

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc, dealloc};
    
    #[test]
    fn test_secure_allocator_basic() {
        let allocator = SecureAllocator::new();
        let layout = Layout::new::<u64>();
        
        let ptr = allocator.allocate_secure(layout);
        assert!(!ptr.is_null());
        
        unsafe {
            *(ptr as *mut u64) = 0x1234567890ABCDEF;
            assert_eq!(*(ptr as *const u64), 0x1234567890ABCDEF);
        }
        
        allocator.deallocate_secure(ptr, layout);
    }
    
    #[test]
    fn test_allocation_header() {
        let header = AllocationHeader::new(1024, 42);
        assert!(header.verify());
        assert_eq!(header.size, 1024);
        assert_eq!(header.allocation_id, 42);
        assert_eq!(header.magic, AllocationHeader::MAGIC);
    }
    
    #[test]
    fn test_secure_buffer() -> Result<()> {
        let mut buffer = SecureBuffer::new(100)?;
        assert_eq!(buffer.len(), 100);
        
        buffer.as_mut_slice()[0] = 42;
        assert_eq!(buffer.as_slice()[0], 42);
        
        buffer.resize(200)?;
        assert_eq!(buffer.len(), 200);
        assert_eq!(buffer.as_slice()[0], 42);
        
        Ok(())
    }
    
    #[test]
    fn test_secure_string() -> Result<()> {
        let secure_str = SecureString::new("Hello, secure world!")?;
        assert_eq!(secure_str.as_str()?, "Hello, secure world!");
        assert_eq!(secure_str.len(), 20);
        
        Ok(())
    }
    
    #[test]
    fn test_allocator_stats() {
        let allocator = SecureAllocator::new();
        let initial_stats = allocator.stats();
        
        let layout = Layout::new::<[u8; 1024]>();
        let ptr = allocator.allocate_secure(layout);
        
        let after_alloc_stats = allocator.stats();
        assert_eq!(after_alloc_stats.total_allocations, initial_stats.total_allocations + 1);
        assert_eq!(after_alloc_stats.current_allocated, initial_stats.current_allocated + 1024);
        
        allocator.deallocate_secure(ptr, layout);
        
        let after_dealloc_stats = allocator.stats();
        assert_eq!(after_dealloc_stats.current_allocated, initial_stats.current_allocated);
    }
    
    #[test]
    #[should_panic(expected = "Heap corruption detected")]
    fn test_corruption_detection() {
        let allocator = SecureAllocator::new();
        let layout = Layout::new::<u64>();
        
        let ptr = allocator.allocate_secure(layout);
        let header_ptr = unsafe { ptr.sub(size_of::<AllocationHeader>()) };
        let header = unsafe { &mut *(header_ptr as *mut AllocationHeader) };
        
        header.magic = 0xDEADDEADDEADDEAD;
        
        allocator.deallocate_secure(ptr, layout);
    }
}