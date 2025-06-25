use wide::*;
use aligned_vec::AVec;

pub fn is_simd_available() -> bool {
    cfg!(any(target_feature = "sse4.1", target_feature = "avx2", target_feature = "neon"))
}

pub fn get_optimal_chunk_size() -> usize {
    if cfg!(target_feature = "avx2") {
        32
    } else if cfg!(target_feature = "sse4.1") {
        16
    } else {
        8
    }
}

pub fn create_aligned_buffer(size: usize) -> AVec<u8> {
    AVec::with_capacity(64, size)
}

pub struct SimdProcessor {
    chunk_size: usize,
}

impl SimdProcessor {
    pub fn new() -> Self {
        Self {
            chunk_size: get_optimal_chunk_size(),
        }
    }
    
    pub fn process_chunks<F>(&self, data: &[u8], mut processor: F) -> Vec<usize>
    where
        F: FnMut(&[u8], usize) -> Option<usize>,
    {
        let mut results = Vec::new();
        
        for (chunk_idx, chunk) in data.chunks(self.chunk_size).enumerate() {
            if let Some(result) = processor(chunk, chunk_idx * self.chunk_size) {
                results.push(result);
            }
        }
        
        results
    }
    
    #[cfg(target_feature = "avx2")]
    pub fn compare_bytes_avx2(&self, data: &[u8], pattern: u8) -> Vec<usize> {
        let mut matches = Vec::new();
        
        // Simplified implementation - in practice would use proper AVX2 intrinsics
        for (i, &byte) in data.iter().enumerate() {
            if byte == pattern {
                matches.push(i);
            }
        }
        
        matches
    }
    
    #[cfg(target_feature = "sse4.1")]
    pub fn compare_bytes_sse(&self, data: &[u8], pattern: u8) -> Vec<usize> {
        let mut matches = Vec::new();
        
        // Simplified implementation - in practice would use proper SSE intrinsics
        for (i, &byte) in data.iter().enumerate() {
            if byte == pattern {
                matches.push(i);
            }
        }
        
        matches
    }
    
    pub fn compare_bytes_scalar(&self, data: &[u8], pattern: u8) -> Vec<usize> {
        data.iter()
            .enumerate()
            .filter_map(|(i, &byte)| if byte == pattern { Some(i) } else { None })
            .collect()
    }
    
    pub fn find_byte_pattern(&self, data: &[u8], pattern: u8) -> Vec<usize> {
        #[cfg(target_feature = "avx2")]
        {
            return self.compare_bytes_avx2(data, pattern);
        }
        
        #[cfg(all(target_feature = "sse4.1", not(target_feature = "avx2")))]
        {
            return self.compare_bytes_sse(data, pattern);
        }
        
        #[cfg(not(any(target_feature = "avx2", target_feature = "sse4.1")))]
        {
            return self.compare_bytes_scalar(data, pattern);
        }
    }
    
    pub fn parallel_byte_count(&self, data: &[u8], pattern: u8) -> usize {
        use rayon::prelude::*;
        
        data.par_chunks(self.chunk_size)
            .map(|chunk| chunk.iter().filter(|&&b| b == pattern).count())
            .sum()
    }
    
    pub fn memory_prefetch(&self, data: &[u8]) {
        // Prefetch memory for better cache performance
        const PREFETCH_DISTANCE: usize = 64;
        
        for chunk in data.chunks(PREFETCH_DISTANCE) {
            unsafe {
                std::arch::x86_64::_mm_prefetch(
                    chunk.as_ptr() as *const i8,
                    std::arch::x86_64::_MM_HINT_T0
                );
            }
        }
    }
}

pub fn validate_alignment(ptr: *const u8, alignment: usize) -> bool {
    (ptr as usize) % alignment == 0
}

pub fn align_pointer_up(ptr: *const u8, alignment: usize) -> *const u8 {
    let addr = ptr as usize;
    let aligned_addr = (addr + alignment - 1) & !(alignment - 1);
    aligned_addr as *const u8
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_availability() {
        // This test will pass on most modern x86_64 systems
        let available = is_simd_available();
        println!("SIMD available: {}", available);
    }
    
    #[test]
    fn test_chunk_size() {
        let chunk_size = get_optimal_chunk_size();
        assert!(chunk_size >= 8);
        assert!(chunk_size <= 32);
    }
    
    #[test]
    fn test_aligned_buffer() {
        let buffer = create_aligned_buffer(1024);
        assert_eq!(buffer.capacity(), 1024);
    }
    
    #[test]
    fn test_simd_processor() {
        let processor = SimdProcessor::new();
        let data = b"hello world test data";
        
        let matches = processor.find_byte_pattern(data, b'l');
        assert!(matches.len() >= 3); // At least 3 'l' characters
    }
    
    #[test]
    fn test_parallel_counting() {
        let processor = SimdProcessor::new();
        let data = b"aaabbbcccaaabbbccc";
        
        let count = processor.parallel_byte_count(data, b'a');
        assert_eq!(count, 6);
    }
    
    #[test]
    fn test_alignment() {
        let data = vec![0u8; 64];
        let ptr = data.as_ptr();
        
        // Test alignment validation
        assert!(validate_alignment(ptr, 1));
        
        // Test pointer alignment
        let aligned = align_pointer_up(ptr, 16);
        assert!(validate_alignment(aligned, 16));
    }
}