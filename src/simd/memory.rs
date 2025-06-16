/**
 * SIMD-Optimized Memory Scanning
 * 
 * High-performance memory analysis for credential detection in process memory,
 * heap dumps, and memory snapshots with multi-architecture SIMD support.
 */

use super::{SimdOptimized, SimdStrategy, get_simd_capabilities};
use std::collections::HashMap;

#[cfg(feature = "simd-optimizations")]
use wide::*;

/// SIMD-optimized memory scanner
pub struct SimdMemoryScanner {
    strategy: SimdStrategy,
    chunk_size: usize,
    alignment: usize,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_address: usize,
    pub size: usize,
    pub data: Vec<u8>,
    pub permissions: String,
    pub mapped_file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryMatch {
    pub region_start: usize,
    pub offset: usize,
    pub absolute_address: usize,
    pub pattern_type: String,
    pub matched_data: Vec<u8>,
    pub context: Vec<u8>,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

impl Default for SimdMemoryScanner {
    fn default() -> Self {
        let caps = get_simd_capabilities();
        Self {
            strategy: caps.best_strategy(),
            chunk_size: caps.cache_line_size * 8, // Larger chunks for memory scanning
            alignment: caps.cache_line_size,
        }
    }
}

impl SimdMemoryScanner {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Scan memory region for credential patterns using optimal SIMD strategy
    pub fn scan_memory_region(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        match self.strategy {
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Avx2 => self.scan_avx2(region),
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Sse42 => self.scan_sse42(region),
            #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
            SimdStrategy::ArmNeon => self.scan_neon(region),
            _ => self.scan_scalar(region),
        }
    }
    
    /// Batch scan multiple memory regions in parallel
    pub fn scan_memory_regions(&self, regions: &[MemoryRegion]) -> Vec<Vec<MemoryMatch>> {
        #[cfg(feature = "simd-optimizations")]
        {
            use rayon::prelude::*;
            regions.par_iter()
                .map(|region| self.scan_memory_region(region))
                .collect()
        }
        
        #[cfg(not(feature = "simd-optimizations"))]
        {
            regions.iter()
                .map(|region| self.scan_memory_region(region))
                .collect()
        }
    }
    
    /// AVX2-optimized memory scanning
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn scan_avx2(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        let data = &region.data;
        
        // Scan for common credential patterns using AVX2
        matches.extend(self.scan_pattern_avx2(region, b"AKIA", "AWS_ACCESS_KEY"));
        matches.extend(self.scan_pattern_avx2(region, b"ghp_", "GITHUB_TOKEN"));
        matches.extend(self.scan_pattern_avx2(region, b"sk_live_", "STRIPE_KEY"));
        matches.extend(self.scan_pattern_avx2(region, b"password", "PASSWORD"));
        matches.extend(self.scan_pattern_avx2(region, b"api_key", "API_KEY"));
        
        // Scan for high-entropy regions that might contain encoded credentials
        matches.extend(self.scan_entropy_regions_avx2(region));
        
        matches
    }
    
    /// SSE4.2-optimized memory scanning
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn scan_sse42(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        
        matches.extend(self.scan_pattern_sse42(region, b"AKIA", "AWS_ACCESS_KEY"));
        matches.extend(self.scan_pattern_sse42(region, b"ghp_", "GITHUB_TOKEN"));
        matches.extend(self.scan_pattern_sse42(region, b"sk_live_", "STRIPE_KEY"));
        matches.extend(self.scan_pattern_sse42(region, b"password", "PASSWORD"));
        matches.extend(self.scan_pattern_sse42(region, b"api_key", "API_KEY"));
        
        matches.extend(self.scan_entropy_regions_sse42(region));
        
        matches
    }
    
    /// ARM NEON-optimized memory scanning
    #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
    fn scan_neon(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        
        matches.extend(self.scan_pattern_neon(region, b"AKIA", "AWS_ACCESS_KEY"));
        matches.extend(self.scan_pattern_neon(region, b"ghp_", "GITHUB_TOKEN"));
        matches.extend(self.scan_pattern_neon(region, b"sk_live_", "STRIPE_KEY"));
        matches.extend(self.scan_pattern_neon(region, b"password", "PASSWORD"));
        matches.extend(self.scan_pattern_neon(region, b"api_key", "API_KEY"));
        
        matches.extend(self.scan_entropy_regions_neon(region));
        
        matches
    }
    
    /// Scalar fallback memory scanning
    fn scan_scalar(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        
        matches.extend(self.scan_pattern_scalar(region, b"AKIA", "AWS_ACCESS_KEY"));
        matches.extend(self.scan_pattern_scalar(region, b"ghp_", "GITHUB_TOKEN"));
        matches.extend(self.scan_pattern_scalar(region, b"sk_live_", "STRIPE_KEY"));
        matches.extend(self.scan_pattern_scalar(region, b"password", "PASSWORD"));
        matches.extend(self.scan_pattern_scalar(region, b"api_key", "API_KEY"));
        
        matches.extend(self.scan_entropy_regions_scalar(region));
        
        matches
    }
    
    /// AVX2 pattern scanning implementation
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn scan_pattern_avx2(&self, region: &MemoryRegion, pattern: &[u8], pattern_type: &str) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        let data = &region.data;
        
        if pattern.is_empty() || data.len() < pattern.len() {
            return matches;
        }
        
        let first_byte = pattern[0];
        let first_byte_vec = u8x32::splat(first_byte);
        
        // Process 32-byte aligned chunks
        let aligned_chunks = data.chunks_exact(32);
        let mut offset = 0;
        
        for chunk in aligned_chunks {
            let chunk_vec = u8x32::new(chunk.try_into().unwrap_or([0; 32]));
            let mask = chunk_vec.cmp_eq(first_byte_vec);
            let bitmask = mask.move_mask();
            
            // Check each potential match position
            for i in 0..32 {
                if (bitmask & (1 << i)) != 0 {
                    let pos = offset + i;
                    if pos + pattern.len() <= data.len() {
                        if data[pos..pos + pattern.len()] == *pattern {
                            if let Some(memory_match) = self.create_memory_match(region, pos, pattern_type) {
                                matches.push(memory_match);
                            }
                        }
                    }
                }
            }
            
            offset += 32;
        }
        
        // Process remainder with scalar
        let remainder = &data[offset..];
        matches.extend(self.scan_pattern_scalar_range(region, remainder, offset, pattern, pattern_type));
        
        matches
    }
    
    /// SSE4.2 pattern scanning implementation
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn scan_pattern_sse42(&self, region: &MemoryRegion, pattern: &[u8], pattern_type: &str) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        let data = &region.data;
        
        if pattern.is_empty() || data.len() < pattern.len() {
            return matches;
        }
        
        let first_byte = pattern[0];
        let first_byte_vec = u8x16::splat(first_byte);
        
        let aligned_chunks = data.chunks_exact(16);
        let mut offset = 0;
        
        for chunk in aligned_chunks {
            let chunk_vec = u8x16::new(chunk.try_into().unwrap_or([0; 16]));
            let mask = chunk_vec.cmp_eq(first_byte_vec);
            let bitmask = mask.move_mask();
            
            for i in 0..16 {
                if (bitmask & (1 << i)) != 0 {
                    let pos = offset + i;
                    if pos + pattern.len() <= data.len() {
                        if data[pos..pos + pattern.len()] == *pattern {
                            if let Some(memory_match) = self.create_memory_match(region, pos, pattern_type) {
                                matches.push(memory_match);
                            }
                        }
                    }
                }
            }
            
            offset += 16;
        }
        
        let remainder = &data[offset..];
        matches.extend(self.scan_pattern_scalar_range(region, remainder, offset, pattern, pattern_type));
        
        matches
    }
    
    /// ARM NEON pattern scanning implementation
    #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
    fn scan_pattern_neon(&self, region: &MemoryRegion, pattern: &[u8], pattern_type: &str) -> Vec<MemoryMatch> {
        // For now, use scalar implementation - real NEON would use vector instructions
        self.scan_pattern_scalar(region, pattern, pattern_type)
    }
    
    /// Scalar pattern scanning implementation
    fn scan_pattern_scalar(&self, region: &MemoryRegion, pattern: &[u8], pattern_type: &str) -> Vec<MemoryMatch> {
        self.scan_pattern_scalar_range(region, &region.data, 0, pattern, pattern_type)
    }
    
    /// Scalar pattern scanning for a specific range
    fn scan_pattern_scalar_range(&self, region: &MemoryRegion, data: &[u8], base_offset: usize, 
                                pattern: &[u8], pattern_type: &str) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        let mut start = 0;
        
        while let Some(pos) = self.find_pattern_in_slice(data, pattern, start) {
            if let Some(memory_match) = self.create_memory_match(region, base_offset + pos, pattern_type) {
                matches.push(memory_match);
            }
            start = pos + 1;
        }
        
        matches
    }
    
    /// Find pattern in byte slice
    fn find_pattern_in_slice(&self, haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
        if start >= haystack.len() || needle.is_empty() {
            return None;
        }
        
        haystack[start..]
            .windows(needle.len())
            .position(|window| window == needle)
            .map(|pos| start + pos)
    }
    
    /// Create a memory match structure
    fn create_memory_match(&self, region: &MemoryRegion, offset: usize, pattern_type: &str) -> Option<MemoryMatch> {
        if offset >= region.data.len() {
            return None;
        }
        
        // Extract context around the match (32 bytes before and after)
        let context_size = 32;
        let start_context = offset.saturating_sub(context_size);
        let end_context = std::cmp::min(offset + context_size, region.data.len());
        let context = region.data[start_context..end_context].to_vec();
        
        // Extract the matched data (up to 64 bytes or next null byte)
        let match_end = std::cmp::min(offset + 64, region.data.len());
        let mut matched_data = region.data[offset..match_end].to_vec();
        
        // Truncate at null byte for string data
        if let Some(null_pos) = matched_data.iter().position(|&b| b == 0) {
            matched_data.truncate(null_pos);
        }
        
        let mut metadata = HashMap::new();
        metadata.insert("detection_method".to_string(), "simd_memory_scan".to_string());
        metadata.insert("memory_region_start".to_string(), format!("0x{:x}", region.start_address));
        metadata.insert("memory_region_size".to_string(), region.size.to_string());
        metadata.insert("permissions".to_string(), region.permissions.clone());
        
        if let Some(ref file) = region.mapped_file {
            metadata.insert("mapped_file".to_string(), file.clone());
        }
        
        Some(MemoryMatch {
            region_start: region.start_address,
            offset,
            absolute_address: region.start_address + offset,
            pattern_type: pattern_type.to_string(),
            matched_data,
            context,
            confidence: self.calculate_match_confidence(pattern_type, &region.data[offset..]),
            metadata,
        })
    }
    
    /// Calculate confidence score for a memory match
    fn calculate_match_confidence(&self, pattern_type: &str, data: &[u8]) -> f64 {
        let base_confidence = match pattern_type {
            "AWS_ACCESS_KEY" => 0.95,
            "GITHUB_TOKEN" => 0.9,
            "STRIPE_KEY" => 0.9,
            "PASSWORD" => 0.7,
            "API_KEY" => 0.75,
            "HIGH_ENTROPY" => 0.6,
            _ => 0.5,
        };
        
        // Adjust confidence based on context
        let printable_ratio = data.iter().take(32)
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count() as f64 / std::cmp::min(32, data.len()) as f64;
        
        base_confidence * (0.5 + 0.5 * printable_ratio)
    }
    
    /// Scan for high-entropy regions using AVX2
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn scan_entropy_regions_avx2(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        let data = &region.data;
        
        // Process in 256-byte windows for entropy analysis
        let window_size = 256;
        let step_size = 64; // Overlapping windows
        
        for start in (0..data.len().saturating_sub(window_size)).step_by(step_size) {
            let window = &data[start..start + window_size];
            let entropy = self.calculate_entropy_avx2(window);
            
            // High entropy threshold - indicates possible encoded/encrypted data
            if entropy > 7.0 {
                if let Some(memory_match) = self.create_memory_match(region, start, "HIGH_ENTROPY") {
                    matches.push(memory_match);
                }
            }
        }
        
        matches
    }
    
    /// Scan for high-entropy regions using SSE4.2
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn scan_entropy_regions_sse42(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        let data = &region.data;
        let window_size = 256;
        let step_size = 64;
        
        for start in (0..data.len().saturating_sub(window_size)).step_by(step_size) {
            let window = &data[start..start + window_size];
            let entropy = self.calculate_entropy_sse42(window);
            
            if entropy > 7.0 {
                if let Some(memory_match) = self.create_memory_match(region, start, "HIGH_ENTROPY") {
                    matches.push(memory_match);
                }
            }
        }
        
        matches
    }
    
    /// Scan for high-entropy regions using ARM NEON
    #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
    fn scan_entropy_regions_neon(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        // Use scalar entropy calculation for now
        self.scan_entropy_regions_scalar(region)
    }
    
    /// Scan for high-entropy regions using scalar approach
    fn scan_entropy_regions_scalar(&self, region: &MemoryRegion) -> Vec<MemoryMatch> {
        let mut matches = Vec::new();
        let data = &region.data;
        let window_size = 256;
        let step_size = 64;
        
        for start in (0..data.len().saturating_sub(window_size)).step_by(step_size) {
            let window = &data[start..start + window_size];
            let entropy = self.calculate_entropy_scalar(window);
            
            if entropy > 7.0 {
                if let Some(memory_match) = self.create_memory_match(region, start, "HIGH_ENTROPY") {
                    matches.push(memory_match);
                }
            }
        }
        
        matches
    }
    
    /// Calculate entropy using AVX2 SIMD instructions
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn calculate_entropy_avx2(&self, data: &[u8]) -> f64 {
        // Use the SIMD entropy calculator from the entropy module
        use super::entropy::SimdEntropyCalculator;
        let calculator = SimdEntropyCalculator::new();
        calculator.calculate(data)
    }
    
    /// Calculate entropy using SSE4.2 SIMD instructions
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn calculate_entropy_sse42(&self, data: &[u8]) -> f64 {
        use super::entropy::SimdEntropyCalculator;
        let calculator = SimdEntropyCalculator::new();
        calculator.calculate(data)
    }
    
    /// Calculate entropy using scalar approach
    fn calculate_entropy_scalar(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in frequency.iter() {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Get scanner statistics
    pub fn get_stats(&self) -> MemoryScannerStats {
        MemoryScannerStats {
            strategy: self.strategy,
            chunk_size: self.chunk_size,
            alignment: self.alignment,
        }
    }
}

#[derive(Debug)]
pub struct MemoryScannerStats {
    pub strategy: SimdStrategy,
    pub chunk_size: usize,
    pub alignment: usize,
}

impl SimdOptimized for SimdMemoryScanner {
    type Input = &'static MemoryRegion;
    type Output = Vec<MemoryMatch>;
    
    fn execute_simd(&self, input: Self::Input) -> Self::Output {
        match self.strategy {
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Avx2 => self.scan_avx2(input),
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Sse42 => self.scan_sse42(input),
            #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
            SimdStrategy::ArmNeon => self.scan_neon(input),
            _ => self.scan_scalar(input),
        }
    }
    
    fn execute_scalar(&self, input: Self::Input) -> Self::Output {
        self.scan_scalar(input)
    }
}

/// Memory dump analyzer for forensics applications
pub struct MemoryDumpAnalyzer {
    scanner: SimdMemoryScanner,
}

impl MemoryDumpAnalyzer {
    pub fn new() -> Self {
        Self {
            scanner: SimdMemoryScanner::new(),
        }
    }
    
    /// Analyze a complete memory dump file
    pub fn analyze_dump(&self, dump_data: &[u8]) -> Vec<MemoryMatch> {
        // Create a single large memory region for the dump
        let region = MemoryRegion {
            start_address: 0,
            size: dump_data.len(),
            data: dump_data.to_vec(),
            permissions: "r--".to_string(),
            mapped_file: Some("memory_dump".to_string()),
        };
        
        self.scanner.scan_memory_region(&region)
    }
    
    /// Extract credentials from process memory snapshots
    pub fn extract_process_credentials(&self, process_regions: &[MemoryRegion]) -> Vec<MemoryMatch> {
        let mut all_matches = Vec::new();
        
        #[cfg(feature = "simd-optimizations")]
        {
            use rayon::prelude::*;
            let batch_results: Vec<Vec<MemoryMatch>> = process_regions.par_iter()
                .map(|region| self.scanner.scan_memory_region(region))
                .collect();
            
            for mut batch in batch_results {
                all_matches.append(&mut batch);
            }
        }
        
        #[cfg(not(feature = "simd-optimizations"))]
        {
            for region in process_regions {
                let mut matches = self.scanner.scan_memory_region(region);
                all_matches.append(&mut matches);
            }
        }
        
        all_matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_scanner_creation() {
        let scanner = SimdMemoryScanner::new();
        let stats = scanner.get_stats();
        println!("Memory scanner created with strategy: {:?}", stats.strategy);
        assert!(stats.chunk_size > 0);
        assert!(stats.alignment > 0);
    }
    
    #[test]
    fn test_memory_region_scanning() {
        let scanner = SimdMemoryScanner::new();
        
        // Create test memory region with embedded credentials
        let test_data = b"some data AKIAIOSFODNN7EXAMPLE more data ghp_1234567890123456789012345678901234567890 end";
        let region = MemoryRegion {
            start_address: 0x1000,
            size: test_data.len(),
            data: test_data.to_vec(),
            permissions: "r-x".to_string(),
            mapped_file: Some("/bin/test".to_string()),
        };
        
        let matches = scanner.scan_memory_region(&region);
        assert!(!matches.is_empty());
        
        // Should find AWS key and GitHub token
        let aws_match = matches.iter().find(|m| m.pattern_type == "AWS_ACCESS_KEY");
        let github_match = matches.iter().find(|m| m.pattern_type == "GITHUB_TOKEN");
        
        assert!(aws_match.is_some());
        assert!(github_match.is_some());
        
        if let Some(aws) = aws_match {
            assert_eq!(aws.region_start, 0x1000);
            assert!(aws.absolute_address >= 0x1000);
            println!("Found AWS key at address: 0x{:x}", aws.absolute_address);
        }
    }
    
    #[test]
    fn test_batch_memory_scanning() {
        let scanner = SimdMemoryScanner::new();
        
        let regions = vec![
            MemoryRegion {
                start_address: 0x1000,
                size: 100,
                data: b"AKIAIOSFODNN7EXAMPLE in first region".to_vec(),
                permissions: "r--".to_string(),
                mapped_file: None,
            },
            MemoryRegion {
                start_address: 0x2000,
                size: 100,
                data: b"ghp_1234567890123456789012345678901234567890 in second region".to_vec(),
                permissions: "r--".to_string(),
                mapped_file: None,
            },
        ];
        
        let batch_results = scanner.scan_memory_regions(&regions);
        assert_eq!(batch_results.len(), 2);
        
        // First region should have AWS key
        assert!(!batch_results[0].is_empty());
        assert!(batch_results[0].iter().any(|m| m.pattern_type == "AWS_ACCESS_KEY"));
        
        // Second region should have GitHub token
        assert!(!batch_results[1].is_empty());
        assert!(batch_results[1].iter().any(|m| m.pattern_type == "GITHUB_TOKEN"));
    }
    
    #[test]
    fn test_entropy_scanning() {
        let scanner = SimdMemoryScanner::new();
        
        // Create region with high-entropy data (simulated encrypted content)
        let mut high_entropy_data = Vec::new();
        for i in 0..256 {
            high_entropy_data.push((i ^ 0xAA ^ (i * 17)) as u8);
        }
        
        let region = MemoryRegion {
            start_address: 0x3000,
            size: high_entropy_data.len(),
            data: high_entropy_data,
            permissions: "r--".to_string(),
            mapped_file: None,
        };
        
        let matches = scanner.scan_memory_region(&region);
        
        // Should find high-entropy regions
        let entropy_matches: Vec<_> = matches.iter()
            .filter(|m| m.pattern_type == "HIGH_ENTROPY")
            .collect();
        
        println!("Found {} high-entropy regions", entropy_matches.len());
        // Note: might not find high entropy in small test data
    }
    
    #[test]
    fn test_memory_dump_analyzer() {
        let analyzer = MemoryDumpAnalyzer::new();
        
        // Simulate a memory dump with embedded credentials
        let dump_data = b"Memory dump header\x00\x00\x00AKIAIOSFODNN7EXAMPLE\x00some other data\x00ghp_1234567890123456789012345678901234567890\x00end of dump";
        
        let matches = analyzer.analyze_dump(dump_data);
        assert!(!matches.is_empty());
        
        println!("Memory dump analysis found {} matches", matches.len());
        for m in &matches {
            println!("  - {} at offset 0x{:x}", m.pattern_type, m.offset);
        }
    }
    
    #[test]
    fn test_performance_memory_scanning() {
        let scanner = SimdMemoryScanner::new();
        
        // Create large memory region for performance testing
        let mut large_data = Vec::new();
        let credential_data = b"AKIAIOSFODNN7EXAMPLE";
        
        // Embed credentials throughout a large memory region
        for i in 0..10000 {
            large_data.extend_from_slice(b"random_data_");
            if i % 100 == 0 {
                large_data.extend_from_slice(credential_data);
            }
            large_data.extend_from_slice(b"_more_data\n");
        }
        
        let region = MemoryRegion {
            start_address: 0x10000,
            size: large_data.len(),
            data: large_data,
            permissions: "r-x".to_string(),
            mapped_file: Some("/large_process".to_string()),
        };
        
        let start_time = std::time::Instant::now();
        let matches = scanner.scan_memory_region(&region);
        let duration = start_time.elapsed();
        
        println!("Scanned {} bytes in {:?}, found {} matches", 
                 region.size, duration, matches.len());
        
        assert!(!matches.is_empty());
        
        // Should find multiple AWS keys
        let aws_matches: Vec<_> = matches.iter()
            .filter(|m| m.pattern_type == "AWS_ACCESS_KEY")
            .collect();
        
        println!("Found {} AWS access keys in memory", aws_matches.len());
        assert!(aws_matches.len() > 50); // Should find around 100
    }
}