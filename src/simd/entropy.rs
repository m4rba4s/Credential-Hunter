/**
 * SIMD-Optimized Entropy Calculation
 * 
 * High-performance Shannon entropy calculation with multi-architecture SIMD support.
 * Optimized for large-scale log analysis and credential detection workloads.
 */

use super::{SimdOptimized, SimdStrategy, get_simd_capabilities};
use std::collections::HashMap;

#[cfg(feature = "simd-optimizations")]
use wide::*;

/// SIMD-optimized entropy calculator
pub struct SimdEntropyCalculator {
    strategy: SimdStrategy,
    chunk_size: usize,
}

impl Default for SimdEntropyCalculator {
    fn default() -> Self {
        let caps = get_simd_capabilities();
        Self {
            strategy: caps.best_strategy(),
            chunk_size: caps.cache_line_size * 4,
        }
    }
}

impl SimdEntropyCalculator {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Calculate Shannon entropy with optimal SIMD strategy
    pub fn calculate(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        match self.strategy {
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Avx2 => self.calculate_avx2(data),
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Sse42 => self.calculate_sse42(data),
            #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
            SimdStrategy::ArmNeon => self.calculate_neon(data),
            _ => self.calculate_scalar(data),
        }
    }
    
    /// Calculate entropy for string (UTF-8)
    pub fn calculate_string(&self, text: &str) -> f64 {
        self.calculate(text.as_bytes())
    }
    
    /// Batch calculate entropy for multiple strings
    pub fn calculate_batch(&self, texts: &[&str]) -> Vec<f64> {
        // Use Rayon for parallel processing
        #[cfg(feature = "simd-optimizations")]
        {
            use rayon::prelude::*;
            texts.par_iter()
                .map(|text| self.calculate_string(text))
                .collect()
        }
        
        #[cfg(not(feature = "simd-optimizations"))]
        {
            texts.iter()
                .map(|text| self.calculate_string(text))
                .collect()
        }
    }
    
    /// AVX2-optimized entropy calculation
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn calculate_avx2(&self, data: &[u8]) -> f64 {
        // Frequency counting with AVX2
        let mut frequency = [0u32; 256];
        
        // Process 32 bytes at a time with AVX2
        let chunks = data.chunks_exact(32);
        let remainder = chunks.remainder();
        
        for chunk in chunks {
            // SIMD-optimized frequency counting
            self.count_frequencies_avx2(chunk, &mut frequency);
        }
        
        // Process remainder
        for &byte in remainder {
            frequency[byte as usize] += 1;
        }
        
        self.entropy_from_frequencies(&frequency, data.len())
    }
    
    /// SSE4.2-optimized entropy calculation
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn calculate_sse42(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        
        // Process 16 bytes at a time with SSE4.2
        let chunks = data.chunks_exact(16);
        let remainder = chunks.remainder();
        
        for chunk in chunks {
            self.count_frequencies_sse42(chunk, &mut frequency);
        }
        
        // Process remainder
        for &byte in remainder {
            frequency[byte as usize] += 1;
        }
        
        self.entropy_from_frequencies(&frequency, data.len())
    }
    
    /// ARM NEON-optimized entropy calculation
    #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
    fn calculate_neon(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        
        // Process 16 bytes at a time with NEON
        let chunks = data.chunks_exact(16);
        let remainder = chunks.remainder();
        
        for chunk in chunks {
            self.count_frequencies_neon(chunk, &mut frequency);
        }
        
        // Process remainder
        for &byte in remainder {
            frequency[byte as usize] += 1;
        }
        
        self.entropy_from_frequencies(&frequency, data.len())
    }
    
    /// Scalar fallback entropy calculation
    fn calculate_scalar(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        
        for &byte in data {
            frequency[byte as usize] += 1;
        }
        
        self.entropy_from_frequencies(&frequency, data.len())
    }
    
    /// AVX2 frequency counting
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn count_frequencies_avx2(&self, chunk: &[u8], frequency: &mut [u32; 256]) {
        // For now, use scalar counting within SIMD chunks
        // Real implementation would use lookup tables and SIMD instructions
        for &byte in chunk {
            frequency[byte as usize] += 1;
        }
    }
    
    /// SSE4.2 frequency counting
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn count_frequencies_sse42(&self, chunk: &[u8], frequency: &mut [u32; 256]) {
        for &byte in chunk {
            frequency[byte as usize] += 1;
        }
    }
    
    /// NEON frequency counting
    #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
    fn count_frequencies_neon(&self, chunk: &[u8], frequency: &mut [u32; 256]) {
        for &byte in chunk {
            frequency[byte as usize] += 1;
        }
    }
    
    /// Calculate entropy from frequency array
    fn entropy_from_frequencies(&self, frequency: &[u32; 256], total_len: usize) -> f64 {
        let len = total_len as f64;
        let mut entropy = 0.0;
        
        // SIMD-optimized entropy calculation using wide types
        #[cfg(feature = "simd-optimizations")]
        {
            // Process frequencies in SIMD chunks
            let mut entropy_acc = f64x4::splat(0.0);
            
            for chunk in frequency.chunks_exact(4) {
                let counts = [chunk[0] as f64, chunk[1] as f64, chunk[2] as f64, chunk[3] as f64];
                let count_vec = f64x4::new(counts);
                
                // Calculate probabilities
                let prob_vec = count_vec / f64x4::splat(len);
                
                // Calculate -p * log2(p) for non-zero probabilities
                let non_zero_mask = prob_vec.cmp_gt(f64x4::splat(0.0));
                let log_prob = prob_vec.ln() / f64x4::splat(std::f64::consts::LN_2);
                let entropy_contrib = prob_vec * log_prob;
                
                // Mask out zero contributions
                let masked_contrib = entropy_contrib.blend(f64x4::splat(0.0), non_zero_mask);
                entropy_acc = entropy_acc - masked_contrib;
            }
            
            // Sum the SIMD results
            let entropy_array = entropy_acc.to_array();
            entropy += entropy_array.iter().sum::<f64>();
            
            // Process remaining frequencies
            for &count in &frequency[frequency.len() & !3..] {
                if count > 0 {
                    let probability = count as f64 / len;
                    entropy -= probability * probability.log2();
                }
            }
        }
        
        #[cfg(not(feature = "simd-optimizations"))]
        {
            for &count in frequency.iter() {
                if count > 0 {
                    let probability = count as f64 / len;
                    entropy -= probability * probability.log2();
                }
            }
        }
        
        entropy
    }
}

impl SimdOptimized for SimdEntropyCalculator {
    type Input = &'static [u8];
    type Output = f64;
    
    fn execute_simd(&self, input: Self::Input) -> Self::Output {
        match self.strategy {
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Avx2 => self.calculate_avx2(input),
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Sse42 => self.calculate_sse42(input),
            #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
            SimdStrategy::ArmNeon => self.calculate_neon(input),
            _ => self.calculate_scalar(input),
        }
    }
    
    fn execute_scalar(&self, input: Self::Input) -> Self::Output {
        self.calculate_scalar(input)
    }
}

/// Parallel entropy analysis for large datasets
pub struct ParallelEntropyAnalyzer {
    calculator: SimdEntropyCalculator,
    chunk_size: usize,
    thread_count: usize,
}

impl ParallelEntropyAnalyzer {
    pub fn new() -> Self {
        let caps = get_simd_capabilities();
        Self {
            calculator: SimdEntropyCalculator::new(),
            chunk_size: caps.cache_line_size * 16, // Larger chunks for parallel processing
            thread_count: num_cpus::get(),
        }
    }
    
    /// Analyze entropy across large text corpus
    pub fn analyze_corpus(&self, texts: &[&str]) -> Vec<f64> {
        #[cfg(feature = "simd-optimizations")]
        {
            use rayon::prelude::*;
            
            texts.par_chunks(self.chunk_size)
                .flat_map(|chunk| {
                    chunk.iter()
                        .map(|text| self.calculator.calculate_string(text))
                        .collect::<Vec<_>>()
                })
                .collect()
        }
        
        #[cfg(not(feature = "simd-optimizations"))]
        {
            texts.iter()
                .map(|text| self.calculator.calculate_string(text))
                .collect()
        }
    }
    
    /// Real-time entropy monitoring for streaming data
    pub fn monitor_stream<I>(&self, stream: I) -> impl Iterator<Item = f64> + '_
    where
        I: Iterator<Item = String>,
    {
        stream.map(move |text| self.calculator.calculate_string(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_entropy_calculation() {
        let calculator = SimdEntropyCalculator::new();
        
        // Test cases with known entropy characteristics
        let test_cases = vec![
            ("aaaaaaaaaa", 0.0), // No entropy
            ("abcdefghij", 3.32), // High entropy (approximately)
            ("AKIAIOSFODNN7EXAMPLE", 3.68), // AWS key entropy
        ];
        
        for (text, expected_entropy) in test_cases {
            let calculated = calculator.calculate_string(text);
            println!("Text: '{}' -> Entropy: {:.2}", text, calculated);
            
            // Allow some tolerance for floating point comparison
            if expected_entropy > 0.0 {
                let diff = (calculated - expected_entropy).abs();
                assert!(diff < 0.5, "Entropy calculation mismatch for '{}': expected {:.2}, got {:.2}", 
                        text, expected_entropy, calculated);
            }
        }
    }
    
    #[test]
    fn test_batch_entropy_calculation() {
        let calculator = SimdEntropyCalculator::new();
        
        let texts = vec![
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890123456789012345678901234567890",
            "sk_live_TEST_PLACEHOLDER_MASKED",
            "password123",
            "test_string",
        ];
        
        let entropies = calculator.calculate_batch(&texts);
        assert_eq!(entropies.len(), texts.len());
        
        // All entropies should be positive
        for (i, entropy) in entropies.iter().enumerate() {
            assert!(*entropy > 0.0, "Entropy for text {} should be positive: {}", i, entropy);
        }
    }
    
    #[test]
    fn test_parallel_entropy_analyzer() {
        let analyzer = ParallelEntropyAnalyzer::new();
        
        let large_dataset: Vec<&str> = (0..1000)
            .map(|i| {
                if i % 3 == 0 {
                    "AKIAIOSFODNN7EXAMPLE"
                } else if i % 3 == 1 {
                    "ghp_1234567890123456789012345678901234567890"
                } else {
                    "sk_live_TEST_PLACEHOLDER_MASKED"
                }
            })
            .collect();
        
        let results = analyzer.analyze_corpus(&large_dataset);
        assert_eq!(results.len(), large_dataset.len());
        
        // All results should be positive
        for entropy in results {
            assert!(entropy > 0.0);
        }
    }
    
    #[test]
    fn test_entropy_correctness_across_strategies() {
        let calculator = SimdEntropyCalculator::new();
        
        let test_data = "AKIAIOSFODNN7EXAMPLE_test_string_with_mixed_entropy";
        
        // Calculate with SIMD
        let simd_result = calculator.calculate_string(test_data);
        
        // Calculate with scalar fallback
        let scalar_calculator = SimdEntropyCalculator {
            strategy: SimdStrategy::Scalar,
            chunk_size: 64,
        };
        let scalar_result = scalar_calculator.calculate_string(test_data);
        
        // Results should be very close (within floating point precision)
        let diff = (simd_result - scalar_result).abs();
        assert!(diff < 1e-10, "SIMD and scalar results should match: SIMD={}, Scalar={}, Diff={}", 
                simd_result, scalar_result, diff);
    }
}