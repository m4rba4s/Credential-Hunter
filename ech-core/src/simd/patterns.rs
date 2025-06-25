/**
 * SIMD-Optimized Pattern Matching
 * 
 * High-performance credential pattern detection with multi-architecture SIMD support.
 * Optimized for enterprise-scale log analysis and real-time credential hunting.
 */

use super::{SimdOptimized, SimdStrategy, get_simd_capabilities};
use std::collections::HashMap;

#[cfg(feature = "simd-optimizations")]
use wide::*;

/// SIMD-optimized pattern matcher for credential detection
pub struct SimdPatternMatcher {
    strategy: SimdStrategy,
    patterns: Vec<CredentialPattern>,
    chunk_size: usize,
}

#[derive(Debug, Clone)]
pub struct CredentialPattern {
    pub name: String,
    pub pattern: Vec<u8>,
    pub min_length: usize,
    pub max_length: usize,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub start_offset: usize,
    pub length: usize,
    pub matched_text: String,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

impl Default for SimdPatternMatcher {
    fn default() -> Self {
        let caps = get_simd_capabilities();
        let mut matcher = Self {
            strategy: caps.best_strategy(),
            patterns: Vec::new(),
            chunk_size: caps.cache_line_size * 2,
        };
        
        // Load default credential patterns
        matcher.load_default_patterns();
        matcher
    }
}

impl SimdPatternMatcher {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Load common credential patterns for enterprise detection
    fn load_default_patterns(&mut self) {
        let default_patterns = vec![
            // AWS patterns
            CredentialPattern {
                name: "AWS_ACCESS_KEY".to_string(),
                pattern: b"AKIA".to_vec(),
                min_length: 20,
                max_length: 20,
                confidence: 0.95,
            },
            CredentialPattern {
                name: "AWS_SECRET_KEY".to_string(),
                pattern: b"aws_secret_access_key".to_vec(),
                min_length: 40,
                max_length: 40,
                confidence: 0.9,
            },
            // GitHub patterns
            CredentialPattern {
                name: "GITHUB_TOKEN".to_string(),
                pattern: b"ghp_".to_vec(),
                min_length: 36,
                max_length: 40,
                confidence: 0.95,
            },
            CredentialPattern {
                name: "GITHUB_APP_TOKEN".to_string(),
                pattern: b"ghs_".to_vec(),
                min_length: 36,
                max_length: 40,
                confidence: 0.95,
            },
            // Stripe patterns
            CredentialPattern {
                name: "STRIPE_SECRET_KEY".to_string(),
                pattern: b"sk_live_".to_vec(),
                min_length: 24,
                max_length: 64,
                confidence: 0.9,
            },
            CredentialPattern {
                name: "STRIPE_PUBLISHABLE_KEY".to_string(),
                pattern: b"pk_live_".to_vec(),
                min_length: 24,
                max_length: 64,
                confidence: 0.85,
            },
            // Generic patterns
            CredentialPattern {
                name: "API_KEY".to_string(),
                pattern: b"api_key".to_vec(),
                min_length: 16,
                max_length: 128,
                confidence: 0.7,
            },
            CredentialPattern {
                name: "PASSWORD".to_string(),
                pattern: b"password".to_vec(),
                min_length: 8,
                max_length: 256,
                confidence: 0.6,
            },
        ];
        
        self.patterns = default_patterns;
    }
    
    /// Add custom pattern for detection
    pub fn add_pattern(&mut self, pattern: CredentialPattern) {
        self.patterns.push(pattern);
    }
    
    /// Find all credential patterns in text using optimal SIMD strategy
    pub fn find_patterns(&self, text: &str) -> Vec<PatternMatch> {
        let data = text.as_bytes();
        
        match self.strategy {
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Avx2 => self.find_patterns_avx2(data, text),
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Sse42 => self.find_patterns_sse42(data, text),
            #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
            SimdStrategy::ArmNeon => self.find_patterns_neon(data, text),
            _ => self.find_patterns_scalar(data, text),
        }
    }
    
    /// Batch pattern matching for multiple texts
    pub fn find_patterns_batch(&self, texts: &[&str]) -> Vec<Vec<PatternMatch>> {
        #[cfg(feature = "simd-optimizations")]
        {
            use rayon::prelude::*;
            texts.par_iter()
                .map(|text| self.find_patterns(text))
                .collect()
        }
        
        #[cfg(not(feature = "simd-optimizations"))]
        {
            texts.iter()
                .map(|text| self.find_patterns(text))
                .collect()
        }
    }
    
    /// AVX2-optimized pattern matching
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn find_patterns_avx2(&self, data: &[u8], text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        
        for pattern in &self.patterns {
            // Use SIMD for pattern prefix matching
            let pattern_matches = self.simd_find_pattern_avx2(data, &pattern.pattern);
            
            for match_pos in pattern_matches {
                if let Some(credential_match) = self.validate_match(text, match_pos, pattern) {
                    matches.push(credential_match);
                }
            }
        }
        
        matches
    }
    
    /// SSE4.2-optimized pattern matching
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn find_patterns_sse42(&self, data: &[u8], text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        
        for pattern in &self.patterns {
            let pattern_matches = self.simd_find_pattern_sse42(data, &pattern.pattern);
            
            for match_pos in pattern_matches {
                if let Some(credential_match) = self.validate_match(text, match_pos, pattern) {
                    matches.push(credential_match);
                }
            }
        }
        
        matches
    }
    
    /// ARM NEON-optimized pattern matching
    #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
    fn find_patterns_neon(&self, data: &[u8], text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        
        for pattern in &self.patterns {
            let pattern_matches = self.simd_find_pattern_neon(data, &pattern.pattern);
            
            for match_pos in pattern_matches {
                if let Some(credential_match) = self.validate_match(text, match_pos, pattern) {
                    matches.push(credential_match);
                }
            }
        }
        
        matches
    }
    
    /// Scalar fallback pattern matching
    fn find_patterns_scalar(&self, data: &[u8], text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        
        for pattern in &self.patterns {
            let mut start = 0;
            
            while let Some(pos) = self.find_bytes_scalar(data, &pattern.pattern, start) {
                if let Some(credential_match) = self.validate_match(text, pos, pattern) {
                    matches.push(credential_match);
                }
                start = pos + 1;
            }
        }
        
        matches
    }
    
    /// SIMD pattern finding with AVX2
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn simd_find_pattern_avx2(&self, haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        
        if needle.is_empty() || haystack.len() < needle.len() {
            return positions;
        }
        
        let first_byte = needle[0];
        let first_byte_vec = u8x32::splat(first_byte);
        
        // Process 32-byte chunks with AVX2
        let chunks = haystack.chunks_exact(32);
        let mut offset = 0;
        
        for chunk in chunks {
            // Load chunk into SIMD register
            let chunk_vec = u8x32::new(chunk.try_into().unwrap_or([0; 32]));
            
            // Compare with first byte
            let mask = chunk_vec.cmp_eq(first_byte_vec);
            let bitmask = mask.move_mask();
            
            // Check each potential match
            for i in 0..32 {
                if (bitmask & (1 << i)) != 0 {
                    let pos = offset + i;
                    if pos + needle.len() <= haystack.len() {
                        if haystack[pos..pos + needle.len()] == *needle {
                            positions.push(pos);
                        }
                    }
                }
            }
            
            offset += 32;
        }
        
        // Process remainder with scalar approach
        let remainder = &haystack[offset..];
        let mut remainder_pos = 0;
        while let Some(pos) = self.find_bytes_scalar(remainder, needle, remainder_pos) {
            positions.push(offset + pos);
            remainder_pos = pos + 1;
        }
        
        positions
    }
    
    /// SIMD pattern finding with SSE4.2
    #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
    fn simd_find_pattern_sse42(&self, haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        
        if needle.is_empty() || haystack.len() < needle.len() {
            return positions;
        }
        
        let first_byte = needle[0];
        let first_byte_vec = u8x16::splat(first_byte);
        
        // Process 16-byte chunks with SSE4.2
        let chunks = haystack.chunks_exact(16);
        let mut offset = 0;
        
        for chunk in chunks {
            let chunk_vec = u8x16::new(chunk.try_into().unwrap_or([0; 16]));
            let mask = chunk_vec.cmp_eq(first_byte_vec);
            let bitmask = mask.move_mask();
            
            for i in 0..16 {
                if (bitmask & (1 << i)) != 0 {
                    let pos = offset + i;
                    if pos + needle.len() <= haystack.len() {
                        if haystack[pos..pos + needle.len()] == *needle {
                            positions.push(pos);
                        }
                    }
                }
            }
            
            offset += 16;
        }
        
        // Process remainder
        let remainder = &haystack[offset..];
        let mut remainder_pos = 0;
        while let Some(pos) = self.find_bytes_scalar(remainder, needle, remainder_pos) {
            positions.push(offset + pos);
            remainder_pos = pos + 1;
        }
        
        positions
    }
    
    /// SIMD pattern finding with ARM NEON
    #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
    fn simd_find_pattern_neon(&self, haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        // For now, use scalar implementation
        // Real NEON implementation would use vld1q_u8, vcmpq_eq_u8, etc.
        let mut positions = Vec::new();
        let mut start = 0;
        
        while let Some(pos) = self.find_bytes_scalar(haystack, needle, start) {
            positions.push(pos);
            start = pos + 1;
        }
        
        positions
    }
    
    /// Scalar byte pattern finding
    fn find_bytes_scalar(&self, haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
        if start >= haystack.len() || needle.is_empty() {
            return None;
        }
        
        haystack[start..]
            .windows(needle.len())
            .position(|window| window == needle)
            .map(|pos| start + pos)
    }
    
    /// Validate and extract full credential match
    fn validate_match(&self, text: &str, pos: usize, pattern: &CredentialPattern) -> Option<PatternMatch> {
        let start_pos = pos;
        
        // Find word boundaries or credential boundaries
        let end_pos = self.find_credential_end(text, start_pos, pattern);
        
        if end_pos - start_pos < pattern.min_length || end_pos - start_pos > pattern.max_length {
            return None;
        }
        
        let matched_text = text[start_pos..end_pos].to_string();
        
        // Additional validation based on pattern type
        if !self.validate_credential_format(&matched_text, pattern) {
            return None;
        }
        
        let mut metadata = HashMap::new();
        metadata.insert("detection_method".to_string(), "simd_pattern_match".to_string());
        metadata.insert("pattern_type".to_string(), pattern.name.clone());
        
        Some(PatternMatch {
            pattern_name: pattern.name.clone(),
            start_offset: start_pos,
            length: end_pos - start_pos,
            matched_text,
            confidence: pattern.confidence,
            metadata,
        })
    }
    
    /// Find the end of a credential based on common delimiters
    fn find_credential_end(&self, text: &str, start: usize, pattern: &CredentialPattern) -> usize {
        let bytes = text.as_bytes();
        let mut end = start + pattern.pattern.len();
        
        // Common credential delimiters
        let delimiters = [b' ', b'\t', b'\n', b'\r', b'"', b'\'', b'&', b';', b','];
        
        while end < bytes.len() && end - start < pattern.max_length {
            if delimiters.contains(&bytes[end]) {
                break;
            }
            end += 1;
        }
        
        end
    }
    
    /// Validate credential format based on pattern type
    fn validate_credential_format(&self, credential: &str, pattern: &CredentialPattern) -> bool {
        match pattern.name.as_str() {
            "AWS_ACCESS_KEY" => {
                credential.len() == 20 && credential.starts_with("AKIA") 
                    && credential.chars().all(|c| c.is_ascii_alphanumeric())
            },
            "GITHUB_TOKEN" => {
                credential.starts_with("ghp_") && credential.len() >= 36
                    && credential.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            },
            "STRIPE_SECRET_KEY" => {
                credential.starts_with("sk_live_") && credential.len() >= 24
                    && credential.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            },
            _ => true, // Generic validation
        }
    }
    
    /// Get statistics about pattern matching performance
    pub fn get_stats(&self) -> PatternMatcherStats {
        PatternMatcherStats {
            strategy: self.strategy,
            pattern_count: self.patterns.len(),
            chunk_size: self.chunk_size,
        }
    }
}

#[derive(Debug)]
pub struct PatternMatcherStats {
    pub strategy: SimdStrategy,
    pub pattern_count: usize,
    pub chunk_size: usize,
}

impl SimdOptimized for SimdPatternMatcher {
    type Input = &'static str;
    type Output = Vec<PatternMatch>;
    
    fn execute_simd(&self, input: Self::Input) -> Self::Output {
        match self.strategy {
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Avx2 => self.find_patterns_avx2(input.as_bytes(), input),
            #[cfg(all(target_arch = "x86_64", feature = "simd-optimizations"))]
            SimdStrategy::Sse42 => self.find_patterns_sse42(input.as_bytes(), input),
            #[cfg(all(target_arch = "aarch64", feature = "simd-optimizations"))]
            SimdStrategy::ArmNeon => self.find_patterns_neon(input.as_bytes(), input),
            _ => self.find_patterns_scalar(input.as_bytes(), input),
        }
    }
    
    fn execute_scalar(&self, input: Self::Input) -> Self::Output {
        self.find_patterns_scalar(input.as_bytes(), input)
    }
}

/// Parallel pattern matcher for enterprise-scale processing
pub struct ParallelPatternMatcher {
    matcher: SimdPatternMatcher,
    thread_count: usize,
}

impl ParallelPatternMatcher {
    pub fn new() -> Self {
        Self {
            matcher: SimdPatternMatcher::new(),
            thread_count: num_cpus::get(),
        }
    }
    
    /// Process large datasets in parallel with SIMD optimization
    pub fn process_log_files(&self, file_contents: &[String]) -> Vec<Vec<PatternMatch>> {
        #[cfg(feature = "simd-optimizations")]
        {
            use rayon::prelude::*;
            
            file_contents.par_iter()
                .map(|content| self.matcher.find_patterns(content))
                .collect()
        }
        
        #[cfg(not(feature = "simd-optimizations"))]
        {
            file_contents.iter()
                .map(|content| self.matcher.find_patterns(content))
                .collect()
        }
    }
    
    /// Real-time pattern matching for streaming data
    pub fn process_stream<I>(&self, stream: I) -> impl Iterator<Item = Vec<PatternMatch>> + '_
    where
        I: Iterator<Item = String>,
    {
        stream.map(move |data| self.matcher.find_patterns(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_pattern_matcher_creation() {
        let matcher = SimdPatternMatcher::new();
        assert!(!matcher.patterns.is_empty());
        println!("Pattern matcher created with {} patterns", matcher.patterns.len());
    }
    
    #[test]
    fn test_aws_key_detection() {
        let matcher = SimdPatternMatcher::new();
        let test_text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        
        let matches = matcher.find_patterns(test_text);
        assert!(!matches.is_empty());
        
        let aws_match = matches.iter().find(|m| m.pattern_name == "AWS_ACCESS_KEY");
        assert!(aws_match.is_some());
        
        if let Some(m) = aws_match {
            assert_eq!(m.matched_text, "AKIAIOSFODNN7EXAMPLE");
            assert!(m.confidence > 0.9);
        }
    }
    
    #[test]
    fn test_github_token_detection() {
        let matcher = SimdPatternMatcher::new();
        let test_text = "GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890";
        
        let matches = matcher.find_patterns(test_text);
        let github_match = matches.iter().find(|m| m.pattern_name == "GITHUB_TOKEN");
        assert!(github_match.is_some());
        
        if let Some(m) = github_match {
            assert!(m.matched_text.starts_with("ghp_"));
            assert!(m.confidence > 0.9);
        }
    }
    
    #[test]
    fn test_stripe_key_detection() {
        let matcher = SimdPatternMatcher::new();
        let test_text = "STRIPE_SECRET=sk_live_TEST_PLACEHOLDER_MASKED";
        
        let matches = matcher.find_patterns(test_text);
        let stripe_match = matches.iter().find(|m| m.pattern_name == "STRIPE_SECRET_KEY");
        assert!(stripe_match.is_some());
        
        if let Some(m) = stripe_match {
            assert!(m.matched_text.starts_with("sk_live_"));
            assert!(m.confidence > 0.8);
        }
    }
    
    #[test]
    fn test_batch_pattern_matching() {
        let matcher = SimdPatternMatcher::new();
        let test_texts = vec![
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890", 
            "STRIPE_SECRET=sk_live_TEST_PLACEHOLDER_MASKED",
            "normal_config_value=just_a_regular_string",
        ];
        
        let batch_results = matcher.find_patterns_batch(&test_texts);
        assert_eq!(batch_results.len(), test_texts.len());
        
        // Should find credentials in first 3 texts
        assert!(!batch_results[0].is_empty()); // AWS
        assert!(!batch_results[1].is_empty()); // GitHub
        assert!(!batch_results[2].is_empty()); // Stripe
        assert!(batch_results[3].is_empty());  // Normal config
    }
    
    #[test]
    fn test_pattern_validation() {
        let matcher = SimdPatternMatcher::new();
        
        // Valid AWS key
        assert!(matcher.validate_credential_format("AKIAIOSFODNN7EXAMPLE", 
            &matcher.patterns.iter().find(|p| p.name == "AWS_ACCESS_KEY").unwrap()));
        
        // Invalid AWS key (wrong length)
        assert!(!matcher.validate_credential_format("AKIA123", 
            &matcher.patterns.iter().find(|p| p.name == "AWS_ACCESS_KEY").unwrap()));
        
        // Valid GitHub token
        assert!(matcher.validate_credential_format("ghp_1234567890123456789012345678901234567890", 
            &matcher.patterns.iter().find(|p| p.name == "GITHUB_TOKEN").unwrap()));
    }
    
    #[test]
    fn test_parallel_pattern_matcher() {
        let parallel_matcher = ParallelPatternMatcher::new();
        let file_contents = vec![
            "Log file 1: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string(),
            "Log file 2: GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890".to_string(),
            "Log file 3: STRIPE_SECRET=sk_live_TEST_PLACEHOLDER_MASKED".to_string(),
        ];
        
        let results = parallel_matcher.process_log_files(&file_contents);
        assert_eq!(results.len(), file_contents.len());
        
        // Each log file should have at least one credential detected
        for result in results {
            assert!(!result.is_empty());
        }
    }
    
    #[test]
    fn test_performance_simd_vs_scalar() {
        let matcher = SimdPatternMatcher::new();
        let large_text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE ".repeat(1000);
        
        // Test SIMD version
        let simd_start = std::time::Instant::now();
        let simd_matches = matcher.find_patterns(&large_text);
        let simd_duration = simd_start.elapsed();
        
        // Test scalar version
        let scalar_start = std::time::Instant::now();
        let scalar_matches = matcher.find_patterns_scalar(large_text.as_bytes(), &large_text);
        let scalar_duration = scalar_start.elapsed();
        
        println!("SIMD: {:?}, Scalar: {:?}", simd_duration, scalar_duration);
        
        // Results should be identical
        assert_eq!(simd_matches.len(), scalar_matches.len());
        
        // SIMD should be faster or at least comparable
        // Note: On small datasets, overhead might make SIMD slower
        println!("SIMD found {} matches in {:?}", simd_matches.len(), simd_duration);
        println!("Scalar found {} matches in {:?}", scalar_matches.len(), scalar_duration);
    }
}