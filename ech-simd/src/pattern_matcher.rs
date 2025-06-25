use crate::{PatternMatch, simd_utils::*};
use anyhow::Result;
use wide::*;
use aligned_vec::AVec;

pub struct PatternMatcher {
    chunk_size: usize,
}

impl PatternMatcher {
    pub fn new() -> Result<Self> {
        Ok(Self {
            chunk_size: 64,
        })
    }
    
    pub fn find_patterns(&self, data: &[u8], patterns: &[Vec<u8>]) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        for (pattern_id, pattern) in patterns.iter().enumerate() {
            let pattern_matches = self.find_single_pattern(data, pattern, pattern_id)?;
            matches.extend(pattern_matches);
        }
        
        Ok(matches)
    }
    
    fn find_single_pattern(&self, data: &[u8], pattern: &[u8], pattern_id: usize) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        if pattern.is_empty() || data.len() < pattern.len() {
            return Ok(matches);
        }
        
        // Use SIMD for pattern matching when possible
        #[cfg(target_feature = "avx2")]
        if pattern.len() >= 32 {
            matches.extend(self.simd_search_avx2(data, pattern, pattern_id)?);
        } else {
            matches.extend(self.scalar_search(data, pattern, pattern_id)?);
        }
        
        #[cfg(all(target_feature = "sse4.1", not(target_feature = "avx2")))]
        if pattern.len() >= 16 {
            matches.extend(self.simd_search_sse(data, pattern, pattern_id)?);
        } else {
            matches.extend(self.scalar_search(data, pattern, pattern_id)?);
        }
        
        #[cfg(not(any(target_feature = "avx2", target_feature = "sse4.1")))]
        {
            matches.extend(self.scalar_search(data, pattern, pattern_id)?);
        }
        
        Ok(matches)
    }
    
    #[cfg(target_feature = "avx2")]
    fn simd_search_avx2(&self, data: &[u8], pattern: &[u8], pattern_id: usize) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        // Simplified AVX2 implementation
        // In a real implementation, this would use proper AVX2 intrinsics
        matches.extend(self.scalar_search(data, pattern, pattern_id)?);
        
        Ok(matches)
    }
    
    #[cfg(target_feature = "sse4.1")]
    fn simd_search_sse(&self, data: &[u8], pattern: &[u8], pattern_id: usize) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        // Simplified SSE implementation
        // In a real implementation, this would use proper SSE intrinsics
        matches.extend(self.scalar_search(data, pattern, pattern_id)?);
        
        Ok(matches)
    }
    
    fn scalar_search(&self, data: &[u8], pattern: &[u8], pattern_id: usize) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        for (offset, window) in data.windows(pattern.len()).enumerate() {
            if window == pattern {
                matches.push(PatternMatch {
                    pattern_id,
                    offset,
                    length: pattern.len(),
                    confidence: 1.0,
                });
            }
        }
        
        Ok(matches)
    }
    
    pub fn find_approximate_patterns(&self, data: &[u8], patterns: &[Vec<u8>], max_distance: usize) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        for (pattern_id, pattern) in patterns.iter().enumerate() {
            let approx_matches = self.find_approximate_pattern(data, pattern, pattern_id, max_distance)?;
            matches.extend(approx_matches);
        }
        
        Ok(matches)
    }
    
    fn find_approximate_pattern(&self, data: &[u8], pattern: &[u8], pattern_id: usize, max_distance: usize) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        if pattern.is_empty() || data.len() < pattern.len() {
            return Ok(matches);
        }
        
        for (offset, window) in data.windows(pattern.len()).enumerate() {
            let distance = hamming_distance(window, pattern);
            if distance <= max_distance {
                let confidence = 1.0 - (distance as f64 / pattern.len() as f64);
                matches.push(PatternMatch {
                    pattern_id,
                    offset,
                    length: pattern.len(),
                    confidence,
                });
            }
        }
        
        Ok(matches)
    }
}

fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).filter(|(x, y)| x != y).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pattern_matching() {
        let matcher = PatternMatcher::new().unwrap();
        let data = b"test AKIA1234567890ABCDEF more data";
        let patterns = vec![b"AKIA".to_vec()];
        
        let matches = matcher.find_patterns(data, &patterns).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 5);
    }
    
    #[test]
    fn test_multiple_patterns() {
        let matcher = PatternMatcher::new().unwrap();
        let data = b"AKIA1234 sk_live_test ghp_token";
        let patterns = vec![
            b"AKIA".to_vec(),
            b"sk_live_".to_vec(),
            b"ghp_".to_vec(),
        ];
        
        let matches = matcher.find_patterns(data, &patterns).unwrap();
        assert_eq!(matches.len(), 3);
    }
    
    #[test]
    fn test_approximate_matching() {
        let matcher = PatternMatcher::new().unwrap();
        let data = b"AKIB1234567890ABCDEF"; // One character different
        let patterns = vec![b"AKIA".to_vec()];
        
        let matches = matcher.find_approximate_patterns(data, &patterns, 1).unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].confidence < 1.0);
    }
}