use crate::{MemoryRegion, PatternMatch, PatternMatcher};
use anyhow::Result;
use memmap2::MmapOptions;
use std::fs::File;

pub struct MemoryScanner {
    matcher: PatternMatcher,
    default_patterns: Vec<Vec<u8>>,
}

impl MemoryScanner {
    pub fn new() -> Result<Self> {
        let default_patterns = vec![
            b"AKIA".to_vec(),          // AWS Access Key
            b"ASIA".to_vec(),          // AWS Temporary Token
            b"sk_live_".to_vec(),      // Stripe Live Key
            b"pk_live_".to_vec(),      // Stripe Public Key
            b"ghp_".to_vec(),          // GitHub Personal Token
            b"gho_".to_vec(),          // GitHub OAuth Token
            b"-----BEGIN".to_vec(),    // PEM Certificate/Key
            b"ssh-rsa".to_vec(),       // SSH Public Key
            b"ssh-ed25519".to_vec(),   // SSH Ed25519 Key
        ];
        
        Ok(Self {
            matcher: PatternMatcher::new()?,
            default_patterns,
        })
    }
    
    pub fn scan_region(&self, region: MemoryRegion) -> Result<Vec<PatternMatch>> {
        self.matcher.find_patterns(&region.data, &self.default_patterns)
    }
    
    pub fn scan_region_with_patterns(&self, region: MemoryRegion, patterns: &[Vec<u8>]) -> Result<Vec<PatternMatch>> {
        self.matcher.find_patterns(&region.data, patterns)
    }
    
    pub fn scan_file(&self, file_path: &std::path::Path) -> Result<Vec<PatternMatch>> {
        let file = File::open(file_path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        
        self.matcher.find_patterns(&mmap, &self.default_patterns)
    }
    
    pub fn scan_memory_mapped(&self, data: &[u8]) -> Result<Vec<PatternMatch>> {
        self.matcher.find_patterns(data, &self.default_patterns)
    }
    
    pub fn scan_with_entropy_filter(&self, region: MemoryRegion, min_entropy: f64) -> Result<Vec<PatternMatch>> {
        // Pre-filter high-entropy regions that are more likely to contain credentials
        let high_entropy_regions = self.find_high_entropy_regions(&region.data, min_entropy)?;
        
        let mut all_matches = Vec::new();
        
        for entropy_region in high_entropy_regions {
            let matches = self.matcher.find_patterns(&entropy_region.data, &self.default_patterns)?;
            all_matches.extend(matches);
        }
        
        Ok(all_matches)
    }
    
    fn find_high_entropy_regions(&self, data: &[u8], min_entropy: f64) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        let window_size = 64;
        
        for (offset, window) in data.windows(window_size).enumerate() {
            let entropy = calculate_entropy(window);
            
            if entropy >= min_entropy {
                regions.push(MemoryRegion {
                    start: offset,
                    size: window_size,
                    data: window.to_vec(),
                });
            }
        }
        
        Ok(regions)
    }
    
    pub fn add_custom_pattern(&mut self, pattern: Vec<u8>) {
        self.default_patterns.push(pattern);
    }
    
    pub fn clear_patterns(&mut self) {
        self.default_patterns.clear();
    }
    
    pub fn get_pattern_count(&self) -> usize {
        self.default_patterns.len()
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_scanner_creation() {
        let scanner = MemoryScanner::new().unwrap();
        assert!(scanner.get_pattern_count() > 0);
    }
    
    #[test]
    fn test_scan_region() {
        let scanner = MemoryScanner::new().unwrap();
        let region = MemoryRegion {
            start: 0,
            size: 32,
            data: b"test AKIA1234567890ABCDEF data".to_vec(),
        };
        
        let matches = scanner.scan_region(region).unwrap();
        assert!(!matches.is_empty());
    }
    
    #[test]
    fn test_entropy_calculation() {
        let high_entropy = b"a8f5f167f44f4964e6c998dee827110c";
        let low_entropy = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        
        assert!(calculate_entropy(high_entropy) > calculate_entropy(low_entropy));
    }
    
    #[test]
    fn test_custom_patterns() {
        let mut scanner = MemoryScanner::new().unwrap();
        let initial_count = scanner.get_pattern_count();
        
        scanner.add_custom_pattern(b"CUSTOM".to_vec());
        assert_eq!(scanner.get_pattern_count(), initial_count + 1);
        
        scanner.clear_patterns();
        assert_eq!(scanner.get_pattern_count(), 0);
    }
}