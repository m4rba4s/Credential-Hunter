pub mod pattern_matcher;
pub mod memory_scanner;
pub mod simd_utils;

pub use pattern_matcher::*;
pub use memory_scanner::*;
pub use simd_utils::*;

use anyhow::Result;

pub struct SimdEngine {
    matcher: PatternMatcher,
    scanner: MemoryScanner,
}

impl SimdEngine {
    pub fn new() -> Result<Self> {
        Ok(Self {
            matcher: PatternMatcher::new()?,
            scanner: MemoryScanner::new()?,
        })
    }
    
    pub fn scan_with_patterns(&self, data: &[u8], patterns: &[Vec<u8>]) -> Result<Vec<PatternMatch>> {
        self.matcher.find_patterns(data, patterns)
    }
    
    pub fn scan_memory_region(&self, region: MemoryRegion) -> Result<Vec<PatternMatch>> {
        self.scanner.scan_region(region)
    }
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_id: usize,
    pub offset: usize,
    pub length: usize,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: usize,
    pub size: usize,
    pub data: Vec<u8>,
}