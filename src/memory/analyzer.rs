//! Memory analyzer primitives responsible for deriving entropy, printable
//! ratios, and structured pattern matches from raw regions.

use super::{regions::MemoryRegion, MemoryConfig};
use anyhow::Result;

/// Calculates low-level statistics for sampled chunks of process memory.
pub struct MemoryAnalyzer;

/// Summary describing the statistical characteristics of an analyzed block.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Shannon entropy captured from the byte distribution (0-8 bits).
    pub entropy: f64,
    /// Percentage of bytes that map to printable ASCII characters.
    pub printable_ratio: f64,
    /// Count of zero bytes, often indicating cleared buffers.
    pub null_bytes: usize,
    /// Patterns that heuristics flagged as potentially sensitive secrets.
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    /// Absolute virtual address where this segment begins.
    pub base_address: u64,
    /// Offset within the scanned region where this analysis segment begins.
    pub start_offset: usize,
    /// Length of the analyzed segment in bytes.
    pub length: usize,
}

/// Metadata describing a single suspicious pattern discovered in memory.
#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    /// Logical name for the matched signature (e.g., `pem_block`).
    pub pattern: &'static str,
    /// Offset within the region containing the match
    pub offset: usize,
    /// Absolute virtual address for the pattern
    pub address: u64,
}

impl MemoryAnalyzer {
    /// Build a new analyzer instance; configuration is provided for tunables.
    pub async fn new(_config: &MemoryConfig) -> Result<Self> {
        Ok(Self)
    }

    /// Analyze a chunk of process memory and derive statistical signals.
    pub async fn analyze_memory_block(
        &self,
        data: &[u8],
        region: &MemoryRegion,
        base_offset: usize,
    ) -> Result<AnalysisResult> {
        let base_address = region.start_address + base_offset as u64;

        if data.is_empty() {
            return Ok(AnalysisResult {
                entropy: 0.0,
                printable_ratio: 0.0,
                null_bytes: 0,
                suspicious_patterns: Vec::new(),
                base_address,
                start_offset: base_offset,
                length: 0,
            });
        }

        let entropy = calculate_entropy(data);
        let printable_ratio = calculate_printable_ratio(data);
        let null_bytes = data.iter().filter(|&&b| b == 0).count();
        let suspicious_patterns = find_suspicious_patterns(data, base_offset, region.start_address);

        Ok(AnalysisResult {
            entropy,
            printable_ratio,
            null_bytes,
            suspicious_patterns,
            base_address,
            start_offset: base_offset,
            length: data.len(),
        })
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn calculate_printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let printable = data
        .iter()
        .filter(|&&byte| matches!(byte, 0x20..=0x7E | b'\n' | b'\r' | b'\t'))
        .count();

    printable as f64 / data.len() as f64
}

fn find_suspicious_patterns(
    data: &[u8],
    base_offset: usize,
    region_base: u64,
) -> Vec<SuspiciousPattern> {
    const PATTERNS: [&[u8]; 4] = [
        b"-----BEGIN",
        b"AKIA",
        b"aws_secret_access_key",
        b"PRIVATE KEY",
    ];

    let mut matches = Vec::new();
    for pattern in PATTERNS {
        let mut offset = 0usize;
        while offset + pattern.len() <= data.len() {
            if &data[offset..offset + pattern.len()] == pattern {
                matches.push(SuspiciousPattern {
                    pattern: match pattern {
                        b"-----BEGIN" => "pem_block",
                        b"AKIA" => "aws_access_key",
                        b"aws_secret_access_key" => "aws_secret_key",
                        b"PRIVATE KEY" => "private_key_marker",
                        _ => "unknown",
                    },
                    offset: base_offset + offset,
                    address: region_base + (base_offset + offset) as u64,
                });
                offset += pattern.len();
                continue;
            }
            offset += 1;
        }
    }

    matches
}
