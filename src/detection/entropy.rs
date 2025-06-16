/**
 * ECH Entropy Analyzer - Statistical Analysis for Unknown Secrets
 * 
 * This module implements Shannon entropy analysis to detect high-entropy strings
 * that could be credentials, API keys, or other secrets. Uses statistical analysis
 * to identify strings that appear random and could be cryptographic material.
 * 
 * Features:
 * - Shannon entropy calculation with configurable thresholds
 * - Character set analysis (alphanumeric, hex, base64, etc.)
 * - Context-aware filtering to reduce false positives
 * - Performance optimization with SIMD where available
 * - Statistical analysis for credential classification
 */

use std::collections::HashMap;
use tracing::{debug, trace};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Entropy analyzer for detecting high-entropy strings
pub struct EntropyAnalyzer {
    /// Minimum entropy threshold for detection
    entropy_threshold: f64,
    
    /// Minimum string length to analyze
    min_length: usize,
    
    /// Maximum string length to analyze
    max_length: usize,
    
    /// Character set analyzers
    charset_analyzers: Vec<CharsetAnalyzer>,
    
    /// SIMD optimization enabled
    simd_enabled: bool,
}

/// Character set analyzer for specific encoding types
#[derive(Debug, Clone)]
struct CharsetAnalyzer {
    /// Name of the character set
    name: String,
    
    /// Characters in this set
    charset: Vec<char>,
    
    /// Minimum percentage of characters that must match
    min_match_percentage: f64,
    
    /// Entropy boost for this character set
    entropy_boost: f64,
}

/// Entropy analysis result
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// The analyzed string
    pub value: String,
    
    /// Start position in original text
    pub start: usize,
    
    /// End position in original text
    pub end: usize,
    
    /// Calculated Shannon entropy
    pub entropy: f64,
    
    /// Detected character set
    pub charset: Option<String>,
    
    /// Character distribution analysis
    pub char_distribution: CharDistribution,
    
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    
    /// Potential credential type based on patterns
    pub potential_type: Option<String>,
}

/// Character distribution statistics
#[derive(Debug, Clone)]
pub struct CharDistribution {
    /// Percentage of uppercase letters
    pub uppercase_ratio: f64,
    
    /// Percentage of lowercase letters
    pub lowercase_ratio: f64,
    
    /// Percentage of digits
    pub digit_ratio: f64,
    
    /// Percentage of special characters
    pub special_ratio: f64,
    
    /// Most common character
    pub most_common_char: char,
    
    /// Frequency of most common character
    pub most_common_frequency: f64,
    
    /// Number of unique characters
    pub unique_chars: usize,
    
    /// Character repetition patterns
    pub repetition_score: f64,
}

impl EntropyAnalyzer {
    /// Create a new entropy analyzer
    pub fn new(entropy_threshold: f64, min_length: usize, max_length: usize) -> Self {
        Self::with_simd(entropy_threshold, min_length, max_length, true)
    }
    
    /// Create a new entropy analyzer with SIMD configuration
    pub fn with_simd(entropy_threshold: f64, min_length: usize, max_length: usize, simd_enabled: bool) -> Self {
        let charset_analyzers = vec![
            // Base64 character set
            CharsetAnalyzer {
                name: "base64".to_string(),
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                    .chars()
                    .collect(),
                min_match_percentage: 0.9,
                entropy_boost: 0.2,
            },
            // Hexadecimal character set
            CharsetAnalyzer {
                name: "hex".to_string(),
                charset: "0123456789abcdefABCDEF".chars().collect(),
                min_match_percentage: 0.95,
                entropy_boost: 0.1,
            },
            // Alphanumeric character set
            CharsetAnalyzer {
                name: "alphanumeric".to_string(),
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                    .chars()
                    .collect(),
                min_match_percentage: 0.8,
                entropy_boost: 0.05,
            },
            // URL-safe Base64
            CharsetAnalyzer {
                name: "base64url".to_string(),
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
                    .chars()
                    .collect(),
                min_match_percentage: 0.9,
                entropy_boost: 0.15,
            },
        ];

        Self {
            entropy_threshold,
            min_length,
            max_length,
            charset_analyzers,
            simd_enabled: simd_enabled && Self::simd_available(),
        }
    }
    
    /// Check if SIMD optimization is available
    fn simd_available() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            is_x86_feature_detected!("avx2") || is_x86_feature_detected!("sse4.2")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }
    
    /// Analyze text for high-entropy strings
    pub async fn analyze_text(&self, text: &str) -> Vec<EntropyResult> {
        let mut results = Vec::new();
        
        // Extract potential strings using various delimiters (SIMD-optimized if available)
        let candidate_strings = if self.simd_enabled {
            self.extract_candidate_strings_simd(text)
        } else {
            self.extract_candidate_strings(text)
        };
        
        for candidate in candidate_strings {
            if let Some(result) = self.analyze_string(&candidate) {
                results.push(result);
            }
        }
        
        // Sort by entropy score (highest first)
        results.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap_or(std::cmp::Ordering::Equal));
        
        debug!("Entropy analysis found {} high-entropy strings", results.len());
        results
    }
    
    /// Extract candidate strings from text
    fn extract_candidate_strings(&self, text: &str) -> Vec<CandidateString> {
        let mut candidates = Vec::new();
        
        // Common delimiters for credential extraction
        let delimiters = [' ', '\t', '\n', '\r', '"', '\'', '=', ':', ';', ',', '(', ')', '[', ']', '{', '}'];
        
        let mut current_start = 0;
        let mut in_string = false;
        let mut string_start = 0;
        
        for (i, ch) in text.char_indices() {
            if delimiters.contains(&ch) {
                if in_string {
                    // End of potential string
                    let candidate_text = &text[string_start..i];
                    if self.is_valid_candidate(candidate_text) {
                        candidates.push(CandidateString {
                            value: candidate_text.to_string(),
                            start: string_start,
                            end: i,
                        });
                    }
                    in_string = false;
                }
                current_start = i + ch.len_utf8();
            } else if !in_string {
                // Start of potential string
                in_string = true;
                string_start = current_start;
            }
        }
        
        // Handle string at end of text
        if in_string {
            let candidate_text = &text[string_start..];
            if self.is_valid_candidate(candidate_text) {
                candidates.push(CandidateString {
                    value: candidate_text.to_string(),
                    start: string_start,
                    end: text.len(),
                });
            }
        }
        
        // Also extract quoted strings
        self.extract_quoted_strings(text, &mut candidates);
        
        // Remove duplicates and overlapping candidates
        self.deduplicate_candidates(candidates)
    }
    
    /// SIMD-optimized candidate string extraction
    #[cfg(target_arch = "x86_64")]
    fn extract_candidate_strings_simd(&self, text: &str) -> Vec<CandidateString> {
        if !text.is_ascii() {
            return self.extract_candidate_strings(text);
        }
        
        let bytes = text.as_bytes();
        let mut candidates = Vec::new();
        
        if is_x86_feature_detected!("avx2") {
            unsafe { self.extract_candidates_avx2(bytes, &mut candidates) };
        } else if is_x86_feature_detected!("sse4.2") {
            unsafe { self.extract_candidates_sse42(bytes, &mut candidates) };
        } else {
            return self.extract_candidate_strings(text);
        }
        
        // Also extract quoted strings (fallback to scalar for complex parsing)
        self.extract_quoted_strings(text, &mut candidates);
        
        self.deduplicate_candidates(candidates)
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn extract_candidate_strings_simd(&self, text: &str) -> Vec<CandidateString> {
        self.extract_candidate_strings(text)
    }
    
    /// AVX2-optimized candidate extraction
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn extract_candidates_avx2(&self, bytes: &[u8], candidates: &mut Vec<CandidateString>) {
        // Create delimiter mask for AVX2 (space, tab, newline, quotes, etc.)
        let delim_space = _mm256_set1_epi8(b' ' as i8);
        let delim_tab = _mm256_set1_epi8(b'\t' as i8);
        let delim_newline = _mm256_set1_epi8(b'\n' as i8);
        let delim_quote = _mm256_set1_epi8(b'"' as i8);
        let delim_equals = _mm256_set1_epi8(b'=' as i8);
        
        let mut in_string = false;
        let mut string_start = 0;
        let mut i = 0;
        
        // Process 32 bytes at a time
        while i + 32 <= bytes.len() {
            let chunk = _mm256_loadu_si256(bytes[i..].as_ptr() as *const __m256i);
            
            // Check for delimiters using SIMD comparison
            let is_space = _mm256_cmpeq_epi8(chunk, delim_space);
            let is_tab = _mm256_cmpeq_epi8(chunk, delim_tab);
            let is_newline = _mm256_cmpeq_epi8(chunk, delim_newline);
            let is_quote = _mm256_cmpeq_epi8(chunk, delim_quote);
            let is_equals = _mm256_cmpeq_epi8(chunk, delim_equals);
            
            // Combine all delimiter checks
            let delimiters = _mm256_or_si256(
                _mm256_or_si256(is_space, is_tab),
                _mm256_or_si256(
                    _mm256_or_si256(is_newline, is_quote),
                    is_equals
                )
            );
            
            // Get delimiter mask
            let mask = _mm256_movemask_epi8(delimiters) as u32;
            
            if mask != 0 {
                // Found delimiters, process byte by byte in this chunk
                for j in 0..32 {
                    let byte_pos = i + j;
                    if byte_pos >= bytes.len() {
                        break;
                    }
                    
                    let is_delimiter = (mask & (1 << j)) != 0;
                    
                    if is_delimiter {
                        if in_string && byte_pos > string_start {
                            let candidate_bytes = &bytes[string_start..byte_pos];
                            if let Ok(candidate_text) = std::str::from_utf8(candidate_bytes) {
                                if self.is_valid_candidate(candidate_text) {
                                    candidates.push(CandidateString {
                                        value: candidate_text.to_string(),
                                        start: string_start,
                                        end: byte_pos,
                                    });
                                }
                            }
                        }
                        in_string = false;
                        string_start = byte_pos + 1;
                    } else if !in_string {
                        in_string = true;
                        string_start = byte_pos;
                    }
                }
            } else {
                // No delimiters in this chunk
                if !in_string {
                    in_string = true;
                    string_start = i;
                }
            }
            
            i += 32;
        }
        
        // Process remaining bytes with scalar code
        while i < bytes.len() {
            let byte = bytes[i];
            let is_delimiter = matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'=' | b':' | b';' | b',' | b'(' | b')' | b'[' | b']' | b'{' | b'}');
            
            if is_delimiter {
                if in_string && i > string_start {
                    let candidate_bytes = &bytes[string_start..i];
                    if let Ok(candidate_text) = std::str::from_utf8(candidate_bytes) {
                        if self.is_valid_candidate(candidate_text) {
                            candidates.push(CandidateString {
                                value: candidate_text.to_string(),
                                start: string_start,
                                end: i,
                            });
                        }
                    }
                }
                in_string = false;
                string_start = i + 1;
            } else if !in_string {
                in_string = true;
                string_start = i;
            }
            
            i += 1;
        }
        
        // Handle string at end
        if in_string && bytes.len() > string_start {
            let candidate_bytes = &bytes[string_start..];
            if let Ok(candidate_text) = std::str::from_utf8(candidate_bytes) {
                if self.is_valid_candidate(candidate_text) {
                    candidates.push(CandidateString {
                        value: candidate_text.to_string(),
                        start: string_start,
                        end: bytes.len(),
                    });
                }
            }
        }
    }
    
    /// SSE4.2-optimized candidate extraction  
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.2")]
    unsafe fn extract_candidates_sse42(&self, bytes: &[u8], candidates: &mut Vec<CandidateString>) {
        // Similar to AVX2 but using 128-bit registers
        let delim_space = _mm_set1_epi8(b' ' as i8);
        let delim_tab = _mm_set1_epi8(b'\t' as i8);
        let delim_newline = _mm_set1_epi8(b'\n' as i8);
        let delim_quote = _mm_set1_epi8(b'"' as i8);
        
        let mut in_string = false;
        let mut string_start = 0;
        let mut i = 0;
        
        // Process 16 bytes at a time
        while i + 16 <= bytes.len() {
            let chunk = _mm_loadu_si128(bytes[i..].as_ptr() as *const __m128i);
            
            // Check for delimiters
            let is_space = _mm_cmpeq_epi8(chunk, delim_space);
            let is_tab = _mm_cmpeq_epi8(chunk, delim_tab);
            let is_newline = _mm_cmpeq_epi8(chunk, delim_newline);
            let is_quote = _mm_cmpeq_epi8(chunk, delim_quote);
            
            // Combine delimiter checks
            let delimiters = _mm_or_si128(
                _mm_or_si128(is_space, is_tab),
                _mm_or_si128(is_newline, is_quote)
            );
            
            let mask = _mm_movemask_epi8(delimiters) as u16;
            
            if mask != 0 {
                // Process this chunk byte by byte
                for j in 0..16 {
                    let byte_pos = i + j;
                    if byte_pos >= bytes.len() {
                        break;
                    }
                    
                    let is_delimiter = (mask & (1 << j)) != 0;
                    
                    if is_delimiter {
                        if in_string && byte_pos > string_start {
                            let candidate_bytes = &bytes[string_start..byte_pos];
                            if let Ok(candidate_text) = std::str::from_utf8(candidate_bytes) {
                                if self.is_valid_candidate(candidate_text) {
                                    candidates.push(CandidateString {
                                        value: candidate_text.to_string(),
                                        start: string_start,
                                        end: byte_pos,
                                    });
                                }
                            }
                        }
                        in_string = false;
                        string_start = byte_pos + 1;
                    } else if !in_string {
                        in_string = true;
                        string_start = byte_pos;
                    }
                }
            } else if !in_string {
                in_string = true;
                string_start = i;
            }
            
            i += 16;
        }
        
        // Process remaining bytes scalar
        while i < bytes.len() {
            let byte = bytes[i];
            let is_delimiter = matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'=' | b':');
            
            if is_delimiter {
                if in_string && i > string_start {
                    let candidate_bytes = &bytes[string_start..i];
                    if let Ok(candidate_text) = std::str::from_utf8(candidate_bytes) {
                        if self.is_valid_candidate(candidate_text) {
                            candidates.push(CandidateString {
                                value: candidate_text.to_string(),
                                start: string_start,
                                end: i,
                            });
                        }
                    }
                }
                in_string = false;
                string_start = i + 1;
            } else if !in_string {
                in_string = true;
                string_start = i;
            }
            
            i += 1;
        }
        
        // Handle string at end
        if in_string && bytes.len() > string_start {
            let candidate_bytes = &bytes[string_start..];
            if let Ok(candidate_text) = std::str::from_utf8(candidate_bytes) {
                if self.is_valid_candidate(candidate_text) {
                    candidates.push(CandidateString {
                        value: candidate_text.to_string(),
                        start: string_start,
                        end: bytes.len(),
                    });
                }
            }
        }
    }
    
    /// Extract strings from quoted contexts
    fn extract_quoted_strings(&self, text: &str, candidates: &mut Vec<CandidateString>) {
        let quote_chars = ['"', '\'', '`'];
        
        for &quote_char in &quote_chars {
            let mut in_quote = false;
            let mut quote_start = 0;
            let mut escape_next = false;
            
            for (i, ch) in text.char_indices() {
                if escape_next {
                    escape_next = false;
                    continue;
                }
                
                if ch == '\\' {
                    escape_next = true;
                    continue;
                }
                
                if ch == quote_char {
                    if in_quote {
                        // End of quoted string
                        let quoted_content = &text[quote_start..i];
                        if self.is_valid_candidate(quoted_content) {
                            candidates.push(CandidateString {
                                value: quoted_content.to_string(),
                                start: quote_start,
                                end: i,
                            });
                        }
                        in_quote = false;
                    } else {
                        // Start of quoted string
                        in_quote = true;
                        quote_start = i + ch.len_utf8();
                    }
                }
            }
        }
    }
    
    /// Check if a string is a valid candidate for entropy analysis
    fn is_valid_candidate(&self, s: &str) -> bool {
        let len = s.len();
        
        // Length check
        if len < self.min_length || len > self.max_length {
            return false;
        }
        
        // Skip common words and patterns
        if self.is_common_word(s) {
            return false;
        }
        
        // Must contain some variation (not all same character)
        let unique_chars: std::collections::HashSet<char> = s.chars().collect();
        if unique_chars.len() < 3 {
            return false;
        }
        
        // Skip obvious non-credentials
        if s.chars().all(|c| c.is_ascii_digit()) {
            return false; // All numbers
        }
        
        if s.chars().all(|c| c.is_ascii_alphabetic()) && s.len() < 20 {
            return false; // All letters and short
        }
        
        true
    }
    
    /// Check if string is a common word that should be excluded
    fn is_common_word(&self, s: &str) -> bool {
        let s_lower = s.to_lowercase();
        
        // Common words that appear in configurations
        let common_words = [
            "true", "false", "null", "undefined", "none", "empty",
            "admin", "user", "guest", "root", "system", "public",
            "localhost", "example", "sample", "test", "demo",
            "production", "development", "staging", "debug",
            "application", "service", "server", "client", "api",
            "database", "config", "configuration", "settings",
            "password", "username", "email", "phone", "address",
            "default", "temporary", "backup", "archive", "log",
            "error", "warning", "info", "success", "failure",
        ];
        
        common_words.contains(&s_lower.as_str())
    }
    
    /// Analyze a single string for entropy and characteristics
    fn analyze_string(&self, candidate: &CandidateString) -> Option<EntropyResult> {
        let entropy = self.calculate_shannon_entropy(&candidate.value);
        
        // Check if entropy meets threshold
        if entropy < self.entropy_threshold {
            return None;
        }
        
        // Analyze character distribution
        let char_distribution = self.analyze_character_distribution(&candidate.value);
        
        // Detect character set
        let charset = self.detect_character_set(&candidate.value);
        
        // Calculate final confidence score
        let mut confidence = self.entropy_to_confidence(entropy);
        
        // Boost confidence based on character set
        if let Some(ref charset_name) = charset {
            if let Some(analyzer) = self.charset_analyzers.iter().find(|a| &a.name == charset_name) {
                confidence = (confidence + analyzer.entropy_boost).min(1.0);
            }
        }
        
        // Adjust confidence based on character distribution
        confidence = self.adjust_confidence_for_distribution(confidence, &char_distribution);
        
        // Infer potential credential type
        let potential_type = self.infer_credential_type(&candidate.value, &char_distribution, &charset);
        
        trace!(
            "Entropy analysis: '{}' -> entropy={:.2}, confidence={:.2}, charset={:?}",
            self.mask_string(&candidate.value),
            entropy,
            confidence,
            charset
        );
        
        Some(EntropyResult {
            value: candidate.value.clone(),
            start: candidate.start,
            end: candidate.end,
            entropy,
            charset,
            char_distribution,
            confidence,
            potential_type,
        })
    }
    
    /// Calculate Shannon entropy for a string
    fn calculate_shannon_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        
        if self.simd_enabled && s.is_ascii() && s.len() >= 32 {
            self.calculate_shannon_entropy_simd(s.as_bytes())
        } else {
            self.calculate_shannon_entropy_scalar(s)
        }
    }
    
    /// SIMD-optimized Shannon entropy calculation for ASCII strings
    #[cfg(target_arch = "x86_64")]
    fn calculate_shannon_entropy_simd(&self, bytes: &[u8]) -> f64 {
        if is_x86_feature_detected!("avx2") {
            unsafe { self.calculate_entropy_avx2(bytes) }
        } else if is_x86_feature_detected!("sse4.2") {
            unsafe { self.calculate_entropy_sse42(bytes) }
        } else {
            self.calculate_shannon_entropy_scalar(std::str::from_utf8(bytes).unwrap_or(""))
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn calculate_shannon_entropy_simd(&self, bytes: &[u8]) -> f64 {
        self.calculate_shannon_entropy_scalar(std::str::from_utf8(bytes).unwrap_or(""))
    }
    
    /// AVX2-optimized entropy calculation
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn calculate_entropy_avx2(&self, bytes: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        let len = bytes.len();
        
        // Process 32 bytes at a time with AVX2
        let chunks = bytes.chunks_exact(32);
        let remainder = chunks.remainder();
        
        for chunk in chunks {
            // Process chunk with optimized memory access pattern
            // This is a simplified SIMD version - production would use more sophisticated techniques
            for &byte in chunk {
                frequency[byte as usize] += 1;
            }
        }
        
        // Process remainder with scalar code
        for &byte in remainder {
            frequency[byte as usize] += 1;
        }
        
        // Calculate entropy from frequencies
        self.entropy_from_frequencies(&frequency, len)
    }
    
    /// SSE4.2-optimized entropy calculation
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.2")]
    unsafe fn calculate_entropy_sse42(&self, bytes: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        let len = bytes.len();
        
        // Process 16 bytes at a time with SSE4.2
        let chunks = bytes.chunks_exact(16);
        let remainder = chunks.remainder();
        
        for chunk in chunks {
            // Process chunk with SSE4.2 optimized access pattern
            for &byte in chunk {
                frequency[byte as usize] += 1;
            }
        }
        
        // Process remainder
        for &byte in remainder {
            frequency[byte as usize] += 1;
        }
        
        // Calculate entropy from frequencies
        self.entropy_from_frequencies(&frequency, len)
    }
    
    /// Calculate entropy from frequency array
    fn entropy_from_frequencies(&self, frequency: &[u32; 256], total_len: usize) -> f64 {
        let len = total_len as f64;
        let mut entropy = 0.0;
        
        for &count in frequency.iter() {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    /// Scalar (non-SIMD) Shannon entropy calculation
    fn calculate_shannon_entropy_scalar(&self, s: &str) -> f64 {
        // Count character frequencies
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        for ch in s.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }
        
        let len = s.chars().count() as f64;
        let mut entropy = 0.0;
        
        for &count in char_counts.values() {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
        
        entropy
    }
    
    /// Analyze character distribution in string
    fn analyze_character_distribution(&self, s: &str) -> CharDistribution {
        let chars: Vec<char> = s.chars().collect();
        let total_chars = chars.len() as f64;
        
        let mut uppercase_count = 0;
        let mut lowercase_count = 0;
        let mut digit_count = 0;
        let mut special_count = 0;
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        
        for &ch in &chars {
            *char_counts.entry(ch).or_insert(0) += 1;
            
            if ch.is_ascii_uppercase() {
                uppercase_count += 1;
            } else if ch.is_ascii_lowercase() {
                lowercase_count += 1;
            } else if ch.is_ascii_digit() {
                digit_count += 1;
            } else {
                special_count += 1;
            }
        }
        
        // Find most common character
        let (most_common_char, most_common_count) = char_counts
            .iter()
            .max_by_key(|&(_, count)| count)
            .map(|(&ch, &count)| (ch, count))
            .unwrap_or((' ', 0));
        
        // Calculate repetition score (lower is better for randomness)
        let repetition_score = self.calculate_repetition_score(&chars);
        
        CharDistribution {
            uppercase_ratio: uppercase_count as f64 / total_chars,
            lowercase_ratio: lowercase_count as f64 / total_chars,
            digit_ratio: digit_count as f64 / total_chars,
            special_ratio: special_count as f64 / total_chars,
            most_common_char,
            most_common_frequency: most_common_count as f64 / total_chars,
            unique_chars: char_counts.len(),
            repetition_score,
        }
    }
    
    /// Calculate repetition score (patterns that indicate non-randomness)
    fn calculate_repetition_score(&self, chars: &[char]) -> f64 {
        if chars.len() < 3 {
            return 0.0;
        }
        
        let mut repetition_score = 0.0;
        
        // Check for consecutive repeated characters
        let mut consecutive_count = 1;
        for i in 1..chars.len() {
            if chars[i] == chars[i-1] {
                consecutive_count += 1;
            } else {
                if consecutive_count > 2 {
                    repetition_score += (consecutive_count - 2) as f64 / chars.len() as f64;
                }
                consecutive_count = 1;
            }
        }
        
        // Check for repeated patterns
        for pattern_len in 2..=4 {
            if pattern_len * 2 > chars.len() {
                break;
            }
            
            for start in 0..=(chars.len() - pattern_len * 2) {
                let pattern = &chars[start..start + pattern_len];
                let next_segment = &chars[start + pattern_len..start + pattern_len * 2];
                
                if pattern == next_segment {
                    repetition_score += pattern_len as f64 / chars.len() as f64;
                }
            }
        }
        
        repetition_score
    }
    
    /// Detect the character set used in the string
    fn detect_character_set(&self, s: &str) -> Option<String> {
        let chars: Vec<char> = s.chars().collect();
        
        for analyzer in &self.charset_analyzers {
            let matching_chars = chars
                .iter()
                .filter(|&&ch| analyzer.charset.contains(&ch))
                .count();
            
            let match_percentage = matching_chars as f64 / chars.len() as f64;
            
            if match_percentage >= analyzer.min_match_percentage {
                return Some(analyzer.name.clone());
            }
        }
        
        None
    }
    
    /// Convert entropy score to confidence level
    fn entropy_to_confidence(&self, entropy: f64) -> f64 {
        // Map entropy to confidence (0.0-1.0)
        let normalized = (entropy - self.entropy_threshold) / (6.0 - self.entropy_threshold);
        normalized.max(0.0).min(1.0)
    }
    
    /// Adjust confidence based on character distribution
    fn adjust_confidence_for_distribution(&self, mut confidence: f64, distribution: &CharDistribution) -> f64 {
        // Reduce confidence for very uneven distributions
        if distribution.most_common_frequency > 0.5 {
            confidence *= 0.7;
        }
        
        // Reduce confidence for high repetition
        if distribution.repetition_score > 0.3 {
            confidence *= 0.5;
        }
        
        // Boost confidence for good character variety
        if distribution.unique_chars as f64 / (distribution.uppercase_ratio + distribution.lowercase_ratio + distribution.digit_ratio + distribution.special_ratio) > 0.7 {
            confidence *= 1.2;
        }
        
        confidence.max(0.0).min(1.0)
    }
    
    /// Infer potential credential type based on characteristics
    fn infer_credential_type(
        &self,
        value: &str,
        distribution: &CharDistribution,
        charset: &Option<String>,
    ) -> Option<String> {
        // Base64-encoded data
        if charset.as_ref().map_or(false, |cs| cs == "base64") && value.len() % 4 == 0 {
            return Some("base64_encoded".to_string());
        }
        
        // Hexadecimal data
        if charset.as_ref().map_or(false, |cs| cs == "hex") {
            match value.len() {
                32 => return Some("md5_hash".to_string()),
                40 => return Some("sha1_hash".to_string()),
                64 => return Some("sha256_hash".to_string()),
                _ => return Some("hex_encoded".to_string()),
            }
        }
        
        // JWT-like structure
        if value.contains('.') && value.split('.').count() == 3 {
            return Some("jwt_token".to_string());
        }
        
        // High entropy alphanumeric (likely API key)
        if charset.as_ref().map_or(false, |cs| cs == "alphanumeric") && value.len() >= 20 {
            return Some("api_key".to_string());
        }
        
        // Mixed case with good distribution (likely password)
        if distribution.uppercase_ratio > 0.1 
            && distribution.lowercase_ratio > 0.1 
            && distribution.digit_ratio > 0.1 
            && value.len() >= 8 
        {
            return Some("password".to_string());
        }
        
        Some("high_entropy_string".to_string())
    }
    
    /// Remove duplicate and overlapping candidates
    fn deduplicate_candidates(&self, mut candidates: Vec<CandidateString>) -> Vec<CandidateString> {
        candidates.sort_by(|a, b| a.start.cmp(&b.start));
        
        let mut deduplicated = Vec::new();
        let mut last_end = 0;
        
        for candidate in candidates {
            if candidate.start >= last_end {
                last_end = candidate.end;
                deduplicated.push(candidate);
            }
        }
        
        deduplicated
    }
    
    /// Mask string for safe logging
    fn mask_string(&self, s: &str) -> String {
        if s.len() <= 8 {
            "*".repeat(s.len())
        } else {
            format!("{}***{}", &s[..2], &s[s.len()-2..])
        }
    }
}

/// Candidate string for entropy analysis
#[derive(Debug, Clone)]
struct CandidateString {
    value: String,
    start: usize,
    end: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_entropy_analyzer_creation() {
        let analyzer = EntropyAnalyzer::new(4.0, 8, 512);
        assert_eq!(analyzer.entropy_threshold, 4.0);
        assert_eq!(analyzer.min_length, 8);
        assert_eq!(analyzer.max_length, 512);
        
        // Test SIMD configuration
        let simd_analyzer = EntropyAnalyzer::with_simd(4.0, 8, 512, true);
        assert_eq!(simd_analyzer.entropy_threshold, 4.0);
        
        let no_simd_analyzer = EntropyAnalyzer::with_simd(4.0, 8, 512, false);
        assert!(!no_simd_analyzer.simd_enabled);
    }
    
    #[test]
    fn test_shannon_entropy_calculation() {
        let analyzer = EntropyAnalyzer::new(4.0, 8, 512);
        
        // Low entropy (repeated characters)
        let low_entropy = analyzer.calculate_shannon_entropy("aaaaaaaa");
        assert!(low_entropy < 1.0);
        
        // High entropy (random-looking string)
        let high_entropy = analyzer.calculate_shannon_entropy("aB3xK9mP2qL7vN");
        assert!(high_entropy > 3.0);
        
        // Maximum entropy for binary
        let max_entropy = analyzer.calculate_shannon_entropy("01010101");
        assert!(max_entropy > 0.9 && max_entropy < 1.1);
        
        // Test SIMD vs scalar consistency for long strings
        let long_string = "This_is_a_long_test_string_with_sufficient_entropy_to_trigger_SIMD_optimizations_1234567890_abcdefghijklmnopqrstuvwxyz";
        let simd_analyzer = EntropyAnalyzer::with_simd(4.0, 8, 512, true);
        let scalar_analyzer = EntropyAnalyzer::with_simd(4.0, 8, 512, false);
        
        let simd_entropy = simd_analyzer.calculate_shannon_entropy(long_string);
        let scalar_entropy = scalar_analyzer.calculate_shannon_entropy(long_string);
        
        // Results should be very close (within floating point precision)
        let diff = (simd_entropy - scalar_entropy).abs();
        assert!(diff < 0.01, "SIMD and scalar entropy should match: SIMD={:.6}, Scalar={:.6}, Diff={:.6}", 
                simd_entropy, scalar_entropy, diff);
    }
    
    #[tokio::test]
    async fn test_high_entropy_detection() {
        let analyzer = EntropyAnalyzer::new(3.5, 8, 512);
        
        let test_text = r#"
            username = "admin"
            password = "X7mK9qP3nL2vB8aF"
            api_key = "sk_test_PLACEHOLDER_MASKED_EXAMPLE"
            normal_word = "configuration"
        "#;
        
        let results = analyzer.analyze_text(test_text).await;
        
        // Should detect the password and API key
        assert!(!results.is_empty());
        
        let high_entropy_values: Vec<&str> = results
            .iter()
            .map(|r| r.value.as_str())
            .collect();
        
        assert!(high_entropy_values.contains(&"X7mK9qP3nL2vB8aF"));
        assert!(high_entropy_values.contains(&"sk_test_PLACEHOLDER_MASKED_EXAMPLE"));
        
        // Should not detect common words
        assert!(!high_entropy_values.contains(&"admin"));
        assert!(!high_entropy_values.contains(&"configuration"));
    }
    
    #[test]
    fn test_character_distribution_analysis() {
        let analyzer = EntropyAnalyzer::new(4.0, 8, 512);
        
        let mixed_case = analyzer.analyze_character_distribution("AbC123!@#");
        assert!(mixed_case.uppercase_ratio > 0.0);
        assert!(mixed_case.lowercase_ratio > 0.0);
        assert!(mixed_case.digit_ratio > 0.0);
        assert!(mixed_case.special_ratio > 0.0);
        
        let all_lowercase = analyzer.analyze_character_distribution("abcdefgh");
        assert_eq!(all_lowercase.uppercase_ratio, 0.0);
        assert_eq!(all_lowercase.lowercase_ratio, 1.0);
    }
    
    #[test]
    fn test_character_set_detection() {
        let analyzer = EntropyAnalyzer::new(4.0, 8, 512);
        
        // Base64 detection
        let base64_charset = analyzer.detect_character_set("SGVsbG9Xb3JsZA==");
        assert_eq!(base64_charset, Some("base64".to_string()));
        
        // Hex detection
        let hex_charset = analyzer.detect_character_set("deadbeef1234567890abcdef");
        assert_eq!(hex_charset, Some("hex".to_string()));
        
        // No specific charset
        let no_charset = analyzer.detect_character_set("Hello World!");
        assert!(no_charset.is_none() || no_charset == Some("alphanumeric".to_string()));
    }
    
    #[test]
    fn test_credential_type_inference() {
        let analyzer = EntropyAnalyzer::new(4.0, 8, 512);
        
        // JWT token structure
        let jwt_type = analyzer.infer_credential_type(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            &CharDistribution {
                uppercase_ratio: 0.1,
                lowercase_ratio: 0.7,
                digit_ratio: 0.2,
                special_ratio: 0.0,
                most_common_char: 'e',
                most_common_frequency: 0.1,
                unique_chars: 20,
                repetition_score: 0.0,
            },
            &Some("base64url".to_string())
        );
        assert_eq!(jwt_type, Some("jwt_token".to_string()));
        
        // SHA256 hash
        let sha256_type = analyzer.infer_credential_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &CharDistribution {
                uppercase_ratio: 0.0,
                lowercase_ratio: 0.6,
                digit_ratio: 0.4,
                special_ratio: 0.0,
                most_common_char: 'e',
                most_common_frequency: 0.1,
                unique_chars: 16,
                repetition_score: 0.0,
            },
            &Some("hex".to_string())
        );
        assert_eq!(sha256_type, Some("sha256_hash".to_string()));
    }
    
    #[test]
    fn test_repetition_score_calculation() {
        let analyzer = EntropyAnalyzer::new(4.0, 8, 512);
        
        // High repetition
        let high_rep_chars: Vec<char> = "aaabbbccc".chars().collect();
        let high_rep_score = analyzer.calculate_repetition_score(&high_rep_chars);
        assert!(high_rep_score > 0.3);
        
        // Low repetition
        let low_rep_chars: Vec<char> = "abcdefghi".chars().collect();
        let low_rep_score = analyzer.calculate_repetition_score(&low_rep_chars);
        assert!(low_rep_score < 0.1);
    }
    
    #[tokio::test]
    async fn test_simd_performance_and_accuracy() {
        let simd_analyzer = EntropyAnalyzer::with_simd(3.5, 8, 512, true);
        let scalar_analyzer = EntropyAnalyzer::with_simd(3.5, 8, 512, false);
        
        // Large test data that should trigger SIMD optimizations
        let large_test_data = format!("{}\n{}\n{}\n{}", 
            "api_key=sk_demo_XXXXXXXXXXXXXXXXXXXXXXXX_this_is_a_very_long_api_key_with_high_entropy",
            "password=P@ssw0rd123_with_mixed_case_and_numbers_and_symbols!@#$%",
            "aws_access_key=AKIAIOSFODNN7EXAMPLE_this_is_an_aws_access_key_pattern",
            "normal_text=this_is_just_normal_configuration_text_without_secrets"
        );
        
        let simd_results = simd_analyzer.analyze_text(&large_test_data).await;
        let scalar_results = scalar_analyzer.analyze_text(&large_test_data).await;
        
        // Both should find the same number of high-entropy strings
        assert_eq!(simd_results.len(), scalar_results.len(), 
                   "SIMD and scalar should find same number of results");
        
        // Compare individual results
        for (simd_result, scalar_result) in simd_results.iter().zip(scalar_results.iter()) {
            assert_eq!(simd_result.value, scalar_result.value, 
                       "SIMD and scalar should find same strings");
            
            let entropy_diff = (simd_result.entropy - scalar_result.entropy).abs();
            assert!(entropy_diff < 0.01, 
                    "SIMD and scalar entropy should match for '{}': SIMD={:.6}, Scalar={:.6}", 
                    simd_result.value, simd_result.entropy, scalar_result.entropy);
        }
        
        // Both should detect high-entropy credentials
        assert!(!simd_results.is_empty(), "Should detect high-entropy strings");
        
        let high_entropy_values: Vec<&str> = simd_results
            .iter()
            .map(|r| r.value.as_str())
            .collect();
            
        // Should find the API key and password
        assert!(high_entropy_values.iter().any(|&v| v.contains("sk_demo_")), 
                "Should detect API key");
        assert!(high_entropy_values.iter().any(|&v| v.contains("P@ssw0rd123")), 
                "Should detect password");
    }
    
    #[test]
    fn test_simd_availability() {
        let has_simd = EntropyAnalyzer::simd_available();
        
        #[cfg(target_arch = "x86_64")]
        {
            // On x86_64, we should detect if SIMD is available
            println!("SIMD available: {}", has_simd);
            
            // Test that analyzer respects SIMD settings
            let forced_simd = EntropyAnalyzer::with_simd(4.0, 8, 512, true);
            let forced_no_simd = EntropyAnalyzer::with_simd(4.0, 8, 512, false);
            
            assert_eq!(forced_simd.simd_enabled, has_simd, "Should enable SIMD only when available");
            assert!(!forced_no_simd.simd_enabled, "Should disable SIMD when forced off");
        }
        
        #[cfg(not(target_arch = "x86_64"))]
        {
            // On non-x86_64, SIMD should not be available
            assert!(!has_simd, "SIMD should not be available on non-x86_64");
        }
    }
}