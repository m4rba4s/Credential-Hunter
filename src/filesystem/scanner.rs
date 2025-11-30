use super::FilesystemConfig;
use crate::detection::engine::CredentialLocation;
use crate::detection::{DetectionEngine, DetectionResult};
/**
 * ECH Filesystem Scanner Module
 */
use anyhow::{Context, Result};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

/// Streaming file scanner that hands data to the detection engine.
pub struct FileScanner;
/// Placeholder for future file-content abstractions.
#[allow(dead_code)]
pub struct FileContent;

/// Tuning knobs for file scanning operations.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ScanOptions {
    /// Whether to prefer memory-mapped I/O.
    pub use_memory_mapping: bool,
    /// Chunk size for buffered reads (bytes).
    pub buffer_size: usize,
    /// Per-file timeout for scanning.
    pub timeout: Duration,
}

/// Result of scanning a single file.
#[derive(Debug)]
pub struct FileScanResult {
    /// Detections produced while scanning the file.
    pub detections: Vec<DetectionResult>,
    /// Number of bytes processed.
    pub bytes_processed: u64,
}

impl FileScanner {
    /// Construct a file scanner; options are supplied per invocation.
    pub async fn new(_config: &FilesystemConfig) -> Result<Self> {
        Ok(Self)
    }

    /// Scan a file path using the provided detection engine.
    pub async fn scan_file(
        &self,
        path: &Path,
        detection_engine: &DetectionEngine,
        _options: ScanOptions,
    ) -> Result<FileScanResult> {
        let metadata =
            fs::metadata(path).with_context(|| format!("stat failed: {}", path.display()))?;
        let bytes_processed = metadata.len();

        // Try to read as UTF-8 text first
        let mut file =
            fs::File::open(path).with_context(|| format!("open failed: {}", path.display()))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .with_context(|| format!("read failed: {}", path.display()))?;

        let location = CredentialLocation {
            source_type: "file".to_string(),
            path: path.display().to_string(),
            line_number: None,
            column: None,
            memory_address: None,
            process_id: None,
            container_id: None,
        };

        let detections: Vec<DetectionResult> = match std::str::from_utf8(&buffer) {
            Ok(text) => detection_engine
                .detect_in_text(text, location)
                .await
                .with_context(|| format!("text detection failed: {}", path.display()))?,
            Err(_) => detection_engine
                .detect_in_binary(&buffer, location)
                .await
                .with_context(|| format!("binary detection failed: {}", path.display()))?,
        };

        Ok(FileScanResult {
            detections,
            bytes_processed,
        })
    }
}
