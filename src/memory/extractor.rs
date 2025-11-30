//! Credential extraction helpers that convert analyzer buffers into
//! structured detection records using the detection engine.

use super::{regions::MemoryRegion, MemoryConfig};
use crate::detection::engine::CredentialLocation;
use crate::detection::{DetectionEngine, DetectionResult};
use anyhow::{Context, Result};

/// Stateful wrapper around the detection engine for memory slices.
pub struct CredentialExtractor;

/// Placeholder for future extraction techniques (string/binary heuristics).
#[allow(dead_code)]
pub struct ExtractionMethod;

/// Placeholder for pattern metadata used by tuned extractors.
#[allow(dead_code)]
pub struct MemoryPattern;

/// Normalized detection plus the offset where it triggered.
pub struct ExtractionResult {
    /// Detection record produced by the engine.
    pub detection: DetectionResult,
    /// Byte offset within the scanned buffer.
    pub offset: usize,
}

impl CredentialExtractor {
    /// Build a new extractor; configuration stays reserved for tuned rules.
    pub async fn new(_config: &MemoryConfig) -> Result<Self> {
        Ok(Self)
    }

    /// Run the detection engine over a memory slice and capture offsets.
    pub async fn extract_credentials(
        &self,
        data: &[u8],
        region: &MemoryRegion,
        detection_engine: &DetectionEngine,
    ) -> Result<Vec<ExtractionResult>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let location = CredentialLocation {
            source_type: "memory".to_string(),
            path: format!("region:{:016x}", region.start_address),
            line_number: None,
            column: None,
            memory_address: None,
            process_id: None,
            container_id: None,
        };

        let mut detections = detection_engine
            .detect_in_binary(data, location)
            .await
            .context("binary credential detection failed")?;

        let mut results = Vec::with_capacity(detections.len());
        for mut detection in detections.drain(..) {
            let offset = detection
                .location
                .memory_address
                .unwrap_or_default()
                .clamp(0, data.len() as u64) as usize;

            // Reset memory_address so the outer caller can rebase it to the absolute region address.
            detection.location.memory_address = None;

            results.push(ExtractionResult { detection, offset });
        }

        Ok(results)
    }
}
