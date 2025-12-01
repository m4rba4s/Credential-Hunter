use crate::core::config::{OutputConfig, OutputFormat};
use crate::core::engine::{EngineResult, OperationSummary};
use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{info, warn};

/// Render and persist engine results according to the configured output format.
pub fn write_output(result: &EngineResult, output: &OutputConfig) -> Result<()> {
    let sanitized = sanitize_result(result, output);
    let serialized = serialize(&sanitized, output)?;

    if output.console_output {
        println!("{serialized}");
    }

    if let Some(path) = &output.file_path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create output directory {}", parent.display())
            })?;
        }

        std::fs::write(path, serialized.as_bytes())
            .with_context(|| format!("Failed to write output file {}", path.display()))?;
        info!("Wrote scan results to {}", path.display());
    }

    Ok(())
}

fn sanitize_result(result: &EngineResult, output: &OutputConfig) -> EngineResult {
    let mut sanitized = result.clone();
    sanitized.detections = result
        .detections
        .iter()
        .map(|detection| sanitize_detection(detection, output))
        .collect();
    sanitized
}

fn sanitize_detection(
    detection: &crate::detection::DetectionResult,
    output: &OutputConfig,
) -> crate::detection::DetectionResult {
    let mut sanitized = detection.clone();
    if !output.include_full_values {
        sanitized.full_value = None;
    }

    if output.mask_character != '*' {
        sanitized.masked_value = remask(&sanitized.masked_value, output.mask_character);
    }

    sanitized
}

fn remask(masked_value: &str, mask_character: char) -> String {
    masked_value
        .chars()
        .map(|ch| if ch == '*' { mask_character } else { ch })
        .collect()
}

fn serialize(result: &EngineResult, output: &OutputConfig) -> Result<String> {
    match output.format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(result).context("Failed to serialize results as JSON")
        }
        OutputFormat::Ndjson => serialize_ndjson(result),
        OutputFormat::Yaml => {
            serde_yaml::to_string(result).context("Failed to serialize results as YAML")
        }
        OutputFormat::Text => Ok(format!("{:#?}", result)),
        _ => {
            warn!(
                "Output format {:?} not fully supported, falling back to JSON",
                output.format
            );
            serde_json::to_string_pretty(result)
                .context("Failed to serialize results while falling back to JSON")
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum NdjsonRecord<'a> {
    Detection {
        detection: &'a crate::detection::DetectionResult,
    },
    Summary {
        summary: &'a OperationSummary,
    },
}

fn serialize_ndjson(result: &EngineResult) -> Result<String> {
    let mut lines = Vec::new();
    for detection in &result.detections {
        let line = serde_json::to_string(&NdjsonRecord::Detection { detection })
            .context("Failed to serialize detection as NDJSON")?;
        lines.push(line);
    }

    let summary = serde_json::to_string(&NdjsonRecord::Summary {
        summary: &result.summary,
    })
    .context("Failed to serialize summary as NDJSON")?;
    lines.push(summary);

    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::engine::{
        ConfidenceLevel, CredentialContext, CredentialLocation, CredentialType, DetectionMetadata,
        DetectionResult, RiskLevel,
    };
    use chrono::Utc;
    use serde_json::Value;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn sample_detection() -> DetectionResult {
        DetectionResult {
            id: Uuid::nil(),
            credential_type: CredentialType::Password,
            confidence: ConfidenceLevel::High,
            masked_value: "pa***rd".to_string(),
            full_value: Some("password".to_string()),
            location: CredentialLocation {
                source_type: "file".to_string(),
                path: "/tmp/.env".to_string(),
                line_number: Some(1),
                column: Some(1),
                memory_address: None,
                process_id: None,
                container_id: None,
            },
            context: CredentialContext {
                surrounding_text: "PASSWORD=password".to_string(),
                variable_name: Some("PASSWORD".to_string()),
                file_type: Some("env".to_string()),
                language: Some("ini".to_string()),
                context_clues: vec![],
            },
            metadata: DetectionMetadata {
                detection_methods: vec!["test".to_string()],
                pattern_name: Some("password".to_string()),
                entropy_score: Some(4.8),
                ml_confidence: None,
                yara_matches: vec![],
                processing_time_us: 10,
            },
            risk_level: RiskLevel::High,
            recommended_actions: vec!["rotate".to_string()],
            timestamp: Utc::now(),
        }
    }

    fn sample_result() -> EngineResult {
        EngineResult {
            operation_id: Uuid::nil(),
            detections: vec![sample_detection()],
            summary: crate::core::engine::OperationSummary {
                targets_scanned: 1,
                credentials_found: 1,
                high_risk_credentials: 1,
                processing_time_ms: 10,
                bytes_processed: 128,
                errors_encountered: 0,
            },
            recommendations: vec![],
            compliance_report: None,
        }
    }

    #[test]
    fn writes_json_and_redacts_full_values() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("result.json");

        let mut output_config = OutputConfig::default();
        output_config.file_path = Some(output_path.clone());
        output_config.console_output = false;
        output_config.include_full_values = false;
        output_config.mask_character = '#';

        write_output(&sample_result(), &output_config).expect("output writer should succeed");

        let content =
            std::fs::read_to_string(output_path).expect("result file should have been written");
        let value: Value = serde_json::from_str(&content).expect("valid json output");

        let masked = value["detections"][0]["masked_value"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(masked, "pa###rd");
        assert!(value["detections"][0]["full_value"].is_null());
        assert_eq!(value["summary"]["credentials_found"].as_u64(), Some(1));
    }

    #[test]
    fn writes_ndjson_records() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("result.ndjson");

        let mut output_config = OutputConfig::default();
        output_config.file_path = Some(output_path.clone());
        output_config.console_output = false;
        output_config.format = OutputFormat::Ndjson;
        output_config.include_full_values = false;

        write_output(&sample_result(), &output_config).expect("ndjson output should succeed");

        let content =
            std::fs::read_to_string(output_path).expect("ndjson file should have been written");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "one detection + one summary");

        let first: Value = serde_json::from_str(lines[0]).expect("valid detection ndjson");
        assert_eq!(first["type"].as_str(), Some("detection"));

        let summary: Value = serde_json::from_str(lines[1]).expect("valid summary ndjson");
        assert_eq!(summary["type"].as_str(), Some("summary"));
        assert_eq!(summary["summary"]["credentials_found"].as_u64(), Some(1));
    }
}
