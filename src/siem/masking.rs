use super::MaskingConfig;
use crate::detection::DetectionResult;
/**
 * ECH SIEM Masking Module
 */
use anyhow::Result;

#[derive(Clone)]
pub struct DataMasker {
    config: MaskingConfig,
}

#[derive(Debug, Clone, Default)]
pub struct MaskingPolicy;
#[derive(Debug, Clone, Default)]
pub struct SensitiveDataType;

impl DataMasker {
    pub async fn new(config: &MaskingConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    pub async fn mask_detection(&self, detection: &DetectionResult) -> Result<DetectionResult> {
        if !self.config.mask_credentials && !self.config.mask_pii {
            return Ok(detection.clone());
        }

        let mut masked = detection.clone();
        masked.full_value = None;
        masked.masked_value = mask_value(&masked.masked_value, &self.config);
        Ok(masked)
    }
}

fn mask_value(value: &str, config: &MaskingConfig) -> String {
    if value.is_empty() {
        return value.to_string();
    }

    if !config.show_partial {
        return config
            .mask_character
            .to_string()
            .repeat(value.chars().count());
    }

    let visible = config.partial_length.min(value.len() / 2);
    if visible == 0 {
        return config
            .mask_character
            .to_string()
            .repeat(value.chars().count());
    }

    let prefix = &value[..visible];
    let suffix = &value[value.len().saturating_sub(visible)..];
    let mask_len = value.len().saturating_sub(visible * 2);
    format!(
        "{}{}{}",
        prefix,
        config.mask_character.to_string().repeat(mask_len.max(0)),
        suffix
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::engine::{CredentialContext, CredentialType};
    use crate::detection::engine::{CredentialLocation, DetectionMetadata};
    use uuid::Uuid;

    fn make_detection(value: &str) -> DetectionResult {
        DetectionResult {
            id: Uuid::new_v4(),
            credential_type: CredentialType::Password,
            confidence: crate::detection::engine::ConfidenceLevel::High,
            masked_value: value.to_string(),
            full_value: Some(value.to_string()),
            location: CredentialLocation {
                source_type: String::new(),
                path: String::new(),
                line_number: None,
                column: None,
                memory_address: None,
                process_id: None,
                container_id: None,
            },
            context: CredentialContext {
                surrounding_text: String::new(),
                variable_name: None,
                file_type: None,
                language: None,
                context_clues: Vec::new(),
            },
            metadata: DetectionMetadata {
                detection_methods: vec![],
                pattern_name: None,
                entropy_score: None,
                ml_confidence: None,
                yara_matches: vec![],
                processing_time_us: 0,
            },
            risk_level: crate::detection::engine::RiskLevel::Low,
            recommended_actions: vec![],
            timestamp: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn masks_values() {
        let config = MaskingConfig {
            mask_credentials: true,
            mask_pii: true,
            masking_policies: vec![],
            mask_character: '*',
            preserve_length: true,
            show_partial: true,
            partial_length: 2,
        };
        let masker = DataMasker::new(&config).await.unwrap();

        let detection = make_detection("ABCDEFGHIJKLMNOP");
        let masked = masker.mask_detection(&detection).await.unwrap();
        assert!(masked.full_value.is_none());
        assert!(masked.masked_value.starts_with("AB"));
        assert!(masked.masked_value.ends_with("OP"));
        assert!(masked.masked_value.contains("**"));
    }
}
