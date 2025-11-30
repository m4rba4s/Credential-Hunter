//! Remediation helpers that quarantine, mask, or wipe secrets after detection.

use crate::core::config::{RemediationAction, RemediationConfig};
use crate::detection::DetectionResult;
use anyhow::{Context, Result};
use rand::Rng;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Remediation engine that applies configured actions to detections.
pub struct RemediationEngine {
    config: RemediationConfig,
    /// Prevents concurrent writes to the same remediation directories.
    io_guard: Mutex<()>,
}

impl RemediationEngine {
    /// Initialize the remediation engine and ensure state directories exist.
    pub async fn new(config: RemediationConfig) -> Result<Self> {
        if config.create_backups {
            fs::create_dir_all(&config.backup_directory)
                .await
                .with_context(|| {
                    format!(
                        "failed to create backup directory {}",
                        config.backup_directory.display()
                    )
                })?;
        }

        if config.auto_remediate {
            fs::create_dir_all(&config.quarantine_directory)
                .await
                .with_context(|| {
                    format!(
                        "failed to create quarantine directory {}",
                        config.quarantine_directory.display()
                    )
                })?;
        }

        Ok(Self {
            config,
            io_guard: Mutex::new(()),
        })
    }

    /// Apply the configured remediation workflow to every detection.
    pub async fn process_detections(
        &self,
        detections: Vec<DetectionResult>,
    ) -> Result<Vec<DetectionResult>> {
        if detections.is_empty() {
            return Ok(detections);
        }

        if !self.config.auto_remediate {
            warn!(
                "Remediation requested but auto_remediate=false. Returning detections unchanged."
            );
            return Ok(detections);
        }

        let mut remediated = Vec::with_capacity(detections.len());
        for mut detection in detections {
            if let Err(err) = self.remediate_detection(&mut detection).await {
                warn!(
                    "Remediation failed for {}: {}",
                    detection.location.path, err
                );
            }
            remediated.push(detection);
        }

        Ok(remediated)
    }

    async fn remediate_detection(&self, detection: &mut DetectionResult) -> Result<()> {
        match self.config.default_action {
            RemediationAction::Report => {
                info!("Remediation (report): {}", detection.location.path);
            }
            RemediationAction::Mask => {
                self.mask_detection(detection);
            }
            RemediationAction::Quarantine => {
                self.quarantine_target(&detection.location.path).await?;
                self.mask_detection(detection);
            }
            RemediationAction::Wipe => {
                self.wipe_target(&detection.location.path).await?;
                self.mask_detection(detection);
            }
            RemediationAction::Rotate => {
                info!(
                    "Rotation requested for credential type {:?}; manual follow-up required",
                    detection.credential_type
                );
                self.mask_detection(detection);
            }
        }

        Ok(())
    }

    fn mask_detection(&self, detection: &mut DetectionResult) {
        if detection.full_value.is_some() {
            detection.full_value = None;
        }

        let masked = mask_secret(&detection.masked_value);
        detection.masked_value = masked;
    }

    async fn quarantine_target(&self, path: &str) -> Result<()> {
        let file_path = Path::new(path);
        if !file_path.is_file() {
            debug!("quarantine skipped; not a file: {}", path);
            return Ok(());
        }

        let _guard = self.io_guard.lock().await;

        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("quarantined");
        let sanitized = file_name.replace('/', "_");
        let dest = self.config.quarantine_directory.join(format!(
            "{}_{}",
            chrono::Utc::now().timestamp_millis(),
            sanitized
        ));

        fs::create_dir_all(&self.config.quarantine_directory)
            .await
            .ok();

        if self.config.create_backups {
            self.backup_file(file_path).await.ok();
        }

        fs::copy(file_path, &dest)
            .await
            .with_context(|| format!("failed to copy {} to quarantine", path))?;
        info!("Quarantined {} -> {}", file_path.display(), dest.display());

        Ok(())
    }

    async fn wipe_target(&self, path: &str) -> Result<()> {
        let file_path = Path::new(path);
        if !file_path.is_file() {
            debug!("wipe skipped; not a file: {}", path);
            return Ok(());
        }

        let _guard = self.io_guard.lock().await;

        if self.config.create_backups {
            self.backup_file(file_path).await.ok();
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(file_path)
            .await
            .with_context(|| format!("failed to open {} for wiping", path))?;

        let metadata = file.metadata().await?;
        let mut buffer = vec![0u8; metadata.len() as usize];

        for pass in 0..self.config.wipe_passes.max(1) {
            file.rewind().await?;
            fill_pattern(&mut buffer, pass);
            file.write_all(&buffer).await?;
            file.flush().await?;
        }

        info!("Securely wiped {}", file_path.display());
        Ok(())
    }

    async fn backup_file(&self, path: &Path) -> Result<PathBuf> {
        if !path.is_file() {
            return Ok(path.to_path_buf());
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("backup");
        let sanitized = file_name.replace('/', "_");
        fs::create_dir_all(&self.config.backup_directory).await?;
        let dest = self.config.backup_directory.join(format!(
            "{}_{}",
            chrono::Utc::now().timestamp_millis(),
            sanitized
        ));
        fs::copy(path, &dest).await?;
        Ok(dest)
    }
}

fn mask_secret(value: &str) -> String {
    if value.len() <= 8 {
        return "********".to_string();
    }

    let prefix = &value[..4];
    let suffix = &value[value.len() - 4..];
    format!("{}{}{}", prefix, "*".repeat(value.len() - 8), suffix)
}

fn fill_pattern(buffer: &mut [u8], pass: usize) {
    let byte = match pass % 3 {
        0 => 0x00,
        1 => 0xFF,
        _ => {
            let mut rng = rand::thread_rng();
            rng.gen::<u8>()
        }
    };
    buffer.fill(byte);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::engine::{CredentialLocation, DetectionMetadata};
    use crate::detection::engine::{CredentialType, RiskLevel};
    use tempfile::tempdir;

    fn sample_detection(path: &Path) -> DetectionResult {
        DetectionResult {
            id: uuid::Uuid::new_v4(),
            credential_type: CredentialType::Password,
            confidence: crate::detection::engine::ConfidenceLevel::High,
            masked_value: "SECRET_TEST_VALUE".into(),
            full_value: Some("SECRET_TEST_VALUE".into()),
            location: CredentialLocation {
                source_type: "file".into(),
                path: path.display().to_string(),
                line_number: None,
                column: None,
                memory_address: None,
                process_id: None,
                container_id: None,
            },
            context: crate::detection::engine::CredentialContext {
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
            risk_level: RiskLevel::High,
            recommended_actions: vec![],
            timestamp: chrono::Utc::now(),
        }
    }

    fn remediation_config(action: RemediationAction, dir: &Path) -> RemediationConfig {
        RemediationConfig {
            default_action: action,
            auto_remediate: true,
            create_backups: true,
            backup_directory: dir.join("backups"),
            enable_rotation: false,
            quarantine_directory: dir.join("quarantine"),
            wipe_passes: 1,
        }
    }

    #[tokio::test]
    async fn masks_detection_values() {
        let dir = tempdir().unwrap();
        let engine =
            RemediationEngine::new(remediation_config(RemediationAction::Mask, dir.path()))
                .await
                .unwrap();

        let file = dir.path().join("secret.txt");
        tokio::fs::write(&file, b"dummy").await.unwrap();
        let detection = sample_detection(&file);

        let results = engine
            .process_detections(vec![detection])
            .await
            .expect("remediation");

        assert!(results[0].full_value.is_none());
        assert!(results[0].masked_value.contains('*'));
    }

    #[tokio::test]
    async fn quarantines_file() {
        let dir = tempdir().unwrap();
        let engine = RemediationEngine::new(remediation_config(
            RemediationAction::Quarantine,
            dir.path(),
        ))
        .await
        .unwrap();

        let file = dir.path().join("secret.env");
        tokio::fs::write(&file, b"TOKEN=VALUE").await.unwrap();
        let detection = sample_detection(&file);

        engine
            .process_detections(vec![detection])
            .await
            .expect("remediation");

        let mut entries = tokio::fs::read_dir(dir.path().join("quarantine"))
            .await
            .unwrap();
        let mut found = false;
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            if entry.file_name().to_string_lossy().contains("secret.env") {
                found = true;
                break;
            }
        }
        assert!(found, "quarantined copy not found");
    }

    #[tokio::test]
    async fn wipes_file_contents() {
        let dir = tempdir().unwrap();
        let engine =
            RemediationEngine::new(remediation_config(RemediationAction::Wipe, dir.path()))
                .await
                .unwrap();

        let file = dir.path().join("wipe.txt");
        tokio::fs::write(&file, b"SENSITIVE_DATA").await.unwrap();
        let detection = sample_detection(&file);

        engine
            .process_detections(vec![detection])
            .await
            .expect("remediation");

        let wiped = tokio::fs::read(&file).await.unwrap();
        assert_ne!(wiped, b"SENSITIVE_DATA");
    }
}
