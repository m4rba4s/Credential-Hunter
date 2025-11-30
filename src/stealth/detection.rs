//! Detection-awareness helpers that catalogue security products and recommend
//! evasions based on the configured stealth posture.
use super::engine::{EvasionDifficulty, ThreatSeverity};
use super::StealthSystemConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

/// Tracks anti-detection triggers that were observed on the host.
#[derive(Debug, Clone, Default)]
pub struct AntiDetection {
    /// Names of products or hooks that reacted to our activity.
    pub detected_components: Vec<String>,
    /// Last time a trigger was observed.
    pub last_detection: Option<DateTime<Utc>>,
}

impl AntiDetection {
    fn record_detection(&mut self, name: impl Into<String>) {
        let value = name.into();
        if !self.detected_components.contains(&value) {
            self.detected_components.push(value);
        }
        self.last_detection = Some(Utc::now());
    }
}

/// Accumulates recommended evasion actions.
#[derive(Debug, Clone, Default)]
pub struct DetectionEvasion {
    /// Human-readable actions to execute.
    pub recommended_actions: Vec<String>,
    /// Timestamp of the last recommendation.
    pub last_updated: Option<DateTime<Utc>>,
}

impl DetectionEvasion {
    fn recommend_action(&mut self, action: impl Into<String>) {
        self.recommended_actions.push(action.into());
        self.last_updated = Some(Utc::now());
    }
}

/// High-level detection orchestrator.
pub struct ThreatDetection {
    config: StealthSystemConfig,
    anti_detection: RwLock<AntiDetection>,
    detection_evasion: RwLock<DetectionEvasion>,
}

/// Metadata describing a defensive product we must evade.
#[derive(Debug, Clone)]
pub struct SecurityProduct {
    /// Canonical product or family name.
    pub name: String,
    /// Severity assigned to detections from this product.
    pub severity: ThreatSeverity,
    /// Difficulty of evading the product with our current capabilities.
    pub evasion_difficulty: EvasionDifficulty,
    /// Evasion playbooks recommended for this product.
    pub recommended_evasions: Vec<String>,
}

/// Host analysis tooling (debuggers, instrumentation, etc.).
#[derive(Debug, Clone)]
pub struct AnalysisTool {
    /// Tool name or identifier.
    pub name: String,
}

/// Continuous monitoring systems such as Sysmon or auditd.
#[derive(Debug, Clone)]
pub struct MonitoringSystem {
    /// Monitoring solution name.
    pub name: String,
}

impl ThreatDetection {
    /// Build a detection-orchestration helper using the supplied config baseline.
    pub async fn new(config: &StealthSystemConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            anti_detection: RwLock::new(AntiDetection::default()),
            detection_evasion: RwLock::new(DetectionEvasion::default()),
        })
    }

    /// Identify security products based on enabled stealth knobs and update telemetry.
    pub async fn detect_security_products(&self) -> Result<Vec<SecurityProduct>> {
        let mut products = Vec::new();

        if self.config.edr_evasion_enabled {
            products.push(SecurityProduct {
                name: "falcon_edr".to_string(),
                severity: ThreatSeverity::High,
                evasion_difficulty: EvasionDifficulty::High,
                recommended_evasions: vec![
                    "kernel_callback_scrubbing".to_string(),
                    "syscall_stubbing".to_string(),
                ],
            });
        }

        if self.config.av_evasion_enabled {
            products.push(SecurityProduct {
                name: "sentinel_av".to_string(),
                severity: ThreatSeverity::Medium,
                evasion_difficulty: EvasionDifficulty::Medium,
                recommended_evasions: vec!["reflective_loader".to_string()],
            });
        }

        if products.is_empty() {
            products.push(SecurityProduct {
                name: "baseline_guard".to_string(),
                severity: ThreatSeverity::Low,
                evasion_difficulty: EvasionDifficulty::Low,
                recommended_evasions: vec!["noop".to_string()],
            });
        }

        {
            let mut anti = self.anti_detection.write().await;
            for product in &products {
                anti.record_detection(&product.name);
            }
        }

        {
            let mut evasion = self.detection_evasion.write().await;
            for product in &products {
                for evasion_step in &product.recommended_evasions {
                    evasion.recommend_action(evasion_step.clone());
                }
            }
        }

        Ok(products)
    }

    /// Identify active analysis frameworks (debuggers, instrumentation) and log recommendations.
    pub async fn detect_analysis_tools(&self) -> Result<Vec<AnalysisTool>> {
        let tools = if self.config.anti_debugging_enabled {
            vec![AnalysisTool {
                name: "frida".to_string(),
            }]
        } else {
            Vec::new()
        };

        if !tools.is_empty() {
            let mut anti = self.anti_detection.write().await;
            for tool in &tools {
                anti.record_detection(&tool.name);
            }

            let mut evasion = self.detection_evasion.write().await;
            evasion.recommend_action("enable_anti_debug_hooks".to_string());
        }

        Ok(tools)
    }

    /// Identify monitoring/telemetry systems that require cleanup evasion.
    pub async fn detect_monitoring_systems(&self) -> Result<Vec<MonitoringSystem>> {
        let systems = if self.config.artifact_cleanup_enabled {
            vec![MonitoringSystem {
                name: "sysmon".to_string(),
            }]
        } else {
            Vec::new()
        };

        if !systems.is_empty() {
            let mut anti = self.anti_detection.write().await;
            for system in &systems {
                anti.record_detection(&system.name);
            }

            let mut evasion = self.detection_evasion.write().await;
            evasion.recommend_action("logtamper".to_string());
        }

        Ok(systems)
    }

    /// Snapshot telemetry for reporting or debugging.
    pub async fn telemetry(&self) -> (AntiDetection, DetectionEvasion) {
        (
            self.anti_detection.read().await.clone(),
            self.detection_evasion.read().await.clone(),
        )
    }
}
