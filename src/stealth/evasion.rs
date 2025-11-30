//! Evasion helpers that simulate EDR/AV bypass operations for telemetry.
use super::engine::EvasionDifficulty;
use super::StealthSystemConfig;
use anyhow::Result;

/// High-level EDR evasion orchestrator.
pub struct EdrEvasion {
    config: StealthSystemConfig,
}

/// Anti-virus evasion helper mirroring the EDR façade.
pub struct AvEvasion {
    config: StealthSystemConfig,
}

/// Describes a single evasion technique and its relative payoff.
#[derive(Debug, Clone)]
pub struct EvasionTechnique {
    /// Identifier for the technique (e.g., `dll_unhook`).
    pub name: String,
    /// Normalized effectiveness score between 0-1.
    pub effectiveness: f32,
    /// Difficulty of deploying the technique across environments.
    pub difficulty: EvasionDifficulty,
}

/// Aggregated result from applying one or more evasion techniques.
#[derive(Debug, Clone)]
pub struct EvasionResult {
    /// Whether the evasion attempt succeeded.
    pub success: bool,
    /// Techniques that were attempted during the run.
    pub techniques_used: Vec<EvasionTechnique>,
}

impl EdrEvasion {
    /// Build a new EDR evasion helper based on the stealth config.
    pub async fn new(config: &StealthSystemConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Attempt to bypass a named EDR product and record techniques used.
    pub async fn evade_product(&self, product: &str) -> Result<EvasionResult> {
        let techniques = vec![EvasionTechnique {
            name: format!("{}_dll_unhook", product),
            effectiveness: 0.72,
            difficulty: EvasionDifficulty::High,
        }];

        Ok(EvasionResult {
            success: self.config.edr_evasion_enabled,
            techniques_used: techniques,
        })
    }

    /// Surface a more advanced technique for telemetry/testing purposes.
    pub async fn apply_advanced_evasion(&self) -> Result<EvasionTechnique> {
        Ok(EvasionTechnique {
            name: "edr_syscall_shim".to_string(),
            effectiveness: 0.81,
            difficulty: EvasionDifficulty::Extreme,
        })
    }
}

impl AvEvasion {
    /// Build a new AV evasion helper derived from the stealth config.
    pub async fn new(config: &StealthSystemConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Attempt to bypass a given AV engine and capture the steps taken.
    pub async fn evade_product(&self, product: &str) -> Result<EvasionResult> {
        let techniques = vec![EvasionTechnique {
            name: format!("{}_memory_padding", product),
            effectiveness: 0.64,
            difficulty: EvasionDifficulty::Medium,
        }];

        Ok(EvasionResult {
            success: self.config.av_evasion_enabled,
            techniques_used: techniques,
        })
    }

    /// Retrieve a heavier-weight evasion approach for testing.
    pub async fn apply_advanced_evasion(&self) -> Result<EvasionTechnique> {
        Ok(EvasionTechnique {
            name: "av_in_memory_unpack".to_string(),
            effectiveness: 0.69,
            difficulty: EvasionDifficulty::High,
        })
    }
}
