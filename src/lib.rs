//! ECH Library - Enterprise Credential Hunter Library
//!
//! This is the main library entry point for the Enterprise Credential Hunter (ECH).
//! Provides all core functionality as a library that can be embedded in other applications
//! or used through the CLI interface.
//!
//! Features:
//! - Core credential detection engine
//! - Memory scanning capabilities
//! - Filesystem credential hunting
//! - SIEM integration
//! - Stealth and evasion techniques
//! - Cross-platform support

#![warn(missing_docs, rust_2018_idioms)]
#![allow(dead_code)]
//#![deny(unsafe_code)]

// Core modules
/// Container scanning subsystem (Docker, Podman, Kubernetes attachments).
pub mod container;

/// Core orchestration engine, configuration, and shared infrastructure.
pub mod core;

/// Credential detection engines (patterns, ML, entropy, context).
pub mod detection;

/// Filesystem hunters, filters, metadata collectors, and watchers.
pub mod filesystem;

/// Memory scanners, analyzers, region extractors, and supporting logic.
pub mod memory;

/// Remediation workflows (masking, quarantine, wiping, backups).
pub mod remediation;

#[cfg(feature = "siem-integration")]
/// SIEM integrations and transport adapters.
pub mod siem;

/// Stealth, anti-detection, and evasion orchestration.
pub mod stealth;

// Re-export commonly used types
pub use core::config::{EchConfig, LogLevel, OutputFormat};
pub use core::engine::EchEngine;
pub use core::platform::Platform;
pub use core::security::SecurityContext;
pub use detection::engine::{CredentialType, DetectionEngine, DetectionResult};
pub use filesystem::hunter::{FilesystemHunter, HunterConfig};
pub use filesystem::ScanTarget;
pub use memory::process::ProcessManager;
pub use memory::scanner::MemoryScanner;
pub use memory::MemoryConfig;
#[cfg(feature = "siem-integration")]
pub use siem::{SiemConfig, SiemIntegration, SiemPlatform};
pub use stealth::engine::{StealthConfig, StealthEngine, StealthLevel};

/// ECH library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ECH library initialization
pub async fn initialize() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(true)
        .event_format(core::logging::FancyLogFormatter::default())
        .init();

    if std::env::var("ECH_SILENT_BANNER").is_err() {
        core::logging::emit_banner();
    }

    // Initialize subsystems
    memory::initialize_memory_subsystem().await?;
    filesystem::initialize_filesystem_subsystem().await?;
    #[cfg(feature = "siem-integration")]
    {
        siem::initialize_siem_subsystem().await?;
    }
    stealth::initialize_stealth_subsystem().await?;

    tracing::info!("ECH Library v{} initialized", VERSION);

    Ok(())
}

/// ECH library result type
pub type Result<T> = anyhow::Result<T>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_library_initialization() {
        let result = initialize().await;
        // Should not fail on basic initialization
        assert!(result.is_ok());
    }

    #[test]
    fn test_version() {
        assert!(VERSION.contains('.'));
    }

    #[test]
    fn test_exports() {
        // Test that main exports are available
        let _config = EchConfig::default();
        let _memory_config = MemoryConfig::default();
        let _stealth_level = StealthLevel::Medium;
    }
}
