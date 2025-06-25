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
//#![deny(unsafe_code)]

// Core modules
pub mod error;
pub mod types;
pub mod core;
pub mod detection;
pub mod memory;
pub mod stealth;

// Re-export commonly used types
// ELITE CORE EXPORTS - NO BLOAT!
pub use core::{EchConfig, EchEngine, SecurityContext, Platform};
pub use detection::{DetectionEngine, DetectionResult, CredentialType};
pub use stealth::{StealthEngine, StealthConfig, StealthLevel};

pub mod prelude {
    pub use crate::error::{EchError, EchResult};
    pub use crate::types::*;
    pub use crate::core::*;
    pub use crate::detection::*;
    pub use crate::stealth::*;
}

/// ECH library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ECH library initialization
pub async fn initialize() -> anyhow::Result<()> {
    // Initialize logging if tracing_subscriber is available
    #[cfg(feature = "tracing-subscriber")]
    {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }
    
    // Initialize subsystems
    memory::initialize_memory_subsystem().await?;
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
        assert!(!VERSION.is_empty());
        assert!(VERSION.contains('.'));
    }
    
    #[test]
    fn test_exports() {
        // Test that main exports are available
        let _config = EchConfig::default();
        let _memory_config = crate::memory::MemoryConfig::default();
        let _stealth_level = StealthLevel::Medium;
    }
}