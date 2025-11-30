/// Machine-learning classifiers and feature extraction pipelines.
pub mod classifier;

/// Context-aware validation to reduce false positives.
pub mod context;
/**
 * ECH Detection Engine - Advanced Credential Pattern Detection
 *
 * This module implements the core credential detection capabilities with multiple
 * detection strategies:
 * - Pattern-based detection (regex, signatures)
 * - Entropy analysis for random strings
 * - Machine learning classification
 * - Context-aware validation
 * - YARA rule integration
 *
 * Designed for enterprise-scale deployment with performance optimizations
 * and comprehensive threat coverage.
 */
/// Orchestrates all detection strategies and aggregates results.
pub mod engine;

/// Entropy-based detection for high-entropy secrets.
pub mod entropy;

/// Pattern registry (regex, signatures, and matching metadata).
pub mod patterns;

/// Optional YARA integration for binary hunting and IOC sweeps.
pub mod yara_integration;

// Re-export common detection types for convenience.
#[allow(unused_imports)]
pub use engine::{
    ConfidenceLevel, CredentialContext, CredentialLocation, CredentialType, DetectionConfig,
    DetectionEngine, DetectionMetadata, DetectionResult, DetectionStats, RiskLevel,
};
