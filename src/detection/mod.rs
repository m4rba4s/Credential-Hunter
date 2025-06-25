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

pub mod engine;
pub mod patterns;
pub mod entropy;
pub mod context;
pub mod classifier;
pub mod yara_integration;
pub mod webauthn_simple;

pub use engine::{DetectionEngine, DetectionResult, CredentialType, ConfidenceLevel, CredentialLocation, RiskLevel};
pub use patterns::{PatternRegistry, PatternMatch, CustomPattern};
pub use entropy::EntropyAnalyzer;
pub use context::ContextAnalyzer;
pub use classifier::MLClassifier;
pub use webauthn_simple::{WebAuthnHunter, WebAuthnCredential};

#[cfg(feature = "yara-integration")]
pub use yara_integration::YaraScanner;