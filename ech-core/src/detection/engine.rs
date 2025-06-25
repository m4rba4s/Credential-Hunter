/**
 * ECH Detection Engine - Core Credential Detection Orchestrator
 * 
 * This is the main detection engine that coordinates all credential detection
 * strategies and provides a unified interface for credential hunting operations.
 * 
 * Features:
 * - Multi-strategy detection (patterns, entropy, ML, context)
 * - Performance optimization with SIMD and parallel processing
 * - Threat intelligence integration
 * - False positive reduction with context analysis
 * - Enterprise-grade reporting and audit trails
 */

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use super::{
    patterns::{PatternRegistry, PatternMatch},
    entropy::EntropyAnalyzer,
    context::ContextAnalyzer,
    classifier::MLClassifier,
};

#[cfg(feature = "yara-integration")]
use super::yara_integration::YaraScanner;

/// Core detection engine that orchestrates all credential detection strategies
pub struct DetectionEngine {
    /// Pattern-based detection registry
    pattern_registry: Arc<PatternRegistry>,
    
    /// Entropy analysis engine
    entropy_analyzer: Arc<EntropyAnalyzer>,
    
    /// Context-aware validation
    context_analyzer: Arc<ContextAnalyzer>,
    
    /// Machine learning classifier
    ml_classifier: Option<Arc<MLClassifier>>,
    
    /// YARA rule scanner
    #[cfg(feature = "yara-integration")]
    yara_scanner: Option<Arc<YaraScanner>>,
    
    /// Detection statistics
    stats: Arc<RwLock<DetectionStats>>,
    
    /// Configuration
    config: DetectionConfig,
}

/// Detection result with comprehensive metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Unique identifier for this detection
    pub id: Uuid,
    
    /// Type of credential detected
    pub credential_type: CredentialType,
    
    /// Confidence level of detection
    pub confidence: ConfidenceLevel,
    
    /// Raw detected value (masked for security)
    pub masked_value: String,
    
    /// Full value (only in dry-run mode)
    pub full_value: Option<String>,
    
    /// Location where credential was found
    pub location: CredentialLocation,
    
    /// Context surrounding the credential
    pub context: CredentialContext,
    
    /// Detection metadata
    pub metadata: DetectionMetadata,
    
    /// Risk assessment
    pub risk_level: RiskLevel,
    
    /// Recommended actions
    pub recommended_actions: Vec<String>,
    
    /// Detection timestamp
    pub timestamp: DateTime<Utc>,
}

/// Types of credentials that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialType {
    // Cloud Provider Credentials
    AwsAccessKey,
    AwsSecretKey,
    AwsSessionToken,
    AzureClientSecret,
    AzureStorageKey,
    GcpServiceKey,
    GcpApiKey,
    
    // Database Credentials
    DatabasePassword,
    MongoDbConnectionString,
    RedisPassword,
    PostgreSqlPassword,
    MySqlPassword,
    
    // API Keys and Tokens
    GitHubToken,
    SlackToken,
    StripeApiKey,
    TwilioApiKey,
    SendGridApiKey,
    JwtToken,
    BearerToken,
    
    // Cryptographic Material
    RsaPrivateKey,
    EcdsaPrivateKey,
    Ed25519PrivateKey,
    X509Certificate,
    PemCertificate,
    
    // Authentication
    Password,
    ApiSecret,
    SessionToken,
    OauthToken,
    WebAuthn,
    Passkey,
    WindowsHello,
    
    // Personal Information
    SocialSecurityNumber,
    CreditCardNumber,
    EmailAddress,
    PhoneNumber,
    
    // Generic High-Entropy String
    HighEntropyString,
    
    // Custom Pattern
    Custom(String),
}

/// Confidence levels for detections
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,      // 0-25%
    Medium,   // 26-75%
    High,     // 76-95%
    Critical, // 96-100%
}

/// Risk levels for security assessment
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Location where credential was found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialLocation {
    /// Source type (file, memory, environment, etc.)
    pub source_type: String,
    
    /// Full path or identifier
    pub path: String,
    
    /// Line number (for text files)
    pub line_number: Option<usize>,
    
    /// Column position
    pub column: Option<usize>,
    
    /// Memory address (for memory scans)
    pub memory_address: Option<u64>,
    
    /// Process ID (for memory scans)
    pub process_id: Option<u32>,
    
    /// Container ID (for container scans)
    pub container_id: Option<String>,
}

/// Context surrounding the credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialContext {
    /// Surrounding text/code
    pub surrounding_text: String,
    
    /// Variable name or key
    pub variable_name: Option<String>,
    
    /// File type or format
    pub file_type: Option<String>,
    
    /// Language or technology detected
    pub language: Option<String>,
    
    /// Additional context clues
    pub context_clues: Vec<String>,
}

/// Detection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetadata {
    /// Detection methods used
    pub detection_methods: Vec<String>,
    
    /// Pattern that matched
    pub pattern_name: Option<String>,
    
    /// Entropy score
    pub entropy_score: Option<f64>,
    
    /// ML confidence score
    pub ml_confidence: Option<f64>,
    
    /// YARA rule matches
    pub yara_matches: Vec<String>,
    
    /// Processing time (microseconds)
    pub processing_time_us: u64,
}

/// Detection statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DetectionStats {
    /// Total credentials detected
    pub total_detections: u64,
    
    /// Detections by type
    pub detections_by_type: HashMap<CredentialType, u64>,
    
    /// Detections by confidence
    pub detections_by_confidence: HashMap<ConfidenceLevel, u64>,
    
    /// False positives identified
    pub false_positives: u64,
    
    /// Processing performance
    pub avg_processing_time_us: u64,
    
    /// Data processed (bytes)
    pub bytes_processed: u64,
}

/// Detection configuration
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Enable pattern-based detection
    pub enable_patterns: bool,
    
    /// Enable entropy analysis
    pub enable_entropy: bool,
    
    /// Enable ML classification
    pub enable_ml: bool,
    
    /// Enable context analysis
    pub enable_context: bool,
    
    /// Enable YARA scanning
    pub enable_yara: bool,
    
    /// Minimum confidence threshold
    pub min_confidence: ConfidenceLevel,
    
    /// Maximum false positive rate
    pub max_false_positive_rate: f64,
    
    /// Performance settings
    pub parallel_workers: usize,
    pub enable_simd: bool,
    pub max_memory_usage: usize,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enable_patterns: true,
            enable_entropy: true,
            enable_ml: false, // Disabled by default
            enable_context: true,
            enable_yara: false, // Disabled by default
            min_confidence: ConfidenceLevel::Medium,
            max_false_positive_rate: 0.05,
            parallel_workers: num_cpus::get(),
            enable_simd: true,
            max_memory_usage: 1024 * 1024 * 1024, // 1GB
        }
    }
}

impl DetectionEngine {
    /// Create a new detection engine
    pub async fn new(config: DetectionConfig) -> Result<Self> {
        info!("🔍 Initializing ECH Detection Engine");
        
        // Initialize pattern registry
        let pattern_registry = Arc::new(
            PatternRegistry::new()
                .await
                .context("Failed to initialize pattern registry")?
        );
        
        // Initialize entropy analyzer
        let entropy_analyzer = Arc::new(
            EntropyAnalyzer::new(4.5, 8, 1024) // threshold, min_len, max_len
        );
        
        // Initialize context analyzer
        let context_analyzer = Arc::new(
            ContextAnalyzer::new()
                .context("Failed to initialize context analyzer")?
        );
        
        // Initialize ML classifier if enabled
        let ml_classifier = if config.enable_ml {
            Some(Arc::new(
                MLClassifier::new()
                    .await
                    .context("Failed to initialize ML classifier")?
            ))
        } else {
            None
        };
        
        // Initialize YARA scanner if enabled
        #[cfg(feature = "yara-integration")]
        let yara_scanner = if config.enable_yara {
            Some(Arc::new(
                YaraScanner::new()
                    .await
                    .context("Failed to initialize YARA scanner")?
            ))
        } else {
            None
        };
        
        #[cfg(not(feature = "yara-integration"))]
        let _yara_scanner = None;
        
        let stats = Arc::new(RwLock::new(DetectionStats::default()));
        
        info!("✅ Detection engine initialized successfully");
        
        Ok(Self {
            pattern_registry,
            entropy_analyzer,
            context_analyzer,
            ml_classifier,
            #[cfg(feature = "yara-integration")]
            yara_scanner,
            stats,
            config,
        })
    }
    
    /// Detect credentials in text content
    pub async fn detect_in_text(
        &self,
        content: &str,
        location: CredentialLocation,
    ) -> Result<Vec<DetectionResult>> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();
        
        debug!("🔍 Scanning text content: {} chars", content.len());
        
        // Pattern-based detection
        if self.config.enable_patterns {
            let pattern_matches = self.pattern_registry
                .scan_text(content)
                .await
                .context("Pattern scanning failed")?;
            
            for pattern_match in pattern_matches {
                if let Some(result) = self.create_detection_result(
                    pattern_match,
                    &location,
                    content,
                ).await? {
                    results.push(result);
                }
            }
        }
        
        // Entropy-based detection
        if self.config.enable_entropy {
            let entropy_matches = self.entropy_analyzer
                .analyze_text(content)
                .await;
            
            for entropy_match in entropy_matches {
                if let Some(result) = self.process_entropy_match(
                    entropy_match,
                    &location,
                    content,
                ).await? {
                    results.push(result);
                }
            }
        }
        
        // ML classification
        if let Some(ref ml_classifier) = self.ml_classifier {
            let ml_results = ml_classifier
                .classify_text(content)
                .await
                .context("ML classification failed")?;
            
            for ml_result in ml_results {
                if let Some(result) = self.process_ml_result(
                    ml_result,
                    &location,
                    content,
                ).await? {
                    results.push(result);
                }
            }
        }
        
        // Context validation and false positive reduction
        if self.config.enable_context {
            results = self.validate_with_context(results, content).await?;
        }
        
        // Update statistics
        self.update_stats(&results, start_time.elapsed()).await;
        
        debug!("🎯 Found {} potential credentials", results.len());
        Ok(results)
    }
    
    /// Detect credentials in binary data
    pub async fn detect_in_binary(
        &self,
        data: &[u8],
        location: CredentialLocation,
    ) -> Result<Vec<DetectionResult>> {
        // Extract strings from binary data
        let strings = self.extract_strings_from_binary(data);
        
        let mut results = Vec::new();
        for string_data in strings {
            let mut string_results = self.detect_in_text(&string_data.content, location.clone()).await?;
            
            // Adjust locations for binary context
            for result in &mut string_results {
                result.location.memory_address = Some(string_data.offset as u64);
            }
            
            results.extend(string_results);
        }
        
        Ok(results)
    }
    
    /// Create detection result from pattern match
    async fn create_detection_result(
        &self,
        pattern_match: PatternMatch,
        location: &CredentialLocation,
        content: &str,
    ) -> Result<Option<DetectionResult>> {
        let confidence = self.calculate_confidence(&pattern_match);
        
        if confidence < self.config.min_confidence {
            return Ok(None);
        }
        
        let context = self.extract_context(content, pattern_match.start, pattern_match.end);
        let risk_level = self.assess_risk(&pattern_match.credential_type, &context);
        
        let result = DetectionResult {
            id: Uuid::new_v4(),
            credential_type: pattern_match.credential_type.clone(),
            confidence,
            masked_value: self.mask_value(&pattern_match.value),
            full_value: if self.is_dry_run() { Some(pattern_match.value) } else { None },
            location: location.clone(),
            context: CredentialContext {
                surrounding_text: context,
                variable_name: pattern_match.variable_name,
                file_type: self.detect_file_type(&location.path),
                language: self.detect_language(content),
                context_clues: Vec::new(),
            },
            metadata: DetectionMetadata {
                detection_methods: vec!["pattern_matching".to_string()],
                pattern_name: Some(pattern_match.pattern_name),
                entropy_score: None,
                ml_confidence: None,
                yara_matches: Vec::new(),
                processing_time_us: 0,
            },
            risk_level: risk_level.clone(),
            recommended_actions: self.get_recommended_actions(&pattern_match.credential_type, &risk_level),
            timestamp: Utc::now(),
        };
        
        Ok(Some(result))
    }
    
    /// Process entropy-based match
    async fn process_entropy_match(
        &self,
        entropy_match: EntropyMatch,
        location: &CredentialLocation,
        content: &str,
    ) -> Result<Option<DetectionResult>> {
        // Enhanced entropy analysis with context
        let context_text = self.extract_context(content, entropy_match.start, entropy_match.end);
        let credential_type = self.infer_credential_type(&entropy_match.value, &context_text);
        
        let confidence = self.calculate_entropy_confidence(entropy_match.entropy_score);
        
        if confidence < self.config.min_confidence {
            return Ok(None);
        }
        
        let result = DetectionResult {
            id: Uuid::new_v4(),
            credential_type: credential_type.clone(),
            confidence,
            masked_value: self.mask_value(&entropy_match.value),
            full_value: if self.is_dry_run() { Some(entropy_match.value) } else { None },
            location: location.clone(),
            context: CredentialContext {
                surrounding_text: context_text.clone(),
                variable_name: self.extract_variable_name(&context_text),
                file_type: self.detect_file_type(&location.path),
                language: self.detect_language(content),
                context_clues: Vec::new(),
            },
            metadata: DetectionMetadata {
                detection_methods: vec!["entropy_analysis".to_string()],
                pattern_name: None,
                entropy_score: Some(entropy_match.entropy_score),
                ml_confidence: None,
                yara_matches: Vec::new(),
                processing_time_us: 0,
            },
            risk_level: self.assess_risk(&credential_type, &context_text),
            recommended_actions: self.get_recommended_actions(&credential_type, &RiskLevel::Medium),
            timestamp: Utc::now(),
        };
        
        Ok(Some(result))
    }
    
    /// Process ML classification result
    async fn process_ml_result(
        &self,
        ml_result: MLResult,
        location: &CredentialLocation,
        content: &str,
    ) -> Result<Option<DetectionResult>> {
        if ml_result.confidence < 0.7 { // ML threshold
            return Ok(None);
        }
        
        let context_text = self.extract_context(content, ml_result.start, ml_result.end);
        
        let result = DetectionResult {
            id: Uuid::new_v4(),
            credential_type: ml_result.credential_type.clone(),
            confidence: self.ml_confidence_to_level(ml_result.confidence),
            masked_value: self.mask_value(&ml_result.value),
            full_value: if self.is_dry_run() { Some(ml_result.value) } else { None },
            location: location.clone(),
            context: CredentialContext {
                surrounding_text: context_text,
                variable_name: None,
                file_type: self.detect_file_type(&location.path),
                language: self.detect_language(content),
                context_clues: Vec::new(),
            },
            metadata: DetectionMetadata {
                detection_methods: vec!["ml_classification".to_string()],
                pattern_name: None,
                entropy_score: None,
                ml_confidence: Some(ml_result.confidence),
                yara_matches: Vec::new(),
                processing_time_us: 0,
            },
            risk_level: RiskLevel::Medium,
            recommended_actions: self.get_recommended_actions(&ml_result.credential_type, &RiskLevel::Medium),
            timestamp: Utc::now(),
        };
        
        Ok(Some(result))
    }
    
    /// Validate results with context analysis
    async fn validate_with_context(
        &self,
        mut results: Vec<DetectionResult>,
        content: &str,
    ) -> Result<Vec<DetectionResult>> {
        let validated_results = Vec::new();
        
        for mut result in results {
            let validation_score = self.context_analyzer
                .validate_credential(&result, content)
                .await
                .context("Context validation failed")?;
            
            if validation_score > 0.3 { // Context validation threshold
                // Adjust confidence based on context
                result.confidence = self.adjust_confidence_with_context(
                    result.confidence,
                    validation_score
                );
                validated_results.push(result);
            }
        }
        
        Ok(validated_results)
    }
    
    /// Extract context around a detection
    fn extract_context(&self, content: &str, start: usize, end: usize) -> String {
        let context_size = 100;
        let start_pos = start.saturating_sub(context_size);
        let end_pos = std::cmp::min(end + context_size, content.len());
        
        content[start_pos..end_pos].to_string()
    }
    
    /// Mask sensitive values for safe logging
    fn mask_value(&self, value: &str) -> String {
        if value.len() <= 8 {
            "*".repeat(value.len())
        } else {
            format!("{}***{}", &value[..2], &value[value.len()-2..])
        }
    }
    
    /// Calculate confidence level from pattern match
    fn calculate_confidence(&self, pattern_match: &PatternMatch) -> ConfidenceLevel {
        match pattern_match.confidence_score {
            0.0..=0.25 => ConfidenceLevel::Low,
            0.26..=0.75 => ConfidenceLevel::Medium,
            0.76..=0.95 => ConfidenceLevel::High,
            _ => ConfidenceLevel::Critical,
        }
    }
    
    /// Calculate confidence from entropy score
    fn calculate_entropy_confidence(&self, entropy: f64) -> ConfidenceLevel {
        match entropy {
            0.0..=3.0 => ConfidenceLevel::Low,
            3.1..=4.5 => ConfidenceLevel::Medium,
            4.6..=5.5 => ConfidenceLevel::High,
            _ => ConfidenceLevel::Critical,
        }
    }
    
    /// Convert ML confidence to confidence level
    fn ml_confidence_to_level(&self, confidence: f64) -> ConfidenceLevel {
        match confidence {
            0.0..=0.5 => ConfidenceLevel::Low,
            0.51..=0.8 => ConfidenceLevel::Medium,
            0.81..=0.95 => ConfidenceLevel::High,
            _ => ConfidenceLevel::Critical,
        }
    }
    
    /// Assess risk level for a credential type
    fn assess_risk(&self, credential_type: &CredentialType, context: &str) -> RiskLevel {
        match credential_type {
            CredentialType::AwsAccessKey | CredentialType::AwsSecretKey => RiskLevel::Critical,
            CredentialType::RsaPrivateKey | CredentialType::EcdsaPrivateKey => RiskLevel::High,
            CredentialType::DatabasePassword => RiskLevel::High,
            CredentialType::ApiSecret => RiskLevel::Medium,
            CredentialType::HighEntropyString => {
                if context.contains("test") || context.contains("example") {
                    RiskLevel::Low
                } else {
                    RiskLevel::Medium
                }
            }
            _ => RiskLevel::Medium,
        }
    }
    
    /// Get recommended actions for credential type and risk level
    fn get_recommended_actions(&self, credential_type: &CredentialType, risk_level: &RiskLevel) -> Vec<String> {
        let mut actions = Vec::new();
        
        match risk_level {
            RiskLevel::Critical => {
                actions.push("IMMEDIATE: Rotate credential".to_string());
                actions.push("IMMEDIATE: Revoke access".to_string());
                actions.push("Review access logs".to_string());
            }
            RiskLevel::High => {
                actions.push("Rotate credential within 24h".to_string());
                actions.push("Update secret management".to_string());
            }
            RiskLevel::Medium => {
                actions.push("Review and rotate if necessary".to_string());
                actions.push("Implement proper secret management".to_string());
            }
            _ => {
                actions.push("Monitor and review".to_string());
            }
        }
        
        actions
    }
    
    /// Update detection statistics
    async fn update_stats(&self, results: &[DetectionResult], processing_time: std::time::Duration) {
        let mut stats = self.stats.write().await;
        
        stats.total_detections += results.len() as u64;
        
        for result in results {
            *stats.detections_by_type.entry(result.credential_type.clone()).or_insert(0) += 1;
            *stats.detections_by_confidence.entry(result.confidence.clone()).or_insert(0) += 1;
        }
        
        // Update average processing time
        let processing_us = processing_time.as_micros() as u64;
        stats.avg_processing_time_us = 
            (stats.avg_processing_time_us + processing_us) / 2;
    }
    
    /// Check if running in dry-run mode
    fn is_dry_run(&self) -> bool {
        // This would be set from the main config
        std::env::var("ECH_DRY_RUN").is_ok()
    }
    
    /// Additional helper methods would go here...
    fn extract_strings_from_binary(&self, _data: &[u8]) -> Vec<BinaryString> {
        // Implementation for extracting strings from binary data
        Vec::new()
    }
    
    fn infer_credential_type(&self, _value: &str, _context: &str) -> CredentialType {
        CredentialType::HighEntropyString
    }
    
    fn detect_file_type(&self, path: &str) -> Option<String> {
        std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_string())
    }
    
    fn detect_language(&self, _content: &str) -> Option<String> {
        // Implementation for language detection
        None
    }
    
    fn extract_variable_name(&self, _context: &str) -> Option<String> {
        // Implementation for variable name extraction
        None
    }
    
    fn adjust_confidence_with_context(&self, confidence: ConfidenceLevel, _validation_score: f64) -> ConfidenceLevel {
        confidence
    }
}

// Additional types for internal use
#[derive(Debug)]
struct EntropyMatch {
    value: String,
    start: usize,
    end: usize,
    entropy_score: f64,
}

#[derive(Debug)]
struct MLResult {
    value: String,
    start: usize,
    end: usize,
    credential_type: CredentialType,
    confidence: f64,
}

#[derive(Debug)]
struct BinaryString {
    content: String,
    offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_detection_engine_creation() {
        let config = DetectionConfig {
            enable_patterns: true,
            enable_entropy: true,
            enable_ml: false,
            enable_context: true,
            enable_yara: false,
            min_confidence: ConfidenceLevel::Medium,
            max_false_positive_rate: 0.1,
            parallel_workers: 4,
            enable_simd: true,
            max_memory_usage: 1024 * 1024 * 100, // 100MB
        };
        
        let engine = DetectionEngine::new(config).await;
        assert!(engine.is_ok());
    }
    
    #[tokio::test]
    async fn test_aws_key_detection() {
        let config = DetectionConfig {
            enable_patterns: true,
            enable_entropy: false,
            enable_ml: false,
            enable_context: false,
            enable_yara: false,
            min_confidence: ConfidenceLevel::Low,
            max_false_positive_rate: 0.5,
            parallel_workers: 1,
            enable_simd: false,
            max_memory_usage: 1024 * 1024,
        };
        
        let engine = DetectionEngine::new(config).await.unwrap();
        
        let test_content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let location = CredentialLocation {
            source_type: "file".to_string(),
            path: "/test/config".to_string(),
            line_number: Some(1),
            column: Some(1),
            memory_address: None,
            process_id: None,
            container_id: None,
        };
        
        let results = engine.detect_in_text(test_content, location).await.unwrap();
        assert!(!results.is_empty());
        
        let result = &results[0];
        assert!(matches!(result.credential_type, CredentialType::AwsAccessKey));
        assert!(result.confidence >= ConfidenceLevel::Medium);
    }
}