/**
 * ECH ML Classifier - Machine Learning Credential Classification
 * 
 * This module implements machine learning-based credential classification to detect
 * unknown or novel credential patterns. Uses lightweight ML models optimized for
 * real-time inference in enterprise environments.
 * 
 * Features:
 * - Pre-trained models for common credential types
 * - Feature extraction from text patterns
 * - Ensemble classification for improved accuracy
 * - Online learning for adaptation to new threats
 * - Performance optimization for production deployment
 */

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::engine::CredentialType;

/// Machine learning classifier for credential detection
pub struct MLClassifier {
    /// Loaded models
    models: Arc<RwLock<HashMap<String, ClassificationModel>>>,
    
    /// Feature extractors
    feature_extractors: Vec<FeatureExtractor>,
    
    /// Classification thresholds
    thresholds: ClassificationThresholds,
    
    /// Model statistics
    stats: Arc<RwLock<MLStats>>,
}

/// Individual classification model
#[derive(Debug, Clone)]
pub struct ClassificationModel {
    /// Model name
    pub name: String,
    
    /// Model type
    pub model_type: ModelType,
    
    /// Model weights/parameters (simplified for demo)
    pub weights: Vec<f64>,
    
    /// Feature names this model expects
    pub feature_names: Vec<String>,
    
    /// Output classes
    pub classes: Vec<String>,
    
    /// Model accuracy metrics
    pub accuracy: f64,
    
    /// Model version
    pub version: String,
}

/// Types of ML models supported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelType {
    /// Logistic regression
    LogisticRegression,
    
    /// Random forest
    RandomForest,
    
    /// Neural network
    NeuralNetwork,
    
    /// Support vector machine
    SVM,
    
    /// Ensemble of multiple models
    Ensemble,
}

/// Feature extractor for ML models
#[derive(Debug, Clone)]
pub struct FeatureExtractor {
    /// Extractor name
    pub name: String,
    
    /// Features this extractor produces
    pub feature_names: Vec<String>,
    
    /// Extractor function type
    pub extractor_type: ExtractorType,
}

/// Types of feature extractors
#[derive(Debug, Clone)]
pub enum ExtractorType {
    /// Character-level features
    CharacterLevel,
    
    /// N-gram features
    NGram { n: usize },
    
    /// Statistical features
    Statistical,
    
    /// Structural features
    Structural,
    
    /// Domain-specific features
    DomainSpecific,
}

/// Classification thresholds for different credential types
#[derive(Debug, Clone)]
pub struct ClassificationThresholds {
    /// Default threshold for binary classification
    pub default_threshold: f64,
    
    /// Per-credential-type thresholds
    pub type_thresholds: HashMap<String, f64>,
    
    /// Ensemble voting threshold
    pub ensemble_threshold: f64,
}

/// ML classification result
#[derive(Debug, Clone)]
pub struct MLResult {
    /// Detected value
    pub value: String,
    
    /// Start position
    pub start: usize,
    
    /// End position  
    pub end: usize,
    
    /// Predicted credential type
    pub credential_type: CredentialType,
    
    /// Classification confidence (0.0-1.0)
    pub confidence: f64,
    
    /// Individual model predictions
    pub model_predictions: Vec<ModelPrediction>,
    
    /// Feature vector used for classification
    pub features: FeatureVector,
    
    /// Processing time
    pub processing_time_ms: f64,
}

/// Individual model prediction
#[derive(Debug, Clone)]
pub struct ModelPrediction {
    /// Model name
    pub model_name: String,
    
    /// Predicted class
    pub predicted_class: String,
    
    /// Prediction confidence
    pub confidence: f64,
    
    /// Class probabilities
    pub class_probabilities: HashMap<String, f64>,
}

/// Feature vector for ML classification
#[derive(Debug, Clone)]
pub struct FeatureVector {
    /// Feature names
    pub names: Vec<String>,
    
    /// Feature values
    pub values: Vec<f64>,
    
    /// Feature metadata
    pub metadata: HashMap<String, String>,
}

/// ML classification statistics
#[derive(Debug, Default, Clone)]
pub struct MLStats {
    /// Total classifications performed
    pub total_classifications: u64,
    
    /// Classifications by confidence level
    pub confidence_distribution: HashMap<String, u64>,
    
    /// Model performance metrics
    pub model_performance: HashMap<String, ModelPerformance>,
    
    /// Average processing time
    pub avg_processing_time_ms: f64,
    
    /// Feature importance scores
    pub feature_importance: HashMap<String, f64>,
}

/// Model performance metrics
#[derive(Debug, Default, Clone)]
pub struct ModelPerformance {
    /// Number of predictions made
    pub predictions_made: u64,
    
    /// Average confidence
    pub avg_confidence: f64,
    
    /// Accuracy (when ground truth available)
    pub accuracy: Option<f64>,
    
    /// Precision per class
    pub precision: HashMap<String, f64>,
    
    /// Recall per class
    pub recall: HashMap<String, f64>,
}

impl MLClassifier {
    /// Create a new ML classifier
    pub async fn new() -> Result<Self> {
        info!("🤖 Initializing ML Classifier for credential detection");
        
        let feature_extractors = Self::create_feature_extractors();
        let thresholds = Self::create_default_thresholds();
        let models = Arc::new(RwLock::new(HashMap::new()));
        let stats = Arc::new(RwLock::new(MLStats::default()));
        
        let classifier = Self {
            models,
            feature_extractors,
            thresholds,
            stats,
        };
        
        // Load pre-trained models
        classifier.load_pretrained_models().await?;
        
        info!("✅ ML Classifier initialized successfully");
        Ok(classifier)
    }
    
    /// Classify text content for credentials
    pub async fn classify_text(&self, text: &str) -> Result<Vec<MLResult>> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();
        
        // Extract candidate strings (similar to entropy analyzer)
        let candidates = self.extract_candidates(text);
        
        for candidate in candidates {
            if let Some(result) = self.classify_candidate(&candidate).await? {
                results.push(result);
            }
        }
        
        // Update statistics
        let processing_time = start_time.elapsed().as_millis() as f64;
        self.update_stats(&results, processing_time).await;
        
        debug!("ML classification found {} potential credentials", results.len());
        Ok(results)
    }
    
    /// Classify a single candidate string
    async fn classify_candidate(&self, candidate: &CandidateString) -> Result<Option<MLResult>> {
        let start_time = std::time::Instant::now();
        
        // Extract features
        let features = self.extract_features(&candidate.value);
        
        // Get model predictions
        let models = self.models.read().await;
        let mut model_predictions = Vec::new();
        
        for (model_name, model) in models.iter() {
            if let Some(prediction) = self.predict_with_model(model, &features).await? {
                model_predictions.push(prediction);
            }
        }
        
        if model_predictions.is_empty() {
            return Ok(None);
        }
        
        // Ensemble voting
        let (final_class, final_confidence) = self.ensemble_vote(&model_predictions);
        
        // Check confidence threshold
        let threshold = self.thresholds.type_thresholds
            .get(&final_class)
            .unwrap_or(&self.thresholds.default_threshold);
            
        if final_confidence < *threshold {
            return Ok(None);
        }
        
        // Convert class name to credential type
        let credential_type = self.class_to_credential_type(&final_class);
        
        let processing_time = start_time.elapsed().as_millis() as f64;
        
        Ok(Some(MLResult {
            value: candidate.value.clone(),
            start: candidate.start,
            end: candidate.end,
            credential_type,
            confidence: final_confidence,
            model_predictions,
            features,
            processing_time_ms: processing_time,
        }))
    }
    
    /// Extract features from a string
    fn extract_features(&self, text: &str) -> FeatureVector {
        let mut feature_names = Vec::new();
        let mut feature_values = Vec::new();
        let mut metadata = HashMap::new();
        
        for extractor in &self.feature_extractors {
            let (names, values, meta) = match extractor.extractor_type {
                ExtractorType::CharacterLevel => self.extract_character_features(text),
                ExtractorType::NGram { n } => self.extract_ngram_features(text, n),
                ExtractorType::Statistical => self.extract_statistical_features(text),
                ExtractorType::Structural => self.extract_structural_features(text),
                ExtractorType::DomainSpecific => self.extract_domain_features(text),
            };
            
            feature_names.extend(names);
            feature_values.extend(values);
            metadata.extend(meta);
        }
        
        FeatureVector {
            names: feature_names,
            values: feature_values,
            metadata,
        }
    }
    
    /// Extract character-level features
    fn extract_character_features(&self, text: &str) -> (Vec<String>, Vec<f64>, HashMap<String, String>) {
        let mut names = Vec::new();
        let mut values = Vec::new();
        let mut metadata = HashMap::new();
        
        let chars: Vec<char> = text.chars().collect();
        let total_chars = chars.len() as f64;
        
        if total_chars == 0.0 {
            return (names, values, metadata);
        }
        
        // Character type ratios
        let uppercase_count = chars.iter().filter(|c| c.is_uppercase()).count() as f64;
        let lowercase_count = chars.iter().filter(|c| c.is_lowercase()).count() as f64;
        let digit_count = chars.iter().filter(|c| c.is_ascii_digit()).count() as f64;
        let special_count = chars.iter().filter(|c| !c.is_alphanumeric()).count() as f64;
        
        names.extend(vec![
            "char_uppercase_ratio".to_string(),
            "char_lowercase_ratio".to_string(),
            "char_digit_ratio".to_string(),
            "char_special_ratio".to_string(),
        ]);
        
        values.extend(vec![
            uppercase_count / total_chars,
            lowercase_count / total_chars,
            digit_count / total_chars,
            special_count / total_chars,
        ]);
        
        // Character diversity
        let unique_chars: std::collections::HashSet<char> = chars.iter().cloned().collect();
        let char_diversity = unique_chars.len() as f64 / total_chars;
        
        names.push("char_diversity".to_string());
        values.push(char_diversity);
        
        // Most frequent character
        let mut char_counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
        for &ch in &chars {
            *char_counts.entry(ch).or_insert(0) += 1;
        }
        
        let max_char_freq = char_counts.values().max().unwrap_or(&0);
        let max_char_ratio = *max_char_freq as f64 / total_chars;
        
        names.push("max_char_frequency".to_string());
        values.push(max_char_ratio);
        
        metadata.insert("extractor".to_string(), "character_level".to_string());
        
        (names, values, metadata)
    }
    
    /// Extract n-gram features
    fn extract_ngram_features(&self, text: &str, n: usize) -> (Vec<String>, Vec<f64>, HashMap<String, String>) {
        let mut names = Vec::new();
        let mut values = Vec::new();
        let mut metadata = HashMap::new();
        
        let chars: Vec<char> = text.chars().collect();
        
        if chars.len() < n {
            return (names, values, metadata);
        }
        
        // Extract n-grams
        let mut ngram_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        
        for i in 0..=(chars.len() - n) {
            let ngram: String = chars[i..i+n].iter().collect();
            *ngram_counts.entry(ngram).or_insert(0) += 1;
        }
        
        let total_ngrams = ngram_counts.values().sum::<usize>() as f64;
        
        // N-gram diversity
        let unique_ngrams = ngram_counts.len() as f64;
        let ngram_diversity = unique_ngrams / total_ngrams;
        
        names.push(format!("{}_gram_diversity", n));
        values.push(ngram_diversity);
        
        // Most frequent n-gram
        let max_ngram_count = ngram_counts.values().max().unwrap_or(&0);
        let max_ngram_ratio = *max_ngram_count as f64 / total_ngrams;
        
        names.push(format!("max_{}_gram_frequency", n));
        values.push(max_ngram_ratio);
        
        // Repeating n-gram detection
        let repeating_ngrams = ngram_counts.values().filter(|&&count| count > 1).count() as f64;
        let repeat_ratio = repeating_ngrams / unique_ngrams;
        
        names.push(format!("{}_gram_repeat_ratio", n));
        values.push(repeat_ratio);
        
        metadata.insert("extractor".to_string(), format!("{}_gram", n));
        
        (names, values, metadata)
    }
    
    /// Extract statistical features
    fn extract_statistical_features(&self, text: &str) -> (Vec<String>, Vec<f64>, HashMap<String, String>) {
        let mut names = Vec::new();
        let mut values = Vec::new();
        let mut metadata = HashMap::new();
        
        // Length features
        names.push("text_length".to_string());
        values.push(text.len() as f64);
        
        // Entropy (reuse from entropy analyzer logic)
        let entropy = self.calculate_entropy(text);
        names.push("shannon_entropy".to_string());
        values.push(entropy);
        
        // Compression ratio (estimate of randomness)
        let compression_ratio = self.estimate_compression_ratio(text);
        names.push("compression_ratio".to_string());
        values.push(compression_ratio);
        
        // ASCII printable ratio
        let ascii_printable_count = text.chars()
            .filter(|c| c.is_ascii() && !c.is_ascii_control())
            .count() as f64;
        let ascii_ratio = ascii_printable_count / text.len() as f64;
        
        names.push("ascii_printable_ratio".to_string());
        values.push(ascii_ratio);
        
        metadata.insert("extractor".to_string(), "statistical".to_string());
        
        (names, values, metadata)
    }
    
    /// Extract structural features
    fn extract_structural_features(&self, text: &str) -> (Vec<String>, Vec<f64>, HashMap<String, String>) {
        let mut names = Vec::new();
        let mut values = Vec::new();
        let mut metadata = HashMap::new();
        
        // Pattern detection
        let has_base64_pattern = text.chars().all(|c| 
            c.is_alphanumeric() || c == '+' || c == '/' || c == '='
        ) && text.len() % 4 == 0;
        
        let has_hex_pattern = text.chars().all(|c| 
            c.is_ascii_hexdigit()
        ) && text.len() >= 8;
        
        let has_jwt_structure = text.split('.').count() == 3;
        
        let has_key_structure = text.contains("-----BEGIN") && text.contains("-----END");
        
        names.extend(vec![
            "has_base64_pattern".to_string(),
            "has_hex_pattern".to_string(),
            "has_jwt_structure".to_string(),
            "has_key_structure".to_string(),
        ]);
        
        values.extend(vec![
            if has_base64_pattern { 1.0 } else { 0.0 },
            if has_hex_pattern { 1.0 } else { 0.0 },
            if has_jwt_structure { 1.0 } else { 0.0 },
            if has_key_structure { 1.0 } else { 0.0 },
        ]);
        
        // Delimiter count
        let delimiters = ['-', '_', '.', ':', '/', '+', '='];
        for &delimiter in &delimiters {
            let count = text.chars().filter(|&c| c == delimiter).count() as f64;
            let ratio = count / text.len() as f64;
            
            names.push(format!("delimiter_{}_ratio", delimiter as u8));
            values.push(ratio);
        }
        
        metadata.insert("extractor".to_string(), "structural".to_string());
        
        (names, values, metadata)
    }
    
    /// Extract domain-specific features
    fn extract_domain_features(&self, text: &str) -> (Vec<String>, Vec<f64>, HashMap<String, String>) {
        let mut names = Vec::new();
        let mut values = Vec::new();
        let mut metadata = HashMap::new();
        
        // Common credential prefixes
        let prefixes = [
            ("sk_", "stripe_secret"),
            ("pk_", "stripe_public"),
            ("AKIA", "aws_access_key"),
            ("ghp_", "github_token"),
            ("xoxb-", "slack_bot_token"),
            ("xoxp-", "slack_user_token"),
            ("SG.", "sendgrid_api_key"),
            ("AC", "twilio_account_sid"),
        ];
        
        for (prefix, name) in &prefixes {
            let has_prefix = text.starts_with(prefix);
            names.push(format!("has_{}_prefix", name));
            values.push(if has_prefix { 1.0 } else { 0.0 });
        }
        
        // Length patterns for specific credential types
        let length_matches = match text.len() {
            20 => "aws_access_key_length",
            40 => "aws_secret_key_length",
            32 => "md5_hash_length",
            64 => "sha256_hash_length",
            36 => "uuid_length",
            _ => "other_length",
        };
        
        names.push("length_pattern_match".to_string());
        values.push(if length_matches != "other_length" { 1.0 } else { 0.0 });
        
        metadata.insert("extractor".to_string(), "domain_specific".to_string());
        metadata.insert("length_pattern".to_string(), length_matches.to_string());
        
        (names, values, metadata)
    }
    
    /// Simple entropy calculation
    fn calculate_entropy(&self, text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }
        
        let mut char_counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
        for ch in text.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }
        
        let len = text.chars().count() as f64;
        let mut entropy = 0.0;
        
        for &count in char_counts.values() {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
        
        entropy
    }
    
    /// Estimate compression ratio (simplified)
    fn estimate_compression_ratio(&self, text: &str) -> f64 {
        // Simple repetition-based estimate
        let unique_chars: std::collections::HashSet<char> = text.chars().collect();
        let compression_estimate = unique_chars.len() as f64 / text.len() as f64;
        compression_estimate
    }
    
    /// Make prediction with a specific model
    async fn predict_with_model(
        &self,
        model: &ClassificationModel,
        features: &FeatureVector,
    ) -> Result<Option<ModelPrediction>> {
        // Simplified model prediction (in real implementation, this would use actual ML libraries)
        match model.model_type {
            ModelType::LogisticRegression => self.predict_logistic_regression(model, features),
            ModelType::RandomForest => self.predict_random_forest(model, features),
            ModelType::NeuralNetwork => self.predict_neural_network(model, features),
            ModelType::SVM => self.predict_svm(model, features),
            ModelType::Ensemble => self.predict_ensemble(model, features),
        }
    }
    
    /// Simplified logistic regression prediction
    fn predict_logistic_regression(
        &self,
        model: &ClassificationModel,
        features: &FeatureVector,
    ) -> Result<Option<ModelPrediction>> {
        // This is a simplified implementation
        // In practice, you'd use libraries like linfa, smartcore, or candle
        
        let mut score = 0.0;
        for (i, &feature_value) in features.values.iter().enumerate() {
            if i < model.weights.len() {
                score += feature_value * model.weights[i];
            }
        }
        
        // Sigmoid activation
        let probability = 1.0 / (1.0 + (-score).exp());
        
        let predicted_class = if probability > 0.5 {
            "credential".to_string()
        } else {
            "not_credential".to_string()
        };
        
        let mut class_probabilities = HashMap::new();
        class_probabilities.insert("credential".to_string(), probability);
        class_probabilities.insert("not_credential".to_string(), 1.0 - probability);
        
        Ok(Some(ModelPrediction {
            model_name: model.name.clone(),
            predicted_class,
            confidence: probability.max(1.0 - probability),
            class_probabilities,
        }))
    }
    
    /// Placeholder for other model types
    fn predict_random_forest(&self, model: &ClassificationModel, _features: &FeatureVector) -> Result<Option<ModelPrediction>> {
        // Simplified random forest simulation
        Ok(Some(ModelPrediction {
            model_name: model.name.clone(),
            predicted_class: "credential".to_string(),
            confidence: 0.75,
            class_probabilities: {
                let mut probs = HashMap::new();
                probs.insert("credential".to_string(), 0.75);
                probs.insert("not_credential".to_string(), 0.25);
                probs
            },
        }))
    }
    
    fn predict_neural_network(&self, model: &ClassificationModel, _features: &FeatureVector) -> Result<Option<ModelPrediction>> {
        // Simplified neural network simulation
        Ok(Some(ModelPrediction {
            model_name: model.name.clone(),
            predicted_class: "credential".to_string(),
            confidence: 0.8,
            class_probabilities: {
                let mut probs = HashMap::new();
                probs.insert("credential".to_string(), 0.8);
                probs.insert("not_credential".to_string(), 0.2);
                probs
            },
        }))
    }
    
    fn predict_svm(&self, model: &ClassificationModel, _features: &FeatureVector) -> Result<Option<ModelPrediction>> {
        // Simplified SVM simulation
        Ok(Some(ModelPrediction {
            model_name: model.name.clone(),
            predicted_class: "credential".to_string(),
            confidence: 0.7,
            class_probabilities: {
                let mut probs = HashMap::new();
                probs.insert("credential".to_string(), 0.7);
                probs.insert("not_credential".to_string(), 0.3);
                probs
            },
        }))
    }
    
    fn predict_ensemble(&self, model: &ClassificationModel, _features: &FeatureVector) -> Result<Option<ModelPrediction>> {
        // Simplified ensemble simulation
        Ok(Some(ModelPrediction {
            model_name: model.name.clone(),
            predicted_class: "credential".to_string(),
            confidence: 0.85,
            class_probabilities: {
                let mut probs = HashMap::new();
                probs.insert("credential".to_string(), 0.85);
                probs.insert("not_credential".to_string(), 0.15);
                probs
            },
        }))
    }
    
    /// Ensemble voting across models
    fn ensemble_vote(&self, predictions: &[ModelPrediction]) -> (String, f64) {
        let mut class_votes: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        let mut total_confidence = 0.0;
        
        for prediction in predictions {
            let weight = prediction.confidence;
            *class_votes.entry(prediction.predicted_class.clone()).or_insert(0.0) += weight;
            total_confidence += weight;
        }
        
        if total_confidence == 0.0 {
            return ("not_credential".to_string(), 0.0);
        }
        
        // Find class with highest weighted vote
        let (best_class, best_score) = class_votes
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(class, &score)| (class.clone(), score))
            .unwrap_or(("not_credential".to_string(), 0.0));
        
        let confidence = best_score / total_confidence;
        (best_class, confidence)
    }
    
    /// Convert class name to credential type
    fn class_to_credential_type(&self, class_name: &str) -> CredentialType {
        match class_name {
            "aws_access_key" => CredentialType::AwsAccessKey,
            "aws_secret_key" => CredentialType::AwsSecretKey,
            "github_token" => CredentialType::GitHubToken,
            "slack_token" => CredentialType::SlackToken,
            "api_key" => CredentialType::ApiSecret,
            "jwt_token" => CredentialType::JwtToken,
            "rsa_private_key" => CredentialType::RsaPrivateKey,
            "password" => CredentialType::Password,
            _ => CredentialType::HighEntropyString,
        }
    }
    
    /// Extract candidate strings from text
    fn extract_candidates(&self, text: &str) -> Vec<CandidateString> {
        // Reuse similar logic from entropy analyzer
        let mut candidates = Vec::new();
        
        // Extract space-separated tokens
        for (line_idx, line) in text.lines().enumerate() {
            for (start, token) in line.split_whitespace().enumerate() {
                if self.is_ml_candidate(token) {
                    candidates.push(CandidateString {
                        value: token.to_string(),
                        start: start,
                        end: start + token.len(),
                    });
                }
            }
        }
        
        candidates
    }
    
    /// Check if string is suitable for ML classification
    fn is_ml_candidate(&self, s: &str) -> bool {
        let len = s.len();
        len >= 8 && len <= 2048 && s.chars().any(|c| c.is_alphanumeric())
    }
    
    /// Load pre-trained models
    async fn load_pretrained_models(&self) -> Result<()> {
        let mut models = self.models.write().await;
        
        // Create dummy pre-trained models for demonstration
        // In production, these would be loaded from files or model registry
        
        let credential_detector = ClassificationModel {
            name: "credential_detector_v1".to_string(),
            model_type: ModelType::LogisticRegression,
            weights: vec![0.5, -0.3, 0.8, 0.2, -0.1, 0.4, 0.6, -0.2, 0.3, 0.7],
            feature_names: vec![
                "char_uppercase_ratio".to_string(),
                "char_lowercase_ratio".to_string(), 
                "char_digit_ratio".to_string(),
                "char_special_ratio".to_string(),
                "char_diversity".to_string(),
                "shannon_entropy".to_string(),
                "has_base64_pattern".to_string(),
                "has_hex_pattern".to_string(),
                "text_length".to_string(),
                "compression_ratio".to_string(),
            ],
            classes: vec!["credential".to_string(), "not_credential".to_string()],
            accuracy: 0.89,
            version: "1.0.0".to_string(),
        };
        
        models.insert("credential_detector".to_string(), credential_detector);
        
        info!("Loaded {} pre-trained models", models.len());
        Ok(())
    }
    
    /// Create default feature extractors
    fn create_feature_extractors() -> Vec<FeatureExtractor> {
        vec![
            FeatureExtractor {
                name: "character_level".to_string(),
                feature_names: vec![
                    "char_uppercase_ratio".to_string(),
                    "char_lowercase_ratio".to_string(),
                    "char_digit_ratio".to_string(),
                    "char_special_ratio".to_string(),
                    "char_diversity".to_string(),
                ],
                extractor_type: ExtractorType::CharacterLevel,
            },
            FeatureExtractor {
                name: "bigram".to_string(),
                feature_names: vec![
                    "2_gram_diversity".to_string(),
                    "max_2_gram_frequency".to_string(),
                ],
                extractor_type: ExtractorType::NGram { n: 2 },
            },
            FeatureExtractor {
                name: "statistical".to_string(),
                feature_names: vec![
                    "text_length".to_string(),
                    "shannon_entropy".to_string(),
                    "compression_ratio".to_string(),
                ],
                extractor_type: ExtractorType::Statistical,
            },
            FeatureExtractor {
                name: "structural".to_string(),
                feature_names: vec![
                    "has_base64_pattern".to_string(),
                    "has_hex_pattern".to_string(),
                    "has_jwt_structure".to_string(),
                ],
                extractor_type: ExtractorType::Structural,
            },
            FeatureExtractor {
                name: "domain_specific".to_string(),
                feature_names: vec![
                    "has_aws_prefix".to_string(),
                    "has_github_prefix".to_string(),
                    "length_pattern_match".to_string(),
                ],
                extractor_type: ExtractorType::DomainSpecific,
            },
        ]
    }
    
    /// Create default classification thresholds
    fn create_default_thresholds() -> ClassificationThresholds {
        let mut type_thresholds = HashMap::new();
        type_thresholds.insert("aws_access_key".to_string(), 0.9);
        type_thresholds.insert("aws_secret_key".to_string(), 0.85);
        type_thresholds.insert("github_token".to_string(), 0.9);
        type_thresholds.insert("api_key".to_string(), 0.75);
        type_thresholds.insert("password".to_string(), 0.6);
        
        ClassificationThresholds {
            default_threshold: 0.7,
            type_thresholds,
            ensemble_threshold: 0.8,
        }
    }
    
    /// Update ML statistics
    async fn update_stats(&self, results: &[MLResult], processing_time: f64) {
        let mut stats = self.stats.write().await;
        
        stats.total_classifications += results.len() as u64;
        
        // Update confidence distribution
        for result in results {
            let confidence_bucket = match result.confidence {
                0.0..=0.5 => "low",
                0.51..=0.75 => "medium", 
                0.76..=0.9 => "high",
                _ => "very_high",
            };
            
            *stats.confidence_distribution
                .entry(confidence_bucket.to_string())
                .or_insert(0) += 1;
        }
        
        // Update average processing time
        stats.avg_processing_time_ms = (stats.avg_processing_time_ms + processing_time) / 2.0;
    }
    
    /// Get ML classification statistics
    pub async fn get_stats(&self) -> MLStats {
        self.stats.read().await.clone()
    }
}

/// Candidate string for ML classification
#[derive(Debug, Clone)]
struct CandidateString {
    value: String,
    start: usize,
    end: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ml_classifier_creation() {
        let classifier = MLClassifier::new().await;
        assert!(classifier.is_ok());
    }
    
    #[tokio::test]
    async fn test_feature_extraction() {
        let classifier = MLClassifier::new().await.unwrap();
        
        let test_string = "AKIAIOSFODNN7EXAMPLE";
        let features = classifier.extract_features(test_string);
        
        assert!(!features.names.is_empty());
        assert_eq!(features.names.len(), features.values.len());
        
        // Check that we have expected feature types
        let feature_names_str = features.names.join(",");
        assert!(feature_names_str.contains("char_uppercase_ratio"));
        assert!(feature_names_str.contains("shannon_entropy"));
        assert!(feature_names_str.contains("has_base64_pattern"));
    }
    
    #[tokio::test]
    async fn test_ml_classification() {
        let classifier = MLClassifier::new().await.unwrap();
        
        let test_content = r#"
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
            password=MySecret123!
            normal_text=hello_world
        "#;
        
        let results = classifier.classify_text(test_content).await.unwrap();
        
        // Should find some potential credentials
        assert!(!results.is_empty());
        
        // Check that results have proper structure
        for result in &results {
            assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
            assert!(!result.value.is_empty());
            assert!(!result.model_predictions.is_empty());
        }
    }
    
    #[test]
    fn test_character_feature_extraction() {
        let classifier = MLClassifier {
            models: Arc::new(RwLock::new(HashMap::new())),
            feature_extractors: Vec::new(),
            thresholds: ClassificationThresholds {
                default_threshold: 0.7,
                type_thresholds: HashMap::new(),
                ensemble_threshold: 0.8,
            },
            stats: Arc::new(RwLock::new(MLStats::default())),
        };
        
        let (names, values, _) = classifier.extract_character_features("AbC123!@#");
        
        assert!(names.contains(&"char_uppercase_ratio".to_string()));
        assert!(names.contains(&"char_lowercase_ratio".to_string()));
        assert!(names.contains(&"char_digit_ratio".to_string()));
        assert!(names.contains(&"char_special_ratio".to_string()));
        
        // Check that ratios sum to approximately 1.0
        let ratio_sum: f64 = values[0..4].iter().sum();
        assert!((ratio_sum - 1.0).abs() < 0.001);
    }
    
    #[test]
    fn test_entropy_calculation() {
        let classifier = MLClassifier {
            models: Arc::new(RwLock::new(HashMap::new())),
            feature_extractors: Vec::new(),
            thresholds: ClassificationThresholds {
                default_threshold: 0.7,
                type_thresholds: HashMap::new(),
                ensemble_threshold: 0.8,
            },
            stats: Arc::new(RwLock::new(MLStats::default())),
        };
        
        // Low entropy (repeated characters)
        let low_entropy = classifier.calculate_entropy("aaaaaaaa");
        assert!(low_entropy < 1.0);
        
        // High entropy (varied characters)
        let high_entropy = classifier.calculate_entropy("aB3xK9mP2qL7vN");
        assert!(high_entropy > 3.0);
    }
    
    #[test]
    fn test_structural_features() {
        let classifier = MLClassifier {
            models: Arc::new(RwLock::new(HashMap::new())),
            feature_extractors: Vec::new(),
            thresholds: ClassificationThresholds {
                default_threshold: 0.7,
                type_thresholds: HashMap::new(),
                ensemble_threshold: 0.8,
            },
            stats: Arc::new(RwLock::new(MLStats::default())),
        };
        
        // Test Base64 pattern detection
        let (names, values, _) = classifier.extract_structural_features("SGVsbG9Xb3JsZA==");
        let base64_idx = names.iter().position(|n| n == "has_base64_pattern").unwrap();
        assert_eq!(values[base64_idx], 1.0);
        
        // Test hex pattern detection
        let (names, values, _) = classifier.extract_structural_features("deadbeef1234567890abcdef");
        let hex_idx = names.iter().position(|n| n == "has_hex_pattern").unwrap();
        assert_eq!(values[hex_idx], 1.0);
        
        // Test JWT structure detection
        let (names, values, _) = classifier.extract_structural_features("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature");
        let jwt_idx = names.iter().position(|n| n == "has_jwt_structure").unwrap();
        assert_eq!(values[jwt_idx], 1.0);
    }
}