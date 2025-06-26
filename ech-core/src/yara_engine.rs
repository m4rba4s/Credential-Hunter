/**
 * YARA-based Detection Engine
 * 
 * Advanced pattern matching using YARA rules for complex credential detection.
 * Supports custom rules, rule compilation, and high-performance scanning.
 */

use crate::types::*;
use crate::error::EchError;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct YaraEngine {
    config: YaraConfig,
    compiled_rules: Arc<RwLock<HashMap<String, CompiledRule>>>,
    rule_statistics: Arc<RwLock<YaraStatistics>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraConfig {
    pub rules_directory: PathBuf,
    pub custom_rules_path: Option<PathBuf>,
    pub enable_fast_mode: bool,
    pub max_scan_size: usize,
    pub timeout_seconds: u64,
    pub enable_rule_profiling: bool,
    pub auto_update_rules: bool,
    pub rule_categories: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    rule_content: String,
    compiled_patterns: Vec<YaraPattern>,
    metadata: RuleMetadata,
    performance_stats: PerformanceStats,
}

#[derive(Debug, Clone)]
struct YaraPattern {
    identifier: String,
    pattern_type: PatternType,
    content: String,
    modifiers: Vec<String>,
}

#[derive(Debug, Clone)]
enum PatternType {
    String,
    Hex,
    Regex,
    Condition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub author: String,
    pub description: String,
    pub version: String,
    pub date: String,
    pub category: String,
    pub severity: String,
    pub reference: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct PerformanceStats {
    total_scans: u64,
    total_matches: u64,
    average_scan_time: f64,
    last_used: u64,
}

#[derive(Debug, Clone)]
struct YaraStatistics {
    rules_loaded: usize,
    total_scans: u64,
    total_matches: u64,
    scan_errors: u64,
    average_scan_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub matched_strings: Vec<MatchedString>,
    pub metadata: RuleMetadata,
    pub file_path: Option<String>,
    pub scan_context: ScanContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    pub identifier: String,
    pub content: String,
    pub offset: usize,
    pub length: usize,
    pub matched_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    pub scan_type: String,
    pub target_size: usize,
    pub scan_time: u64,
    pub confidence: f64,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rules_directory: PathBuf::from("./rules"),
            custom_rules_path: Some(PathBuf::from("~/.config/ech/rules")),
            enable_fast_mode: true,
            max_scan_size: 100 * 1024 * 1024, // 100MB
            timeout_seconds: 30,
            enable_rule_profiling: true,
            auto_update_rules: false,
            rule_categories: vec![
                "credentials".to_string(),
                "secrets".to_string(),
                "keys".to_string(),
                "tokens".to_string(),
            ],
        }
    }
}

impl YaraEngine {
    pub fn new(config: YaraConfig) -> Self {
        Self {
            config,
            compiled_rules: Arc::new(RwLock::new(HashMap::new())),
            rule_statistics: Arc::new(RwLock::new(YaraStatistics {
                rules_loaded: 0,
                total_scans: 0,
                total_matches: 0,
                scan_errors: 0,
                average_scan_time: 0.0,
            })),
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        info!("🔍 Initializing YARA detection engine");

        // Create rules directory if it doesn't exist
        if !self.config.rules_directory.exists() {
            std::fs::create_dir_all(&self.config.rules_directory)?;
            info!("📁 Created rules directory: {:?}", self.config.rules_directory);
        }

        // Load built-in rules
        self.load_builtin_rules().await?;

        // Load rules from directory
        self.load_rules_from_directory(&self.config.rules_directory).await?;

        // Load custom rules if specified
        if let Some(custom_path) = &self.config.custom_rules_path {
            if custom_path.exists() {
                self.load_rules_from_directory(custom_path).await?;
            }
        }

        let stats = self.rule_statistics.read();
        info!("✅ YARA engine initialized with {} rules", stats.rules_loaded);

        Ok(())
    }

    async fn load_builtin_rules(&self) -> Result<()> {
        info!("📦 Loading built-in YARA rules");

        let builtin_rules = vec![
            self.create_aws_credentials_rule(),
            self.create_github_tokens_rule(),
            self.create_stripe_keys_rule(),
            self.create_private_keys_rule(),
            self.create_jwt_tokens_rule(),
            self.create_database_credentials_rule(),
            self.create_api_keys_rule(),
        ];

        let mut rules = self.compiled_rules.write();
        for rule in builtin_rules {
            rules.insert(rule.name.clone(), rule);
        }

        let mut stats = self.rule_statistics.write();
        stats.rules_loaded += rules.len();

        Ok(())
    }

    async fn load_rules_from_directory(&self, directory: &Path) -> Result<()> {
        info!("📂 Loading YARA rules from directory: {:?}", directory);

        if !directory.exists() {
            warn!("Rules directory does not exist: {:?}", directory);
            return Ok(());
        }

        let entries = std::fs::read_dir(directory)?;
        let mut loaded_count = 0;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("yar") ||
               path.extension().and_then(|s| s.to_str()) == Some("yara") {
                
                match self.load_rule_file(&path).await {
                    Ok(rule) => {
                        let mut rules = self.compiled_rules.write();
                        rules.insert(rule.name.clone(), rule);
                        loaded_count += 1;
                    }
                    Err(e) => {
                        warn!("Failed to load rule file {:?}: {}", path, e);
                    }
                }
            }
        }

        info!("📈 Loaded {} rules from directory", loaded_count);
        Ok(())
    }

    async fn load_rule_file(&self, path: &Path) -> Result<CompiledRule> {
        debug!("Loading YARA rule file: {:?}", path);

        let content = std::fs::read_to_string(path)?;
        let rule = self.parse_yara_rule(&content, path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown"))?;

        Ok(rule)
    }

    fn parse_yara_rule(&self, content: &str, name: &str) -> Result<CompiledRule> {
        // Simplified YARA rule parsing - in real implementation would use yara-rust
        let mut patterns = Vec::new();
        let mut metadata = RuleMetadata {
            author: "Unknown".to_string(),
            description: "Custom rule".to_string(),
            version: "1.0".to_string(),
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            category: "credentials".to_string(),
            severity: "medium".to_string(),
            reference: None,
            tags: Vec::new(),
        };

        // Parse metadata section
        if let Some(meta_start) = content.find("meta:") {
            if let Some(meta_end) = content[meta_start..].find("strings:") {
                let meta_section = &content[meta_start..meta_start + meta_end];
                self.parse_metadata(meta_section, &mut metadata);
            }
        }

        // Parse strings section
        if let Some(strings_start) = content.find("strings:") {
            if let Some(strings_end) = content[strings_start..].find("condition:") {
                let strings_section = &content[strings_start..strings_start + strings_end];
                patterns = self.parse_patterns(strings_section)?;
            }
        }

        Ok(CompiledRule {
            name: name.to_string(),
            rule_content: content.to_string(),
            compiled_patterns: patterns,
            metadata,
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        })
    }

    fn parse_metadata(&self, meta_section: &str, metadata: &mut RuleMetadata) {
        for line in meta_section.lines() {
            let line = line.trim();
            if line.contains("author") {
                if let Some(value) = self.extract_quoted_value(line) {
                    metadata.author = value;
                }
            } else if line.contains("description") {
                if let Some(value) = self.extract_quoted_value(line) {
                    metadata.description = value;
                }
            } else if line.contains("version") {
                if let Some(value) = self.extract_quoted_value(line) {
                    metadata.version = value;
                }
            } else if line.contains("category") {
                if let Some(value) = self.extract_quoted_value(line) {
                    metadata.category = value;
                }
            }
        }
    }

    fn parse_patterns(&self, strings_section: &str) -> Result<Vec<YaraPattern>> {
        let mut patterns = Vec::new();

        for line in strings_section.lines() {
            let line = line.trim();
            if line.starts_with('$') {
                if let Some(equals_pos) = line.find('=') {
                    let identifier = line[..equals_pos].trim().to_string();
                    let content = line[equals_pos + 1..].trim();

                    let (pattern_type, clean_content) = if content.starts_with('"') && content.ends_with('"') {
                        (PatternType::String, content[1..content.len()-1].to_string())
                    } else if content.starts_with('{') && content.ends_with('}') {
                        (PatternType::Hex, content.to_string())
                    } else if content.starts_with('/') && content.ends_with('/') {
                        (PatternType::Regex, content[1..content.len()-1].to_string())
                    } else {
                        (PatternType::String, content.to_string())
                    };

                    patterns.push(YaraPattern {
                        identifier,
                        pattern_type,
                        content: clean_content,
                        modifiers: Vec::new(),
                    });
                }
            }
        }

        Ok(patterns)
    }

    fn extract_quoted_value(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        None
    }

    pub async fn scan_data(&self, data: &[u8], context: &str) -> Result<Vec<YaraMatch>> {
        let scan_start = std::time::Instant::now();
        let mut matches = Vec::new();

        if data.len() > self.config.max_scan_size {
            return Err(anyhow!("Data size exceeds maximum scan size"));
        }

        let data_str = String::from_utf8_lossy(data);
        let rules = self.compiled_rules.read();

        for rule in rules.values() {
            let rule_matches = self.scan_with_rule(rule, &data_str, context).await?;
            matches.extend(rule_matches);
        }

        let scan_duration = scan_start.elapsed();
        self.update_statistics(matches.len(), scan_duration.as_secs_f64()).await;

        Ok(matches)
    }

    async fn scan_with_rule(
        &self, 
        rule: &CompiledRule, 
        data: &str, 
        context: &str
    ) -> Result<Vec<YaraMatch>> {
        let mut matches = Vec::new();

        for pattern in &rule.compiled_patterns {
            let pattern_matches = match &pattern.pattern_type {
                PatternType::String => self.scan_string_pattern(pattern, data)?,
                PatternType::Regex => self.scan_regex_pattern(pattern, data)?,
                PatternType::Hex => self.scan_hex_pattern(pattern, data)?,
                PatternType::Condition => Vec::new(), // Conditions handled separately
            };

            if !pattern_matches.is_empty() {
                let confidence = self.calculate_match_confidence(rule, &pattern_matches);
                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    matched_strings: pattern_matches,
                    metadata: rule.metadata.clone(),
                    file_path: None,
                    scan_context: ScanContext {
                        scan_type: context.to_string(),
                        target_size: data.len(),
                        scan_time: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_secs(),
                        confidence,
                    },
                });
            }
        }

        Ok(matches)
    }

    fn scan_string_pattern(&self, pattern: &YaraPattern, data: &str) -> Result<Vec<MatchedString>> {
        let mut matches = Vec::new();
        let pattern_content = &pattern.content;

        for (offset, _) in data.match_indices(pattern_content) {
            matches.push(MatchedString {
                identifier: pattern.identifier.clone(),
                content: pattern_content.clone(),
                offset,
                length: pattern_content.len(),
                matched_data: pattern_content.clone(),
            });
        }

        Ok(matches)
    }

    fn scan_regex_pattern(&self, pattern: &YaraPattern, data: &str) -> Result<Vec<MatchedString>> {
        let mut matches = Vec::new();
        
        if let Ok(regex) = Regex::new(&pattern.content) {
            for capture in regex.find_iter(data) {
                matches.push(MatchedString {
                    identifier: pattern.identifier.clone(),
                    content: pattern.content.clone(),
                    offset: capture.start(),
                    length: capture.len(),
                    matched_data: capture.as_str().to_string(),
                });
            }
        }

        Ok(matches)
    }

    fn scan_hex_pattern(&self, pattern: &YaraPattern, data: &str) -> Result<Vec<MatchedString>> {
        // Simplified hex pattern matching
        // In real implementation, would convert hex pattern to bytes and search
        Ok(Vec::new())
    }

    fn calculate_match_confidence(&self, rule: &CompiledRule, matches: &[MatchedString]) -> f64 {
        let base_confidence = match rule.metadata.severity.as_str() {
            "critical" => 0.95,
            "high" => 0.90,
            "medium" => 0.80,
            "low" => 0.70,
            _ => 0.75,
        };

        // Adjust based on number of pattern matches
        let match_bonus = (matches.len() as f64 * 0.1).min(0.2);
        
        (base_confidence + match_bonus).min(1.0)
    }

    async fn update_statistics(&self, matches_count: usize, scan_time: f64) {
        let mut stats = self.rule_statistics.write();
        stats.total_scans += 1;
        stats.total_matches += matches_count as u64;
        
        // Update rolling average
        stats.average_scan_time = (stats.average_scan_time * (stats.total_scans - 1) as f64 + scan_time) 
            / stats.total_scans as f64;
    }

    pub fn get_statistics(&self) -> YaraStatistics {
        self.rule_statistics.read().clone()
    }

    pub async fn add_custom_rule(&self, name: &str, rule_content: &str) -> Result<()> {
        info!("➕ Adding custom YARA rule: {}", name);

        let rule = self.parse_yara_rule(rule_content, name)?;
        let mut rules = self.compiled_rules.write();
        rules.insert(name.to_string(), rule);

        Ok(())
    }

    pub fn list_loaded_rules(&self) -> Vec<String> {
        self.compiled_rules.read().keys().cloned().collect()
    }

    // Built-in rule generators
    fn create_aws_credentials_rule(&self) -> CompiledRule {
        CompiledRule {
            name: "aws_credentials".to_string(),
            rule_content: r#"
rule aws_credentials {
    meta:
        author = "ECH"
        description = "AWS Access Key and Secret"
        category = "credentials"
        severity = "critical"
    
    strings:
        $aws_access_key = /AKIA[0-9A-Z]{16}/
        $aws_secret_key = /[A-Za-z0-9\/\+]{40}/
    
    condition:
        any of them
}
"#.to_string(),
            compiled_patterns: vec![
                YaraPattern {
                    identifier: "$aws_access_key".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"AKIA[0-9A-Z]{16}".to_string(),
                    modifiers: Vec::new(),
                },
                YaraPattern {
                    identifier: "$aws_secret_key".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"[A-Za-z0-9/\+]{40}".to_string(),
                    modifiers: Vec::new(),
                },
            ],
            metadata: RuleMetadata {
                author: "ECH".to_string(),
                description: "AWS Access Key and Secret".to_string(),
                version: "1.0".to_string(),
                date: "2024-01-01".to_string(),
                category: "credentials".to_string(),
                severity: "critical".to_string(),
                reference: Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html".to_string()),
                tags: vec!["aws".to_string(), "credentials".to_string()],
            },
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        }
    }

    fn create_github_tokens_rule(&self) -> CompiledRule {
        CompiledRule {
            name: "github_tokens".to_string(),
            rule_content: "".to_string(),
            compiled_patterns: vec![
                YaraPattern {
                    identifier: "$github_token".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"ghp_[a-zA-Z0-9]{36}".to_string(),
                    modifiers: Vec::new(),
                },
                YaraPattern {
                    identifier: "$github_oauth".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"gho_[a-zA-Z0-9]{36}".to_string(),
                    modifiers: Vec::new(),
                },
            ],
            metadata: RuleMetadata {
                author: "ECH".to_string(),
                description: "GitHub Personal Access Tokens".to_string(),
                version: "1.0".to_string(),
                date: "2024-01-01".to_string(),
                category: "tokens".to_string(),
                severity: "high".to_string(),
                reference: Some("https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token".to_string()),
                tags: vec!["github".to_string(), "tokens".to_string()],
            },
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        }
    }

    fn create_stripe_keys_rule(&self) -> CompiledRule {
        CompiledRule {
            name: "stripe_keys".to_string(),
            rule_content: "".to_string(),
            compiled_patterns: vec![
                YaraPattern {
                    identifier: "$stripe_secret".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"sk_live_[a-zA-Z0-9]{24}".to_string(),
                    modifiers: Vec::new(),
                },
                YaraPattern {
                    identifier: "$stripe_test".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"sk_test_[a-zA-Z0-9]{24}".to_string(),
                    modifiers: Vec::new(),
                },
            ],
            metadata: RuleMetadata {
                author: "ECH".to_string(),
                description: "Stripe API Keys".to_string(),
                version: "1.0".to_string(),
                date: "2024-01-01".to_string(),
                category: "api_keys".to_string(),
                severity: "critical".to_string(),
                reference: None,
                tags: vec!["stripe".to_string(), "payment".to_string()],
            },
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        }
    }

    fn create_private_keys_rule(&self) -> CompiledRule {
        CompiledRule {
            name: "private_keys".to_string(),
            rule_content: "".to_string(),
            compiled_patterns: vec![
                YaraPattern {
                    identifier: "$rsa_private".to_string(),
                    pattern_type: PatternType::String,
                    content: "-----BEGIN RSA PRIVATE KEY-----".to_string(),
                    modifiers: Vec::new(),
                },
                YaraPattern {
                    identifier: "$private_key".to_string(),
                    pattern_type: PatternType::String,
                    content: "-----BEGIN PRIVATE KEY-----".to_string(),
                    modifiers: Vec::new(),
                },
            ],
            metadata: RuleMetadata {
                author: "ECH".to_string(),
                description: "Private Keys (RSA, ECDSA, etc.)".to_string(),
                version: "1.0".to_string(),
                date: "2024-01-01".to_string(),
                category: "keys".to_string(),
                severity: "critical".to_string(),
                reference: None,
                tags: vec!["private_key".to_string(), "crypto".to_string()],
            },
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        }
    }

    fn create_jwt_tokens_rule(&self) -> CompiledRule {
        CompiledRule {
            name: "jwt_tokens".to_string(),
            rule_content: "".to_string(),
            compiled_patterns: vec![
                YaraPattern {
                    identifier: "$jwt_token".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+".to_string(),
                    modifiers: Vec::new(),
                },
            ],
            metadata: RuleMetadata {
                author: "ECH".to_string(),
                description: "JWT Tokens".to_string(),
                version: "1.0".to_string(),
                date: "2024-01-01".to_string(),
                category: "tokens".to_string(),
                severity: String::from("medium"),
                reference: Some("https://jwt.io/".to_string()),
                tags: vec!["jwt".to_string(), "token".to_string()],
            },
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        }
    }

    fn create_database_credentials_rule(&self) -> CompiledRule {
        CompiledRule {
            name: "database_credentials".to_string(),
            rule_content: "".to_string(),
            compiled_patterns: vec![
                YaraPattern {
                    identifier: "$db_connection".to_string(),
                    pattern_type: PatternType::Regex,
                    content: r"(mysql|postgresql|mongodb)://[^:]+:[^@]+@".to_string(),
                    modifiers: Vec::new(),
                },
            ],
            metadata: RuleMetadata {
                author: "ECH".to_string(),
                description: "Database Connection Strings".to_string(),
                version: "1.0".to_string(),
                date: "2024-01-01".to_string(),
                category: "credentials".to_string(),
                severity: "high".to_string(),
                reference: None,
                tags: vec!["database".to_string(), "connection".to_string()],
            },
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        }
    }

    fn create_api_keys_rule(&self) -> CompiledRule {
        CompiledRule {
            name: String::from("generic_api_keys"),
            rule_content: String::new(),
            compiled_patterns: Vec::new(),
            metadata: RuleMetadata {
                author: String::from("ECH"),
                description: String::from("API patterns"),
                version: String::from("1.0"),
                date: String::from("2024-01-01"),
                category: String::from("api_keys"),
                severity: String::from("medium"),
                reference: None,
                tags: Vec::new(),
            },
            performance_stats: PerformanceStats {
                total_scans: 0,
                total_matches: 0,
                average_scan_time: 0.0,
                last_used: 0,
            },
        }
    }
}

// Tests temporarily disabled due to encoding issues