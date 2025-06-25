/**
 * ECH Context Analyzer - Intelligent Context-Aware Validation
 * 
 * This module provides context-aware validation to reduce false positives
 * and improve detection accuracy. Analyzes surrounding code, variable names,
 * file types, and linguistic patterns to determine if a detected string
 * is likely a real credential.
 * 
 * Features:
 * - Programming language detection and analysis
 * - Variable name pattern recognition
 * - File type context analysis
 * - Code structure understanding
 * - False positive reduction with ML
 * - Comment and documentation filtering
 */

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, trace};
use once_cell::sync::Lazy;

use super::engine::{DetectionResult, CredentialType};

/// Context analyzer for intelligent credential validation
pub struct ContextAnalyzer {
    /// Language-specific analyzers
    language_analyzers: HashMap<String, LanguageAnalyzer>,
    
    /// Variable name patterns
    variable_patterns: VariablePatterns,
    
    /// File extension mappings
    file_extensions: HashMap<String, String>,
    
    /// Context validation rules
    validation_rules: Vec<ContextRule>,
}

/// Language-specific code analysis
#[derive(Debug, Clone)]
struct LanguageAnalyzer {
    /// Language name
    pub name: String,
    
    /// Comment patterns
    pub comment_patterns: Vec<Regex>,
    
    /// String literal patterns
    pub string_patterns: Vec<Regex>,
    
    /// Variable assignment patterns
    pub assignment_patterns: Vec<Regex>,
    
    /// Import/include patterns
    pub import_patterns: Vec<Regex>,
    
    /// Function definition patterns
    pub function_patterns: Vec<Regex>,
}

/// Variable name pattern recognition
#[derive(Debug)]
struct VariablePatterns {
    /// Patterns indicating test/example data
    test_patterns: Vec<Regex>,
    
    /// Patterns indicating real credentials
    credential_patterns: Vec<Regex>,
    
    /// Patterns indicating configuration
    config_patterns: Vec<Regex>,
    
    /// Patterns indicating documentation
    docs_patterns: Vec<Regex>,
}

/// Context validation rule
#[derive(Debug, Clone)]
struct ContextRule {
    /// Rule name
    name: String,
    
    /// Credential types this rule applies to
    credential_types: Vec<CredentialType>,
    
    /// Positive indicators (increase confidence)
    positive_indicators: Vec<String>,
    
    /// Negative indicators (decrease confidence)
    negative_indicators: Vec<String>,
    
    /// Weight of this rule
    weight: f64,
}

/// Context analysis result
#[derive(Debug, Clone)]
pub struct ContextAnalysis {
    /// Overall validation score (0.0-1.0)
    pub validation_score: f64,
    
    /// Detected programming language
    pub detected_language: Option<String>,
    
    /// Variable context information
    pub variable_context: VariableContext,
    
    /// File context information
    pub file_context: FileContext,
    
    /// Code structure analysis
    pub code_context: CodeContext,
    
    /// Applied validation rules
    pub applied_rules: Vec<String>,
    
    /// Confidence adjustments
    pub confidence_adjustments: Vec<ConfidenceAdjustment>,
}

/// Variable context analysis
#[derive(Debug, Clone)]
pub struct VariableContext {
    /// Variable name if detected
    pub variable_name: Option<String>,
    
    /// Variable naming convention
    pub naming_convention: Option<String>,
    
    /// Is this likely a test/example variable?
    pub is_test_variable: bool,
    
    /// Is this likely a real credential variable?
    pub is_credential_variable: bool,
    
    /// Variable scope (local, global, class member, etc.)
    pub scope: Option<String>,
}

/// File context analysis
#[derive(Debug, Clone)]
pub struct FileContext {
    /// File extension
    pub extension: Option<String>,
    
    /// Detected file type
    pub file_type: Option<String>,
    
    /// Is this a configuration file?
    pub is_config_file: bool,
    
    /// Is this a test file?
    pub is_test_file: bool,
    
    /// Is this documentation?
    pub is_documentation: bool,
    
    /// File path indicators
    pub path_indicators: Vec<String>,
}

/// Code structure context
#[derive(Debug, Clone)]
pub struct CodeContext {
    /// Is the credential in a comment?
    pub in_comment: bool,
    
    /// Is the credential in a string literal?
    pub in_string_literal: bool,
    
    /// Is this in a function/method?
    pub in_function: bool,
    
    /// Is this in a class definition?
    pub in_class: bool,
    
    /// Is this in an import/include statement?
    pub in_import: bool,
    
    /// Surrounding code patterns
    pub surrounding_patterns: Vec<String>,
}

/// Confidence adjustment applied by rules
#[derive(Debug, Clone)]
pub struct ConfidenceAdjustment {
    /// Rule that made this adjustment
    pub rule_name: String,
    
    /// Adjustment amount (-1.0 to 1.0)
    pub adjustment: f64,
    
    /// Reason for adjustment
    pub reason: String,
}

// Language analyzers for common programming languages
static LANGUAGE_ANALYZERS: Lazy<HashMap<String, LanguageAnalyzer>> = Lazy::new(|| {
    let mut analyzers = HashMap::new();
    
    // Python analyzer
    analyzers.insert("python".to_string(), LanguageAnalyzer {
        name: "python".to_string(),
        comment_patterns: vec![
            Regex::new(r"#.*$").unwrap(),
            Regex::new(r#""{3}[\s\S]*?"{3}"#).unwrap(),
            Regex::new(r"'{3}[\s\S]*?'{3}").unwrap(),
        ],
        string_patterns: vec![
            Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*""#).unwrap(),
            Regex::new(r"'[^'\\]*(?:\\.[^'\\]*)*'").unwrap(),
            Regex::new(r#"f"[^"\\]*(?:\\.[^"\\]*)*""#).unwrap(),
        ],
        assignment_patterns: vec![
            Regex::new(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=").unwrap(),
        ],
        import_patterns: vec![
            Regex::new(r"^\s*import\s+").unwrap(),
            Regex::new(r"^\s*from\s+.+\s+import\s+").unwrap(),
        ],
        function_patterns: vec![
            Regex::new(r"^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap(),
            Regex::new(r"^\s*async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap(),
        ],
    });
    
    // JavaScript/TypeScript analyzer
    analyzers.insert("javascript".to_string(), LanguageAnalyzer {
        name: "javascript".to_string(),
        comment_patterns: vec![
            Regex::new(r"//.*$").unwrap(),
            Regex::new(r"/\*[\s\S]*?\*/").unwrap(),
        ],
        string_patterns: vec![
            Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*""#).unwrap(),
            Regex::new(r"'[^'\\]*(?:\\.[^'\\]*)*'").unwrap(),
            Regex::new(r"`[^`\\]*(?:\\.[^`\\]*)*`").unwrap(),
        ],
        assignment_patterns: vec![
            Regex::new(r"(const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=").unwrap(),
            Regex::new(r"([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[:=]").unwrap(),
        ],
        import_patterns: vec![
            Regex::new(r"^\s*import\s+").unwrap(),
            Regex::new(r"^\s*require\s*\(").unwrap(),
        ],
        function_patterns: vec![
            Regex::new(r"function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(").unwrap(),
            Regex::new(r"([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[:=]\s*function").unwrap(),
            Regex::new(r"([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[:=]\s*\(.*?\)\s*=>").unwrap(),
        ],
    });
    
    // Java analyzer
    analyzers.insert("java".to_string(), LanguageAnalyzer {
        name: "java".to_string(),
        comment_patterns: vec![
            Regex::new(r"//.*$").unwrap(),
            Regex::new(r"/\*[\s\S]*?\*/").unwrap(),
        ],
        string_patterns: vec![
            Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*""#).unwrap(),
        ],
        assignment_patterns: vec![
            Regex::new(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=").unwrap(),
        ],
        import_patterns: vec![
            Regex::new(r"^\s*import\s+").unwrap(),
        ],
        function_patterns: vec![
            Regex::new(r"(public|private|protected|static).*?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap(),
        ],
    });
    
    // Go analyzer
    analyzers.insert("go".to_string(), LanguageAnalyzer {
        name: "go".to_string(),
        comment_patterns: vec![
            Regex::new(r"//.*$").unwrap(),
            Regex::new(r"/\*[\s\S]*?\*/").unwrap(),
        ],
        string_patterns: vec![
            Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*""#).unwrap(),
            Regex::new(r"`[^`]*`").unwrap(),
        ],
        assignment_patterns: vec![
            Regex::new(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]").unwrap(),
        ],
        import_patterns: vec![
            Regex::new(r"^\s*import\s+").unwrap(),
        ],
        function_patterns: vec![
            Regex::new(r"func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(").unwrap(),
        ],
    });
    
    analyzers
});

impl ContextAnalyzer {
    /// Create a new context analyzer
    pub fn new() -> Result<Self> {
        let variable_patterns = VariablePatterns {
            test_patterns: vec![
                Regex::new(r"(?i)(test|example|demo|sample|mock|fake|dummy)").unwrap(),
                Regex::new(r"(?i)(placeholder|template|default)").unwrap(),
            ],
            credential_patterns: vec![
                Regex::new(r"(?i)(key|token|secret|password|pwd|pass|auth|credential)").unwrap(),
                Regex::new(r"(?i)(api|access|private|client|service)").unwrap(),
            ],
            config_patterns: vec![
                Regex::new(r"(?i)(config|setting|env|environment|option)").unwrap(),
            ],
            docs_patterns: vec![
                Regex::new(r"(?i)(doc|readme|example|tutorial|guide)").unwrap(),
            ],
        };
        
        let file_extensions = [
            ("py", "python"),
            ("js", "javascript"),
            ("ts", "typescript"),
            ("jsx", "javascript"),
            ("tsx", "typescript"),
            ("java", "java"),
            ("go", "go"),
            ("rs", "rust"),
            ("c", "c"),
            ("cpp", "cpp"),
            ("h", "c"),
            ("hpp", "cpp"),
            ("php", "php"),
            ("rb", "ruby"),
            ("yaml", "yaml"),
            ("yml", "yaml"),
            ("json", "json"),
            ("xml", "xml"),
            ("toml", "toml"),
            ("ini", "ini"),
            ("conf", "config"),
            ("config", "config"),
            ("env", "env"),
            ("properties", "properties"),
        ].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        
        let validation_rules = vec![
            ContextRule {
                name: "test_file_penalty".to_string(),
                credential_types: vec![], // Applies to all
                positive_indicators: vec![],
                negative_indicators: vec!["test".to_string(), "spec".to_string(), "example".to_string()],
                weight: -0.5,
            },
            ContextRule {
                name: "config_file_boost".to_string(),
                credential_types: vec![], // Applies to all
                positive_indicators: vec!["config".to_string(), "env".to_string(), "settings".to_string()],
                negative_indicators: vec![],
                weight: 0.3,
            },
            ContextRule {
                name: "comment_penalty".to_string(),
                credential_types: vec![], // Applies to all
                positive_indicators: vec![],
                negative_indicators: vec!["comment".to_string()],
                weight: -0.7,
            },
            ContextRule {
                name: "production_boost".to_string(),
                credential_types: vec![], // Applies to all
                positive_indicators: vec!["prod".to_string(), "production".to_string(), "live".to_string()],
                negative_indicators: vec![],
                weight: 0.4,
            },
        ];
        
        Ok(Self {
            language_analyzers: LANGUAGE_ANALYZERS.clone(),
            variable_patterns,
            file_extensions,
            validation_rules,
        })
    }
    
    /// Validate a credential detection using context analysis
    pub async fn validate_credential(
        &self,
        detection: &DetectionResult,
        full_content: &str,
    ) -> Result<f64> {
        let context_analysis = self.analyze_context(detection, full_content).await?;
        
        debug!(
            "Context validation for {}: score={:.2}, language={:?}",
            detection.credential_type,
            context_analysis.validation_score,
            context_analysis.detected_language
        );
        
        Ok(context_analysis.validation_score)
    }
    
    /// Perform comprehensive context analysis
    pub async fn analyze_context(
        &self,
        detection: &DetectionResult,
        full_content: &str,
    ) -> Result<ContextAnalysis> {
        // Detect programming language
        let detected_language = self.detect_language(&detection.location.path, full_content);
        
        // Analyze variable context
        let variable_context = self.analyze_variable_context(detection, full_content);
        
        // Analyze file context
        let file_context = self.analyze_file_context(&detection.location.path);
        
        // Analyze code structure
        let code_context = self.analyze_code_structure(detection, full_content, &detected_language);
        
        // Apply validation rules
        let (validation_score, applied_rules, confidence_adjustments) = 
            self.apply_validation_rules(detection, &variable_context, &file_context, &code_context);
        
        Ok(ContextAnalysis {
            validation_score,
            detected_language,
            variable_context,
            file_context,
            code_context,
            applied_rules,
            confidence_adjustments,
        })
    }
    
    /// Detect programming language from file path and content
    fn detect_language(&self, file_path: &str, content: &str) -> Option<String> {
        // First try file extension
        if let Some(extension) = std::path::Path::new(file_path)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            if let Some(language) = self.file_extensions.get(extension) {
                return Some(language.clone());
            }
        }
        
        // Try content-based detection
        for (lang_name, analyzer) in &self.language_analyzers {
            let mut score = 0;
            
            // Check for language-specific patterns
            for pattern in &analyzer.comment_patterns {
                if pattern.is_match(content) {
                    score += 1;
                }
            }
            
            for pattern in &analyzer.function_patterns {
                if pattern.is_match(content) {
                    score += 2;
                }
            }
            
            for pattern in &analyzer.import_patterns {
                if pattern.is_match(content) {
                    score += 2;
                }
            }
            
            if score >= 2 {
                return Some(lang_name.clone());
            }
        }
        
        None
    }
    
    /// Analyze variable naming context
    fn analyze_variable_context(&self, detection: &DetectionResult, content: &str) -> VariableContext {
        let variable_name = self.extract_variable_name_from_context(detection, content);
        
        let mut is_test_variable = false;
        let mut is_credential_variable = false;
        let mut naming_convention = None;
        
        if let Some(ref var_name) = variable_name {
            let var_lower = var_name.to_lowercase();
            
            // Check for test patterns
            for pattern in &self.variable_patterns.test_patterns {
                if pattern.is_match(&var_lower) {
                    is_test_variable = true;
                    break;
                }
            }
            
            // Check for credential patterns
            for pattern in &self.variable_patterns.credential_patterns {
                if pattern.is_match(&var_lower) {
                    is_credential_variable = true;
                    break;
                }
            }
            
            // Detect naming convention
            naming_convention = self.detect_naming_convention(var_name);
        }
        
        VariableContext {
            variable_name,
            naming_convention,
            is_test_variable,
            is_credential_variable,
            scope: None, // TODO: Implement scope detection
        }
    }
    
    /// Analyze file context
    fn analyze_file_context(&self, file_path: &str) -> FileContext {
        let path = std::path::Path::new(file_path);
        let extension = path.extension().and_then(|ext| ext.to_str()).map(|s| s.to_string());
        let file_type = extension.as_ref().and_then(|ext| self.file_extensions.get(ext)).cloned();
        
        let path_lower = file_path.to_lowercase();
        
        let is_config_file = path_lower.contains("config") 
            || path_lower.contains("settings") 
            || path_lower.contains(".env")
            || matches!(extension.as_deref(), Some("conf" | "ini" | "yaml" | "yml" | "toml"));
        
        let is_test_file = path_lower.contains("test") 
            || path_lower.contains("spec") 
            || path_lower.contains("__test__")
            || path_lower.contains("tests/");
        
        let is_documentation = path_lower.contains("readme") 
            || path_lower.contains("doc") 
            || path_lower.contains("example")
            || matches!(extension.as_deref(), Some("md" | "rst" | "txt"));
        
        let mut path_indicators = Vec::new();
        if path_lower.contains("prod") || path_lower.contains("production") {
            path_indicators.push("production".to_string());
        }
        if path_lower.contains("dev") || path_lower.contains("development") {
            path_indicators.push("development".to_string());
        }
        if path_lower.contains("staging") {
            path_indicators.push("staging".to_string());
        }
        
        FileContext {
            extension,
            file_type,
            is_config_file,
            is_test_file,
            is_documentation,
            path_indicators,
        }
    }
    
    /// Analyze code structure around the detection
    fn analyze_code_structure(
        &self,
        detection: &DetectionResult,
        content: &str,
        detected_language: &Option<String>,
    ) -> CodeContext {
        let detection_start = detection.location.line_number.unwrap_or(0).saturating_sub(1);
        let detection_end = detection_start + 1;
        
        let lines: Vec<&str> = content.lines().collect();
        let context_start = detection_start.saturating_sub(5);
        let context_end = std::cmp::min(detection_end + 5, lines.len());
        
        let context_lines = if context_start < lines.len() && context_end <= lines.len() {
            lines[context_start..context_end].join("\n")
        } else {
            String::new()
        };
        
        let mut code_context = CodeContext {
            in_comment: false,
            in_string_literal: false,
            in_function: false,
            in_class: false,
            in_import: false,
            surrounding_patterns: Vec::new(),
        };
        
        // Analyze with language-specific patterns if available
        if let Some(lang_name) = detected_language {
            if let Some(analyzer) = self.language_analyzers.get(lang_name) {
                // Check for comments
                for pattern in &analyzer.comment_patterns {
                    if pattern.is_match(&context_lines) {
                        code_context.in_comment = true;
                        break;
                    }
                }
                
                // Check for string literals
                for pattern in &analyzer.string_patterns {
                    if pattern.is_match(&context_lines) {
                        code_context.in_string_literal = true;
                        break;
                    }
                }
                
                // Check for functions
                for pattern in &analyzer.function_patterns {
                    if pattern.is_match(&context_lines) {
                        code_context.in_function = true;
                        break;
                    }
                }
                
                // Check for imports
                for pattern in &analyzer.import_patterns {
                    if pattern.is_match(&context_lines) {
                        code_context.in_import = true;
                        break;
                    }
                }
            }
        }
        
        // Generic pattern detection
        let generic_patterns = [
            ("class_definition", r"(?i)class\s+"),
            ("function_call", r"\w+\s*\("),
            ("assignment", r"="),
            ("environment_var", r"(?i)(env|environment)"),
            ("configuration", r"(?i)(config|setting)"),
        ];
        
        for (pattern_name, pattern_str) in &generic_patterns {
            if let Ok(regex) = Regex::new(pattern_str) {
                if regex.is_match(&context_lines) {
                    code_context.surrounding_patterns.push(pattern_name.to_string());
                }
            }
        }
        
        code_context
    }
    
    /// Apply validation rules to calculate final score
    fn apply_validation_rules(
        &self,
        detection: &DetectionResult,
        variable_context: &VariableContext,
        file_context: &FileContext,
        code_context: &CodeContext,
    ) -> (f64, Vec<String>, Vec<ConfidenceAdjustment>) {
        let mut score = 0.5; // Base score
        let mut applied_rules = Vec::new();
        let mut adjustments = Vec::new();
        
        for rule in &self.validation_rules {
            // Check if rule applies to this credential type
            if !rule.credential_types.is_empty() 
                && !rule.credential_types.contains(&detection.credential_type) {
                continue;
            }
            
            let mut rule_applies = false;
            let mut adjustment_reason = String::new();
            
            // Check positive indicators
            for indicator in &rule.positive_indicators {
                let indicator_lower = indicator.to_lowercase();
                
                if file_context.file_type.as_ref().map_or(false, |ft| ft.contains(&indicator_lower))
                    || variable_context.variable_name.as_ref().map_or(false, |vn| vn.to_lowercase().contains(&indicator_lower))
                    || code_context.surrounding_patterns.iter().any(|p| p.contains(&indicator_lower))
                {
                    rule_applies = true;
                    adjustment_reason = format!("Positive indicator: {}", indicator);
                    break;
                }
            }
            
            // Check negative indicators
            for indicator in &rule.negative_indicators {
                let indicator_lower = indicator.to_lowercase();
                
                if file_context.is_test_file && indicator == "test"
                    || file_context.is_documentation && indicator == "example"
                    || code_context.in_comment && indicator == "comment"
                    || variable_context.is_test_variable && indicator == "test"
                    || file_context.file_type.as_ref().map_or(false, |ft| ft.contains(&indicator_lower))
                    || variable_context.variable_name.as_ref().map_or(false, |vn| vn.to_lowercase().contains(&indicator_lower))
                {
                    rule_applies = true;
                    adjustment_reason = format!("Negative indicator: {}", indicator);
                    break;
                }
            }
            
            if rule_applies {
                score += rule.weight;
                applied_rules.push(rule.name.clone());
                adjustments.push(ConfidenceAdjustment {
                    rule_name: rule.name.clone(),
                    adjustment: rule.weight,
                    reason: adjustment_reason,
                });
            }
        }
        
        // Additional specific adjustments
        
        // Boost for credential variable names
        if variable_context.is_credential_variable && !variable_context.is_test_variable {
            score += 0.2;
            adjustments.push(ConfidenceAdjustment {
                rule_name: "credential_variable_boost".to_string(),
                adjustment: 0.2,
                reason: "Variable name indicates credential".to_string(),
            });
        }
        
        // Penalty for being in documentation
        if file_context.is_documentation {
            score -= 0.4;
            adjustments.push(ConfidenceAdjustment {
                rule_name: "documentation_penalty".to_string(),
                adjustment: -0.4,
                reason: "Found in documentation file".to_string(),
            });
        }
        
        // Boost for production environment indicators
        if file_context.path_indicators.contains(&"production".to_string()) {
            score += 0.3;
            adjustments.push(ConfidenceAdjustment {
                rule_name: "production_boost".to_string(),
                adjustment: 0.3,
                reason: "Found in production path".to_string(),
            });
        }
        
        // Clamp score to valid range
        score = score.max(0.0).min(1.0);
        
        (score, applied_rules, adjustments)
    }
    
    /// Extract variable name from detection context
    fn extract_variable_name_from_context(&self, detection: &DetectionResult, content: &str) -> Option<String> {
        // Try to get from detection result first
        if let Some(ref var_name) = detection.context.variable_name {
            return Some(var_name.clone());
        }
        
        // Extract from surrounding context
        let lines: Vec<&str> = content.lines().collect();
        let line_num = detection.location.line_number.unwrap_or(1).saturating_sub(1);
        
        if line_num < lines.len() {
            let line = lines[line_num];
            
            // Common variable assignment patterns
            let patterns = [
                r"([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]",
                r#""([a-zA-Z_][a-zA-Z0-9_]*)"\s*:"#,
                r"'([a-zA-Z_][a-zA-Z0-9_]*)'\s*:",
                r"([A-Z_][A-Z0-9_]*)\s*=",
                r"export\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
                r"const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
                r"let\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
                r"var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
            ];
            
            for pattern_str in &patterns {
                if let Ok(regex) = Regex::new(pattern_str) {
                    if let Some(captures) = regex.captures(line) {
                        if let Some(var_match) = captures.get(1) {
                            return Some(var_match.as_str().to_string());
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Detect variable naming convention
    fn detect_naming_convention(&self, variable_name: &str) -> Option<String> {
        if variable_name.contains('_') && variable_name.chars().all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '_') {
            Some("snake_case".to_string())
        } else if variable_name.chars().any(|c| c.is_uppercase()) 
            && variable_name.chars().next().map_or(false, |c| c.is_lowercase()) {
            Some("camelCase".to_string())
        } else if variable_name.chars().next().map_or(false, |c| c.is_uppercase()) {
            Some("PascalCase".to_string())
        } else if variable_name.chars().all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_') {
            Some("SCREAMING_SNAKE_CASE".to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::engine::{CredentialLocation, CredentialContext, DetectionMetadata};
    use chrono::Utc;
    use uuid::Uuid;
    
    #[tokio::test]
    async fn test_context_analyzer_creation() {
        let analyzer = ContextAnalyzer::new();
        assert!(analyzer.is_ok());
    }
    
    #[test]
    fn test_language_detection() {
        let analyzer = ContextAnalyzer::new().unwrap();
        
        // Test file extension detection
        let python_lang = analyzer.detect_language("script.py", "");
        assert_eq!(python_lang, Some("python".to_string()));
        
        let js_lang = analyzer.detect_language("app.js", "");
        assert_eq!(js_lang, Some("javascript".to_string()));
        
        // Test content-based detection
        let python_content = r#"
            def hello_world():
                print("Hello")
            import os
        "#;
        let detected = analyzer.detect_language("unknown", python_content);
        assert_eq!(detected, Some("python".to_string()));
    }
    
    #[test]
    fn test_file_context_analysis() {
        let analyzer = ContextAnalyzer::new().unwrap();
        
        // Test config file detection
        let config_context = analyzer.analyze_file_context("/etc/app/config.yaml");
        assert!(config_context.is_config_file);
        assert_eq!(config_context.extension, Some("yaml".to_string()));
        
        // Test test file detection
        let test_context = analyzer.analyze_file_context("/src/tests/test_auth.py");
        assert!(test_context.is_test_file);
        
        // Test documentation detection
        let doc_context = analyzer.analyze_file_context("README.md");
        assert!(doc_context.is_documentation);
    }
    
    #[test]
    fn test_variable_context_analysis() {
        let analyzer = ContextAnalyzer::new().unwrap();
        
        let detection = create_test_detection("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE");
        let content = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'";
        
        let var_context = analyzer.analyze_variable_context(&detection, content);
        assert!(var_context.is_credential_variable);
        assert!(!var_context.is_test_variable);
    }
    
    #[tokio::test]
    async fn test_validation_scoring() {
        let analyzer = ContextAnalyzer::new().unwrap();
        
        // Test production config file (should boost score)
        let prod_detection = create_test_detection_with_location(
            "API_KEY", 
            "sk_live_TEST_PLACEHOLDER_MASKED",
            "/etc/app/production.config"
        );
        let content = "API_KEY=sk_live_TEST_PLACEHOLDER_MASKED";
        
        let score = analyzer.validate_credential(&prod_detection, content).await.unwrap();
        assert!(score > 0.6, "Production config should have high score: {}", score);
        
        // Test test file (should reduce score)
        let test_detection = create_test_detection_with_location(
            "TEST_API_KEY",
            "sk_test_123456789", 
            "/src/tests/test_api.py"
        );
        let test_content = "TEST_API_KEY = 'sk_test_123456789'  # Test key for unit tests";
        
        let test_score = analyzer.validate_credential(&test_detection, test_content).await.unwrap();
        assert!(test_score < 0.4, "Test file should have low score: {}", test_score);
    }
    
    #[test]
    fn test_naming_convention_detection() {
        let analyzer = ContextAnalyzer::new().unwrap();
        
        assert_eq!(
            analyzer.detect_naming_convention("api_key"),
            Some("snake_case".to_string())
        );
        
        assert_eq!(
            analyzer.detect_naming_convention("apiKey"),
            Some("camelCase".to_string())
        );
        
        assert_eq!(
            analyzer.detect_naming_convention("ApiKey"),
            Some("PascalCase".to_string())
        );
        
        assert_eq!(
            analyzer.detect_naming_convention("API_KEY"),
            Some("SCREAMING_SNAKE_CASE".to_string())
        );
    }
    
    // Helper functions for tests
    fn create_test_detection(var_name: &str, value: &str) -> DetectionResult {
        DetectionResult {
            id: Uuid::new_v4(),
            credential_type: CredentialType::ApiSecret,
            confidence: crate::detection::engine::ConfidenceLevel::High,
            masked_value: value.to_string(),
            full_value: Some(value.to_string()),
            location: CredentialLocation {
                source_type: "file".to_string(),
                path: "/test/config".to_string(),
                line_number: Some(1),
                column: Some(1),
                memory_address: None,
                process_id: None,
                container_id: None,
            },
            context: CredentialContext {
                surrounding_text: format!("{}={}", var_name, value),
                variable_name: Some(var_name.to_string()),
                file_type: None,
                language: None,
                context_clues: Vec::new(),
            },
            metadata: DetectionMetadata {
                detection_methods: vec!["pattern".to_string()],
                pattern_name: Some("test_pattern".to_string()),
                entropy_score: None,
                ml_confidence: None,
                yara_matches: Vec::new(),
                processing_time_us: 100,
            },
            risk_level: crate::detection::engine::RiskLevel::Medium,
            recommended_actions: Vec::new(),
            timestamp: Utc::now(),
        }
    }
    
    fn create_test_detection_with_location(var_name: &str, value: &str, path: &str) -> DetectionResult {
        let mut detection = create_test_detection(var_name, value);
        detection.location.path = path.to_string();
        detection
    }
}