/**
 * SARIF 2.1.0 Static Analysis Results Interchange Format
 * 
 * Full compliance with SARIF 2.1.0 specification for GitHub Security Alerts,
 * Azure DevOps, and other security tooling platforms.
 * 
 * References:
 * - https://sarifweb.azurewebsites.net/
 * - https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{ScanReport, Finding, SeverityLevel};

/// SARIF Log - root object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// SARIF Run - represents a single run of an analysis tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub artifacts: Vec<SarifArtifact>,
    pub results: Vec<SarifResult>,
    pub invocations: Vec<SarifInvocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// SARIF Tool - information about the analysis tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifToolComponent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<SarifToolComponent>>,
}

/// SARIF Tool Component - driver or extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifToolComponent {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri", skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(rename = "productSuite", skip_serializing_if = "Option::is_none")]
    pub product_suite: Option<String>,
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<SarifRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notifications: Option<Vec<SarifNotification>>,
}

/// SARIF Rule - describes an analysis rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(rename = "defaultConfiguration", skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<SarifRuleConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// SARIF Message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

/// SARIF Result - represents a single analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<SarifLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<SarifLocation>>,
    #[serde(rename = "partialFingerprints", skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

/// SARIF Level
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SarifLevel {
    None,
    Note,
    Warning,
    Error,
}

/// SARIF Rule Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleConfiguration {
    pub level: SarifLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,
}

/// SARIF Artifact - represents a file or other artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifact {
    pub location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i64>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// SARIF Artifact Location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

/// SARIF Location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation", skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<SarifPhysicalLocation>,
}

/// SARIF Physical Location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// SARIF Region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<i32>,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<i32>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<i32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,
}

/// SARIF Artifact Content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// SARIF Invocation - represents tool invocation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifInvocation {
    #[serde(rename = "commandLine", skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(rename = "startTimeUtc", skip_serializing_if = "Option::is_none")]
    pub start_time_utc: Option<DateTime<Utc>>,
    #[serde(rename = "endTimeUtc", skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<DateTime<Utc>>,
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
}

/// SARIF Notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifNotification {
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub message: SarifMessage,
    pub level: SarifLevel,
}

/// SARIF Property Bag - extensible properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPropertyBag {
    #[serde(flatten)]
    pub properties: HashMap<String, serde_json::Value>,
}

/// SARIF Generator
pub struct SarifGenerator;

impl SarifGenerator {
    /// Convert scan report to SARIF format
    pub fn generate_sarif(report: &ScanReport) -> Result<SarifLog> {
        let tool = SarifTool {
            driver: SarifToolComponent {
                name: "Enterprise Credential Hunter".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                information_uri: Some("https://github.com/ech-security/enterprise-credential-hunter".to_string()),
                organization: Some("ECH Security".to_string()),
                product: Some("Enterprise Credential Hunter".to_string()),
                product_suite: Some("ECH Security Suite".to_string()),
                short_description: Some(SarifMessage {
                    text: Some("Advanced credential and secret detection tool".to_string()),
                    markdown: None,
                }),
                full_description: Some(SarifMessage {
                    text: Some("Enterprise-grade credential hunting tool with advanced detection capabilities".to_string()),
                    markdown: Some("**Enterprise Credential Hunter** is an advanced security tool designed to detect credentials, secrets, and sensitive data across various sources.".to_string()),
                }),
                rules: Some(Self::generate_rules(&report.findings)),
                notifications: None,
            },
            extensions: None,
        };

        let artifacts = Self::generate_artifacts(&report.findings);
        let results = Self::generate_results(&report.findings);
        let invocations = vec![Self::generate_invocation(&report)];

        let mut properties = HashMap::new();
        properties.insert("scan_id".to_string(), serde_json::Value::String(report.metadata.id.to_string()));
        properties.insert("compliance_score".to_string(), serde_json::Value::Number(
            serde_json::Number::from_f64(report.compliance.overall_score).unwrap()
        ));

        let run = SarifRun {
            tool,
            artifacts,
            results,
            invocations,
            properties: Some(SarifPropertyBag { properties }),
        };

        Ok(SarifLog {
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![run],
        })
    }

    /// Generate SARIF rules from findings
    fn generate_rules(findings: &[Finding]) -> Vec<SarifRule> {
        let mut rules = Vec::new();
        let mut rule_ids = std::collections::HashSet::new();

        for finding in findings {
            if rule_ids.contains(&finding.rule_id) {
                continue;
            }
            rule_ids.insert(finding.rule_id.clone());

            let rule = SarifRule {
                id: finding.rule_id.clone(),
                name: Some(finding.title.clone()),
                short_description: Some(SarifMessage {
                    text: Some(finding.title.clone()),
                    markdown: None,
                }),
                full_description: Some(SarifMessage {
                    text: Some(finding.description.clone()),
                    markdown: finding.remediation.as_ref().map(|r| format!("**Description:** {}\n\n**Remediation:** {}", finding.description, r)),
                }),
                default_configuration: Some(SarifRuleConfiguration {
                    level: Self::severity_to_sarif_level(&finding.severity),
                    enabled: Some(true),
                    rank: Some(Self::severity_to_rank(&finding.severity)),
                }),
                help: finding.remediation.as_ref().map(|remediation| SarifMessage {
                    text: Some(remediation.clone()),
                    markdown: Some(format!(
                        "## Remediation\n\n{}\n\n## References\n\n{}",
                        remediation,
                        finding.references.iter()
                            .map(|r| format!("- [{}]({})", r, r))
                            .collect::<Vec<_>>()
                            .join("\n")
                    )),
                }),
                help_uri: finding.references.get(0).cloned(),
                properties: Some(SarifPropertyBag {
                    properties: {
                        let mut props = HashMap::new();
                        props.insert("security_severity".to_string(), 
                            serde_json::Value::String(format!("{:.1}", finding.confidence * 10.0)));
                        props.insert("precision".to_string(), 
                            serde_json::Value::String(if finding.confidence >= 0.8 { "high" } else { "medium" }.to_string()));
                        props.insert("tags".to_string(), 
                            serde_json::Value::Array(finding.tags.iter().map(|t| serde_json::Value::String(t.clone())).collect()));
                        if !finding.mitre_techniques.is_empty() {
                            props.insert("mitre_techniques".to_string(),
                                serde_json::Value::Array(finding.mitre_techniques.iter().map(|t| serde_json::Value::String(t.clone())).collect()));
                        }
                        props
                    }
                }),
            };

            rules.push(rule);
        }

        rules
    }

    /// Generate SARIF artifacts from findings
    fn generate_artifacts(findings: &[Finding]) -> Vec<SarifArtifact> {
        let mut artifacts = Vec::new();
        let mut artifact_uris = std::collections::HashSet::new();

        for finding in findings {
            let uri = finding.location.file_path.clone();
            if artifact_uris.contains(&uri) {
                continue;
            }
            artifact_uris.insert(uri.clone());

            let artifact = SarifArtifact {
                location: SarifArtifactLocation {
                    uri: uri.clone(),
                    uri_base_id: Some("%SRCROOT%".to_string()),
                },
                length: None,
                mime_type: Self::detect_mime_type(&uri),
            };

            artifacts.push(artifact);
        }

        artifacts
    }

    /// Generate SARIF results from findings
    fn generate_results(findings: &[Finding]) -> Vec<SarifResult> {
        findings.iter().map(|finding| {
            let mut partial_fingerprints = HashMap::new();
            partial_fingerprints.insert("primaryLocationLineHash".to_string(), 
                format!("{:x}", md5::compute(format!("{}:{}", finding.location.file_path, finding.location.line.unwrap_or(0)))));

            let location = SarifLocation {
                physical_location: Some(SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: finding.location.file_path.clone(),
                        uri_base_id: Some("%SRCROOT%".to_string()),
                    },
                    region: Some(SarifRegion {
                        start_line: finding.location.line.map(|l| l as i32),
                        start_column: finding.location.column.map(|c| c as i32),
                        end_line: finding.location.line.map(|l| l as i32),
                        end_column: finding.location.column.map(|c| (c + 20) as i32),
                        snippet: finding.code_snippet.as_ref().map(|snippet| SarifArtifactContent {
                            text: Some(snippet.clone()),
                        }),
                    }),
                }),
            };

            let mut properties = HashMap::new();
            properties.insert("confidence".to_string(), 
                serde_json::Value::Number(serde_json::Number::from_f64(finding.confidence).unwrap()));
            properties.insert("finding_id".to_string(), 
                serde_json::Value::String(finding.id.to_string()));

            SarifResult {
                rule_id: Some(finding.rule_id.clone()),
                message: SarifMessage {
                    text: Some(format!("{}: {}", finding.title, finding.description)),
                    markdown: Some(format!(
                        "**{}**\n\n{}\n\n**Confidence:** {:.1}%\n\n**Remediation:** {}",
                        finding.title,
                        finding.description,
                        finding.confidence * 100.0,
                        finding.remediation.as_deref().unwrap_or("Review and remove if confirmed as credential")
                    )),
                },
                level: Some(Self::severity_to_sarif_level(&finding.severity)),
                locations: Some(vec![location]),
                partial_fingerprints: Some(partial_fingerprints),
                properties: Some(SarifPropertyBag { properties }),
            }
        }).collect()
    }

    /// Generate SARIF invocation
    fn generate_invocation(report: &ScanReport) -> SarifInvocation {
        SarifInvocation {
            command_line: Some("ech scan".to_string()),
            start_time_utc: Some(report.metadata.generated_at),
            end_time_utc: Some(report.metadata.generated_at + chrono::Duration::seconds(report.summary.scan_duration as i64)),
            execution_successful: true,
        }
    }

    /// Convert severity level to SARIF level
    fn severity_to_sarif_level(severity: &SeverityLevel) -> SarifLevel {
        match severity {
            SeverityLevel::Critical => SarifLevel::Error,
            SeverityLevel::High => SarifLevel::Error,
            SeverityLevel::Medium => SarifLevel::Warning,
            SeverityLevel::Low => SarifLevel::Warning,
            SeverityLevel::Info => SarifLevel::Note,
        }
    }

    /// Convert severity to rank (for priority ordering)
    fn severity_to_rank(severity: &SeverityLevel) -> f64 {
        match severity {
            SeverityLevel::Critical => 95.0,
            SeverityLevel::High => 85.0,
            SeverityLevel::Medium => 65.0,
            SeverityLevel::Low => 35.0,
            SeverityLevel::Info => 15.0,
        }
    }

    /// Detect MIME type from file extension
    fn detect_mime_type(file_path: &str) -> Option<String> {
        let extension = std::path::Path::new(file_path)
            .extension()
            .and_then(|ext| ext.to_str())?;

        match extension.to_lowercase().as_str() {
            "js" | "jsx" | "mjs" => Some("application/javascript".to_string()),
            "ts" | "tsx" => Some("application/typescript".to_string()),
            "py" => Some("text/x-python".to_string()),
            "java" => Some("text/x-java-source".to_string()),
            "rs" => Some("text/x-rust".to_string()),
            "go" => Some("text/x-go".to_string()),
            "yaml" | "yml" => Some("application/x-yaml".to_string()),
            "json" => Some("application/json".to_string()),
            _ => Some("text/plain".to_string()),
        }
    }

    /// Export SARIF to JSON string
    pub fn to_json(sarif: &SarifLog) -> Result<String> {
        Ok(serde_json::to_string_pretty(sarif)?)
    }

    /// Export SARIF to JSON file
    pub fn to_file(sarif: &SarifLog, file_path: &str) -> Result<()> {
        let json = Self::to_json(sarif)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::EchConfig;
    use crate::reporting::{ReportMetadata, AuthorInfo, ScanSummary, ComplianceAssessment, RiskMetrics, ScanStatistics, PerformanceMetrics, CoverageMetrics, DetectionMetrics, QualityMetrics, ValidationStatus, FindingLocation};
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_sarif_generation() {
        let finding = Finding {
            id: Uuid::new_v4(),
            rule_id: "ECH-AWS-001".to_string(),
            severity: SeverityLevel::High,
            confidence: 0.95,
            title: "AWS Access Key Detected".to_string(),
            description: "Hardcoded AWS access key found".to_string(),
            location: FindingLocation {
                file_path: "src/config.js".to_string(),
                line: Some(42),
                column: Some(15),
                start_pos: Some(1250),
                end_pos: Some(1270),
                physical_location: None,
            },
            code_snippet: Some("const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';".to_string()),
            remediation: Some("Remove hardcoded key and use environment variables".to_string()),
            references: vec!["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html".to_string()],
            tags: vec!["aws".to_string(), "credentials".to_string()],
            mitre_techniques: vec!["T1552.001".to_string()],
        };

        let report = ScanReport {
            metadata: ReportMetadata {
                id: Uuid::new_v4(),
                version: "1.0".to_string(),
                generated_at: Utc::now(),
                scanner_version: "1.0.0".to_string(),
                scan_config: EchConfig::default(),
                format: crate::reporting::ReportFormat::Sarif,
                author: AuthorInfo::default(),
            },
            summary: ScanSummary {
                files_scanned: 100,
                credentials_found: 1,
                unique_types: 1,
                high_severity: 1,
                medium_severity: 0,
                low_severity: 0,
                scan_duration: 30.5,
                coverage_percentage: 95.0,
            },
            findings: vec![finding],
            compliance: ComplianceAssessment {
                overall_score: 0.7,
                frameworks: HashMap::new(),
                failed_controls: Vec::new(),
                recommendations: Vec::new(),
            },
            risk_metrics: RiskMetrics {
                overall_risk: 0.8,
                credential_exposure: 0.9,
                breach_probability: 0.7,
                business_impact: 0.8,
                risk_by_category: HashMap::new(),
                trending: None,
            },
            recommendations: Vec::new(),
            statistics: ScanStatistics {
                performance: PerformanceMetrics {
                    total_time: 30.5,
                    files_per_second: 3.3,
                    bytes_per_second: 1024.0,
                    memory_usage: 128.0,
                    cpu_usage: 25.0,
                },
                coverage: CoverageMetrics {
                    file_types: HashMap::new(),
                    directory_coverage: 95.0,
                    excluded_files: 5,
                    skipped_files: 2,
                },
                detection: DetectionMetrics {
                    true_positives: 1,
                    false_positives: 0,
                    precision: 1.0,
                    recall: 0.95,
                    f1_score: 0.97,
                },
                quality: QualityMetrics {
                    avg_confidence: 0.95,
                    high_confidence: 1,
                    low_confidence: 0,
                    validation_status: ValidationStatus {
                        validated: 1,
                        pending: 0,
                        accuracy: 1.0,
                    },
                },
            },
        };

        let sarif = SarifGenerator::generate_sarif(&report).unwrap();
        
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        
        let run = &sarif.runs[0];
        assert_eq!(run.tool.driver.name, "Enterprise Credential Hunter");
        assert_eq!(run.results.len(), 1);
        
        let result = &run.results[0];
        assert_eq!(result.rule_id, Some("ECH-AWS-001".to_string()));
        assert!(matches!(result.level, Some(SarifLevel::Error)));
        
        // Test JSON serialization
        let json = SarifGenerator::to_json(&sarif).unwrap();
        assert!(json.contains("Enterprise Credential Hunter"));
        assert!(json.contains("ECH-AWS-001"));
    }
}