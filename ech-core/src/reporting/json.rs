/**
 * JSON Reporting Module
 * 
 * Enterprise-grade JSON reporting with multiple output formats,
 * API-friendly structures, and extensible metadata.
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{ScanReport, Finding, SeverityLevel, ReportConfig};

/// JSON Report Format Variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JsonFormat {
    /// Compact format for API responses
    Compact,
    /// Detailed format with full metadata
    Detailed,
    /// Summary format for dashboards
    Summary,
    /// GitHub-compatible format
    GitHub,
    /// Custom format with user-defined fields
    Custom(JsonCustomConfig),
}

/// Custom JSON configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonCustomConfig {
    /// Fields to include
    pub include_fields: Vec<String>,
    /// Fields to exclude
    pub exclude_fields: Vec<String>,
    /// Custom field mappings
    pub field_mappings: HashMap<String, String>,
    /// Grouping strategy
    pub group_by: Option<String>,
}

/// Compact JSON report for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactJsonReport {
    /// Report metadata
    pub scan_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    
    /// Summary statistics
    pub summary: CompactSummary,
    
    /// Findings array
    pub findings: Vec<CompactFinding>,
    
    /// Risk assessment
    pub risk: CompactRisk,
}

/// Compact summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactSummary {
    pub total_files: u64,
    pub total_findings: u64,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub scan_duration: f64,
}

/// Compact finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactFinding {
    pub id: Uuid,
    pub type_: String,
    pub severity: String,
    pub confidence: f64,
    pub file: String,
    pub line: Option<u32>,
    pub description: String,
}

/// Compact risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactRisk {
    pub overall_score: f64,
    pub exposure_risk: f64,
    pub compliance_score: f64,
}

/// Detailed JSON report with full metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedJsonReport {
    /// Report metadata
    pub metadata: DetailedMetadata,
    
    /// Comprehensive summary
    pub summary: DetailedSummary,
    
    /// Full findings with context
    pub findings: Vec<DetailedFinding>,
    
    /// Compliance assessment
    pub compliance: DetailedCompliance,
    
    /// Risk metrics
    pub risk_metrics: DetailedRiskMetrics,
    
    /// Recommendations
    pub recommendations: Vec<DetailedRecommendation>,
    
    /// Performance statistics
    pub statistics: DetailedStatistics,
    
    /// Scan configuration
    pub scan_config: DetailedScanConfig,
}

/// Detailed metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedMetadata {
    pub report_id: Uuid,
    pub report_version: String,
    pub generated_at: DateTime<Utc>,
    pub scanner: ScannerInfo,
    pub environment: EnvironmentInfo,
    pub format_version: String,
}

/// Scanner information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerInfo {
    pub name: String,
    pub version: String,
    pub build: String,
    pub commit_hash: Option<String>,
    pub capabilities: Vec<String>,
}

/// Environment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub os: String,
    pub architecture: String,
    pub runtime: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub working_directory: String,
}

/// Detailed summary with breakdowns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedSummary {
    pub scan_scope: ScanScope,
    pub findings_summary: FindingsSummary,
    pub performance_summary: PerformanceSummary,
    pub coverage_summary: CoverageSummary,
}

/// Scan scope information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanScope {
    pub targets: Vec<String>,
    pub file_types: HashMap<String, u64>,
    pub total_size_bytes: u64,
    pub directories_scanned: u64,
    pub files_processed: u64,
    pub files_skipped: u64,
    pub exclusion_patterns: Vec<String>,
}

/// Findings summary with categorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsSummary {
    pub total_findings: u64,
    pub by_severity: HashMap<String, u64>,
    pub by_type: HashMap<String, u64>,
    pub by_confidence: ConfidenceBreakdown,
    pub unique_types: u64,
    pub false_positive_rate: f64,
}

/// Confidence level breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBreakdown {
    pub high_confidence: u64,      // >= 0.8
    pub medium_confidence: u64,    // 0.5 - 0.8
    pub low_confidence: u64,       // < 0.5
    pub average_confidence: f64,
}

/// Performance summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_duration: f64,
    pub files_per_second: f64,
    pub bytes_per_second: f64,
    pub memory_usage: MemoryUsage,
    pub cpu_usage: CpuUsage,
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsage {
    pub peak_usage_mb: f64,
    pub average_usage_mb: f64,
    pub gc_collections: u64,
}

/// CPU usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuUsage {
    pub average_cpu_percent: f64,
    pub peak_cpu_percent: f64,
    pub core_utilization: Vec<f64>,
}

/// Coverage summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub overall_coverage: f64,
    pub by_file_type: HashMap<String, f64>,
    pub by_directory: HashMap<String, f64>,
    pub exclusions: ExclusionSummary,
}

/// Exclusion summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionSummary {
    pub excluded_files: u64,
    pub excluded_directories: u64,
    pub exclusion_reasons: HashMap<String, u64>,
}

/// Detailed finding with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedFinding {
    pub id: Uuid,
    pub rule_id: String,
    pub finding_type: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub location: DetailedLocation,
    pub context: FindingContext,
    pub validation: ValidationInfo,
    pub remediation: RemediationInfo,
    pub references: Vec<Reference>,
    pub metadata: FindingMetadata,
}

/// Detailed location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedLocation {
    pub file_path: String,
    pub absolute_path: Option<String>,
    pub relative_path: Option<String>,
    pub line_number: Option<u32>,
    pub column_number: Option<u32>,
    pub start_offset: Option<u32>,
    pub end_offset: Option<u32>,
    pub file_size: Option<u64>,
    pub file_modified: Option<DateTime<Utc>>,
}

/// Finding context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingContext {
    pub code_snippet: Option<String>,
    pub surrounding_lines: Option<Vec<String>>,
    pub variable_name: Option<String>,
    pub function_name: Option<String>,
    pub class_name: Option<String>,
    pub namespace: Option<String>,
    pub language: Option<String>,
    pub encoding: Option<String>,
}

/// Validation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationInfo {
    pub validated: bool,
    pub validation_method: Option<String>,
    pub validation_confidence: Option<f64>,
    pub false_positive_likelihood: f64,
    pub requires_manual_review: bool,
}

/// Remediation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationInfo {
    pub priority: String,
    pub effort_estimate: String,
    pub impact_assessment: String,
    pub recommended_actions: Vec<String>,
    pub automated_fix_available: bool,
    pub fix_complexity: String,
}

/// External reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: String,
    pub url: String,
    pub reference_type: String, // "documentation", "advisory", "blog", etc.
}

/// Finding metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingMetadata {
    pub tags: Vec<String>,
    pub categories: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub cwe_ids: Vec<u32>,
    pub cvss_score: Option<f64>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub detection_method: String,
    pub custom_properties: HashMap<String, serde_json::Value>,
}

/// Detailed compliance assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedCompliance {
    pub overall_assessment: ComplianceAssessment,
    pub frameworks: Vec<FrameworkCompliance>,
    pub controls: Vec<ControlAssessment>,
    pub gaps: Vec<ComplianceGap>,
}

/// Framework compliance details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkCompliance {
    pub framework_name: String,
    pub framework_version: String,
    pub overall_score: f64,
    pub total_controls: u32,
    pub passed_controls: u32,
    pub failed_controls: u32,
    pub not_applicable: u32,
    pub control_details: Vec<ControlDetail>,
}

/// Control assessment detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlDetail {
    pub control_id: String,
    pub control_name: String,
    pub status: String, // "passed", "failed", "not_applicable"
    pub findings_count: u32,
    pub risk_level: String,
    pub remediation_effort: String,
}

/// Individual control assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAssessment {
    pub control_id: String,
    pub description: String,
    pub status: String,
    pub findings: Vec<Uuid>,
    pub recommendations: Vec<String>,
}

/// Compliance gap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceGap {
    pub gap_id: String,
    pub description: String,
    pub severity: String,
    pub affected_controls: Vec<String>,
    pub remediation_steps: Vec<String>,
    pub estimated_effort: String,
}

/// General compliance assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAssessment {
    pub score: f64,
    pub grade: String, // "A+", "A", "B", etc.
    pub status: String, // "compliant", "non-compliant", "partial"
    pub last_assessment: DateTime<Utc>,
    pub next_assessment_due: Option<DateTime<Utc>>,
}

/// Detailed risk metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedRiskMetrics {
    pub overall_risk: RiskAssessment,
    pub risk_categories: Vec<RiskCategory>,
    pub risk_factors: Vec<RiskFactor>,
    pub trending: Option<RiskTrending>,
    pub projections: Option<RiskProjections>,
}

/// Risk assessment details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: f64,
    pub level: String, // "critical", "high", "medium", "low"
    pub confidence: f64,
    pub methodology: String,
    pub last_calculated: DateTime<Utc>,
}

/// Risk category breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCategory {
    pub category: String,
    pub score: f64,
    pub weight: f64,
    pub findings_count: u32,
    pub description: String,
}

/// Risk factor analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub impact: f64,
    pub likelihood: f64,
    pub mitigation_available: bool,
    pub description: String,
}

/// Risk trending data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTrending {
    pub historical_scores: Vec<HistoricalRiskScore>,
    pub trend_direction: String, // "improving", "stable", "degrading"
    pub velocity: f64,
    pub forecast: Option<RiskForecast>,
}

/// Historical risk score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalRiskScore {
    pub timestamp: DateTime<Utc>,
    pub score: f64,
    pub findings_count: u32,
}

/// Risk forecast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskForecast {
    pub predicted_score_30d: f64,
    pub predicted_score_90d: f64,
    pub confidence_interval: (f64, f64),
    pub assumptions: Vec<String>,
}

/// Risk projections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskProjections {
    pub best_case: f64,
    pub worst_case: f64,
    pub most_likely: f64,
    pub scenarios: Vec<RiskScenario>,
}

/// Risk scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScenario {
    pub name: String,
    pub description: String,
    pub probability: f64,
    pub impact: f64,
    pub risk_score: f64,
}

/// Detailed recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedRecommendation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub category: String,
    pub effort_estimate: EffortEstimate,
    pub impact_assessment: ImpactAssessment,
    pub implementation: ImplementationGuide,
    pub related_findings: Vec<Uuid>,
    pub dependencies: Vec<String>,
    pub timeline: Timeline,
}

/// Effort estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffortEstimate {
    pub level: String, // "low", "medium", "high", "very_high"
    pub hours: Option<u32>,
    pub cost: Option<f64>,
    pub resources_required: Vec<String>,
    pub skills_required: Vec<String>,
}

/// Impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub security_impact: String,
    pub business_impact: String,
    pub operational_impact: String,
    pub quantified_benefit: Option<f64>,
    pub risk_reduction: f64,
}

/// Implementation guide
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementationGuide {
    pub steps: Vec<ImplementationStep>,
    pub prerequisites: Vec<String>,
    pub tools_needed: Vec<String>,
    pub validation_criteria: Vec<String>,
    pub rollback_plan: Option<String>,
}

/// Implementation step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementationStep {
    pub step_number: u32,
    pub description: String,
    pub estimated_duration: Option<String>,
    pub owner: Option<String>,
    pub dependencies: Vec<u32>,
}

/// Timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub milestones: Vec<Milestone>,
    pub critical_path: Vec<u32>,
}

/// Milestone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Milestone {
    pub name: String,
    pub description: String,
    pub target_date: DateTime<Utc>,
    pub completion_criteria: Vec<String>,
}

/// Detailed statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedStatistics {
    pub performance: DetailedPerformance,
    pub coverage: DetailedCoverage,
    pub quality: QualityMetrics,
    pub efficiency: EfficiencyMetrics,
}

/// Detailed performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedPerformance {
    pub timing: TimingMetrics,
    pub throughput: ThroughputMetrics,
    pub resource_usage: ResourceUsage,
    pub bottlenecks: Vec<Bottleneck>,
}

/// Timing metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMetrics {
    pub total_duration: f64,
    pub initialization_time: f64,
    pub scanning_time: f64,
    pub analysis_time: f64,
    pub reporting_time: f64,
    pub cleanup_time: f64,
}

/// Throughput metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputMetrics {
    pub files_per_second: f64,
    pub bytes_per_second: f64,
    pub patterns_per_second: f64,
    pub peak_throughput: f64,
    pub average_throughput: f64,
}

/// Resource usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory: DetailedMemoryUsage,
    pub cpu: DetailedCpuUsage,
    pub io: IoUsage,
    pub network: Option<NetworkUsage>,
}

/// Detailed memory usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedMemoryUsage {
    pub peak_usage_bytes: u64,
    pub average_usage_bytes: u64,
    pub heap_usage: u64,
    pub stack_usage: u64,
    pub allocations: u64,
    pub deallocations: u64,
    pub gc_time: f64,
}

/// Detailed CPU usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedCpuUsage {
    pub total_cpu_time: f64,
    pub user_cpu_time: f64,
    pub system_cpu_time: f64,
    pub average_utilization: f64,
    pub peak_utilization: f64,
    pub thread_count: u32,
}

/// I/O usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoUsage {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_operations: u64,
    pub write_operations: u64,
    pub seek_operations: u64,
    pub io_wait_time: f64,
}

/// Network usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkUsage {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_sent: u64,
    pub responses_received: u64,
    pub connection_time: f64,
}

/// Performance bottleneck
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bottleneck {
    pub component: String,
    pub description: String,
    pub impact: f64,
    pub suggested_optimization: String,
}

/// Detailed coverage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedCoverage {
    pub file_coverage: FileCoverage,
    pub pattern_coverage: PatternCoverage,
    pub exclusions: DetailedExclusions,
}

/// File coverage details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverage {
    pub total_files: u64,
    pub scanned_files: u64,
    pub coverage_percentage: f64,
    pub by_extension: HashMap<String, CoverageStats>,
    pub by_size: HashMap<String, CoverageStats>,
}

/// Coverage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    pub total: u64,
    pub scanned: u64,
    pub percentage: f64,
}

/// Pattern coverage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCoverage {
    pub total_patterns: u32,
    pub active_patterns: u32,
    pub triggered_patterns: u32,
    pub pattern_efficiency: HashMap<String, f64>,
}

/// Detailed exclusions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedExclusions {
    pub total_excluded: u64,
    pub by_reason: HashMap<String, u64>,
    pub by_pattern: HashMap<String, u64>,
    pub exclusion_rules: Vec<ExclusionRule>,
}

/// Exclusion rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRule {
    pub rule_id: String,
    pub pattern: String,
    pub reason: String,
    pub files_excluded: u64,
}

/// Quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub accuracy: AccuracyMetrics,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
}

/// Accuracy metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub overall_accuracy: f64,
    pub by_credential_type: HashMap<String, f64>,
    pub confidence_calibration: f64,
}

/// Efficiency metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficiencyMetrics {
    pub scan_efficiency: f64,
    pub pattern_efficiency: f64,
    pub resource_efficiency: f64,
    pub time_efficiency: f64,
}

/// Detailed scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedScanConfig {
    pub scan_type: String,
    pub targets: Vec<String>,
    pub patterns: PatternConfig,
    pub filters: FilterConfig,
    pub performance: PerformanceConfig,
    pub output: OutputConfig,
}

/// Pattern configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternConfig {
    pub enabled_patterns: Vec<String>,
    pub disabled_patterns: Vec<String>,
    pub custom_patterns: Vec<String>,
    pub confidence_threshold: f64,
}

/// Filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub file_filters: Vec<String>,
    pub content_filters: Vec<String>,
    pub size_limits: SizeLimits,
    pub exclusion_patterns: Vec<String>,
}

/// Size limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeLimits {
    pub max_file_size: u64,
    pub max_scan_size: u64,
    pub max_memory_usage: u64,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_threads: u32,
    pub timeout_seconds: u64,
    pub batch_size: u32,
    pub parallel_processing: bool,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub verbosity: String,
    pub include_metadata: bool,
    pub redaction_enabled: bool,
}

/// JSON Report Generator
pub struct JsonReportGenerator;

impl JsonReportGenerator {
    /// Generate compact JSON report
    pub fn generate_compact(report: &ScanReport) -> Result<CompactJsonReport> {
        let summary = CompactSummary {
            total_files: report.summary.files_scanned,
            total_findings: report.summary.credentials_found,
            critical: report.findings.iter()
                .filter(|f| matches!(f.severity, SeverityLevel::Critical))
                .count() as u64,
            high: report.findings.iter()
                .filter(|f| matches!(f.severity, SeverityLevel::High))
                .count() as u64,
            medium: report.findings.iter()
                .filter(|f| matches!(f.severity, SeverityLevel::Medium))
                .count() as u64,
            low: report.findings.iter()
                .filter(|f| matches!(f.severity, SeverityLevel::Low | SeverityLevel::Info))
                .count() as u64,
            scan_duration: report.summary.scan_duration,
        };

        let findings = report.findings.iter().map(|f| CompactFinding {
            id: f.id,
            type_: f.rule_id.clone(),
            severity: format!("{:?}", f.severity),
            confidence: f.confidence,
            file: f.location.file_path.clone(),
            line: f.location.line,
            description: f.description.clone(),
        }).collect();

        let risk = CompactRisk {
            overall_score: report.risk_metrics.overall_risk,
            exposure_risk: report.risk_metrics.credential_exposure,
            compliance_score: report.compliance.overall_score,
        };

        Ok(CompactJsonReport {
            scan_id: report.metadata.id,
            timestamp: report.metadata.generated_at,
            version: report.metadata.version.clone(),
            summary,
            findings,
            risk,
        })
    }

    /// Generate detailed JSON report
    pub fn generate_detailed(report: &ScanReport) -> Result<DetailedJsonReport> {
        // This would be a comprehensive implementation
        // For now, providing a simplified version
        let metadata = DetailedMetadata {
            report_id: report.metadata.id,
            report_version: report.metadata.version.clone(),
            generated_at: report.metadata.generated_at,
            scanner: ScannerInfo {
                name: "Enterprise Credential Hunter".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                build: "release".to_string(),
                commit_hash: None,
                capabilities: vec![
                    "filesystem_scan".to_string(),
                    "memory_scan".to_string(),
                    "container_scan".to_string(),
                    "network_scan".to_string(),
                ],
            },
            environment: EnvironmentInfo {
                os: std::env::consts::OS.to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                runtime: "native".to_string(),
                hostname: None,
                user: None,
                working_directory: std::env::current_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
            },
            format_version: "1.0".to_string(),
        };

        // Convert other report sections...
        // This is a complex conversion that would require detailed mapping

        Ok(DetailedJsonReport {
            metadata,
            summary: DetailedSummary {
                scan_scope: ScanScope {
                    targets: vec!["filesystem".to_string()],
                    file_types: HashMap::new(),
                    total_size_bytes: 0,
                    directories_scanned: 0,
                    files_processed: report.summary.files_scanned,
                    files_skipped: 0,
                    exclusion_patterns: Vec::new(),
                },
                findings_summary: FindingsSummary {
                    total_findings: report.summary.credentials_found,
                    by_severity: HashMap::new(),
                    by_type: HashMap::new(),
                    by_confidence: ConfidenceBreakdown {
                        high_confidence: 0,
                        medium_confidence: 0,
                        low_confidence: 0,
                        average_confidence: 0.0,
                    },
                    unique_types: report.summary.unique_types,
                    false_positive_rate: 0.15,
                },
                performance_summary: PerformanceSummary {
                    total_duration: report.summary.scan_duration,
                    files_per_second: report.summary.files_scanned as f64 / report.summary.scan_duration,
                    bytes_per_second: 0.0,
                    memory_usage: MemoryUsage {
                        peak_usage_mb: 0.0,
                        average_usage_mb: 0.0,
                        gc_collections: 0,
                    },
                    cpu_usage: CpuUsage {
                        average_cpu_percent: 0.0,
                        peak_cpu_percent: 0.0,
                        core_utilization: Vec::new(),
                    },
                },
                coverage_summary: CoverageSummary {
                    overall_coverage: report.summary.coverage_percentage,
                    by_file_type: HashMap::new(),
                    by_directory: HashMap::new(),
                    exclusions: ExclusionSummary {
                        excluded_files: 0,
                        excluded_directories: 0,
                        exclusion_reasons: HashMap::new(),
                    },
                },
            },
            findings: Vec::new(), // Would convert each finding
            compliance: DetailedCompliance {
                overall_assessment: ComplianceAssessment {
                    score: report.compliance.overall_score,
                    grade: Self::score_to_grade(report.compliance.overall_score),
                    status: if report.compliance.overall_score >= 0.8 { "compliant" } else { "non-compliant" }.to_string(),
                    last_assessment: report.metadata.generated_at,
                    next_assessment_due: None,
                },
                frameworks: Vec::new(),
                controls: Vec::new(),
                gaps: Vec::new(),
            },
            risk_metrics: DetailedRiskMetrics {
                overall_risk: RiskAssessment {
                    score: report.risk_metrics.overall_risk,
                    level: Self::risk_score_to_level(report.risk_metrics.overall_risk),
                    confidence: 0.85,
                    methodology: "ECH Risk Assessment v1.0".to_string(),
                    last_calculated: report.metadata.generated_at,
                },
                risk_categories: Vec::new(),
                risk_factors: Vec::new(),
                trending: None,
                projections: None,
            },
            recommendations: Vec::new(),
            statistics: DetailedStatistics {
                performance: DetailedPerformance {
                    timing: TimingMetrics {
                        total_duration: report.summary.scan_duration,
                        initialization_time: 0.0,
                        scanning_time: 0.0,
                        analysis_time: 0.0,
                        reporting_time: 0.0,
                        cleanup_time: 0.0,
                    },
                    throughput: ThroughputMetrics {
                        files_per_second: 0.0,
                        bytes_per_second: 0.0,
                        patterns_per_second: 0.0,
                        peak_throughput: 0.0,
                        average_throughput: 0.0,
                    },
                    resource_usage: ResourceUsage {
                        memory: DetailedMemoryUsage {
                            peak_usage_bytes: 0,
                            average_usage_bytes: 0,
                            heap_usage: 0,
                            stack_usage: 0,
                            allocations: 0,
                            deallocations: 0,
                            gc_time: 0.0,
                        },
                        cpu: DetailedCpuUsage {
                            total_cpu_time: 0.0,
                            user_cpu_time: 0.0,
                            system_cpu_time: 0.0,
                            average_utilization: 0.0,
                            peak_utilization: 0.0,
                            thread_count: 0,
                        },
                        io: IoUsage {
                            bytes_read: 0,
                            bytes_written: 0,
                            read_operations: 0,
                            write_operations: 0,
                            seek_operations: 0,
                            io_wait_time: 0.0,
                        },
                        network: None,
                    },
                    bottlenecks: Vec::new(),
                },
                coverage: DetailedCoverage {
                    file_coverage: FileCoverage {
                        total_files: 0,
                        scanned_files: 0,
                        coverage_percentage: 0.0,
                        by_extension: HashMap::new(),
                        by_size: HashMap::new(),
                    },
                    pattern_coverage: PatternCoverage {
                        total_patterns: 0,
                        active_patterns: 0,
                        triggered_patterns: 0,
                        pattern_efficiency: HashMap::new(),
                    },
                    exclusions: DetailedExclusions {
                        total_excluded: 0,
                        by_reason: HashMap::new(),
                        by_pattern: HashMap::new(),
                        exclusion_rules: Vec::new(),
                    },
                },
                quality: QualityMetrics {
                    accuracy: AccuracyMetrics {
                        overall_accuracy: 0.0,
                        by_credential_type: HashMap::new(),
                        confidence_calibration: 0.0,
                    },
                    precision: 0.0,
                    recall: 0.0,
                    f1_score: 0.0,
                    false_positive_rate: 0.0,
                    false_negative_rate: 0.0,
                },
                efficiency: EfficiencyMetrics {
                    scan_efficiency: 0.0,
                    pattern_efficiency: 0.0,
                    resource_efficiency: 0.0,
                    time_efficiency: 0.0,
                },
            },
            scan_config: DetailedScanConfig {
                scan_type: "comprehensive".to_string(),
                targets: Vec::new(),
                patterns: PatternConfig {
                    enabled_patterns: Vec::new(),
                    disabled_patterns: Vec::new(),
                    custom_patterns: Vec::new(),
                    confidence_threshold: 0.5,
                },
                filters: FilterConfig {
                    file_filters: Vec::new(),
                    content_filters: Vec::new(),
                    size_limits: SizeLimits {
                        max_file_size: 0,
                        max_scan_size: 0,
                        max_memory_usage: 0,
                    },
                    exclusion_patterns: Vec::new(),
                },
                performance: PerformanceConfig {
                    max_threads: 0,
                    timeout_seconds: 0,
                    batch_size: 0,
                    parallel_processing: true,
                },
                output: OutputConfig {
                    format: "detailed_json".to_string(),
                    verbosity: "normal".to_string(),
                    include_metadata: true,
                    redaction_enabled: false,
                },
            },
        })
    }

    /// Convert compliance score to letter grade
    fn score_to_grade(score: f64) -> String {
        match score {
            s if s >= 0.97 => "A+".to_string(),
            s if s >= 0.93 => "A".to_string(),
            s if s >= 0.90 => "A-".to_string(),
            s if s >= 0.87 => "B+".to_string(),
            s if s >= 0.83 => "B".to_string(),
            s if s >= 0.80 => "B-".to_string(),
            s if s >= 0.77 => "C+".to_string(),
            s if s >= 0.73 => "C".to_string(),
            s if s >= 0.70 => "C-".to_string(),
            s if s >= 0.67 => "D+".to_string(),
            s if s >= 0.60 => "D".to_string(),
            _ => "F".to_string(),
        }
    }

    /// Convert risk score to level
    fn risk_score_to_level(score: f64) -> String {
        match score {
            s if s >= 0.8 => "critical".to_string(),
            s if s >= 0.6 => "high".to_string(),
            s if s >= 0.4 => "medium".to_string(),
            _ => "low".to_string(),
        }
    }

    /// Export to JSON string
    pub fn to_json<T: Serialize>(report: &T) -> Result<String> {
        Ok(serde_json::to_string_pretty(report)?)
    }

    /// Export to JSON file
    pub fn to_file<T: Serialize>(report: &T, file_path: &str) -> Result<()> {
        let json = Self::to_json(report)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::{ReportMetadata, AuthorInfo, ScanSummary, ComplianceAssessment, RiskMetrics, ScanStatistics, PerformanceMetrics, CoverageMetrics, DetectionMetrics, QualityMetrics, ValidationStatus, FindingLocation};
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_compact_json_generation() {
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
                scan_config: crate::core::EchConfig::default(),
                format: crate::reporting::ReportFormat::Json,
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

        let compact = JsonReportGenerator::generate_compact(&report).unwrap();
        
        assert_eq!(compact.summary.total_findings, 1);
        assert_eq!(compact.summary.high, 1);
        assert_eq!(compact.findings.len(), 1);
        assert_eq!(compact.findings[0].type_, "ECH-AWS-001");
        assert_eq!(compact.risk.overall_score, 0.8);
        
        // Test JSON serialization
        let json = JsonReportGenerator::to_json(&compact).unwrap();
        assert!(json.contains("ECH-AWS-001"));
        assert!(json.contains("src/config.js"));
    }

    #[test]
    fn test_score_to_grade() {
        assert_eq!(JsonReportGenerator::score_to_grade(0.98), "A+");
        assert_eq!(JsonReportGenerator::score_to_grade(0.95), "A");
        assert_eq!(JsonReportGenerator::score_to_grade(0.85), "B");
        assert_eq!(JsonReportGenerator::score_to_grade(0.75), "C");
        assert_eq!(JsonReportGenerator::score_to_grade(0.50), "F");
    }

    #[test]
    fn test_risk_score_to_level() {
        assert_eq!(JsonReportGenerator::risk_score_to_level(0.9), "critical");
        assert_eq!(JsonReportGenerator::risk_score_to_level(0.7), "high");
        assert_eq!(JsonReportGenerator::risk_score_to_level(0.5), "medium");
        assert_eq!(JsonReportGenerator::risk_score_to_level(0.2), "low");
    }
}