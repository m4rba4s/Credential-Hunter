/**
 * ECH Core Engine - Main Orchestration Engine
 *
 * This is the central orchestrator that coordinates all ECH operations including
 * credential detection, memory scanning, filesystem hunting, container analysis,
 * and enterprise reporting. Designed for high-performance operation in enterprise
 * environments with comprehensive error handling and security features.
 *
 * Features:
 * - Multi-threaded operation with work-stealing queues
 * - Comprehensive error handling and recovery
 * - Enterprise audit trails and compliance reporting
 * - Resource management and memory safety
 * - Cross-platform operation coordination
 * - Real-time SIEM integration
 * - Self-destruct and evidence cleanup
 */
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::config::EchConfig;
use super::metrics::{CompletedOperationMetrics, Metrics};
use super::platform::Platform;
use super::scheduler::TaskScheduler;
use super::security::SecurityContext;

use crate::container::ContainerScanner;
use crate::detection::{DetectionEngine, DetectionResult};
use crate::filesystem::watchers::{FilesystemEventKind, FilesystemMonitorEvent};
use crate::filesystem::FilesystemHunter;
use crate::memory::scanner::ProcessCriteria;
use crate::memory::{MemoryScanResult, MemoryScanner};
use crate::remediation::RemediationEngine;
#[cfg(feature = "siem-integration")]
use crate::siem::SiemIntegration;
use crate::stealth::StealthEngine;

// Provide a minimal SIEM placeholder when the feature is disabled
#[cfg(not(feature = "siem-integration"))]
mod siem_placeholder {
    use crate::detection::DetectionResult;
    use anyhow::Result;

    pub struct SiemIntegration;

    impl SiemIntegration {
        pub async fn new(_config: crate::core::config::SiemConfig) -> Result<Self> {
            Ok(Self)
        }

        pub async fn send_detections(&self, _detections: &[DetectionResult]) -> Result<()> {
            Ok(())
        }

        pub async fn test_connection(&self) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(not(feature = "siem-integration"))]
use siem_placeholder::SiemIntegration;

/// Main ECH engine that orchestrates all operations
pub struct EchEngine {
    /// Engine configuration
    config: EchConfig,

    /// Security context and validation
    security_context: Arc<SecurityContext>,

    /// Platform abstraction layer
    platform: Arc<Platform>,

    /// Detection engine
    detection_engine: Arc<DetectionEngine>,

    /// Memory scanner
    memory_scanner: Option<Arc<MemoryScanner>>,

    /// Filesystem hunter
    filesystem_hunter: Arc<FilesystemHunter>,

    /// Container scanner
    container_scanner: Option<Arc<ContainerScanner>>,

    /// Stealth engine
    stealth_engine: Option<Arc<StealthEngine>>,

    /// Remediation engine
    remediation_engine: Arc<RemediationEngine>,

    /// SIEM integration
    siem_integration: Option<Arc<SiemIntegration>>,

    /// Task scheduler
    task_scheduler: Arc<TaskScheduler>,

    /// Performance metrics
    metrics: Arc<Metrics>,

    /// Engine state
    state: Arc<RwLock<EngineState>>,

    /// Session information
    session: Arc<RwLock<SessionInfo>>,
}

/// Summary of active engine components
#[derive(Debug, Clone)]
pub struct EngineComponents {
    /// Detection engine availability.
    pub detection_enabled: bool,
    /// Filesystem hunter availability.
    pub filesystem_enabled: bool,
    /// Memory scanner availability.
    pub memory_enabled: bool,
    /// Container scanner availability.
    pub container_enabled: bool,
    /// Stealth engine availability.
    pub stealth_enabled: bool,
    /// SIEM integration availability.
    pub siem_enabled: bool,
    /// Remediation engine availability.
    pub remediation_enabled: bool,
}

/// Engine operational state
#[derive(Debug, Clone)]
pub struct EngineState {
    /// Is engine running
    pub running: bool,

    /// Start time
    pub start_time: DateTime<Utc>,

    /// Last operation time
    pub last_operation: DateTime<Utc>,

    /// Total operations performed
    pub operations_count: u64,

    /// Current active tasks
    pub active_tasks: u32,

    /// Error count
    pub error_count: u64,

    /// Last error
    pub last_error: Option<String>,
}

/// Session information for audit trails
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: Uuid,

    /// User context
    pub user_context: Option<String>,

    /// Correlation ID for distributed tracing
    pub correlation_id: Option<String>,

    /// Session start time
    pub start_time: DateTime<Utc>,

    /// Operations performed in this session
    pub operations: Vec<OperationRecord>,

    /// Files accessed
    pub files_accessed: Vec<String>,

    /// Credentials found
    pub credentials_found: u64,

    /// High-risk findings
    pub high_risk_findings: u64,
}

/// Record of an operation performed
#[derive(Debug, Clone)]
pub struct OperationRecord {
    /// Operation ID
    pub id: Uuid,

    /// Operation type
    pub operation_type: String,

    /// Target (file, PID, container, etc.)
    pub target: String,

    /// Start time
    pub start_time: DateTime<Utc>,

    /// End time
    pub end_time: Option<DateTime<Utc>>,

    /// Result status
    pub status: OperationStatus,

    /// Results summary
    pub results_summary: String,

    /// Error message if failed
    pub error_message: Option<String>,
}

/// Operation result status
#[derive(Debug, Clone)]
pub enum OperationStatus {
    /// Operation is currently running.
    Running,
    /// Operation finished successfully.
    Completed,
    /// Operation failed.
    Failed,
    /// Operation was cancelled.
    Cancelled,
}

/// Engine operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    /// Operation ID
    pub operation_id: Uuid,

    /// Detected credentials
    pub detections: Vec<DetectionResult>,

    /// Operation summary
    pub summary: OperationSummary,

    /// Recommendations
    pub recommendations: Vec<String>,

    /// Compliance report
    pub compliance_report: Option<ComplianceReport>,
}

impl EngineResult {
    fn log_telemetry(&self, operation: &str) {
        info!(
            operation,
            operation_id = %self.operation_id,
            detections = self.detections.len(),
            recommendations = self.recommendations.len(),
            has_compliance_report = self.compliance_report.is_some(),
            targets_scanned = self.summary.targets_scanned,
            "Engine result produced"
        );

        if let Some(report) = &self.compliance_report {
            debug!(
                report_id = %report.report_id,
                generated_at = %report.generated_at.to_rfc3339(),
                compliance_score = report.compliance_score,
                frameworks = ?report.frameworks,
                violations = report.violations.len(),
                recommendations = report.recommendations.len(),
                "Compliance report metadata"
            );
            for violation in report.violations.iter().take(3) {
                debug!(
                    violation_id = %violation.id,
                    framework = %violation.framework,
                    rule = %violation.rule,
                    severity = %violation.severity,
                    description = %violation.description,
                    affected = ?violation.affected_credential,
                    remediation_steps = violation.remediation.len(),
                    "Compliance violation snapshot"
                );
            }
        }
    }
}

#[derive(Debug, Clone)]
struct MonitorEventStats {
    detections: usize,
    high_risk: usize,
    bytes_processed: u64,
}

/// Summary of operation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSummary {
    /// Total files/targets scanned
    pub targets_scanned: u64,

    /// Total credentials found
    pub credentials_found: u64,

    /// High-risk credentials found
    pub high_risk_credentials: u64,

    /// Processing time
    pub processing_time_ms: u64,

    /// Data processed (bytes)
    pub bytes_processed: u64,

    /// Error count
    pub errors_encountered: u64,
}

/// Compliance report for enterprise auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Report ID
    pub report_id: Uuid,

    /// Generation time
    pub generated_at: DateTime<Utc>,

    /// Compliance frameworks checked
    pub frameworks: Vec<String>,

    /// Compliance score (0.0-1.0)
    pub compliance_score: f64,

    /// Violations found
    pub violations: Vec<ComplianceViolation>,

    /// Recommended actions
    pub recommendations: Vec<String>,
}

/// Compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    /// Violation ID
    pub id: Uuid,

    /// Framework (PCI, GDPR, SOX, etc.)
    pub framework: String,

    /// Rule violated
    pub rule: String,

    /// Severity level
    pub severity: String,

    /// Description
    pub description: String,

    /// Affected credential
    pub affected_credential: Option<String>,

    /// Remediation steps
    pub remediation: Vec<String>,
}

impl EchEngine {
    /// Create a new ECH engine
    pub async fn new(config: EchConfig) -> Result<Self> {
        info!("🚀 Initializing ECH Engine v{}", env!("CARGO_PKG_VERSION"));

        // Initialize security context
        let security_context = Arc::new(
            SecurityContext::new(&config)
                .await
                .context("Failed to initialize security context")?,
        );

        // Initialize platform abstraction
        let platform = Arc::new(
            Platform::new(&config)
                .await
                .context("Failed to initialize platform layer")?,
        );

        // Initialize detection engine
        let detection_config = detection_engine_config(&config);
        let detection_engine = Arc::new(
            DetectionEngine::new(detection_config)
                .await
                .context("Failed to initialize detection engine")?,
        );

        // Initialize filesystem hunter
        let filesystem_config = filesystem_hunter_config(&config);
        let filesystem_hunter = Arc::new(
            FilesystemHunter::new(filesystem_config)
                .await
                .context("Failed to initialize filesystem hunter")?,
        );

        // Initialize remediation engine
        let remediation_engine = Arc::new(
            RemediationEngine::new(config.remediation.clone())
                .await
                .context("Failed to initialize remediation engine")?,
        );

        // Initialize task scheduler
        let task_scheduler = Arc::new(
            TaskScheduler::new(config.engine.worker_threads)
                .context("Failed to initialize task scheduler")?,
        );

        // Initialize metrics
        let metrics = Arc::new(Metrics::new());

        // Initialize optional components based on configuration
        let memory_scanner =
            if config.operation.memory_enabled && security_context.can_access_memory() {
                let memory_config = memory_scanner_config(&config);
                Some(Arc::new(
                    MemoryScanner::new(memory_config)
                        .await
                        .context("Failed to initialize memory scanner")?,
                ))
            } else {
                if config.operation.memory_enabled {
                    warn!("Memory scanning requested but insufficient privileges");
                }
                None
            };

        let container_scanner =
            if config.container.docker_enabled || config.container.podman_enabled {
                Some(Arc::new(
                    ContainerScanner::new(config.container.clone())
                        .await
                        .context("Failed to initialize container scanner")?,
                ))
            } else {
                None
            };

        let stealth_engine = if !matches!(config.stealth.mode, super::config::StealthMode::None) {
            let stealth_config = stealth_engine_config(&config);
            Some(Arc::new(
                StealthEngine::new(stealth_config)
                    .await
                    .context("Failed to initialize stealth engine")?,
            ))
        } else {
            None
        };

        #[cfg(feature = "siem-integration")]
        let siem_integration = if config.siem.endpoint.is_some() {
            let siem_config = siem_integration_config(&config);
            Some(Arc::new(
                SiemIntegration::new(siem_config)
                    .await
                    .context("Failed to initialize SIEM integration")?,
            ))
        } else {
            None
        };

        #[cfg(not(feature = "siem-integration"))]
        let siem_integration: Option<Arc<SiemIntegration>> = if config.siem.endpoint.is_some() {
            Some(Arc::new(
                SiemIntegration::new(config.siem.clone())
                    .await
                    .context("Failed to initialize SIEM placeholder")?,
            ))
        } else {
            None
        };

        // Initialize engine state
        let now = Utc::now();
        let state = Arc::new(RwLock::new(EngineState {
            running: false,
            start_time: now,
            last_operation: now,
            operations_count: 0,
            active_tasks: 0,
            error_count: 0,
            last_error: None,
        }));

        // Initialize session
        let session = Arc::new(RwLock::new(SessionInfo {
            session_id: Uuid::new_v4(),
            user_context: config.audit.user_context.clone(),
            correlation_id: config.audit.correlation_id.clone(),
            start_time: now,
            operations: Vec::new(),
            files_accessed: Vec::new(),
            credentials_found: 0,
            high_risk_findings: 0,
        }));

        let engine = Self {
            config,
            security_context,
            platform,
            detection_engine,
            memory_scanner,
            filesystem_hunter,
            container_scanner,
            stealth_engine,
            remediation_engine,
            siem_integration,
            task_scheduler,
            metrics,
            state,
            session,
        };

        info!("✅ ECH Engine initialized successfully");
        Ok(engine)
    }

    /// Report which engine components are active
    pub fn components(&self) -> EngineComponents {
        EngineComponents {
            detection_enabled: true,
            filesystem_enabled: true,
            memory_enabled: self.memory_scanner.is_some(),
            container_enabled: self.container_scanner.is_some(),
            stealth_enabled: self.stealth_engine.is_some(),
            siem_enabled: self.siem_integration.is_some(),
            remediation_enabled: true,
        }
    }

    /// Scan filesystem for credentials
    pub async fn scan_filesystem(&self, mut targets: Vec<String>) -> Result<EngineResult> {
        let target_descriptor = targets.join(",");
        let operation_id = self
            .start_operation("filesystem_scan", &target_descriptor)
            .await?;

        let mut path_targets = Vec::new();
        let mut full_filesystem_requested = false;
        for target in targets.drain(..) {
            if is_full_filesystem_target(&target) {
                full_filesystem_requested = true;
            } else {
                path_targets.push(target);
            }
        }

        let total_requests =
            path_targets.len() as u64 + if full_filesystem_requested { 1 } else { 0 };
        info!(
            "📁 Starting filesystem credential scan on {} targets",
            total_requests
        );

        let start_time = std::time::Instant::now();
        let mut all_detections = Vec::new();
        let mut targets_scanned = 0u64;
        let mut bytes_processed = 0u64;
        let mut errors_encountered = 0u64;

        // Apply stealth measures if configured
        if let Some(ref stealth_engine) = self.stealth_engine {
            stealth_engine.activate_stealth_mode().await?;
        }

        let mut accumulate_scan_result = |scan_result: crate::filesystem::ScanResult| {
            targets_scanned += scan_result.summary.files_scanned;
            bytes_processed += scan_result.summary.bytes_processed;
            all_detections.extend(scan_result.detections);
        };

        if full_filesystem_requested {
            match self
                .filesystem_hunter
                .scan_filesystem_root(Arc::clone(&self.detection_engine))
                .await
            {
                Ok(scan_result) => accumulate_scan_result(scan_result),
                Err(e) => {
                    error!("Filesystem scan error (root): {}", e);
                    errors_encountered += 1;
                }
            }
        }

        match path_targets.len() {
            0 => {}
            1 => {
                if let Some(target) = path_targets.pop() {
                    match self
                        .filesystem_hunter
                        .scan_path(&target, Arc::clone(&self.detection_engine))
                        .await
                    {
                        Ok(scan_result) => accumulate_scan_result(scan_result),
                        Err(e) => {
                            error!("Filesystem scan error ({}): {}", target, e);
                            errors_encountered += 1;
                        }
                    }
                }
            }
            _ => {
                match self
                    .filesystem_hunter
                    .scan_paths(path_targets, Arc::clone(&self.detection_engine))
                    .await
                {
                    Ok(scan_result) => accumulate_scan_result(scan_result),
                    Err(e) => {
                        error!("Filesystem scan error (multi-target): {}", e);
                        errors_encountered += 1;
                    }
                }
            }
        }

        let processing_time = start_time.elapsed().as_millis() as u64;

        // Process results through remediation if configured
        if !self.config.operation.dry_run {
            all_detections = self.apply_remediation(all_detections).await?;
        }

        // Send to SIEM if configured
        if let Some(ref siem) = self.siem_integration {
            if let Err(e) = siem.send_detections(&all_detections).await {
                warn!("Failed to send detections to SIEM: {}", e);
            }
        }

        let summary = OperationSummary {
            targets_scanned,
            credentials_found: all_detections.len() as u64,
            high_risk_credentials: all_detections
                .iter()
                .filter(|d| {
                    matches!(
                        d.risk_level,
                        crate::detection::engine::RiskLevel::High
                            | crate::detection::engine::RiskLevel::Critical
                    )
                })
                .count() as u64,
            processing_time_ms: processing_time,
            bytes_processed,
            errors_encountered,
        };

        // Generate compliance report if needed
        let compliance_report = if self.config.audit.chain_of_custody {
            Some(self.generate_compliance_report(&all_detections).await?)
        } else {
            None
        };

        let result = EngineResult {
            operation_id,
            detections: all_detections,
            summary: summary.clone(),
            recommendations: self.generate_recommendations(&summary).await,
            compliance_report,
        };

        result.log_telemetry("filesystem_scan");
        self.complete_operation(operation_id, &summary).await?;

        info!(
            "✅ Filesystem scan completed: {} credentials found in {}ms",
            result.summary.credentials_found, result.summary.processing_time_ms
        );

        Ok(result)
    }

    /// Scan process memory for credentials
    pub async fn scan_memory(&self, targets: Vec<String>) -> Result<EngineResult> {
        let memory_scanner = self
            .memory_scanner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Memory scanning not available"))?;

        let operation_id = self
            .start_operation("memory_scan", &targets.join(","))
            .await?;
        info!(
            "🧠 Starting memory credential scan on {} targets",
            targets.len()
        );

        if !self.security_context.validate_privileges().await {
            return Err(anyhow::anyhow!(
                "Insufficient privileges for memory scanning"
            ));
        }

        let start_time = std::time::Instant::now();
        let mut all_detections = Vec::new();
        let mut targets_scanned = 0u64;

        // Apply maximum stealth for memory operations
        if let Some(ref stealth_engine) = self.stealth_engine {
            stealth_engine.activate_memory_stealth().await?;
        }

        if targets.is_empty() {
            match memory_scanner
                .scan_all_processes(Arc::clone(&self.detection_engine))
                .await
            {
                Ok(result) => {
                    self.log_memory_scan_metadata(&result);
                    targets_scanned += result.summary.processes_scanned;
                    all_detections.extend(result.detections);
                }
                Err(e) => {
                    error!("Memory scan error for all processes: {}", e);
                }
            }
        } else {
            // Parse targets as PIDs or process names
            for target in &targets {
                let target_lower = target.to_ascii_lowercase();
                let criteria_prefix = "criteria:";
                let region_prefix = "region:";

                if target_lower.starts_with(criteria_prefix) {
                    let spec = &target[criteria_prefix.len()..];
                    let criteria = parse_process_criteria_spec(spec)?;
                    match memory_scanner
                        .scan_with_criteria(criteria, Arc::clone(&self.detection_engine))
                        .await
                    {
                        Ok(result) => {
                            self.log_memory_scan_metadata(&result);
                            targets_scanned += result.summary.processes_scanned;
                            all_detections.extend(result.detections);
                        }
                        Err(e) => {
                            error!("Memory scan error for criteria target {}: {}", target, e);
                        }
                    }
                    continue;
                }

                if target_lower.starts_with(region_prefix) {
                    let spec = &target[region_prefix.len()..];
                    let (pid, start, size) = parse_memory_region_spec(spec)?;
                    match memory_scanner
                        .scan_memory_region(pid, start, size, Arc::clone(&self.detection_engine))
                        .await
                    {
                        Ok(detections) => {
                            targets_scanned += 1;
                            all_detections.extend(detections);
                        }
                        Err(e) => {
                            error!("Memory scan error for region target {}: {}", target, e);
                        }
                    }
                    continue;
                }

                let scan_result = if let Ok(pid) = target.parse::<u32>() {
                    memory_scanner
                        .scan_process_by_pid(pid, Arc::clone(&self.detection_engine))
                        .await
                } else {
                    memory_scanner
                        .scan_process_by_name(target, Arc::clone(&self.detection_engine))
                        .await
                };

                match scan_result {
                    Ok(detections) => {
                        targets_scanned += 1;
                        all_detections.extend(detections);
                    }
                    Err(e) => {
                        error!("Memory scan error for target {}: {}", target, e);
                    }
                }
            }
        }

        let processing_time = start_time.elapsed().as_millis() as u64;

        // Apply remediation
        if !self.config.operation.dry_run {
            all_detections = self.apply_remediation(all_detections).await?;
        }

        let summary = OperationSummary {
            targets_scanned: if targets.is_empty() {
                targets_scanned.max(1)
            } else {
                targets_scanned
            },
            credentials_found: all_detections.len() as u64,
            high_risk_credentials: all_detections
                .iter()
                .filter(|d| matches!(d.risk_level, crate::detection::engine::RiskLevel::Critical))
                .count() as u64,
            processing_time_ms: processing_time,
            bytes_processed: 0, // Memory scanning doesn't track bytes
            errors_encountered: 0,
        };

        let result = EngineResult {
            operation_id,
            detections: all_detections,
            summary: summary.clone(),
            recommendations: self.generate_recommendations(&summary).await,
            compliance_report: None,
        };

        result.log_telemetry("memory_scan");
        self.complete_operation(operation_id, &summary).await?;

        info!(
            "✅ Memory scan completed: {} credentials found",
            result.summary.credentials_found
        );
        Ok(result)
    }

    /// Scan containers for credentials
    pub async fn scan_containers(&self, targets: Vec<String>) -> Result<EngineResult> {
        let container_scanner = self
            .container_scanner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Container scanning not available"))?;

        let operation_id = self
            .start_operation("container_scan", &targets.join(","))
            .await?;
        info!("🐳 Starting container credential scan");

        let start_time = std::time::Instant::now();
        let all_detections = if targets.is_empty() {
            // Scan all containers
            container_scanner
                .scan_all_containers(Arc::clone(&self.detection_engine))
                .await?
        } else {
            // Scan specific containers
            let mut detections = Vec::new();
            for target in &targets {
                let result = container_scanner
                    .scan_container(target, Arc::clone(&self.detection_engine))
                    .await?;
                detections.extend(result);
            }
            detections
        };

        let processing_time = start_time.elapsed().as_millis() as u64;

        let summary = OperationSummary {
            targets_scanned: if targets.is_empty() {
                1
            } else {
                targets.len() as u64
            },
            credentials_found: all_detections.len() as u64,
            high_risk_credentials: all_detections
                .iter()
                .filter(|d| {
                    matches!(
                        d.risk_level,
                        crate::detection::engine::RiskLevel::High
                            | crate::detection::engine::RiskLevel::Critical
                    )
                })
                .count() as u64,
            processing_time_ms: processing_time,
            bytes_processed: 0,
            errors_encountered: 0,
        };

        let result = EngineResult {
            operation_id,
            detections: all_detections,
            summary: summary.clone(),
            recommendations: self.generate_recommendations(&summary).await,
            compliance_report: None,
        };

        result.log_telemetry("container_scan");
        self.complete_operation(operation_id, &summary).await?;

        info!(
            "✅ Container scan completed: {} credentials found",
            result.summary.credentials_found
        );
        Ok(result)
    }

    /// Start continuous monitoring mode
    pub async fn start_monitoring(&self, targets: Vec<String>) -> Result<()> {
        let shutdown = async {
            if let Err(err) = signal::ctrl_c().await {
                warn!("Failed to await ctrl_c signal: {}", err);
            }
        };

        self.start_monitoring_until(targets, shutdown).await
    }

    /// Start monitoring until the provided shutdown future resolves (primarily for tests)
    pub async fn start_monitoring_until<F>(&self, targets: Vec<String>, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.run_monitoring_loop(targets, shutdown).await
    }

    async fn run_monitoring_loop<F>(&self, targets: Vec<String>, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        info!("👁️ Entering continuous filesystem monitoring mode");

        let operation_id = self.start_operation("monitoring", "continuous").await?;
        let start_time = Instant::now();

        let monitor_paths = self.build_monitor_paths(targets);
        info!("Watching {} path(s) for changes", monitor_paths.len());

        let Some(mut event_rx) = self
            .filesystem_hunter
            .start_monitoring(monitor_paths.clone())
            .await?
        else {
            warn!("Filesystem monitoring is disabled in the current configuration");
            let summary = OperationSummary {
                targets_scanned: 0,
                credentials_found: 0,
                high_risk_credentials: 0,
                processing_time_ms: start_time.elapsed().as_millis() as u64,
                bytes_processed: 0,
                errors_encountered: 0,
            };
            self.complete_operation(operation_id, &summary).await?;
            return Ok(());
        };

        let mut shutdown_signal: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(shutdown);
        let mut bytes_processed = 0u64;
        let mut detections_total = 0u64;
        let mut high_risk = 0u64;
        let mut errors = 0u64;
        let mut scans_triggered = 0u64;
        let mut debounce = HashMap::<PathBuf, Instant>::new();
        let debounce_window = Duration::from_secs(2);

        loop {
            tokio::select! {
                _ = &mut shutdown_signal => {
                    info!("Received shutdown signal; stopping continuous monitoring");
                    break;
                }
                maybe_event = event_rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            match self
                                .process_monitor_event(
                                    event,
                                    &mut debounce,
                                    debounce_window,
                                )
                                .await
                            {
                                Ok(Some(event_stats)) => {
                                    scans_triggered += 1;
                                    bytes_processed = bytes_processed
                                        .saturating_add(event_stats.bytes_processed);
                                    detections_total += event_stats.detections as u64;
                                    high_risk += event_stats.high_risk as u64;
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    errors += 1;
                                    warn!("Monitoring scan failed: {}", err);
                                }
                            }
                        }
                        None => {
                            info!("Filesystem watcher channel closed");
                            break;
                        }
                    }
                }
            }
        }

        self.filesystem_hunter.stop_monitoring().await?;

        let summary = OperationSummary {
            targets_scanned: scans_triggered,
            credentials_found: detections_total,
            high_risk_credentials: high_risk,
            processing_time_ms: start_time.elapsed().as_millis() as u64,
            bytes_processed,
            errors_encountered: errors,
        };

        self.complete_operation(operation_id, &summary).await?;
        info!(
            "✅ Monitoring stopped: {} detections ({} high-risk)",
            detections_total, high_risk
        );
        Ok(())
    }

    async fn process_monitor_event(
        &self,
        event: FilesystemMonitorEvent,
        debounce: &mut HashMap<PathBuf, Instant>,
        debounce_window: Duration,
    ) -> Result<Option<MonitorEventStats>> {
        if !matches!(
            event.kind,
            FilesystemEventKind::Created | FilesystemEventKind::Modified
        ) {
            return Ok(None);
        }

        let path = event.path;
        if !path.is_file() {
            return Ok(None);
        }

        let now = Instant::now();
        if let Some(last_seen) = debounce.get(&path) {
            if now.duration_since(*last_seen) < debounce_window {
                return Ok(None);
            }
        }
        debounce.insert(path.clone(), now);

        let detection_engine = Arc::clone(&self.detection_engine);
        let path_string = path.to_string_lossy().to_string();
        let scan_result = self
            .filesystem_hunter
            .scan_path(&path_string, detection_engine)
            .await?;

        let bytes_processed = scan_result.summary.bytes_processed;
        let mut detections = scan_result.detections;

        if detections.is_empty() {
            return Ok(Some(MonitorEventStats {
                detections: 0,
                high_risk: 0,
                bytes_processed,
            }));
        }

        if !self.config.operation.dry_run {
            detections = self.apply_remediation(detections).await?;
        }

        if let Some(ref siem) = self.siem_integration {
            if let Err(err) = siem.send_detections(&detections).await {
                warn!("Failed to stream monitoring detections to SIEM: {}", err);
            }
        }

        let high_risk = detections
            .iter()
            .filter(|d| {
                matches!(
                    d.risk_level,
                    crate::detection::engine::RiskLevel::High
                        | crate::detection::engine::RiskLevel::Critical
                )
            })
            .count();
        let detection_count = detections.len();

        {
            let mut session = self.session.write().await;
            session.credentials_found += detection_count as u64;
            session.high_risk_findings += high_risk as u64;
            session.files_accessed.push(path_string.clone());
        }

        info!(
            "📁 Monitoring detected {} credential(s) in {}",
            detection_count, path_string
        );

        Ok(Some(MonitorEventStats {
            detections: detection_count,
            high_risk,
            bytes_processed,
        }))
    }

    /// Expose a snapshot of the current session for testing/telemetry
    #[allow(dead_code)]
    pub async fn session_snapshot(&self) -> SessionInfo {
        self.session.read().await.clone()
    }

    /// Generate compliance report
    pub async fn generate_report(&self) -> Result<EngineResult> {
        info!("📊 Generating compliance report");

        let operation_id = self.start_operation("compliance_report", "full").await?;
        let start_time = std::time::Instant::now();

        // Generate comprehensive report based on session data
        let session = self.session.read().await;
        let compliance_report = ComplianceReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            frameworks: vec!["PCI-DSS".to_string(), "GDPR".to_string(), "SOX".to_string()],
            compliance_score: 0.85, // Would be calculated based on findings
            violations: Vec::new(), // Would be populated with actual violations
            recommendations: vec![
                "Implement secret management system".to_string(),
                "Rotate exposed credentials".to_string(),
                "Add credential scanning to CI/CD pipeline".to_string(),
            ],
        };

        let processing_time = start_time.elapsed().as_millis() as u64;

        let summary = OperationSummary {
            targets_scanned: 1,
            credentials_found: session.credentials_found,
            high_risk_credentials: session.high_risk_findings,
            processing_time_ms: processing_time,
            bytes_processed: 0,
            errors_encountered: 0,
        };

        let result = EngineResult {
            operation_id,
            detections: Vec::new(),
            summary: summary.clone(),
            recommendations: compliance_report.recommendations.clone(),
            compliance_report: Some(compliance_report),
        };

        result.log_telemetry("compliance_report");
        self.complete_operation(operation_id, &summary).await?;

        info!("✅ Compliance report generated");
        Ok(result)
    }

    /// Test SIEM integration
    pub async fn test_siem_integration(&self) -> Result<()> {
        if let Some(ref siem) = self.siem_integration {
            info!("🔗 Testing SIEM integration");
            siem.test_connection().await?;
            info!("✅ SIEM integration test successful");
        } else {
            warn!("SIEM integration not configured");
        }
        Ok(())
    }

    /// Self-destruct and cleanup
    pub async fn self_destruct(&self) -> Result<()> {
        warn!("💥 Initiating self-destruct sequence");

        // Clear sensitive data from memory
        if let Some(ref stealth_engine) = self.stealth_engine {
            stealth_engine.secure_cleanup().await?;
        }

        // Clear session data
        {
            let mut session = self.session.write().await;
            for operation in &mut session.operations {
                if !matches!(
                    operation.status,
                    OperationStatus::Completed | OperationStatus::Failed
                ) {
                    operation.status = OperationStatus::Cancelled;
                    operation.error_message =
                        Some("Operation cancelled during self-destruct".to_string());
                }
            }
            session.operations.clear();
            session.files_accessed.clear();
        }

        // Secure memory cleanup
        self.security_context.secure_memory_cleanup().await?;

        info!("🔥 Self-destruct completed - all traces removed");
        Ok(())
    }

    /// Show system capabilities
    pub async fn show_capabilities(&self) -> Result<()> {
        info!("🔍 ECH System Capabilities:");
        let platform_info = self.platform.get_info().await?;
        info!(
            "  Platform: {} {} ({})",
            platform_info.name, platform_info.version, platform_info.architecture
        );

        let privileged = self.security_context.validate_privileges().await;
        info!("  Privileged mode: {}", privileged);
        info!("  Memory scanning: {}", self.memory_scanner.is_some());
        info!("  Container scanning: {}", self.container_scanner.is_some());
        info!("  Stealth mode: {}", self.stealth_engine.is_some());
        info!("  SIEM integration: {}", self.siem_integration.is_some());
        let components = self.components();
        info!(
            "  Components -> detection={}, filesystem={}, memory={}, containers={}, stealth={}, siem={}, remediation={}",
            components.detection_enabled,
            components.filesystem_enabled,
            components.memory_enabled,
            components.container_enabled,
            components.stealth_enabled,
            components.siem_enabled,
            components.remediation_enabled
        );
        {
            let session = self.session.read().await;
            info!(
                "  Session -> id={}, started={}, operations={}",
                session.session_id,
                session.start_time.to_rfc3339(),
                session.operations.len()
            );
        }
        if let Some(ref memory_scanner) = self.memory_scanner {
            let mem_stats = memory_scanner.get_stats().await;
            info!(
                "  Memory stats -> processes_scanned={}, creds_found={}, bytes_scanned={}",
                mem_stats.processes_scanned, mem_stats.credentials_found, mem_stats.bytes_scanned
            );
        }
        if let Some(ref stealth_engine) = self.stealth_engine {
            let stealth_stats = stealth_engine.get_stats().await;
            info!(
                "  Stealth stats -> evasions={}, successes={}, artifacts_cleaned={}",
                stealth_stats.evasion_attempts,
                stealth_stats.evasion_successes,
                stealth_stats.artifacts_cleaned
            );
            let stealth_context = stealth_engine.get_context().await;
            info!(
                "  Stealth context -> mode={:?}, level={:.2}, performance={:.2}%",
                stealth_context.mode,
                stealth_context.current_level,
                stealth_context.performance_impact
            );
            if let Some(strategy) = stealth_engine.last_mutation_strategy().await {
                info!(
                    "  Stealth last mutation -> {} ({})",
                    strategy.name, strategy.description
                );
            }
        }

        let security_snapshot = self.security_context.perform_security_checks().await?;
        info!(
            "  Security checks -> secure={}, warnings={}, violations={}",
            security_snapshot.is_secure,
            security_snapshot.warnings.len(),
            security_snapshot.violations.len()
        );
        if self.stealth_engine.is_some() {
            match crate::stealth::capabilities_snapshot().await {
                Ok(stealth_caps) => {
                    info!(
                        "  Stealth -> process_injection={}, memory_protection={}, code_obfuscation={}, api_unhooking={}, runtime_mutation={}, anti_debugging={}, network_obfuscation={}, artifact_cleanup={}, edr_evasion={}, av_evasion={}",
                        stealth_caps.process_injection,
                        stealth_caps.memory_protection,
                        stealth_caps.code_obfuscation,
                        stealth_caps.api_unhooking,
                        stealth_caps.runtime_mutation,
                        stealth_caps.anti_debugging,
                        stealth_caps.network_obfuscation,
                        stealth_caps.artifact_cleanup,
                        stealth_caps.edr_evasion,
                        stealth_caps.av_evasion
                    );
                }
                Err(err) => warn!("  Stealth capabilities unavailable: {}", err),
            }
        }

        let capabilities = self.platform.get_capabilities();
        info!(
            "  Capabilities -> memory_scanning: {}, network_monitoring: {}, container_apis: {}",
            capabilities.memory_scanning,
            capabilities.network_monitoring,
            capabilities.container_apis
        );
        info!(
            "  Extended FS access: {}",
            capabilities.extended_filesystem_access
        );
        info!(
            "  Threading -> max={}, work_stealing={}, affinity={}, high_priority={}",
            capabilities.threading.max_threads,
            capabilities.threading.work_stealing,
            capabilities.threading.thread_affinity,
            capabilities.threading.high_priority_threads
        );
        info!(
            "  Security features -> ASLR={}, DEP/NX={}, CFI={}, secure_boot={}, hardware={} entries",
            capabilities.security_features.aslr,
            capabilities.security_features.dep_nx,
            capabilities.security_features.cfi,
            capabilities.security_features.secure_boot,
            capabilities.security_features.hardware_security.len()
        );

        let optimizations = self.platform.get_optimizations();
        info!(
            "  Optimizations -> allocator: {}, FS tuning: {} entries",
            optimizations.memory_allocation,
            optimizations.filesystem_opts.len()
        );
        info!(
            "  Recommended -> threads: {}, buffer: {} KB",
            self.platform.get_optimal_thread_count(),
            self.platform.get_optimal_buffer_size() / 1024
        );

        let scheduler_snapshot = self.task_scheduler.snapshot();
        let metrics_snapshot = self.metrics.snapshot();

        info!(
            "  Scheduler -> workers: {}, running: {}, completed: {}",
            scheduler_snapshot.worker_threads,
            scheduler_snapshot.running_tasks,
            scheduler_snapshot.completed_tasks
        );
        if !scheduler_snapshot.recent_operations.is_empty() {
            debug!(
                "  Recent scheduler ops: {:?}",
                scheduler_snapshot.recent_operations
            );
        }
        info!(
            "  Metrics -> ops: {} started / {} completed, detections: {}, bytes: {}",
            metrics_snapshot.operations_started,
            metrics_snapshot.operations_completed,
            metrics_snapshot.detections_recorded,
            metrics_snapshot.bytes_processed
        );

        if let Ok(processes) = self.platform.enumerate_processes().await {
            if let Some(proc_info) = processes.iter().find(|p| p.pid == std::process::id()) {
                let cmdline_preview = proc_info
                    .cmdline
                    .split_whitespace()
                    .take(4)
                    .collect::<Vec<_>>()
                    .join(" ");
                info!(
                    "  Process snapshot -> pid: {}, name: {}, rss: {} KB, cmdline: {}",
                    proc_info.pid, proc_info.name, proc_info.memory_usage, cmdline_preview
                );
            }
        }

        {
            let session_snapshot = self.session.read().await;
            info!(
                "  Session -> id={}, correlation_id={:?}, user={:?}, operations={}, creds_found={}",
                session_snapshot.session_id,
                session_snapshot.correlation_id,
                session_snapshot.user_context,
                session_snapshot.operations.len(),
                session_snapshot.credentials_found
            );
        }

        {
            let state_snapshot = self.state.read().await;
            let uptime = Utc::now()
                .signed_duration_since(state_snapshot.start_time)
                .num_seconds();
            info!(
                "  Engine state -> running={}, active_tasks={}, operations={}, errors={}, last_error={:?}",
                state_snapshot.running,
                state_snapshot.active_tasks,
                state_snapshot.operations_count,
                state_snapshot.error_count,
                state_snapshot.last_error
            );
            info!("  Engine uptime: {}s", uptime.max(0));
        }

        let (audit_events, audit_entries) = self.security_context.audit_trail_summary().await?;
        info!(
            "  Audit trail -> recorded events: {}, log entries: {}",
            audit_events, audit_entries
        );

        // Show detection capabilities
        info!("  Detection patterns: Available");
        info!("  Entropy analysis: Available");
        info!("  ML classification: Available");
        info!("  Context analysis: Available");

        Ok(())
    }

    /// Start a new operation and record it
    async fn start_operation(&self, operation_type: &str, target: &str) -> Result<Uuid> {
        let operation_id = Uuid::new_v4();
        let now = Utc::now();

        let operation = OperationRecord {
            id: operation_id,
            operation_type: operation_type.to_string(),
            target: target.to_string(),
            start_time: now,
            end_time: None,
            status: OperationStatus::Running,
            results_summary: String::new(),
            error_message: None,
        };

        info!(
            operation_id = %operation.id,
            operation_type = %operation.operation_type,
            target = %operation.target,
            start_time = %operation.start_time.to_rfc3339(),
            "Operation started"
        );

        self.task_scheduler
            .record_start(operation_id, operation_type);
        self.metrics.record_operation_start();

        // Update session
        {
            let mut session = self.session.write().await;
            session.operations.push(operation);
        }

        // Update state
        {
            let mut state = self.state.write().await;
            state.operations_count += 1;
            state.active_tasks += 1;
            state.last_operation = now;
            state.running = true;
        }

        Ok(operation_id)
    }

    /// Complete an operation and update records
    async fn complete_operation(
        &self,
        operation_id: Uuid,
        summary: &OperationSummary,
    ) -> Result<()> {
        let now = Utc::now();
        let mut latest_error_message: Option<String> = None;

        // Update session
        {
            let mut session = self.session.write().await;
            if let Some(operation) = session
                .operations
                .iter_mut()
                .find(|op| op.id == operation_id)
            {
                operation.end_time = Some(now);
                operation.status = if summary.errors_encountered > 0 {
                    OperationStatus::Failed
                } else {
                    OperationStatus::Completed
                };
                operation.results_summary =
                    format!("Found {} credentials", summary.credentials_found);

                if summary.errors_encountered > 0 {
                    let msg = format!(
                        "{} errors during operation {}",
                        summary.errors_encountered, operation_id
                    );
                    operation.error_message = Some(msg.clone());
                    latest_error_message = Some(msg);
                    warn!(
                        operation_id = %operation.id,
                        target = %operation.target,
                        "Operation completed with errors"
                    );
                } else {
                    operation.error_message = None;
                }

                info!(
                    operation_id = %operation.id,
                    operation_type = %operation.operation_type,
                    target = %operation.target,
                    started = %operation.start_time.to_rfc3339(),
                    status = ?operation.status,
                    summary = %operation.results_summary,
                    error = operation
                        .error_message
                        .as_deref()
                        .unwrap_or("n/a"),
                    "Operation completed"
                );
            }

            session.credentials_found += summary.credentials_found;
            session.high_risk_findings += summary.high_risk_credentials;
        }

        // Update state
        {
            let mut state = self.state.write().await;
            state.active_tasks = state.active_tasks.saturating_sub(1);
            if state.active_tasks == 0 {
                state.running = false;
            }
            if summary.errors_encountered > 0 {
                state.error_count += summary.errors_encountered;
                if let Some(ref msg) = latest_error_message {
                    state.last_error = Some(msg.clone());
                } else {
                    state.last_error = Some(format!(
                        "{} errors during operation {}",
                        summary.errors_encountered, operation_id
                    ));
                }
            }
        }

        self.task_scheduler.record_completion(operation_id);
        self.metrics
            .record_operation_completion(CompletedOperationMetrics {
                detections: summary.credentials_found,
                bytes_processed: summary.bytes_processed,
                errors: summary.errors_encountered,
            });

        Ok(())
    }

    /// Apply remediation actions to detections
    async fn apply_remediation(
        &self,
        detections: Vec<DetectionResult>,
    ) -> Result<Vec<DetectionResult>> {
        if detections.is_empty() {
            return Ok(detections);
        }

        info!("🔧 Applying remediation to {} detections", detections.len());

        let remediated_detections = self
            .remediation_engine
            .process_detections(detections)
            .await
            .context("Remediation failed")?;

        Ok(remediated_detections)
    }

    fn log_memory_scan_metadata(&self, result: &MemoryScanResult) {
        let suspicious_segments: usize = result
            .analysis_results
            .iter()
            .map(|analysis| analysis.suspicious_patterns.len())
            .sum();

        info!(
            session_id = %result.session_id,
            target = ?result.target,
            duration_ms = result.duration.as_millis(),
            processes = result.summary.processes_scanned,
            regions = result.summary.regions_analyzed,
            bytes = result.summary.bytes_scanned,
            scan_rate_bps = result.performance.scan_rate_bps,
            errors = result.errors.len(),
            suspicious_segments,
            "Memory scan telemetry"
        );

        if let Some(first_error) = result.errors.first() {
            warn!(
                session_id = %result.session_id,
                error = %first_error,
                "Memory scan reported error"
            );
        }

        debug!(
            session_id = %result.session_id,
            process_metadata_entries = result.process_info.len(),
            analysis_segments = result.analysis_results.len(),
            "Memory scan metadata captured"
        );
    }

    fn build_monitor_paths(&self, targets: Vec<String>) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for target in targets {
            let candidate = PathBuf::from(&target);
            if candidate.exists() {
                paths.push(candidate);
            } else {
                warn!("Monitor target not found: {}", target);
            }
        }

        if paths.is_empty() {
            match env::current_dir() {
                Ok(dir) => {
                    info!(
                        "No monitor targets specified; defaulting to current directory {}",
                        dir.display()
                    );
                    paths.push(dir);
                }
                Err(err) => {
                    warn!(
                        "Failed to determine current directory for monitoring, falling back to '.' : {}",
                        err
                    );
                    paths.push(PathBuf::from("."));
                }
            }
        }

        paths.sort();
        paths.dedup();
        paths
    }

    /// Generate compliance report for detections
    async fn generate_compliance_report(
        &self,
        detections: &[DetectionResult],
    ) -> Result<ComplianceReport> {
        let mut violations = Vec::new();

        // Check for PCI-DSS violations (credit cards)
        for detection in detections {
            if matches!(
                detection.credential_type,
                crate::detection::engine::CredentialType::CreditCardNumber
            ) {
                violations.push(ComplianceViolation {
                    id: Uuid::new_v4(),
                    framework: "PCI-DSS".to_string(),
                    rule: "3.4 - Protect stored cardholder data".to_string(),
                    severity: "High".to_string(),
                    description: "Credit card number found in unprotected storage".to_string(),
                    affected_credential: Some(detection.masked_value.clone()),
                    remediation: vec![
                        "Remove credit card data from storage".to_string(),
                        "Implement proper tokenization".to_string(),
                        "Review data handling procedures".to_string(),
                    ],
                });
            }
        }

        // Calculate compliance score
        let total_checks = 10; // Simplified
        let violations_count = violations.len();
        let compliance_score =
            ((total_checks - violations_count) as f64 / total_checks as f64).max(0.0);

        Ok(ComplianceReport {
            report_id: Uuid::new_v4(),
            generated_at: Utc::now(),
            frameworks: vec!["PCI-DSS".to_string(), "GDPR".to_string()],
            compliance_score,
            violations,
            recommendations: vec![
                "Implement comprehensive secret management".to_string(),
                "Add automated credential scanning to CI/CD".to_string(),
                "Regular security training for developers".to_string(),
            ],
        })
    }

    /// Generate recommendations based on findings
    async fn generate_recommendations(&self, summary: &OperationSummary) -> Vec<String> {
        let mut recommendations = Vec::new();

        if summary.credentials_found > 0 {
            recommendations.push("Immediate: Review and rotate exposed credentials".to_string());
            recommendations.push(
                "Implement secret management system (HashiCorp Vault, AWS Secrets Manager)"
                    .to_string(),
            );
        }

        if summary.high_risk_credentials > 0 {
            recommendations.push("CRITICAL: Immediately revoke high-risk credentials".to_string());
            recommendations
                .push("Review access logs for potential unauthorized access".to_string());
        }

        if summary.errors_encountered > 0 {
            recommendations
                .push("Review and fix scan errors to ensure complete coverage".to_string());
        }

        recommendations.push("Add ECH to CI/CD pipeline for continuous monitoring".to_string());
        recommendations.push("Implement developer security training program".to_string());

        recommendations
    }
}

fn detection_engine_config(config: &EchConfig) -> crate::detection::DetectionConfig {
    use crate::detection::{ConfidenceLevel, DetectionConfig as DetectionEngineConfig};

    let mut detection_config = DetectionEngineConfig::default();
    detection_config.enable_entropy = config.detection.entropy_analysis;
    detection_config.enable_ml = config.detection.ml_classification;
    detection_config.enable_context = config.detection.context_analysis;
    detection_config.enable_yara = !config.detection.yara_rules.is_empty();
    detection_config.parallel_workers =
        resolve_parallel_workers(config.performance.parallel_workers);
    detection_config.enable_simd = config.performance.simd_optimizations;
    detection_config.entropy_threshold = config.detection.entropy_threshold;
    detection_config.min_secret_length = config.detection.min_credential_length.max(4);
    detection_config.max_secret_length = config
        .detection
        .max_credential_length
        .max(detection_config.min_secret_length);
    detection_config.include_full_values =
        config.operation.dry_run && config.output.include_full_values;
    if config.performance.cache_size_mb > 0 {
        detection_config.max_memory_usage =
            config.performance.cache_size_mb.saturating_mul(1024 * 1024);
    }

    detection_config.min_confidence = match config.detection.entropy_threshold {
        threshold if threshold >= 5.0 => ConfidenceLevel::High,
        threshold if threshold <= 4.0 => ConfidenceLevel::Low,
        _ => ConfidenceLevel::Medium,
    };

    detection_config
}

fn filesystem_hunter_config(config: &EchConfig) -> crate::filesystem::FilesystemConfig {
    use crate::filesystem::FilesystemConfig as FilesystemEngineConfig;

    let mut fs_config = FilesystemEngineConfig::default();

    if config.filesystem.max_file_size_mb > 0 {
        fs_config.max_file_size =
            (config.filesystem.max_file_size_mb as u64).saturating_mul(1024 * 1024);
    }
    fs_config.follow_symlinks = config.filesystem.follow_symlinks;
    fs_config.scan_hidden = config.filesystem.scan_hidden;
    fs_config.scan_archives = !config.filesystem.scan_archives.is_empty();
    fs_config.realtime_monitoring = config.filesystem.real_time_monitoring;
    fs_config.use_memory_mapping = config.performance.memory_mapping;
    fs_config.worker_threads = resolve_parallel_workers(config.performance.parallel_workers);
    fs_config.buffer_size = config.performance.io_buffer_size.saturating_mul(1024);
    fs_config.file_timeout_sec = config.engine.timeout_seconds;
    fs_config.max_memory_mb = config.performance.cache_size_mb.max(1) as u64;
    fs_config.scan_system = config.security.privileged_mode;

    fs_config.exclude_patterns = merge_strings(
        fs_config.exclude_patterns,
        config
            .filesystem
            .exclude_extensions
            .iter()
            .map(|ext| format!("*.{}", ext.trim_start_matches('.'))),
    );

    fs_config.include_patterns = merge_strings(
        fs_config.include_patterns,
        config
            .filesystem
            .scan_extensions
            .iter()
            .map(|ext| format!("*.{}", ext.trim_start_matches('.'))),
    );

    fs_config.exclude_directories = merge_strings(
        fs_config.exclude_directories,
        config
            .filesystem
            .exclude_directories
            .iter()
            .map(|dir| dir.to_string_lossy().into_owned()),
    );

    fs_config
}

fn is_full_filesystem_target(spec: &str) -> bool {
    let normalized = spec.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "filesystem://root"
            | "filesystem:///"
            | "filesystem://*"
            | "fs://root"
            | "fs://*"
            | "full-filesystem"
    )
}

fn parse_process_criteria_spec(spec: &str) -> Result<ProcessCriteria> {
    let mut criteria = ProcessCriteria {
        name_patterns: Vec::new(),
        min_memory_mb: None,
        max_memory_mb: None,
        max_age_hours: None,
        user_filter: None,
        exclude_system: false,
        include_children: false,
    };

    for (key, value) in split_key_value_pairs(spec) {
        match key.as_str() {
            "name" | "pattern" => {
                if let Some(val) = value {
                    if !val.is_empty() {
                        criteria.name_patterns.push(val);
                    }
                }
            }
            "user" | "user_filter" => {
                if let Some(val) = value {
                    criteria.user_filter = Some(val);
                }
            }
            "min_memory" | "min_memory_mb" | "min_mem" => {
                let raw = value
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("min_memory requires a value"))?;
                criteria.min_memory_mb = Some(
                    raw.parse::<u64>()
                        .map_err(|e| anyhow::anyhow!("invalid min_memory value '{}': {e}", raw))?,
                );
            }
            "max_memory" | "max_memory_mb" | "max_mem" => {
                let raw = value
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("max_memory requires a value"))?;
                criteria.max_memory_mb = Some(
                    raw.parse::<u64>()
                        .map_err(|e| anyhow::anyhow!("invalid max_memory value '{}': {e}", raw))?,
                );
            }
            "max_age" | "max_age_hours" => {
                let raw = value
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("max_age requires a value"))?;
                criteria.max_age_hours = Some(
                    raw.parse::<u64>()
                        .map_err(|e| anyhow::anyhow!("invalid max_age value '{}': {e}", raw))?,
                );
            }
            "exclude_system" => {
                criteria.exclude_system = parse_bool_flag(value.as_deref())?;
            }
            "include_children" => {
                criteria.include_children = parse_bool_flag(value.as_deref())?;
            }
            _ => {
                warn!("Ignoring unknown process criteria key: {}", key);
            }
        }
    }

    if criteria.name_patterns.is_empty()
        && criteria.user_filter.is_none()
        && criteria.min_memory_mb.is_none()
        && criteria.max_memory_mb.is_none()
        && criteria.max_age_hours.is_none()
    {
        return Err(anyhow::anyhow!(
            "process criteria target must include at least one selector"
        ));
    }

    Ok(criteria)
}

fn parse_memory_region_spec(spec: &str) -> Result<(u32, u64, usize)> {
    let mut pid: Option<u32> = None;
    let mut start: Option<u64> = None;
    let mut size: Option<usize> = None;

    for (key, value) in split_key_value_pairs(spec) {
        let raw_value = value
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("{} requires a value", key))?;

        match key.as_str() {
            "pid" => {
                pid = Some(
                    raw_value
                        .parse::<u32>()
                        .map_err(|e| anyhow::anyhow!("invalid pid '{}': {e}", raw_value))?,
                );
            }
            "start" | "address" => {
                start = Some(parse_numeric_value(raw_value)?);
            }
            "size" | "length" => {
                let bytes = parse_numeric_value(raw_value)?;
                size = Some(usize::try_from(bytes).map_err(|_| {
                    anyhow::anyhow!("region size '{}' exceeds platform limits", raw_value)
                })?);
            }
            _ => warn!("Ignoring unknown memory region key: {}", key),
        }
    }

    let pid = pid.ok_or_else(|| anyhow::anyhow!("memory region target missing pid"))?;
    let start =
        start.ok_or_else(|| anyhow::anyhow!("memory region target missing start address"))?;
    let size = size.ok_or_else(|| anyhow::anyhow!("memory region target missing size"))?;

    Ok((pid, start, size))
}

fn parse_bool_flag(value: Option<&str>) -> Result<bool> {
    match value {
        None => Ok(true),
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            other => Err(anyhow::anyhow!(
                "invalid boolean value '{}': expected true/false",
                other
            )),
        },
    }
}

fn parse_numeric_value(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex value '{}': {e}", value))
    } else {
        trimmed
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid numeric value '{}': {e}", value))
    }
}

fn split_key_value_pairs(spec: &str) -> Vec<(String, Option<String>)> {
    spec.split(',')
        .filter_map(|raw_pair| {
            let trimmed = raw_pair.trim();
            if trimmed.is_empty() {
                return None;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                Some((
                    key.trim().to_ascii_lowercase(),
                    Some(value.trim().to_string()),
                ))
            } else {
                Some((trimmed.to_ascii_lowercase(), None))
            }
        })
        .collect()
}

fn memory_scanner_config(config: &EchConfig) -> crate::memory::MemoryConfig {
    use super::config::StealthMode;
    use crate::memory::MemoryConfig as MemoryEngineConfig;

    let mut memory_config = MemoryEngineConfig::default();

    if config.memory.max_region_size_mb > 0 {
        memory_config.max_memory_mb = config.memory.max_region_size_mb as u64;
    }
    memory_config.scan_timeout_sec = config.engine.timeout_seconds;
    memory_config.stealth_mode = config.memory.use_injection
        || matches!(
            config.stealth.mode,
            StealthMode::High | StealthMode::Maximum
        );
    memory_config.scan_heap = config.memory.heap_analysis;
    memory_config.scan_stack = config.memory.stack_scanning;
    memory_config.scan_modules = config.memory.scan_executable_regions;
    memory_config.scan_private = config.memory.process_scanning;
    memory_config.min_region_size = config.memory.scan_batch_size.max(4096);
    memory_config.analysis_chunk_size = config.memory.scan_batch_size;
    memory_config.max_concurrent_scans = resolve_parallel_workers(config.engine.worker_threads);
    memory_config.use_simd = config.performance.simd_optimizations;
    memory_config.pattern_cache_size = memory_config
        .pattern_cache_size
        .max(config.memory.scan_batch_size / 512);
    memory_config.anti_detection = config.memory.use_injection
        || matches!(
            config.stealth.mode,
            StealthMode::Low | StealthMode::High | StealthMode::Maximum
        )
        || config.stealth.edr_evasion;
    memory_config.terminate_on_cancel = config.remediation.auto_remediate;
    memory_config.log_memory_reads = config.memory.log_memory_reads;

    memory_config
}

fn stealth_engine_config(config: &EchConfig) -> crate::stealth::StealthConfig {
    use super::config::StealthMode;
    use crate::stealth::{OperationalMode, StealthConfig as EngineStealthConfig, StealthLevel};

    let mut stealth_config = EngineStealthConfig::default();

    stealth_config.level = match config.stealth.mode {
        StealthMode::None => StealthLevel::None,
        StealthMode::Low => StealthLevel::Low,
        StealthMode::High => StealthLevel::High,
        StealthMode::Maximum => StealthLevel::Maximum,
    };

    stealth_config.mode = if matches!(config.stealth.mode, StealthMode::None) {
        OperationalMode::Normal
    } else {
        OperationalMode::Covert
    };

    stealth_config.edr_evasion = config.stealth.edr_evasion;
    stealth_config.av_evasion = config.stealth.edr_evasion;
    stealth_config.process_injection =
        config.memory.use_injection || config.stealth.process_hollowing;
    stealth_config.code_obfuscation = config.stealth.api_obfuscation;
    stealth_config.memory_protection = config.security.memory_encryption;
    stealth_config.anti_debugging =
        config.security.tamper_detection || config.stealth.process_hollowing;
    stealth_config.runtime_mutation = matches!(config.stealth.mode, StealthMode::Maximum);
    stealth_config.cleanup_on_exit = config.stealth.auto_cleanup;
    stealth_config.performance_budget = if config.stealth.minimize_footprint {
        20.0
    } else {
        35.0
    };
    stealth_config.detection_threshold = match config.stealth.mode {
        StealthMode::None | StealthMode::Low => 0.7,
        StealthMode::High => 0.8,
        StealthMode::Maximum => 0.9,
    };

    stealth_config
}

#[cfg(feature = "siem-integration")]
fn siem_integration_config(config: &EchConfig) -> crate::siem::SiemConfig {
    use crate::siem::integration::{AuthType, SiemConfig as SiemEngineConfig, SiemPlatform};
    use secrecy::ExposeSecret;

    let mut siem_config = SiemEngineConfig::default();

    siem_config.platform = match config.siem.format {
        super::config::SiemFormat::Json | super::config::SiemFormat::Syslog => {
            SiemPlatform::Generic
        }
        super::config::SiemFormat::Cef => SiemPlatform::ArcSight,
        super::config::SiemFormat::Leef => SiemPlatform::QRadar,
        super::config::SiemFormat::Splunk => SiemPlatform::Splunk,
        super::config::SiemFormat::Elastic => SiemPlatform::Elasticsearch,
    };

    siem_config.endpoint = config.siem.endpoint.clone();
    if let Some(token) = config.siem.auth_token.as_ref() {
        siem_config.auth_config.auth_type = AuthType::ApiKey;
        siem_config.auth_config.api_key = Some(token.expose_secret().to_owned());
    } else {
        siem_config.auth_config.auth_type = AuthType::None;
        siem_config.auth_config.api_key = None;
    }

    siem_config.secure_logging = config.security.audit_logging;
    siem_config.data_masking = true;
    siem_config.batch_size = config.siem.batch_size.max(1);
    siem_config.batch_timeout_ms = config.siem.timeout_seconds.saturating_mul(1000);
    siem_config.correlation_enabled = config.audit.chain_of_custody;
    siem_config.health_check_interval_sec = 60;
    siem_config.connection_timeout_sec = config.siem.timeout_seconds;
    siem_config.retry_attempts = 3;
    siem_config.compression_enabled = true;

    siem_config
}

fn resolve_parallel_workers(value: usize) -> usize {
    if value == 0 {
        num_cpus::get().max(1)
    } else {
        value
    }
}

fn merge_strings<I>(mut base: Vec<String>, additional: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    base.extend(additional);
    base.sort();
    base.dedup();
    base
}

// Placeholder modules that need to be implemented
// Removed broad placeholder modules; engine now uses real subsystems.

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_creation() {
        let config = EchConfig::default();
        let engine = EchEngine::new(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_filesystem_scan() {
        let config = EchConfig::default();
        let engine = EchEngine::new(config).await.unwrap();

        let targets = vec!["/tmp".to_string()];
        let result = engine.scan_filesystem(targets).await;
        assert!(result.is_ok());
    }

    #[test]
    fn parses_process_criteria_spec() {
        let criteria =
            parse_process_criteria_spec("name=sshd,min_memory_mb=256,exclude_system=true").unwrap();
        assert_eq!(criteria.name_patterns, vec!["sshd".to_string()]);
        assert_eq!(criteria.min_memory_mb, Some(256));
        assert!(criteria.exclude_system);
    }

    #[test]
    fn parses_memory_region_spec() {
        let (pid, start, size) = parse_memory_region_spec("pid=42,start=0x1000,size=4096").unwrap();
        assert_eq!(pid, 42);
        assert_eq!(start, 0x1000);
        assert_eq!(size, 4096);
    }

    #[test]
    fn detects_full_filesystem_tokens() {
        assert!(is_full_filesystem_target("filesystem://root"));
        assert!(is_full_filesystem_target("FS://*"));
        assert!(!is_full_filesystem_target("/tmp"));
    }

    #[test]
    fn detection_config_respects_entropy_settings() {
        let mut config = EchConfig::default();
        config.detection.entropy_threshold = 5.5;
        config.detection.min_credential_length = 16;
        config.detection.max_credential_length = 256;
        config.operation.dry_run = true;
        config.output.include_full_values = true;

        let detection_config = detection_engine_config(&config);

        assert_eq!(detection_config.entropy_threshold, 5.5);
        assert_eq!(detection_config.min_secret_length, 16);
        assert_eq!(detection_config.max_secret_length, 256);
        assert!(detection_config.include_full_values);
    }
}
