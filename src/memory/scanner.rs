//! Core memory scanning engine responsible for orchestrating analyzers,
//! extractors, stealth checks, and telemetry aggregation.
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
// use tokio::task::JoinSet; // not used in KISS mode
use chrono::{DateTime, Utc};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use super::analyzer::{AnalysisResult, MemoryAnalyzer};
use super::extractor::CredentialExtractor;
use super::process::{MonitoringStatus, ProcessContext, ProcessInfo, ProcessManager};
use super::regions::{MemoryRegion, RegionType};
use super::stealth::{AntiDetection, StealthMemoryScanner};
use super::{MemoryConfig, MemoryError, MemoryStats, PerformanceMetrics};
use crate::detection::{CredentialLocation, DetectionEngine, DetectionResult};

/// Core memory scanner for credential extraction
pub struct MemoryScanner {
    /// Scanner configuration
    config: MemoryConfig,

    /// Process manager
    process_manager: Arc<ProcessManager>,

    /// Memory region analyzer
    memory_analyzer: Arc<MemoryAnalyzer>,

    /// Credential extractor
    credential_extractor: Arc<CredentialExtractor>,

    /// Stealth scanner
    stealth_scanner: Option<Arc<StealthMemoryScanner>>,

    /// Anti-detection system
    anti_detection: Option<Arc<AntiDetection>>,

    /// Scanning statistics
    stats: Arc<RwLock<MemoryStats>>,

    /// Concurrent scanning semaphore
    scan_semaphore: Arc<Semaphore>,

    /// Active scans tracking
    active_scans: Arc<RwLock<HashMap<Uuid, ScanSession>>>,
}

/// Memory scan target specification
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// Scan specific process by PID
    ProcessId(u32),

    /// Scan process by name pattern
    ProcessName(String),

    /// Scan all processes
    AllProcesses,

    /// Scan processes matching criteria
    ProcessCriteria(ProcessCriteria),

    /// Scan a specific memory region in a target process.
    MemoryRegion {
        /// Process identifier containing the region.
        pid: u32,
        /// Starting virtual address for the region slice.
        start: u64,
        /// Number of bytes to read from the region.
        size: usize,
    },
}

/// Process selection criteria
#[derive(Debug, Clone)]
pub struct ProcessCriteria {
    /// Process name patterns
    pub name_patterns: Vec<String>,

    /// Minimum memory usage (MB)
    pub min_memory_mb: Option<u64>,

    /// Maximum memory usage (MB)
    pub max_memory_mb: Option<u64>,

    /// Process age criteria
    pub max_age_hours: Option<u64>,

    /// User context filter
    pub user_filter: Option<String>,

    /// Exclude system processes
    pub exclude_system: bool,

    /// Include child processes
    pub include_children: bool,
}

/// Memory scan session tracking
#[derive(Debug, Clone)]
pub(crate) struct ScanSession {
    /// Session ID
    id: Uuid,

    /// Target being scanned
    target: ScanTarget,

    /// Start time
    start_time: DateTime<Utc>,

    /// Current status
    status: ScanStatus,

    /// Credentials found so far
    credentials_found: u64,

    /// Bytes scanned so far
    bytes_scanned: u64,

    /// Current process being scanned
    current_process: Option<u32>,
}

/// Scan session status
#[derive(Debug, Clone)]
enum ScanStatus {
    Initializing,
    Scanning,
    Analyzing,
    Completing,
    Completed,
    Failed(String),
    Cancelled,
}

/// Memory scan result
/// Result payload returned by memory scans.
#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    /// Scan session ID
    pub session_id: Uuid,

    /// Target that was scanned
    pub target: ScanTarget,

    /// Detected credentials
    pub detections: Vec<DetectionResult>,

    /// Scan summary
    pub summary: ScanSummary,

    /// Process information
    pub process_info: Vec<ProcessInfo>,

    /// Memory analysis results
    pub analysis_results: Vec<AnalysisResult>,

    /// Performance metrics
    pub performance: PerformanceMetrics,

    /// Scan duration
    pub duration: Duration,

    /// Errors encountered
    pub errors: Vec<String>,
}

/// Scan summary statistics
#[derive(Debug, Clone)]
pub struct ScanSummary {
    /// Total processes scanned
    pub processes_scanned: u64,

    /// Total memory regions analyzed
    pub regions_analyzed: u64,

    /// Total bytes scanned
    pub bytes_scanned: u64,

    /// Credentials found
    pub credentials_found: u64,

    /// High-risk credentials
    pub high_risk_credentials: u64,

    /// Suspicious patterns detected
    pub suspicious_patterns: u64,

    /// Anti-detection triggers
    pub anti_detection_triggers: u64,

    /// Scan efficiency (bytes/second)
    pub scan_efficiency: u64,
}

impl MemoryScanner {
    /// Create a new memory scanner
    pub async fn new(config: MemoryConfig) -> Result<Self> {
        info!("🧠 Initializing Memory Scanner");

        let process_manager = Arc::new(
            ProcessManager::new(config.log_memory_reads)
                .await
                .context("Failed to initialize process manager")?,
        );

        let memory_analyzer = Arc::new(
            MemoryAnalyzer::new(&config)
                .await
                .context("Failed to initialize memory analyzer")?,
        );

        let credential_extractor = Arc::new(
            CredentialExtractor::new(&config)
                .await
                .context("Failed to initialize credential extractor")?,
        );

        let stealth_scanner = if config.stealth_mode {
            Some(Arc::new(
                StealthMemoryScanner::new(&config)
                    .await
                    .context("Failed to initialize stealth scanner")?,
            ))
        } else {
            None
        };

        let anti_detection = if config.anti_detection {
            Some(Arc::new(
                AntiDetection::new(&config)
                    .await
                    .context("Failed to initialize anti-detection")?,
            ))
        } else {
            None
        };

        let stats = Arc::new(RwLock::new(MemoryStats::default()));
        let scan_semaphore = Arc::new(Semaphore::new(config.max_concurrent_scans));
        let active_scans = Arc::new(RwLock::new(HashMap::new()));

        info!("✅ Memory Scanner initialized");
        info!("   Stealth mode: {}", config.stealth_mode);
        info!("   Anti-detection: {}", config.anti_detection);
        info!("   SIMD optimizations: {}", config.use_simd);
        info!("   Max concurrent scans: {}", config.max_concurrent_scans);

        Ok(Self {
            config,
            process_manager,
            memory_analyzer,
            credential_extractor,
            stealth_scanner,
            anti_detection,
            stats,
            scan_semaphore,
            active_scans,
        })
    }

    /// Scan memory for credentials by process ID
    pub async fn scan_process_by_pid(
        &self,
        pid: u32,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<Vec<DetectionResult>> {
        let target = ScanTarget::ProcessId(pid);
        let result = self.scan_target(target, detection_engine).await?;
        Ok(result.detections)
    }

    /// Scan memory for credentials by process name
    pub async fn scan_process_by_name(
        &self,
        name: &str,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<Vec<DetectionResult>> {
        let target = ScanTarget::ProcessName(name.to_string());
        let result = self.scan_target(target, detection_engine).await?;
        Ok(result.detections)
    }

    /// Scan all accessible processes
    pub async fn scan_all_processes(
        &self,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<MemoryScanResult> {
        let target = ScanTarget::AllProcesses;
        self.scan_target(target, detection_engine).await
    }

    /// Scan processes matching criteria
    pub async fn scan_with_criteria(
        &self,
        criteria: ProcessCriteria,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<MemoryScanResult> {
        let target = ScanTarget::ProcessCriteria(criteria);
        self.scan_target(target, detection_engine).await
    }

    /// Scan specific memory region
    pub async fn scan_memory_region(
        &self,
        pid: u32,
        start_address: u64,
        size: usize,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<Vec<DetectionResult>> {
        let target = ScanTarget::MemoryRegion {
            pid,
            start: start_address,
            size,
        };
        let result = self.scan_target(target, detection_engine).await?;
        Ok(result.detections)
    }

    /// Core scanning implementation
    async fn scan_target(
        &self,
        target: ScanTarget,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<MemoryScanResult> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();

        info!("🔍 Starting memory scan session {}", session_id);
        debug!("Target: {:?}", target);

        // Acquire scanning semaphore
        let _permit = self
            .scan_semaphore
            .acquire()
            .await
            .context("Failed to acquire scan permit")?;

        // Initialize scan session
        let session = ScanSession {
            id: session_id,
            target: target.clone(),
            start_time,
            status: ScanStatus::Initializing,
            credentials_found: 0,
            bytes_scanned: 0,
            current_process: None,
        };

        {
            let mut active_scans = self.active_scans.write().await;
            active_scans.insert(session_id, session);
        }

        let scan_start = Instant::now();
        let mut all_detections = Vec::new();
        let mut process_info = Vec::new();
        let mut analysis_results = Vec::new();
        let mut errors = Vec::new();
        let mut summary = ScanSummary {
            processes_scanned: 0,
            regions_analyzed: 0,
            bytes_scanned: 0,
            credentials_found: 0,
            high_risk_credentials: 0,
            suspicious_patterns: 0,
            anti_detection_triggers: 0,
            scan_efficiency: 0,
        };

        // Perform anti-detection checks now that we can accumulate metrics
        if let Some(ref anti_detection) = self.anti_detection {
            match anti_detection.check_environment().await {
                Ok(report) => {
                    if !report.triggers.is_empty() {
                        summary.anti_detection_triggers += report.triggers.len() as u64;
                        for trigger in &report.triggers {
                            warn!(
                                target: "ech::anti_detection",
                                trigger = trigger.name,
                                description = %trigger.description,
                                "⚠ Anti-detection trigger fired"
                            );
                        }

                        if report.should_abort() {
                            let _ = self.cancel_scan(session_id).await;
                            return Err(MemoryError::AntiDebuggingDetected.into());
                        }
                    }
                }
                Err(e) => {
                    warn!("Anti-detection check failed: {}", e);
                    if self.config.anti_detection {
                        return Err(MemoryError::AntiDebuggingDetected.into());
                    }
                }
            }
        }

        self.update_session_status(session_id, ScanStatus::Scanning)
            .await;

        // Get target processes
        let target_processes = self.resolve_target_processes(&target).await?;

        if target_processes.is_empty() {
            warn!("No processes found matching target criteria");
            self.update_session_status(
                session_id,
                ScanStatus::Failed("No processes matched target".to_string()),
            )
            .await;
            self.finalize_session(session_id).await;
            return Ok(MemoryScanResult {
                session_id,
                target,
                detections: Vec::new(),
                summary,
                process_info: Vec::new(),
                analysis_results: Vec::new(),
                performance: PerformanceMetrics::default(),
                duration: scan_start.elapsed(),
                errors: vec!["No processes found".to_string()],
            });
        }

        info!("📋 Found {} processes to scan", target_processes.len());

        if let ScanTarget::MemoryRegion { pid, start, size } = &target {
            info!(
                pid,
                start = %format!("0x{:016x}", start),
                size,
                "🎯 Scanning focused memory region"
            );
        }

        // Scan processes sequentially (KISS)
        for process in target_processes {
            let pid = process.pid;
            self.update_session_current_process(session_id, Some(pid))
                .await;
            match self
                .scan_single_process(process, Arc::clone(&detection_engine), &target)
                .await
            {
                Ok(scan_result) => {
                    summary.processes_scanned += 1;
                    summary.regions_analyzed += scan_result.regions_scanned;
                    summary.bytes_scanned += scan_result.bytes_scanned;
                    summary.credentials_found += scan_result.credentials_found as u64;

                    let high_risk = scan_result
                        .detections
                        .iter()
                        .filter(|d| {
                            matches!(
                                d.risk_level,
                                crate::detection::engine::RiskLevel::High
                                    | crate::detection::engine::RiskLevel::Critical
                            )
                        })
                        .count() as u64;
                    summary.high_risk_credentials += high_risk;

                    let suspicious_hits: u64 = scan_result
                        .analysis_results
                        .iter()
                        .map(|result| result.suspicious_patterns.len() as u64)
                        .sum();
                    summary.suspicious_patterns += suspicious_hits;

                    all_detections.extend(scan_result.detections);
                    process_info.push(scan_result.process_info);
                    analysis_results.extend(scan_result.analysis_results);

                    self.update_session_progress(
                        session_id,
                        scan_result.bytes_scanned,
                        scan_result.credentials_found as u64,
                    )
                    .await;
                }
                Err(e) => {
                    error!("Process scan failed: {}", e);
                    errors.push(e.to_string());
                }
            }
        }

        self.update_session_current_process(session_id, None).await;

        self.update_session_status(session_id, ScanStatus::Analyzing)
            .await;

        let scan_duration = scan_start.elapsed();

        let avg_cpu_usage = if process_info.is_empty() {
            0.0
        } else {
            process_info.iter().map(|info| info.cpu_usage).sum::<f64>() / process_info.len() as f64
        };

        summary.scan_efficiency = if scan_duration.as_secs_f64() > 0.0 {
            (summary.bytes_scanned as f64 / scan_duration.as_secs_f64()) as u64
        } else {
            summary.bytes_scanned
        };

        let scan_rate_bps = summary.scan_efficiency;

        // Update global statistics
        {
            let mut stats = self.stats.write().await;
            stats.processes_scanned += summary.processes_scanned;
            stats.regions_scanned += summary.regions_analyzed;
            stats.bytes_scanned += summary.bytes_scanned;
            stats.credentials_found += summary.credentials_found;
            stats.scan_errors += errors.len() as u64;
            stats.anti_detection_triggers += summary.anti_detection_triggers;

            // Update average scan time
            let total_scans = stats.processes_scanned.max(1);
            stats.avg_scan_time_ms = (stats.avg_scan_time_ms.saturating_mul(total_scans - 1)
                + scan_duration.as_millis() as u64)
                / total_scans;

            stats.performance_metrics.scan_rate_bps = scan_rate_bps;
            stats.performance_metrics.cpu_utilization = avg_cpu_usage;
        }

        self.update_session_status(session_id, ScanStatus::Completing)
            .await;

        self.update_session_status(session_id, ScanStatus::Completed)
            .await;

        info!(
            "✅ Memory scan completed: {} credentials found in {:.2}s",
            summary.credentials_found,
            scan_duration.as_secs_f64()
        );

        if let Some(session) = self.finalize_session(session_id).await {
            let elapsed = Utc::now()
                .signed_duration_since(session.start_time)
                .num_seconds();
            debug!(
                session_id = %session.id,
                target = ?session.target,
                duration_secs = elapsed,
                bytes_scanned = session.bytes_scanned,
                credentials = session.credentials_found,
                "Memory scan session finalized"
            );
        }

        let remaining_sessions = self.get_active_scans().await.len();
        debug!(
            remaining_sessions,
            "Memory scanner active sessions remaining"
        );

        self.process_manager.clear_cache();

        Ok(MemoryScanResult {
            session_id,
            target,
            detections: all_detections,
            summary,
            process_info,
            analysis_results,
            performance: PerformanceMetrics {
                scan_rate_bps,
                cpu_utilization: avg_cpu_usage,
                ..PerformanceMetrics::default()
            },
            duration: scan_duration,
            errors,
        })
    }

    /// Resolve target specification to actual processes
    async fn resolve_target_processes(&self, target: &ScanTarget) -> Result<Vec<ProcessInfo>> {
        match target {
            ScanTarget::ProcessId(pid) => match self.process_manager.get_process_info(*pid).await {
                Ok(info) => Ok(vec![info]),
                Err(_) => Err(MemoryError::ProcessNotFound { pid: *pid }.into()),
            },

            ScanTarget::ProcessName(name) => {
                self.process_manager.find_processes_by_name(name).await
            }

            ScanTarget::AllProcesses => self.process_manager.get_all_processes().await,

            ScanTarget::ProcessCriteria(criteria) => {
                self.process_manager
                    .find_processes_by_criteria(criteria)
                    .await
            }

            ScanTarget::MemoryRegion { pid, .. } => {
                match self.process_manager.get_process_info(*pid).await {
                    Ok(info) => Ok(vec![info]),
                    Err(_) => Err(MemoryError::ProcessNotFound { pid: *pid }.into()),
                }
            }
        }
    }

    /// Scan a single process for credentials
    async fn scan_single_process(
        &self,
        process: ProcessInfo,
        detection_engine: Arc<DetectionEngine>,
        target: &ScanTarget,
    ) -> Result<ProcessScanResult> {
        let pid = process.pid;

        debug!("🔍 Scanning process {} ({})", pid, process.name);

        if !self.process_manager.process_exists(pid).await {
            warn!(pid, "Process vanished before scan could start");
            return Ok(ProcessScanResult::empty(process));
        }

        let mut process_context = match self.process_manager.create_process_context(pid).await {
            Ok(ctx) => ctx,
            Err(err) => {
                warn!(pid, "Failed to build process context: {}", err);
                return Ok(ProcessScanResult::empty(process));
            }
        };
        self.log_process_context_details(&process_context);
        process_context.monitoring_status = MonitoringStatus::Active;

        if !process_context.memory_accessible || !process_context.scan_permissions.read_memory {
            process_context.monitoring_status = MonitoringStatus::Paused;
            warn!(
                pid,
                accessible = process_context.memory_accessible,
                read_memory = process_context.scan_permissions.read_memory,
                "Skipping process due to insufficient memory access"
            );
            return Ok(ProcessScanResult::empty(process));
        }

        if !process_context.scan_permissions.enumerate_regions {
            process_context.monitoring_status = MonitoringStatus::Paused;
            warn!(pid, "Skipping process; cannot enumerate regions");
            return Ok(ProcessScanResult::empty(process));
        }

        debug!(
            pid,
            risk = ?process_context.risk_level,
            monitoring = ?process_context.monitoring_status,
            "Process context prepared for memory scan"
        );

        let scan_start = Instant::now();
        let mut detections = Vec::new();
        let mut analysis_results = Vec::new();
        let mut regions_scanned = 0u64;
        let mut bytes_scanned = 0u64;

        // Get memory map for process
        let memory_map = match self.process_manager.get_memory_map(pid).await {
            Ok(map) => map,
            Err(e) => {
                warn!("Failed to get memory map for process {}: {}", pid, e);
                return Ok(ProcessScanResult::empty(process));
            }
        };

        info!(
            pid,
            map_pid = memory_map.pid,
            regions = memory_map.regions.len(),
            "📊 Process memory map prepared"
        );

        // Filter regions based on configuration
        let mut scannable_regions = self.filter_scannable_regions(&memory_map.regions);

        if let ScanTarget::MemoryRegion { start, size, .. } = target {
            scannable_regions = scannable_regions
                .into_iter()
                .filter_map(|mut region| {
                    let region_end = region.start_address + region.size as u64;
                    if *start < region.start_address || *start >= region_end {
                        return None;
                    }
                    let offset = (*start).saturating_sub(region.start_address) as usize;
                    let available = region.size.saturating_sub(offset);
                    region.start_address = *start;
                    region.size = (*size).min(available);
                    Some(region)
                })
                .collect();
        }

        if scannable_regions.is_empty() {
            process_context.monitoring_status = MonitoringStatus::Paused;
            debug!("No scannable regions found for process {}", pid);
            return Ok(ProcessScanResult::empty(process));
        }

        // Scan each region
        for region in scannable_regions {
            // Check scan timeout
            if scan_start.elapsed().as_secs() > self.config.scan_timeout_sec {
                warn!("Scan timeout reached for process {}", pid);
                break;
            }

            // Check memory limit
            if bytes_scanned > self.config.max_memory_mb * 1024 * 1024 {
                warn!("Memory scan limit reached for process {}", pid);
                break;
            }

            match self
                .scan_memory_region_impl(pid, &region, &detection_engine)
                .await
            {
                Ok(region_result) => {
                    detections.extend(region_result.detections);
                    analysis_results.extend(region_result.analysis_results);
                    regions_scanned += 1;
                    bytes_scanned += region_result.bytes_read;
                }
                Err(e) => {
                    debug!("Failed to scan region {:016x}: {}", region.start_address, e);
                    // Continue with other regions
                }
            }
        }

        let credentials_found = detections.len();

        debug!(
            "✅ Process {} scan complete: {} credentials found",
            pid, credentials_found
        );

        process_context.monitoring_status = MonitoringStatus::Paused;
        debug!(
            pid,
            monitoring_status = ?process_context.monitoring_status,
            "Process monitoring paused after scan"
        );

        Ok(ProcessScanResult {
            process_info: process,
            detections,
            analysis_results,
            regions_scanned,
            bytes_scanned,
            credentials_found,
        })
    }

    /// Filter memory regions based on configuration
    fn filter_scannable_regions(&self, regions: &[MemoryRegion]) -> Vec<MemoryRegion> {
        regions
            .iter()
            .filter(|region| {
                // Check minimum size
                if region.size < self.config.min_region_size {
                    return false;
                }

                // Check if region is readable
                if !region.permissions.read {
                    return false;
                }

                // Filter by region type based on config
                match region.region_type {
                    RegionType::Heap => self.config.scan_heap,
                    RegionType::Stack => self.config.scan_stack,
                    RegionType::Module => self.config.scan_modules,
                    RegionType::Private => self.config.scan_private,
                    RegionType::Mapped => true,
                    RegionType::Unknown => false,
                }
            })
            .cloned()
            .collect()
    }

    /// Scan a specific memory region
    async fn scan_memory_region_impl(
        &self,
        pid: u32,
        region: &MemoryRegion,
        detection_engine: &DetectionEngine,
    ) -> Result<RegionScanResult> {
        trace!(
            start = %format!("0x{:016x}", region.start_address),
            end = %format!(
                "0x{:016x}",
                region.start_address + region.size as u64
            ),
            region_type = ?region.region_type,
            writable = region.permissions.write,
            executable = region.permissions.execute,
            protection = %region.protection,
            module = region.module_name.as_deref().unwrap_or("anonymous"),
            "🔍 Scanning memory region"
        );

        // Read memory region
        let memory_data = if let Some(ref stealth_scanner) = self.stealth_scanner {
            stealth_scanner
                .read_memory_stealthy(pid, region.start_address, region.size)
                .await?
        } else {
            self.process_manager
                .read_process_memory(pid, region.start_address, region.size)
                .await?
        };

        let mut detections = Vec::new();
        let mut analysis_results = Vec::new();

        let chunk_size = self.config.analysis_chunk_size.max(1);
        if memory_data.is_empty() {
            let analysis = self
                .memory_analyzer
                .analyze_memory_block(&memory_data, region, 0)
                .await?;
            if is_interesting_analysis(&analysis) {
                trace!(
                    base_address = %format!("0x{:016x}", analysis.base_address),
                    start_offset = analysis.start_offset,
                    length = analysis.length,
                    null_bytes = analysis.null_bytes,
                    suspicious = analysis.suspicious_patterns.len(),
                    entropy = analysis.entropy,
                    printable_ratio = analysis.printable_ratio,
                    "Interesting memory analysis segment"
                );
                for pattern in &analysis.suspicious_patterns {
                    trace!(
                        pattern = pattern.pattern,
                        offset = pattern.offset,
                        address = %format!("0x{:016x}", pattern.address),
                        "Suspicious pattern detected in memory"
                    );
                }
                analysis_results.push(analysis);
            }
        } else {
            let mut offset = 0usize;
            for chunk in memory_data.chunks(chunk_size) {
                let analysis = self
                    .memory_analyzer
                    .analyze_memory_block(chunk, region, offset)
                    .await?;
                if is_interesting_analysis(&analysis) {
                    trace!(
                        base_address = %format!("0x{:016x}", analysis.base_address),
                        start_offset = analysis.start_offset,
                        length = analysis.length,
                        null_bytes = analysis.null_bytes,
                        suspicious = analysis.suspicious_patterns.len(),
                        entropy = analysis.entropy,
                        printable_ratio = analysis.printable_ratio,
                        "Interesting memory analysis segment"
                    );
                    for pattern in &analysis.suspicious_patterns {
                        trace!(
                            pattern = pattern.pattern,
                            offset = pattern.offset,
                            address = %format!("0x{:016x}", pattern.address),
                            "Suspicious pattern detected in memory"
                        );
                    }
                    analysis_results.push(analysis);
                }
                offset += chunk.len();
            }
        }

        // Extract credentials using configured methods
        let extraction_results = self
            .credential_extractor
            .extract_credentials(&memory_data, region, detection_engine)
            .await?;

        for extraction in extraction_results {
            let location = CredentialLocation {
                source_type: "memory".to_string(),
                path: format!("process:{}", pid),
                line_number: None,
                column: None,
                memory_address: Some(region.start_address + extraction.offset as u64),
                process_id: Some(pid),
                container_id: None,
            };

            let mut detection = extraction.detection;
            detection.location = location;

            detections.push(detection);
        }

        Ok(RegionScanResult {
            detections,
            analysis_results,
            bytes_read: memory_data.len() as u64,
        })
    }

    async fn update_session_status(&self, session_id: Uuid, status: ScanStatus) {
        let mut active_scans = self.active_scans.write().await;
        if let Some(session) = active_scans.get_mut(&session_id) {
            session.status = status.clone();
            match &session.status {
                ScanStatus::Failed(reason) => {
                    debug!(
                        session_id = %session.id,
                        target = ?session.target,
                        status = ?session.status,
                        failure_reason = reason.as_str(),
                        "Memory scan status updated"
                    );
                }
                _ => {
                    debug!(
                        session_id = %session.id,
                        target = ?session.target,
                        status = ?session.status,
                        "Memory scan status updated"
                    );
                }
            }
        }
    }

    async fn update_session_current_process(&self, session_id: Uuid, pid: Option<u32>) {
        let mut active_scans = self.active_scans.write().await;
        if let Some(session) = active_scans.get_mut(&session_id) {
            session.current_process = pid;
            if let Some(pid) = pid {
                trace!(session_id = %session.id, pid, "Scanning process context updated");
            }
        }
    }

    async fn update_session_progress(
        &self,
        session_id: Uuid,
        bytes_scanned: u64,
        new_credentials: u64,
    ) {
        let mut active_scans = self.active_scans.write().await;
        if let Some(session) = active_scans.get_mut(&session_id) {
            session.bytes_scanned += bytes_scanned;
            session.credentials_found += new_credentials;
            debug!(
                session_id = %session.id,
                bytes_scanned = session.bytes_scanned,
                credentials = session.credentials_found,
                "Memory scan progress updated"
            );
        }
    }

    async fn finalize_session(&self, session_id: Uuid) -> Option<ScanSession> {
        let mut active_scans = self.active_scans.write().await;
        active_scans.remove(&session_id)
    }

    /// Get current scanning statistics
    pub async fn get_stats(&self) -> MemoryStats {
        self.stats.read().await.clone()
    }

    /// Get active scan sessions
    pub(crate) async fn get_active_scans(&self) -> Vec<ScanSession> {
        self.active_scans.read().await.values().cloned().collect()
    }

    /// Cancel a scan session
    pub async fn cancel_scan(&self, session_id: Uuid) -> Result<()> {
        let mut active_scans = self.active_scans.write().await;
        let process_to_terminate = if let Some(session) = active_scans.get_mut(&session_id) {
            session.status = ScanStatus::Cancelled;
            info!("🚫 Cancelled scan session {}", session_id);
            session.current_process
        } else {
            return Err(anyhow!("Scan session not found: {}", session_id));
        };
        drop(active_scans);

        if self.config.terminate_on_cancel {
            if let Some(pid) = process_to_terminate {
                if let Err(err) = self.process_manager.terminate_process(pid).await {
                    warn!(
                        pid,
                        "Failed to terminate process after cancellation: {}", err
                    );
                } else {
                    info!(pid, "Terminated process after scan cancellation");
                }
            }
        }

        if let Some(session) = self.finalize_session(session_id).await {
            debug!(
                session_id = %session.id,
                target = ?session.target,
                "Memory scan session cancelled and cleaned up"
            );
        }

        Ok(())
    }

    fn log_process_context_details(&self, context: &ProcessContext) {
        let info = &context.info;
        let security = &info.security_context;
        debug!(
            pid = info.pid,
            ppid = info.ppid,
            user = %info.user,
            command_line = ?info.command_line,
            start_time = %info.start_time.to_rfc3339(),
            working_dir = %info.working_directory,
            memory_bytes = info.memory_usage,
            cpu_percent = info.cpu_usage,
            env_vars = info.environment.len(),
            children = ?info.children,
            file_handles = info.file_handles,
            network_connections = info.network_connections,
            is_system = info.is_system,
            effective_uid = security.effective_uid,
            effective_gid = security.effective_gid,
            privileges = ?security.privileges,
            security_labels = ?security.security_labels,
            elevated = security.is_elevated,
            can_access_processes = security.can_access_processes,
            protection = ?security.protection_level,
            monitoring_status = ?context.monitoring_status,
            "Process context snapshot"
        );
    }
}

/// Result of scanning a single process
#[derive(Debug)]
struct ProcessScanResult {
    process_info: ProcessInfo,
    detections: Vec<DetectionResult>,
    analysis_results: Vec<AnalysisResult>,
    regions_scanned: u64,
    bytes_scanned: u64,
    credentials_found: usize,
}

impl ProcessScanResult {
    fn empty(process_info: ProcessInfo) -> Self {
        Self {
            process_info,
            detections: Vec::new(),
            analysis_results: Vec::new(),
            regions_scanned: 0,
            bytes_scanned: 0,
            credentials_found: 0,
        }
    }
}

/// Result of scanning a single memory region
#[derive(Debug)]
struct RegionScanResult {
    detections: Vec<DetectionResult>,
    analysis_results: Vec<AnalysisResult>,
    bytes_read: u64,
}

fn is_interesting_analysis(analysis: &AnalysisResult) -> bool {
    if !analysis.suspicious_patterns.is_empty() {
        return true;
    }

    if analysis.length == 0 {
        return false;
    }

    analysis.entropy >= 7.5 || analysis.printable_ratio <= 0.20
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_scanner_creation() {
        let config = MemoryConfig::default();
        let scanner = MemoryScanner::new(config).await;

        // Scanner creation may fail on systems without memory scanning capabilities
        match scanner {
            Ok(_) => {
                // Scanner created successfully
            }
            Err(e) => {
                // Expected on systems without privileges
                println!("Memory scanner creation failed (expected): {}", e);
            }
        }
    }

    #[test]
    fn test_scan_target_types() {
        let pid_target = ScanTarget::ProcessId(1234);
        let name_target = ScanTarget::ProcessName("test".to_string());
        let all_target = ScanTarget::AllProcesses;

        // Just ensure the types compile and can be created
        assert!(matches!(pid_target, ScanTarget::ProcessId(1234)));
        assert!(matches!(name_target, ScanTarget::ProcessName(_)));
        assert!(matches!(all_target, ScanTarget::AllProcesses));
    }

    #[test]
    fn test_process_criteria() {
        let criteria = ProcessCriteria {
            name_patterns: vec!["test*".to_string()],
            min_memory_mb: Some(10),
            max_memory_mb: Some(1000),
            max_age_hours: Some(24),
            user_filter: None,
            exclude_system: true,
            include_children: false,
        };

        assert_eq!(criteria.name_patterns.len(), 1);
        assert_eq!(criteria.min_memory_mb, Some(10));
        assert!(criteria.exclude_system);
    }

    #[tokio::test]
    async fn test_cancel_scan_gracefully() {
        let config = MemoryConfig::default();
        let scanner = match MemoryScanner::new(config).await {
            Ok(scanner) => scanner,
            Err(_) => return, // skip on platforms without privileges
        };

        let session_id = Uuid::new_v4();
        {
            let mut sessions = scanner.active_scans.write().await;
            sessions.insert(
                session_id,
                ScanSession {
                    id: session_id,
                    target: ScanTarget::AllProcesses,
                    start_time: Utc::now(),
                    status: ScanStatus::Scanning,
                    credentials_found: 0,
                    bytes_scanned: 0,
                    current_process: Some(std::process::id()),
                },
            );
        }

        let result = scanner.cancel_scan(session_id).await;
        assert!(result.is_ok());
    }
}
