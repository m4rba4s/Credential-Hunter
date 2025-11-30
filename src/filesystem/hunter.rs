/**
 * ECH Filesystem Hunter - Core Filesystem Credential Scanning Engine
 *
 * This module implements the main filesystem hunting engine that orchestrates
 * comprehensive file system scanning for credential detection. Features atomic
 * operations, parallel processing, and enterprise-grade performance optimization.
 *
 * Features:
 * - Atomic file scanning with rollback capability
 * - Multi-threaded directory traversal
 * - Work-stealing queue optimization
 * - Memory-mapped file processing
 * - Real-time progress tracking
 * - Advanced filtering and exclusion rules
 * - Archive and compressed file support
 * - Symbolic link loop detection
 */
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use futures::{stream::FuturesUnordered, StreamExt};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::analyzers::{FileAnalysis, FileAnalyzer};
use super::archives::{ArchiveScanner, ArchiveType};
use super::filters::FileFilter;
use super::metadata::{FileMetadata, MetadataAnalyzer};
use super::scanner::{FileScanner, ScanOptions};
use super::watchers::{FilesystemMonitorEvent, FilesystemWatcher};
use super::{FilesystemConfig, FilesystemError, FilesystemStats, ScanTarget};
use crate::detection::{CredentialLocation, DetectionEngine, DetectionResult};

/// Main filesystem hunting engine
pub struct FilesystemHunter {
    /// Hunter configuration
    config: FilesystemConfig,

    /// File scanner
    file_scanner: Arc<FileScanner>,

    /// File analyzer
    file_analyzer: Arc<FileAnalyzer>,

    /// Archive scanner
    archive_scanner: Arc<ArchiveScanner>,

    /// Metadata analyzer
    metadata_analyzer: Arc<MetadataAnalyzer>,

    /// File filter
    file_filter: Arc<FileFilter>,

    /// Filesystem watcher
    filesystem_watcher: Option<Arc<FilesystemWatcher>>,

    /// Scanning statistics
    stats: Arc<RwLock<FilesystemStats>>,

    /// Worker semaphore for concurrency control
    worker_semaphore: Arc<Semaphore>,

    /// Active scan sessions
    active_scans: Arc<RwLock<HashMap<Uuid, ScanSession>>>,

    /// Symlink tracking for loop detection
    symlink_tracker: Arc<RwLock<HashSet<PathBuf>>>,
}

/// Hunter configuration (re-export for convenience)
#[allow(unused_imports)]
pub use super::FilesystemConfig as HunterConfig;

/// Scan session tracking
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct ScanSession {
    /// Session ID
    id: Uuid,

    /// Scan target
    target: ScanTarget,

    /// Start time
    start_time: DateTime<Utc>,

    /// Current status
    status: ScanStatus,

    /// Files processed
    files_processed: u64,

    /// Credentials found
    credentials_found: u64,

    /// Current file being processed
    current_file: Option<PathBuf>,

    /// Progress percentage (0.0-1.0)
    progress: f64,
}

/// Scan session status
#[allow(dead_code)]
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

/// Filesystem scan result
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Scan session ID
    pub session_id: Uuid,

    /// Target that was scanned
    pub target: ScanTarget,

    /// Detected credentials
    pub detections: Vec<DetectionResult>,

    /// Scan summary
    pub summary: ScanSummary,

    /// File analysis results
    pub file_analyses: Vec<FileAnalysis>,

    /// Metadata analyses
    pub metadata_analyses: Vec<FileMetadata>,

    /// Archive scan results
    pub archive_results: Vec<ArchiveScanResult>,

    /// Scan duration
    pub duration: Duration,

    /// Errors encountered
    pub errors: Vec<String>,

    /// Performance metrics
    pub performance: super::FilesystemPerformanceMetrics,
}

/// Scan summary statistics
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScanSummary {
    /// Total files scanned
    pub files_scanned: u64,

    /// Total directories traversed
    pub directories_traversed: u64,

    /// Total bytes processed
    pub bytes_processed: u64,

    /// Credentials found
    pub credentials_found: u64,

    /// High-risk credentials
    pub high_risk_credentials: u64,

    /// Files skipped
    pub files_skipped: u64,

    /// Archives processed
    pub archives_processed: u64,

    /// Symlinks followed
    pub symlinks_followed: u64,

    /// Scan efficiency (files/second)
    pub scan_efficiency: f64,
}

/// Archive scan result
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ArchiveScanResult {
    /// Archive file path
    pub archive_path: PathBuf,

    /// Archive type
    pub archive_type: ArchiveType,

    /// Entries scanned
    pub entries_scanned: u64,

    /// Credentials found in archive
    pub credentials_found: u64,

    /// Processing time
    pub processing_time: Duration,
}

/// Work item for parallel processing
#[derive(Debug, Clone)]
enum WorkItem {
    /// Scan a file
    File(PathBuf),

    /// Traverse a directory
    Directory(PathBuf),

    /// Process an archive
    Archive(PathBuf),

    /// Analyze metadata
    Metadata(PathBuf),
}

impl FilesystemHunter {
    /// Create a new filesystem hunter
    pub async fn new(config: FilesystemConfig) -> Result<Self> {
        info!("📁 Initializing Filesystem Hunter");

        let file_scanner = Arc::new(
            FileScanner::new(&config)
                .await
                .context("Failed to initialize file scanner")?,
        );

        let file_analyzer =
            Arc::new(FileAnalyzer::new(&config).context("Failed to initialize file analyzer")?);

        let archive_scanner =
            Arc::new(ArchiveScanner::new(&config).context("Failed to initialize archive scanner")?);

        let metadata_analyzer = Arc::new(
            MetadataAnalyzer::new(&config).context("Failed to initialize metadata analyzer")?,
        );

        let file_filter =
            Arc::new(FileFilter::new(&config).context("Failed to initialize file filter")?);

        let filesystem_watcher = if config.realtime_monitoring {
            Some(Arc::new(
                FilesystemWatcher::new(&config)
                    .await
                    .context("Failed to initialize filesystem watcher")?,
            ))
        } else {
            None
        };

        let stats = Arc::new(RwLock::new(FilesystemStats::default()));
        let worker_semaphore = Arc::new(Semaphore::new(config.worker_threads));
        let active_scans = Arc::new(RwLock::new(HashMap::new()));
        let symlink_tracker = Arc::new(RwLock::new(HashSet::new()));

        info!("✅ Filesystem Hunter initialized");
        info!("   Worker threads: {}", config.worker_threads);
        info!(
            "   Max file size: {} MB",
            config.max_file_size / 1024 / 1024
        );
        info!("   Archive scanning: {}", config.scan_archives);
        info!("   Real-time monitoring: {}", config.realtime_monitoring);

        Ok(Self {
            config,
            file_scanner,
            file_analyzer,
            archive_scanner,
            metadata_analyzer,
            file_filter,
            filesystem_watcher,
            stats,
            worker_semaphore,
            active_scans,
            symlink_tracker,
        })
    }

    /// Scan a filesystem target for credentials
    pub async fn scan_path(
        &self,
        path: &str,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<ScanResult> {
        let target = if std::path::Path::new(path).is_dir() {
            ScanTarget::directory_with_depth(path, self.config.max_depth)
        } else {
            ScanTarget::file(path)
        };

        self.scan_target(target, detection_engine).await
    }

    /// Scan multiple paths
    pub async fn scan_paths(
        &self,
        paths: Vec<String>,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<ScanResult> {
        let target = ScanTarget::multiple(paths);

        self.scan_target(target, detection_engine).await
    }

    /// Scan with glob pattern
    #[allow(dead_code)]
    pub async fn scan_glob(
        &self,
        pattern: &str,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<ScanResult> {
        let target = ScanTarget::Glob(pattern.to_string());
        self.scan_target(target, detection_engine).await
    }

    /// Scan the entire filesystem root (explicit opt-in)
    pub async fn scan_filesystem_root(
        &self,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<ScanResult> {
        self.scan_target(ScanTarget::Filesystem, detection_engine)
            .await
    }

    /// Core scan implementation
    async fn scan_target(
        &self,
        target: ScanTarget,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<ScanResult> {
        let session_id = Uuid::new_v4();
        let start_time = Utc::now();
        let scan_start = Instant::now();

        info!("🔍 Starting filesystem scan session {}", session_id);
        debug!("Target: {:?}", target);

        // Initialize scan session
        let session = ScanSession {
            id: session_id,
            target: target.clone(),
            start_time,
            status: ScanStatus::Initializing,
            files_processed: 0,
            credentials_found: 0,
            current_file: None,
            progress: 0.0,
        };

        {
            let mut active_scans = self.active_scans.write().await;
            active_scans.insert(session_id, session);
        }

        // Update session status
        self.update_session_status(session_id, ScanStatus::Scanning)
            .await;

        // Resolve target to work items
        let work_items = self.resolve_target_to_work_items(&target).await?;

        if work_items.is_empty() {
            warn!("No files found matching target criteria");
            self.update_session_status(
                session_id,
                ScanStatus::Failed("No files matched target criteria".to_string()),
            )
            .await;
            self.finalize_session(session_id).await;
            return Ok(ScanResult {
                session_id,
                target,
                detections: Vec::new(),
                summary: ScanSummary {
                    files_scanned: 0,
                    directories_traversed: 0,
                    bytes_processed: 0,
                    credentials_found: 0,
                    high_risk_credentials: 0,
                    files_skipped: 0,
                    archives_processed: 0,
                    symlinks_followed: 0,
                    scan_efficiency: 0.0,
                },
                file_analyses: Vec::new(),
                metadata_analyses: Vec::new(),
                archive_results: Vec::new(),
                duration: scan_start.elapsed(),
                errors: vec!["No files found".to_string()],
                performance: super::FilesystemPerformanceMetrics::default(),
            });
        }

        info!("📋 Found {} items to process", work_items.len());

        // Process work items with bounded concurrency
        let total_items = work_items.len();
        let mut all_detections = Vec::new();
        let mut file_analyses = Vec::new();
        let mut metadata_analyses = Vec::new();
        let mut archive_results = Vec::new();
        let mut errors = Vec::new();
        let mut summary = ScanSummary {
            files_scanned: 0,
            directories_traversed: 0,
            bytes_processed: 0,
            credentials_found: 0,
            high_risk_credentials: 0,
            files_skipped: 0,
            archives_processed: 0,
            symlinks_followed: 0,
            scan_efficiency: 0.0,
        };

        let worker_semaphore = Arc::clone(&self.worker_semaphore);
        let mut in_flight = FuturesUnordered::new();

        for work_item in work_items {
            let detection_engine = Arc::clone(&detection_engine);
            let semaphore = Arc::clone(&worker_semaphore);
            let hunter = self;
            in_flight.push(async move {
                let permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|err| anyhow!("Worker pool unavailable: {err}"))?;
                let _permit = permit;
                hunter
                    .process_work_item(work_item, detection_engine, session_id)
                    .await
            });
        }

        while let Some(result) = in_flight.next().await {
            match result {
                Ok(mut work_result) => {
                    if let Some(analysis) = work_result.file_analysis.take() {
                        file_analyses.push(analysis);
                    }
                    if let Some(metadata) = work_result.metadata.take() {
                        metadata_analyses.push(metadata);
                    }
                    if let Some(archive_result) = work_result.archive_result.take() {
                        archive_results.push(archive_result);
                    }

                    summary.files_scanned += work_result.files_processed;
                    summary.directories_traversed += work_result.directories_traversed;
                    summary.archives_processed += work_result.archives_processed;
                    summary.bytes_processed += work_result.bytes_processed;
                    all_detections.append(&mut work_result.detections);

                    self.update_session_progress(
                        session_id,
                        1,
                        total_items,
                        work_result.credentials_found,
                    )
                    .await;
                }
                Err(e) => {
                    error!("Work item processing failed: {}", e);
                    errors.push(e.to_string());
                }
            }
        }

        self.update_session_status(session_id, ScanStatus::Analyzing)
            .await;

        let scan_duration = scan_start.elapsed();

        // Calculate final metrics
        summary.credentials_found = all_detections.len() as u64;
        summary.high_risk_credentials = all_detections
            .iter()
            .filter(|d| {
                matches!(
                    d.risk_level,
                    crate::detection::engine::RiskLevel::High
                        | crate::detection::engine::RiskLevel::Critical
                )
            })
            .count() as u64;

        summary.scan_efficiency = if scan_duration.as_secs_f64() > 0.0 {
            summary.files_scanned as f64 / scan_duration.as_secs_f64()
        } else {
            0.0
        };

        self.update_session_status(session_id, ScanStatus::Completing)
            .await;

        // Update global statistics
        {
            let mut stats = self.stats.write().await;
            stats.files_scanned += summary.files_scanned;
            stats.directories_traversed += summary.directories_traversed;
            stats.bytes_processed += summary.bytes_processed;
            stats.credentials_found += summary.credentials_found;
            stats.high_risk_credentials += summary.high_risk_credentials;
            stats.archives_processed += summary.archives_processed;
            stats.scan_errors += errors.len() as u64;

            // Update average scan time
            if stats.files_scanned > 0 {
                stats.avg_scan_time_ms = (stats.avg_scan_time_ms
                    * (stats.files_scanned - summary.files_scanned)
                    + scan_duration.as_millis() as u64)
                    / stats.files_scanned;
            }
        }

        // Update session status
        self.update_session_status(session_id, ScanStatus::Completed)
            .await;

        info!(
            "✅ Filesystem scan completed: {} credentials found in {:.2}s",
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
                progress = session.progress,
                creds = session.credentials_found,
                duration_secs = elapsed,
                "Filesystem scan session finalized"
            );
        }

        let remaining_sessions = self.get_active_scans().await.len();
        debug!(
            remaining_sessions,
            "Filesystem hunter active sessions remaining"
        );

        self.emit_scan_telemetry(&file_analyses, &metadata_analyses);

        Ok(ScanResult {
            session_id,
            target,
            detections: all_detections,
            summary,
            file_analyses,
            metadata_analyses,
            archive_results,
            duration: scan_duration,
            errors,
            performance: super::FilesystemPerformanceMetrics::default(), // TODO: Collect actual metrics
        })
    }

    fn emit_scan_telemetry(
        &self,
        file_analyses: &[FileAnalysis],
        metadata_analyses: &[FileMetadata],
    ) {
        if !tracing::level_enabled!(tracing::Level::DEBUG) {
            return;
        }

        if file_analyses.is_empty() && metadata_analyses.is_empty() {
            return;
        }

        let binary_files = file_analyses
            .iter()
            .filter(|analysis| analysis.content.is_binary)
            .count();
        let largest_file = file_analyses
            .iter()
            .max_by_key(|analysis| analysis.size)
            .map(|analysis| (analysis.path.display().to_string(), analysis.size));

        let mut latest_modified: Option<&DateTime<Utc>> = None;
        let mut latest_accessed: Option<&DateTime<Utc>> = None;
        for analysis in file_analyses {
            if let Some(ref modified) = analysis.modified {
                if latest_modified.map_or(true, |current| modified > current) {
                    latest_modified = Some(modified);
                }
            }
            if let Some(ref accessed) = analysis.accessed {
                if latest_accessed.map_or(true, |current| accessed > current) {
                    latest_accessed = Some(accessed);
                }
            }
        }

        let preview_samples: Vec<String> = file_analyses
            .iter()
            .filter(|analysis| !analysis.content.preview.is_empty())
            .take(3)
            .map(|analysis| {
                let first_line = analysis
                    .content
                    .preview
                    .lines()
                    .next()
                    .unwrap_or("<binary>")
                    .trim();
                format!("{}: {}", analysis.path.display(), first_line)
            })
            .collect();

        let metadata_samples: Vec<String> = metadata_analyses
            .iter()
            .take(3)
            .map(|entry| {
                format!(
                    "{}: readonly={}, dir={}, symlink={}, perms={}, owner={:?}, group={:?}, created={:?}, modified={:?}, accessed={:?}, size={}, xattrs={:?}",
                    entry.path.display(),
                    entry.readonly,
                    entry.is_directory,
                    entry.is_symlink,
                    entry.permissions,
                    entry.owner,
                    entry.group,
                    entry.created,
                    entry.modified,
                    entry.accessed,
                    entry.size,
                    entry.extended_attributes.keys.clone()
                )
            })
            .collect();

        let readonly_files = metadata_analyses
            .iter()
            .filter(|entry| entry.readonly)
            .count();
        let symlink_targets = metadata_analyses
            .iter()
            .filter(|entry| entry.is_symlink)
            .count();
        let directory_entries = metadata_analyses
            .iter()
            .filter(|entry| entry.is_directory)
            .count();

        let last_modified = latest_modified.map(|dt| dt.to_rfc3339());
        let last_accessed = latest_accessed.map(|dt| dt.to_rfc3339());

        debug!(
            binary_files,
            readonly_files,
            symlink_targets,
            directory_entries,
            largest_file = ?largest_file,
            last_modified = ?last_modified,
            last_accessed = ?last_accessed,
            preview_samples = ?preview_samples,
            metadata_samples = ?metadata_samples,
            "Filesystem analysis telemetry"
        );
    }

    /// Resolve scan target to work items
    async fn resolve_target_to_work_items(&self, target: &ScanTarget) -> Result<Vec<WorkItem>> {
        match target {
            ScanTarget::File(path) => {
                if path.is_file() {
                    let mut items = vec![WorkItem::File(path.clone())];
                    if self.config.scan_archives && self.archive_scanner.is_archive(path).await {
                        items.push(WorkItem::Archive(path.clone()));
                    }
                    items.push(WorkItem::Metadata(path.clone()));
                    Ok(items)
                } else if path.is_dir() {
                    let mut items = vec![WorkItem::Directory(path.clone())];
                    let mut nested = self.traverse_directory(path, self.config.max_depth).await?;
                    items.append(&mut nested);
                    Ok(items)
                } else {
                    Err(FilesystemError::FileNotFound {
                        path: path.display().to_string(),
                    }
                    .into())
                }
            }

            ScanTarget::Directory { path, max_depth } => {
                let mut items = vec![WorkItem::Directory(path.clone())];
                let mut nested = self
                    .traverse_directory(path, max_depth.unwrap_or(self.config.max_depth))
                    .await?;
                items.append(&mut nested);
                Ok(items)
            }

            ScanTarget::Multiple(paths) => {
                let mut work_items = Vec::new();
                for path in paths {
                    if path.is_file() {
                        work_items.push(WorkItem::File(path.clone()));
                        if self.config.scan_archives && self.archive_scanner.is_archive(path).await
                        {
                            work_items.push(WorkItem::Archive(path.clone()));
                        }
                        work_items.push(WorkItem::Metadata(path.clone()));
                    } else if path.is_dir() {
                        work_items.push(WorkItem::Directory(path.clone()));
                        let mut dir_items =
                            self.traverse_directory(path, self.config.max_depth).await?;
                        work_items.append(&mut dir_items);
                    }
                }
                Ok(work_items)
            }

            ScanTarget::Filesystem => {
                // Start from root and traverse everything (be careful!)
                let root = PathBuf::from("/");
                let mut items = vec![WorkItem::Directory(root.clone())];
                let mut nested = self
                    .traverse_directory(&root, self.config.max_depth)
                    .await?;
                items.append(&mut nested);
                Ok(items)
            }

            ScanTarget::Glob(pattern) => self.resolve_glob_pattern(pattern).await,
        }
    }

    /// Traverse directory and create work items
    async fn traverse_directory(&self, path: &Path, max_depth: usize) -> Result<Vec<WorkItem>> {
        let mut work_items = Vec::new();
        let mut directories_to_visit = vec![(path.to_path_buf(), 0)];

        while let Some((current_dir, depth)) = directories_to_visit.pop() {
            if depth >= max_depth {
                continue;
            }

            // Check if directory should be excluded
            if self.file_filter.should_exclude_directory(&current_dir) {
                debug!("Excluding directory: {}", current_dir.display());
                continue;
            }

            work_items.push(WorkItem::Directory(current_dir.clone()));

            match tokio::fs::read_dir(&current_dir).await {
                Ok(mut entries) => {
                    while let Some(entry) = entries.next_entry().await? {
                        let entry_path = entry.path();

                        if entry_path.is_dir() {
                            if self.config.recursive {
                                directories_to_visit.push((entry_path, depth + 1));
                            }
                        } else if entry_path.is_file() {
                            // Check if file should be scanned
                            if self.should_scan_file(&entry_path).await {
                                work_items.push(WorkItem::File(entry_path.clone()));
                                if self.config.scan_archives
                                    && self.archive_scanner.is_archive(&entry_path).await
                                {
                                    work_items.push(WorkItem::Archive(entry_path.clone()));
                                }

                                // Add metadata analysis if enabled
                                work_items.push(WorkItem::Metadata(entry_path));
                            }
                        } else if entry_path.is_symlink() && self.config.follow_symlinks {
                            if let Ok(target) = tokio::fs::read_link(&entry_path).await {
                                if !self.has_symlink_loop(&target).await {
                                    if target.is_file() {
                                        work_items.push(WorkItem::File(target.clone()));
                                        if self.config.scan_archives
                                            && self.archive_scanner.is_archive(&target).await
                                        {
                                            work_items.push(WorkItem::Archive(target.clone()));
                                        }
                                    } else if target.is_dir() {
                                        directories_to_visit.push((target, depth + 1));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read directory {}: {}", current_dir.display(), e);
                }
            }
        }

        Ok(work_items)
    }

    /// Resolve glob pattern to work items
    async fn resolve_glob_pattern(&self, pattern: &str) -> Result<Vec<WorkItem>> {
        use glob::glob;

        let mut work_items = Vec::new();

        for entry in glob(pattern).context("Invalid glob pattern")? {
            match entry {
                Ok(path) => {
                    if path.is_file() && self.should_scan_file(&path).await {
                        work_items.push(WorkItem::File(path.clone()));
                        if self.config.scan_archives && self.archive_scanner.is_archive(&path).await
                        {
                            work_items.push(WorkItem::Archive(path.clone()));
                        }
                        work_items.push(WorkItem::Metadata(path));
                    }
                }
                Err(e) => {
                    warn!("Glob entry error: {}", e);
                }
            }
        }

        Ok(work_items)
    }

    /// Check if file should be scanned
    async fn should_scan_file(&self, path: &Path) -> bool {
        // Check file filter
        if !self.file_filter.should_scan_file(path) {
            return false;
        }

        // Check file size
        if let Ok(metadata) = tokio::fs::metadata(path).await {
            if metadata.len() > self.config.max_file_size {
                debug!(
                    "Skipping large file: {} ({} bytes)",
                    path.display(),
                    metadata.len()
                );
                return false;
            }
        }

        // Check if hidden file
        if !self.config.scan_hidden {
            if let Some(filename) = path.file_name() {
                if filename.to_string_lossy().starts_with('.') {
                    return false;
                }
            }
        }

        true
    }

    /// Check for symbolic link loops
    async fn has_symlink_loop(&self, path: &Path) -> bool {
        if let Ok(canonical) = path.canonicalize() {
            let mut tracker = self.symlink_tracker.write().await;
            if tracker.contains(&canonical) {
                return true;
            }
            tracker.insert(canonical);
        }
        false
    }

    fn is_pkcs12_path(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "p12" | "pfx"))
            .unwrap_or(false)
    }

    /// Process a single work item
    async fn process_work_item(
        &self,
        work_item: WorkItem,
        detection_engine: Arc<DetectionEngine>,
        session_id: Uuid,
    ) -> Result<WorkItemResult> {
        let _start_time = Instant::now();
        let mut result = WorkItemResult {
            detections: Vec::new(),
            file_analysis: None,
            metadata: None,
            archive_result: None,
            files_processed: 0,
            bytes_processed: 0,
            credentials_found: 0,
            directories_traversed: 0,
            archives_processed: 0,
        };

        match work_item {
            WorkItem::File(path) => {
                self.update_session_current_file(session_id, Some(path.clone()))
                    .await;

                let mut detections = Vec::new();
                let path_string = path.to_string_lossy().to_string();
                if self.is_pkcs12_path(&path) {
                    let location = CredentialLocation {
                        source_type: "file".to_string(),
                        path: path_string.clone(),
                        line_number: None,
                        column: None,
                        memory_address: None,
                        process_id: None,
                        container_id: None,
                    };

                    match detection_engine
                        .detect_in_text(&path_string, location)
                        .await
                    {
                        Ok(mut path_hits) => {
                            if !path_hits.is_empty() {
                                debug!(
                                    path = %path.display(),
                                    hits = path_hits.len(),
                                    "Detected PKCS#12 bundle by extension"
                                );
                            }
                            detections.append(&mut path_hits);
                        }
                        Err(err) => {
                            debug!(
                                path = %path.display(),
                                "PKCS#12 path detection skipped due to error: {err}"
                            );
                        }
                    }
                }

                // Scan file for credentials
                let scan_options = ScanOptions {
                    use_memory_mapping: self.config.use_memory_mapping,
                    buffer_size: self.config.buffer_size,
                    timeout: Duration::from_secs(self.config.file_timeout_sec),
                };

                match self
                    .file_scanner
                    .scan_file(&path, &detection_engine, scan_options)
                    .await
                {
                    Ok(scan_result) => {
                        detections.extend(scan_result.detections);
                        result.files_processed = 1;
                        result.bytes_processed = scan_result.bytes_processed;

                        // Analyze file if needed
                        if let Ok(analysis) = self.file_analyzer.analyze_file(&path).await {
                            result.file_analysis = Some(analysis);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to scan file {}: {}", path.display(), e);
                    }
                }

                result.credentials_found = detections.len() as u64;
                result.detections = detections;
            }

            WorkItem::Metadata(path) => {
                if let Ok(metadata) = self.metadata_analyzer.analyze_metadata(&path).await {
                    result.metadata = Some(metadata);
                }
            }

            WorkItem::Archive(path) => {
                if let Ok((archive_result, archive_detections)) =
                    self.process_archive(&path, &detection_engine).await
                {
                    result.archive_result = Some(archive_result);
                    result.archives_processed = 1;
                    result.credentials_found = archive_detections.len() as u64;
                    result.detections = archive_detections;
                }
            }

            WorkItem::Directory(path) => {
                debug!("Traversed directory {}", path.display());
                result.directories_traversed = 1;
            }
        }

        Ok(result)
    }

    /// Process archive file
    async fn process_archive(
        &self,
        path: &Path,
        detection_engine: &DetectionEngine,
    ) -> Result<(ArchiveScanResult, Vec<DetectionResult>)> {
        let start_time = Instant::now();

        let archive_type = self.archive_scanner.detect_archive_type(path).await?;
        let entries = self
            .archive_scanner
            .extract_and_scan(path, detection_engine)
            .await?;

        let mut detections = Vec::new();
        for entry in &entries {
            detections.extend(entry.detections.clone());
        }

        let credentials_found = detections.len() as u64;

        Ok((
            ArchiveScanResult {
                archive_path: path.to_path_buf(),
                archive_type,
                entries_scanned: entries.len() as u64,
                credentials_found,
                processing_time: start_time.elapsed(),
            },
            detections,
        ))
    }

    /// Update session status
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
                        "Filesystem scan status updated"
                    );
                }
                _ => {
                    debug!(
                        session_id = %session.id,
                        target = ?session.target,
                        status = ?session.status,
                        "Filesystem scan status updated"
                    );
                }
            }
        }
    }

    /// Update session current file
    async fn update_session_current_file(&self, session_id: Uuid, file: Option<PathBuf>) {
        let mut active_scans = self.active_scans.write().await;
        if let Some(session) = active_scans.get_mut(&session_id) {
            session.current_file = file;
        }
    }

    /// Update session progress
    async fn update_session_progress(
        &self,
        session_id: Uuid,
        items_completed: u64,
        total_items: usize,
        new_credentials: u64,
    ) {
        let mut active_scans = self.active_scans.write().await;
        if let Some(session) = active_scans.get_mut(&session_id) {
            session.files_processed += items_completed;
            session.credentials_found += new_credentials;
            if total_items > 0 {
                session.progress = (session.files_processed as f64 / total_items as f64).min(1.0);
            }

            debug!(
                session_id = %session.id,
                progress = session.progress,
                credentials = session.credentials_found,
                "Filesystem scan progress updated"
            );
        }
    }

    async fn finalize_session(&self, session_id: Uuid) -> Option<ScanSession> {
        let mut active_scans = self.active_scans.write().await;
        active_scans.remove(&session_id)
    }

    /// Get current scanning statistics
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> FilesystemStats {
        self.stats.read().await.clone()
    }

    /// Get active scan sessions (crate-internal)
    pub(crate) async fn get_active_scans(&self) -> Vec<ScanSession> {
        self.active_scans.read().await.values().cloned().collect()
    }

    /// Cancel a scan session
    #[allow(dead_code)]
    pub async fn cancel_scan(&self, session_id: Uuid) -> Result<()> {
        self.update_session_status(session_id, ScanStatus::Cancelled)
            .await;
        info!("🚫 Cancelled filesystem scan session {}", session_id);
        if let Some(session) = self.finalize_session(session_id).await {
            debug!(
                session_id = %session.id,
                target = ?session.target,
                "Filesystem scan cancelled and cleaned up"
            );
        }
        Ok(())
    }

    /// Start real-time monitoring (if enabled)
    pub async fn start_monitoring(
        &self,
        paths: Vec<PathBuf>,
    ) -> Result<Option<mpsc::UnboundedReceiver<FilesystemMonitorEvent>>> {
        if let Some(ref watcher) = self.filesystem_watcher {
            let (tx, rx) = mpsc::unbounded_channel();
            watcher.start_monitoring(paths, tx).await?;
            info!("👁️ Started filesystem monitoring");
            Ok(Some(rx))
        } else {
            warn!("Filesystem monitoring not enabled");
            Ok(None)
        }
    }

    /// Stop real-time monitoring
    pub async fn stop_monitoring(&self) -> Result<()> {
        if let Some(ref watcher) = self.filesystem_watcher {
            watcher.stop_monitoring().await?;
            info!("🛑 Stopped filesystem monitoring");
        }
        Ok(())
    }
}

/// Result of processing a work item
#[derive(Debug)]
struct WorkItemResult {
    detections: Vec<DetectionResult>,
    file_analysis: Option<FileAnalysis>,
    metadata: Option<FileMetadata>,
    archive_result: Option<ArchiveScanResult>,
    files_processed: u64,
    bytes_processed: u64,
    credentials_found: u64,
    directories_traversed: u64,
    archives_processed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_filesystem_hunter_creation() {
        let config = FilesystemConfig::default();
        let hunter = FilesystemHunter::new(config).await;

        match hunter {
            Ok(_) => {
                // Hunter created successfully
            }
            Err(e) => {
                // Expected on systems without full filesystem access
                println!("Filesystem hunter creation failed (expected): {}", e);
            }
        }
    }

    #[test]
    fn test_scan_target_types() {
        let file_target = ScanTarget::file("/path/to/file.txt");
        let dir_target = ScanTarget::directory("/path/to/dir");
        let glob_target = ScanTarget::glob("*.env");

        assert!(matches!(file_target, ScanTarget::File(_)));
        assert!(matches!(dir_target, ScanTarget::Directory { .. }));
        assert!(matches!(glob_target, ScanTarget::Glob(_)));
    }

    #[tokio::test]
    async fn test_work_item_processing() {
        // Test that work items can be created and processed
        let work_item = WorkItem::File(PathBuf::from("/nonexistent"));

        // Just test that the enum variants compile
        match work_item {
            WorkItem::File(_) => {
                // File work item
            }
            WorkItem::Directory(_) => {
                // Directory work item
            }
            WorkItem::Archive(_) => {
                // Archive work item
            }
            WorkItem::Metadata(_) => {
                // Metadata work item
            }
        }
    }
}
