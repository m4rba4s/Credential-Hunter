/**
 * ECH Filesystem Hunter Module - Enterprise File System Credential Scanning
 * 
 * This module provides comprehensive filesystem scanning capabilities for detecting
 * credentials in files, directories, and file systems. Features atomic operations,
 * performance optimizations, and enterprise-grade security controls.
 * 
 * Features:
 * - Recursive directory traversal with filtering
 * - Atomic file operations for safe scanning
 * - Content-aware file type detection
 * - Parallel processing with work-stealing queues
 * - Memory-mapped file scanning for performance
 * - Extended attribute and metadata analysis
 * - Archive and compressed file support
 * - Real-time filesystem monitoring
 * - Symbolic link handling and loop detection
 */

pub mod hunter;
pub mod scanner;
pub mod filters;
pub mod analyzers;
pub mod watchers;
pub mod archives;
pub mod metadata;

pub use hunter::{FilesystemHunter, HunterConfig, ScanResult};
pub use scanner::{FileScanner, FileContent, ScanOptions};
pub use filters::{FileFilter, FilterCriteria, FilterRule};
pub use analyzers::{FileAnalyzer, FileAnalysis, ContentAnalysis};
pub use watchers::{FilesystemWatcher, WatchEvent, WatchConfig};
pub use archives::{ArchiveScanner, ArchiveType, ArchiveEntry};
pub use metadata::{MetadataAnalyzer, FileMetadata, ExtendedAttributes};

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, error};

/// Initialize filesystem scanning subsystem
pub async fn initialize_filesystem_subsystem() -> Result<()> {
    info!("📁 Initializing Filesystem Scanning Subsystem");
    
    // Check filesystem capabilities
    let capabilities = check_filesystem_capabilities().await?;
    
    if !capabilities.extended_attributes {
        warn!("Extended attributes not supported on this filesystem");
    }
    
    if !capabilities.memory_mapping {
        warn!("Memory mapping not available - using standard I/O");
    }
    
    info!("✅ Filesystem scanning subsystem initialized");
    info!("   Extended attributes: {}", capabilities.extended_attributes);
    info!("   Memory mapping: {}", capabilities.memory_mapping);
    info!("   Symbolic links: {}", capabilities.symbolic_links);
    info!("   Archive support: {}", capabilities.archive_support);
    
    Ok(())
}

/// Filesystem capabilities detection
#[derive(Debug, Clone)]
pub struct FilesystemCapabilities {
    /// Extended attributes support
    pub extended_attributes: bool,
    
    /// Memory mapping support
    pub memory_mapping: bool,
    
    /// Symbolic link support
    pub symbolic_links: bool,
    
    /// Archive scanning support
    pub archive_support: bool,
    
    /// Real-time monitoring support
    pub realtime_monitoring: bool,
    
    /// Large file support (>4GB)
    pub large_file_support: bool,
    
    /// Atomic operations support
    pub atomic_operations: bool,
}

/// Filesystem scanning configuration
#[derive(Debug, Clone)]
pub struct FilesystemConfig {
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    
    /// Maximum directory depth
    pub max_depth: usize,
    
    /// Enable recursive scanning
    pub recursive: bool,
    
    /// Follow symbolic links
    pub follow_symlinks: bool,
    
    /// Scan hidden files
    pub scan_hidden: bool,
    
    /// Scan system files
    pub scan_system: bool,
    
    /// Enable archive scanning
    pub scan_archives: bool,
    
    /// Enable binary file scanning
    pub scan_binary: bool,
    
    /// Use memory mapping for large files
    pub use_memory_mapping: bool,
    
    /// Number of worker threads
    pub worker_threads: usize,
    
    /// Buffer size for file I/O
    pub buffer_size: usize,
    
    /// Enable atomic operations
    pub atomic_operations: bool,
    
    /// Scan timeout per file (seconds)
    pub file_timeout_sec: u64,
    
    /// Enable real-time monitoring
    pub realtime_monitoring: bool,
    
    /// Excluded file patterns
    pub exclude_patterns: Vec<String>,
    
    /// Included file patterns
    pub include_patterns: Vec<String>,
    
    /// Excluded directories
    pub exclude_directories: Vec<String>,
    
    /// Maximum memory usage (MB)
    pub max_memory_mb: u64,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,  // 100MB
            max_depth: 50,
            recursive: true,
            follow_symlinks: false,
            scan_hidden: true,
            scan_system: false,
            scan_archives: true,
            scan_binary: false,
            use_memory_mapping: true,
            worker_threads: num_cpus::get(),
            buffer_size: 64 * 1024,            // 64KB
            atomic_operations: true,
            file_timeout_sec: 30,
            realtime_monitoring: false,
            exclude_patterns: vec![
                "*.log".to_string(),
                "*.tmp".to_string(),
                "*.cache".to_string(),
                "node_modules/*".to_string(),
                ".git/*".to_string(),
                "target/*".to_string(),
                "build/*".to_string(),
                "dist/*".to_string(),
            ],
            include_patterns: vec![
                "*.env".to_string(),
                "*.config".to_string(),
                "*.properties".to_string(),
                "*.yaml".to_string(),
                "*.yml".to_string(),
                "*.json".to_string(),
                "*.toml".to_string(),
                "*.ini".to_string(),
                "*.conf".to_string(),
                "*.xml".to_string(),
                "*.py".to_string(),
                "*.js".to_string(),
                "*.ts".to_string(),
                "*.java".to_string(),
                "*.go".to_string(),
                "*.rs".to_string(),
                "*.sh".to_string(),
                "*.ps1".to_string(),
            ],
            exclude_directories: vec![
                "/proc".to_string(),
                "/sys".to_string(),
                "/dev".to_string(),
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/var/log".to_string(),
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "build".to_string(),
                "dist".to_string(),
            ],
            max_memory_mb: 512,
        }
    }
}

/// Filesystem scanning statistics
#[derive(Debug, Default, Clone)]
pub struct FilesystemStats {
    /// Total files scanned
    pub files_scanned: u64,
    
    /// Total directories traversed
    pub directories_traversed: u64,
    
    /// Total bytes processed
    pub bytes_processed: u64,
    
    /// Credentials found
    pub credentials_found: u64,
    
    /// High-risk credentials found
    pub high_risk_credentials: u64,
    
    /// Files skipped due to size
    pub files_skipped_size: u64,
    
    /// Files skipped due to permissions
    pub files_skipped_permissions: u64,
    
    /// Files skipped due to filters
    pub files_skipped_filters: u64,
    
    /// Scan errors encountered
    pub scan_errors: u64,
    
    /// Average scan time per file (ms)
    pub avg_scan_time_ms: u64,
    
    /// Archives processed
    pub archives_processed: u64,
    
    /// Symlinks followed
    pub symlinks_followed: u64,
    
    /// Performance metrics
    pub performance_metrics: FilesystemPerformanceMetrics,
}

/// Performance metrics for filesystem scanning
#[derive(Debug, Default, Clone)]
pub struct FilesystemPerformanceMetrics {
    /// I/O operations per second
    pub io_ops_per_sec: u64,
    
    /// Memory mapping usage
    pub memory_mapping_usage: u64,
    
    /// Buffer cache hits
    pub cache_hits: u64,
    
    /// Buffer cache misses
    pub cache_misses: u64,
    
    /// Atomic operations performed
    pub atomic_operations: u64,
    
    /// Worker thread utilization
    pub thread_utilization: f64,
    
    /// Disk I/O wait time (ms)
    pub disk_io_wait_ms: u64,
}

/// Filesystem scanning errors
#[derive(Debug, thiserror::Error)]
pub enum FilesystemError {
    #[error("Permission denied: {path}")]
    PermissionDenied { path: String },
    
    #[error("File not found: {path}")]
    FileNotFound { path: String },
    
    #[error("Path is not a file or directory: {path}")]
    InvalidPath { path: String },
    
    #[error("File too large: {path} ({size} bytes)")]
    FileTooLarge { path: String, size: u64 },
    
    #[error("Scan timeout: {path}")]
    ScanTimeout { path: String },
    
    #[error("Memory limit exceeded")]
    MemoryLimitExceeded,
    
    #[error("Symbolic link loop detected: {path}")]
    SymlinkLoop { path: String },
    
    #[error("Archive extraction failed: {path}")]
    ArchiveExtractionFailed { path: String },
    
    #[error("Filesystem not supported")]
    FilesystemNotSupported,
    
    #[error("I/O error: {message}")]
    IoError { message: String },
}

/// Check filesystem capabilities
async fn check_filesystem_capabilities() -> Result<FilesystemCapabilities> {
    let extended_attributes = check_extended_attributes_support().await;
    let memory_mapping = check_memory_mapping_support().await;
    let symbolic_links = check_symbolic_links_support().await;
    let archive_support = check_archive_support().await;
    let realtime_monitoring = check_realtime_monitoring_support().await;
    let large_file_support = check_large_file_support().await;
    let atomic_operations = check_atomic_operations_support().await;
    
    Ok(FilesystemCapabilities {
        extended_attributes,
        memory_mapping,
        symbolic_links,
        archive_support,
        realtime_monitoring,
        large_file_support,
        atomic_operations,
    })
}

async fn check_extended_attributes_support() -> bool {
    #[cfg(unix)]
    {
        // Try to get extended attributes on a test file
        std::process::Command::new("getfattr")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
    
    #[cfg(windows)]
    {
        // Windows has alternate data streams
        true
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

async fn check_memory_mapping_support() -> bool {
    // Memory mapping is generally available on all modern systems
    true
}

async fn check_symbolic_links_support() -> bool {
    #[cfg(unix)]
    {
        true
    }
    
    #[cfg(windows)]
    {
        // Windows supports symbolic links but requires privileges
        std::env::var("USERPROFILE").is_ok()
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

async fn check_archive_support() -> bool {
    // Check if we can load archive libraries
    true // We'll implement with built-in Rust libraries
}

async fn check_realtime_monitoring_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check for inotify support
        std::path::Path::new("/proc/sys/fs/inotify").exists()
    }
    
    #[cfg(target_os = "windows")]
    {
        // Windows has ReadDirectoryChanges
        true
    }
    
    #[cfg(target_os = "macos")]
    {
        // macOS has FSEvents
        true
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        false
    }
}

async fn check_large_file_support() -> bool {
    // Most modern filesystems support large files
    true
}

async fn check_atomic_operations_support() -> bool {
    // Atomic operations are generally available
    true
}

/// File system scanning target
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// Single file
    File(PathBuf),
    
    /// Directory with optional depth limit
    Directory { path: PathBuf, max_depth: Option<usize> },
    
    /// Multiple paths
    Multiple(Vec<PathBuf>),
    
    /// Entire filesystem root
    Filesystem,
    
    /// Files matching glob pattern
    Glob(String),
}

impl ScanTarget {
    /// Create a file target
    pub fn file<P: Into<PathBuf>>(path: P) -> Self {
        Self::File(path.into())
    }
    
    /// Create a directory target
    pub fn directory<P: Into<PathBuf>>(path: P) -> Self {
        Self::Directory {
            path: path.into(),
            max_depth: None,
        }
    }
    
    /// Create a directory target with depth limit
    pub fn directory_with_depth<P: Into<PathBuf>>(path: P, max_depth: usize) -> Self {
        Self::Directory {
            path: path.into(),
            max_depth: Some(max_depth),
        }
    }
    
    /// Create multiple targets
    pub fn multiple<P: Into<PathBuf>, I: IntoIterator<Item = P>>(paths: I) -> Self {
        Self::Multiple(paths.into_iter().map(|p| p.into()).collect())
    }
    
    /// Create glob pattern target
    pub fn glob<S: Into<String>>(pattern: S) -> Self {
        Self::Glob(pattern.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_filesystem_subsystem_init() {
        let result = initialize_filesystem_subsystem().await;
        // Should not fail on initialization
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_filesystem_config_default() {
        let config = FilesystemConfig::default();
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert!(config.recursive);
        assert!(config.scan_archives);
        assert!(!config.follow_symlinks);
    }
    
    #[test]
    fn test_scan_target_creation() {
        let file_target = ScanTarget::file("/path/to/file.txt");
        let dir_target = ScanTarget::directory("/path/to/dir");
        let glob_target = ScanTarget::glob("*.env");
        
        assert!(matches!(file_target, ScanTarget::File(_)));
        assert!(matches!(dir_target, ScanTarget::Directory { .. }));
        assert!(matches!(glob_target, ScanTarget::Glob(_)));
    }
    
    #[test]
    fn test_filesystem_stats_default() {
        let stats = FilesystemStats::default();
        assert_eq!(stats.files_scanned, 0);
        assert_eq!(stats.credentials_found, 0);
        assert_eq!(stats.bytes_processed, 0);
    }
    
    #[tokio::test]
    async fn test_capabilities_check() {
        let capabilities = check_filesystem_capabilities().await;
        assert!(capabilities.is_ok());
        
        let caps = capabilities.unwrap();
        // Memory mapping should be available on most systems
        assert!(caps.memory_mapping);
    }
}