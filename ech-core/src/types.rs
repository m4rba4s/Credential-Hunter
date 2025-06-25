/**
 * Enterprise Credential Hunter - Core Types
 * 
 * Unified type definitions used across all ECH modules.
 * Provides consistency and interoperability between different components.
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::error::EchResult;

/// Process identification and context
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(pub u32);

impl From<u32> for ProcessId {
    fn from(id: u32) -> Self {
        ProcessId(id)
    }
}

impl From<ProcessId> for u32 {
    fn from(pid: ProcessId) -> Self {
        pid.0
    }
}

/// Memory address representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryAddress(pub u64);

impl From<u64> for MemoryAddress {
    fn from(addr: u64) -> Self {
        MemoryAddress(addr)
    }
}

impl From<MemoryAddress> for u64 {
    fn from(addr: MemoryAddress) -> Self {
        addr.0
    }
}

impl std::fmt::Display for MemoryAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

/// File system path with metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePath {
    pub path: PathBuf,
    pub exists: bool,
    pub is_file: bool,
    pub is_directory: bool,
    pub size: Option<u64>,
    pub modified: Option<DateTime<Utc>>,
}

impl From<PathBuf> for FilePath {
    fn from(path: PathBuf) -> Self {
        let metadata = std::fs::metadata(&path).ok();
        Self {
            exists: path.exists(),
            is_file: path.is_file(),
            is_directory: path.is_dir(),
            size: metadata.as_ref().map(|m| m.len()),
            modified: metadata.and_then(|m| m.modified().ok())
                .map(|t| DateTime::from(t)),
            path,
        }
    }
}

/// Detection session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unified scan target specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTarget {
    /// Scan entire filesystem from root
    Filesystem {
        root_paths: Vec<PathBuf>,
        max_depth: Option<usize>,
        follow_symlinks: bool,
    },
    
    /// Scan specific files
    Files {
        paths: Vec<PathBuf>,
    },
    
    /// Scan process memory
    ProcessMemory {
        process_ids: Vec<ProcessId>,
        include_heap: bool,
        include_stack: bool,
        include_modules: bool,
    },
    
    /// Scan all running processes
    AllProcesses {
        exclude_system: bool,
        min_memory_mb: Option<u64>,
    },
    
    /// Scan network endpoints (IMDS, etc.)
    Network {
        endpoints: Vec<String>,
        timeout_ms: u64,
    },
    
    /// Scan browser credentials
    Browser {
        browsers: Vec<BrowserType>,
        include_profiles: bool,
    },
    
    /// Custom scan target
    Custom {
        target_type: String,
        parameters: HashMap<String, String>,
    },
}

/// Supported browser types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Opera,
    Brave,
    Vivaldi,
}

impl std::fmt::Display for BrowserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserType::Chrome => write!(f, "Chrome"),
            BrowserType::Firefox => write!(f, "Firefox"),
            BrowserType::Edge => write!(f, "Edge"),
            BrowserType::Safari => write!(f, "Safari"),
            BrowserType::Opera => write!(f, "Opera"),
            BrowserType::Brave => write!(f, "Brave"),
            BrowserType::Vivaldi => write!(f, "Vivaldi"),
        }
    }
}

/// Scan progress tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub session_id: SessionId,
    pub total_targets: usize,
    pub completed_targets: usize,
    pub current_target: Option<String>,
    pub start_time: DateTime<Utc>,
    pub estimated_completion: Option<DateTime<Utc>>,
    pub errors_encountered: usize,
    pub credentials_found: usize,
}

impl ScanProgress {
    pub fn new(session_id: SessionId, total_targets: usize) -> Self {
        Self {
            session_id,
            total_targets,
            completed_targets: 0,
            current_target: None,
            start_time: Utc::now(),
            estimated_completion: None,
            errors_encountered: 0,
            credentials_found: 0,
        }
    }
    
    pub fn progress_percentage(&self) -> f64 {
        if self.total_targets == 0 {
            100.0
        } else {
            (self.completed_targets as f64 / self.total_targets as f64) * 100.0
        }
    }
    
    pub fn is_complete(&self) -> bool {
        self.completed_targets >= self.total_targets
    }
}

/// Performance metrics for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub operation: String,
    pub duration_ms: u64,
    pub memory_used_bytes: Option<u64>,
    pub cpu_time_ms: Option<u64>,
    pub items_processed: Option<usize>,
    pub throughput_items_per_second: Option<f64>,
}

impl PerformanceMetrics {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            duration_ms: 0,
            memory_used_bytes: None,
            cpu_time_ms: None,
            items_processed: None,
            throughput_items_per_second: None,
        }
    }
    
    pub fn calculate_throughput(&mut self) {
        if let Some(items) = self.items_processed {
            if self.duration_ms > 0 {
                self.throughput_items_per_second = Some(
                    (items as f64 * 1000.0) / self.duration_ms as f64
                );
            }
        }
    }
}

/// Configuration validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub suggestions: Vec<String>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            suggestions: Vec::new(),
        }
    }
    
    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: Vec::new(),
            suggestions: Vec::new(),
        }
    }
    
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
        self.is_valid = false;
    }
    
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
    
    pub fn add_suggestion(&mut self, suggestion: impl Into<String>) {
        self.suggestions.push(suggestion.into());
    }
}

/// Async operation handle for long-running tasks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationHandle {
    pub id: Uuid,
    pub operation_type: String,
    pub started_at: DateTime<Utc>,
    pub status: OperationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl OperationHandle {
    pub fn new(operation_type: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            operation_type: operation_type.into(),
            started_at: Utc::now(),
            status: OperationStatus::Pending,
        }
    }
}

/// Generic result container for any operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult<T> {
    pub handle: OperationHandle,
    pub result: Option<T>,
    pub error: Option<String>,
    pub metadata: HashMap<String, String>,
    pub performance: Option<PerformanceMetrics>,
}

impl<T> OperationResult<T> {
    pub fn success(handle: OperationHandle, result: T) -> Self {
        Self {
            handle,
            result: Some(result),
            error: None,
            metadata: HashMap::new(),
            performance: None,
        }
    }
    
    pub fn failure(handle: OperationHandle, error: impl Into<String>) -> Self {
        Self {
            handle,
            result: None,
            error: Some(error.into()),
            metadata: HashMap::new(),
            performance: None,
        }
    }
    
    pub fn is_success(&self) -> bool {
        self.result.is_some() && self.error.is_none()
    }
    
    pub fn is_failure(&self) -> bool {
        self.error.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_id() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_scan_progress() {
        let session_id = SessionId::new();
        let mut progress = ScanProgress::new(session_id, 10);
        assert_eq!(progress.progress_percentage(), 0.0);
        assert!(!progress.is_complete());
        
        progress.completed_targets = 5;
        assert_eq!(progress.progress_percentage(), 50.0);
        
        progress.completed_targets = 10;
        assert_eq!(progress.progress_percentage(), 100.0);
        assert!(progress.is_complete());
    }
    
    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::valid();
        assert!(result.is_valid);
        
        result.add_error("Test error");
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);
    }
    
    #[test]
    fn test_operation_result() {
        let handle = OperationHandle::new("test_operation");
        let result = OperationResult::success(handle.clone(), "test_data");
        assert!(result.is_success());
        assert!(!result.is_failure());
        
        let result = OperationResult::<String>::failure(handle, "test_error");
        assert!(!result.is_success());
        assert!(result.is_failure());
    }
}