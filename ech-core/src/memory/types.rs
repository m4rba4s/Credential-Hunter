/**
 * ECH Memory Types - Enterprise-Grade Memory Management
 * 
 * Clean, consistent type definitions for all memory operations.
 * Designed for performance, safety, and maintainability.
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};
// use crate::error::{EchError, EchResult};
// use crate::types::{ProcessId, MemoryAddress, SessionId};

// Local type definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryAddress(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// Memory region permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryPermissions {
    pub const NONE: Self = Self { read: false, write: false, execute: false };
    pub const READ_ONLY: Self = Self { read: true, write: false, execute: false };
    pub const READ_WRITE: Self = Self { read: true, write: true, execute: false };
    pub const READ_EXECUTE: Self = Self { read: true, write: false, execute: true };
    pub const ALL: Self = Self { read: true, write: true, execute: true };
    
    pub fn can_scan(&self) -> bool {
        self.read
    }
    
    pub fn is_executable(&self) -> bool {
        self.execute
    }
}

impl std::fmt::Display for MemoryPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}{}",
            if self.read { "R" } else { "-" },
            if self.write { "W" } else { "-" },
            if self.execute { "X" } else { "-" }
        )
    }
}

/// Memory region type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryRegionType {
    /// Process heap memory
    Heap,
    /// Process stack memory
    Stack,
    /// Loaded module/library
    Module,
    /// Private process memory
    Private,
    /// Memory-mapped file
    Mapped,
    /// Unknown/other memory
    Unknown,
}

impl std::fmt::Display for MemoryRegionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryRegionType::Heap => write!(f, "Heap"),
            MemoryRegionType::Stack => write!(f, "Stack"),
            MemoryRegionType::Module => write!(f, "Module"),
            MemoryRegionType::Private => write!(f, "Private"),
            MemoryRegionType::Mapped => write!(f, "Mapped"),
            MemoryRegionType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Memory region information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Base address of the region
    pub base_address: MemoryAddress,
    /// Size of the region in bytes
    pub size: u64,
    /// Region permissions
    pub permissions: MemoryPermissions,
    /// Region type
    pub region_type: MemoryRegionType,
    /// Module name (if applicable)
    pub module_name: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl MemoryRegion {
    pub fn end_address(&self) -> MemoryAddress {
        MemoryAddress(self.base_address.0 + self.size)
    }
    
    pub fn contains_address(&self, address: MemoryAddress) -> bool {
        address.0 >= self.base_address.0 && address.0 < self.base_address.0 + self.size
    }
    
    pub fn is_scannable(&self) -> bool {
        self.permissions.can_scan() && self.size > 0
    }
}

/// Complete memory map for a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryMap {
    pub process_id: ProcessId,
    pub regions: Vec<MemoryRegion>,
    pub total_memory: u64,
    pub scannable_memory: u64,
    pub generated_at: DateTime<Utc>,
}

impl ProcessMemoryMap {
    pub fn new(process_id: ProcessId, regions: Vec<MemoryRegion>) -> Self {
        let total_memory = regions.iter().map(|r| r.size).sum();
        let scannable_memory = regions.iter()
            .filter(|r| r.is_scannable())
            .map(|r| r.size)
            .sum();
            
        Self {
            process_id,
            regions,
            total_memory,
            scannable_memory,
            generated_at: Utc::now(),
        }
    }
    
    pub fn find_region_by_address(&self, address: MemoryAddress) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains_address(address))
    }
    
    pub fn get_scannable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.is_scannable()).collect()
    }
}

/// Process information for memory operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: ProcessId,
    pub name: String,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_pid: Option<ProcessId>,
    pub user_id: Option<u32>,
    pub memory_usage_bytes: Option<u64>,
    pub cpu_time_ms: Option<u64>,
    pub start_time: Option<DateTime<Utc>>,
    pub is_system_process: bool,
    pub architecture: ProcessArchitecture,
}

/// Process architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessArchitecture {
    X86,
    X64,
    ARM,
    ARM64,
    Unknown,
}

impl std::fmt::Display for ProcessArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessArchitecture::X86 => write!(f, "x86"),
            ProcessArchitecture::X64 => write!(f, "x64"),
            ProcessArchitecture::ARM => write!(f, "ARM"),
            ProcessArchitecture::ARM64 => write!(f, "ARM64"),
            ProcessArchitecture::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Security context for process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub can_read_memory: bool,
    pub can_write_memory: bool,
    pub requires_elevation: bool,
    pub access_token: Option<String>,
    pub integrity_level: IntegrityLevel,
}

/// Process integrity level (Windows)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,
    Protected = 5,
}

impl std::fmt::Display for IntegrityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityLevel::Untrusted => write!(f, "Untrusted"),
            IntegrityLevel::Low => write!(f, "Low"),
            IntegrityLevel::Medium => write!(f, "Medium"),
            IntegrityLevel::High => write!(f, "High"),
            IntegrityLevel::System => write!(f, "System"),
            IntegrityLevel::Protected => write!(f, "Protected"),
        }
    }
}

/// Scanning configuration for memory operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanConfig {
    /// Include heap memory in scans
    pub include_heap: bool,
    /// Include stack memory in scans
    pub include_stack: bool,
    /// Include loaded modules in scans
    pub include_modules: bool,
    /// Include private memory in scans
    pub include_private: bool,
    /// Include memory-mapped files in scans
    pub include_mapped: bool,
    /// Maximum memory chunk size for reading
    pub max_chunk_size: usize,
    /// Timeout for memory operations
    pub operation_timeout: Duration,
    /// Skip regions smaller than this
    pub min_region_size: u64,
    /// Skip regions larger than this
    pub max_region_size: Option<u64>,
}

impl Default for MemoryScanConfig {
    fn default() -> Self {
        Self {
            include_heap: true,
            include_stack: true,
            include_modules: false,  // Usually not needed for credential scanning
            include_private: true,
            include_mapped: false,   // Can be noisy
            max_chunk_size: 1024 * 1024, // 1MB chunks
            operation_timeout: Duration::from_secs(30),
            min_region_size: 4096,   // 4KB minimum
            max_region_size: Some(512 * 1024 * 1024), // 512MB maximum
        }
    }
}

/// Memory scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanResult {
    pub session_id: SessionId,
    pub process_id: ProcessId,
    pub regions_scanned: usize,
    pub total_bytes_scanned: u64,
    pub scan_duration: Duration,
    pub credentials_found: usize,
    pub errors_encountered: Vec<String>,
    pub performance_metrics: MemoryScanMetrics,
}

/// Performance metrics for memory operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanMetrics {
    pub bytes_per_second: f64,
    pub regions_per_second: f64,
    pub average_region_size: u64,
    pub memory_overhead_bytes: u64,
    pub cache_hit_rate: Option<f64>,
}

/// Process criteria for filtering
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessFilter {
    /// Process name patterns to match
    pub name_patterns: Vec<String>,
    /// Minimum memory usage (MB)
    pub min_memory_mb: Option<u64>,
    /// Maximum memory usage (MB)
    pub max_memory_mb: Option<u64>,
    /// Maximum process age (hours)
    pub max_age_hours: Option<u64>,
    /// User filter
    pub user_filter: Option<String>,
    /// Exclude system processes
    pub exclude_system: bool,
    /// Required architecture
    pub required_architecture: Option<ProcessArchitecture>,
    /// Minimum integrity level required
    pub min_integrity_level: Option<IntegrityLevel>,
}

impl ProcessFilter {
    pub fn matches_process(&self, process: &ProcessInfo) -> bool {
        // Name pattern matching
        if !self.name_patterns.is_empty() {
            let matches_pattern = self.name_patterns.iter().any(|pattern| {
                process.name.to_lowercase().contains(&pattern.to_lowercase())
            });
            if !matches_pattern {
                return false;
            }
        }
        
        // Memory constraints
        if let Some(memory_bytes) = process.memory_usage_bytes {
            let memory_mb = memory_bytes / (1024 * 1024);
            
            if let Some(min) = self.min_memory_mb {
                if memory_mb < min {
                    return false;
                }
            }
            
            if let Some(max) = self.max_memory_mb {
                if memory_mb > max {
                    return false;
                }
            }
        }
        
        // Age constraints
        if let Some(max_hours) = self.max_age_hours {
            if let Some(start_time) = process.start_time {
                let age = Utc::now().signed_duration_since(start_time);
                if age.num_hours() > max_hours as i64 {
                    return false;
                }
            }
        }
        
        // User filter
        if let Some(ref user_filter) = self.user_filter {
            // Implementation depends on platform
            // This is a placeholder
            let _ = user_filter;
        }
        
        // System process filter
        if self.exclude_system && process.is_system_process {
            return false;
        }
        
        // Architecture filter
        if let Some(required_arch) = self.required_architecture {
            if process.architecture != required_arch {
                return false;
            }
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_permissions() {
        let perms = MemoryPermissions::READ_WRITE;
        assert!(perms.can_scan());
        assert!(!perms.is_executable());
        assert_eq!(perms.to_string(), "RW-");
    }
    
    #[test]
    fn test_memory_region() {
        let region = MemoryRegion {
            base_address: MemoryAddress(0x1000),
            size: 0x1000,
            permissions: MemoryPermissions::READ_ONLY,
            region_type: MemoryRegionType::Heap,
            module_name: None,
            metadata: HashMap::new(),
        };
        
        assert!(region.contains_address(MemoryAddress(0x1500)));
        assert!(!region.contains_address(MemoryAddress(0x2000)));
        assert!(region.is_scannable());
    }
    
    #[test]
    fn test_process_filter() {
        let filter = ProcessFilter {
            name_patterns: vec!["notepad".to_string()],
            exclude_system: true,
            ..Default::default()
        };
        
        let process = ProcessInfo {
            pid: ProcessId(1234),
            name: "notepad.exe".to_string(),
            exe_path: None,
            command_line: None,
            parent_pid: None,
            user_id: Some(1000),
            memory_usage_bytes: Some(1024 * 1024),
            cpu_time_ms: None,
            start_time: Some(Utc::now()),
            is_system_process: false,
            architecture: ProcessArchitecture::X64,
        };
        
        assert!(filter.matches_process(&process));
    }
}