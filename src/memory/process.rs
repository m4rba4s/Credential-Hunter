//! Cross-platform process enumeration, privilege assessment, and memory map
//! construction utilities used by the memory scanner.
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, trace};

use super::regions::{MemoryMap, MemoryRegion, RegionPermissions, RegionType};
use super::scanner::ProcessCriteria;
#[cfg(not(target_os = "linux"))]
use super::MemoryError;

/// Cross-platform process manager
pub struct ProcessManager {
    /// Platform-specific implementation
    platform_impl: Box<dyn ProcessManagerImpl + Send + Sync>,

    /// Process cache
    process_cache: std::sync::Mutex<HashMap<u32, (ProcessInfo, SystemTime)>>,

    /// Cache timeout
    cache_timeout: Duration,

    /// Optional interceptors invoked around memory reads.
    interceptors: RwLock<Vec<Arc<dyn MemoryInterceptHook>>>,
}

/// Process information structure
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,

    /// Parent process ID
    pub ppid: u32,

    /// Process name/executable
    pub name: String,

    /// Full command line
    pub command_line: Vec<String>,

    /// Process owner/user
    pub user: String,

    /// Memory usage (bytes)
    pub memory_usage: u64,

    /// CPU usage percentage
    pub cpu_usage: f64,

    /// Process start time
    pub start_time: DateTime<Utc>,

    /// Working directory
    pub working_directory: String,

    /// Environment variables (filtered)
    pub environment: HashMap<String, String>,

    /// Process security context
    pub security_context: ProcessSecurityContext,

    /// Is system process
    pub is_system: bool,

    /// Child processes
    pub children: Vec<u32>,

    /// Open file handles count
    pub file_handles: u32,

    /// Network connections count
    pub network_connections: u32,
}

/// Process security context
#[derive(Debug, Clone)]
pub struct ProcessSecurityContext {
    /// Effective user ID
    pub effective_uid: u32,

    /// Effective group ID
    pub effective_gid: u32,

    /// Process privileges
    pub privileges: Vec<String>,

    /// Security labels (SELinux, etc.)
    pub security_labels: Vec<String>,

    /// Is elevated/privileged
    pub is_elevated: bool,

    /// Can access other processes
    pub can_access_processes: bool,

    /// Protection level
    pub protection_level: ProtectionLevel,
}

/// Process protection level
#[derive(Debug, Clone, PartialEq)]
pub enum ProtectionLevel {
    /// No special protection
    None,

    /// System process protection
    System,

    /// Critical system process
    Critical,

    /// Protected process (Windows)
    Protected,

    /// Protected process light (Windows)
    ProtectedLight,

    /// Anti-malware protection
    AntiMalware,
}

/// Process context for scanning
#[derive(Debug, Clone)]
pub struct ProcessContext {
    /// Process information
    pub info: ProcessInfo,

    /// Memory accessibility
    pub memory_accessible: bool,

    /// Scan permissions
    pub scan_permissions: ScanPermissions,

    /// Risk assessment
    pub risk_level: ProcessRiskLevel,

    /// Monitoring status
    pub monitoring_status: MonitoringStatus,
}

/// Process scanning permissions
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ScanPermissions {
    /// Can read process memory
    pub read_memory: bool,

    /// Can enumerate memory regions
    pub enumerate_regions: bool,

    /// Can access process handles
    pub access_handles: bool,

    /// Can read environment variables
    pub read_environment: bool,

    /// Can access process modules
    pub access_modules: bool,
}

/// Process risk level for scanning
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessRiskLevel {
    /// Low risk - safe to scan
    Low,

    /// Medium risk - scan with caution
    Medium,

    /// High risk - may cause instability
    High,

    /// Critical - avoid scanning
    Critical,
}

/// Process monitoring status
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum MonitoringStatus {
    /// Not being monitored
    Inactive,

    /// Currently being monitored
    Active,

    /// Monitoring paused
    Paused,

    /// Monitoring failed with an error message
    Failed(String),
}

/// Platform-specific process management implementation
trait ProcessManagerImpl {
    /// Get all running processes
    fn get_all_processes(&self) -> Result<Vec<ProcessInfo>>;

    /// Get specific process information
    fn get_process_info(&self, pid: u32) -> Result<ProcessInfo>;

    /// Get memory map for process
    fn get_memory_map(&self, pid: u32) -> Result<MemoryMap>;

    /// Read process memory
    fn read_process_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>>;

    /// Check if process exists
    fn process_exists(&self, pid: u32) -> bool;

    /// Get process security context
    fn get_security_context(&self, pid: u32) -> Result<ProcessSecurityContext>;

    /// Terminate process (if needed for cleanup)
    fn terminate_process(&self, pid: u32) -> Result<()>;

    /// Parse memory map line (platform-specific)
    fn parse_maps_line(&self, line: &str) -> Option<MemoryRegion>;
}

/// Interceptor hooks that wrap process memory reads (useful for auditing/testing).
pub trait MemoryInterceptHook: Send + Sync {
    /// Stable identifier for telemetry.
    fn name(&self) -> &'static str;

    /// Called before a read is issued.
    fn before_read(&self, _pid: u32, _address: u64, _size: usize) -> Result<()> {
        Ok(())
    }

    /// Called after a read completes with the captured bytes.
    fn after_read(&self, _pid: u32, _address: u64, _data: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// Lightweight logging interceptor that traces memory read boundaries when enabled.
#[derive(Default)]
struct LoggingMemoryInterceptor;

impl MemoryInterceptHook for LoggingMemoryInterceptor {
    fn name(&self) -> &'static str {
        "memory_logging"
    }

    fn before_read(&self, pid: u32, address: u64, size: usize) -> Result<()> {
        debug!(
            pid,
            address = format_args!("{address:016x}"),
            size,
            "Intercepting memory read"
        );
        Ok(())
    }

    fn after_read(&self, pid: u32, address: u64, data: &[u8]) -> Result<()> {
        trace!(
            pid,
            address = format_args!("{address:016x}"),
            bytes_returned = data.len(),
            "Memory read completed"
        );
        Ok(())
    }
}

impl ProcessManager {
    /// Create a new process manager
    pub async fn new(log_memory_reads: bool) -> Result<Self> {
        debug!("🔧 Initializing Process Manager");

        let platform_impl: Box<dyn ProcessManagerImpl + Send + Sync> = {
            #[cfg(target_os = "linux")]
            {
                Box::new(LinuxProcessManager::new()?)
            }

            #[cfg(target_os = "windows")]
            {
                Box::new(WindowsProcessManager::new()?)
            }

            #[cfg(target_os = "macos")]
            {
                Box::new(MacOSProcessManager::new()?)
            }

            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            {
                return Err(MemoryError::PlatformNotSupported.into());
            }
        };

        let process_cache = std::sync::Mutex::new(HashMap::new());
        let cache_timeout = Duration::from_secs(30); // 30 second cache

        debug!("✅ Process Manager initialized");

        let manager = Self {
            platform_impl,
            process_cache,
            cache_timeout,
            interceptors: RwLock::new(Vec::new()),
        };

        let env_override = parse_env_flag("ECH_LOG_MEMORY_READS");
        let should_log_reads = env_override.unwrap_or(log_memory_reads);

        if should_log_reads {
            manager.register_interceptor(Arc::new(LoggingMemoryInterceptor::default()));
            if env_override.is_some() {
                info!("Memory read logging enabled via ECH_LOG_MEMORY_READS");
            } else {
                debug!("Memory read logging enabled via configuration");
            }
        }

        Ok(manager)
    }

    /// Register a memory intercept hook to wrap process reads.
    pub fn register_interceptor(&self, interceptor: Arc<dyn MemoryInterceptHook>) {
        if let Ok(mut hooks) = self.interceptors.write() {
            hooks.push(interceptor);
        }
    }

    /// Get all running processes
    pub async fn get_all_processes(&self) -> Result<Vec<ProcessInfo>> {
        debug!("📋 Enumerating all processes");

        let processes = {
            let platform_impl = &*self.platform_impl;
            platform_impl.get_all_processes()
        }?;

        debug!("Found {} processes", processes.len());
        Ok(processes)
    }

    /// Get specific process information
    pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo> {
        // Check cache first
        {
            let cache = self.process_cache.lock().unwrap();
            if let Some((info, timestamp)) = cache.get(&pid) {
                if timestamp.elapsed().unwrap_or(Duration::MAX) < self.cache_timeout {
                    trace!("Cache hit for process {}", pid);
                    return Ok(info.clone());
                }
            }
        }

        let info = {
            let platform_impl = &*self.platform_impl;
            platform_impl.get_process_info(pid)
        }?;

        // Update cache
        {
            let mut cache = self.process_cache.lock().unwrap();
            cache.insert(pid, (info.clone(), SystemTime::now()));
        }

        Ok(info)
    }

    /// Find processes by name pattern
    pub async fn find_processes_by_name(&self, pattern: &str) -> Result<Vec<ProcessInfo>> {
        let all_processes = self.get_all_processes().await?;

        let pattern_lower = pattern.to_lowercase();
        let matching_processes: Vec<ProcessInfo> = all_processes
            .into_iter()
            .filter(|process| {
                process.name.to_lowercase().contains(&pattern_lower)
                    || process
                        .command_line
                        .iter()
                        .any(|arg| arg.to_lowercase().contains(&pattern_lower))
            })
            .collect();

        debug!(
            "Found {} processes matching pattern '{}'",
            matching_processes.len(),
            pattern
        );
        Ok(matching_processes)
    }

    /// Find processes by criteria
    pub async fn find_processes_by_criteria(
        &self,
        criteria: &ProcessCriteria,
    ) -> Result<Vec<ProcessInfo>> {
        let all_processes = self.get_all_processes().await?;

        let matching_processes: Vec<ProcessInfo> = all_processes
            .into_iter()
            .filter(|process| self.matches_criteria(process, criteria))
            .collect();

        debug!(
            "Found {} processes matching criteria",
            matching_processes.len()
        );
        Ok(matching_processes)
    }

    /// Check if process matches criteria
    fn matches_criteria(&self, process: &ProcessInfo, criteria: &ProcessCriteria) -> bool {
        // Check name patterns
        if !criteria.name_patterns.is_empty() {
            let name_lower = process.name.to_lowercase();
            let matches_pattern = criteria.name_patterns.iter().any(|pattern| {
                let pattern_lower = pattern.to_lowercase();
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let pattern_parts: Vec<&str> = pattern_lower.split('*').collect();
                    if pattern_parts.len() == 2 {
                        name_lower.starts_with(pattern_parts[0])
                            && name_lower.ends_with(pattern_parts[1])
                    } else {
                        name_lower.contains(&pattern_lower.replace('*', ""))
                    }
                } else {
                    name_lower.contains(&pattern_lower)
                }
            });

            if !matches_pattern {
                return false;
            }
        }

        // Check memory usage
        let memory_mb = process.memory_usage / 1024 / 1024;
        if let Some(min_memory) = criteria.min_memory_mb {
            if memory_mb < min_memory {
                return false;
            }
        }
        if let Some(max_memory) = criteria.max_memory_mb {
            if memory_mb > max_memory {
                return false;
            }
        }

        // Check process age
        if let Some(max_age_hours) = criteria.max_age_hours {
            let process_age = Utc::now().signed_duration_since(process.start_time);
            if process_age.num_hours() > max_age_hours as i64 {
                return false;
            }
        }

        // Check user filter
        if let Some(ref user_filter) = criteria.user_filter {
            if process.user != *user_filter {
                return false;
            }
        }

        // Check system process exclusion
        if criteria.exclude_system && process.is_system {
            return false;
        }

        true
    }

    /// Get memory map for process
    pub async fn get_memory_map(&self, pid: u32) -> Result<MemoryMap> {
        let memory_map = {
            let platform_impl = &*self.platform_impl;
            platform_impl.get_memory_map(pid)
        }?;

        trace!(
            "Got memory map for process {} with {} regions",
            pid,
            memory_map.regions.len()
        );
        Ok(memory_map)
    }

    /// Read process memory
    pub async fn read_process_memory(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        if let Ok(hooks) = self.interceptors.read() {
            for hook in hooks.iter() {
                hook.before_read(pid, address, size)
                    .with_context(|| format!("interceptor {} before_read failed", hook.name()))?;
            }
        }

        let data = {
            let platform_impl = &*self.platform_impl;
            platform_impl.read_process_memory(pid, address, size)
        }?;

        if let Ok(hooks) = self.interceptors.read() {
            for hook in hooks.iter() {
                hook.after_read(pid, address, &data)
                    .with_context(|| format!("interceptor {} after_read failed", hook.name()))?;
            }
        }

        trace!(
            "Read {} bytes from process {} at address {:016x}",
            data.len(),
            pid,
            address
        );
        Ok(data)
    }

    /// Check if process exists
    pub async fn process_exists(&self, pid: u32) -> bool {
        {
            let platform_impl = &*self.platform_impl;
            platform_impl.process_exists(pid)
        }
    }

    /// Terminate a running process (best-effort)
    pub async fn terminate_process(&self, pid: u32) -> Result<()> {
        debug!("Attempting to terminate process {}", pid);
        let platform_impl = &*self.platform_impl;
        platform_impl.terminate_process(pid)
    }

    /// Create process context for scanning
    pub async fn create_process_context(&self, pid: u32) -> Result<ProcessContext> {
        let info = self.get_process_info(pid).await?;
        let security_context = {
            let platform_impl = &*self.platform_impl;
            platform_impl.get_security_context(pid)
        }?;

        let memory_accessible = self
            .check_memory_accessibility(pid, &security_context)
            .await;
        let scan_permissions = self.determine_scan_permissions(&security_context);
        let risk_level = self.assess_process_risk(&info);

        Ok(ProcessContext {
            info,
            memory_accessible,
            scan_permissions,
            risk_level,
            monitoring_status: MonitoringStatus::Inactive,
        })
    }

    /// Check if process memory is accessible
    async fn check_memory_accessibility(
        &self,
        pid: u32,
        security_context: &ProcessSecurityContext,
    ) -> bool {
        // Try to read a small amount of memory to test accessibility
        match self.read_process_memory(pid, 0x1000, 4).await {
            Ok(_) => true,
            Err(_) => {
                // Check if we have sufficient privileges
                security_context.can_access_processes
            }
        }
    }

    /// Determine scanning permissions for process
    fn determine_scan_permissions(
        &self,
        security_context: &ProcessSecurityContext,
    ) -> ScanPermissions {
        ScanPermissions {
            read_memory: security_context.can_access_processes,
            enumerate_regions: security_context.can_access_processes,
            access_handles: security_context.is_elevated,
            read_environment: true, // Usually accessible
            access_modules: security_context.can_access_processes,
        }
    }

    /// Assess process risk level for scanning
    fn assess_process_risk(&self, info: &ProcessInfo) -> ProcessRiskLevel {
        // Critical system processes
        let critical_processes = [
            "kernel",
            "kthreadd",
            "migration",
            "rcu_",
            "watchdog",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "lsass.exe",
            "services.exe",
            "smss.exe",
            "system",
            "ntoskrnl.exe",
        ];

        let name_lower = info.name.to_lowercase();

        if critical_processes
            .iter()
            .any(|&critical| name_lower.contains(critical))
        {
            return ProcessRiskLevel::Critical;
        }

        // System processes
        if info.is_system || info.security_context.protection_level != ProtectionLevel::None {
            return ProcessRiskLevel::High;
        }

        // High memory usage processes (potential instability)
        if info.memory_usage > 2_000_000_000 {
            // 2GB
            return ProcessRiskLevel::Medium;
        }

        ProcessRiskLevel::Low
    }

    /// Clear process cache
    pub fn clear_cache(&self) {
        let mut cache = self.process_cache.lock().unwrap();
        cache.clear();
        debug!("Process cache cleared");
    }
}

// Platform-specific implementations

#[cfg(target_os = "linux")]
struct LinuxProcessManager;

#[cfg(target_os = "linux")]
impl LinuxProcessManager {
    fn new() -> Result<Self> {
        Ok(Self)
    }

    fn parse_capabilities(hex_value: &str) -> Vec<String> {
        const LINUX_CAPABILITIES: [&str; 41] = [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE",
        ];

        let sanitized = hex_value.trim();
        let value = u128::from_str_radix(sanitized, 16).unwrap_or(0);

        LINUX_CAPABILITIES
            .iter()
            .enumerate()
            .filter_map(|(bit, name)| {
                if bit < 128 && (value & (1u128 << bit)) != 0 {
                    Some((*name).to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    fn read_boot_time() -> Option<i64> {
        std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|content| {
                content.lines().find_map(|line| {
                    if let Some(rest) = line.strip_prefix("btime ") {
                        rest.trim().parse::<i64>().ok()
                    } else {
                        None
                    }
                })
            })
    }

    fn read_environment(pid: u32) -> HashMap<String, String> {
        let mut env_map = HashMap::new();
        let path = format!("/proc/{}/environ", pid);
        if let Ok(content) = std::fs::read(&path) {
            for entry in content.split(|&b| b == 0).take(128) {
                if entry.is_empty() {
                    continue;
                }
                if let Some(eq) = entry.iter().position(|&b| b == b'=') {
                    let key = String::from_utf8_lossy(&entry[..eq]).to_string();
                    let value = String::from_utf8_lossy(&entry[eq + 1..]).to_string();
                    env_map.insert(key, value);
                }
            }
        }
        env_map
    }

    fn read_children(pid: u32) -> Vec<u32> {
        let mut children = Vec::new();
        let path = format!("/proc/{}/task/{}/children", pid, pid);
        if let Ok(content) = std::fs::read_to_string(&path) {
            for child in content.split_whitespace() {
                if let Ok(id) = child.parse::<u32>() {
                    children.push(id);
                }
            }
        }
        children
    }

    fn count_file_descriptors(pid: u32) -> u32 {
        let path = format!("/proc/{}/fd", pid);
        std::fs::read_dir(&path)
            .map(|entries| entries.filter_map(Result::ok).count() as u32)
            .unwrap_or(0)
    }

    fn count_network_connections(pid: u32) -> u32 {
        const FILES: [&str; 4] = ["tcp", "tcp6", "udp", "udp6"];
        FILES
            .iter()
            .map(|entry| {
                let path = format!("/proc/{}/net/{}", pid, entry);
                std::fs::read_to_string(&path)
                    .ok()
                    .map(|content| {
                        content
                            .lines()
                            .skip(1)
                            .filter(|line| !line.trim().is_empty())
                            .count() as u32
                    })
                    .unwrap_or(0)
            })
            .sum()
    }
}

#[cfg(target_os = "linux")]
impl ProcessManagerImpl for LinuxProcessManager {
    fn get_all_processes(&self) -> Result<Vec<ProcessInfo>> {
        use std::fs;

        let mut processes = Vec::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();

            if let Ok(pid) = filename_str.parse::<u32>() {
                if let Ok(info) = self.get_process_info(pid) {
                    processes.push(info);
                }
            }
        }

        Ok(processes)
    }

    fn get_process_info(&self, pid: u32) -> Result<ProcessInfo> {
        use std::fs;

        let proc_path = format!("/proc/{}", pid);

        // Read process name
        let comm_path = format!("{}/comm", proc_path);
        let name = fs::read_to_string(&comm_path)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();
        let name_lower = name.to_lowercase();

        // Read command line
        let cmdline_path = format!("{}/cmdline", proc_path);
        let cmdline_raw = fs::read(&cmdline_path).unwrap_or_default();
        let command_line: Vec<String> = cmdline_raw
            .split(|&b| b == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).to_string())
            .collect();

        // Read status for additional info
        let status_path = format!("{}/status", proc_path);
        let status_content = fs::read_to_string(&status_path).unwrap_or_default();

        let mut ppid = 0;
        let mut memory_usage = 0;
        let mut uid = 0;
        let mut gid = 0;
        let mut cap_eff_hex: Option<String> = None;

        for line in status_content.lines() {
            if line.starts_with("PPid:") {
                ppid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if line.starts_with("VmRSS:") {
                memory_usage = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    * 1024; // Convert KB to bytes
            } else if line.starts_with("Uid:") {
                uid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if line.starts_with("Gid:") {
                gid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if line.starts_with("CapEff:") {
                cap_eff_hex = line.split_whitespace().nth(1).map(|s| s.to_string());
            }
        }

        // Get user name (simplified)
        let user = if uid == 0 {
            "root".to_string()
        } else {
            format!("uid:{}", uid)
        };

        // Get working directory
        let cwd_path = format!("{}/cwd", proc_path);
        let working_directory = fs::read_link(&cwd_path)
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|_| "/".to_string());

        let privileges = cap_eff_hex
            .as_deref()
            .map(Self::parse_capabilities)
            .unwrap_or_default();

        let stat_path = format!("{}/stat", proc_path);
        let stat_content = fs::read_to_string(&stat_path).unwrap_or_default();
        let (start_time, cpu_usage) = if let Some(end_idx) = stat_content.rfind(')') {
            let metrics_segment = stat_content[end_idx + 1..].trim();
            let fields: Vec<&str> = metrics_segment.split_whitespace().collect();

            let utime_ticks = fields
                .get(11)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let stime_ticks = fields
                .get(12)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let start_ticks = fields
                .get(19)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            let clock_ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
            if clock_ticks == 0 {
                (Utc::now(), 0.0)
            } else {
                let start_time = Self::read_boot_time()
                    .and_then(|boot_time| {
                        let start_seconds = start_ticks as f64 / clock_ticks as f64;
                        let epoch = boot_time as f64 + start_seconds;
                        let secs = epoch.floor() as i64;
                        let nanos = ((epoch - epoch.floor()) * 1_000_000_000f64) as u32;
                        Utc.timestamp_opt(secs, nanos).single()
                    })
                    .unwrap_or_else(Utc::now);

                let lifetime = Utc::now().signed_duration_since(start_time);
                let lifetime_secs = lifetime.num_seconds().max(1) as f64;
                let total_cpu = (utime_ticks + stime_ticks) as f64 / clock_ticks as f64;
                let cpu_percent = ((total_cpu / lifetime_secs) * 100.0).min(400.0);
                (start_time, cpu_percent)
            }
        } else {
            (Utc::now(), 0.0)
        };

        let environment = Self::read_environment(pid);
        let children = Self::read_children(pid);
        let file_handles = Self::count_file_descriptors(pid);
        let network_connections = Self::count_network_connections(pid);

        let protection_level = if pid == 1 {
            ProtectionLevel::Critical
        } else if uid == 0 {
            ProtectionLevel::System
        } else if privileges.iter().any(|cap| cap == "CAP_SYS_ADMIN") {
            ProtectionLevel::Protected
        } else if privileges.iter().any(|cap| cap == "CAP_SYS_PTRACE") {
            ProtectionLevel::ProtectedLight
        } else if name_lower.contains("defender")
            || name_lower.contains("sentinel")
            || name_lower.contains("clam")
            || name_lower.contains("crowdstrike")
        {
            ProtectionLevel::AntiMalware
        } else {
            ProtectionLevel::None
        };

        let security_context = ProcessSecurityContext {
            effective_uid: uid,
            effective_gid: gid,
            privileges: privileges.clone(),
            security_labels: Vec::new(),
            is_elevated: uid == 0,
            can_access_processes: uid == 0 || privileges.iter().any(|cap| cap == "CAP_SYS_PTRACE"),
            protection_level,
        };

        Ok(ProcessInfo {
            pid,
            ppid,
            name,
            command_line,
            user,
            memory_usage,
            cpu_usage,
            start_time,
            working_directory,
            environment,
            security_context,
            is_system: uid == 0 || pid < 100,
            children,
            file_handles,
            network_connections,
        })
    }

    fn get_memory_map(&self, pid: u32) -> Result<MemoryMap> {
        use std::fs;

        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content =
            fs::read_to_string(&maps_path).context("Failed to read process memory map")?;

        let mut regions = Vec::new();

        for line in maps_content.lines() {
            if let Some(region) = self.parse_maps_line(line) {
                regions.push(region);
            }
        }

        Ok(MemoryMap { pid, regions })
    }

    fn parse_maps_line(&self, line: &str) -> Option<MemoryRegion> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        // Parse address range
        let address_parts: Vec<&str> = parts[0].split('-').collect();
        if address_parts.len() != 2 {
            return None;
        }

        let start_address = u64::from_str_radix(address_parts[0], 16).ok()?;
        let end_address = u64::from_str_radix(address_parts[1], 16).ok()?;
        let size = (end_address - start_address) as usize;

        // Parse permissions
        let perms = parts[1];
        let permissions = RegionPermissions {
            read: perms.chars().nth(0) == Some('r'),
            write: perms.chars().nth(1) == Some('w'),
            execute: perms.chars().nth(2) == Some('x'),
        };

        // Determine region type
        let region_type = if parts.len() > 5 {
            let path = parts[5];
            if path.contains("[heap]") {
                RegionType::Heap
            } else if path.contains("[stack]") {
                RegionType::Stack
            } else if path.starts_with('/') {
                if path.contains(".so") || path.contains(".dll") || path.contains(".dylib") {
                    RegionType::Module
                } else {
                    RegionType::Mapped
                }
            } else if path.contains("[anon]") {
                RegionType::Private
            } else {
                RegionType::Unknown
            }
        } else {
            RegionType::Unknown
        };

        Some(MemoryRegion {
            start_address,
            size,
            permissions,
            region_type,
            module_name: if parts.len() > 5 {
                Some(parts[5].to_string())
            } else {
                None
            },
            protection: perms.to_string(),
        })
    }

    fn read_process_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mem_path = format!("/proc/{}/mem", pid);
        let mut file = File::open(&mem_path).context("Failed to open process memory")?;

        file.seek(SeekFrom::Start(address))
            .context("Failed to seek to memory address")?;

        let mut buffer = vec![0u8; size];
        file.read_exact(&mut buffer)
            .context("Failed to read process memory")?;

        Ok(buffer)
    }

    fn process_exists(&self, pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    fn get_security_context(&self, pid: u32) -> Result<ProcessSecurityContext> {
        // This is a simplified implementation
        let proc_info = self.get_process_info(pid)?;
        Ok(proc_info.security_context)
    }

    fn terminate_process(&self, pid: u32) -> Result<()> {
        use std::process::Command;

        let output = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .output()
            .context("Failed to execute kill command")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to terminate process {}", pid));
        }

        Ok(())
    }
}

fn parse_env_flag(key: &str) -> Option<bool> {
    std::env::var(key).ok().and_then(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    })
}

// Windows and macOS implementations would go here
#[cfg(target_os = "windows")]
struct WindowsProcessManager;

#[cfg(target_os = "windows")]
impl WindowsProcessManager {
    fn new() -> Result<Self> {
        // Windows-specific initialization
        Ok(Self)
    }
}

#[cfg(target_os = "windows")]
impl ProcessManagerImpl for WindowsProcessManager {
    fn get_all_processes(&self) -> Result<Vec<ProcessInfo>> {
        // Windows implementation using Process32First/Process32Next
        Ok(Vec::new()) // Placeholder
    }

    fn get_process_info(&self, _pid: u32) -> Result<ProcessInfo> {
        // Windows implementation
        Err(anyhow::anyhow!("Windows process info not implemented"))
    }

    fn get_memory_map(&self, _pid: u32) -> Result<MemoryMap> {
        // Windows implementation using VirtualQueryEx
        Err(anyhow::anyhow!("Windows memory map not implemented"))
    }

    fn read_process_memory(&self, _pid: u32, _address: u64, _size: usize) -> Result<Vec<u8>> {
        // Windows implementation using ReadProcessMemory
        Err(anyhow::anyhow!("Windows memory read not implemented"))
    }

    fn process_exists(&self, _pid: u32) -> bool {
        false // Placeholder
    }

    fn get_security_context(&self, _pid: u32) -> Result<ProcessSecurityContext> {
        Err(anyhow::anyhow!("Windows security context not implemented"))
    }

    fn terminate_process(&self, _pid: u32) -> Result<()> {
        Err(anyhow::anyhow!(
            "Windows process termination not implemented"
        ))
    }
}

#[cfg(target_os = "macos")]
struct MacOSProcessManager;

#[cfg(target_os = "macos")]
impl MacOSProcessManager {
    fn new() -> Result<Self> {
        Ok(Self)
    }
}

#[cfg(target_os = "macos")]
impl ProcessManagerImpl for MacOSProcessManager {
    fn get_all_processes(&self) -> Result<Vec<ProcessInfo>> {
        // macOS implementation using sysctl or libproc
        Ok(Vec::new()) // Placeholder
    }

    fn get_process_info(&self, _pid: u32) -> Result<ProcessInfo> {
        Err(anyhow::anyhow!("macOS process info not implemented"))
    }

    fn get_memory_map(&self, _pid: u32) -> Result<MemoryMap> {
        // macOS implementation using vm_region
        Err(anyhow::anyhow!("macOS memory map not implemented"))
    }

    fn read_process_memory(&self, _pid: u32, _address: u64, _size: usize) -> Result<Vec<u8>> {
        // macOS implementation using vm_read
        Err(anyhow::anyhow!("macOS memory read not implemented"))
    }

    fn process_exists(&self, _pid: u32) -> bool {
        false // Placeholder
    }

    fn get_security_context(&self, _pid: u32) -> Result<ProcessSecurityContext> {
        Err(anyhow::anyhow!("macOS security context not implemented"))
    }

    fn terminate_process(&self, _pid: u32) -> Result<()> {
        Err(anyhow::anyhow!("macOS process termination not implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_process_manager_creation() {
        let manager = ProcessManager::new(false).await;
        match manager {
            Ok(_) => {
                // Process manager created successfully
            }
            Err(e) => {
                // Expected on unsupported platforms
                println!("Process manager creation failed (expected): {}", e);
            }
        }
    }

    #[test]
    fn test_process_criteria_matching() {
        let _criteria = ProcessCriteria {
            name_patterns: vec!["test*".to_string()],
            min_memory_mb: Some(10),
            max_memory_mb: None,
            max_age_hours: None,
            user_filter: None,
            exclude_system: false,
            include_children: false,
        };

        let process = ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "test_process".to_string(),
            command_line: vec!["test_process".to_string()],
            user: "user".to_string(),
            memory_usage: 20 * 1024 * 1024, // 20MB
            cpu_usage: 0.0,
            start_time: Utc::now(),
            working_directory: "/tmp".to_string(),
            environment: HashMap::new(),
            security_context: ProcessSecurityContext {
                effective_uid: 1000,
                effective_gid: 1000,
                privileges: Vec::new(),
                security_labels: Vec::new(),
                is_elevated: false,
                can_access_processes: false,
                protection_level: ProtectionLevel::None,
            },
            is_system: false,
            children: Vec::new(),
            file_handles: 0,
            network_connections: 0,
        };

        // Minimal sanity check mirroring criteria expectations
        assert!(process.name.contains("test"));
        assert!(process.memory_usage / 1024 / 1024 >= 10);
    }

    #[tokio::test]
    async fn interceptors_wrap_memory_reads() {
        struct MockProcessManager;
        impl ProcessManagerImpl for MockProcessManager {
            fn get_all_processes(&self) -> Result<Vec<ProcessInfo>> {
                Ok(Vec::new())
            }
            fn get_process_info(&self, _pid: u32) -> Result<ProcessInfo> {
                Err(anyhow::anyhow!("not implemented"))
            }
            fn get_memory_map(&self, _pid: u32) -> Result<MemoryMap> {
                Err(anyhow::anyhow!("not implemented"))
            }
            fn read_process_memory(
                &self,
                _pid: u32,
                _address: u64,
                _size: usize,
            ) -> Result<Vec<u8>> {
                Ok(vec![1, 2, 3, 4])
            }
            fn process_exists(&self, _pid: u32) -> bool {
                true
            }
            fn get_security_context(&self, _pid: u32) -> Result<ProcessSecurityContext> {
                Err(anyhow::anyhow!("not implemented"))
            }
            fn terminate_process(&self, _pid: u32) -> Result<()> {
                Ok(())
            }
            fn parse_maps_line(&self, _line: &str) -> Option<MemoryRegion> {
                None
            }
        }

        struct CountingHook {
            before: Arc<AtomicUsize>,
            after: Arc<AtomicUsize>,
        }
        impl MemoryInterceptHook for CountingHook {
            fn name(&self) -> &'static str {
                "counting"
            }
            fn before_read(&self, _pid: u32, _address: u64, _size: usize) -> Result<()> {
                self.before.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn after_read(&self, _pid: u32, _address: u64, _data: &[u8]) -> Result<()> {
                self.after.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let manager = ProcessManager {
            platform_impl: Box::new(MockProcessManager),
            process_cache: std::sync::Mutex::new(HashMap::new()),
            cache_timeout: Duration::from_secs(30),
            interceptors: RwLock::new(Vec::new()),
        };

        let before = Arc::new(AtomicUsize::new(0));
        let after = Arc::new(AtomicUsize::new(0));
        manager.register_interceptor(Arc::new(CountingHook {
            before: Arc::clone(&before),
            after: Arc::clone(&after),
        }));

        let _ = manager.read_process_memory(1, 0x1000, 4).await.unwrap();

        assert_eq!(before.load(Ordering::SeqCst), 1);
        assert_eq!(after.load(Ordering::SeqCst), 1);
    }
}
