/**
 * ECH Configuration Management
 * 
 * Enterprise-grade configuration system with hierarchical loading, environment variable
 * support, and secure secrets management. Designed for complex enterprise deployments
 * with multiple environments and security requirements.
 * 
 * Configuration Precedence (highest to lowest):
 * 1. Command line arguments
 * 2. Environment variables (ECH_*)
 * 3. Configuration file
 * 4. Secure defaults
 */

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use clap::ValueEnum;
use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;

/// Primary ECH configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchConfig {
    /// Core engine configuration
    pub engine: EngineConfig,
    
    /// Detection engine settings
    pub detection: DetectionConfig,
    
    /// Memory scanning configuration
    pub memory: MemoryConfig,
    
    /// Filesystem scanning configuration
    pub filesystem: FilesystemConfig,
    
    /// Container scanning configuration
    pub container: ContainerConfig,
    
    /// Stealth operation settings
    pub stealth: StealthConfig,
    
    /// Remediation configuration
    pub remediation: RemediationConfig,
    
    /// SIEM integration settings
    pub siem: SiemConfig,
    
    /// Output configuration
    pub output: OutputConfig,
    
    /// Security settings
    pub security: SecurityConfig,
    
    /// Performance tuning
    pub performance: PerformanceConfig,
    
    /// Audit and compliance
    pub audit: AuditConfig,
    
    /// Operation mode settings
    pub operation: OperationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Worker thread pool size (0 = auto-detect)
    pub worker_threads: usize,
    
    /// Maximum memory usage in MB
    pub memory_limit_mb: usize,
    
    /// Operation timeout in seconds
    pub timeout_seconds: u64,
    
    /// Plugin directories
    pub plugin_directories: Vec<PathBuf>,
    
    /// Enable experimental features
    pub experimental_features: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Enable entropy analysis for unknown secrets
    pub entropy_analysis: bool,
    
    /// Minimum entropy threshold for detection
    pub entropy_threshold: f64,
    
    /// Enable ML-based classification
    pub ml_classification: bool,
    
    /// Custom pattern files
    pub custom_patterns: Vec<PathBuf>,
    
    /// YARA rules files
    pub yara_rules: Vec<PathBuf>,
    
    /// Enable context-aware detection
    pub context_analysis: bool,
    
    /// Minimum credential length
    pub min_credential_length: usize,
    
    /// Maximum credential length
    pub max_credential_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Enable process memory scanning
    pub process_scanning: bool,
    
    /// Enable heap analysis
    pub heap_analysis: bool,
    
    /// Enable stack scanning
    pub stack_scanning: bool,
    
    /// Maximum memory region size to scan (MB)
    pub max_region_size_mb: usize,
    
    /// Scan executable memory regions
    pub scan_executable_regions: bool,
    
    /// Use process injection for stealth
    pub use_injection: bool,
    
    /// Memory scan batch size
    pub scan_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    /// Maximum file size to scan (MB)
    pub max_file_size_mb: usize,
    
    /// File extensions to scan
    pub scan_extensions: Vec<String>,
    
    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,
    
    /// Directories to exclude
    pub exclude_directories: Vec<PathBuf>,
    
    /// Follow symbolic links
    pub follow_symlinks: bool,
    
    /// Scan hidden files and directories
    pub scan_hidden: bool,
    
    /// Enable real-time monitoring
    pub real_time_monitoring: bool,
    
    /// Archive formats to extract and scan
    pub scan_archives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Enable Docker container scanning
    pub docker_enabled: bool,
    
    /// Enable Podman container scanning
    pub podman_enabled: bool,
    
    /// Enable Kubernetes pod scanning
    pub kubernetes_enabled: bool,
    
    /// Scan container images
    pub scan_images: bool,
    
    /// Scan container volumes
    pub scan_volumes: bool,
    
    /// Scan environment variables
    pub scan_environment: bool,
    
    /// Docker socket path
    pub docker_socket: PathBuf,
    
    /// Kubernetes config path
    pub kube_config: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    /// Stealth operation mode
    pub mode: StealthMode,
    
    /// Enable EDR evasion techniques
    pub edr_evasion: bool,
    
    /// Enable process hollowing
    pub process_hollowing: bool,
    
    /// Enable API obfuscation
    pub api_obfuscation: bool,
    
    /// Timing randomization (ms)
    pub timing_jitter: u64,
    
    /// Memory footprint minimization
    pub minimize_footprint: bool,
    
    /// Auto-cleanup temporary files
    pub auto_cleanup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationConfig {
    /// Default remediation action
    pub default_action: RemediationAction,
    
    /// Enable automatic remediation
    pub auto_remediate: bool,
    
    /// Backup before remediation
    pub create_backups: bool,
    
    /// Backup directory
    pub backup_directory: PathBuf,
    
    /// Enable credential rotation
    pub enable_rotation: bool,
    
    /// Quarantine directory
    pub quarantine_directory: PathBuf,
    
    /// Secure wipe passes
    pub wipe_passes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    /// SIEM endpoint URL
    pub endpoint: Option<String>,
    
    /// Authentication token
    #[serde(skip_serializing)]
    pub auth_token: Option<Secret<String>>,
    
    /// Output format for SIEM
    pub format: SiemFormat,
    
    /// Enable real-time streaming
    pub real_time_streaming: bool,
    
    /// Batch size for bulk uploads
    pub batch_size: usize,
    
    /// Connection timeout (seconds)
    pub timeout_seconds: u64,
    
    /// Enable TLS verification
    pub verify_tls: bool,
    
    /// Custom headers
    pub custom_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    
    /// Output file path
    pub file_path: Option<PathBuf>,
    
    /// Enable console output
    pub console_output: bool,
    
    /// Enable colored output
    pub colored_output: bool,
    
    /// Compress output files
    pub compress_output: bool,
    
    /// Include full credential values (dangerous!)
    pub include_full_values: bool,
    
    /// Mask character for credentials
    pub mask_character: char,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable privileged mode
    pub privileged_mode: bool,
    
    /// Enable memory encryption
    pub memory_encryption: bool,
    
    /// Enable secure buffer clearing
    pub secure_buffer_clearing: bool,
    
    /// Maximum credential cache time (seconds)
    pub credential_cache_ttl: u64,
    
    /// Enable audit logging
    pub audit_logging: bool,
    
    /// Audit log file
    pub audit_log_file: PathBuf,
    
    /// Enable tamper detection
    pub tamper_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable SIMD optimizations
    pub simd_optimizations: bool,
    
    /// Enable memory mapping for large files
    pub memory_mapping: bool,
    
    /// I/O buffer size (KB)
    pub io_buffer_size: usize,
    
    /// Parallel scan workers
    pub parallel_workers: usize,
    
    /// Enable caching
    pub enable_caching: bool,
    
    /// Cache size (MB)
    pub cache_size_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Correlation ID for distributed tracing
    pub correlation_id: Option<String>,
    
    /// User context for operations
    pub user_context: Option<String>,
    
    /// Session ID
    pub session_id: Option<String>,
    
    /// Operation source
    pub operation_source: String,
    
    /// Enable chain of custody logging
    pub chain_of_custody: bool,
    
    /// Digital signature for audit logs
    pub sign_audit_logs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationConfig {
    /// Dry run mode (no modifications)
    pub dry_run: bool,
    
    /// Enable self-destruct after operation
    pub self_destruct: bool,
    
    /// Verbose output level
    pub verbose_level: u8,
    
    /// Quiet mode
    pub quiet_mode: bool,
    
    /// Enable network operations
    pub network_enabled: bool,
    
    /// Enable file system operations
    pub filesystem_enabled: bool,
    
    /// Enable memory operations
    pub memory_enabled: bool,
}

/// Log levels for enterprise logging
#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Output formats for scan results
#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Yaml,
    Csv,
    Html,
    Markdown,
    Text,
}

/// SIEM integration formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiemFormat {
    Json,
    Cef,
    Leef,
    Syslog,
    Splunk,
    Elastic,
}

/// Stealth operation modes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StealthMode {
    None,
    Low,
    High,
    Maximum,
}

/// Remediation actions for found credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationAction {
    Report,
    Mask,
    Quarantine,
    Wipe,
    Rotate,
}

impl Default for EchConfig {
    fn default() -> Self {
        Self {
            engine: EngineConfig::default(),
            detection: DetectionConfig::default(),
            memory: MemoryConfig::default(),
            filesystem: FilesystemConfig::default(),
            container: ContainerConfig::default(),
            stealth: StealthConfig::default(),
            remediation: RemediationConfig::default(),
            siem: SiemConfig::default(),
            output: OutputConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
            audit: AuditConfig::default(),
            operation: OperationConfig::default(),
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            worker_threads: 0, // Auto-detect
            memory_limit_mb: 512,
            timeout_seconds: 3600,
            plugin_directories: vec![
                PathBuf::from("/usr/lib/ech/plugins"),
                PathBuf::from("/opt/ech/plugins"),
                PathBuf::from("./plugins"),
            ],
            experimental_features: false,
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            entropy_analysis: true,
            entropy_threshold: 4.5,
            ml_classification: true,
            custom_patterns: vec![],
            yara_rules: vec![],
            context_analysis: true,
            min_credential_length: 8,
            max_credential_length: 1024,
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            process_scanning: true,
            heap_analysis: true,
            stack_scanning: false, // Potentially noisy
            max_region_size_mb: 100,
            scan_executable_regions: false,
            use_injection: false,
            scan_batch_size: 1024 * 1024, // 1MB
        }
    }
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: 100,
            scan_extensions: vec![
                "txt".to_string(), "conf".to_string(), "config".to_string(),
                "yaml".to_string(), "yml".to_string(), "json".to_string(),
                "xml".to_string(), "env".to_string(), "properties".to_string(),
                "ini".to_string(), "cfg".to_string(), "toml".to_string(),
            ],
            exclude_extensions: vec![
                "exe".to_string(), "dll".to_string(), "so".to_string(),
                "bin".to_string(), "jpg".to_string(), "png".to_string(),
                "mp4".to_string(), "avi".to_string(), "pdf".to_string(),
            ],
            exclude_directories: vec![
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/dev"),
                PathBuf::from(".git"),
                PathBuf::from("node_modules"),
                PathBuf::from("target"),
            ],
            follow_symlinks: false,
            scan_hidden: false,
            real_time_monitoring: false,
            scan_archives: vec!["zip".to_string(), "tar".to_string(), "gz".to_string()],
        }
    }
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            docker_enabled: true,
            podman_enabled: true,
            kubernetes_enabled: false,
            scan_images: true,
            scan_volumes: true,
            scan_environment: true,
            docker_socket: PathBuf::from("/var/run/docker.sock"),
            kube_config: None,
        }
    }
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            mode: StealthMode::None,
            edr_evasion: false,
            process_hollowing: false,
            api_obfuscation: false,
            timing_jitter: 100,
            minimize_footprint: true,
            auto_cleanup: true,
        }
    }
}

impl Default for RemediationConfig {
    fn default() -> Self {
        Self {
            default_action: RemediationAction::Report,
            auto_remediate: false,
            create_backups: true,
            backup_directory: PathBuf::from("/var/backups/ech"),
            enable_rotation: false,
            quarantine_directory: PathBuf::from("/var/quarantine/ech"),
            wipe_passes: 3,
        }
    }
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            auth_token: None,
            format: SiemFormat::Json,
            real_time_streaming: false,
            batch_size: 100,
            timeout_seconds: 30,
            verify_tls: true,
            custom_headers: HashMap::new(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            file_path: None,
            console_output: true,
            colored_output: true,
            compress_output: false,
            include_full_values: false,
            mask_character: '*',
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            privileged_mode: false,
            memory_encryption: false,
            secure_buffer_clearing: true,
            credential_cache_ttl: 300, // 5 minutes
            audit_logging: true,
            audit_log_file: PathBuf::from("/var/log/ech/audit.log"),
            tamper_detection: true,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            simd_optimizations: true,
            memory_mapping: true,
            io_buffer_size: 64, // 64KB
            parallel_workers: 0, // Auto-detect
            enable_caching: true,
            cache_size_mb: 100,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            correlation_id: None,
            user_context: None,
            session_id: None,
            operation_source: "ech-cli".to_string(),
            chain_of_custody: true,
            sign_audit_logs: false,
        }
    }
}

impl Default for OperationConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            self_destruct: false,
            verbose_level: 0,
            quiet_mode: false,
            network_enabled: true,
            filesystem_enabled: true,
            memory_enabled: true,
        }
    }
}

impl EchConfig {
    /// Load configuration from file with environment variable overrides
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        let mut config = if path.exists() {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;
            
            if path.extension().map_or(false, |ext| ext == "yaml" || ext == "yml") {
                serde_yaml::from_str(&contents)
                    .with_context(|| format!("Failed to parse YAML config: {}", path.display()))?
            } else {
                serde_json::from_str(&contents)
                    .with_context(|| format!("Failed to parse JSON config: {}", path.display()))?
            }
        } else {
            Self::default()
        };
        
        // Override with environment variables
        config.apply_environment_overrides()
            .context("Failed to apply environment variable overrides")?;
        
        // Validate configuration
        config.validate()
            .context("Configuration validation failed")?;
        
        Ok(config)
    }
    
    /// Apply environment variable overrides
    fn apply_environment_overrides(&mut self) -> Result<()> {
        // Engine configuration
        if let Ok(workers) = std::env::var("ECH_WORKER_THREADS") {
            self.engine.worker_threads = workers.parse()
                .context("Invalid ECH_WORKER_THREADS value")?;
        }
        
        if let Ok(memory) = std::env::var("ECH_MEMORY_LIMIT_MB") {
            self.engine.memory_limit_mb = memory.parse()
                .context("Invalid ECH_MEMORY_LIMIT_MB value")?;
        }
        
        // SIEM configuration
        if let Ok(endpoint) = std::env::var("ECH_SIEM_ENDPOINT") {
            self.siem.endpoint = Some(endpoint);
        }
        
        if let Ok(token) = std::env::var("ECH_SIEM_TOKEN") {
            self.siem.auth_token = Some(Secret::new(token));
        }
        
        // Security configuration
        if let Ok(privileged) = std::env::var("ECH_PRIVILEGED_MODE") {
            self.security.privileged_mode = privileged.parse()
                .context("Invalid ECH_PRIVILEGED_MODE value")?;
        }
        
        // Audit configuration
        if let Ok(correlation_id) = std::env::var("ECH_CORRELATION_ID") {
            self.audit.correlation_id = Some(correlation_id);
        }
        
        if let Ok(user_context) = std::env::var("ECH_USER_CONTEXT") {
            self.audit.user_context = Some(user_context);
        }
        
        Ok(())
    }
    
    /// Validate configuration for security and consistency
    fn validate(&self) -> Result<()> {
        // Memory limit validation
        if self.engine.memory_limit_mb < 64 {
            return Err(anyhow::anyhow!("Memory limit too low: minimum 64MB required"));
        }
        
        // Thread count validation
        if self.engine.worker_threads > 0 && self.engine.worker_threads > num_cpus::get() * 4 {
            return Err(anyhow::anyhow!("Worker thread count too high"));
        }
        
        // Security validation
        if self.output.include_full_values && !self.operation.dry_run {
            return Err(anyhow::anyhow!(
                "Including full credential values is only allowed in dry-run mode"
            ));
        }
        
        // SIEM validation
        if self.siem.endpoint.is_some() && self.siem.auth_token.is_none() {
            return Err(anyhow::anyhow!("SIEM endpoint requires authentication token"));
        }
        
        Ok(())
    }
    
    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        
        let contents = if path.extension().map_or(false, |ext| ext == "yaml" || ext == "yml") {
            serde_yaml::to_string(self)
                .context("Failed to serialize config to YAML")?
        } else {
            serde_json::to_string_pretty(self)
                .context("Failed to serialize config to JSON")?
        };
        
        std::fs::write(path, contents)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        
        Ok(())
    }
}

// Implement zeroization for sensitive data
impl Drop for SiemConfig {
    fn drop(&mut self) {
        if let Some(ref mut token) = self.auth_token {
            // The Secret type automatically zeroizes on drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_default_config() {
        let config = EchConfig::default();
        assert_eq!(config.engine.worker_threads, 0);
        assert_eq!(config.detection.entropy_threshold, 4.5);
        assert!(!config.security.privileged_mode);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = EchConfig::default();
        config.engine.memory_limit_mb = 32; // Too low
        
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = EchConfig::default();
        
        // Test JSON serialization
        let json = serde_json::to_string(&config).unwrap();
        let _deserialized: EchConfig = serde_json::from_str(&json).unwrap();
        
        // Test YAML serialization
        let yaml = serde_yaml::to_string(&config).unwrap();
        let _deserialized: EchConfig = serde_yaml::from_str(&yaml).unwrap();
    }
    
    #[test]
    fn test_config_file_loading() {
        let config = EchConfig::default();
        
        // Create temporary file
        let temp_file = NamedTempFile::new().unwrap();
        config.save_to_file(temp_file.path()).unwrap();
        
        // Load from file
        let loaded_config = EchConfig::load_from_file(temp_file.path()).unwrap();
        assert_eq!(config.engine.worker_threads, loaded_config.engine.worker_threads);
    }
}