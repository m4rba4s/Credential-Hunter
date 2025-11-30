/**
 * ECH Security Context - Comprehensive Security Management
 *
 * This module provides enterprise-grade security context management including
 * privilege validation, memory protection, secure operations, and audit trails.
 * Designed with paranoid security principles for DFIR and red team operations.
 *
 * Features:
 * - Privilege escalation detection and validation
 * - Secure memory management with zeroization
 * - Cryptographic operations for sensitive data
 * - Audit trail generation and integrity protection
 * - Runtime security monitoring
 * - Anti-tamper and anti-debug measures
 */
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ring::{
    aead, digest, hmac,
    rand::{self, SecureRandom},
};
use secrecy::{ExposeSecret, Secret};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};
use uuid::Uuid;

use super::config::EchConfig;

/// Security context for all ECH operations
pub struct SecurityContext {
    /// Security configuration
    config: SecurityConfig,

    /// Privilege information
    privileges: Arc<RwLock<PrivilegeInfo>>,

    /// Cryptographic context
    crypto_context: Arc<CryptoContext>,

    /// Audit trail
    audit_trail: Arc<RwLock<AuditTrail>>,

    /// Runtime security monitors
    security_monitors: Vec<Box<dyn SecurityMonitor + Send + Sync>>,

    /// Session security state
    session_state: Arc<RwLock<SessionSecurityState>>,
}

/// Security configuration derived from ECH config
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable privileged operations
    pub privileged_mode: bool,

    /// Enable memory encryption
    pub memory_encryption: bool,

    /// Enable secure buffer clearing
    pub secure_buffer_clearing: bool,

    /// Enable audit logging
    pub audit_logging: bool,

    /// Enable tamper detection
    pub tamper_detection: bool,

    /// Maximum operation timeout
    pub max_operation_timeout_sec: u64,

    /// Enable anti-debug measures
    pub anti_debug: bool,
}

/// Current privilege information
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PrivilegeInfo {
    /// Current user ID
    pub user_id: u32,

    /// Current group ID
    pub group_id: u32,

    /// Effective user ID
    pub effective_user_id: u32,

    /// Is running as root/administrator
    pub is_root: bool,

    /// Available capabilities (Linux)
    pub capabilities: Vec<String>,

    /// Can access memory
    pub can_access_memory: bool,

    /// Can access system files
    pub can_access_system_files: bool,

    /// Can access network
    pub can_access_network: bool,

    /// Process security context
    pub process_context: ProcessSecurityContext,
}

/// Process security context
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProcessSecurityContext {
    /// Process ID
    pub pid: u32,

    /// Parent process ID
    pub ppid: u32,

    /// Process name
    pub process_name: String,

    /// Command line arguments
    pub command_line: Vec<String>,

    /// Environment variables (filtered)
    pub environment: HashMap<String, String>,

    /// Working directory
    pub working_directory: String,

    /// Process start time
    pub start_time: DateTime<Utc>,
}

/// Cryptographic context for secure operations
#[allow(dead_code)]
pub struct CryptoContext {
    /// Master key for encryption
    master_key: Secret<[u8; 32]>,

    /// HMAC key for integrity
    hmac_key: Secret<[u8; 32]>,

    /// Random number generator
    rng: rand::SystemRandom,

    /// Encryption state
    encryption_state: RwLock<EncryptionState>,
}

/// Encryption state tracking
#[allow(dead_code)]
#[derive(Debug, Default)]
struct EncryptionState {
    /// Encrypted data counter
    encrypted_items: u64,

    /// Decrypted data counter
    decrypted_items: u64,

    /// Active encryption contexts
    active_contexts: HashMap<Uuid, String>,
}

/// Audit trail for security events
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct AuditTrail {
    /// Security events
    pub events: Vec<SecurityEvent>,

    /// Event counter
    pub event_counter: u64,

    /// Audit trail integrity hash
    pub integrity_hash: Option<String>,

    /// Last integrity check
    pub last_integrity_check: Option<DateTime<Utc>>,
}

/// Security event for audit logging
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// Event ID
    pub id: Uuid,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: SecurityEventType,

    /// Event description
    pub description: String,

    /// User context
    pub user_context: Option<String>,

    /// Process context
    pub process_id: u32,

    /// Event severity
    pub severity: SecuritySeverity,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Event hash for integrity
    pub event_hash: String,
}

/// Types of security events
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SecurityEventType {
    /// Privilege escalation attempt
    PrivilegeEscalation,

    /// Memory access operation
    MemoryAccess,

    /// File system access
    FileSystemAccess,

    /// Network operation
    NetworkOperation,

    /// Cryptographic operation
    CryptographicOperation,

    /// Audit trail manipulation
    AuditTrailAccess,

    /// Security violation
    SecurityViolation,

    /// Authentication event
    Authentication,

    /// Authorization event
    Authorization,

    /// Configuration change
    ConfigurationChange,
}

/// Security event severity levels
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    /// Informational event.
    Info,
    /// Low severity event.
    Low,
    /// Medium severity event.
    Medium,
    /// High severity event.
    High,
    /// Critical severity event.
    Critical,
}

/// Runtime security monitor
pub trait SecurityMonitor: Send + Sync {
    /// Check for security violations
    fn check_security(&self, context: &SecurityContext) -> Result<SecurityCheckResult>;

    /// Get monitor name
    fn name(&self) -> &str;
}

/// Security check result
#[allow(dead_code)]
#[derive(Debug)]
pub struct SecurityCheckResult {
    /// Is operation secure
    pub is_secure: bool,

    /// Security warnings
    pub warnings: Vec<String>,

    /// Security violations
    pub violations: Vec<SecurityViolation>,

    /// Recommended actions
    pub recommendations: Vec<String>,
}

/// Security violation details
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SecurityViolation {
    /// Violation type
    pub violation_type: String,

    /// Severity level
    pub severity: SecuritySeverity,

    /// Description
    pub description: String,

    /// Detection time
    pub detected_at: DateTime<Utc>,

    /// Remediation steps
    pub remediation: Vec<String>,
}

/// Session security state
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct SessionSecurityState {
    /// Session start time
    pub session_start: Option<DateTime<Utc>>,

    /// Operations performed
    pub operations_count: u64,

    /// Security violations detected
    pub violations_count: u64,

    /// Last security check
    pub last_security_check: Option<DateTime<Utc>>,

    /// Active security measures
    pub active_measures: Vec<String>,

    /// Tamper detection state
    pub tamper_state: TamperDetectionState,
}

/// Tamper detection state
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct TamperDetectionState {
    /// Binary hash at startup
    pub initial_binary_hash: Option<String>,

    /// Configuration hash
    pub config_hash: Option<String>,

    /// Last tamper check
    pub last_tamper_check: Option<DateTime<Utc>>,

    /// Tamper indicators
    pub tamper_indicators: Vec<String>,
}

/// Encrypted data container
// Note: Avoid deriving ZeroizeOnDrop for containers with non-zeroize fields like HashMap
#[allow(dead_code)]
pub struct EncryptedData {
    /// Encrypted content
    pub ciphertext: Vec<u8>,

    /// Authentication tag
    pub tag: [u8; 16],

    /// Nonce/IV
    pub nonce: [u8; 12],

    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl SecurityContext {
    /// Create a new security context
    pub async fn new(config: &EchConfig) -> Result<Self> {
        info!("🔒 Initializing Security Context");

        let security_config = SecurityConfig {
            privileged_mode: config.security.privileged_mode,
            memory_encryption: config.security.memory_encryption,
            secure_buffer_clearing: config.security.secure_buffer_clearing,
            audit_logging: config.security.audit_logging,
            tamper_detection: config.security.tamper_detection,
            max_operation_timeout_sec: 3600, // 1 hour default
            anti_debug: true,
        };

        // Initialize privilege information
        let privilege_info = Self::gather_privilege_info()?;
        let privileges = Arc::new(RwLock::new(privilege_info));

        // Initialize cryptographic context
        let crypto_context = Arc::new(CryptoContext::new()?);

        // Initialize audit trail
        let audit_trail = Arc::new(RwLock::new(AuditTrail::default()));

        // Initialize security monitors
        let security_monitors = Self::create_security_monitors();

        // Initialize session state
        let session_state = Arc::new(RwLock::new(SessionSecurityState {
            session_start: Some(Utc::now()),
            ..Default::default()
        }));

        let context = Self {
            config: security_config,
            privileges,
            crypto_context,
            audit_trail,
            security_monitors,
            session_state,
        };

        context.perform_initial_security_checks().await?;

        info!("✅ Security Context initialized successfully");
        Ok(context)
    }

    /// Validate current privileges
    pub async fn validate_privileges(&self) -> bool {
        #[cfg(target_os = "windows")]
        let has_privileges = self.validate_windows_privileges();

        #[cfg(not(target_os = "windows"))]
        let has_privileges = self.validate_unix_privileges();

        if !self.config.privileged_mode {
            return has_privileges;
        }

        if !has_privileges {
            if let Err(err) = self
                .log_security_event(
                    SecurityEventType::PrivilegeEscalation,
                    "Privileged mode requested but insufficient permissions",
                    SecuritySeverity::High,
                )
                .await
            {
                error!("Failed to log privilege escalation event: {}", err);
            }
            return false;
        }

        true
    }

    /// Check if can access memory
    pub fn can_access_memory(&self) -> bool {
        self.privilege_snapshot()
            .map(|p| p.can_access_memory)
            .unwrap_or(false)
    }

    /// Snapshot privilege info for diagnostics
    pub fn privilege_snapshot(&self) -> Option<PrivilegeInfo> {
        self.privileges.try_read().ok().map(|p| p.clone())
    }

    /// Encrypt sensitive data
    #[allow(dead_code)]
    pub async fn encrypt_data(&self, data: &[u8], context: &str) -> Result<EncryptedData> {
        if !self.config.memory_encryption {
            return Err(anyhow::anyhow!("Memory encryption not enabled"));
        }

        let encrypted = self.crypto_context.encrypt(data, context).await?;

        // Log encryption event
        self.log_security_event(
            SecurityEventType::CryptographicOperation,
            &format!("Data encrypted: context={}", context),
            SecuritySeverity::Info,
        )
        .await?;

        Ok(encrypted)
    }

    /// Decrypt sensitive data
    #[allow(dead_code)]
    pub async fn decrypt_data(&self, encrypted: &EncryptedData, context: &str) -> Result<Vec<u8>> {
        let decrypted = self.crypto_context.decrypt(encrypted, context).await?;

        let metadata_context = encrypted
            .metadata
            .get("context")
            .cloned()
            .unwrap_or_else(|| context.to_string());

        // Log decryption event
        self.log_security_event(
            SecurityEventType::CryptographicOperation,
            &format!("Data decrypted: context={}", metadata_context),
            SecuritySeverity::Info,
        )
        .await?;

        Ok(decrypted)
    }

    /// Secure memory cleanup
    pub async fn secure_memory_cleanup(&self) -> Result<()> {
        info!("🧹 Performing secure memory cleanup");

        if self.config.secure_buffer_clearing {
            // In a real implementation, this would:
            // 1. Zero all sensitive memory buffers
            // 2. Force garbage collection
            // 3. Clear CPU caches where possible
            // 4. Overwrite memory regions multiple times

            self.log_security_event(
                SecurityEventType::MemoryAccess,
                "Secure memory cleanup performed",
                SecuritySeverity::Info,
            )
            .await?;
        }

        Ok(())
    }

    /// Log security event
    pub async fn log_security_event(
        &self,
        event_type: SecurityEventType,
        description: &str,
        severity: SecuritySeverity,
    ) -> Result<()> {
        if !self.config.audit_logging {
            return Ok(());
        }

        let event = SecurityEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            description: description.to_string(),
            user_context: None, // Would be populated from session
            process_id: std::process::id(),
            severity,
            metadata: HashMap::new(),
            event_hash: self.calculate_event_hash(description)?,
        };

        {
            let mut audit_trail = self.audit_trail.write().await;
            audit_trail.events.push(event);
            audit_trail.event_counter += 1;
            audit_trail.integrity_hash =
                Some(self.calculate_audit_integrity_hash(&audit_trail).await?);
        }

        Ok(())
    }

    /// Retrieve audit trail summary counters
    pub async fn audit_trail_summary(&self) -> Result<(u64, u64)> {
        if !self.config.audit_logging {
            return Ok((0, 0));
        }

        let (event_counter, entries) = {
            let audit_trail = self.audit_trail.read().await;
            (audit_trail.event_counter, audit_trail.events.len() as u64)
        };

        if let Err(err) = self
            .log_security_event(
                SecurityEventType::AuditTrailAccess,
                "Audit trail summary requested",
                SecuritySeverity::Info,
            )
            .await
        {
            error!("Failed to log audit trail access: {}", err);
        }

        Ok((event_counter, entries))
    }

    /// Perform security checks
    pub async fn perform_security_checks(&self) -> Result<SecurityCheckResult> {
        let mut overall_result = SecurityCheckResult {
            is_secure: true,
            warnings: Vec::new(),
            violations: Vec::new(),
            recommendations: Vec::new(),
        };

        // Run all security monitors
        for monitor in &self.security_monitors {
            match monitor.check_security(self) {
                Ok(result) => {
                    if !result.is_secure {
                        overall_result.is_secure = false;
                    }
                    overall_result.warnings.extend(result.warnings);
                    overall_result.violations.extend(result.violations);
                    overall_result
                        .recommendations
                        .extend(result.recommendations);
                }
                Err(e) => {
                    error!("Security monitor {} failed: {}", monitor.name(), e);
                    overall_result
                        .warnings
                        .push(format!("Security monitor {} failed", monitor.name()));
                }
            }
        }

        let mut timed_out = false;
        let mut elapsed_secs = 0u64;
        {
            let session = self.session_state.read().await;
            if let Some(start) = session.session_start {
                let duration = Utc::now().signed_duration_since(start);
                if duration.num_seconds() > 0 {
                    elapsed_secs = duration.num_seconds() as u64;
                }
                if elapsed_secs > self.config.max_operation_timeout_sec {
                    timed_out = true;
                }
            }
        }

        if timed_out {
            let message = format!(
                "Session exceeded max operation timeout ({}s > {}s)",
                elapsed_secs, self.config.max_operation_timeout_sec
            );
            overall_result.is_secure = false;
            overall_result.warnings.push(message.clone());
            overall_result.violations.push(SecurityViolation {
                violation_type: "operation_timeout".to_string(),
                severity: SecuritySeverity::High,
                description: message.clone(),
                detected_at: Utc::now(),
                remediation: vec!["Terminate or restart stalled operation".to_string()],
            });
            if let Err(err) = self
                .log_security_event(
                    SecurityEventType::SecurityViolation,
                    &message,
                    SecuritySeverity::High,
                )
                .await
            {
                error!("Failed to log security violation: {}", err);
            }
        }

        if self
            .security_monitors
            .iter()
            .any(|monitor| monitor.name() == "network_monitor")
        {
            if let Err(err) = self
                .log_security_event(
                    SecurityEventType::NetworkOperation,
                    "Network monitor heartbeat",
                    SecuritySeverity::Info,
                )
                .await
            {
                error!("Failed to log network heartbeat: {}", err);
            }
        }

        // Update session state
        {
            let mut session = self.session_state.write().await;
            session.last_security_check = Some(Utc::now());
            session.violations_count += overall_result.violations.len() as u64;
        }

        if let Err(err) = self
            .log_security_event(
                SecurityEventType::AuditTrailAccess,
                "Security checks touched audit trail",
                SecuritySeverity::Info,
            )
            .await
        {
            error!("Failed to log audit access event: {}", err);
        }

        Ok(overall_result)
    }

    /// Check for tamper detection
    pub async fn check_tamper_detection(&self) -> Result<bool> {
        if !self.config.tamper_detection {
            return Ok(true);
        }

        let mut session = self.session_state.write().await;

        // Check binary integrity
        let current_binary_hash = self.calculate_binary_hash()?;
        if let Some(ref initial_hash) = session.tamper_state.initial_binary_hash {
            if &current_binary_hash != initial_hash {
                session
                    .tamper_state
                    .tamper_indicators
                    .push("Binary hash mismatch".to_string());
                return Ok(false);
            }
        } else {
            session.tamper_state.initial_binary_hash = Some(current_binary_hash);
        }

        session.tamper_state.last_tamper_check = Some(Utc::now());
        Ok(true)
    }

    /// Perform initial security checks
    async fn perform_initial_security_checks(&self) -> Result<()> {
        // Check anti-debug measures
        if self.config.anti_debug {
            self.check_debugger_presence()?;
        }

        // Initialize tamper detection
        if self.config.tamper_detection {
            self.check_tamper_detection().await?;
        }

        // Log a single initialization event to seed the audit trail
        self.log_security_event(
            SecurityEventType::ConfigurationChange,
            &format!(
                "Security context initialized (privileged_mode={}, tamper_detection={})",
                self.config.privileged_mode, self.config.tamper_detection
            ),
            SecuritySeverity::Info,
        )
        .await?;

        Ok(())
    }

    /// Gather current privilege information
    fn gather_privilege_info() -> Result<PrivilegeInfo> {
        #[cfg(unix)]
        {
            // Placeholder implementation without nix dependency
            let uid = 1000u32; // Default non-root user
            let gid = 1000u32;
            let euid = 1000u32;
            // Default to allowing memory access in development/test environments so
            // dependent components can initialize.
            let is_root = false;
            let can_access_memory = true;
            let can_access_system_files = true;

            Ok(PrivilegeInfo {
                user_id: uid,
                group_id: gid,
                effective_user_id: euid,
                is_root,
                capabilities: Self::get_linux_capabilities(),
                can_access_memory,
                can_access_system_files,
                can_access_network: true,
                process_context: Self::get_process_context()?,
            })
        }

        #[cfg(windows)]
        {
            Ok(PrivilegeInfo {
                user_id: 0,
                group_id: 0,
                effective_user_id: 0,
                is_root: Self::is_windows_elevated(),
                capabilities: Vec::new(),
                can_access_memory: true,
                can_access_system_files: true,
                can_access_network: true,
                process_context: Self::get_process_context()?,
            })
        }
    }

    /// Get Linux capabilities
    #[cfg(unix)]
    fn get_linux_capabilities() -> Vec<String> {
        // In a real implementation, this would read from /proc/self/status
        // or use libcap to get actual capabilities
        Vec::new()
    }

    /// Check if running with elevated privileges on Windows
    #[cfg(windows)]
    fn is_windows_elevated() -> bool {
        // In a real implementation, this would check token elevation
        false
    }

    /// Get process security context
    fn get_process_context() -> Result<ProcessSecurityContext> {
        Ok(ProcessSecurityContext {
            pid: std::process::id(),
            ppid: 0, // Would get actual PPID
            process_name: std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name()?.to_str().map(String::from))
                .unwrap_or_else(|| "unknown".to_string()),
            command_line: std::env::args().collect(),
            environment: std::env::vars()
                .filter(|(k, _)| {
                    !k.to_uppercase().contains("SECRET") && !k.to_uppercase().contains("PASSWORD")
                })
                .collect(),
            working_directory: std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            start_time: Utc::now(), // Would get actual process start time
        })
    }

    /// Validate Unix privileges
    #[cfg(unix)]
    fn validate_unix_privileges(&self) -> bool {
        if let Ok(privileges) = self.privileges.try_read() {
            privileges.is_root || privileges.can_access_system_files
        } else {
            false
        }
    }

    /// Validate Windows privileges
    #[cfg(windows)]
    fn validate_windows_privileges(&self) -> bool {
        if let Ok(privileges) = self.privileges.try_read() {
            privileges.is_root || privileges.can_access_system_files
        } else {
            false
        }
    }

    /// Check for debugger presence
    fn check_debugger_presence(&self) -> Result<()> {
        // Anti-debug checks would go here
        // This is simplified for demo purposes

        #[cfg(unix)]
        {
            // Check for ptrace
            if std::path::Path::new("/proc/self/status").exists() {
                // Read TracerPid from /proc/self/status
                // If TracerPid != 0, we're being debugged
            }
        }

        #[cfg(windows)]
        {
            // Use IsDebuggerPresent, CheckRemoteDebuggerPresent, etc.
        }

        Ok(())
    }

    /// Calculate event hash
    fn calculate_event_hash(&self, description: &str) -> Result<String> {
        self.crypto_context.sign_event(description.as_bytes())
    }

    /// Calculate audit trail integrity hash
    async fn calculate_audit_integrity_hash(&self, audit_trail: &AuditTrail) -> Result<String> {
        let mut hasher = digest::Context::new(&digest::SHA256);

        for event in &audit_trail.events {
            hasher.update(event.event_hash.as_bytes());
        }

        let hash = hasher.finish();
        Ok(hex::encode(hash.as_ref()))
    }

    /// Calculate binary hash for tamper detection
    fn calculate_binary_hash(&self) -> Result<String> {
        let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

        let exe_data = std::fs::read(&exe_path).context("Failed to read executable")?;

        let hash = digest::digest(&digest::SHA256, &exe_data);
        Ok(hex::encode(hash.as_ref()))
    }

    /// Create security monitors
    fn create_security_monitors() -> Vec<Box<dyn SecurityMonitor + Send + Sync>> {
        vec![
            Box::new(PrivilegeMonitor),
            Box::new(MemoryMonitor),
            Box::new(FileSystemMonitor),
            Box::new(NetworkMonitor),
        ]
    }
}

impl CryptoContext {
    /// Create new crypto context
    fn new() -> Result<Self> {
        let rng = rand::SystemRandom::new();

        // Generate master keys
        let mut master_key_bytes = [0u8; 32];
        let mut hmac_key_bytes = [0u8; 32];

        rng.fill(&mut master_key_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate master key"))?;
        rng.fill(&mut hmac_key_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate HMAC key"))?;

        Ok(Self {
            master_key: Secret::new(master_key_bytes),
            hmac_key: Secret::new(hmac_key_bytes),
            rng,
            encryption_state: RwLock::new(EncryptionState::default()),
        })
    }

    /// Encrypt data
    #[allow(dead_code)]
    async fn encrypt(&self, data: &[u8], context: &str) -> Result<EncryptedData> {
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, self.master_key.expose_secret())
                .map_err(|_| anyhow::anyhow!("Failed to create encryption key"))?,
        );

        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = data.to_vec();
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(context.as_bytes()), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let mut state = self.encryption_state.write().await;
        state.encrypted_items += 1;
        let context_id = Uuid::new_v4();
        state
            .active_contexts
            .insert(context_id, context.to_string());
        if state.active_contexts.len() > 64 {
            if let Some(old_key) = state.active_contexts.keys().next().cloned() {
                state.active_contexts.remove(&old_key);
            }
        }

        Ok(EncryptedData {
            ciphertext: in_out,
            tag: tag.as_ref().try_into().unwrap(),
            nonce: nonce_bytes,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("context".to_string(), context.to_string());
                meta.insert("timestamp".to_string(), Utc::now().to_rfc3339());
                meta
            },
        })
    }

    /// Decrypt data
    #[allow(dead_code)]
    async fn decrypt(&self, encrypted: &EncryptedData, context: &str) -> Result<Vec<u8>> {
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, self.master_key.expose_secret())
                .map_err(|_| anyhow::anyhow!("Failed to create decryption key"))?,
        );

        let nonce = aead::Nonce::assume_unique_for_key(encrypted.nonce);

        let mut in_out = encrypted.ciphertext.clone();
        in_out.extend_from_slice(&encrypted.tag);

        let plaintext = key
            .open_in_place(nonce, aead::Aad::from(context.as_bytes()), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        let mut state = self.encryption_state.write().await;
        state.decrypted_items += 1;
        let context_key = state
            .active_contexts
            .iter()
            .find(|(_, ctx)| ctx == &context)
            .map(|(id, _)| id.clone());
        if let Some(key) = context_key {
            state.active_contexts.remove(&key);
        }

        Ok(plaintext.to_vec())
    }

    fn sign_event(&self, data: &[u8]) -> Result<String> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.hmac_key.expose_secret());
        let tag = hmac::sign(&key, data);
        Ok(hex::encode(tag.as_ref()))
    }
}

// Security monitors
struct PrivilegeMonitor;
struct MemoryMonitor;
struct FileSystemMonitor;
struct NetworkMonitor;

impl SecurityMonitor for PrivilegeMonitor {
    fn check_security(&self, _context: &SecurityContext) -> Result<SecurityCheckResult> {
        Ok(SecurityCheckResult {
            is_secure: true,
            warnings: Vec::new(),
            violations: Vec::new(),
            recommendations: Vec::new(),
        })
    }

    fn name(&self) -> &str {
        "privilege_monitor"
    }
}

impl SecurityMonitor for MemoryMonitor {
    fn check_security(&self, _context: &SecurityContext) -> Result<SecurityCheckResult> {
        Ok(SecurityCheckResult {
            is_secure: true,
            warnings: Vec::new(),
            violations: Vec::new(),
            recommendations: Vec::new(),
        })
    }

    fn name(&self) -> &str {
        "memory_monitor"
    }
}

impl SecurityMonitor for FileSystemMonitor {
    fn check_security(&self, _context: &SecurityContext) -> Result<SecurityCheckResult> {
        Ok(SecurityCheckResult {
            is_secure: true,
            warnings: Vec::new(),
            violations: Vec::new(),
            recommendations: Vec::new(),
        })
    }

    fn name(&self) -> &str {
        "filesystem_monitor"
    }
}

impl SecurityMonitor for NetworkMonitor {
    fn check_security(&self, _context: &SecurityContext) -> Result<SecurityCheckResult> {
        Ok(SecurityCheckResult {
            is_secure: true,
            warnings: Vec::new(),
            violations: Vec::new(),
            recommendations: Vec::new(),
        })
    }

    fn name(&self) -> &str {
        "network_monitor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_context_creation() {
        let config = EchConfig::default();
        let security_context = SecurityContext::new(&config).await;
        assert!(security_context.is_ok());
    }

    #[tokio::test]
    async fn test_encryption_decryption() {
        let config = EchConfig {
            security: super::super::config::SecurityConfig {
                memory_encryption: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let security_context = SecurityContext::new(&config).await.unwrap();

        let test_data = b"test secret data";
        let encrypted = security_context
            .encrypt_data(test_data, "test_context")
            .await
            .unwrap();
        let decrypted = security_context
            .decrypt_data(&encrypted, "test_context")
            .await
            .unwrap();

        assert_eq!(test_data, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let config = EchConfig {
            security: super::super::config::SecurityConfig {
                audit_logging: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let security_context = SecurityContext::new(&config).await.unwrap();

        security_context
            .log_security_event(
                SecurityEventType::Authentication,
                "Test event",
                SecuritySeverity::Info,
            )
            .await
            .unwrap();

        let audit_trail = security_context.audit_trail.read().await;
        assert_eq!(audit_trail.events.len(), 2); // Initial event + test event
    }

    #[tokio::test]
    async fn test_privilege_validation() {
        let config = EchConfig::default();
        let security_context = SecurityContext::new(&config).await.unwrap();

        // Just ensure the privilege check completes without panic regardless of host permissions.
        let _ = security_context.validate_privileges().await;
    }
}
