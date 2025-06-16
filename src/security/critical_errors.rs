/**
 * Critical Error Management for ECH
 * 
 * Handles root-level critical errors with custom enum and recovery strategies.
 * Provides atomic error handling for security-critical situations.
 */

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Critical errors that require immediate security response
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum EchCriticalError {
    #[error("Audit log has been compromised: {details}")]
    AuditLogCompromise {
        details: String,
        integrity_hash: Option<String>,
        last_valid_entry: Option<String>,
    },
    
    #[error("Debugger detected: {detection_method}")]
    DebuggerDetected {
        detection_method: String,
        debugger_process: Option<String>,
        threat_level: u8,
    },
    
    #[error("Memory tampering detected: {address:#x}")]
    MemoryTampering {
        address: usize,
        expected_value: Vec<u8>,
        actual_value: Vec<u8>,
        tamper_signature: String,
    },
    
    #[error("Process injection detected: {injector_pid}")]
    ProcessInjection {
        injector_pid: u32,
        injection_type: InjectionType,
        target_module: String,
    },
    
    #[error("Anti-tamper mechanism triggered: {mechanism}")]
    AntiTamperTriggered {
        mechanism: String,
        trigger_count: u32,
        last_trigger_time: chrono::DateTime<chrono::Utc>,
    },
    
    #[error("SIEM connection lost: {duration_seconds}s")]
    SiemConnectionLost {
        duration_seconds: u64,
        last_successful_ping: chrono::DateTime<chrono::Utc>,
        retry_count: u32,
    },
    
    #[error("Configuration tampering detected: {config_path}")]
    ConfigurationTampering {
        config_path: String,
        expected_hash: String,
        actual_hash: String,
        modification_time: chrono::DateTime<chrono::Utc>,
    },
    
    #[error("Critical module failure: {module_name}")]
    CriticalModuleFailure {
        module_name: String,
        failure_reason: String,
        recovery_possible: bool,
        error_code: i32,
    },
    
    #[error("Unauthorized privilege escalation: {process}")]
    UnauthorizedPrivilegeEscalation {
        process: String,
        original_privileges: String,
        escalated_privileges: String,
        escalation_method: String,
    },
    
    #[error("Security policy violation: {policy}")]
    SecurityPolicyViolation {
        policy: String,
        violation_details: String,
        user_context: Option<String>,
        severity_score: u8,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionType {
    DllInjection,
    ProcessHollowing,
    AtomBombing,
    ManualDllMapping,
    SetWindowsHookEx,
    QueueUserApc,
    Unknown(String),
}

impl fmt::Display for InjectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InjectionType::DllInjection => write!(f, "DLL Injection"),
            InjectionType::ProcessHollowing => write!(f, "Process Hollowing"),
            InjectionType::AtomBombing => write!(f, "Atom Bombing"),
            InjectionType::ManualDllMapping => write!(f, "Manual DLL Mapping"),
            InjectionType::SetWindowsHookEx => write!(f, "SetWindowsHookEx"),
            InjectionType::QueueUserApc => write!(f, "QueueUserAPC"),
            InjectionType::Unknown(method) => write!(f, "Unknown: {}", method),
        }
    }
}

/// Critical error context with recovery information
#[derive(Debug, Clone)]
pub struct CriticalErrorContext {
    pub error: EchCriticalError,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_module: String,
    pub stack_trace: Option<String>,
    pub system_state: SystemState,
    pub recovery_strategy: RecoveryStrategy,
    pub incident_id: uuid::Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub memory_usage: u64,
    pub cpu_usage: f32,
    pub open_handles: u32,
    pub network_connections: u32,
    pub running_threads: u32,
    pub security_modules_active: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    /// Immediate self-destruct
    SelfDestruct,
    /// Graceful shutdown with cleanup
    GracefulShutdown,
    /// Enter stealth mode
    EnterStealthMode,
    /// Isolate and continue
    IsolateAndContinue,
    /// Restart affected module
    RestartModule(String),
    /// No recovery possible
    NoRecovery,
}

/// Critical error handler with atomic operations
pub struct CriticalErrorHandler {
    self_destruct_armed: AtomicBool,
    emergency_shutdown_initiated: AtomicBool,
    stealth_mode_active: AtomicBool,
}

impl CriticalErrorHandler {
    pub fn new() -> Self {
        Self {
            self_destruct_armed: AtomicBool::new(false),
            emergency_shutdown_initiated: AtomicBool::new(false),
            stealth_mode_active: AtomicBool::new(false),
        }
    }
    
    /// Handle critical error with appropriate response
    pub async fn handle_critical_error(&self, context: CriticalErrorContext) -> Result<(), Box<dyn std::error::Error>> {
        // Log critical error
        tracing::error!("CRITICAL ERROR: {} (ID: {})", context.error, context.incident_id);
        
        // Report to security manager
        let incident = crate::security::SecurityIncident {
            severity: self.determine_severity(&context.error),
            incident_type: self.map_to_incident_type(&context.error),
            timestamp: context.timestamp,
            details: context.error.to_string(),
            source_module: context.source_module.clone(),
            threat_level: self.assess_threat_level(&context.error),
            recommended_action: self.determine_action(&context.recovery_strategy),
        };
        
        crate::security::report_security_incident(incident).await?;
        
        // Execute recovery strategy
        self.execute_recovery_strategy(&context).await?;
        
        Ok(())
    }
    
    /// Determine severity based on error type
    fn determine_severity(&self, error: &EchCriticalError) -> crate::security::SecuritySeverity {
        match error {
            EchCriticalError::AuditLogCompromise { .. } => crate::security::SecuritySeverity::Emergency,
            EchCriticalError::DebuggerDetected { threat_level, .. } => {
                if *threat_level >= 8 {
                    crate::security::SecuritySeverity::Emergency
                } else if *threat_level >= 5 {
                    crate::security::SecuritySeverity::Critical
                } else {
                    crate::security::SecuritySeverity::High
                }
            },
            EchCriticalError::MemoryTampering { .. } => crate::security::SecuritySeverity::Critical,
            EchCriticalError::ProcessInjection { .. } => crate::security::SecuritySeverity::Critical,
            EchCriticalError::AntiTamperTriggered { trigger_count, .. } => {
                if *trigger_count >= 3 {
                    crate::security::SecuritySeverity::Emergency
                } else {
                    crate::security::SecuritySeverity::Critical
                }
            },
            EchCriticalError::SiemConnectionLost { duration_seconds, .. } => {
                if *duration_seconds > 300 {
                    crate::security::SecuritySeverity::Critical
                } else {
                    crate::security::SecuritySeverity::High
                }
            },
            EchCriticalError::ConfigurationTampering { .. } => crate::security::SecuritySeverity::Critical,
            EchCriticalError::CriticalModuleFailure { recovery_possible, .. } => {
                if *recovery_possible {
                    crate::security::SecuritySeverity::High
                } else {
                    crate::security::SecuritySeverity::Critical
                }
            },
            EchCriticalError::UnauthorizedPrivilegeEscalation { .. } => crate::security::SecuritySeverity::Emergency,
            EchCriticalError::SecurityPolicyViolation { severity_score, .. } => {
                if *severity_score >= 8 {
                    crate::security::SecuritySeverity::Critical
                } else if *severity_score >= 5 {
                    crate::security::SecuritySeverity::High
                } else {
                    crate::security::SecuritySeverity::Medium
                }
            },
        }
    }
    
    /// Map error to incident type
    fn map_to_incident_type(&self, error: &EchCriticalError) -> crate::security::SecurityIncidentType {
        match error {
            EchCriticalError::AuditLogCompromise { .. } => crate::security::SecurityIncidentType::AuditLogCompromise,
            EchCriticalError::DebuggerDetected { .. } => crate::security::SecurityIncidentType::DebuggerDetected,
            EchCriticalError::MemoryTampering { .. } => crate::security::SecurityIncidentType::MemoryTampering,
            EchCriticalError::ProcessInjection { .. } => crate::security::SecurityIncidentType::ProcessInjection,
            EchCriticalError::AntiTamperTriggered { .. } => crate::security::SecurityIncidentType::AntiTamperTriggered,
            EchCriticalError::SiemConnectionLost { .. } => crate::security::SecurityIncidentType::SiemDisconnection,
            EchCriticalError::ConfigurationTampering { .. } => crate::security::SecurityIncidentType::ConfigurationTampering,
            EchCriticalError::CriticalModuleFailure { .. } => crate::security::SecurityIncidentType::CriticalModuleFailure,
            EchCriticalError::UnauthorizedPrivilegeEscalation { .. } => crate::security::SecurityIncidentType::UnauthorizedAccess,
            EchCriticalError::SecurityPolicyViolation { .. } => crate::security::SecurityIncidentType::UnauthorizedAccess,
        }
    }
    
    /// Assess threat level
    fn assess_threat_level(&self, error: &EchCriticalError) -> crate::security::ThreatLevel {
        match error {
            EchCriticalError::AuditLogCompromise { .. } => crate::security::ThreatLevel::Imminent,
            EchCriticalError::DebuggerDetected { threat_level, .. } => {
                if *threat_level >= 8 {
                    crate::security::ThreatLevel::Imminent
                } else if *threat_level >= 5 {
                    crate::security::ThreatLevel::Critical
                } else {
                    crate::security::ThreatLevel::High
                }
            },
            EchCriticalError::MemoryTampering { .. } => crate::security::ThreatLevel::Critical,
            EchCriticalError::ProcessInjection { .. } => crate::security::ThreatLevel::Critical,
            EchCriticalError::AntiTamperTriggered { .. } => crate::security::ThreatLevel::Critical,
            EchCriticalError::UnauthorizedPrivilegeEscalation { .. } => crate::security::ThreatLevel::Imminent,
            _ => crate::security::ThreatLevel::High,
        }
    }
    
    /// Determine recommended action
    fn determine_action(&self, strategy: &RecoveryStrategy) -> crate::security::SecurityAction {
        match strategy {
            RecoveryStrategy::SelfDestruct => crate::security::SecurityAction::SelfDestruct,
            RecoveryStrategy::GracefulShutdown => crate::security::SecurityAction::EmergencyShutdown,
            RecoveryStrategy::EnterStealthMode => crate::security::SecurityAction::StealthMode,
            RecoveryStrategy::IsolateAndContinue => crate::security::SecurityAction::Quarantine,
            RecoveryStrategy::RestartModule(_) => crate::security::SecurityAction::Alert,
            RecoveryStrategy::NoRecovery => crate::security::SecurityAction::SelfDestruct,
        }
    }
    
    /// Execute recovery strategy
    async fn execute_recovery_strategy(&self, context: &CriticalErrorContext) -> Result<(), Box<dyn std::error::Error>> {
        match &context.recovery_strategy {
            RecoveryStrategy::SelfDestruct => {
                if !self.self_destruct_armed.swap(true, Ordering::SeqCst) {
                    tracing::error!("EXECUTING SELF-DESTRUCT for error: {}", context.error);
                    self.execute_self_destruct().await?;
                }
            },
            RecoveryStrategy::GracefulShutdown => {
                if !self.emergency_shutdown_initiated.swap(true, Ordering::SeqCst) {
                    tracing::warn!("EXECUTING GRACEFUL SHUTDOWN for error: {}", context.error);
                    self.execute_graceful_shutdown().await?;
                }
            },
            RecoveryStrategy::EnterStealthMode => {
                if !self.stealth_mode_active.swap(true, Ordering::SeqCst) {
                    tracing::warn!("ENTERING STEALTH MODE for error: {}", context.error);
                    self.enter_stealth_mode().await?;
                }
            },
            RecoveryStrategy::IsolateAndContinue => {
                tracing::warn!("ISOLATING SYSTEM for error: {}", context.error);
                self.isolate_system().await?;
            },
            RecoveryStrategy::RestartModule(module_name) => {
                tracing::warn!("RESTARTING MODULE {} for error: {}", module_name, context.error);
                self.restart_module(module_name).await?;
            },
            RecoveryStrategy::NoRecovery => {
                tracing::error!("NO RECOVERY POSSIBLE for error: {}", context.error);
                // Fall back to self-destruct
                if !self.self_destruct_armed.swap(true, Ordering::SeqCst) {
                    self.execute_self_destruct().await?;
                }
            },
        }
        
        Ok(())
    }
    
    /// Execute self-destruct sequence
    async fn execute_self_destruct(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Wipe sensitive memory
        self.wipe_sensitive_memory().await?;
        
        // Delete temporary files
        self.delete_temporary_files().await?;
        
        // Send final alert
        tracing::error!("Self-destruct sequence completed. Terminating process.");
        
        // Terminate immediately
        std::process::abort();
    }
    
    /// Execute graceful shutdown
    async fn execute_graceful_shutdown(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Save critical state
        // Cleanup resources
        // Send shutdown notification
        
        tracing::warn!("Graceful shutdown completed. Exiting.");
        std::process::exit(1);
    }
    
    /// Enter stealth mode
    async fn enter_stealth_mode(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Disable all logging
        // Minimize memory footprint
        // Reduce network activity
        // Hide process
        
        Ok(())
    }
    
    /// Isolate system
    async fn isolate_system(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Disable network connections
        // Stop credential scanning
        // Maintain monitoring only
        
        Ok(())
    }
    
    /// Restart module
    async fn restart_module(&self, _module_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Module restart logic would go here
        Ok(())
    }
    
    /// Wipe sensitive memory regions
    async fn wipe_sensitive_memory(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Zero out credential storage
        // Clear encryption keys
        // Wipe temporary buffers
        
        Ok(())
    }
    
    /// Delete temporary files
    async fn delete_temporary_files(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Remove log files
        // Delete cache files
        // Clean up process artifacts
        
        Ok(())
    }
    
    /// Check if self-destruct is armed
    pub fn is_self_destruct_armed(&self) -> bool {
        self.self_destruct_armed.load(Ordering::SeqCst)
    }
    
    /// Check if emergency shutdown is initiated
    pub fn is_emergency_shutdown_initiated(&self) -> bool {
        self.emergency_shutdown_initiated.load(Ordering::SeqCst)
    }
    
    /// Check if stealth mode is active
    pub fn is_stealth_mode_active(&self) -> bool {
        self.stealth_mode_active.load(Ordering::SeqCst)
    }
}

/// Convenience function to create critical error context
pub fn create_critical_error_context(
    error: EchCriticalError,
    source_module: &str,
    recovery_strategy: RecoveryStrategy,
) -> CriticalErrorContext {
    CriticalErrorContext {
        error,
        timestamp: chrono::Utc::now(),
        source_module: source_module.to_string(),
        stack_trace: std::backtrace::Backtrace::capture().to_string().into(),
        system_state: SystemState {
            memory_usage: 0, // Would be populated with real data
            cpu_usage: 0.0,
            open_handles: 0,
            network_connections: 0,
            running_threads: 0,
            security_modules_active: vec![],
        },
        recovery_strategy,
        incident_id: uuid::Uuid::new_v4(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_critical_error_creation() {
        let error = EchCriticalError::DebuggerDetected {
            detection_method: "IsDebuggerPresent".to_string(),
            debugger_process: Some("windbg.exe".to_string()),
            threat_level: 8,
        };
        
        assert!(error.to_string().contains("Debugger detected"));
    }
    
    #[tokio::test]
    async fn test_critical_error_handler() {
        let handler = CriticalErrorHandler::new();
        
        assert!(!handler.is_self_destruct_armed());
        assert!(!handler.is_emergency_shutdown_initiated());
        assert!(!handler.is_stealth_mode_active());
    }
    
    #[test]
    fn test_error_context_creation() {
        let error = EchCriticalError::AuditLogCompromise {
            details: "Hash mismatch detected".to_string(),
            integrity_hash: Some("abc123".to_string()),
            last_valid_entry: None,
        };
        
        let context = create_critical_error_context(
            error,
            "audit_module",
            RecoveryStrategy::SelfDestruct,
        );
        
        assert_eq!(context.source_module, "audit_module");
        assert!(matches!(context.recovery_strategy, RecoveryStrategy::SelfDestruct));
    }
}