/**
 * ECH Engine Event Bus
 * 
 * Unified event system for internal communication between modules.
 * Provides async message passing, tracing, metrics collection, and debugging.
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, RwLock};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Central event bus for the ECH engine
pub struct EngineEventBus {
    // Event channels for different event types
    system_events: broadcast::Sender<SystemEvent>,
    security_events: broadcast::Sender<SecurityEvent>,
    performance_events: broadcast::Sender<PerformanceEvent>,
    detection_events: broadcast::Sender<DetectionEvent>,
    
    // Command channels for module communication
    module_commands: Arc<RwLock<HashMap<String, mpsc::Sender<ModuleCommand>>>>,
    
    // Event statistics and metrics
    event_stats: Arc<RwLock<EventStatistics>>,
    
    // Event tracing and debugging
    event_trace: Arc<RwLock<Vec<EventTrace>>>,
    max_trace_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub event_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_module: String,
    pub event_type: SystemEventType,
    pub severity: EventSeverity,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemEventType {
    ModuleStarted,
    ModuleStopped,
    ModuleRestarted,
    ConfigurationChanged,
    ResourceExhaustion,
    HeartbeatMissed,
    HealthCheckFailed,
    WorkerSpawned,
    WorkerTerminated,
    ProcessingStarted,
    ProcessingCompleted,
    Error,
    Warning,
    Information,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_module: String,
    pub event_type: SecurityEventType,
    pub threat_level: ThreatLevel,
    pub details: String,
    pub affected_resources: Vec<String>,
    pub response_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    CredentialDetected,
    ThreatDetected,
    SecurityViolation,
    AnomalousActivity,
    AccessAttempt,
    AuthenticationFailure,
    PrivilegeEscalation,
    DataExfiltration,
    IntrusionAttempt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEvent {
    pub event_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_module: String,
    pub metric_name: String,
    pub metric_value: f64,
    pub unit: String,
    pub operation_type: String,
    pub duration_ms: Option<u64>,
    pub throughput_per_sec: Option<f64>,
    pub memory_usage_mb: Option<f64>,
    pub cpu_usage_percent: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub event_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_module: String,
    pub detection_type: DetectionType,
    pub confidence_score: f64,
    pub location: String,
    pub credential_type: Option<String>,
    pub risk_level: RiskLevel,
    pub validation_status: ValidationStatus,
    pub remediation_suggested: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionType {
    CredentialFound,
    HighEntropy,
    SuspiciousPattern,
    PolicyViolation,
    FalsePositive,
    Validated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSeverity {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
    Imminent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationStatus {
    Pending,
    Validated,
    Invalid,
    Expired,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleCommand {
    pub command_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_module: String,
    pub target_module: String,
    pub command_type: CommandType,
    pub parameters: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub response_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandType {
    Start,
    Stop,
    Restart,
    Configure,
    Scan,
    Pause,
    Resume,
    GetStatus,
    GetMetrics,
    UpdateConfig,
    ClearCache,
    ForceGC,
    EnterStealthMode,
    ExitStealthMode,
    SelfDestruct,
}

#[derive(Debug, Clone)]
struct EventTrace {
    event_id: Uuid,
    timestamp: Instant,
    event_type: String,
    source_module: String,
    processing_time_ns: u64,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Default)]
struct EventStatistics {
    total_events: u64,
    events_by_type: HashMap<String, u64>,
    events_by_module: HashMap<String, u64>,
    events_by_severity: HashMap<String, u64>,
    avg_processing_time_ns: u64,
    max_processing_time_ns: u64,
    error_count: u64,
    last_reset: Instant,
}

impl EngineEventBus {
    pub fn new() -> Self {
        let (system_tx, _) = broadcast::channel(10000);
        let (security_tx, _) = broadcast::channel(5000);
        let (performance_tx, _) = broadcast::channel(15000);
        let (detection_tx, _) = broadcast::channel(20000);
        
        Self {
            system_events: system_tx,
            security_events: security_tx,
            performance_events: performance_tx,
            detection_events: detection_tx,
            module_commands: Arc::new(RwLock::new(HashMap::new())),
            event_stats: Arc::new(RwLock::new(EventStatistics::default())),
            event_trace: Arc::new(RwLock::new(Vec::new())),
            max_trace_size: 10000,
        }
    }
    
    /// Publish system event
    pub async fn publish_system_event(&self, event: SystemEvent) -> Result<(), Box<dyn std::error::Error>> {
        let start = Instant::now();
        
        // Add to trace
        self.add_to_trace(&event.event_id, "SystemEvent", &event.source_module, start).await;
        
        // Publish event
        let _ = self.system_events.send(event.clone());
        
        // Update statistics
        self.update_stats("SystemEvent", &event.source_module, event.severity.clone(), start).await;
        
        // Log based on severity
        match event.severity {
            EventSeverity::Emergency | EventSeverity::Critical => {
                tracing::error!("SYSTEM EVENT: {} - {}", event.event_type, event.message);
            },
            EventSeverity::Error => {
                tracing::error!("System event: {} - {}", event.event_type, event.message);
            },
            EventSeverity::Warning => {
                tracing::warn!("System event: {} - {}", event.event_type, event.message);
            },
            _ => {
                tracing::info!("System event: {} - {}", event.event_type, event.message);
            },
        }
        
        Ok(())
    }
    
    /// Publish security event
    pub async fn publish_security_event(&self, event: SecurityEvent) -> Result<(), Box<dyn std::error::Error>> {
        let start = Instant::now();
        
        self.add_to_trace(&event.event_id, "SecurityEvent", &event.source_module, start).await;
        let _ = self.security_events.send(event.clone());
        
        // Security events are always important
        tracing::warn!("SECURITY EVENT: {:?} - {} (Threat: {:?})", 
                      event.event_type, event.details, event.threat_level);
        
        // Update statistics
        let severity = match event.threat_level {
            ThreatLevel::Critical | ThreatLevel::Imminent => EventSeverity::Critical,
            ThreatLevel::High => EventSeverity::Error,
            ThreatLevel::Medium => EventSeverity::Warning,
            _ => EventSeverity::Info,
        };
        
        self.update_stats("SecurityEvent", &event.source_module, severity, start).await;
        
        Ok(())
    }
    
    /// Publish performance event
    pub async fn publish_performance_event(&self, event: PerformanceEvent) -> Result<(), Box<dyn std::error::Error>> {
        let start = Instant::now();
        
        self.add_to_trace(&event.event_id, "PerformanceEvent", &event.source_module, start).await;
        let _ = self.performance_events.send(event.clone());
        
        tracing::debug!("Performance: {} = {} {} ({})", 
                       event.metric_name, event.metric_value, event.unit, event.source_module);
        
        self.update_stats("PerformanceEvent", &event.source_module, EventSeverity::Debug, start).await;
        
        Ok(())
    }
    
    /// Publish detection event
    pub async fn publish_detection_event(&self, event: DetectionEvent) -> Result<(), Box<dyn std::error::Error>> {
        let start = Instant::now();
        
        self.add_to_trace(&event.event_id, "DetectionEvent", &event.source_module, start).await;
        let _ = self.detection_events.send(event.clone());
        
        let severity = match event.risk_level {
            RiskLevel::Critical | RiskLevel::VeryHigh => EventSeverity::Critical,
            RiskLevel::High => EventSeverity::Error,
            RiskLevel::Medium => EventSeverity::Warning,
            _ => EventSeverity::Info,
        };
        
        tracing::info!("DETECTION: {:?} at {} (confidence: {:.2}, risk: {:?})", 
                      event.detection_type, event.location, event.confidence_score, event.risk_level);
        
        self.update_stats("DetectionEvent", &event.source_module, severity, start).await;
        
        Ok(())
    }
    
    /// Subscribe to system events
    pub fn subscribe_system_events(&self) -> broadcast::Receiver<SystemEvent> {
        self.system_events.subscribe()
    }
    
    /// Subscribe to security events
    pub fn subscribe_security_events(&self) -> broadcast::Receiver<SecurityEvent> {
        self.security_events.subscribe()
    }
    
    /// Subscribe to performance events
    pub fn subscribe_performance_events(&self) -> broadcast::Receiver<PerformanceEvent> {
        self.performance_events.subscribe()
    }
    
    /// Subscribe to detection events
    pub fn subscribe_detection_events(&self) -> broadcast::Receiver<DetectionEvent> {
        self.detection_events.subscribe()
    }
    
    /// Register module for command handling
    pub async fn register_module(&self, module_name: String, command_receiver: mpsc::Sender<ModuleCommand>) {
        let mut modules = self.module_commands.write().await;
        modules.insert(module_name.clone(), command_receiver);
        
        let event = SystemEvent {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            source_module: "event_bus".to_string(),
            event_type: SystemEventType::ModuleStarted,
            severity: EventSeverity::Info,
            message: format!("Module {} registered for command handling", module_name),
            metadata: HashMap::new(),
        };
        
        let _ = self.publish_system_event(event).await;
    }
    
    /// Send command to module
    pub async fn send_module_command(&self, command: ModuleCommand) -> Result<(), Box<dyn std::error::Error>> {
        let modules = self.module_commands.read().await;
        
        if let Some(sender) = modules.get(&command.target_module) {
            sender.send(command.clone()).await?;
            
            tracing::debug!("Command {:?} sent to module {}", command.command_type, command.target_module);
        } else {
            tracing::error!("Module {} not registered for commands", command.target_module);
            return Err(format!("Module {} not found", command.target_module).into());
        }
        
        Ok(())
    }
    
    /// Get event statistics
    pub async fn get_statistics(&self) -> EventStatistics {
        self.event_stats.read().await.clone()
    }
    
    /// Get recent event trace
    pub async fn get_event_trace(&self, limit: Option<usize>) -> Vec<EventTrace> {
        let trace = self.event_trace.read().await;
        let limit = limit.unwrap_or(100).min(trace.len());
        
        trace.iter().rev().take(limit).cloned().collect()
    }
    
    /// Clear event statistics
    pub async fn clear_statistics(&self) {
        let mut stats = self.event_stats.write().await;
        *stats = EventStatistics::default();
        stats.last_reset = Instant::now();
    }
    
    /// Add event to trace for debugging
    async fn add_to_trace(&self, event_id: &Uuid, event_type: &str, source_module: &str, start_time: Instant) {
        let mut trace = self.event_trace.write().await;
        
        // Remove old entries if at capacity
        if trace.len() >= self.max_trace_size {
            trace.remove(0);
        }
        
        trace.push(EventTrace {
            event_id: *event_id,
            timestamp: start_time,
            event_type: event_type.to_string(),
            source_module: source_module.to_string(),
            processing_time_ns: start_time.elapsed().as_nanos() as u64,
            metadata: HashMap::new(),
        });
    }
    
    /// Update event statistics
    async fn update_stats(&self, event_type: &str, source_module: &str, severity: EventSeverity, start_time: Instant) {
        let mut stats = self.event_stats.write().await;
        
        stats.total_events += 1;
        
        *stats.events_by_type.entry(event_type.to_string()).or_insert(0) += 1;
        *stats.events_by_module.entry(source_module.to_string()).or_insert(0) += 1;
        *stats.events_by_severity.entry(format!("{:?}", severity)).or_insert(0) += 1;
        
        if matches!(severity, EventSeverity::Error | EventSeverity::Critical | EventSeverity::Emergency) {
            stats.error_count += 1;
        }
        
        let processing_time = start_time.elapsed().as_nanos() as u64;
        stats.avg_processing_time_ns = (stats.avg_processing_time_ns + processing_time) / 2;
        
        if processing_time > stats.max_processing_time_ns {
            stats.max_processing_time_ns = processing_time;
        }
    }
    
    /// Start background health monitoring
    pub async fn start_health_monitoring(&self) {
        let event_bus = self.clone_for_monitoring();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                event_bus.perform_health_check().await;
            }
        });
    }
    
    /// Perform health check
    async fn perform_health_check(&self) {
        let stats = self.get_statistics().await;
        
        // Check for high error rates
        let error_rate = if stats.total_events > 0 {
            (stats.error_count as f64 / stats.total_events as f64) * 100.0
        } else {
            0.0
        };
        
        if error_rate > 10.0 {
            let event = SystemEvent {
                event_id: Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                source_module: "event_bus".to_string(),
                event_type: SystemEventType::HealthCheckFailed,
                severity: EventSeverity::Warning,
                message: format!("High error rate detected: {:.1}%", error_rate),
                metadata: HashMap::new(),
            };
            
            let _ = self.publish_system_event(event).await;
        }
        
        // Check for slow processing
        if stats.avg_processing_time_ns > 10_000_000 { // 10ms
            let event = SystemEvent {
                event_id: Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                source_module: "event_bus".to_string(),
                event_type: SystemEventType::Warning,
                severity: EventSeverity::Warning,
                message: format!("Slow event processing detected: {:.2}ms average", 
                               stats.avg_processing_time_ns as f64 / 1_000_000.0),
                metadata: HashMap::new(),
            };
            
            let _ = self.publish_system_event(event).await;
        }
    }
    
    /// Clone for monitoring thread
    fn clone_for_monitoring(&self) -> Self {
        Self {
            system_events: self.system_events.clone(),
            security_events: self.security_events.clone(),
            performance_events: self.performance_events.clone(),
            detection_events: self.detection_events.clone(),
            module_commands: self.module_commands.clone(),
            event_stats: self.event_stats.clone(),
            event_trace: self.event_trace.clone(),
            max_trace_size: self.max_trace_size,
        }
    }
}

/// Convenience functions for event creation
impl SystemEvent {
    pub fn new(source_module: &str, event_type: SystemEventType, severity: EventSeverity, message: &str) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            source_module: source_module.to_string(),
            event_type,
            severity,
            message: message.to_string(),
            metadata: HashMap::new(),
        }
    }
}

impl PerformanceEvent {
    pub fn new(source_module: &str, metric_name: &str, metric_value: f64, unit: &str) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            source_module: source_module.to_string(),
            metric_name: metric_name.to_string(),
            metric_value,
            unit: unit.to_string(),
            operation_type: "unknown".to_string(),
            duration_ms: None,
            throughput_per_sec: None,
            memory_usage_mb: None,
            cpu_usage_percent: None,
        }
    }
}

impl ModuleCommand {
    pub fn new(source_module: &str, target_module: &str, command_type: CommandType) -> Self {
        Self {
            command_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            source_module: source_module.to_string(),
            target_module: target_module.to_string(),
            command_type,
            parameters: HashMap::new(),
            timeout_ms: None,
            response_channel: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_event_bus_creation() {
        let bus = EngineEventBus::new();
        let stats = bus.get_statistics().await;
        assert_eq!(stats.total_events, 0);
    }
    
    #[tokio::test]
    async fn test_system_event_publishing() {
        let bus = EngineEventBus::new();
        let mut receiver = bus.subscribe_system_events();
        
        let event = SystemEvent::new("test_module", SystemEventType::Information, EventSeverity::Info, "Test message");
        
        let _ = bus.publish_system_event(event.clone()).await;
        
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.source_module, "test_module");
        assert_eq!(received.message, "Test message");
    }
    
    #[tokio::test]
    async fn test_module_commands() {
        let bus = EngineEventBus::new();
        let (tx, mut rx) = mpsc::channel(100);
        
        bus.register_module("test_module".to_string(), tx).await;
        
        let command = ModuleCommand::new("controller", "test_module", CommandType::GetStatus);
        
        let result = bus.send_module_command(command.clone()).await;
        assert!(result.is_ok());
        
        let received = rx.recv().await.unwrap();
        assert_eq!(received.target_module, "test_module");
        assert!(matches!(received.command_type, CommandType::GetStatus));
    }
    
    #[tokio::test]
    async fn test_event_statistics() {
        let bus = EngineEventBus::new();
        
        // Publish some events
        for i in 0..5 {
            let event = SystemEvent::new("test", SystemEventType::Information, EventSeverity::Info, &format!("Test {}", i));
            let _ = bus.publish_system_event(event).await;
        }
        
        let stats = bus.get_statistics().await;
        assert_eq!(stats.total_events, 5);
        assert_eq!(stats.events_by_module.get("test"), Some(&5));
    }
}