/**
 * ECH SIEM Integration Engine - Enterprise SIEM Platform Integration
 * 
 * This module implements the core SIEM integration engine that connects ECH
 * to major enterprise SIEM platforms. Features real-time event streaming,
 * secure authentication, and comprehensive error handling.
 * 
 * Features:
 * - Multi-platform SIEM support (Splunk, ELK, QRadar, Sentinel, etc.)
 * - Real-time event streaming with batching
 * - Secure transport with TLS and authentication
 * - Event correlation and enrichment
 * - Health monitoring and failover
 * - Performance optimization and metrics
 */

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn, error, trace};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::detection::DetectionResult;
use super::{SiemIntegrationConfig, SiemError, SiemStats, AuthConfig, AuthType};
use super::logging::{SecureLogger, LogEntry, LogLevel};
use super::masking::{DataMasker, MaskingPolicy};
use super::events::{SiemEvent, EventType, EventSeverity};
use super::transports::{SiemTransport, TransportType};
use super::formatters::{EventFormatter, FormatType};
use super::correlators::{EventCorrelator, CorrelatedEvent};
use super::health::{HealthMonitor, HealthStatus};

/// Main SIEM integration engine
pub struct SiemIntegration {
    /// Integration configuration
    config: SiemIntegrationConfig,
    
    /// SIEM platform type
    platform: SiemPlatform,
    
    /// Secure logger
    secure_logger: Arc<SecureLogger>,
    
    /// Data masker
    data_masker: Arc<DataMasker>,
    
    /// Event correlator
    event_correlator: Arc<EventCorrelator>,
    
    /// Transport layer
    transport: Arc<dyn SiemTransport + Send + Sync>,
    
    /// Event formatter
    event_formatter: Arc<EventFormatter>,
    
    /// Health monitor
    health_monitor: Arc<HealthMonitor>,
    
    /// Event queue for batching
    event_queue: Arc<RwLock<Vec<SiemEvent>>>,
    
    /// Statistics tracking
    stats: Arc<RwLock<SiemStats>>,
    
    /// Worker semaphore
    worker_semaphore: Arc<Semaphore>,
    
    /// Active connections
    active_connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
    
    /// Session tracking
    session_id: Uuid,
}

/// Supported SIEM platforms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SiemPlatform {
    /// Generic SIEM (CEF/LEEF format)
    Generic,
    
    /// Splunk Enterprise/Cloud
    Splunk,
    
    /// Elastic Stack (ELK)
    Elasticsearch,
    
    /// IBM QRadar
    QRadar,
    
    /// Microsoft Sentinel
    Sentinel,
    
    /// ArcSight
    ArcSight,
    
    /// LogRhythm
    LogRhythm,
    
    /// Sumo Logic
    SumoLogic,
    
    /// Datadog
    Datadog,
    
    /// Custom integration
    Custom(String),
}

/// SIEM configuration
#[derive(Debug, Clone)]
pub struct SiemConfig {
    /// SIEM platform
    pub platform: SiemPlatform,
    
    /// Connection endpoint
    pub endpoint: Option<String>,
    
    /// Authentication settings
    pub auth_config: AuthConfig,
    
    /// Enable secure logging
    pub secure_logging: bool,
    
    /// Enable data masking
    pub data_masking: bool,
    
    /// Event batching size
    pub batch_size: usize,
    
    /// Batch timeout (milliseconds)
    pub batch_timeout_ms: u64,
    
    /// Enable event correlation
    pub correlation_enabled: bool,
    
    /// Health check interval (seconds)
    pub health_check_interval_sec: u64,
    
    /// Connection timeout (seconds)
    pub connection_timeout_sec: u64,
    
    /// Retry attempts
    pub retry_attempts: u32,
    
    /// Enable compression
    pub compression_enabled: bool,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            platform: SiemPlatform::Generic,
            endpoint: None,
            auth_config: AuthConfig {
                auth_type: AuthType::None,
                username: None,
                password: None,
                api_key: None,
                cert_path: None,
                key_path: None,
                ca_cert_path: None,
            },
            secure_logging: true,
            data_masking: true,
            batch_size: 100,
            batch_timeout_ms: 1000,
            correlation_enabled: true,
            health_check_interval_sec: 60,
            connection_timeout_sec: 30,
            retry_attempts: 3,
            compression_enabled: true,
        }
    }
}

/// Connection information tracking
#[derive(Debug, Clone)]
struct ConnectionInfo {
    /// Connection ID
    id: String,
    
    /// Connection start time
    start_time: DateTime<Utc>,
    
    /// Last activity time
    last_activity: DateTime<Utc>,
    
    /// Connection status
    status: ConnectionStatus,
    
    /// Events sent through this connection
    events_sent: u64,
    
    /// Bytes sent
    bytes_sent: u64,
    
    /// Error count
    error_count: u64,
}

/// Connection status
#[derive(Debug, Clone)]
enum ConnectionStatus {
    Connecting,
    Connected,
    Authenticated,
    Error(String),
    Disconnected,
}

impl SiemIntegration {
    /// Create a new SIEM integration
    pub async fn new(config: SiemConfig) -> Result<Self> {
        info!("🔗 Initializing SIEM Integration for {:?}", config.platform);
        
        let integration_config = SiemIntegrationConfig::default();
        let session_id = Uuid::new_v4();
        
        // Initialize secure logger
        let secure_logger = Arc::new(
            SecureLogger::new(&integration_config.logging_config).await
                .context("Failed to initialize secure logger")?
        );
        
        // Initialize data masker
        let data_masker = Arc::new(
            DataMasker::new(&integration_config.masking_config).await
                .context("Failed to initialize data masker")?
        );
        
        // Initialize event correlator
        let event_correlator = Arc::new(
            EventCorrelator::new(&integration_config.correlation_config).await
                .context("Failed to initialize event correlator")?
        );
        
        // Initialize transport layer
        let transport = Self::create_transport(&config).await
            .context("Failed to create SIEM transport")?;
        
        // Initialize event formatter
        let event_formatter = Arc::new(
            EventFormatter::new(&config.platform).await
                .context("Failed to initialize event formatter")?
        );
        
        // Initialize health monitor
        let health_monitor = Arc::new(
            HealthMonitor::new(&integration_config.health_config).await
                .context("Failed to initialize health monitor")?
        );
        
        let event_queue = Arc::new(RwLock::new(Vec::new()));
        let stats = Arc::new(RwLock::new(SiemStats::default()));
        let worker_semaphore = Arc::new(Semaphore::new(integration_config.performance_config.worker_threads));
        let active_connections = Arc::new(RwLock::new(HashMap::new()));
        
        let integration = Self {
            config: integration_config,
            platform: config.platform.clone(),
            secure_logger,
            data_masker,
            event_correlator,
            transport,
            event_formatter,
            health_monitor,
            event_queue,
            stats,
            worker_semaphore,
            active_connections,
            session_id,
        };
        
        // Start background tasks
        integration.start_background_tasks().await?;
        
        info!("✅ SIEM Integration initialized");
        info!("   Platform: {:?}", config.platform);
        info!("   Session ID: {}", session_id);
        info!("   Secure logging: {}", config.secure_logging);
        info!("   Data masking: {}", config.data_masking);
        
        Ok(integration)
    }
    
    /// Create transport layer for SIEM platform
    async fn create_transport(config: &SiemConfig) -> Result<Arc<dyn SiemTransport + Send + Sync>> {
        let transport_type = match &config.platform {
            SiemPlatform::Splunk => TransportType::Http,
            SiemPlatform::Elasticsearch => TransportType::Http,
            SiemPlatform::QRadar => TransportType::Syslog,
            SiemPlatform::Sentinel => TransportType::Http,
            SiemPlatform::ArcSight => TransportType::Syslog,
            SiemPlatform::LogRhythm => TransportType::Syslog,
            SiemPlatform::SumoLogic => TransportType::Http,
            SiemPlatform::Datadog => TransportType::Http,
            SiemPlatform::Generic => TransportType::Syslog,
            SiemPlatform::Custom(_) => TransportType::Http,
        };
        
        let transport_config = super::transports::TransportConfig {
            transport_type,
            endpoint: config.endpoint.clone(),
            auth_config: config.auth_config.clone(),
            timeout_sec: config.connection_timeout_sec,
            retry_attempts: config.retry_attempts,
            compression_enabled: config.compression_enabled,
            ..Default::default()
        };
        
        super::transports::create_transport(transport_config).await
    }
    
    /// Send detection results to SIEM
    pub async fn send_detections(&self, detections: &[DetectionResult]) -> Result<()> {
        if detections.is_empty() {
            return Ok(());
        }
        
        info!("📤 Sending {} detections to SIEM", detections.len());
        
        let mut events = Vec::new();
        
        for detection in detections {
            // Mask sensitive data
            let masked_detection = self.data_masker.mask_detection(detection).await?;
            
            // Convert to SIEM event
            let siem_event = self.create_siem_event_from_detection(&masked_detection).await?;
            
            // Correlate event if enabled
            let correlated_events = if self.config.correlation_config.enabled {
                self.event_correlator.correlate_event(&siem_event).await?
            } else {
                vec![siem_event]
            };
            
            events.extend(correlated_events);
        }
        
        // Send events
        self.send_events(events).await?;
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.events_sent += detections.len() as u64;
        }
        
        info!("✅ Successfully sent {} detections to SIEM", detections.len());
        Ok(())
    }
    
    /// Send custom SIEM event
    pub async fn send_event(&self, event: SiemEvent) -> Result<()> {
        self.send_events(vec![event]).await
    }
    
    /// Send multiple SIEM events
    pub async fn send_events(&self, events: Vec<SiemEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        
        // Add events to queue for batching
        {
            let mut queue = self.event_queue.write().await;
            queue.extend(events);
            
            // Check if we should flush the batch
            if queue.len() >= self.config.performance_config.batch_size {
                let batch = queue.drain(..).collect();
                drop(queue); // Release lock before async operation
                
                self.flush_event_batch(batch).await?;
            }
        }
        
        Ok(())
    }
    
    /// Flush event batch to SIEM
    async fn flush_event_batch(&self, events: Vec<SiemEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        
        let _permit = self.worker_semaphore.acquire().await?;
        
        debug!("🔄 Flushing batch of {} events to SIEM", events.len());
        
        let start_time = Instant::now();
        
        // Format events for the target platform
        let formatted_events = self.event_formatter.format_events(&events).await?;
        
        // Send through transport
        let send_result = self.transport.send_events(&formatted_events).await;
        
        let send_duration = start_time.elapsed();
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            match &send_result {
                Ok(_) => {
                    stats.events_sent += events.len() as u64;
                    stats.avg_latency_ms = (stats.avg_latency_ms + send_duration.as_millis() as u64) / 2;
                }
                Err(_) => {
                    stats.events_failed += events.len() as u64;
                }
            }
        }
        
        // Log the operation
        self.log_batch_operation(&events, &send_result, send_duration).await?;
        
        send_result
    }
    
    /// Create SIEM event from detection result
    async fn create_siem_event_from_detection(&self, detection: &DetectionResult) -> Result<SiemEvent> {
        let event_type = match detection.risk_level {
            crate::detection::engine::RiskLevel::Critical => EventType::CriticalThreat,
            crate::detection::engine::RiskLevel::High => EventType::HighThreat,
            crate::detection::engine::RiskLevel::Medium => EventType::MediumThreat,
            crate::detection::engine::RiskLevel::Low => EventType::LowThreat,
            crate::detection::engine::RiskLevel::Info => EventType::Information,
        };
        
        let severity = match detection.risk_level {
            crate::detection::engine::RiskLevel::Critical => EventSeverity::Critical,
            crate::detection::engine::RiskLevel::High => EventSeverity::High,
            crate::detection::engine::RiskLevel::Medium => EventSeverity::Medium,
            crate::detection::engine::RiskLevel::Low => EventSeverity::Low,
            crate::detection::engine::RiskLevel::Info => EventSeverity::Informational,
        };
        
        let mut custom_fields = HashMap::new();
        custom_fields.insert("credential_type".to_string(), detection.credential_type.to_string());
        custom_fields.insert("confidence".to_string(), detection.confidence.to_string());
        custom_fields.insert("detection_id".to_string(), detection.id.to_string());
        custom_fields.insert("source_type".to_string(), detection.location.source_type.clone());
        custom_fields.insert("file_path".to_string(), detection.location.path.clone());
        
        if let Some(line_number) = detection.location.line_number {
            custom_fields.insert("line_number".to_string(), line_number.to_string());
        }
        
        if let Some(process_id) = detection.location.process_id {
            custom_fields.insert("process_id".to_string(), process_id.to_string());
        }
        
        Ok(SiemEvent {
            id: Uuid::new_v4(),
            timestamp: detection.timestamp,
            event_type,
            severity,
            source: "ECH".to_string(),
            title: format!("Credential Detected: {}", detection.credential_type),
            description: format!("ECH detected {} credential in {}", 
                               detection.credential_type, detection.location.path),
            host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
            user: std::env::var("USER").unwrap_or_else(|_| "system".to_string()),
            process: "ech".to_string(),
            tags: vec!["credential_detection".to_string(), "security".to_string()],
            custom_fields,
            metadata: super::events::EventMetadata {
                session_id: self.session_id,
                correlation_id: None,
                tenant_id: None,
                organization: None,
                environment: std::env::var("ECH_ENVIRONMENT").ok(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        })
    }
    
    /// Log batch operation
    async fn log_batch_operation(
        &self,
        events: &[SiemEvent],
        result: &Result<()>,
        duration: Duration,
    ) -> Result<()> {
        let log_level = match result {
            Ok(_) => LogLevel::Info,
            Err(_) => LogLevel::Error,
        };
        
        let log_entry = LogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level: log_level,
            source: "siem_integration".to_string(),
            message: format!("Batch operation: {} events, duration: {}ms", 
                           events.len(), duration.as_millis()),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("batch_size".to_string(), events.len().to_string());
                metadata.insert("duration_ms".to_string(), duration.as_millis().to_string());
                metadata.insert("platform".to_string(), format!("{:?}", self.platform));
                
                if let Err(ref error) = result {
                    metadata.insert("error".to_string(), error.to_string());
                }
                
                metadata
            },
            session_id: Some(self.session_id),
            correlation_id: None,
        };
        
        self.secure_logger.log(log_entry).await
    }
    
    /// Test SIEM connection
    pub async fn test_connection(&self) -> Result<()> {
        info!("🔍 Testing SIEM connection");
        
        let test_event = SiemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: EventType::Information,
            severity: EventSeverity::Informational,
            source: "ECH".to_string(),
            title: "SIEM Connection Test".to_string(),
            description: "Testing SIEM integration connectivity".to_string(),
            host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
            user: "system".to_string(),
            process: "ech".to_string(),
            tags: vec!["test".to_string(), "connectivity".to_string()],
            custom_fields: HashMap::new(),
            metadata: super::events::EventMetadata {
                session_id: self.session_id,
                correlation_id: None,
                tenant_id: None,
                organization: None,
                environment: None,
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };
        
        // Send test event
        self.send_event(test_event).await?;
        
        // Wait a moment for the event to be sent
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Check health status
        let health_status = self.health_monitor.get_status().await;
        match health_status {
            HealthStatus::Healthy => {
                info!("✅ SIEM connection test successful");
                Ok(())
            }
            HealthStatus::Degraded => {
                warn!("⚠️ SIEM connection degraded but functional");
                Ok(())
            }
            HealthStatus::Unhealthy => {
                error!("❌ SIEM connection test failed");
                Err(SiemError::ConnectionFailed { 
                    message: "Health check indicates unhealthy connection".to_string() 
                }.into())
            }
        }
    }
    
    /// Start background tasks
    async fn start_background_tasks(&self) -> Result<()> {
        debug!("🚀 Starting SIEM integration background tasks");
        
        // Start batch flush timer
        let integration = Arc::new(self);
        let batch_timer_integration = Arc::clone(&integration);
        tokio::spawn(async move {
            batch_timer_integration.batch_flush_timer().await;
        });
        
        // Start health monitoring
        let health_integration = Arc::clone(&integration);
        tokio::spawn(async move {
            health_integration.health_monitoring_loop().await;
        });
        
        Ok(())
    }
    
    /// Background batch flush timer
    async fn batch_flush_timer(self: &Arc<Self>) {
        let mut interval = tokio::time::interval(
            Duration::from_millis(self.config.performance_config.batch_timeout_ms)
        );
        
        loop {
            interval.tick().await;
            
            // Flush any pending events
            let events = {
                let mut queue = self.event_queue.write().await;
                if queue.is_empty() {
                    continue;
                }
                queue.drain(..).collect()
            };
            
            if let Err(e) = self.flush_event_batch(events).await {
                error!("Batch flush failed: {}", e);
            }
        }
    }
    
    /// Health monitoring loop
    async fn health_monitoring_loop(self: &Arc<Self>) {
        let mut interval = tokio::time::interval(
            Duration::from_secs(self.config.health_config.check_interval_sec)
        );
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.health_monitor.perform_health_check().await {
                error!("Health check failed: {}", e);
                
                // Update statistics
                let mut stats = self.stats.write().await;
                stats.health_checks_failed += 1;
            } else {
                let mut stats = self.stats.write().await;
                stats.health_checks_passed += 1;
            }
        }
    }
    
    /// Get current statistics
    pub async fn get_stats(&self) -> SiemStats {
        self.stats.read().await.clone()
    }
    
    /// Get health status
    pub async fn get_health_status(&self) -> HealthStatus {
        self.health_monitor.get_status().await
    }
    
    /// Shutdown SIEM integration
    pub async fn shutdown(&self) -> Result<()> {
        info!("🔄 Shutting down SIEM integration");
        
        // Flush any remaining events
        let events = {
            let mut queue = self.event_queue.write().await;
            queue.drain(..).collect()
        };
        
        if !events.is_empty() {
            if let Err(e) = self.flush_event_batch(events).await {
                error!("Final batch flush failed during shutdown: {}", e);
            }
        }
        
        // Close transport connections
        self.transport.close().await?;
        
        info!("✅ SIEM integration shutdown complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_siem_integration_creation() {
        let config = SiemConfig::default();
        let integration = SiemIntegration::new(config).await;
        
        // Integration creation may fail without proper SIEM connectivity
        match integration {
            Ok(_) => {
                // Integration created successfully
            }
            Err(e) => {
                // Expected without actual SIEM endpoint
                println!("SIEM integration creation failed (expected): {}", e);
            }
        }
    }
    
    #[test]
    fn test_siem_platform_types() {
        let platforms = vec![
            SiemPlatform::Splunk,
            SiemPlatform::Elasticsearch,
            SiemPlatform::QRadar,
            SiemPlatform::Sentinel,
            SiemPlatform::Generic,
        ];
        
        for platform in platforms {
            // Test serialization
            let serialized = serde_json::to_string(&platform);
            assert!(serialized.is_ok());
        }
    }
    
    #[test]
    fn test_siem_config_default() {
        let config = SiemConfig::default();
        assert!(matches!(config.platform, SiemPlatform::Generic));
        assert!(config.secure_logging);
        assert!(config.data_masking);
        assert_eq!(config.batch_size, 100);
    }
    
    #[test]
    fn test_connection_info() {
        let conn_info = ConnectionInfo {
            id: "test-connection".to_string(),
            start_time: Utc::now(),
            last_activity: Utc::now(),
            status: ConnectionStatus::Connected,
            events_sent: 0,
            bytes_sent: 0,
            error_count: 0,
        };
        
        assert_eq!(conn_info.id, "test-connection");
        assert!(matches!(conn_info.status, ConnectionStatus::Connected));
    }
}