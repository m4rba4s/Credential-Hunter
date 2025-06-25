/**
 * Self-Healing & Adaptive Defense System for ECH
 * 
 * CrowdStrike-level adaptive defense mechanisms:
 * - Automatic threat response escalation
 * - Self-healing module recovery
 * - Adaptive configuration under attack
 * - Performance-based auto-scaling
 */

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock, Mutex};
use serde::{Serialize, Deserialize};

use super::{SecurityIncident, SecuritySeverity, ThreatLevel, SecurityAction};
use crate::engine::event_bus::{EngineEventBus, SystemEvent, SystemEventType, EventSeverity};

/// Adaptive defense system that responds to threats and system health
pub struct SelfHealingSystem {
    // Current system state
    threat_level: Arc<RwLock<ThreatLevel>>,
    defense_mode: Arc<RwLock<DefenseMode>>,
    system_health: Arc<RwLock<SystemHealth>>,
    
    // Configuration adaptation
    adaptive_config: Arc<RwLock<AdaptiveConfig>>,
    original_config: Arc<RwLock<AdaptiveConfig>>,
    
    // Module recovery tracking
    module_health: Arc<RwLock<HashMap<String, ModuleHealth>>>,
    recovery_attempts: Arc<RwLock<HashMap<String, usize>>>,
    
    // Performance monitoring
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,
    auto_scaling: Arc<Mutex<AutoScalingEngine>>,
    
    // Event bus for coordination
    event_bus: Arc<EngineEventBus>,
    
    // Control flags
    healing_enabled: AtomicBool,
    adaptation_enabled: AtomicBool,
    escalation_count: AtomicUsize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DefenseMode {
    Normal,
    Heightened,
    Defensive,
    Stealth,
    Lockdown,
    Emergency,
}

#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub overall_score: f64,        // 0.0 to 1.0
    pub cpu_health: f64,
    pub memory_health: f64,
    pub network_health: f64,
    pub disk_health: f64,
    pub error_rate: f64,
    pub response_time_ms: f64,
    pub last_assessment: Instant,
}

#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    pub scanning_interval_ms: u64,
    pub thread_pool_size: usize,
    pub memory_limit_mb: usize,
    pub network_timeout_ms: u64,
    pub stealth_level: u8,           // 0-10
    pub logging_level: String,
    pub siem_reporting: bool,
    pub aggressive_detection: bool,
    pub anti_tamper_level: u8,       // 0-10
}

#[derive(Debug, Clone)]
pub struct ModuleHealth {
    pub name: String,
    pub status: ModuleStatus,
    pub last_heartbeat: Instant,
    pub error_count: usize,
    pub restart_count: usize,
    pub performance_score: f64,
    pub critical: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ModuleStatus {
    Healthy,
    Degraded,
    Critical,
    Failed,
    Recovering,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub disk_io_ops_per_sec: u64,
    pub network_bytes_per_sec: u64,
    pub active_connections: u32,
    pub pending_tasks: usize,
    pub avg_response_time_ms: f64,
    pub error_rate_percent: f64,
}

pub struct AutoScalingEngine {
    target_cpu_percent: f32,
    target_memory_percent: f32,
    scale_up_threshold: f32,
    scale_down_threshold: f32,
    min_workers: usize,
    max_workers: usize,
    current_workers: usize,
    last_scale_action: Instant,
    cooldown_duration: Duration,
}

impl SelfHealingSystem {
    pub fn new(event_bus: Arc<EngineEventBus>) -> Self {
        Self {
            threat_level: Arc::new(RwLock::new(ThreatLevel::None)),
            defense_mode: Arc::new(RwLock::new(DefenseMode::Normal)),
            system_health: Arc::new(RwLock::new(SystemHealth::default())),
            adaptive_config: Arc::new(RwLock::new(AdaptiveConfig::default())),
            original_config: Arc::new(RwLock::new(AdaptiveConfig::default())),
            module_health: Arc::new(RwLock::new(HashMap::new())),
            recovery_attempts: Arc::new(RwLock::new(HashMap::new())),
            performance_metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            auto_scaling: Arc::new(Mutex::new(AutoScalingEngine::new())),
            event_bus,
            healing_enabled: AtomicBool::new(true),
            adaptation_enabled: AtomicBool::new(true),
            escalation_count: AtomicUsize::new(0),
        }
    }
    
    /// Start the self-healing monitoring system
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.healing_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        tracing::info!("Starting self-healing system monitoring");
        
        // Save original configuration
        {
            let current_config = self.adaptive_config.read().await.clone();
            *self.original_config.write().await = current_config;
        }
        
        // Start monitoring tasks
        self.start_health_monitoring().await;
        self.start_threat_monitoring().await;
        self.start_performance_monitoring().await;
        self.start_module_monitoring().await;
        self.start_auto_scaling().await;
        
        Ok(())
    }
    
    /// Start health monitoring loop
    async fn start_health_monitoring(&self) {
        let system = self.clone_for_task();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                system.assess_system_health().await;
                system.apply_health_based_adaptations().await;
            }
        });
    }
    
    /// Start threat monitoring loop
    async fn start_threat_monitoring(&self) {
        let system = self.clone_for_task();
        let mut security_receiver = self.event_bus.subscribe_security_events();
        
        tokio::spawn(async move {
            while let Ok(incident) = security_receiver.recv().await {
                system.handle_security_incident(incident).await;
            }
        });
    }
    
    /// Start performance monitoring loop
    async fn start_performance_monitoring(&self) {
        let system = self.clone_for_task();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                system.collect_performance_metrics().await;
                system.apply_performance_adaptations().await;
            }
        });
    }
    
    /// Start module monitoring loop
    async fn start_module_monitoring(&self) {
        let system = self.clone_for_task();
        let mut system_receiver = self.event_bus.subscribe_system_events();
        
        tokio::spawn(async move {
            while let Ok(event) = system_receiver.recv().await {
                system.handle_system_event(event).await;
            }
        });
    }
    
    /// Start auto-scaling monitoring
    async fn start_auto_scaling(&self) {
        let system = self.clone_for_task();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                system.auto_scale_resources().await;
            }
        });
    }
    
    /// Handle security incident with adaptive response
    async fn handle_security_incident(&self, incident: crate::engine::event_bus::SecurityEvent) {
        if !self.adaptation_enabled.load(Ordering::SeqCst) {
            return;
        }
        
        tracing::warn!("Self-healing system handling security incident: {:?}", incident.event_type);
        
        // Update threat level
        self.update_threat_level(incident.threat_level.clone()).await;
        
        // Escalate defense mode based on incident severity
        match incident.threat_level {
            ThreatLevel::Critical | ThreatLevel::Imminent => {
                self.escalate_defense_mode(DefenseMode::Emergency).await;
                self.apply_emergency_measures().await;
            },
            ThreatLevel::High => {
                self.escalate_defense_mode(DefenseMode::Defensive).await;
                self.apply_defensive_measures().await;
            },
            ThreatLevel::Medium => {
                self.escalate_defense_mode(DefenseMode::Heightened).await;
                self.apply_heightened_measures().await;
            },
            _ => {},
        }
        
        // Track escalation frequency
        let escalation_count = self.escalation_count.fetch_add(1, Ordering::SeqCst) + 1;
        
        // If too many escalations, enter lockdown
        if escalation_count >= 5 {
            tracing::error!("Multiple security escalations detected, entering lockdown mode");
            self.escalate_defense_mode(DefenseMode::Lockdown).await;
            self.apply_lockdown_measures().await;
        }
    }
    
    /// Update threat level with adaptive thresholds
    async fn update_threat_level(&self, new_level: ThreatLevel) {
        let mut current_level = self.threat_level.write().await;
        
        // Only escalate threat level, not de-escalate immediately
        if Self::threat_level_priority(&new_level) > Self::threat_level_priority(&current_level) {
            *current_level = new_level;
            
            let event = SystemEvent::new(
                "self_healing",
                SystemEventType::Warning,
                EventSeverity::Warning,
                &format!("Threat level escalated to {:?}", current_level),
            );
            
            let _ = self.event_bus.publish_system_event(event).await;
        }
    }
    
    /// Get threat level priority for comparison
    fn threat_level_priority(level: &ThreatLevel) -> u8 {
        match level {
            ThreatLevel::None => 0,
            ThreatLevel::Low => 1,
            ThreatLevel::Medium => 2,
            ThreatLevel::High => 3,
            ThreatLevel::Critical => 4,
            ThreatLevel::Imminent => 5,
        }
    }
    
    /// Escalate defense mode
    async fn escalate_defense_mode(&self, new_mode: DefenseMode) {
        let mut current_mode = self.defense_mode.write().await;
        
        if Self::defense_mode_priority(&new_mode) > Self::defense_mode_priority(&current_mode) {
            tracing::warn!("Defense mode escalated from {:?} to {:?}", current_mode, new_mode);
            *current_mode = new_mode.clone();
            
            let event = SystemEvent::new(
                "self_healing",
                SystemEventType::Warning,
                EventSeverity::Warning,
                &format!("Defense mode escalated to {:?}", new_mode),
            );
            
            let _ = self.event_bus.publish_system_event(event).await;
        }
    }
    
    /// Get defense mode priority
    fn defense_mode_priority(mode: &DefenseMode) -> u8 {
        match mode {
            DefenseMode::Normal => 0,
            DefenseMode::Heightened => 1,
            DefenseMode::Defensive => 2,
            DefenseMode::Stealth => 3,
            DefenseMode::Lockdown => 4,
            DefenseMode::Emergency => 5,
        }
    }
    
    /// Apply emergency measures
    async fn apply_emergency_measures(&self) {
        tracing::error!("Applying emergency defense measures");
        
        let mut config = self.adaptive_config.write().await;
        
        // Aggressive anti-tamper
        config.anti_tamper_level = 10;
        config.stealth_level = 10;
        
        // Reduce attack surface
        config.network_timeout_ms = 1000;  // Very short timeouts
        config.siem_reporting = true;      // Maximum reporting
        config.aggressive_detection = true;
        config.logging_level = "ERROR".to_string(); // Minimal logging
        
        // Reduce resource usage
        config.thread_pool_size = config.thread_pool_size / 2;
        config.scanning_interval_ms *= 3; // Slower scanning to reduce footprint
    }
    
    /// Apply defensive measures
    async fn apply_defensive_measures(&self) {
        tracing::warn!("Applying defensive measures");
        
        let mut config = self.adaptive_config.write().await;
        
        config.anti_tamper_level = 8;
        config.stealth_level = 7;
        config.aggressive_detection = true;
        config.scanning_interval_ms = (config.scanning_interval_ms as f64 * 1.5) as u64;
        config.logging_level = "WARN".to_string();
    }
    
    /// Apply heightened measures
    async fn apply_heightened_measures(&self) {
        tracing::info!("Applying heightened security measures");
        
        let mut config = self.adaptive_config.write().await;
        
        config.anti_tamper_level = 6;
        config.stealth_level = 5;
        config.siem_reporting = true;
        config.aggressive_detection = true;
    }
    
    /// Apply lockdown measures
    async fn apply_lockdown_measures(&self) {
        tracing::error!("Applying system lockdown measures");
        
        let mut config = self.adaptive_config.write().await;
        
        // Maximum security
        config.anti_tamper_level = 10;
        config.stealth_level = 10;
        
        // Minimal operations
        config.thread_pool_size = 1;
        config.scanning_interval_ms *= 5;
        config.network_timeout_ms = 500;
        config.logging_level = "ERROR".to_string();
        
        // Disable non-essential features
        config.aggressive_detection = false;
        
        // Send lockdown alert
        let event = SystemEvent::new(
            "self_healing",
            SystemEventType::Error,
            EventSeverity::Critical,
            "System entered lockdown mode due to repeated security threats",
        );
        
        let _ = self.event_bus.publish_system_event(event).await;
    }
    
    /// Assess overall system health
    async fn assess_system_health(&self) {
        let metrics = self.performance_metrics.read().await;
        
        let cpu_health = 1.0 - (metrics.cpu_usage_percent / 100.0) as f64;
        let memory_health = 1.0 - (metrics.memory_usage_mb as f64 / (8192.0 * 1024.0 * 1024.0)); // Assume 8GB max
        let network_health = if metrics.active_connections < 1000 { 1.0 } else { 0.5 };
        let disk_health = if metrics.disk_io_ops_per_sec < 10000 { 1.0 } else { 0.5 };
        let error_health = 1.0 - (metrics.error_rate_percent / 100.0) as f64;
        let response_health = if metrics.avg_response_time_ms < 100.0 { 1.0 } else { 0.5 };
        
        let overall_score = (cpu_health + memory_health + network_health + disk_health + error_health + response_health) / 6.0;
        
        let mut health = self.system_health.write().await;
        health.overall_score = overall_score;
        health.cpu_health = cpu_health;
        health.memory_health = memory_health;
        health.network_health = network_health;
        health.disk_health = disk_health;
        health.error_rate = metrics.error_rate_percent as f64;
        health.response_time_ms = metrics.avg_response_time_ms;
        health.last_assessment = Instant::now();
        
        // Report health issues
        if overall_score < 0.7 {
            let event = SystemEvent::new(
                "self_healing",
                SystemEventType::HealthCheckFailed,
                EventSeverity::Warning,
                &format!("System health degraded: {:.1}%", overall_score * 100.0),
            );
            
            let _ = self.event_bus.publish_system_event(event).await;
        }
    }
    
    /// Apply adaptations based on system health
    async fn apply_health_based_adaptations(&self) {
        let health = self.system_health.read().await;
        
        if health.overall_score < 0.5 {
            tracing::warn!("Poor system health detected, applying recovery measures");
            self.apply_performance_recovery().await;
        }
    }
    
    /// Apply performance recovery measures
    async fn apply_performance_recovery(&self) {
        let mut config = self.adaptive_config.write().await;
        
        // Reduce resource usage
        config.thread_pool_size = (config.thread_pool_size / 2).max(1);
        config.scanning_interval_ms *= 2;
        config.memory_limit_mb = (config.memory_limit_mb * 3 / 4).max(128);
        
        tracing::info!("Applied performance recovery: threads={}, interval={}ms", 
                      config.thread_pool_size, config.scanning_interval_ms);
    }
    
    /// Collect performance metrics
    async fn collect_performance_metrics(&self) {
        // In real implementation, would collect actual system metrics
        let mut metrics = self.performance_metrics.write().await;
        
        // Mock metrics collection
        metrics.cpu_usage_percent = Self::get_cpu_usage();
        metrics.memory_usage_mb = Self::get_memory_usage();
        metrics.active_connections = Self::get_active_connections();
        metrics.avg_response_time_ms = Self::get_avg_response_time();
        metrics.error_rate_percent = Self::get_error_rate();
    }
    
    /// Apply performance-based adaptations
    async fn apply_performance_adaptations(&self) {
        let metrics = self.performance_metrics.read().await;
        
        // Auto-scale based on CPU usage
        if metrics.cpu_usage_percent > 80.0 {
            self.request_scale_up().await;
        } else if metrics.cpu_usage_percent < 30.0 {
            self.request_scale_down().await;
        }
        
        // Adapt based on error rate
        if metrics.error_rate_percent > 5.0 {
            self.apply_error_mitigation().await;
        }
    }
    
    /// Handle system events for module health tracking
    async fn handle_system_event(&self, event: SystemEvent) {
        match event.event_type {
            SystemEventType::ModuleStarted => {
                self.register_module(&event.source_module).await;
            },
            SystemEventType::ModuleStopped => {
                self.mark_module_failed(&event.source_module).await;
            },
            SystemEventType::Error => {
                self.increment_module_errors(&event.source_module).await;
            },
            SystemEventType::HealthCheckFailed => {
                self.mark_module_degraded(&event.source_module).await;
            },
            _ => {},
        }
    }
    
    /// Register a new module for health tracking
    async fn register_module(&self, module_name: &str) {
        let mut modules = self.module_health.write().await;
        
        modules.insert(module_name.to_string(), ModuleHealth {
            name: module_name.to_string(),
            status: ModuleStatus::Healthy,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            performance_score: 1.0,
            critical: Self::is_critical_module(module_name),
        });
        
        tracing::info!("Registered module for health monitoring: {}", module_name);
    }
    
    /// Check if module is critical for system operation
    fn is_critical_module(module_name: &str) -> bool {
        matches!(module_name, "detection_engine" | "security_manager" | "event_bus" | "anti_debug")
    }
    
    /// Auto-scale resources based on load
    async fn auto_scale_resources(&self) {
        let mut scaler = self.auto_scaling.lock().await;
        let metrics = self.performance_metrics.read().await;
        
        scaler.evaluate_scaling(&metrics).await;
    }
    
    /// Request scale up
    async fn request_scale_up(&self) {
        tracing::info!("Requesting resource scale-up due to high load");
        
        let mut config = self.adaptive_config.write().await;
        config.thread_pool_size = (config.thread_pool_size * 3 / 2).min(32);
    }
    
    /// Request scale down
    async fn request_scale_down(&self) {
        tracing::debug!("Requesting resource scale-down due to low load");
        
        let mut config = self.adaptive_config.write().await;
        config.thread_pool_size = (config.thread_pool_size * 2 / 3).max(1);
    }
    
    /// Apply error mitigation measures
    async fn apply_error_mitigation(&self) {
        tracing::warn!("High error rate detected, applying mitigation measures");
        
        let mut config = self.adaptive_config.write().await;
        
        // Increase timeouts and reduce concurrency
        config.network_timeout_ms = (config.network_timeout_ms * 3 / 2).min(30000);
        config.thread_pool_size = (config.thread_pool_size * 3 / 4).max(1);
        config.scanning_interval_ms = (config.scanning_interval_ms * 3 / 2);
    }
    
    /// Mock system metric collection functions
    fn get_cpu_usage() -> f32 {
        // Would use actual system APIs
        rand::random::<f32>() * 100.0
    }
    
    fn get_memory_usage() -> u64 {
        // Would use actual system APIs
        (rand::random::<u64>() % (2 * 1024 * 1024 * 1024)) + (512 * 1024 * 1024)
    }
    
    fn get_active_connections() -> u32 {
        rand::random::<u32>() % 1000
    }
    
    fn get_avg_response_time() -> f64 {
        rand::random::<f64>() * 200.0 + 10.0
    }
    
    fn get_error_rate() -> f32 {
        rand::random::<f32>() * 10.0
    }
    
    async fn increment_module_errors(&self, module_name: &str) {
        let mut modules = self.module_health.write().await;
        if let Some(module) = modules.get_mut(module_name) {
            module.error_count += 1;
            
            if module.error_count > 5 {
                module.status = ModuleStatus::Degraded;
            }
            if module.error_count > 10 {
                module.status = ModuleStatus::Critical;
            }
        }
    }
    
    async fn mark_module_failed(&self, module_name: &str) {
        let mut modules = self.module_health.write().await;
        if let Some(module) = modules.get_mut(module_name) {
            module.status = ModuleStatus::Failed;
        }
    }
    
    async fn mark_module_degraded(&self, module_name: &str) {
        let mut modules = self.module_health.write().await;
        if let Some(module) = modules.get_mut(module_name) {
            module.status = ModuleStatus::Degraded;
        }
    }
    
    /// Clone for task spawning
    fn clone_for_task(&self) -> Self {
        Self {
            threat_level: self.threat_level.clone(),
            defense_mode: self.defense_mode.clone(),
            system_health: self.system_health.clone(),
            adaptive_config: self.adaptive_config.clone(),
            original_config: self.original_config.clone(),
            module_health: self.module_health.clone(),
            recovery_attempts: self.recovery_attempts.clone(),
            performance_metrics: self.performance_metrics.clone(),
            auto_scaling: self.auto_scaling.clone(),
            event_bus: self.event_bus.clone(),
            healing_enabled: AtomicBool::new(self.healing_enabled.load(Ordering::SeqCst)),
            adaptation_enabled: AtomicBool::new(self.adaptation_enabled.load(Ordering::SeqCst)),
            escalation_count: AtomicUsize::new(self.escalation_count.load(Ordering::SeqCst)),
        }
    }
    
    /// Get current defense mode
    pub async fn get_defense_mode(&self) -> DefenseMode {
        self.defense_mode.read().await.clone()
    }
    
    /// Get current threat level
    pub async fn get_threat_level(&self) -> ThreatLevel {
        self.threat_level.read().await.clone()
    }
    
    /// Get system health
    pub async fn get_system_health(&self) -> SystemHealth {
        self.system_health.read().await.clone()
    }
}

// Default implementations
impl Default for SystemHealth {
    fn default() -> Self {
        Self {
            overall_score: 1.0,
            cpu_health: 1.0,
            memory_health: 1.0,
            network_health: 1.0,
            disk_health: 1.0,
            error_rate: 0.0,
            response_time_ms: 10.0,
            last_assessment: Instant::now(),
        }
    }
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            scanning_interval_ms: 1000,
            thread_pool_size: num_cpus::get(),
            memory_limit_mb: 1024,
            network_timeout_ms: 5000,
            stealth_level: 3,
            logging_level: "INFO".to_string(),
            siem_reporting: true,
            aggressive_detection: false,
            anti_tamper_level: 5,
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_usage_percent: 25.0,
            memory_usage_mb: 512 * 1024 * 1024,
            disk_io_ops_per_sec: 100,
            network_bytes_per_sec: 1024 * 1024,
            active_connections: 10,
            pending_tasks: 5,
            avg_response_time_ms: 50.0,
            error_rate_percent: 1.0,
        }
    }
}

impl AutoScalingEngine {
    pub fn new() -> Self {
        Self {
            target_cpu_percent: 70.0,
            target_memory_percent: 80.0,
            scale_up_threshold: 85.0,
            scale_down_threshold: 40.0,
            min_workers: 1,
            max_workers: 16,
            current_workers: num_cpus::get(),
            last_scale_action: Instant::now(),
            cooldown_duration: Duration::from_secs(60),
        }
    }
    
    pub async fn evaluate_scaling(&mut self, metrics: &PerformanceMetrics) {
        if self.last_scale_action.elapsed() < self.cooldown_duration {
            return; // Cooldown period
        }
        
        if metrics.cpu_usage_percent > self.scale_up_threshold && self.current_workers < self.max_workers {
            self.scale_up().await;
        } else if metrics.cpu_usage_percent < self.scale_down_threshold && self.current_workers > self.min_workers {
            self.scale_down().await;
        }
    }
    
    async fn scale_up(&mut self) {
        self.current_workers = (self.current_workers + 1).min(self.max_workers);
        self.last_scale_action = Instant::now();
        tracing::info!("Auto-scaling up to {} workers", self.current_workers);
    }
    
    async fn scale_down(&mut self) {
        self.current_workers = (self.current_workers - 1).max(self.min_workers);
        self.last_scale_action = Instant::now();
        tracing::info!("Auto-scaling down to {} workers", self.current_workers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::event_bus::EngineEventBus;
    
    #[tokio::test]
    async fn test_self_healing_system_creation() {
        let event_bus = Arc::new(EngineEventBus::new());
        let system = SelfHealingSystem::new(event_bus);
        
        assert_eq!(system.get_defense_mode().await, DefenseMode::Normal);
        assert_eq!(system.get_threat_level().await, ThreatLevel::None);
    }
    
    #[tokio::test]
    async fn test_threat_level_escalation() {
        let event_bus = Arc::new(EngineEventBus::new());
        let system = SelfHealingSystem::new(event_bus);
        
        system.update_threat_level(ThreatLevel::High).await;
        assert_eq!(system.get_threat_level().await, ThreatLevel::High);
        
        // Should not de-escalate immediately
        system.update_threat_level(ThreatLevel::Medium).await;
        assert_eq!(system.get_threat_level().await, ThreatLevel::High);
    }
    
    #[tokio::test]
    async fn test_defense_mode_escalation() {
        let event_bus = Arc::new(EngineEventBus::new());
        let system = SelfHealingSystem::new(event_bus);
        
        system.escalate_defense_mode(DefenseMode::Defensive).await;
        assert_eq!(system.get_defense_mode().await, DefenseMode::Defensive);
        
        system.escalate_defense_mode(DefenseMode::Emergency).await;
        assert_eq!(system.get_defense_mode().await, DefenseMode::Emergency);
    }
    
    #[tokio::test]
    async fn test_module_health_tracking() {
        let event_bus = Arc::new(EngineEventBus::new());
        let system = SelfHealingSystem::new(event_bus);
        
        system.register_module("test_module").await;
        
        let modules = system.module_health.read().await;
        assert!(modules.contains_key("test_module"));
        assert_eq!(modules["test_module"].status, ModuleStatus::Healthy);
    }
}