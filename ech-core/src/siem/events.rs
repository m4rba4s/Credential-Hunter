/**
 * ECH SIEM Events Module
 */

use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct SiemEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub severity: EventSeverity,
    pub source: String,
    pub title: String,
    pub description: String,
    pub host: String,
    pub user: String,
    pub process: String,
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
    pub metadata: EventMetadata,
}

#[derive(Debug, Clone)]
pub enum EventType {
    Information,
    LowThreat,
    MediumThreat,
    HighThreat,
    CriticalThreat,
}

#[derive(Debug, Clone)]
pub enum EventSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct EventMetadata {
    pub session_id: Uuid,
    pub correlation_id: Option<String>,
    pub tenant_id: Option<String>,
    pub organization: Option<String>,
    pub environment: Option<String>,
    pub version: String,
}