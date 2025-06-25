pub mod sdk;
pub mod runtime;

pub use sdk::*;
pub use runtime::*;

use ech_core::prelude::*;
use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub capabilities: Vec<PluginCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginCapability {
    MemoryScanning,
    FileScanning,
    NetworkMonitoring,
    ProcessInjection,
    CustomPattern,
}

pub trait Plugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    
    fn initialize(&self) -> Result<()>;
    
    fn execute(&self, context: &PluginContext) -> Result<PluginResult>;
    
    fn cleanup(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct PluginContext {
    pub config: std::collections::HashMap<String, String>,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub success: bool,
    pub credentials: Vec<DetectedCredential>,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedCredential {
    pub credential_type: String,
    pub value: String,
    pub location: String,
    pub confidence: f64,
}