/**
 * ECH SIEM Transports Module
 */

use anyhow::Result;
use std::sync::Arc;
use super::{AuthConfig, formatters::FormattedEvent};

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub transport_type: TransportType,
    pub endpoint: Option<String>,
    pub auth_config: AuthConfig,
    pub timeout_sec: u64,
    pub retry_attempts: u32,
    pub compression_enabled: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Http,
            endpoint: None,
            auth_config: AuthConfig {
                auth_type: super::AuthType::None,
                username: None,
                password: None,
                api_key: None,
                cert_path: None,
                key_path: None,
                ca_cert_path: None,
            },
            timeout_sec: 30,
            retry_attempts: 3,
            compression_enabled: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransportType {
    Http,
    Syslog,
}

pub trait SiemTransport {
    async fn send_events(&self, events: &[FormattedEvent]) -> Result<()>;
    async fn close(&self) -> Result<()>;
}

pub async fn create_transport(_config: TransportConfig) -> Result<Arc<dyn SiemTransport + Send + Sync>> {
    Ok(Arc::new(MockTransport))
}

struct MockTransport;

impl SiemTransport for MockTransport {
    async fn send_events(&self, _events: &[FormattedEvent]) -> Result<()> {
        Ok(())
    }
    
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}