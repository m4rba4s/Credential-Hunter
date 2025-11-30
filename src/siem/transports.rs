use super::{formatters::FormattedEvent, AuthConfig};
/**
 * ECH SIEM Transports Module
 */
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use std::sync::Arc;
use tracing::{info, warn};

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

pub async fn create_transport(
    config: TransportConfig,
) -> Result<Arc<dyn SiemTransport + Send + Sync>> {
    match config.transport_type {
        TransportType::Http => Ok(Arc::new(HttpTransport::new(config).await?)),
        TransportType::Syslog => Ok(Arc::new(SyslogTransport::new())),
    }
}

struct HttpTransport {
    client: Client,
    endpoint: String,
    auth: AuthConfig,
    retry_attempts: u32,
}

impl HttpTransport {
    async fn new(config: TransportConfig) -> Result<Self> {
        let endpoint = config
            .endpoint
            .ok_or_else(|| anyhow!("SIEM endpoint not configured"))?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_sec.max(1)))
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            client,
            endpoint,
            auth: config.auth_config,
            retry_attempts: config.retry_attempts.max(1),
        })
    }

    async fn post(&self, body: &str) -> Result<()> {
        let mut request = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "application/json");

        match self.auth.auth_type {
            super::AuthType::Basic => {
                if let (Some(user), Some(pass)) = (&self.auth.username, &self.auth.password) {
                    request = request.basic_auth(user, Some(pass));
                }
            }
            super::AuthType::ApiKey => {
                if let Some(key) = &self.auth.api_key {
                    request = request.header("Authorization", format!("Bearer {}", key));
                }
            }
            _ => {}
        }

        let response = request.body(body.to_string()).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "SIEM endpoint responded with status {}",
                response.status()
            ));
        }
        Ok(())
    }
}

impl SiemTransport for HttpTransport {
    async fn send_events(&self, events: &[FormattedEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let payload =
            serde_json::to_string(&events.iter().map(|e| &e.payload).collect::<Vec<_>>())?;
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.post(&payload).await {
                Ok(_) => return Ok(()),
                Err(err) if attempts < self.retry_attempts => {
                    warn!("SIEM send attempt {} failed: {}", attempts, err);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

struct SyslogTransport;

impl SyslogTransport {
    fn new() -> Self {
        Self
    }
}

impl SiemTransport for SyslogTransport {
    async fn send_events(&self, events: &[FormattedEvent]) -> Result<()> {
        for event in events {
            info!(target: "ech::siem", "[SYSLOG] {}", event.payload);
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}
