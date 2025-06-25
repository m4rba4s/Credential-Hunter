use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{info, warn, debug};
use reqwest::Client;
use uuid::Uuid;
use chrono::Utc;
use crate::detection::engine::{
    DetectionResult, CredentialType, RiskLevel, ConfidenceLevel,
    CredentialLocation, CredentialContext, DetectionMetadata
};

const IMDS_V1_ENDPOINT: &str = "http://169.254.169.254/latest/meta-data/";
const IMDS_V2_ENDPOINT: &str = "http://169.254.169.254/latest/api/token";
const IMDS_V2_DATA_ENDPOINT: &str = "http://169.254.169.254/latest/meta-data/";
const IMDS_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const IMDS_PORT: u16 = 80;

pub struct ImdsHunter {
    config: ImdsConfig,
    client: Client,
    ebpf_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ImdsConfig {
    pub enable_v1_hunting: bool,
    pub enable_v2_hunting: bool,
    pub enable_network_monitoring: bool,
    pub enable_ebpf_monitoring: bool,
    pub monitor_duration: Duration,
    pub request_timeout: Duration,
    pub max_retries: u32,
    pub stealth_mode: bool,
    pub custom_user_agent: Option<String>,
    pub target_cloud_providers: Vec<CloudProvider>,
}

impl Default for ImdsConfig {
    fn default() -> Self {
        Self {
            enable_v1_hunting: true,
            enable_v2_hunting: true,
            enable_network_monitoring: true,
            enable_ebpf_monitoring: cfg!(target_os = "linux"),
            monitor_duration: Duration::from_secs(300), // 5 minutes
            request_timeout: Duration::from_secs(5),
            max_retries: 3,
            stealth_mode: true,
            custom_user_agent: None,
            target_cloud_providers: vec![
                CloudProvider::Aws,
                CloudProvider::Azure,
                CloudProvider::Gcp,
                CloudProvider::Alibaba,
                CloudProvider::DigitalOcean,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    Alibaba,
    DigitalOcean,
    Oracle,
    Vultr,
    Linode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImdsCredential {
    pub cloud_provider: String,
    pub credential_type: ImdsCredentialType,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub role_name: Option<String>,
    pub expiration: Option<String>,
    pub region: Option<String>,
    pub account_id: Option<String>,
    pub instance_id: Option<String>,
    pub metadata: HashMap<String, String>,
    pub extraction_timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImdsCredentialType {
    AwsAccessKeys,
    AwsSessionToken,
    AzureAccessToken,
    GcpServiceAccount,
    TemporaryCredentials,
    InstanceProfile,
    ServicePrincipal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImdsMetadata {
    pub instance_id: Option<String>,
    pub instance_type: Option<String>,
    pub region: Option<String>,
    pub availability_zone: Option<String>,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub security_groups: Vec<String>,
    pub tags: HashMap<String, String>,
    pub user_data: Option<String>,
    pub network_interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub interface_id: String,
    pub mac_address: String,
    pub private_ipv4: String,
    pub public_ipv4: Option<String>,
    pub subnet_id: String,
    pub vpc_id: String,
}

#[derive(Debug, Clone)]
pub struct ImdsMonitoringResult {
    pub intercepted_requests: Vec<ImdsRequest>,
    pub detected_credentials: Vec<ImdsCredential>,
    pub network_activity: Vec<NetworkActivity>,
    pub ebpf_events: Vec<EbpfEvent>,
    pub monitoring_duration: Duration,
    pub total_requests: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImdsRequest {
    pub timestamp: SystemTime,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub target_endpoint: String,
    pub http_method: String,
    pub headers: HashMap<String, String>,
    pub response_status: Option<u16>,
    pub response_data: Option<String>,
    pub process_info: Option<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub command_line: String,
    pub user_id: u32,
    pub parent_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub timestamp: SystemTime,
    pub protocol: String,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfEvent {
    pub timestamp: SystemTime,
    pub event_type: EbpfEventType,
    pub pid: u32,
    pub process_name: String,
    pub syscall: Option<String>,
    pub network_data: Option<String>,
    pub file_path: Option<String>,
    pub additional_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EbpfEventType {
    NetworkConnect,
    HttpRequest,
    FileAccess,
    ProcessExec,
    SystemCall,
}

impl ImdsHunter {
    pub fn new() -> Result<Self> {
        let config = ImdsConfig::default();
        Self::with_config(config)
    }
    
    pub fn with_config(config: ImdsConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()?;
        
        let ebpf_enabled = config.enable_ebpf_monitoring && Self::check_ebpf_support();
        
        Ok(Self {
            config,
            client,
            ebpf_enabled,
        })
    }
    
    fn check_ebpf_support() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Check if eBPF is available
            std::path::Path::new("/sys/fs/bpf").exists()
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
    
    pub async fn hunt_imds_credentials(&self) -> Result<Vec<DetectionResult>> {
        info!("Starting IMDS credential hunting");
        
        let mut results = Vec::new();
        
        // Check if we're in a cloud environment
        if !self.is_cloud_environment().await {
            warn!("Not detected in a cloud environment, IMDS hunting may fail");
        }
        
        // Hunt credentials from different cloud providers
        for provider in &self.config.target_cloud_providers {
            match self.hunt_provider_credentials(provider).await {
                Ok(mut provider_results) => {
                    info!("Found {} credentials from {:?}", provider_results.len(), provider);
                    results.append(&mut provider_results);
                },
                Err(e) => {
                    debug!("Failed to hunt credentials from {:?}: {}", provider, e);
                }
            }
        }
        
        info!("IMDS hunting completed, found {} total credentials", results.len());
        Ok(results)
    }
    
    async fn is_cloud_environment(&self) -> bool {
        // Quick check for cloud environment indicators
        let cloud_indicators = [
            "169.254.169.254", // IMDS endpoint
            "/sys/hypervisor/uuid",
            "/sys/class/dmi/id/product_name",
            "/proc/xen",
        ];
        
        for indicator in &cloud_indicators {
            if indicator.starts_with("169.254") {
                // Try to ping IMDS endpoint
                if self.ping_imds_endpoint().await.is_ok() {
                    return true;
                }
            } else {
                // Check filesystem indicators
                if std::path::Path::new(indicator).exists() {
                    return true;
                }
            }
        }
        
        false
    }
    
    async fn ping_imds_endpoint(&self) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = SocketAddr::new(IpAddr::V4(IMDS_IP), IMDS_PORT);
        
        let ping_data = b"ping";
        let result = timeout(
            Duration::from_secs(1),
            socket.send_to(ping_data, target)
        ).await;
        
        match result {
            Ok(Ok(_)) => Ok(()),
            _ => Err(anyhow!("IMDS endpoint not reachable")),
        }
    }
    
    async fn hunt_provider_credentials(&self, provider: &CloudProvider) -> Result<Vec<DetectionResult>> {
        match provider {
            CloudProvider::Aws => self.hunt_aws_credentials().await,
            CloudProvider::Azure => self.hunt_azure_credentials().await,
            CloudProvider::Gcp => self.hunt_gcp_credentials().await,
            CloudProvider::Alibaba => self.hunt_alibaba_credentials().await,
            CloudProvider::DigitalOcean => self.hunt_digitalocean_credentials().await,
            CloudProvider::Oracle => self.hunt_oracle_credentials().await,
            CloudProvider::Vultr => self.hunt_vultr_credentials().await,
            CloudProvider::Linode => self.hunt_linode_credentials().await,
        }
    }
    
    async fn hunt_aws_credentials(&self) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        debug!("Hunting AWS IMDS credentials");
        
        // Try AWS IMDSv2 first (more secure)
        if self.config.enable_v2_hunting {
            match self.get_aws_imdsv2_token().await {
                Ok(token) => {
                    if let Ok(credentials) = self.extract_aws_credentials_v2(&token).await {
                        results.extend(credentials);
                    }
                },
                Err(e) => debug!("IMDSv2 failed: {}", e),
            }
        }
        
        // Fallback to IMDSv1
        if self.config.enable_v1_hunting && results.is_empty() {
            if let Ok(credentials) = self.extract_aws_credentials_v1().await {
                results.extend(credentials);
            }
        }
        
        Ok(results)
    }
    
    async fn get_aws_imdsv2_token(&self) -> Result<String> {
        let request = self.client
            .put(IMDS_V2_ENDPOINT)
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .header("User-Agent", self.get_user_agent());
        
        let response = request.send().await?;
        
        if response.status().is_success() {
            let token = response.text().await?;
            debug!("Successfully obtained IMDSv2 token");
            Ok(token)
        } else {
            Err(anyhow!("Failed to get IMDSv2 token: {}", response.status()))
        }
    }
    
    async fn extract_aws_credentials_v2(&self, token: &str) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        // Get security credentials
        let creds_url = format!("{}iam/security-credentials/", IMDS_V2_DATA_ENDPOINT);
        let response = self.client
            .get(&creds_url)
            .header("X-aws-ec2-metadata-token", token)
            .header("User-Agent", self.get_user_agent())
            .send()
            .await?;
        
        if response.status().is_success() {
            let role_names = response.text().await?;
            
            for role_name in role_names.lines() {
                let role_creds_url = format!("{}{}", creds_url, role_name.trim());
                
                let role_response = self.client
                    .get(&role_creds_url)
                    .header("X-aws-ec2-metadata-token", token)
                    .header("User-Agent", self.get_user_agent())
                    .send()
                    .await?;
                
                if role_response.status().is_success() {
                    let creds_json = role_response.text().await?;
                    
                    if let Ok(credentials) = self.parse_aws_credentials(&creds_json, role_name) {
                        results.push(credentials);
                    }
                }
            }
        }
        
        Ok(results)
    }
    
    async fn extract_aws_credentials_v1(&self) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        debug!("Attempting AWS IMDSv1 credential extraction");
        
        let creds_url = format!("{}iam/security-credentials/", IMDS_V1_ENDPOINT);
        let response = self.client
            .get(&creds_url)
            .header("User-Agent", self.get_user_agent())
            .send()
            .await?;
        
        if response.status().is_success() {
            let role_names = response.text().await?;
            
            for role_name in role_names.lines() {
                let role_creds_url = format!("{}{}", creds_url, role_name.trim());
                
                let role_response = self.client
                    .get(&role_creds_url)
                    .header("User-Agent", self.get_user_agent())
                    .send()
                    .await?;
                
                if role_response.status().is_success() {
                    let creds_json = role_response.text().await?;
                    
                    if let Ok(credentials) = self.parse_aws_credentials(&creds_json, role_name) {
                        results.push(credentials);
                    }
                }
            }
        }
        
        Ok(results)
    }
    
    fn parse_aws_credentials(&self, json_data: &str, role_name: &str) -> Result<DetectionResult> {
        let parsed: serde_json::Value = serde_json::from_str(json_data)?;
        
        let access_key_id = parsed["AccessKeyId"].as_str().unwrap_or("").to_string();
        let _secret_access_key = parsed["SecretAccessKey"].as_str().unwrap_or("").to_string();
        let _session_token = parsed["Token"].as_str().unwrap_or("").to_string();
        let _expiration = parsed["Expiration"].as_str().unwrap_or("").to_string();
        
        Ok(self.create_imds_detection_result(
            CredentialType::AwsAccessKey,
            "AWS IMDS Endpoint",
            &format!("AccessKeyId: {}", Self::mask_credential(&access_key_id)),
            &format!("Role: {}, IMDS extraction", role_name),
            RiskLevel::Critical,
        ))
    }
    
    fn mask_credential(credential: &str) -> String {
        if credential.len() <= 8 {
            "*".repeat(credential.len())
        } else {
            format!("{}...{}", 
                &credential[..4], 
                &credential[credential.len()-4..]
            )
        }
    }
    
    async fn hunt_azure_credentials(&self) -> Result<Vec<DetectionResult>> {
        debug!("Hunting Azure IMDS credentials");
        
        let azure_endpoint = "http://169.254.169.254/metadata/identity/oauth2/token";
        let response = self.client
            .get(azure_endpoint)
            .header("Metadata", "true")
            .header("User-Agent", self.get_user_agent())
            .query(&[("api-version", "2018-02-01"), ("resource", "https://management.azure.com/")])
            .send()
            .await?;
        
        if response.status().is_success() {
            let token_data = response.text().await?;
            
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&token_data) {
                let access_token = parsed["access_token"].as_str().unwrap_or("");
                
                if !access_token.is_empty() {
                    return Ok(vec![self.create_imds_detection_result(
                        CredentialType::AzureClientSecret,
                        "Azure IMDS Endpoint",
                        &format!("Access Token: {}", Self::mask_credential(access_token)),
                        "Azure Managed Identity",
                        RiskLevel::Critical,
                    )]);
                }
            }
        }
        
        Ok(Vec::new())
    }
    
    async fn hunt_gcp_credentials(&self) -> Result<Vec<DetectionResult>> {
        debug!("Hunting GCP IMDS credentials");
        
        let gcp_endpoint = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token";
        let response = self.client
            .get(gcp_endpoint)
            .header("Metadata-Flavor", "Google")
            .header("User-Agent", self.get_user_agent())
            .send()
            .await?;
        
        if response.status().is_success() {
            let token_data = response.text().await?;
            
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&token_data) {
                let access_token = parsed["access_token"].as_str().unwrap_or("");
                
                if !access_token.is_empty() {
                    return Ok(vec![self.create_imds_detection_result(
                        CredentialType::GcpServiceKey,
                        "GCP IMDS Endpoint",
                        &format!("Access Token: {}", Self::mask_credential(access_token)),
                        "GCP Service Account",
                        RiskLevel::Critical,
                    )]);
                }
            }
        }
        
        Ok(Vec::new())
    }
    
    async fn hunt_alibaba_credentials(&self) -> Result<Vec<DetectionResult>> {
        debug!("Hunting Alibaba Cloud IMDS credentials");
        
        let alibaba_endpoint = "http://100.100.100.200/latest/meta-data/ram/security-credentials/";
        let response = self.client
            .get(alibaba_endpoint)
            .header("User-Agent", self.get_user_agent())
            .send()
            .await?;
        
        if response.status().is_success() {
            let roles = response.text().await?;
            
            for role in roles.lines() {
                let role_url = format!("{}{}", alibaba_endpoint, role.trim());
                let role_response = self.client
                    .get(&role_url)
                    .header("User-Agent", self.get_user_agent())
                    .send()
                    .await?;
                
                if role_response.status().is_success() {
                    let creds_data = role_response.text().await?;
                    
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&creds_data) {
                        let access_key_id = parsed["AccessKeyId"].as_str().unwrap_or("");
                        let _access_key_secret = parsed["AccessKeySecret"].as_str().unwrap_or("");
                        
                        if !access_key_id.is_empty() {
                            return Ok(vec![self.create_imds_detection_result(
                                CredentialType::AwsAccessKey, // Similar format
                                "Alibaba Cloud IMDS",
                                &format!("AccessKeyId: {}", Self::mask_credential(access_key_id)),
                                &format!("Role: {}", role.trim()),
                                RiskLevel::Critical,
                            )]);
                        }
                    }
                }
            }
        }
        
        Ok(Vec::new())
    }
    
    async fn hunt_digitalocean_credentials(&self) -> Result<Vec<DetectionResult>> {
        debug!("Hunting DigitalOcean metadata");
        
        let do_endpoint = "http://169.254.169.254/metadata/v1/id";
        let response = self.client
            .get(do_endpoint)
            .header("User-Agent", self.get_user_agent())
            .send()
            .await?;
        
        if response.status().is_success() {
            let instance_id = response.text().await?;
            
            return Ok(vec![self.create_imds_detection_result(
                CredentialType::ApiSecret,
                "DigitalOcean IMDS",
                &format!("Instance ID: {}", instance_id.trim()),
                "DigitalOcean metadata",
                RiskLevel::Medium,
            )]);
        }
        
        Ok(Vec::new())
    }
    
    async fn hunt_oracle_credentials(&self) -> Result<Vec<DetectionResult>> {
        debug!("Hunting Oracle Cloud metadata");
        Ok(Vec::new()) // Placeholder
    }
    
    async fn hunt_vultr_credentials(&self) -> Result<Vec<DetectionResult>> {
        debug!("Hunting Vultr metadata");
        Ok(Vec::new()) // Placeholder
    }
    
    async fn hunt_linode_credentials(&self) -> Result<Vec<DetectionResult>> {
        debug!("Hunting Linode metadata");
        Ok(Vec::new()) // Placeholder
    }
    
    pub async fn monitor_imds_traffic(&self) -> Result<ImdsMonitoringResult> {
        info!("Starting IMDS traffic monitoring for {:?}", self.config.monitor_duration);
        
        let start_time = Instant::now();
        let mut intercepted_requests = Vec::new();
        let mut network_activity = Vec::new();
        let mut ebpf_events = Vec::new();
        
        // Start eBPF monitoring if available
        if self.ebpf_enabled {
            ebpf_events = self.start_ebpf_monitoring().await?;
        }
        
        // Network monitoring
        if self.config.enable_network_monitoring {
            network_activity = self.monitor_network_activity().await?;
        }
        
        // Passive monitoring for IMDS requests
        intercepted_requests = self.monitor_imds_requests().await?;
        
        let monitoring_duration = start_time.elapsed();
        
        Ok(ImdsMonitoringResult {
            intercepted_requests: intercepted_requests.clone(),
            detected_credentials: Vec::new(), // Would be extracted from intercepted requests
            network_activity,
            ebpf_events,
            monitoring_duration,
            total_requests: intercepted_requests.len() as u32,
        })
    }
    
    #[cfg(target_os = "linux")]
    async fn start_ebpf_monitoring(&self) -> Result<Vec<EbpfEvent>> {
        debug!("Starting eBPF monitoring for IMDS traffic");
        
        // In a real implementation, this would:
        // 1. Load eBPF program to monitor network connections to 169.254.169.254
        // 2. Hook into syscalls like connect(), sendto(), recvfrom()
        // 3. Monitor HTTP requests to IMDS endpoints
        // 4. Track process information making IMDS requests
        
        tokio::time::sleep(self.config.monitor_duration).await;
        
        // Simulate eBPF events
        let mut events = Vec::new();
        events.push(EbpfEvent {
            timestamp: SystemTime::now(),
            event_type: EbpfEventType::NetworkConnect,
            pid: 1234,
            process_name: "aws-cli".to_string(),
            syscall: Some("connect".to_string()),
            network_data: Some("169.254.169.254:80".to_string()),
            file_path: None,
            additional_data: HashMap::from([
                ("dst_ip".to_string(), "169.254.169.254".to_string()),
                ("dst_port".to_string(), "80".to_string()),
            ]),
        });
        
        Ok(events)
    }
    
    #[cfg(not(target_os = "linux"))]
    async fn start_ebpf_monitoring(&self) -> Result<Vec<EbpfEvent>> {
        debug!("eBPF monitoring not available on this platform");
        Ok(Vec::new())
    }
    
    async fn monitor_network_activity(&self) -> Result<Vec<NetworkActivity>> {
        debug!("Monitoring network activity to IMDS endpoints");
        
        // Simulate network monitoring
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let mut activities = Vec::new();
        activities.push(NetworkActivity {
            timestamp: SystemTime::now(),
            protocol: "TCP".to_string(),
            src_addr: "10.0.0.123:45678".parse().unwrap(),
            dst_addr: "169.254.169.254:80".parse().unwrap(),
            bytes_sent: 256,
            bytes_received: 1024,
            connection_state: "ESTABLISHED".to_string(),
        });
        
        Ok(activities)
    }
    
    async fn monitor_imds_requests(&self) -> Result<Vec<ImdsRequest>> {
        debug!("Monitoring IMDS requests");
        
        // In a real implementation, this would set up packet capture
        // or network interception to monitor HTTP requests to IMDS endpoints
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let mut requests = Vec::new();
        requests.push(ImdsRequest {
            timestamp: SystemTime::now(),
            source_ip: "10.0.0.123".parse().unwrap(),
            source_port: 45678,
            target_endpoint: IMDS_V2_ENDPOINT.to_string(),
            http_method: "PUT".to_string(),
            headers: HashMap::from([
                ("X-aws-ec2-metadata-token-ttl-seconds".to_string(), "21600".to_string()),
            ]),
            response_status: Some(200),
            response_data: Some("AQAAAxxxxxxxxxxxxxxx".to_string()),
            process_info: Some(ProcessInfo {
                pid: 1234,
                process_name: "aws-cli".to_string(),
                command_line: "aws sts get-caller-identity".to_string(),
                user_id: 1000,
                parent_pid: 1000,
            }),
        });
        
        Ok(requests)
    }
    
    fn get_user_agent(&self) -> &str {
        self.config.custom_user_agent.as_ref()
            .map(|s| s.as_str())
            .unwrap_or("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
    }
    
    pub fn get_supported_providers(&self) -> &[CloudProvider] {
        &self.config.target_cloud_providers
    }
    
    pub fn is_ebpf_enabled(&self) -> bool {
        self.ebpf_enabled
    }
    
    /// Helper function to create properly structured DetectionResult
    fn create_imds_detection_result(
        &self,
        credential_type: CredentialType,
        location_path: &str,
        value: &str,
        context_description: &str,
        risk_level: RiskLevel,
    ) -> DetectionResult {
        DetectionResult {
            id: Uuid::new_v4(),
            credential_type: credential_type.clone(),
            confidence: ConfidenceLevel::High,
            masked_value: value.to_string(), // Value is already masked by caller
            full_value: None, // Never store full value in production
            location: CredentialLocation {
                source_type: "imds".to_string(),
                path: location_path.to_string(),
                line_number: None,
                column: None,
                memory_address: None,
                process_id: None,
                container_id: None,
            },
            context: CredentialContext {
                surrounding_text: context_description.to_string(),
                variable_name: None,
                file_type: None,
                language: None,
                context_clues: vec!["cloud_imds".to_string()],
            },
            metadata: DetectionMetadata {
                detection_methods: vec!["imds_extraction".to_string()],
                pattern_name: Some("cloud_credentials".to_string()),
                entropy_score: None,
                ml_confidence: None,
                yara_matches: Vec::new(),
                processing_time_us: 0,
            },
            risk_level: risk_level.clone(),
            recommended_actions: self.get_recommended_actions(&credential_type, &risk_level),
            timestamp: Utc::now(),
        }
    }
    
    /// Get recommended actions based on credential type and risk level
    fn get_recommended_actions(&self, credential_type: &CredentialType, risk_level: &RiskLevel) -> Vec<String> {
        let mut actions = Vec::new();
        
        match risk_level {
            RiskLevel::Critical => {
                actions.push("IMMEDIATE: Rotate cloud credentials".to_string());
                actions.push("IMMEDIATE: Revoke compromised access".to_string());
                actions.push("Review IMDS access controls".to_string());
                actions.push("Audit instance metadata usage".to_string());
            }
            RiskLevel::High => {
                actions.push("Rotate credentials within 24h".to_string());
                actions.push("Implement IMDS restrictions".to_string());
                actions.push("Enable cloud audit logging".to_string());
            }
            RiskLevel::Medium => {
                actions.push("Review credential exposure".to_string());
                actions.push("Monitor IMDS usage patterns".to_string());
                actions.push("Implement least privilege access".to_string());
            }
            _ => {
                actions.push("Document credential discovery".to_string());
                actions.push("Review cloud security posture".to_string());
            }
        }
        
        match credential_type {
            CredentialType::AwsAccessKey => {
                actions.push("Use IMDSv2 with session tokens".to_string());
                actions.push("Implement IAM role restrictions".to_string());
            }
            CredentialType::AzureClientSecret => {
                actions.push("Review managed identity configuration".to_string());
                actions.push("Implement Azure AD conditional access".to_string());
            }
            CredentialType::GcpServiceKey => {
                actions.push("Review service account permissions".to_string());
                actions.push("Implement workload identity".to_string());
            }
            _ => {}
        }
        
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_imds_hunter_creation() {
        let hunter = ImdsHunter::new().unwrap();
        assert!(!hunter.get_supported_providers().is_empty());
    }
    
    #[test]
    fn test_credential_masking() {
        let credential = "AKIA1234567890ABCDEF";
        let masked = ImdsHunter::mask_credential(credential);
        assert_eq!(masked, "AKIA...CDEF");
        
        let short_cred = "ABC";
        let masked_short = ImdsHunter::mask_credential(short_cred);
        assert_eq!(masked_short, "***");
    }
    
    #[test]
    fn test_cloud_provider_enum() {
        let providers = vec![
            CloudProvider::Aws,
            CloudProvider::Azure,
            CloudProvider::Gcp,
        ];
        
        assert_eq!(providers.len(), 3);
        assert_eq!(providers[0], CloudProvider::Aws);
    }
    
    #[tokio::test]
    async fn test_ebpf_support_check() {
        let support = ImdsHunter::check_ebpf_support();
        // Should not panic regardless of platform
        println!("eBPF support: {}", support);
    }
    
    #[tokio::test]
    async fn test_config_default() {
        let config = ImdsConfig::default();
        assert!(config.enable_v1_hunting);
        assert!(config.enable_v2_hunting);
        assert!(config.enable_network_monitoring);
        assert_eq!(config.max_retries, 3);
    }
}