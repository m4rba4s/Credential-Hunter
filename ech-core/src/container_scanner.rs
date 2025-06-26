/**
 * Container Credential Scanner
 * 
 * Advanced container security scanning for Docker, Podman, and Kubernetes
 * environments with support for runtime analysis and image inspection.
 */

use crate::types::*;
use crate::error::EchError;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};
use regex::Regex;
use dirs;

#[derive(Debug, Clone)]
pub struct ContainerScanner {
    config: ContainerScanConfig,
    docker_client: Option<Arc<DockerClient>>,
    k8s_client: Option<Arc<KubernetesClient>>,
    detection_patterns: Vec<ContainerPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanConfig {
    pub scan_running_containers: bool,
    pub scan_images: bool,
    pub scan_volumes: bool,
    pub scan_secrets: bool,
    pub scan_environment: bool,
    pub scan_configs: bool,
    pub docker_socket: String,
    pub kubernetes_config: Option<PathBuf>,
    pub max_concurrent_scans: usize,
    pub timeout_seconds: u64,
    pub include_system_containers: bool,
    pub target_namespaces: Vec<String>,
}

#[derive(Debug)]
struct DockerClient {
    endpoint: String,
    api_version: String,
}

#[derive(Debug)]
struct KubernetesClient {
    config_path: Option<PathBuf>,
    current_context: String,
}

#[derive(Debug, Clone)]
pub struct ContainerPattern {
    pub name: String,
    pub pattern: String,
    pub locations: Vec<ContainerLocation>,
    pub risk_level: RiskLevel,
    pub credential_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerLocation {
    Environment,
    Volume,
    ConfigMap,
    Secret,
    Image,
    ProcessMemory,
    Filesystem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanResult {
    pub container_info: ContainerInfo,
    pub credentials_found: Vec<ContainerCredential>,
    pub vulnerabilities: Vec<ContainerVulnerability>,
    pub compliance_issues: Vec<ComplianceIssue>,
    pub scan_metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub runtime: ContainerRuntime,
    pub status: String,
    pub namespace: Option<String>,
    pub labels: HashMap<String, String>,
    pub ports: Vec<ContainerPort>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerRuntime {
    Docker,
    Podman,
    Containerd,
    Kubernetes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPort {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerCredential {
    pub credential_type: String,
    pub value: String, // Masked
    pub location: ContainerLocation,
    pub source: String,
    pub confidence: f64,
    pub risk_assessment: RiskAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerVulnerability {
    pub cve_id: Option<String>,
    pub severity: String,
    pub description: String,
    pub affected_component: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceIssue {
    pub framework: String, // CIS, SOC2, etc.
    pub rule_id: String,
    pub description: String,
    pub severity: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub exposure_level: String,
    pub impact_rating: u8, // 1-10
    pub likelihood: String,
    pub mitigations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub scan_start: u64,
    pub scan_duration: u64,
    pub scanner_version: String,
    pub patterns_used: usize,
    pub errors_encountered: Vec<String>,
}

impl Default for ContainerScanConfig {
    fn default() -> Self {
        Self {
            scan_running_containers: true,
            scan_images: false,
            scan_volumes: true,
            scan_secrets: true,
            scan_environment: true,
            scan_configs: true,
            docker_socket: "/var/run/docker.sock".to_string(),
            kubernetes_config: None,
            max_concurrent_scans: 5,
            timeout_seconds: 300, // 5 minutes
            include_system_containers: false,
            target_namespaces: vec!["default".to_string()],
        }
    }
}

impl ContainerScanner {
    pub fn new(config: ContainerScanConfig) -> Self {
        let patterns = Self::load_container_patterns();
        
        Self {
            config,
            docker_client: None,
            k8s_client: None,
            detection_patterns: patterns,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        info!("🐳 Initializing container scanner");

        // Initialize Docker client if socket exists
        if std::path::Path::new(&self.config.docker_socket).exists() {
            self.docker_client = Some(Arc::new(DockerClient {
                endpoint: self.config.docker_socket.clone(),
                api_version: "1.41".to_string(),
            }));
            info!("✅ Docker client initialized");
        } else {
            warn!("⚠️ Docker socket not found, Docker scanning disabled");
        }

        // Initialize Kubernetes client if config available
        if let Some(k8s_config) = &self.config.kubernetes_config {
            if k8s_config.exists() {
                self.k8s_client = Some(Arc::new(KubernetesClient {
                    config_path: Some(k8s_config.clone()),
                    current_context: "default".to_string(),
                }));
                info!("✅ Kubernetes client initialized");
            }
        } else {
            // Try default kubeconfig location
            let default_config = dirs::home_dir()
                .map(|home| home.join(".kube").join("config"));
                
            if let Some(config_path) = default_config {
                if config_path.exists() {
                    self.k8s_client = Some(Arc::new(KubernetesClient {
                        config_path: Some(config_path),
                        current_context: "default".to_string(),
                    }));
                    info!("✅ Kubernetes client initialized with default config");
                }
            }
        }

        info!("📊 Loaded {} container detection patterns", self.detection_patterns.len());
        Ok(())
    }

    pub async fn scan_all_containers(&self) -> Result<Vec<ContainerScanResult>> {
        info!("🔍 Starting comprehensive container scan");
        let mut results = Vec::new();

        // Scan Docker containers
        if self.docker_client.is_some() && self.config.scan_running_containers {
            let docker_results = self.scan_docker_containers().await?;
            results.extend(docker_results);
        }

        // Scan Kubernetes resources
        if self.k8s_client.is_some() {
            let k8s_results = self.scan_kubernetes_resources().await?;
            results.extend(k8s_results);
        }

        info!("✅ Container scan completed: {} results", results.len());
        Ok(results)
    }

    async fn scan_docker_containers(&self) -> Result<Vec<ContainerScanResult>> {
        info!("🐳 Scanning Docker containers");
        let mut results = Vec::new();

        // Simulate Docker container discovery and scanning
        let containers = self.discover_docker_containers().await?;
        
        for container in containers {
            match self.scan_single_container(&container).await {
                Ok(result) => results.push(result),
                Err(e) => warn!("Failed to scan container {}: {}", container.name, e),
            }
        }

        Ok(results)
    }

    async fn scan_kubernetes_resources(&self) -> Result<Vec<ContainerScanResult>> {
        info!("☸️ Scanning Kubernetes resources");
        let mut results = Vec::new();

        // Scan pods in target namespaces
        for namespace in &self.config.target_namespaces {
            let pods = self.discover_kubernetes_pods(namespace).await?;
            
            for pod in pods {
                match self.scan_kubernetes_pod(&pod, namespace).await {
                    Ok(pod_results) => results.extend(pod_results),
                    Err(e) => warn!("Failed to scan pod {}: {}", pod.name, e),
                }
            }

            // Scan secrets if enabled
            if self.config.scan_secrets {
                let secrets_results = self.scan_kubernetes_secrets(namespace).await?;
                results.extend(secrets_results);
            }

            // Scan configmaps if enabled
            if self.config.scan_configs {
                let config_results = self.scan_kubernetes_configs(namespace).await?;
                results.extend(config_results);
            }
        }

        Ok(results)
    }

    async fn discover_docker_containers(&self) -> Result<Vec<ContainerInfo>> {
        debug!("Discovering Docker containers");
        
        // Simulate Docker API call to list containers
        Ok(vec![
            ContainerInfo {
                id: "abc123def456".to_string(),
                name: "web-app".to_string(),
                image: "nginx:1.21".to_string(),
                runtime: ContainerRuntime::Docker,
                status: "running".to_string(),
                namespace: None,
                labels: {
                    let mut labels = HashMap::new();
                    labels.insert("app".to_string(), "web".to_string());
                    labels.insert("env".to_string(), "production".to_string());
                    labels
                },
                ports: vec![
                    ContainerPort {
                        container_port: 80,
                        host_port: Some(8080),
                        protocol: "tcp".to_string(),
                    }
                ],
            },
            ContainerInfo {
                id: "def789ghi012".to_string(),
                name: "database".to_string(),
                image: "postgres:13".to_string(),
                runtime: ContainerRuntime::Docker,
                status: "running".to_string(),
                namespace: None,
                labels: {
                    let mut labels = HashMap::new();
                    labels.insert("app".to_string(), "db".to_string());
                    labels.insert("env".to_string(), "production".to_string());
                    labels
                },
                ports: vec![
                    ContainerPort {
                        container_port: 5432,
                        host_port: None,
                        protocol: "tcp".to_string(),
                    }
                ],
            }
        ])
    }

    async fn discover_kubernetes_pods(&self, namespace: &str) -> Result<Vec<ContainerInfo>> {
        debug!("Discovering Kubernetes pods in namespace: {}", namespace);
        
        // Simulate kubectl get pods
        Ok(vec![
            ContainerInfo {
                id: "pod-web-abc123".to_string(),
                name: "web-deployment-7d4b6c8f9d-k2x8p".to_string(),
                image: "myapp:v1.2.3".to_string(),
                runtime: ContainerRuntime::Kubernetes,
                status: "Running".to_string(),
                namespace: Some(namespace.to_string()),
                labels: {
                    let mut labels = HashMap::new();
                    labels.insert("app".to_string(), "web".to_string());
                    labels.insert("version".to_string(), "v1.2.3".to_string());
                    labels
                },
                ports: vec![
                    ContainerPort {
                        container_port: 8080,
                        host_port: None,
                        protocol: "tcp".to_string(),
                    }
                ],
            }
        ])
    }

    async fn scan_single_container(&self, container: &ContainerInfo) -> Result<ContainerScanResult> {
        debug!("Scanning container: {}", container.name);
        
        let scan_start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let mut credentials_found = Vec::new();
        let mut vulnerabilities = Vec::new();
        let mut compliance_issues = Vec::new();
        let mut errors = Vec::new();

        // Scan environment variables
        if self.config.scan_environment {
            match self.scan_container_environment(container).await {
                Ok(env_creds) => credentials_found.extend(env_creds),
                Err(e) => errors.push(format!("Environment scan error: {}", e)),
            }
        }

        // Scan mounted volumes
        if self.config.scan_volumes {
            match self.scan_container_volumes(container).await {
                Ok(vol_creds) => credentials_found.extend(vol_creds),
                Err(e) => errors.push(format!("Volume scan error: {}", e)),
            }
        }

        // Check for security vulnerabilities
        let container_vulns = self.check_container_vulnerabilities(container).await?;
        vulnerabilities.extend(container_vulns);

        // Check compliance
        let compliance = self.check_container_compliance(container).await?;
        compliance_issues.extend(compliance);

        let scan_duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() - scan_start;

        Ok(ContainerScanResult {
            container_info: container.clone(),
            credentials_found,
            vulnerabilities,
            compliance_issues,
            scan_metadata: ScanMetadata {
                scan_start,
                scan_duration,
                scanner_version: "1.0.0".to_string(),
                patterns_used: self.detection_patterns.len(),
                errors_encountered: errors,
            },
        })
    }

    async fn scan_container_environment(&self, container: &ContainerInfo) -> Result<Vec<ContainerCredential>> {
        debug!("Scanning environment variables for container: {}", container.name);
        
        // Simulate reading container environment
        let env_vars = self.get_container_environment(container).await?;
        let mut credentials = Vec::new();

        for (key, value) in env_vars {
            for pattern in &self.detection_patterns {
                if pattern.locations.contains(&ContainerLocation::Environment) {
                    if let Ok(regex) = Regex::new(&pattern.pattern) {
                        if regex.is_match(&value) {
                            credentials.push(ContainerCredential {
                                credential_type: pattern.credential_type.clone(),
                                value: self.mask_credential(&value),
                                location: ContainerLocation::Environment,
                                source: format!("env:{}", key),
                                confidence: 0.90,
                                risk_assessment: RiskAssessment {
                                    exposure_level: "High".to_string(),
                                    impact_rating: 8,
                                    likelihood: "Medium".to_string(),
                                    mitigations: vec![
                                        "Use Kubernetes secrets".to_string(),
                                        "Implement secret management".to_string(),
                                    ],
                                },
                            });
                        }
                    }
                }
            }
        }

        Ok(credentials)
    }

    async fn scan_container_volumes(&self, container: &ContainerInfo) -> Result<Vec<ContainerCredential>> {
        debug!("Scanning volumes for container: {}", container.name);
        
        // Simulate volume scanning
        let volumes = self.get_container_volumes(container).await?;
        let mut credentials = Vec::new();

        for volume_path in volumes {
            // Simulate scanning files in mounted volumes
            let volume_files = vec![
                "/etc/ssl/private/server.key".to_string(),
                "/app/config/database.yml".to_string(),
                "/secrets/api-key.txt".to_string(),
            ];

            for file_path in volume_files {
                if let Ok(content) = self.read_volume_file(&volume_path, &file_path).await {
                    for pattern in &self.detection_patterns {
                        if pattern.locations.contains(&ContainerLocation::Volume) {
                            if let Ok(regex) = Regex::new(&pattern.pattern) {
                                for capture in regex.captures_iter(&content) {
                                    if let Some(matched) = capture.get(0) {
                                        credentials.push(ContainerCredential {
                                            credential_type: pattern.credential_type.clone(),
                                            value: self.mask_credential(matched.as_str()),
                                            location: ContainerLocation::Volume,
                                            source: format!("{}:{}", volume_path, file_path),
                                            confidence: 0.95,
                                            risk_assessment: RiskAssessment {
                                                exposure_level: "Critical".to_string(),
                                                impact_rating: 9,
                                                likelihood: "High".to_string(),
                                                mitigations: vec![
                                                    "Remove from volumes".to_string(),
                                                    "Use external secret management".to_string(),
                                                ],
                                            },
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(credentials)
    }

    async fn scan_kubernetes_pod(&self, pod: &ContainerInfo, namespace: &str) -> Result<Vec<ContainerScanResult>> {
        debug!("Scanning Kubernetes pod: {} in namespace: {}", pod.name, namespace);
        
        // For simplicity, treat pod as a single container scan
        let result = self.scan_single_container(pod).await?;
        Ok(vec![result])
    }

    async fn scan_kubernetes_secrets(&self, namespace: &str) -> Result<Vec<ContainerScanResult>> {
        debug!("Scanning Kubernetes secrets in namespace: {}", namespace);
        
        // Simulate scanning secrets
        let secrets = vec![
            ("api-key-secret", "AKIA1234567890ABCDEF"),
            ("database-password", "super_secret_password123"),
            ("tls-cert", "-----BEGIN PRIVATE KEY-----"),
        ];

        let mut results = Vec::new();

        for (secret_name, secret_value) in secrets {
            let mut credentials = Vec::new();

            for pattern in &self.detection_patterns {
                if pattern.locations.contains(&ContainerLocation::Secret) {
                    if let Ok(regex) = Regex::new(&pattern.pattern) {
                        if regex.is_match(secret_value) {
                            credentials.push(ContainerCredential {
                                credential_type: pattern.credential_type.clone(),
                                value: self.mask_credential(secret_value),
                                location: ContainerLocation::Secret,
                                source: format!("secret:{}/{}", namespace, secret_name),
                                confidence: 0.98,
                                risk_assessment: RiskAssessment {
                                    exposure_level: "Medium".to_string(),
                                    impact_rating: 7,
                                    likelihood: "Low".to_string(),
                                    mitigations: vec![
                                        "Rotate secret regularly".to_string(),
                                        "Use external secrets operator".to_string(),
                                    ],
                                },
                            });
                        }
                    }
                }
            }

            if !credentials.is_empty() {
                results.push(ContainerScanResult {
                    container_info: ContainerInfo {
                        id: format!("secret-{}", secret_name),
                        name: secret_name.to_string(),
                        image: "kubernetes-secret".to_string(),
                        runtime: ContainerRuntime::Kubernetes,
                        status: "Active".to_string(),
                        namespace: Some(namespace.to_string()),
                        labels: HashMap::new(),
                        ports: Vec::new(),
                    },
                    credentials_found: credentials,
                    vulnerabilities: Vec::new(),
                    compliance_issues: Vec::new(),
                    scan_metadata: ScanMetadata {
                        scan_start: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        scan_duration: 1,
                        scanner_version: "1.0.0".to_string(),
                        patterns_used: self.detection_patterns.len(),
                        errors_encountered: Vec::new(),
                    },
                });
            }
        }

        Ok(results)
    }

    async fn scan_kubernetes_configs(&self, namespace: &str) -> Result<Vec<ContainerScanResult>> {
        debug!("Scanning Kubernetes ConfigMaps in namespace: {}", namespace);
        
        // Similar to secrets scanning but for ConfigMaps
        Ok(Vec::new())
    }

    async fn get_container_environment(&self, _container: &ContainerInfo) -> Result<HashMap<String, String>> {
        // Simulate docker inspect or kubectl describe
        let mut env = HashMap::new();
        env.insert("DATABASE_URL".to_string(), 
                  "postgresql://user:password123@db:5432/app".to_string());
        env.insert("API_KEY".to_string(), 
                  "AKIAIOSFODNN7EXAMPLE".to_string());
        env.insert("STRIPE_KEY".to_string(), 
                  "sk-test_1234567890abcdef1234567890abcdef".to_string());
        
        Ok(env)
    }

    async fn get_container_volumes(&self, _container: &ContainerInfo) -> Result<Vec<String>> {
        // Simulate getting mounted volumes
        Ok(vec![
            "/var/lib/app/data".to_string(),
            "/etc/ssl/certs".to_string(),
            "/app/config".to_string(),
        ])
    }

    async fn read_volume_file(&self, _volume_path: &str, _file_path: &str) -> Result<String> {
        // Simulate reading file from volume
        Ok("database_password: super_secret_123\napi_key: AKIAIOSFODNN7EXAMPLE".to_string())
    }

    async fn check_container_vulnerabilities(&self, container: &ContainerInfo) -> Result<Vec<ContainerVulnerability>> {
        // Simulate vulnerability scanning
        let vulns = match container.image.as_str() {
            image if image.contains("nginx:1.21") => vec![
                ContainerVulnerability {
                    cve_id: Some("CVE-2021-23017".to_string()),
                    severity: "Medium".to_string(),
                    description: "nginx resolver vulnerability".to_string(),
                    affected_component: "nginx".to_string(),
                    remediation: Some("Upgrade to nginx:1.21.1 or later".to_string()),
                }
            ],
            _ => Vec::new(),
        };

        Ok(vulns)
    }

    async fn check_container_compliance(&self, container: &ContainerInfo) -> Result<Vec<ComplianceIssue>> {
        let mut issues = Vec::new();

        // Check for privileged containers
        if container.labels.get("privileged").map_or(false, |v| v == "true") {
            issues.push(ComplianceIssue {
                framework: "CIS".to_string(),
                rule_id: "5.1".to_string(),
                description: "Container running in privileged mode".to_string(),
                severity: "High".to_string(),
                remediation: "Remove privileged: true from container configuration".to_string(),
            });
        }

        // Check for missing security context
        issues.push(ComplianceIssue {
            framework: "SOC2".to_string(),
            rule_id: "CC6.7".to_string(),
            description: "Container missing security context".to_string(),
            severity: "Medium".to_string(),
            remediation: "Add security context with non-root user".to_string(),
        });

        Ok(issues)
    }

    fn load_container_patterns() -> Vec<ContainerPattern> {
        vec![
            ContainerPattern {
                name: "AWS Access Key".to_string(),
                pattern: r"AKIA[0-9A-Z]{16}".to_string(),
                locations: vec![
                    ContainerLocation::Environment,
                    ContainerLocation::Volume,
                    ContainerLocation::ConfigMap,
                ],
                risk_level: RiskLevel::Critical,
                credential_type: "aws_access_key".to_string(),
            },
            ContainerPattern {
                name: "Database Password".to_string(),
                pattern: r#"password["']?\s*[:=]\s*["']?([^"'\s]+)"#.to_string(),
                locations: vec![
                    ContainerLocation::Environment,
                    ContainerLocation::Volume,
                    ContainerLocation::ConfigMap,
                ],
                risk_level: RiskLevel::High,
                credential_type: "database_password".to_string(),
            },
            ContainerPattern {
                name: "Private Key".to_string(),
                pattern: r"-----BEGIN.*PRIVATE KEY-----".to_string(),
                locations: vec![
                    ContainerLocation::Volume,
                    ContainerLocation::Secret,
                ],
                risk_level: RiskLevel::Critical,
                credential_type: "private_key".to_string(),
            },
            ContainerPattern {
                name: "Stripe API Key".to_string(),
                pattern: r"sk-[a-zA-Z0-9]{32}".to_string(),
                locations: vec![
                    ContainerLocation::Environment,
                    ContainerLocation::ConfigMap,
                    ContainerLocation::Secret,
                ],
                risk_level: RiskLevel::High,
                credential_type: "stripe_api_key".to_string(),
            },
        ]
    }

    fn mask_credential(&self, value: &str) -> String {
        if value.len() <= 8 {
            "*".repeat(value.len())
        } else {
            format!("{}***{}", &value[..4], &value[value.len()-4..])
        }
    }
}

/// Container scanning utilities
pub mod utils {
    use super::*;

    pub async fn quick_container_scan() -> Result<Vec<ContainerScanResult>> {
        let config = ContainerScanConfig::default();
        let mut scanner = ContainerScanner::new(config);
        scanner.initialize().await?;
        scanner.scan_all_containers().await
    }

    pub async fn kubernetes_security_audit(namespace: &str) -> Result<Vec<ContainerScanResult>> {
        let mut config = ContainerScanConfig::default();
        config.target_namespaces = vec![namespace.to_string()];
        config.scan_secrets = true;
        config.scan_configs = true;
        
        let mut scanner = ContainerScanner::new(config);
        scanner.initialize().await?;
        scanner.scan_kubernetes_resources().await
    }

    pub async fn docker_runtime_scan() -> Result<Vec<ContainerScanResult>> {
        let mut config = ContainerScanConfig::default();
        config.scan_running_containers = true;
        config.scan_volumes = true;
        config.include_system_containers = false;
        
        let mut scanner = ContainerScanner::new(config);
        scanner.initialize().await?;
        scanner.scan_docker_containers().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_container_scanner_creation() {
        let config = ContainerScanConfig::default();
        let scanner = ContainerScanner::new(config);
        assert!(!scanner.detection_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_pattern_loading() {
        let patterns = ContainerScanner::load_container_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.credential_type == "aws_access_key"));
    }

    #[test]
    fn test_credential_masking() {
        let config = ContainerScanConfig::default();
        let scanner = ContainerScanner::new(config);
        
        let masked = scanner.mask_credential("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(masked, "AKIA***MPLE");
    }
}