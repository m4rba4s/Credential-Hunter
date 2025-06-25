use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use tracing::{info, warn, debug};
use crate::detection::{DetectionResult, CredentialType, RiskLevel};

#[derive(Debug, Clone)]
pub struct WebAuthnHunter {
    config: WebAuthnConfig,
}

#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub chrome_data_paths: Vec<PathBuf>,
    pub firefox_data_paths: Vec<PathBuf>,
    pub edge_data_paths: Vec<PathBuf>,
    pub windows_hello_paths: Vec<PathBuf>,
    pub scan_depth: usize,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            chrome_data_paths: Self::get_default_chrome_paths(),
            firefox_data_paths: Self::get_default_firefox_paths(),
            edge_data_paths: Self::get_default_edge_paths(),
            windows_hello_paths: Self::get_default_windows_hello_paths(),
            scan_depth: 3,
        }
    }
}

impl WebAuthnConfig {
    fn get_default_chrome_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = std::env::var_os("LOCALAPPDATA") {
                paths.push(PathBuf::from(appdata).join("Google/Chrome/User Data"));
                paths.push(PathBuf::from(appdata).join("Google/Chrome/User Data/Default"));
                paths.push(PathBuf::from(appdata).join("Chromium/User Data"));
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                paths.push(PathBuf::from(home).join("Library/Application Support/Google/Chrome"));
                paths.push(PathBuf::from(home).join("Library/Application Support/Chromium"));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                let home_path = PathBuf::from(home);
                paths.push(home_path.join(".config/google-chrome"));
                paths.push(home_path.join(".config/chromium"));
            }
        }
        
        paths
    }
    
    fn get_default_firefox_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                paths.push(PathBuf::from(appdata).join("Mozilla/Firefox/Profiles"));
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                paths.push(PathBuf::from(home).join("Library/Application Support/Firefox/Profiles"));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                paths.push(PathBuf::from(home).join(".mozilla/firefox"));
            }
        }
        
        paths
    }
    
    fn get_default_edge_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = std::env::var_os("LOCALAPPDATA") {
                paths.push(PathBuf::from(appdata).join("Microsoft/Edge/User Data"));
                paths.push(PathBuf::from(appdata).join("Microsoft/Edge/User Data/Default"));
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                paths.push(PathBuf::from(home).join("Library/Application Support/Microsoft Edge"));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                paths.push(PathBuf::from(home).join(".config/microsoft-edge"));
            }
        }
        
        paths
    }
    
    fn get_default_windows_hello_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        #[cfg(target_os = "windows")]
        {
            // Windows Hello credential storage paths
            paths.push(PathBuf::from("C:/Windows/System32/config/systemprofile/AppData/Local/Microsoft/Vault"));
            paths.push(PathBuf::from("C:/Windows/ServiceProfiles/LocalService/AppData/Local/Microsoft/Vault"));
            
            if let Some(appdata) = std::env::var_os("LOCALAPPDATA") {
                paths.push(PathBuf::from(appdata).join("Microsoft/Vault"));
                paths.push(PathBuf::from(appdata).join("Microsoft/Credentials"));
            }
        }
        
        paths
    }
}

impl WebAuthnHunter {
    pub fn new() -> Self {
        Self {
            config: WebAuthnConfig::default(),
        }
    }
    
    pub fn with_config(config: WebAuthnConfig) -> Self {
        Self { config }
    }
    
    pub async fn hunt_credentials(&self) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        info!("Starting WebAuthn/Passkey credential hunt");
        
        // Hunt Chrome WebAuthn credentials
        for path in &self.config.chrome_data_paths {
            if let Ok(chrome_results) = self.hunt_chrome_webauthn(path).await {
                results.extend(chrome_results);
            }
        }
        
        // Hunt Firefox WebAuthn credentials
        for path in &self.config.firefox_data_paths {
            if let Ok(firefox_results) = self.hunt_firefox_webauthn(path).await {
                results.extend(firefox_results);
            }
        }
        
        // Hunt Edge WebAuthn credentials
        for path in &self.config.edge_data_paths {
            if let Ok(edge_results) = self.hunt_edge_webauthn(path).await {
                results.extend(edge_results);
            }
        }
        
        // Hunt Windows Hello credentials
        #[cfg(target_os = "windows")]
        {
            for path in &self.config.windows_hello_paths {
                if let Ok(hello_results) = self.hunt_windows_hello(path).await {
                    results.extend(hello_results);
                }
            }
        }
        
        info!("WebAuthn hunt completed, found {} credentials", results.len());
        Ok(results)
    }
    
    async fn hunt_chrome_webauthn(&self, base_path: &Path) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        if !base_path.exists() {
            debug!("Chrome path does not exist: {:?}", base_path);
            return Ok(results);
        }
        
        info!("Hunting Chrome WebAuthn credentials in: {:?}", base_path);
        
        // Look for WebAuthn database
        let webauthn_db_path = base_path.join("Web Data");
        if webauthn_db_path.exists() {
            results.extend(self.scan_chrome_web_data(&webauthn_db_path).await?);
        }
        
        // Look for Login Data database (contains some WebAuthn data)
        let login_db_path = base_path.join("Login Data");
        if login_db_path.exists() {
            results.extend(self.scan_chrome_login_data(&login_db_path).await?);
        }
        
        // Scan profile directories
        for entry in fs::read_dir(base_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() && path.file_name().unwrap_or_default().to_string_lossy().starts_with("Profile") {
                let profile_web_data = path.join("Web Data");
                if profile_web_data.exists() {
                    results.extend(self.scan_chrome_web_data(&profile_web_data).await?);
                }
                
                let profile_login_data = path.join("Login Data");
                if profile_login_data.exists() {
                    results.extend(self.scan_chrome_login_data(&profile_login_data).await?);
                }
            }
        }
        
        Ok(results)
    }
    
    async fn scan_chrome_web_data(&self, db_path: &Path) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        debug!("Scanning Chrome Web Data: {:?}", db_path);
        
        // Read database file content
        let content = fs::read(db_path)?;
        
        // Look for WebAuthn-specific patterns
        let webauthn_patterns = [
            b"webauthn",
            b"public_key",
            b"authenticator",
            b"credential_id",
            b"user_handle",
            b"rp_id",
            b"attestation",
            b"allowCredentials",
        ];
        
        for (offset, pattern) in self.scan_for_patterns(&content, &webauthn_patterns) {
            results.push(DetectionResult {
                credential_type: CredentialType::WebAuthn,
                location: format!("{}:0x{:x}", db_path.display(), offset),
                value: format!("WebAuthn pattern: {}", String::from_utf8_lossy(pattern)),
                context: format!("Chrome Web Data database"),
                risk_level: RiskLevel::High,
                metadata: std::collections::HashMap::from([
                    ("browser".to_string(), "Chrome".to_string()),
                    ("file_type".to_string(), "SQLite".to_string()),
                    ("pattern".to_string(), String::from_utf8_lossy(pattern).to_string()),
                ]),
            });
        }
        
        Ok(results)
    }
    
    async fn scan_chrome_login_data(&self, db_path: &Path) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        debug!("Scanning Chrome Login Data: {:?}", db_path);
        
        // Read database file content
        let content = fs::read(db_path)?;
        
        // Look for passkey-related patterns in login data
        let passkey_patterns = [
            b"passkey",
            b"webauthn_credential",
            b"public_key_credential",
            b"authenticator_data",
            b"client_data_json",
        ];
        
        for (offset, pattern) in self.scan_for_patterns(&content, &passkey_patterns) {
            results.push(DetectionResult {
                credential_type: CredentialType::Passkey,
                location: format!("{}:0x{:x}", db_path.display(), offset),
                value: format!("Passkey pattern: {}", String::from_utf8_lossy(pattern)),
                context: format!("Chrome Login Data database"),
                risk_level: RiskLevel::High,
                metadata: std::collections::HashMap::from([
                    ("browser".to_string(), "Chrome".to_string()),
                    ("file_type".to_string(), "SQLite".to_string()),
                    ("pattern".to_string(), String::from_utf8_lossy(pattern).to_string()),
                ]),
            });
        }
        
        Ok(results)
    }
    
    async fn hunt_firefox_webauthn(&self, base_path: &Path) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        if !base_path.exists() {
            debug!("Firefox path does not exist: {:?}", base_path);
            return Ok(results);
        }
        
        info!("Hunting Firefox WebAuthn credentials in: {:?}", base_path);
        
        // Find profile directories
        for entry in fs::read_dir(base_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                // Look for webauthn database
                let webauthn_db = path.join("webappsstore.sqlite");
                if webauthn_db.exists() {
                    results.extend(self.scan_firefox_webauthn_db(&webauthn_db).await?);
                }
                
                // Look for key database
                let key_db = path.join("key4.db");
                if key_db.exists() {
                    results.extend(self.scan_firefox_key_db(&key_db).await?);
                }
            }
        }
        
        Ok(results)
    }
    
    async fn scan_firefox_webauthn_db(&self, db_path: &Path) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        debug!("Scanning Firefox WebAuthn DB: {:?}", db_path);
        
        let content = fs::read(db_path)?;
        
        let webauthn_patterns = [
            b"webauthn",
            b"publickey",
            b"credential",
            b"navigator.credentials",
        ];
        
        for (offset, pattern) in self.scan_for_patterns(&content, &webauthn_patterns) {
            results.push(DetectionResult {
                credential_type: CredentialType::WebAuthn,
                location: format!("{}:0x{:x}", db_path.display(), offset),
                value: format!("Firefox WebAuthn: {}", String::from_utf8_lossy(pattern)),
                context: format!("Firefox WebAuthn database"),
                risk_level: RiskLevel::High,
                metadata: std::collections::HashMap::from([
                    ("browser".to_string(), "Firefox".to_string()),
                    ("file_type".to_string(), "SQLite".to_string()),
                ]),
            });
        }
        
        Ok(results)
    }
    
    async fn scan_firefox_key_db(&self, db_path: &Path) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        debug!("Scanning Firefox Key DB: {:?}", db_path);
        
        let content = fs::read(db_path)?;
        
        let key_patterns = [
            b"webauthn",
            b"fido",
            b"u2f",
            b"authenticator",
        ];
        
        for (offset, pattern) in self.scan_for_patterns(&content, &key_patterns) {
            results.push(DetectionResult {
                credential_type: CredentialType::WebAuthn,
                location: format!("{}:0x{:x}", db_path.display(), offset),
                value: format!("Firefox Key: {}", String::from_utf8_lossy(pattern)),
                context: format!("Firefox key database"),
                risk_level: RiskLevel::Medium,
                metadata: std::collections::HashMap::from([
                    ("browser".to_string(), "Firefox".to_string()),
                    ("file_type".to_string(), "SQLite".to_string()),
                ]),
            });
        }
        
        Ok(results)
    }
    
    async fn hunt_edge_webauthn(&self, base_path: &Path) -> Result<Vec<DetectionResult>> {
        // Edge uses similar structure to Chrome
        self.hunt_chrome_webauthn(base_path).await.map(|mut results| {
            // Update browser metadata
            for result in &mut results {
                result.metadata.insert("browser".to_string(), "Edge".to_string());
                result.context = result.context.replace("Chrome", "Edge");
            }
            results
        })
    }
    
    #[cfg(target_os = "windows")]
    async fn hunt_windows_hello(&self, base_path: &Path) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        if !base_path.exists() {
            debug!("Windows Hello path does not exist: {:?}", base_path);
            return Ok(results);
        }
        
        info!("Hunting Windows Hello credentials in: {:?}", base_path);
        
        // Scan for credential files
        for entry in fs::read_dir(base_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                let content = fs::read(&path)?;
                
                let hello_patterns = [
                    b"Windows Hello",
                    b"PIN",
                    b"Biometric",
                    b"TPM",
                    b"FIDO",
                    b"WebAuthn",
                    b"Microsoft Passport",
                ];
                
                for (offset, pattern) in self.scan_for_patterns(&content, &hello_patterns) {
                    results.push(DetectionResult {
                        credential_type: CredentialType::WindowsHello,
                        location: format!("{}:0x{:x}", path.display(), offset),
                        value: format!("Windows Hello: {}", String::from_utf8_lossy(pattern)),
                        context: format!("Windows Hello credential store"),
                        risk_level: RiskLevel::Critical,
                        metadata: std::collections::HashMap::from([
                            ("system".to_string(), "Windows Hello".to_string()),
                            ("file_type".to_string(), "Credential".to_string()),
                        ]),
                    });
                }
            }
        }
        
        Ok(results)
    }
    
    #[cfg(not(target_os = "windows"))]
    async fn hunt_windows_hello(&self, _base_path: &Path) -> Result<Vec<DetectionResult>> {
        Ok(Vec::new())
    }
    
    fn scan_for_patterns(&self, content: &[u8], patterns: &[&[u8]]) -> Vec<(usize, &[u8])> {
        let mut matches = Vec::new();
        
        for &pattern in patterns {
            for (i, window) in content.windows(pattern.len()).enumerate() {
                if window == pattern {
                    matches.push((i, pattern));
                }
            }
        }
        
        matches
    }
    
    pub async fn extract_webauthn_metadata(&self, db_path: &Path) -> Result<WebAuthnMetadata> {
        let content = fs::read(db_path)?;
        
        // This would be a more sophisticated parser in a real implementation
        // For now, return basic metadata
        Ok(WebAuthnMetadata {
            credential_count: self.count_webauthn_entries(&content),
            last_used: None,
            relying_parties: self.extract_relying_parties(&content),
            authenticator_types: self.extract_authenticator_types(&content),
        })
    }
    
    fn count_webauthn_entries(&self, content: &[u8]) -> usize {
        // Count potential WebAuthn entries by looking for common patterns
        let patterns = [b"webauthn", b"credential_id", b"public_key"];
        let mut count = 0;
        
        for pattern in &patterns {
            count += content.windows(pattern.len()).filter(|w| w == pattern).count();
        }
        
        count / patterns.len() // Approximate deduplication
    }
    
    fn extract_relying_parties(&self, content: &[u8]) -> Vec<String> {
        let mut rps = Vec::new();
        
        // Simple extraction - look for domain patterns after "rp_id"
        if let Ok(content_str) = String::from_utf8_lossy(content).into_owned().into() {
            // This would be more sophisticated in a real implementation
            if content_str.contains("github.com") {
                rps.push("github.com".to_string());
            }
            if content_str.contains("google.com") {
                rps.push("google.com".to_string());
            }
            if content_str.contains("microsoft.com") {
                rps.push("microsoft.com".to_string());
            }
        }
        
        rps
    }
    
    fn extract_authenticator_types(&self, content: &[u8]) -> Vec<String> {
        let mut types = Vec::new();
        
        if content.windows(b"platform".len()).any(|w| w == b"platform") {
            types.push("Platform".to_string());
        }
        
        if content.windows(b"cross-platform".len()).any(|w| w == b"cross-platform") {
            types.push("Cross-platform".to_string());
        }
        
        if content.windows(b"USB".len()).any(|w| w == b"USB") {
            types.push("USB".to_string());
        }
        
        types
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnMetadata {
    pub credential_count: usize,
    pub last_used: Option<String>,
    pub relying_parties: Vec<String>,
    pub authenticator_types: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_webauthn_hunter_creation() {
        let hunter = WebAuthnHunter::new();
        assert!(!hunter.config.chrome_data_paths.is_empty());
    }
    
    #[tokio::test]
    async fn test_pattern_scanning() {
        let hunter = WebAuthnHunter::new();
        let content = b"test webauthn credential_id data";
        let patterns = [b"webauthn", b"credential_id"];
        
        let matches = hunter.scan_for_patterns(content, &patterns);
        assert_eq!(matches.len(), 2);
    }
    
    #[tokio::test]
    async fn test_nonexistent_path() {
        let hunter = WebAuthnHunter::new();
        let fake_path = Path::new("/nonexistent/path");
        
        let results = hunter.hunt_chrome_webauthn(fake_path).await.unwrap();
        assert!(results.is_empty());
    }
}