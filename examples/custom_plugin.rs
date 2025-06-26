/**
 * Example Custom Plugin for Enterprise Credential Hunter
 * 
 * This demonstrates how to create a custom credential detection plugin
 * for specific environments or proprietary credential formats.
 */

use ech_plugin::*;
use std::collections::HashMap;
use regex::Regex;
use anyhow::Result;

/// Custom plugin for detecting internal company credentials
pub struct InternalCredentialsPlugin {
    patterns: Vec<Regex>,
    config: Option<HashMap<String, String>>,
}

impl InternalCredentialsPlugin {
    pub fn new() -> Self {
        let patterns = vec![
            // Company-specific API key format: COMP_API_[32 hex chars]
            Regex::new(r"COMP_API_[A-Fa-f0-9]{32}").unwrap(),
            // Internal service tokens: SVCTKN_[base64]
            Regex::new(r"SVCTKN_[A-Za-z0-9+/=]{40,}").unwrap(),
            // Database connection strings with company format
            Regex::new(r"comp://[^:]+:[^@]+@[^/]+/\w+").unwrap(),
            // Internal certificate serial numbers
            Regex::new(r"CERT_SN_[A-Fa-f0-9]{16}").unwrap(),
        ];
        
        Self {
            patterns,
            config: None,
        }
    }
}

impl Plugin for InternalCredentialsPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "internal-credentials".to_string(),
            version: "1.0.0".to_string(),
            description: "Company-specific credential detection plugin".to_string(),
            author: "Internal Security Team".to_string(),
            capabilities: vec![
                PluginCapability::FileScanning,
                PluginCapability::MemoryScanning,
                PluginCapability::CustomPattern,
            ],
        }
    }
    
    fn initialize(&self) -> Result<()> {
        println!("🔧 Initializing Internal Credentials Plugin");
        println!("📊 Loaded {} detection patterns", self.patterns.len());
        Ok(())
    }
    
    fn execute(&self, context: &PluginContext) -> Result<PluginResult> {
        let mut credentials = Vec::new();
        let mut metadata = HashMap::new();
        
        // Get target data to scan
        let data = if let Some(target) = &context.target {
            std::fs::read_to_string(target)?
        } else {
            return Ok(PluginResult {
                success: false,
                credentials,
                metadata,
            });
        };
        
        // Scan with each pattern
        for (i, pattern) in self.patterns.iter().enumerate() {
            for capture in pattern.captures_iter(&data) {
                if let Some(matched) = capture.get(0) {
                    let credential_type = match i {
                        0 => "company_api_key",
                        1 => "service_token", 
                        2 => "database_connection",
                        3 => "certificate_serial",
                        _ => "unknown_internal",
                    };
                    
                    credentials.push(DetectedCredential {
                        credential_type: credential_type.to_string(),
                        value: self.mask_credential(matched.as_str()),
                        location: format!("offset:{}", matched.start()),
                        confidence: self.calculate_confidence(matched.as_str(), i),
                    });
                }
            }
        }
        
        // Add plugin metadata
        metadata.insert("plugin_version".to_string(), "1.0.0".to_string());
        metadata.insert("scan_time".to_string(), 
                       std::time::SystemTime::now()
                           .duration_since(std::time::UNIX_EPOCH)
                           .unwrap()
                           .as_secs()
                           .to_string());
        metadata.insert("patterns_used".to_string(), self.patterns.len().to_string());
        
        Ok(PluginResult {
            success: true,
            credentials,
            metadata,
        })
    }
    
    fn cleanup(&self) -> Result<()> {
        println!("🧹 Cleaning up Internal Credentials Plugin");
        Ok(())
    }
}

impl InternalCredentialsPlugin {
    /// Mask sensitive parts of detected credentials
    fn mask_credential(&self, value: &str) -> String {
        if value.len() <= 8 {
            "*".repeat(value.len())
        } else {
            format!("{}***{}", &value[..4], &value[value.len()-4..])
        }
    }
    
    /// Calculate confidence based on pattern type and context
    fn calculate_confidence(&self, value: &str, pattern_index: usize) -> f64 {
        let base_confidence = match pattern_index {
            0 => 0.95, // Company API key - very specific format
            1 => 0.90, // Service token - company prefix
            2 => 0.85, // DB connection - could be test data
            3 => 0.80, // Certificate serial - might be documentation
            _ => 0.50,
        };
        
        // Adjust based on context clues
        let mut confidence = base_confidence;
        
        // Lower confidence for obvious test/example data
        if value.to_lowercase().contains("test") || 
           value.to_lowercase().contains("example") ||
           value.to_lowercase().contains("demo") {
            confidence *= 0.6;
        }
        
        // Higher confidence for production-like patterns
        if value.to_lowercase().contains("prod") ||
           value.to_lowercase().contains("live") {
            confidence = (confidence * 1.2).min(1.0);
        }
        
        confidence
    }
}

/// Example usage function
pub fn demo_custom_plugin() -> Result<()> {
    println!("🚀 ECH Custom Plugin Demo");
    
    // Create plugin instance
    let plugin = InternalCredentialsPlugin::new();
    
    // Initialize
    plugin.initialize()?;
    
    // Create test context
    let mut config = HashMap::new();
    config.insert("scan_mode".to_string(), "deep".to_string());
    
    let context = PluginContext {
        config,
        target: Some("/tmp/test_credentials.txt".to_string()),
    };
    
    // Create test file with sample credentials
    std::fs::write("/tmp/test_credentials.txt", 
        "# Test file with company credentials\n\
         COMP_API_A1B2C3D4E5F6789012345678901234567\n\
         SVCTKN_dGVzdF90b2tlbl9mb3JfZGVtb19wdXJwb3Nlcw==\n\
         comp://user:pass@db.company.com/production\n\
         CERT_SN_1234567890ABCDEF\n\
         # This is a test example: COMP_API_test123example\n"
    )?;
    
    // Execute plugin
    match plugin.execute(&context) {
        Ok(result) => {
            println!("✅ Plugin execution successful!");
            println!("📊 Found {} credentials", result.credentials.len());
            
            for cred in &result.credentials {
                println!("  🔑 Type: {} | Confidence: {:.2} | Location: {}", 
                        cred.credential_type, cred.confidence, cred.location);
                println!("      Value: {}", cred.value);
            }
            
            println!("📋 Metadata:");
            for (key, value) in &result.metadata {
                println!("      {}: {}", key, value);
            }
        }
        Err(e) => {
            println!("❌ Plugin execution failed: {}", e);
        }
    }
    
    // Cleanup
    plugin.cleanup()?;
    std::fs::remove_file("/tmp/test_credentials.txt").ok();
    
    println!("🎯 Custom plugin demo completed!");
    Ok(())
}

fn main() -> Result<()> {
    demo_custom_plugin()
}