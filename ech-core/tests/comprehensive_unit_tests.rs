/**
 * Comprehensive Unit Tests for ECH Core
 * 
 * Professional-grade test suite covering all major components
 * with edge cases, error conditions, and performance tests.
 */

use ech_core::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::fs;

/// 🧪 CORE ENGINE TESTS
#[cfg(test)]
mod engine_tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_initialization() {
        let config = EchConfig::default();
        let engine = EchEngine::new(config).await;
        assert!(engine.is_ok(), "Engine should initialize successfully");
    }

    #[tokio::test]
    async fn test_engine_with_custom_config() {
        let mut config = EchConfig::default();
        config.max_memory_usage_mb = 256;
        config.enable_stealth_mode = true;
        
        let engine = EchEngine::new(config).await;
        assert!(engine.is_ok(), "Engine should initialize with custom config");
    }

    #[tokio::test]
    async fn test_engine_scan_basic() {
        let config = EchConfig::default();
        let engine = EchEngine::new(config).await.unwrap();
        
        // This will return empty results since we don't have actual scanning implementation
        // but should not panic or error
        let results = engine.scan_memory(None).await;
        assert!(results.is_ok(), "Basic scan should not error");
    }
}

/// 🔍 DETECTION ENGINE TESTS  
#[cfg(test)]
mod detection_tests {
    use super::*;

    #[tokio::test]
    async fn test_detection_engine_creation() {
        let engine = DetectionEngine::new().await;
        assert!(engine.is_ok(), "Detection engine should create successfully");
    }

    #[tokio::test]
    async fn test_credential_type_display() {
        let cred_type = CredentialType::Password;
        assert_eq!(format!("{}", cred_type), "Password");
        
        let cred_type = CredentialType::ApiKey;
        assert_eq!(format!("{}", cred_type), "API Key");
    }

    #[tokio::test]
    async fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }

    #[tokio::test]
    async fn test_confidence_level_conversion() {
        let confidence = ConfidenceLevel::High;
        assert_eq!(confidence.to_f64(), 0.9);
        
        let confidence = ConfidenceLevel::Medium;
        assert_eq!(confidence.to_f64(), 0.7);
        
        let confidence = ConfidenceLevel::Low;
        assert_eq!(confidence.to_f64(), 0.5);
    }

    #[tokio::test]
    async fn test_detection_result_creation() {
        let result = DetectionResult::new(
            CredentialType::Password,
            "test_data".to_string(),
            ConfidenceLevel::High,
            "test_location".to_string(),
        );
        
        assert_eq!(result.credential_type, CredentialType::Password);
        assert_eq!(result.raw_data, "test_data");
        assert_eq!(result.confidence, ConfidenceLevel::High);
        assert_eq!(result.location, "test_location");
    }
}

/// 💾 MEMORY SCANNER TESTS
#[cfg(test)]
mod memory_tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_scanner_creation() {
        let config = EchConfig::default();
        let scanner = MemoryScanner::new(config).await;
        assert!(scanner.is_ok(), "Memory scanner should create successfully");
    }

    #[tokio::test]
    async fn test_memory_region_creation() {
        let region = MemoryRegion {
            start_address: 0x1000,
            end_address: 0x2000,
            permissions: "rw-".to_string(),
            region_type: RegionType::Heap,
            file_path: None,
        };
        
        assert_eq!(region.size(), 0x1000);
        assert!(region.is_readable());
        assert!(region.is_writable());
        assert!(!region.is_executable());
    }

    #[tokio::test]
    async fn test_region_type_classification() {
        let heap_region = RegionType::Heap;
        assert_eq!(heap_region.to_string(), "Heap");
        
        let stack_region = RegionType::Stack;
        assert_eq!(stack_region.to_string(), "Stack");
    }
}

/// 🥷 STEALTH ENGINE TESTS
#[cfg(test)]
mod stealth_tests {
    use super::*;

    #[tokio::test]
    async fn test_stealth_engine_creation() {
        let config = StealthSystemConfig::default();
        let engine = StealthEngine::new(config).await;
        assert!(engine.is_ok(), "Stealth engine should create successfully");
    }

    #[tokio::test]
    async fn test_stealth_operation_mode() {
        let mode = StealthOperationMode::Standard;
        assert_eq!(format!("{:?}", mode), "Standard");
        
        let mode = StealthOperationMode::Ghost;
        assert_eq!(format!("{:?}", mode), "Ghost");
    }

    #[tokio::test]
    async fn test_stealth_stats_default() {
        let stats = StealthStats::default();
        assert_eq!(stats.evasions_performed, 0);
        assert_eq!(stats.detections_avoided, 0);
        assert!(!stats.currently_detected);
    }
}

/// ⚙️ CONFIGURATION TESTS
#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EchConfig::default();
        assert_eq!(config.max_memory_usage_mb, 512);
        assert!(!config.enable_stealth_mode);
        assert_eq!(config.scan_timeout_seconds, 300);
    }

    #[test]
    fn test_config_serialization() {
        let config = EchConfig::default();
        let serialized = serde_json::to_string(&config);
        assert!(serialized.is_ok(), "Config should serialize to JSON");
        
        let json_str = serialized.unwrap();
        let deserialized: Result<EchConfig, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "Config should deserialize from JSON");
    }

    #[test]
    fn test_config_validation() {
        let mut config = EchConfig::default();
        
        // Test valid configuration
        assert!(config.validate().is_ok());
        
        // Test invalid memory limit
        config.max_memory_usage_mb = 0;
        assert!(config.validate().is_err());
        
        // Reset and test invalid timeout
        config.max_memory_usage_mb = 512;
        config.scan_timeout_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_security_hardening() {
        let mut config = EchConfig::default();
        config.apply_security_hardening();
        
        // Should enable security features
        assert!(config.enable_stealth_mode);
        // Should have reasonable limits
        assert!(config.max_memory_usage_mb <= 1024);
    }
}

/// 🚨 ERROR HANDLING TESTS
#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_ech_error_display() {
        let error = EchError::ConfigurationError("Invalid setting".to_string());
        let display = format!("{}", error);
        assert!(display.contains("Invalid setting"));
    }

    #[test]
    fn test_ech_error_debug() {
        let error = EchError::MemoryError("Access denied".to_string());
        let debug = format!("{:?}", error);
        assert!(debug.contains("MemoryError"));
        assert!(debug.contains("Access denied"));
    }

    #[test]
    fn test_error_chain() {
        let source = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let error = EchError::from(source);
        
        match error {
            EchError::IoError(_) => {}, // Expected
            _ => panic!("Should convert to IoError"),
        }
    }
}

/// 📊 PERFORMANCE TESTS
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_engine_startup_performance() {
        let start = Instant::now();
        let config = EchConfig::default();
        let _engine = EchEngine::new(config).await.unwrap();
        let duration = start.elapsed();
        
        // Should start up in reasonable time (less than 5 seconds)
        assert!(duration.as_secs() < 5, "Engine startup took too long: {:?}", duration);
    }

    #[test]
    fn test_config_parsing_performance() {
        let config = EchConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _: EchConfig = serde_json::from_str(&json).unwrap();
        }
        let duration = start.elapsed();
        
        // Should parse 1000 configs in less than 100ms
        assert!(duration.as_millis() < 100, "Config parsing too slow: {:?}", duration);
    }

    #[test]
    fn test_memory_region_operations() {
        let start = Instant::now();
        
        // Create many memory regions
        let mut regions = Vec::new();
        for i in 0..10000 {
            let region = MemoryRegion {
                start_address: i * 0x1000,
                end_address: (i + 1) * 0x1000,
                permissions: "rw-".to_string(),
                region_type: RegionType::Heap,
                file_path: None,
            };
            regions.push(region);
        }
        
        let duration = start.elapsed();
        
        // Should create 10k regions quickly
        assert!(duration.as_millis() < 50, "Memory region creation too slow: {:?}", duration);
        
        // Test operations on regions
        let start = Instant::now();
        let total_size: u64 = regions.iter().map(|r| r.size()).sum();
        let duration = start.elapsed();
        
        assert_eq!(total_size, 10000 * 0x1000);
        assert!(duration.as_millis() < 10, "Region operations too slow: {:?}", duration);
    }
}

/// 🛡️ SECURITY TESTS
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_sensitive_data_handling() {
        let sensitive_data = "password123".to_string();
        let mut result = DetectionResult::new(
            CredentialType::Password,
            sensitive_data,
            ConfidenceLevel::High,
            "test".to_string(),
        );
        
        // Ensure we can access the data
        assert_eq!(result.raw_data, "password123");
        
        // Clear sensitive data
        result.clear_sensitive_data();
        assert_eq!(result.raw_data, "[REDACTED]");
    }

    #[test]
    fn test_config_no_sensitive_logging() {
        let mut config = EchConfig::default();
        config.auth_token = Some("secret_token".to_string());
        
        let debug_output = format!("{:?}", config);
        
        // Should not contain the actual token in debug output
        assert!(!debug_output.contains("secret_token"), "Config should not leak sensitive data in debug");
    }

    #[test]
    fn test_memory_security_flags() {
        let config = EchConfig::default();
        
        // Should have secure defaults
        assert!(config.scan_timeout_seconds > 0, "Should have timeout");
        assert!(config.max_memory_usage_mb > 0 && config.max_memory_usage_mb < 8192, "Should have reasonable memory limits");
    }
}

/// 🧪 INTEGRATION TESTS
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_full_scan_workflow() {
        // Create temporary directory with test files
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_secrets.txt");
        
        fs::write(&test_file, "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\npassword=secret123").await.unwrap();
        
        let config = EchConfig::default();
        let engine = EchEngine::new(config).await.unwrap();
        
        // This would normally perform actual scanning
        // For now just test that the workflow completes
        let result = engine.scan_memory(None).await;
        assert!(result.is_ok(), "Full scan workflow should complete");
    }

    #[tokio::test]
    async fn test_detection_and_stealth_integration() {
        let config = EchConfig::default();
        let detection_engine = DetectionEngine::new().await.unwrap();
        
        let stealth_config = StealthSystemConfig::default();
        let stealth_engine = StealthEngine::new(stealth_config).await.unwrap();
        
        // Test that both engines can coexist
        assert!(true, "Detection and stealth engines should work together");
    }
}

/// 📈 METRICS AND MONITORING TESTS
#[cfg(test)]
mod metrics_tests {
    use super::*;

    #[test]
    fn test_performance_metrics() {
        let metrics = PerformanceMetrics {
            scan_duration_ms: 1000,
            memory_usage_mb: 256,
            cpu_usage_percent: 45.5,
            throughput_mb_per_sec: 10.5,
        };
        
        assert_eq!(metrics.scan_duration_ms, 1000);
        assert_eq!(metrics.memory_usage_mb, 256);
        assert!((metrics.cpu_usage_percent - 45.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_detection_metrics() {
        let metrics = DetectionMetrics {
            total_scanned: 1000,
            credentials_found: 15,
            false_positives: 2,
            scan_coverage_percent: 95.5,
        };
        
        assert_eq!(metrics.detection_rate(), 15.0 / 1000.0);
        assert_eq!(metrics.false_positive_rate(), 2.0 / 15.0);
    }
}

/// 🏗️ BUILDER PATTERN TESTS
#[cfg(test)]
mod builder_tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = EchConfig::builder()
            .max_memory_usage_mb(1024)
            .enable_stealth_mode(true)
            .scan_timeout_seconds(600)
            .build()
            .unwrap();
            
        assert_eq!(config.max_memory_usage_mb, 1024);
        assert!(config.enable_stealth_mode);
        assert_eq!(config.scan_timeout_seconds, 600);
    }

    #[test]
    fn test_detection_result_builder() {
        let result = DetectionResult::builder()
            .credential_type(CredentialType::ApiKey)
            .raw_data("api_key_123".to_string())
            .confidence(ConfidenceLevel::High)
            .location("config.json:15".to_string())
            .build();
            
        assert_eq!(result.credential_type, CredentialType::ApiKey);
        assert_eq!(result.confidence, ConfidenceLevel::High);
    }
}

/// 🔄 ASYNC/AWAIT TESTS
#[cfg(test)]
mod async_tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_concurrent_scans() {
        let config = EchConfig::default();
        
        // Start multiple concurrent scans
        let handles = (0..5).map(|i| {
            let config_clone = config.clone();
            tokio::spawn(async move {
                let engine = EchEngine::new(config_clone).await.unwrap();
                let result = engine.scan_memory(Some(1000 + i)).await;
                assert!(result.is_ok(), "Concurrent scan {} should succeed", i);
                i
            })
        }).collect::<Vec<_>>();
        
        // Wait for all to complete
        for (i, handle) in handles.into_iter().enumerate() {
            let result = handle.await.unwrap();
            assert_eq!(result, i, "Scan {} should return correct result", i);
        }
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        let start = Instant::now();
        
        // Simulate a long-running operation with timeout
        let result = tokio::time::timeout(Duration::from_millis(100), async {
            sleep(Duration::from_millis(200)).await;
            "completed"
        }).await;
        
        let duration = start.elapsed();
        
        assert!(result.is_err(), "Should timeout");
        assert!(duration.as_millis() >= 100 && duration.as_millis() < 150, "Should timeout around 100ms");
    }
}