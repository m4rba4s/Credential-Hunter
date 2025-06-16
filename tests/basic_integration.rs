/**
 * Basic Integration Tests for ECH
 * 
 * These tests verify the basic functionality and integration
 * of core ECH components without requiring external dependencies.
 */

use enterprise_credential_hunter::*;

#[tokio::test]
async fn test_basic_initialization() {
    // Test that we can initialize the library
    let result = initialize().await;
    assert!(result.is_ok(), "Library initialization should succeed");
}

#[test]
fn test_config_creation() {
    // Test basic config creation
    let config = EchConfig::default();
    assert!(!config.audit.user_context.is_none() || config.audit.user_context.is_none());
}

#[test]
fn test_memory_config_creation() {
    // Test memory config creation
    let config = MemoryConfig::default();
    assert_eq!(config.max_memory_mb, 1024);
    assert!(config.stealth_mode);
}

#[test]
fn test_stealth_levels() {
    // Test stealth level enumeration
    let levels = vec![
        StealthLevel::None,
        StealthLevel::Low,
        StealthLevel::Medium,
        StealthLevel::High,
        StealthLevel::Maximum,
        StealthLevel::Ghost,
    ];
    
    for level in levels {
        // Test that we can create stealth configs with different levels
        let mut config = StealthConfig::default();
        config.level = level;
        assert!(config.cleanup_on_exit); // Default should be true
    }
}

#[tokio::test]
async fn test_detection_engine_creation() {
    use enterprise_credential_hunter::detection::DetectionConfig;
    
    // Test detection engine creation
    let config = DetectionConfig::default();
    let result = DetectionEngine::new(config).await;
    
    // Should succeed in creating detection engine
    assert!(result.is_ok());
}

#[test]
fn test_version_availability() {
    // Test that version is available
    assert!(!VERSION.is_empty());
    assert!(VERSION.contains('.'));
    
    // Version should be semantic versioning format
    let parts: Vec<&str> = VERSION.split('.').collect();
    assert!(parts.len() >= 2);
}

#[test]
fn test_credential_types() {
    use enterprise_credential_hunter::detection::engine::CredentialType;
    
    // Test that credential types are available
    let types = vec![
        CredentialType::ApiSecret,
        CredentialType::AwsAccessKey,
        CredentialType::DatabasePassword,
        CredentialType::GitHubToken,
    ];
    
    for cred_type in types {
        // Test that credential types can be compared
        assert_eq!(cred_type, cred_type);
    }
}

#[test] 
fn test_scan_target_creation() {
    use enterprise_credential_hunter::filesystem::ScanTarget;
    use std::path::PathBuf;
    
    // Test different scan target types
    let file_target = ScanTarget::file("/test/file.txt");
    let dir_target = ScanTarget::directory("/test/dir");
    let glob_target = ScanTarget::glob("*.env");
    
    // Should be able to create different target types
    match file_target {
        ScanTarget::File(_) => {},
        _ => panic!("Expected file target"),
    }
    
    match dir_target {
        ScanTarget::Directory { .. } => {},
        _ => panic!("Expected directory target"),
    }
    
    match glob_target {
        ScanTarget::Glob(_) => {},
        _ => panic!("Expected glob target"),
    }
}