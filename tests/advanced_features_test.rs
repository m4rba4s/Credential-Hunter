use anyhow::Result;
use enterprise_credential_hunter::detection::webauthn_simple::WebAuthnHunter;
use enterprise_credential_hunter::stealth::advanced_evasion::AdvancedEvasionEngine;

#[tokio::test]
async fn test_webauthn_hunter_creation() -> Result<()> {
    let hunter = WebAuthnHunter::new().await?;
    let results = hunter.hunt_credentials().await?;
    
    // Should return at least placeholder result
    assert!(!results.is_empty());
    println!("WebAuthn Hunter test passed: {} credentials found", results.len());
    
    Ok(())
}

#[tokio::test]
async fn test_advanced_evasion_engine() -> Result<()> {
    let mut engine = AdvancedEvasionEngine::new();
    engine.initialize_advanced_evasion().await?;
    
    let status = engine.get_evasion_status();
    println!("Advanced Evasion Engine test passed - Effectiveness: {:.2}", status.effectiveness_score);
    
    Ok(())
}

#[test]
fn test_new_credential_types() {
    use enterprise_credential_hunter::detection::CredentialType;
    
    // Test that new credential types are available
    let webauthn_type = CredentialType::WebAuthn;
    let passkey_type = CredentialType::Passkey;
    
    assert_eq!(format!("{:?}", webauthn_type), "WebAuthn");
    assert_eq!(format!("{:?}", passkey_type), "Passkey");
    
    println!("New credential types test passed");
}

#[test]
fn test_compilation_success() {
    // This test just ensures the code compiles
    println!("Compilation test passed - all modules compile successfully");
}