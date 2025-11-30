use enterprise_credential_hunter::core::config::EchConfig;
use enterprise_credential_hunter::core::engine::EchEngine;
use enterprise_credential_hunter::detection::engine::{
    CredentialLocation, DetectionConfig as EngineDetectionConfig,
};
use enterprise_credential_hunter::detection::CredentialType;
use enterprise_credential_hunter::filesystem::{filters::FileFilter, FilesystemConfig};
use enterprise_credential_hunter::DetectionEngine;
use std::path::Path;

#[tokio::test]
async fn detects_pkcs12_and_pfx_bundles() {
    let file_filter = FileFilter::new(&FilesystemConfig::default()).expect("filter init");
    assert!(
        file_filter.should_scan_file(Path::new("testdata/synthetic/tls/client_auth.p12")),
        "file filter should include .p12 fixtures"
    );
    assert!(
        file_filter.should_scan_file(Path::new("testdata/synthetic/tls/legacy_keystore.pfx")),
        "file filter should include .pfx fixtures"
    );

    let detection_engine = DetectionEngine::new(EngineDetectionConfig::default())
        .await
        .expect("detection engine init");
    let path_text = "testdata/synthetic/tls/client_auth.p12";
    let direct_hits = detection_engine
        .detect_in_text(path_text, credential_location(path_text))
        .await
        .expect("direct detection");
    assert!(
        direct_hits
            .iter()
            .any(|hit| hit.credential_type == CredentialType::Pkcs12Bundle),
        "direct detection engine lookup should flag pkcs12 path"
    );

    let engine = EchEngine::new(EchConfig::default())
        .await
        .expect("engine init");

    let result = engine
        .scan_filesystem(vec!["testdata/synthetic/tls".to_string()])
        .await
        .expect("filesystem scan should succeed");

    let pkcs12_paths: Vec<String> = result
        .detections
        .iter()
        .filter(|d| d.credential_type == CredentialType::Pkcs12Bundle)
        .map(|d| d.location.path.clone())
        .collect();

    assert!(
        pkcs12_paths.iter().any(|path| path.ends_with(".p12")),
        "expected detection for PKCS#12 (.p12) bundle path; got {:?}",
        pkcs12_paths
    );
    assert!(
        pkcs12_paths.iter().any(|path| path.ends_with(".pfx")),
        "expected detection for PFX (.pfx) bundle path; got {:?}",
        pkcs12_paths
    );
}

#[tokio::test]
async fn does_not_flag_unrelated_paths_as_pkcs12() {
    let detection_engine = DetectionEngine::new(EngineDetectionConfig::default())
        .await
        .expect("detection engine init");

    let benign_path = "logs/output.txt";
    let benign_hits = detection_engine
        .detect_in_text(benign_path, credential_location(benign_path))
        .await
        .expect("direct detection");

    assert!(
        !benign_hits
            .iter()
            .any(|hit| hit.credential_type == CredentialType::Pkcs12Bundle),
        "benign paths should not be flagged as PKCS#12"
    );
}

fn credential_location(path: &str) -> CredentialLocation {
    CredentialLocation {
        source_type: "file".to_string(),
        path: path.to_string(),
        line_number: None,
        column: None,
        memory_address: None,
        process_id: None,
        container_id: None,
    }
}
