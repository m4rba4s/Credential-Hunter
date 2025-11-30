use enterprise_credential_hunter::core::config::EchConfig;
use enterprise_credential_hunter::core::engine::EchEngine;

#[tokio::test]
async fn archive_scan_detects_credentials() {
    let engine = EchEngine::new(EchConfig::default())
        .await
        .expect("engine init");

    // Scan only the archive to keep test targeted and fast.
    let result = engine
        .scan_filesystem(vec![
            "testdata/synthetic/archives/creds_bundle.zip".to_string()
        ])
        .await
        .expect("scan succeeds");

    assert!(
        result.summary.credentials_found > 0,
        "expected detections inside archive payload"
    );
}
