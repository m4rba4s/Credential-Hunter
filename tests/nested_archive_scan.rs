use enterprise_credential_hunter::core::config::EchConfig;
use enterprise_credential_hunter::core::engine::EchEngine;

#[tokio::test]
async fn nested_archive_scan_detects_credentials() {
    let engine = EchEngine::new(EchConfig::default())
        .await
        .expect("engine init");

    let result = engine
        .scan_filesystem(vec![
            "testdata/synthetic/archives/nested_creds.zip".to_string()
        ])
        .await
        .expect("scan succeeds");

    assert!(
        result.summary.credentials_found > 0,
        "expected detections inside nested archive payload"
    );
}
