//! Integration test: run EchEngine filesystem scan over testdata/.

use enterprise_credential_hunter::core::config::EchConfig;
use enterprise_credential_hunter::core::engine::EchEngine;

#[tokio::test]
async fn engine_scans_testdata_and_finds_credentials() {
    let config = EchConfig::default();
    let engine = EchEngine::new(config).await.expect("engine init");

    let result = engine
        .scan_filesystem(vec!["testdata".to_string()])
        .await
        .expect("scan success");

    assert!(result.summary.credentials_found > 0, "no detections found");
}
