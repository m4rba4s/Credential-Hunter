use enterprise_credential_hunter::detection::{
    CredentialLocation, DetectionConfig, DetectionEngine,
};
use tokio::fs;

#[tokio::test]
async fn synthetic_fixture_detection() {
    let engine = DetectionEngine::new(DetectionConfig::default())
        .await
        .expect("detection engine");

    let fixtures = [
        "testdata/synthetic/aws_and_github.env",
        "testdata/synthetic/pipeline_dump.txt",
        "testdata/synthetic/cloud_bundle.env",
        "testdata/synthetic/logs/siem_pipeline.log",
        "testdata/synthetic/db/dump.sql",
        "testdata/synthetic/containers/kubeconfig.yaml",
        "testdata/synthetic/containers/kube-secret.yaml",
        "testdata/synthetic/docker/config.json",
        "testdata/synthetic/containers/docker-compose.yaml",
        "testdata/synthetic/memory/memory_strings.txt",
        "testdata/synthetic/archive_payload/env_vars.env",
        "testdata/synthetic/archive_payload/config.yaml",
        "testdata/synthetic/archive_payload/keys/private.pem",
        "testdata/synthetic/tls/tls_manifest.yaml",
    ];

    for fixture in fixtures {
        let content = fs::read_to_string(fixture)
            .await
            .unwrap_or_else(|e| panic!("failed to read {}: {}", fixture, e));
        let location = CredentialLocation {
            source_type: "file".to_string(),
            path: fixture.to_string(),
            line_number: None,
            column: None,
            memory_address: None,
            process_id: None,
            container_id: None,
        };

        let detections = engine
            .detect_in_text(&content, location)
            .await
            .unwrap_or_else(|e| panic!("detection failed for {}: {}", fixture, e));
        assert!(
            !detections.is_empty(),
            "expected detections in synthetic fixture {}",
            fixture
        );
    }
}
