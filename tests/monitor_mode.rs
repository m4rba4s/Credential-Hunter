use std::sync::Arc;
use std::time::Duration;

use enterprise_credential_hunter::core::config::EchConfig;
use enterprise_credential_hunter::core::engine::EchEngine;
use tempfile::tempdir;
use tokio::sync::oneshot;

#[tokio::test]
async fn monitor_detects_new_secret_file() {
    let mut config = EchConfig::default();
    config.filesystem.real_time_monitoring = true;
    config.filesystem.scan_hidden = true;
    config.operation.dry_run = true; // keep monitoring side-effect free for the test
    config.remediation.create_backups = false;

    let remediation_dirs = tempdir().expect("remediation dirs");
    let remediation_root = remediation_dirs.path();
    config.remediation.backup_directory = remediation_root.join("backups");
    config.remediation.quarantine_directory = remediation_root.join("quarantine");

    let engine = Arc::new(EchEngine::new(config).await.expect("engine init"));
    let initial_session = engine.session_snapshot().await;
    let baseline_credentials = initial_session.credentials_found;

    let dir = tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let monitor_engine = Arc::clone(&engine);
    let monitor_target = dir_path.clone();
    let monitor_task = tokio::spawn(async move {
        monitor_engine
            .start_monitoring_until(
                vec![monitor_target.to_string_lossy().into_owned()],
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
    });

    // Give the watcher a brief moment to attach
    tokio::time::sleep(Duration::from_millis(200)).await;

    let secret_file = dir_path.join("fresh_secrets.env");
    tokio::fs::write(&secret_file, b"PASSWORD=supersecretvalue\n")
        .await
        .expect("write secret file");

    let mut detected = false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let snapshot = engine.session_snapshot().await;
        if snapshot.credentials_found > baseline_credentials {
            detected = true;
            break;
        }
    }

    let _ = shutdown_tx.send(());
    let monitor_result = monitor_task.await.expect("monitor task join");
    monitor_result.expect("monitor task success");

    assert!(detected, "monitoring failed to detect the new secret file");
}
