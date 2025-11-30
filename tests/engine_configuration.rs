use enterprise_credential_hunter::core::config::{EchConfig, StealthMode};
use enterprise_credential_hunter::core::engine::EchEngine;

#[tokio::test]
async fn engine_components_reflect_memory_toggle() {
    let mut config = EchConfig::default();
    config.operation.memory_enabled = false;
    let engine = EchEngine::new(config).await.expect("engine init");
    let components = engine.components();
    assert!(
        !components.memory_enabled,
        "memory scanner should be disabled"
    );

    let engine = EchEngine::new(EchConfig::default())
        .await
        .expect("engine init with defaults");
    let components = engine.components();
    assert!(
        components.memory_enabled,
        "memory scanner should be enabled by default"
    );
}

#[tokio::test]
async fn engine_components_reflect_container_toggle() {
    let mut config = EchConfig::default();
    config.container.docker_enabled = false;
    config.container.podman_enabled = false;
    let engine = EchEngine::new(config).await.expect("engine init");
    let components = engine.components();
    assert!(
        !components.container_enabled,
        "container scanner should be disabled"
    );

    let engine = EchEngine::new(EchConfig::default())
        .await
        .expect("engine init with defaults");
    let components = engine.components();
    assert!(
        components.container_enabled,
        "container scanner should be enabled by default"
    );
}

#[tokio::test]
async fn engine_enables_stealth_when_configured() {
    let mut config = EchConfig::default();
    config.stealth.mode = StealthMode::High;
    let engine = EchEngine::new(config).await.expect("engine init");
    let components = engine.components();
    assert!(
        components.stealth_enabled,
        "stealth engine should be active when requested"
    );

    let engine = EchEngine::new(EchConfig::default())
        .await
        .expect("engine init with defaults");
    let components = engine.components();
    assert!(
        !components.stealth_enabled,
        "stealth engine should be disabled by default"
    );
}
