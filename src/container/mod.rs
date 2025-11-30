#[cfg(feature = "container-support")]
use crate::detection::engine::CredentialLocation;
use crate::detection::{DetectionEngine, DetectionResult};
/**
 * ECH Container Scanner Module - Container Credential Hunting
 */
#[cfg(feature = "container-support")]
use anyhow::Context;
use anyhow::Result;
use std::sync::Arc;
#[cfg(feature = "container-support")]
use tracing::info;
use tracing::warn;

#[cfg(feature = "container-support")]
use bollard::container::{InspectContainerOptions, ListContainersOptions};
#[cfg(feature = "container-support")]
use bollard::Docker;

/// Container scanner implementation
#[cfg_attr(not(feature = "container-support"), allow(dead_code))]
pub struct ContainerScanner {
    config: crate::core::config::ContainerConfig,
    #[cfg(feature = "container-support")]
    docker: Option<Docker>,
}

impl ContainerScanner {
    /// Create a new container scanner using the provided configuration.
    pub async fn new(config: crate::core::config::ContainerConfig) -> Result<Self> {
        #[cfg(feature = "container-support")]
        let docker = if config.docker_enabled {
            match Docker::connect_with_local_defaults() {
                Ok(client) => Some(client),
                Err(err) => {
                    warn!("Failed to connect to Docker daemon: {}", err);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            #[cfg(feature = "container-support")]
            docker,
        })
    }

    /// Scan every container that matches the configured runtime targets.
    pub async fn scan_all_containers(
        &self,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<Vec<DetectionResult>> {
        #[cfg(feature = "container-support")]
        {
            if !self.config.docker_enabled {
                warn!("Docker scanning disabled via configuration");
                return Ok(Vec::new());
            }

            let docker = match &self.docker {
                Some(client) => client,
                None => {
                    warn!("Docker client unavailable; skipping container scan");
                    return Ok(Vec::new());
                }
            };

            let containers = docker
                .list_containers(Some(ListContainersOptions::<String> {
                    all: true,
                    ..Default::default()
                }))
                .await
                .context("Failed to list containers")?;

            info!("Scanning {} Docker containers", containers.len());

            let mut all = Vec::new();
            for container in containers {
                if let Some(id) = container.id.clone() {
                    let mut detections = self
                        .scan_container(&id, Arc::clone(&detection_engine))
                        .await?
                        .into_iter()
                        .collect::<Vec<_>>();
                    all.append(&mut detections);
                }
            }

            return Ok(all);
        }

        #[cfg(not(feature = "container-support"))]
        {
            let _ = (detection_engine, &self.config);
            warn!("Container support not compiled in; re-run with --features container-support");
            Ok(Vec::new())
        }
    }

    /// Scan a specific container by ID.
    pub async fn scan_container(
        &self,
        container_id: &str,
        detection_engine: Arc<DetectionEngine>,
    ) -> Result<Vec<DetectionResult>> {
        #[cfg(feature = "container-support")]
        {
            if !self.config.docker_enabled {
                return Ok(Vec::new());
            }

            let docker = match &self.docker {
                Some(client) => client,
                None => {
                    warn!(
                        "Docker client unavailable; skipping container {}",
                        container_id
                    );
                    return Ok(Vec::new());
                }
            };

            let inspect = docker
                .inspect_container(container_id, None::<InspectContainerOptions>)
                .await
                .with_context(|| format!("Failed to inspect container {}", container_id))?;

            let mut detections = Vec::new();

            if self.config.scan_environment {
                if let Some(config) = &inspect.config {
                    if let Some(env) = &config.env {
                        for env_entry in env {
                            let (key, value) = split_env(env_entry);
                            detections.extend(
                                detect_string(&detection_engine, container_id, "env", &key, &value)
                                    .await?,
                            );
                        }
                    }

                    if let Some(cmd) = &config.cmd {
                        let joined = cmd.join(" ");
                        detections.extend(
                            detect_string(
                                &detection_engine,
                                container_id,
                                "command",
                                "argv",
                                &joined,
                            )
                            .await?,
                        );
                    }

                    if let Some(labels) = &config.labels {
                        for (key, value) in labels {
                            detections.extend(
                                detect_string(&detection_engine, container_id, "label", key, value)
                                    .await?,
                            );
                        }
                    }
                }
            }

            Ok(detections)
        }

        #[cfg(not(feature = "container-support"))]
        {
            let _ = (container_id, detection_engine, &self.config);
            warn!("Container support not compiled in; skipping container scan");
            Ok(Vec::new())
        }
    }
}

#[cfg(feature = "container-support")]
async fn detect_string(
    detection_engine: &DetectionEngine,
    container_ref: &str,
    source: &str,
    key: &str,
    value: &str,
) -> Result<Vec<DetectionResult>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }

    let location = CredentialLocation {
        source_type: format!("container_{}", source),
        path: format!("{}:{}", container_ref, key),
        line_number: None,
        column: None,
        memory_address: None,
        process_id: None,
        container_id: Some(container_ref.to_string()),
    };

    detection_engine
        .detect_in_text(value, location)
        .await
        .context("container text detection failed")
}

#[cfg(feature = "container-support")]
#[allow(dead_code)]
fn split_env(entry: &str) -> (String, String) {
    match entry.split_once('=') {
        Some((key, value)) => (key.to_string(), value.to_string()),
        None => (entry.to_string(), String::new()),
    }
}

#[cfg(all(test, feature = "container-support"))]
mod tests {
    use super::split_env;

    #[test]
    fn splits_environment_pairs() {
        assert_eq!(split_env("KEY=value"), ("KEY".into(), "value".into()));
        assert_eq!(split_env("EMPTY="), ("EMPTY".into(), String::new()));
        assert_eq!(split_env("NO_EQUAL"), ("NO_EQUAL".into(), String::new()));
    }
}
