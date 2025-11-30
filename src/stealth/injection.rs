//! Process injection façade used by the stealth engine for telemetry.
use super::StealthSystemConfig;
use anyhow::Result;
use tokio::sync::RwLock;

/// Provides helpers for process injection strategies.
pub struct ProcessInjector {
    /// Strategy currently selected for injection.
    method: InjectionMethod,
    /// Target metadata guarded for concurrent updates.
    target: RwLock<InjectionTarget>,
}
/// Describes the injection method being used.
#[derive(Debug, Clone)]
pub struct InjectionMethod {
    /// Human-readable method name.
    pub name: String,
    /// Whether elevated privileges are required.
    pub requires_privilege: bool,
}
/// Describes the intended injection target.
#[derive(Debug, Clone)]
pub struct InjectionTarget {
    /// Process identifier selected for injection.
    pub pid: u32,
    /// Free-form label describing the target.
    pub description: String,
}

impl ProcessInjector {
    /// Create a process injector helper.
    pub async fn new(_config: &StealthSystemConfig) -> Result<Self> {
        Ok(Self {
            method: InjectionMethod {
                name: "thread_hijack".to_string(),
                requires_privilege: true,
            },
            target: RwLock::new(InjectionTarget {
                pid: std::process::id(),
                description: "self".to_string(),
            }),
        })
    }

    /// Prepare a remote process for injection.
    pub async fn prepare_injection_target(&self) -> Result<()> {
        let mut target = self.target.write().await;
        target.pid = std::process::id();
        target.description = "self-test".to_string();
        Ok(())
    }

    /// Retrieve the current injection method.
    pub fn method(&self) -> InjectionMethod {
        self.method.clone()
    }

    /// Snapshot the current target metadata.
    pub async fn current_target(&self) -> InjectionTarget {
        self.target.read().await.clone()
    }
}
