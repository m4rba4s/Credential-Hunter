//! Stealth helpers responsible for jittered reads, anti-detection hooks, and
//! obfuscation stubs used by the memory scanner.
use anyhow::{anyhow, Context, Result};
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tracing::{debug, trace};

use super::MemoryConfig;

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const DEFAULT_JITTER_MS: u64 = 6;

/// Stealth-focused memory reader that keeps access patterns predictable and throttled.
pub struct StealthMemoryScanner {
    chunk_size: usize,
    enable_jitter: bool,
    obfuscation: MemoryObfuscation,
    log_memory_reads: bool,
}

/// Boxed anti-detection hook used to assemble runtime registries.
pub type AntiDetectionHookBox = Box<dyn AntiDetectionHook>;

/// Anti-detection helper used before sensitive memory operations.
pub struct AntiDetection {
    anti_detection_enabled: bool,
    hooks: Vec<AntiDetectionHookBox>,
}

/// Detailed report describing anti-detection triggers encountered during checks.
#[derive(Debug, Default, Clone)]
pub struct AntiDetectionReport {
    /// Whether anti-detection enforcement is active (no override in effect).
    pub enforcement_active: bool,
    /// List of triggers that fired during the evaluation.
    pub triggers: Vec<AntiDetectionTrigger>,
}

impl AntiDetectionReport {
    /// Returns true if execution should be aborted based on the gathered triggers.
    pub fn should_abort(&self) -> bool {
        self.enforcement_active && !self.triggers.is_empty()
    }

    fn push_trigger(&mut self, trigger: AntiDetectionTrigger) {
        self.triggers.push(trigger);
    }
}

/// Individual anti-detection trigger describing a single guardrail hit.
#[derive(Debug, Clone)]
pub struct AntiDetectionTrigger {
    /// Identifier for the trigger.
    pub name: &'static str,
    /// Human-readable description of the event.
    pub description: String,
}

/// Trait implemented by platform-specific anti-detection hooks.
pub trait AntiDetectionHook: Send + Sync {
    /// Stable identifier for logging and telemetry.
    fn name(&self) -> &'static str;
    /// Run the hook and convert any findings into trigger metadata.
    fn evaluate(&self) -> Result<Vec<AntiDetectionTrigger>>;
}

/// Lightweight metadata about the obfuscation strategy applied to reads.
#[derive(Debug, Clone)]
pub struct MemoryObfuscation {
    enabled: bool,
    strategy: &'static str,
}

impl MemoryObfuscation {
    /// Construct a new obfuscation descriptor based on the stealth flag.
    pub fn new(stealth_mode: bool) -> Self {
        let strategy = if stealth_mode {
            "timing_jitter"
        } else {
            "disabled"
        };

        Self {
            enabled: stealth_mode,
            strategy,
        }
    }

    /// Whether obfuscation is currently active.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Short human-readable descriptor for logging/telemetry.
    pub fn strategy(&self) -> &'static str {
        self.strategy
    }
}

#[cfg(target_os = "linux")]
struct TracerPidHook;

#[cfg(target_os = "linux")]
impl AntiDetectionHook for TracerPidHook {
    fn name(&self) -> &'static str {
        "tracer_pid"
    }

    fn evaluate(&self) -> Result<Vec<AntiDetectionTrigger>> {
        let mut triggers = Vec::new();

        let status = match std::fs::read_to_string("/proc/self/status") {
            Ok(content) => content,
            Err(_) => return Ok(triggers),
        };

        if let Some(tracer_line) = status.lines().find(|line| line.starts_with("TracerPid:")) {
            if let Some(pid_str) = tracer_line.split_whitespace().nth(1) {
                if let Ok(tracer_pid) = pid_str.parse::<u32>() {
                    if tracer_pid != 0 {
                        triggers.push(AntiDetectionTrigger {
                            name: self.name(),
                            description: format!(
                                "Debugger or tracer detected (pid {})",
                                tracer_pid
                            ),
                        });
                    }
                }
            }
        }

        Ok(triggers)
    }
}

#[cfg(target_os = "linux")]
struct LdPreloadHook;

#[cfg(target_os = "linux")]
impl AntiDetectionHook for LdPreloadHook {
    fn name(&self) -> &'static str {
        "ld_preload"
    }

    fn evaluate(&self) -> Result<Vec<AntiDetectionTrigger>> {
        let mut triggers = Vec::new();
        if let Ok(preload) = std::env::var("LD_PRELOAD") {
            let value = preload.trim();
            if !value.is_empty() {
                triggers.push(AntiDetectionTrigger {
                    name: self.name(),
                    description: format!("Suspicious LD_PRELOAD configured: {}", value),
                });
            }
        }
        Ok(triggers)
    }
}

#[cfg(target_os = "linux")]
struct ContainerCgroupHook;

#[cfg(target_os = "linux")]
impl AntiDetectionHook for ContainerCgroupHook {
    fn name(&self) -> &'static str {
        "container_cgroup"
    }

    fn evaluate(&self) -> Result<Vec<AntiDetectionTrigger>> {
        let mut triggers = Vec::new();
        let content = match std::fs::read_to_string("/proc/self/cgroup") {
            Ok(data) => data,
            Err(_) => return Ok(triggers),
        };

        let patterns = ["docker", "lxc", "kubepods", "containerd"];
        if patterns.iter().any(|marker| content.contains(marker)) {
            triggers.push(AntiDetectionTrigger {
                name: self.name(),
                description: "Process appears to run inside a containerized cgroup; anti-detection strategies may be active".to_string(),
            });
        }

        Ok(triggers)
    }
}

impl StealthMemoryScanner {
    /// Build a stealth-aware memory reader from the provided configuration.
    pub async fn new(config: &MemoryConfig) -> Result<Self> {
        let chunk_size = config
            .pattern_cache_size
            .max(MIN_CHUNK_SIZE)
            .min(DEFAULT_CHUNK_SIZE * 4);
        let obfuscation = MemoryObfuscation::new(config.stealth_mode);

        debug!(
            stealth_mode = config.stealth_mode,
            strategy = obfuscation.strategy(),
            obfuscation_enabled = obfuscation.enabled(),
            "Initialized stealth memory scanner"
        );

        Ok(Self {
            chunk_size,
            enable_jitter: config.stealth_mode,
            obfuscation,
            log_memory_reads: config.log_memory_reads,
        })
    }

    /// Perform a jittered memory read that keeps access patterns low-noise.
    pub async fn read_memory_stealthy(
        &self,
        pid: u32,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        #[cfg(target_os = "linux")]
        {
            let chunk_size = self.chunk_size;
            let enable_jitter =
                self.enable_jitter && std::env::var("ECH_DISABLE_STEALTH_JITTER").is_err();
            let obfuscation_strategy = self.obfuscation.strategy();

            // Reading /proc/<pid>/mem is blocking; offload to a blocking worker to avoid stalling the async runtime.
            let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                let mem_path = format!("/proc/{}/mem", pid);
                let file = OpenOptions::new()
                    .read(true)
                    .open(&mem_path)
                    .with_context(|| format!("failed to open {}", mem_path))?;

                let mut buffer = vec![0u8; size];
                let mut read_total = 0usize;

                while read_total < size {
                    let to_read = (size - read_total).min(chunk_size);

                    let result = unsafe {
                        libc::pread(
                            file.as_raw_fd(),
                            buffer[read_total..read_total + to_read].as_mut_ptr()
                                as *mut libc::c_void,
                            to_read,
                            (address + read_total as u64) as libc::off_t,
                        )
                    };

                    if result < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(anyhow!(err).context("pread failed"));
                    }

                    if result == 0 {
                        break; // Reached unmapped memory – stop here.
                    }

                    read_total += result as usize;

                    if enable_jitter {
                        trace!(
                            strategy = obfuscation_strategy,
                            "Applying jitter between memory chunks"
                        );
                        std::thread::sleep(Duration::from_millis(DEFAULT_JITTER_MS));
                    }
                }

                buffer.truncate(read_total);
                Ok(buffer)
            })
            .await??;

            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }

        // Fallback: use the generic process manager implementation.
        let manager = super::process::ProcessManager::new(self.log_memory_reads)
            .await
            .context("failed to construct process manager for stealth read")?;
        manager
            .read_process_memory(pid, address, size)
            .await
            .context("process memory read fallback failed")
    }
}

impl AntiDetection {
    /// Construct the anti-detection controller and register built-in hooks.
    pub async fn new(config: &MemoryConfig) -> Result<Self> {
        let mut instance = Self {
            anti_detection_enabled: config.anti_detection,
            hooks: Vec::new(),
        };

        #[cfg(target_os = "linux")]
        {
            instance.register_hook(Box::new(TracerPidHook));
            instance.register_hook(Box::new(LdPreloadHook));
            instance.register_hook(Box::new(ContainerCgroupHook));
        }

        Ok(instance)
    }

    /// Add a custom anti-detection hook at runtime.
    pub fn register_hook(&mut self, hook: AntiDetectionHookBox) {
        self.hooks.push(hook);
    }

    /// Evaluate all hooks and aggregate their triggers into a report.
    pub async fn check_environment(&self) -> Result<AntiDetectionReport> {
        let enforcement_active =
            self.anti_detection_enabled && std::env::var("ECH_DISABLE_ANTI_DEBUG").is_err();

        if !self.anti_detection_enabled {
            return Ok(AntiDetectionReport {
                enforcement_active,
                ..AntiDetectionReport::default()
            });
        }

        if !enforcement_active {
            return Ok(AntiDetectionReport {
                enforcement_active,
                ..AntiDetectionReport::default()
            });
        }

        let mut report = AntiDetectionReport {
            enforcement_active,
            ..AntiDetectionReport::default()
        };

        for hook in &self.hooks {
            match hook.evaluate() {
                Ok(triggers) => {
                    for trigger in triggers {
                        report.push_trigger(trigger);
                    }
                }
                Err(e) => {
                    report.push_trigger(AntiDetectionTrigger {
                        name: hook.name(),
                        description: format!("Hook error: {}", e),
                    });
                }
            }
        }

        Ok(report)
    }
}
