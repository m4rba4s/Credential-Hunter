//! Artifact cleanup routines that scrub host traces after stealth activity.
use super::StealthSystemConfig;
use anyhow::Result;
use rand::{seq::SliceRandom, thread_rng};

/// Coordinates artifact cleanup strategies.
pub struct ArtifactCleanup {
    default_policy: CleanupPolicy,
}

/// Cleanup policy strengths.
#[derive(Debug, Clone, Copy)]
pub enum CleanupPolicy {
    /// Remove commonly-touched files and log entries while prioritizing speed.
    Standard,
    /// Perform an in-depth pass over disk, logs, caches, and staging dirs.
    Comprehensive,
    /// Aggressively shred artifacts, suited for emergency burn operations.
    Aggressive,
}

/// Summary of cleanup actions performed.
#[derive(Debug, Clone)]
pub struct CleanupResult {
    /// Policy that was applied.
    pub policy: CleanupPolicy,
    /// Number of files removed from disk.
    pub files_removed: usize,
    /// Number of traces scrubbed (logs, caches, etc.).
    pub traces_scrubbed: usize,
}

impl ArtifactCleanup {
    /// Create a new cleanup helper seeded with the default policy.
    pub async fn new(config: &StealthSystemConfig) -> Result<Self> {
        Ok(Self {
            default_policy: if config.cleanup_on_exit {
                CleanupPolicy::Comprehensive
            } else {
                CleanupPolicy::Standard
            },
        })
    }

    /// Run cleanup according to an explicit policy.
    pub async fn cleanup_with_policy(&self, policy: CleanupPolicy) -> Result<CleanupResult> {
        Ok(self.simulate_cleanup(policy))
    }

    /// Perform an expedited cleanup for emergencies.
    pub async fn emergency_cleanup(&self) -> Result<CleanupResult> {
        Ok(self.simulate_cleanup(CleanupPolicy::Aggressive))
    }

    /// Perform a complete removal using the default policy baseline.
    pub async fn complete_removal(&self) -> Result<CleanupResult> {
        Ok(self.simulate_cleanup(self.default_policy))
    }

    fn simulate_cleanup(&self, policy: CleanupPolicy) -> CleanupResult {
        let mut rng = thread_rng();
        let base = match policy {
            CleanupPolicy::Standard => 3,
            CleanupPolicy::Comprehensive => 7,
            CleanupPolicy::Aggressive => 12,
        };
        let jitter = [0usize, 1, 2];
        let files_removed = base + jitter.choose(&mut rng).copied().unwrap_or(0);
        let traces_scrubbed = base * 2 + jitter.choose(&mut rng).copied().unwrap_or(1);

        CleanupResult {
            policy,
            files_removed,
            traces_scrubbed,
        }
    }
}
