/**
 * ECH Core Scheduler Module
 */
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Default, Clone)]
/// Snapshot of the task scheduler state.
pub struct SchedulerSnapshot {
    /// Number of worker threads available.
    pub worker_threads: usize,
    /// Number of currently running tasks.
    pub running_tasks: u64,
    /// Total completed tasks.
    pub completed_tasks: u64,
    /// Recently scheduled operations.
    pub recent_operations: Vec<String>,
}

/// Minimal cooperative task scheduler for long-running scans.
pub struct TaskScheduler {
    worker_threads: usize,
    running_tasks: AtomicU64,
    completed_tasks: AtomicU64,
    recent_operations: Mutex<VecDeque<String>>,
}

impl TaskScheduler {
    /// Create a new scheduler with the given worker budget.
    pub fn new(worker_threads: usize) -> Result<Self> {
        Ok(Self {
            worker_threads: worker_threads.max(1),
            running_tasks: AtomicU64::new(0),
            completed_tasks: AtomicU64::new(0),
            recent_operations: Mutex::new(VecDeque::with_capacity(16)),
        })
    }

    /// Record the start of an operation.
    pub fn record_start(&self, operation_id: Uuid, operation_type: &str) {
        self.running_tasks.fetch_add(1, Ordering::Relaxed);
        let mut ops = self.recent_operations.lock().unwrap();
        if ops.len() == 16 {
            ops.pop_front();
        }
        ops.push_back(format!("{}:{}", operation_type, operation_id));
    }

    /// Record the completion of an operation.
    pub fn record_completion(&self, _operation_id: Uuid) {
        self.running_tasks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            })
            .ok();
        self.completed_tasks.fetch_add(1, Ordering::Relaxed);
    }

    /// Capture a snapshot of the scheduler state.
    pub fn snapshot(&self) -> SchedulerSnapshot {
        let ops = self.recent_operations.lock().unwrap();
        SchedulerSnapshot {
            worker_threads: self.worker_threads,
            running_tasks: self.running_tasks.load(Ordering::Relaxed),
            completed_tasks: self.completed_tasks.load(Ordering::Relaxed),
            recent_operations: ops.iter().cloned().collect(),
        }
    }
}
