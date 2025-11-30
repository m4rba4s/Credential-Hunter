/**
 * ECH Core Metrics Module
 */
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Default, Clone)]
/// Snapshot of cumulative engine metrics.
pub struct MetricsSnapshot {
    /// Number of operations started.
    pub operations_started: u64,
    /// Number of operations completed.
    pub operations_completed: u64,
    /// Total detections recorded.
    pub detections_recorded: u64,
    /// Total bytes processed.
    pub bytes_processed: u64,
    /// Errors encountered in the last window.
    pub last_error_count: u64,
}

#[derive(Debug, Default, Clone)]
/// Metrics captured for a single completed operation.
pub struct CompletedOperationMetrics {
    /// Detections produced by the operation.
    pub detections: u64,
    /// Bytes processed during the operation.
    pub bytes_processed: u64,
    /// Errors found while completing the operation.
    pub errors: u64,
}

/// Thread-safe metrics accumulator for the engine.
pub struct Metrics {
    operations_started: AtomicU64,
    operations_completed: AtomicU64,
    detections_recorded: AtomicU64,
    bytes_processed: AtomicU64,
    last_error_count: AtomicU64,
    last_snapshot: Mutex<MetricsSnapshot>,
}

impl Metrics {
    /// Create a new metrics accumulator.
    pub fn new() -> Self {
        Self {
            operations_started: AtomicU64::new(0),
            operations_completed: AtomicU64::new(0),
            detections_recorded: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            last_error_count: AtomicU64::new(0),
            last_snapshot: Mutex::new(MetricsSnapshot::default()),
        }
    }

    /// Record the start of an operation.
    pub fn record_operation_start(&self) {
        let started = self.operations_started.fetch_add(1, Ordering::Relaxed) + 1;
        let mut snapshot = self.last_snapshot.lock().unwrap();
        snapshot.operations_started = started;
    }

    /// Record the completion of an operation along with summary metrics.
    pub fn record_operation_completion(&self, summary: CompletedOperationMetrics) {
        let completed = self.operations_completed.fetch_add(1, Ordering::Relaxed) + 1;
        let detections = self
            .detections_recorded
            .fetch_add(summary.detections, Ordering::Relaxed)
            + summary.detections;
        let bytes = self
            .bytes_processed
            .fetch_add(summary.bytes_processed, Ordering::Relaxed)
            + summary.bytes_processed;
        self.last_error_count
            .store(summary.errors, Ordering::Relaxed);

        let mut snapshot = self.last_snapshot.lock().unwrap();
        snapshot.operations_completed = completed;
        snapshot.detections_recorded = detections;
        snapshot.bytes_processed = bytes;
        snapshot.last_error_count = summary.errors;
    }

    /// Obtain the latest snapshot of metrics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.last_snapshot.lock().unwrap().clone()
    }
}
