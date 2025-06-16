/**
 * ECH Core Scheduler Module
 */

use anyhow::Result;

pub struct TaskScheduler;

impl TaskScheduler {
    pub fn new(_worker_threads: usize) -> Result<Self> {
        Ok(Self)
    }
}