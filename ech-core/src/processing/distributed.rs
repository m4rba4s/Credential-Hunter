use std::sync::Arc;
use std::collections::HashMap;
use std::thread;
use std::time::{Duration, Instant};
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use anyhow::{Result, anyhow};

use crate::core::lockfree::LockFreeQueue;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingTask {
    pub id: Uuid,
    pub task_type: TaskType,
    pub data: Vec<u8>,
    pub priority: Priority,
    #[serde(skip)]
    pub deadline: Option<Instant>,
    pub retry_count: u32,
    pub max_retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TaskType {
    MemoryScan,
    FilesystemScan,
    NetworkCapture,
    WebAuthnHunt,
    ImdsHunt,
    VbsBypass,
    PatternMatch,
    EntropyAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingResult {
    pub task_id: Uuid,
    pub status: TaskStatus,
    pub data: Vec<u8>,
    pub processing_time: Duration,
    pub worker_id: Uuid,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
    Retrying,
}

pub trait TaskProcessor: Send + Sync {
    fn process(&self, task: ProcessingTask) -> Result<ProcessingResult>;
    fn can_handle(&self, task_type: &TaskType) -> bool;
    fn get_estimated_duration(&self, task: &ProcessingTask) -> Duration;
}

pub struct WorkerPool {
    workers: Vec<Worker>,
    task_queue: Arc<LockFreeQueue<ProcessingTask>>,
    result_queue: Arc<LockFreeQueue<ProcessingResult>>,
    shutdown_sender: Sender<()>,
    shutdown_receiver: Receiver<()>,
    worker_count: usize,
}

struct Worker {
    id: Uuid,
    thread_handle: Option<thread::JoinHandle<()>>,
    processor: Arc<dyn TaskProcessor>,
}

impl WorkerPool {
    pub fn new(worker_count: usize) -> Self {
        let (shutdown_sender, shutdown_receiver) = bounded(1);
        
        Self {
            workers: Vec::with_capacity(worker_count),
            task_queue: Arc::new(LockFreeQueue::new()),
            result_queue: Arc::new(LockFreeQueue::new()),
            shutdown_sender,
            shutdown_receiver,
            worker_count,
        }
    }
    
    pub fn add_processor(&mut self, processor: Arc<dyn TaskProcessor>) {
        if self.workers.len() >= self.worker_count {
            return;
        }
        
        let worker_id = Uuid::new_v4();
        let task_queue = self.task_queue.clone();
        let result_queue = self.result_queue.clone();
        let shutdown_receiver = self.shutdown_receiver.clone();
        let processor_clone = processor.clone();
        
        let handle = thread::spawn(move || {
            Self::worker_loop(
                worker_id,
                task_queue,
                result_queue,
                shutdown_receiver,
                processor_clone,
            );
        });
        
        let worker = Worker {
            id: worker_id,
            thread_handle: Some(handle),
            processor,
        };
        
        self.workers.push(worker);
    }
    
    pub fn submit_task(&self, task: ProcessingTask) {
        self.task_queue.enqueue(task);
    }
    
    pub fn get_result(&self) -> Option<ProcessingResult> {
        self.result_queue.dequeue()
    }
    
    pub fn get_pending_task_count(&self) -> usize {
        let mut count = 0;
        let queue_clone = self.task_queue.clone();
        
        while queue_clone.dequeue().is_some() {
            count += 1;
        }
        
        count
    }
    
    pub fn shutdown(&mut self) {
        let _ = self.shutdown_sender.send(());
        
        for worker in &mut self.workers {
            if let Some(handle) = worker.thread_handle.take() {
                let _ = handle.join();
            }
        }
        
        self.workers.clear();
    }
    
    fn worker_loop(
        worker_id: Uuid,
        task_queue: Arc<LockFreeQueue<ProcessingTask>>,
        result_queue: Arc<LockFreeQueue<ProcessingResult>>,
        shutdown_receiver: Receiver<()>,
        processor: Arc<dyn TaskProcessor>,
    ) {
        loop {
            if shutdown_receiver.try_recv().is_ok() {
                break;
            }
            
            if let Some(mut task) = task_queue.dequeue() {
                if !processor.can_handle(&task.task_type) {
                    task_queue.enqueue(task);
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                
                if let Some(deadline) = task.deadline {
                    if Instant::now() > deadline {
                        let result = ProcessingResult {
                            task_id: task.id,
                            status: TaskStatus::Failed,
                            data: Vec::new(),
                            processing_time: Duration::ZERO,
                            worker_id,
                            error_message: Some("Task deadline exceeded".to_string()),
                        };
                        result_queue.enqueue(result);
                        continue;
                    }
                }
                
                let start_time = Instant::now();
                
                let result = match processor.process(task.clone()) {
                    Ok(mut result) => {
                        result.worker_id = worker_id;
                        result.processing_time = start_time.elapsed();
                        result.status = TaskStatus::Completed;
                        result
                    }
                    Err(e) => {
                        task.retry_count += 1;
                        
                        if task.retry_count < task.max_retries {
                            thread::sleep(Duration::from_millis(100 * task.retry_count as u64));
                            task_queue.enqueue(task.clone());
                            
                            ProcessingResult {
                                task_id: task.id,
                                status: TaskStatus::Retrying,
                                data: Vec::new(),
                                processing_time: start_time.elapsed(),
                                worker_id,
                                error_message: Some(e.to_string()),
                            }
                        } else {
                            ProcessingResult {
                                task_id: task.id,
                                status: TaskStatus::Failed,
                                data: Vec::new(),
                                processing_time: start_time.elapsed(),
                                worker_id,
                                error_message: Some(e.to_string()),
                            }
                        }
                    }
                };
                
                result_queue.enqueue(result);
            } else {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

pub struct DistributedEngine {
    worker_pools: HashMap<TaskType, WorkerPool>,
    load_balancer: LoadBalancer,
    task_scheduler: TaskScheduler,
    metrics: EngineMetrics,
}

impl DistributedEngine {
    pub fn new() -> Self {
        Self {
            worker_pools: HashMap::new(),
            load_balancer: LoadBalancer::new(),
            task_scheduler: TaskScheduler::new(),
            metrics: EngineMetrics::new(),
        }
    }
    
    pub fn add_worker_pool(&mut self, task_type: TaskType, pool: WorkerPool) {
        self.worker_pools.insert(task_type, pool);
    }
    
    pub fn submit_task(&mut self, task: ProcessingTask) -> Result<()> {
        self.metrics.increment_submitted_tasks();
        
        let scheduled_task = self.task_scheduler.schedule(task)?;
        
        if let Some(pool) = self.worker_pools.get_mut(&scheduled_task.task_type) {
            pool.submit_task(scheduled_task);
            Ok(())
        } else {
            Err(anyhow!("No worker pool available for task type: {:?}", scheduled_task.task_type))
        }
    }
    
    pub fn get_results(&mut self) -> Vec<ProcessingResult> {
        let mut results = Vec::new();
        
        for pool in self.worker_pools.values() {
            while let Some(result) = pool.get_result() {
                match result.status {
                    TaskStatus::Completed => self.metrics.increment_completed_tasks(),
                    TaskStatus::Failed => self.metrics.increment_failed_tasks(),
                    _ => {}
                }
                results.push(result);
            }
        }
        
        results
    }
    
    pub fn get_metrics(&self) -> &EngineMetrics {
        &self.metrics
    }
    
    pub fn shutdown(&mut self) {
        for pool in self.worker_pools.values_mut() {
            pool.shutdown();
        }
    }
}

struct LoadBalancer {
    task_weights: HashMap<TaskType, f64>,
}

impl LoadBalancer {
    fn new() -> Self {
        let mut task_weights = HashMap::new();
        task_weights.insert(TaskType::MemoryScan, 1.0);
        task_weights.insert(TaskType::FilesystemScan, 0.8);
        task_weights.insert(TaskType::NetworkCapture, 1.2);
        task_weights.insert(TaskType::WebAuthnHunt, 0.6);
        task_weights.insert(TaskType::ImdsHunt, 0.4);
        task_weights.insert(TaskType::VbsBypass, 1.5);
        task_weights.insert(TaskType::PatternMatch, 0.3);
        task_weights.insert(TaskType::EntropyAnalysis, 0.7);
        
        Self { task_weights }
    }
    
    fn calculate_load(&self, task_type: &TaskType) -> f64 {
        self.task_weights.get(task_type).copied().unwrap_or(1.0)
    }
}

struct TaskScheduler {
    priority_queues: HashMap<Priority, LockFreeQueue<ProcessingTask>>,
}

impl TaskScheduler {
    fn new() -> Self {
        let mut priority_queues = HashMap::new();
        priority_queues.insert(Priority::Low, LockFreeQueue::new());
        priority_queues.insert(Priority::Normal, LockFreeQueue::new());
        priority_queues.insert(Priority::High, LockFreeQueue::new());
        priority_queues.insert(Priority::Critical, LockFreeQueue::new());
        
        Self { priority_queues }
    }
    
    fn schedule(&mut self, task: ProcessingTask) -> Result<ProcessingTask> {
        if let Some(queue) = self.priority_queues.get(&task.priority) {
            queue.enqueue(task.clone());
        }
        
        for priority in [Priority::Critical, Priority::High, Priority::Normal, Priority::Low] {
            if let Some(queue) = self.priority_queues.get(&priority) {
                if let Some(scheduled_task) = queue.dequeue() {
                    return Ok(scheduled_task);
                }
            }
        }
        
        Ok(task)
    }
}

#[derive(Debug, Clone)]
pub struct EngineMetrics {
    submitted_tasks: Arc<std::sync::atomic::AtomicUsize>,
    completed_tasks: Arc<std::sync::atomic::AtomicUsize>,
    failed_tasks: Arc<std::sync::atomic::AtomicUsize>,
    start_time: Instant,
}

impl EngineMetrics {
    fn new() -> Self {
        Self {
            submitted_tasks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            completed_tasks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            failed_tasks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            start_time: Instant::now(),
        }
    }
    
    fn increment_submitted_tasks(&self) {
        self.submitted_tasks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    
    fn increment_completed_tasks(&self) {
        self.completed_tasks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    
    fn increment_failed_tasks(&self) {
        self.failed_tasks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    
    pub fn get_submitted_count(&self) -> usize {
        self.submitted_tasks.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    pub fn get_completed_count(&self) -> usize {
        self.completed_tasks.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    pub fn get_failed_count(&self) -> usize {
        self.failed_tasks.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    pub fn get_success_rate(&self) -> f64 {
        let completed = self.get_completed_count() as f64;
        let total = self.get_submitted_count() as f64;
        
        if total > 0.0 {
            completed / total
        } else {
            0.0
        }
    }
    
    pub fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
    
    pub fn get_throughput(&self) -> f64 {
        let completed = self.get_completed_count() as f64;
        let uptime_secs = self.get_uptime().as_secs_f64();
        
        if uptime_secs > 0.0 {
            completed / uptime_secs
        } else {
            0.0
        }
    }
}

pub struct MemoryScanProcessor;

impl TaskProcessor for MemoryScanProcessor {
    fn process(&self, task: ProcessingTask) -> Result<ProcessingResult> {
        thread::sleep(Duration::from_millis(50));
        
        let mock_result = format!("Memory scan completed for task {}", task.id);
        
        Ok(ProcessingResult {
            task_id: task.id,
            status: TaskStatus::Completed,
            data: mock_result.into_bytes(),
            processing_time: Duration::from_millis(50),
            worker_id: Uuid::new_v4(),
            error_message: None,
        })
    }
    
    fn can_handle(&self, task_type: &TaskType) -> bool {
        matches!(task_type, TaskType::MemoryScan)
    }
    
    fn get_estimated_duration(&self, _task: &ProcessingTask) -> Duration {
        Duration::from_millis(50)
    }
}

pub struct PatternMatchProcessor;

impl TaskProcessor for PatternMatchProcessor {
    fn process(&self, task: ProcessingTask) -> Result<ProcessingResult> {
        thread::sleep(Duration::from_millis(10));
        
        let mock_result = format!("Pattern matching completed for task {}", task.id);
        
        Ok(ProcessingResult {
            task_id: task.id,
            status: TaskStatus::Completed,
            data: mock_result.into_bytes(),
            processing_time: Duration::from_millis(10),
            worker_id: Uuid::new_v4(),
            error_message: None,
        })
    }
    
    fn can_handle(&self, task_type: &TaskType) -> bool {
        matches!(task_type, TaskType::PatternMatch | TaskType::EntropyAnalysis)
    }
    
    fn get_estimated_duration(&self, _task: &ProcessingTask) -> Duration {
        Duration::from_millis(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_worker_pool() {
        let mut pool = WorkerPool::new(2);
        let processor = Arc::new(PatternMatchProcessor);
        
        pool.add_processor(processor.clone());
        pool.add_processor(processor);
        
        let task = ProcessingTask {
            id: Uuid::new_v4(),
            task_type: TaskType::PatternMatch,
            data: b"test data".to_vec(),
            priority: Priority::Normal,
            deadline: None,
            retry_count: 0,
            max_retries: 3,
        };
        
        pool.submit_task(task);
        
        thread::sleep(Duration::from_millis(100));
        
        let result = pool.get_result();
        assert!(result.is_some());
        
        pool.shutdown();
    }
    
    #[test]
    fn test_distributed_engine() {
        let mut engine = DistributedEngine::new();
        
        let mut pool = WorkerPool::new(1);
        pool.add_processor(Arc::new(PatternMatchProcessor));
        
        engine.add_worker_pool(TaskType::PatternMatch, pool);
        
        let task = ProcessingTask {
            id: Uuid::new_v4(),
            task_type: TaskType::PatternMatch,
            data: b"test data".to_vec(),
            priority: Priority::High,
            deadline: None,
            retry_count: 0,
            max_retries: 3,
        };
        
        assert!(engine.submit_task(task).is_ok());
        
        thread::sleep(Duration::from_millis(100));
        
        let results = engine.get_results();
        assert!(!results.is_empty());
        
        engine.shutdown();
    }
    
    #[test]
    fn test_metrics() {
        let metrics = EngineMetrics::new();
        
        assert_eq!(metrics.get_submitted_count(), 0);
        assert_eq!(metrics.get_completed_count(), 0);
        assert_eq!(metrics.get_failed_count(), 0);
        
        metrics.increment_submitted_tasks();
        metrics.increment_completed_tasks();
        
        assert_eq!(metrics.get_submitted_count(), 1);
        assert_eq!(metrics.get_completed_count(), 1);
        assert_eq!(metrics.get_success_rate(), 1.0);
        
        metrics.increment_failed_tasks();
        metrics.increment_submitted_tasks();
        
        assert_eq!(metrics.get_success_rate(), 0.5);
    }
    
    #[test]
    fn test_task_priority() {
        use std::cmp::Ordering;
        
        assert_eq!(Priority::Critical.cmp(&Priority::High), Ordering::Greater);
        assert_eq!(Priority::High.cmp(&Priority::Normal), Ordering::Greater);
        assert_eq!(Priority::Normal.cmp(&Priority::Low), Ordering::Greater);
    }
}