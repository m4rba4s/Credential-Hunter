pub mod distributed;

pub use distributed::{
    DistributedEngine, 
    WorkerPool, 
    ProcessingTask, 
    ProcessingResult,
    TaskType,
    Priority,
    TaskStatus,
    TaskProcessor,
    EngineMetrics,
    MemoryScanProcessor,
    PatternMatchProcessor,
};