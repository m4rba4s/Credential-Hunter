/**
 * ECH Core Module - Foundational Components
 * 
 * This module contains the core foundational components that all other ECH modules depend on.
 * Designed with enterprise-grade reliability, security, and performance in mind.
 * 
 * Key Design Principles:
 * - Zero-allocation hot paths where possible
 * - Memory safety with explicit lifetime management
 * - Fail-safe security with secure defaults
 * - Cross-platform compatibility with platform-specific optimizations
 * - Enterprise logging and audit trail generation
 */

pub mod config;
pub mod engine;
pub mod security;
pub mod platform;
pub mod metrics;
pub mod scheduler;
pub mod zero_copy;
pub mod lockfree;

pub use config::{EchConfig, LogLevel, OutputFormat};
pub use engine::EchEngine;
pub use security::SecurityContext;
pub use platform::Platform;
pub use metrics::Metrics;
pub use scheduler::TaskScheduler;
pub use zero_copy::ZeroCopyScanner;
pub use lockfree::{LockFreeQueue, LockFreeHashMap, ConcurrentCredentialBuffer};