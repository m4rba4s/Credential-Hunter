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
///   Configuration loading and management utilities.
pub mod config;
/// Engine orchestration and lifecycle management.
pub mod engine;
/// Logging adapters and structured tracing helpers.
pub mod logging;
/// Metrics collection and reporting infrastructure.
pub mod metrics;
/// Formatting and emitting results to console/files.
pub mod output;
/// Platform abstraction and capability detection.
pub mod platform;
/// Cooperative task scheduling primitives.
pub mod scheduler;
/// Security context, privilege, and audit facilities.
pub mod security;
