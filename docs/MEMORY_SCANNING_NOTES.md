# Memory Scanning Notes

This document captures the current state of the memory subsystem so new engineers (or AI assistants) can extend it confidently.

## Pipeline Overview
1. `MemoryScanner::scan_target` orchestrates sessions and aggregates metrics.
2. `ProcessManager` enumerates candidate processes (Linux implementation mature; Windows/macOS stubs pending).
3. For each `MemoryRegion`:
   - Memory is read via `StealthMemoryScanner::read_memory_stealthy` (chunked `/proc/<pid>/mem` with jitter).
   - Region data is split into chunks of `MemoryConfig::analysis_chunk_size` (default 256 KiB).
   - Each chunk is analyzed by `MemoryAnalyzer::analyze_memory_block`, producing entropy, printable ratio, and pattern hits with absolute addresses.
   - Uninteresting segments (low-entropy, no patterns) are dropped via `is_interesting_analysis`, keeping telemetry focused.
   - `CredentialExtractor` runs configured detectors and annotates `DetectionResult` with memory addresses.

## Anti-Detection Flow
- `AntiDetection::check_environment` returns an `AntiDetectionReport` rather than a bare error.
- Reports include `enforcement_active` and a list of `AntiDetectionTrigger { name, description }`.
- `MemoryScanner` increments `ScanSummary::anti_detection_triggers` and logs detailed warnings.
- If enforcement is active and any triggers fire, the scan aborts with `MemoryError::AntiDebuggingDetected`.
- Environment variable `ECH_DISABLE_ANTI_DEBUG` allows operators to acknowledge risks explicitly.
- Current hooks: non-zero `/proc/self/status` `TracerPid`, non-empty `LD_PRELOAD`, and container-style cgroup fingerprints (docker/lxc/kubepods).
- The hook registry is extensible—call `AntiDetection::register_hook` before wiring it into the scanner to add platform-specific checks without touching the core.

## Metrics & Telemetry
- `ScanSummary` uses `u64` counters to avoid overflow on long-running hunts.
- `RegionScanResult::bytes_read` measures actual bytes processed (respecting partial reads/jitter).
- `MemoryStats` aggregates totals and average scan time; anti-detection counts now roll up globally.

## Extensibility Points
- **Additional Triggers**: extend `AntiDetection::check_environment` with new platform-specific checks (ptrace, cgroup markers, etc.).
- **Chunk Analysis**: enrich `AnalysisResult` with new heuristics (e.g., n-gram analysis) while keeping offsets accurate.
- **Parallelism**: current implementation is sequential for determinism; future work can reintroduce controlled concurrency with `JoinSet`.
- **Non-Linux Support**: implement `ProcessManager` and `StealthMemoryScanner` backends for Windows/macOS.

## Safety Considerations
- Respect `MemoryConfig::max_memory_mb` to avoid exhausting system RAM.
- Handle partial reads gracefully—`read_memory_stealthy` already truncates to available bytes.
- Ensure `AnalysisResult` additions do not leak sensitive bytes in logs; summarize metrics instead.

Keep this document updated as the subsystem evolves.
