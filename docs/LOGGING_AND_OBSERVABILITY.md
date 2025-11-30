# Logging & Observability Blueprint

The CLI and library now default to a high-energy ANSI formatter that keeps operators laser-focused while remaining machine-parseable.

## Formatter Stack
- `core::logging::FancyLogFormatter` wraps each event in colorized box-drawing glyphs.
- Each frame header includes:
  - Severity glyph (`★`, `⚠`, `✖`, etc.).
  - Timestamp (`YYYY-MM-DD HH:MM:SS`).
  - `metadata.target()` to keep component attribution clear.
- Body lines contain message text plus any structured fields emitted by `tracing` macros.

### Usage
```rust
info!(target: "ech::memory", session = %session_id, "Scan started");
warn!(target: "ech::anti_detection", trigger = %trigger.name, "Debugger detected");
```
The formatter auto-includes span names, so instrument blocks with `tracing::info_span!` when diving into complex logic.

## Startup Banner
- Emitted once per process (unless `ECH_SILENT_BANNER=1` is set).
- Provides immediate visual confirmation that logging is configured.
- Suppressed automatically in `--quiet` mode.

## Anti-Detection Telemetry
- `AntiDetection::check_environment` returns an `AntiDetectionReport` with trigger metadata.
- Built-in hooks today: non-zero `/proc/self/status` `TracerPid`, suspicious `LD_PRELOAD`, and container-style cgroup fingerprints (Docker/LXC/Kubernetes).
- `MemoryScanner` increments `ScanSummary::anti_detection_triggers` and logs each trigger with `target: "ech::anti_detection"`.
- Downstream dashboards can filter on this target to raise alarms.

## SIEM & Structured Output
- Despite the flamboyant CLI, `tracing` retains structured fields for JSON exporters and SIEM connectors.
- When writing integration code, pull context from the event's fields; avoid parsing the formatted string.

## Best Practices
- **No manual ANSI**: let the formatter handle colors to preserve portability.
- **Keep messages terse**: the frame width truncates after 76 characters; use fields for extra data.
- **Include identifiers**: session IDs, PIDs, container IDs help operators correlate logs.
- **Respect verbosity flags**: guard chatty logs behind `debug!`/`trace!`.

## Future Hooks
- Add rate-limiting for repetitive warnings (e.g., mass anti-detection triggers).
- Provide JSON-only formatter toggle for headless deployments.
- Stream logs to `core::metrics` once the telemetry subsystem matures.
