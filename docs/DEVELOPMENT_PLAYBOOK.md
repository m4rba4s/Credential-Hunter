# Development Playbook

This playbook is a companion for all contributors (including automated agents). Follow it to ship features without compromising security or stability.

## 1. Mindset & Priorities
- **Security First**: assume hostile runtime conditions. Never disable anti-detection, sandbox, or privilege checks without a compelling reason.
- **Portability**: Linux is the reference platform, but every change must compile on Windows/macOS via the abstraction layers.
- **Observability**: log everything important via `tracing` using the fancy formatter; keep logs actionable, not noisy.

## 2. Workflow Checklist
1. **Discover Context**
   - Read `ARCHITECTURE.md` and module-specific docs under `docs/`.
   - Inspect existing traits/structs before introducing new ones.
2. **Design Before Code**
   - Outline data flow and error handling.
   - Consider configuration knobs in `core::config`.
3. **Implement**
   - Reuse utilities from `core`, `detection`, or `memory` modules.
   - Keep functions small; prefer pure helpers over large `async fn` bodies.
4. **Instrument**
   - Use `tracing::{info, warn, error}` with contextual fields.
   - When interacting with anti-detection, call `AntiDetection::check_environment` and propagate trigger reports.
5. **Validate**
   - Run `scripts/devcheck` for the full pipeline (format → clippy → cargo-deny → tests).
   - If individual steps fail because components are missing, install them (`rustup component add rustfmt clippy`) and rerun.
   - Document any skipped checks in the PR description.
6. **Document**
   - Update relevant `docs/*.md` files and keep `DOCUMENTATION_TREE.md` current.
7. **Review**
   - Self-review diffs for portability (`cfg` gates) and security regressions.

## 3. Coding Standards
- Follow Rust 2021 idioms; keep modules cohesive.
- Prefer `anyhow::Result` for orchestration layers; `thiserror` for domain errors.
- Guard privileged operations behind explicit configuration flags.
- Handle `cfg`-specific code using platform modules under `platform/` or `process.rs`.
- Use `Arc` + `RwLock` sparingly; prefer `async` channels for high-contention paths.
- Keep logs color-friendly (no raw ANSI in message strings; rely on formatter).

## 4. Feature-Specific Guidance
### Memory Scanner
- Chunk memory analysis via `MemoryConfig::analysis_chunk_size`.
- Aggregate `AntiDetectionReport` triggers in `ScanSummary::anti_detection_triggers`.
- Record bytes read per region (`RegionScanResult::bytes_read`).

### Filesystem Hunter
- Filter using `HunterConfig` includes/excludes; do not traverse `/proc`, `/sys`, `/dev` unfiltered.
- For new parsers, plug into `filesystem::scanner` and register a detector in `detection::patterns`.
- Promote long-lived counters (`files_scanned`, `credentials_found`) to `u64`; see `docs/METRICS_AND_TELEMETRY.md` for overflow guardrails.

### Detection Engine
- Extend pattern registry through `detection/patterns/*.rs`.
- Keep entropy thresholds configurable via `DetectionConfig`.
- Update `detection::context` when introducing new heuristics.

### Logging & SIEM
- High-visibility events should use `warn!(target: "ech::anti_detection", ...)` or similar targeted channels.
- Use `core::logging::FancyLogFormatter` defaults; avoid bespoke formatting in individual modules.

## 5. Portability Footnotes
- Implement platform-specific code inside `platform/` or guard with `#[cfg]`.
- Avoid Linux-only syscalls in shared modules; use abstraction from `core::platform`.
- Provide graceful fallbacks (e.g., return `MemoryError::PlatformNotSupported`).

## 6. Safety & Secrets
- Never hardcode production secrets. Use `testdata/` for synthetic fixtures.
- Respect `config.operation.dry_run` and `config.security.privileged_mode` flags.
- On remediation actions, ensure reversible steps or backups before destructive operations.

## 7. Hand-off Expectations
- Every change should note follow-up work if modules remain stubbed.
- Record test command output (or blockers) in PR descriptions.
- Keep the docs aligned—update this playbook when conventions evolve.

Stay disciplined and the system will remain an engineering art piece.
