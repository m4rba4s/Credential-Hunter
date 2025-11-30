# Metrics & Telemetry Notes

Use this notebook when wiring counters, gauges, and derived metrics across the scanners. It keeps agents aligned on how we size fields and where telemetry is still thin.

## Counter Sizing & Overflow Hygiene
- Default to `u64` for any counter that can accumulate across long-running scans (files visited, credentials found, archive entries). This avoids wraparound on hosts that churn through millions of objects.
- Keep derived rates (`scan_efficiency`, throughput) as `f64`, but recompute them from the authoritative `u64` counters instead of maintaining parallel floats.
- When bridging into external systems (SIEM, metrics exporters) down-cast only at the edge, and document the precision loss.
- For per-region/per-file tallies that reset frequently, `u32` is acceptable, yet promote to `u64` once they roll into user-facing summaries.

## Telemetry Integration Checklist
1. Update `FilesystemStats` / `MemoryStats` after every scan batch; never rely on stale cached values.
2. Emit `tracing` events with structured fields (`bytes_scanned`, `credentials_found`) so downstream sinks can aggregate without log parsing.
3. When introducing new counters, thread them through both the in-memory stats struct and the public `ScanSummary` so API consumers stay consistent.
4. Extend `core::metrics` once the Prometheus/exporter story solidifies; today we only keep in-memory aggregates.

## Outstanding Follow-ups
- Memory scanner still exposes `ScanSession` privately; once the async dashboard is ready, publish a read-only view with proper doc comments.
- Windows/macOS process managers return placeholder errors. Before enabling metrics on those platforms, implement lightweight shims so stats won’t silently zero out.
- SIEM transport (when revived) should stream the new 64-bit counters; remember to cap values when serializing to legacy 32-bit schemas.

Keep this file updated whenever you add counters or unblock telemetry pipelines so the rest of the crew has a reliable playbook.
