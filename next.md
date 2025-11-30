# Next Session Notes
- Warnings remain (dead_code/unused across core/platform/security/filesystem/memory). We intentionally left them; cleaning is the next P0 if we want a quiet CI.
- Detection fixtures added: kube secret, docker config, TLS manifest + P12 bundle, nested archive zip. Tests covering them pass.
- Archive tests: `tests/engine_archive_scan.rs` and `tests/nested_archive_scan.rs` ensure archive/nested archive detections propagate.
- Memory interception: added `MemoryInterceptHook` and hook registration in `ProcessManager`; test `interceptors_wrap_memory_reads` verifies hooks fire around reads.
- Full test command used: `cargo test -q` (all green apart from existing dead_code warnings).
- If continuing: consider cleaning warnings or adding more TLS/P12 detection paths; interceptors and fixtures are now documented in `ARCHITECTURE.md`; sample hook registration in runtime still TBD if desired.
