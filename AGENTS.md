# Repository Guidelines

## Project Structure & Module Organization
This Rust workspace exposes three binaries—`ech`, `ech-daemon`, and `ech-plugin`—declared in the root `Cargo.toml`. Shared logic lives in `src/` with focused modules such as `core/`, `detection/`, `filesystem/`, `memory/`, `container/`, `stealth/`, and `remediation/`. The CLI entry point is `src/main.rs`, while `src/lib.rs` wires shared services for binaries and tests. Integration suites reside in `tests/`, and helper docs like `ARCHITECTURE.md` and `SIMD_IMPLEMENTATION_SUMMARY.md` outline major subsystems.

## Build, Test, and Development Commands
Use `cargo build` for debug builds and `cargo build --release` for optimized artifacts. Run the CLI locally with `cargo run --bin ech -- file-scan --target /tmp` or swap subcommands as needed. Execute all automated checks via `scripts/test` (wrapper around `cargo test -q`), and rely on `scripts/format` plus `scripts/lint` to keep formatting (`cargo fmt --all`) and Clippy warnings (`cargo clippy --all-targets --all-features -D warnings`) in check. Feature flags such as `simd-optimizations` can be toggled with `cargo run --features simd-optimizations --bin ech -- capabilities`.

## Coding Style & Naming Conventions
Follow Rust 2021 defaults formatted by rustfmt; always run `cargo fmt --all` before committing. Use `snake_case` for functions and files, `CamelCase` for types and traits, and `SCREAMING_SNAKE_CASE` for constants. Prefer `anyhow` or `thiserror` for error handling and pipe structured logs through `tracing` macros. Keep modules cohesive—extend existing domains before introducing new top-level crates.

## Testing Guidelines
Favor fast, deterministic tests. Integration coverage belongs in `tests/*.rs`, while targeted unit tests can live inline under `#[cfg(test)]`. Run `scripts/test` or `cargo test -q` before submitting changes, and add focused regressions for new detection paths. Property tests via `proptest` and opt-in benchmarks with `criterion` are welcome when they reduce false positives or quantify performance.

## Commit & Pull Request Guidelines
Commits follow Conventional Commits, e.g., `feat(core): tighten credential entropy check`. Pull requests must include a short problem statement, summary of changes, exact commands run (with feature flags like `--privileged` when required), and linked issues or docs. Keep PRs tight in scope and note any follow-up work explicitly.

## Security & Configuration Tips
Default runtime configuration loads from `/etc/ech/config.yaml`; prefer overrides in development to avoid global changes. Never embed production secrets in code or fixtures—use synthetic data under `testdata/`. Gate privileged operations (memory scans, container attachments) behind explicit CLI flags, document why they are needed, and verify they degrade gracefully when denied.
