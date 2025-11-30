Synthetic test fixtures for ECH scanning.

These files contain fake, non-sensitive examples of credentials and configuration values
to validate the filesystem scanner, pattern detector, entropy analyzer, and context filters.

Run example:
- cargo run --bin ech -- file-scan --target testdata --format json -vv

