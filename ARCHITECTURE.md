# ECH Architecture Design Document

## 🏗️ CORE ARCHITECTURE PRINCIPLES

### 1. Security-First Design
- **Principle of Least Privilege**: Every component runs with minimal required permissions
- **Defense in Depth**: Multiple security layers with fail-safe mechanisms
- **Zero Trust**: No implicit trust between components, all communication verified
- **Secure by Default**: Safe defaults, explicit opt-in for risky operations

### 2. Performance & Scalability
- **Lock-Free Design**: Atomic operations and wait-free data structures
- **Zero-Copy Operations**: Memory mapping and direct buffer access
- **Async I/O**: Non-blocking operations with event-driven architecture
- **Resource Pooling**: Shared thread pools and connection reuse

### 3. Cross-Platform Compatibility
- **Platform Abstraction Layer (PAL)**: Unified API across operating systems
- **Conditional Compilation**: Platform-specific optimizations
- **Runtime Detection**: Dynamic capability discovery
- **Graceful Degradation**: Fallback mechanisms for unsupported features

## 🔧 COMPONENT ARCHITECTURE

### Core Engine (`src/core/`)
```
core/
├── engine.rs           # Main orchestration engine
├── config.rs          # Configuration management
├── scheduler.rs       # Task scheduling and coordination
├── metrics.rs         # Performance and health metrics
├── security.rs        # Security utilities and primitives
└── platform/
    ├── mod.rs         # Platform abstraction interface
    ├── linux.rs       # Linux-specific implementations
    ├── windows.rs     # Windows-specific implementations
    └── macos.rs       # macOS-specific implementations
```

**Responsibilities:**
- System initialization and cleanup
- Cross-platform capability detection
- Resource management and allocation
- Component lifecycle management
- Error handling and recovery

### Detection Engine (`src/detection/`)
```
detection/
├── engine.rs          # Pattern matching orchestrator
├── patterns/
│   ├── mod.rs         # Pattern registry and management
│   ├── api_keys.rs    # Cloud provider API key patterns
│   ├── crypto.rs      # Cryptographic material detection
│   ├── database.rs    # Database credential patterns
│   ├── jwt.rs         # JWT token parsing and validation
│   └── custom.rs      # User-defined patterns
├── entropy.rs         # Shannon entropy analysis
├── context.rs         # Contextual analysis engine
├── ml/
│   ├── classifier.rs  # ML-based secret classification
│   └── models/        # Pre-trained model definitions
└── yara.rs           # YARA integration (optional)
```

**Key Features:**
- **Pattern Registry**: Extensible pattern matching system
- **Entropy Analysis**: Statistical analysis for random strings
- **Context Awareness**: Analyzes surrounding code/config for validation
- **ML Classification**: Machine learning for unknown pattern detection
- **Performance**: Compiled regex with memoization for speed

### Memory Scanner (`src/memory/`)
```
memory/
├── scanner.rs         # Memory scanning orchestrator
├── process.rs         # Process enumeration and handling
├── regions.rs         # Memory region analysis
├── dumper.rs          # Memory content extraction
├── parser.rs          # Binary content parsing
└── platform/
    ├── linux.rs       # Linux /proc and ptrace
    ├── windows.rs     # Windows Process API
    └── macos.rs       # macOS task_info and vm_read
```

**Capabilities:**
- **Process Memory**: Scan running process memory spaces
- **Heap Analysis**: Search heap allocations for credentials
- **Stack Scanning**: Analyze call stacks for sensitive data
- **Binary Parsing**: Extract strings from executable memory
- **Volatile Data**: Capture credentials in transit
- **Interception Hooks**: `MemoryInterceptHook` wrappers around process reads for auditing/testing before/after raw access
  - Enable a runtime logging hook with `ECH_LOG_MEMORY_READS=1` to trace before/after read boundaries without changing scanner code.

### Filesystem Hunter (`src/filesystem/`)
```
filesystem/
├── hunter.rs          # File system scanning engine
├── walker.rs          # Directory traversal with filtering
├── parsers/
│   ├── text.rs        # Plain text file analysis
│   ├── config.rs      # Configuration file parsing
│   ├── archive.rs     # Archive extraction and scanning
│   ├── binary.rs      # Binary file analysis
│   └── logs.rs        # Log file parsing
├── indexer.rs         # Content indexing for fast searches
└── watcher.rs         # Real-time file system monitoring
```

**Features:**
- **Smart Traversal**: Efficient directory walking with exclusions
- **Format Detection**: Automatic file type identification
- **Deep Parsing**: Extract credentials from nested data structures
- **Archive Support**: Scan inside ZIP, TAR, JAR files
- **Real-time Monitoring**: inotify/ReadDirectoryChanges integration
- **Nested Archives**: Detection results bubble up from multi-layer archives (see nested archive tests)

### Synthetic Fixtures (for tests)
- Located under `testdata/synthetic/**` covering env/logs/DB dumps/kube/docker/tls/archives.
- TLS bundle: `testdata/synthetic/tls/client_auth.p12` + `tls_manifest.yaml`.
- Nested archives: `testdata/synthetic/archives/{creds_bundle.zip,nested_creds.zip}`.
- Container secrets: kube secrets, docker config, docker-compose with mixed cloud tokens.
- Tests: `tests/fixture_secrets.rs`, `tests/engine_archive_scan.rs`, `tests/nested_archive_scan.rs`.

### Container Scanner (`src/container/`)
```
container/
├── scanner.rs         # Container scanning orchestrator
├── docker.rs          # Docker runtime integration
├── podman.rs          # Podman runtime support
├── kubernetes.rs      # Kubernetes pod scanning
├── image.rs           # Container image analysis
├── volumes.rs         # Volume and mount scanning
└── secrets.rs         # Kubernetes secrets analysis
```

**Container Capabilities:**
- **Runtime Detection**: Automatic container runtime discovery
- **Image Scanning**: Analyze container images for embedded secrets
- **Volume Analysis**: Scan mounted volumes and bind mounts
- **Environment Variables**: Extract runtime environment secrets
- **Secret Management**: Kubernetes/Docker secret validation

### Stealth Engine (`src/stealth/`)
```
stealth/
├── engine.rs          # Stealth operation coordinator
├── evasion.rs         # EDR/AV evasion techniques
├── obfuscation.rs     # Binary and runtime obfuscation
├── injection.rs       # Process injection for covert scanning
├── footprint.rs       # Minimal footprint operations
└── cleanup.rs         # Evidence removal and cleanup
```

**Stealth Features:**
- **EDR Evasion**: Bypass common endpoint detection systems
- **Process Hollowing**: Hide scanner in legitimate processes
- **API Obfuscation**: Dynamic API resolution and hooking
- **Memory Wiping**: Secure cleanup of sensitive data
- **Timing Attacks**: Evade behavioral analysis

### Remediation Engine (`src/remediation/`)
```
remediation/
├── engine.rs          # Remediation orchestrator
├── actions/
│   ├── mask.rs        # Credential masking operations
│   ├── quarantine.rs  # Safe credential isolation
│   ├── rotate.rs      # Automatic credential rotation
│   └── wipe.rs        # Secure credential deletion
├── safety.rs          # Safety checks and rollback
└── policy.rs          # Remediation policy engine
```

**Remediation Actions:**
- **Masking**: Replace credentials with masked values
- **Quarantine**: Move credentials to secure isolation
- **Rotation**: Trigger automatic credential rotation
- **Secure Wipe**: Cryptographically secure deletion
- **Backup**: Create secure backups before modifications

### SIEM Integration (`src/siem/`)
```
siem/
├── integration.rs     # SIEM integration orchestrator
├── formatters/
│   ├── json.rs        # JSON output formatting
│   ├── cef.rs         # Common Event Format
│   ├── leef.rs        # Log Event Extended Format
│   └── syslog.rs      # RFC5424 syslog format
├── exporters/
│   ├── splunk.rs      # Splunk HEC integration
│   ├── elastic.rs     # Elasticsearch direct indexing
│   ├── kafka.rs       # Kafka producer for streaming
│   └── webhook.rs     # Generic webhook notifications
└── correlation.rs     # Event correlation and enrichment
```

## 🔀 DATA FLOW ARCHITECTURE

### Scanning Pipeline
```
Input Sources → Detection Engine → Analysis → Remediation → SIEM Export
     ↓              ↓              ↓           ↓            ↓
┌─────────────┐ ┌─────────────┐ ┌──────────┐ ┌─────────┐ ┌─────────────┐
│ • Memory    │ │ • Patterns  │ │ • Risk   │ │ • Mask  │ │ • Splunk    │
│ • Files     │ │ • Entropy   │ │ • Context│ │ • Quarantine │ • ELK       │
│ • Containers│ │ • ML Class  │ │ • Validation │ • Rotate │ │ • QRadar    │
│ • Network   │ │ • YARA      │ │ • Scoring│ │ • Wipe  │ │ • Webhooks  │
└─────────────┘ └─────────────┘ └──────────┘ └─────────┘ └─────────────┘
```

### Runtime Flow (CLI → Engine → Output)
1. **CLI (src/main.rs)** parses args, builds `EchConfig`, toggles `--ci` (quiet, NDJSON, exit code on findings).
2. **Engine (core/engine.rs)** expands targets (`--target|--path`, filters/extensions), orchestrates filesystem/memory/container scanners, accumulates detections + summary.
3. **Detection (detection/engine.rs)** runs pattern registry, entropy analyzer, optional ML/YARA; enriches `DetectionResult` with context (file/path/line), metadata (methods, entropy, pattern), risk and recommended actions.
4. **Output (core/output.rs)** serializes `EngineResult` per `OutputFormat`: JSON/YAML/Text, NDJSON for CI (one detection per line + final summary). CI mode suppresses banner/colors and sets non-zero exit when credentials are found.

### Output Contract (NDJSON)
- `type: "detection"` records carry full `DetectionResult`: ids, credential_type, confidence/risk, masked value, optional full value (only in dry-run + allowlist), location (path/line/column/pid/container/memory_address), context (surrounding_text, variable_name, file_type/language), metadata (methods, pattern_name, entropy_score, ml_confidence, yara_matches, processing_time_us), recommended_actions, timestamp.
- Final `type: "summary"` holds aggregate stats: `targets_scanned`, `credentials_found`, `high_risk_credentials`, `processing_time_ms`, `bytes_processed`, `errors_encountered`.
- Formats JSON/YAML/Text follow the same struct shape; NDJSON is line-delimited for CI/log ingestion.

## 🔎 Observability & Telemetry

- CLI and library bootstrap `core::logging::FancyLogFormatter` for colorized yet structured logging (see `docs/LOGGING_AND_OBSERVABILITY.md`).
- Startup banner confirms configuration unless `ECH_SILENT_BANNER=1` or `--quiet` is supplied.
- `AntiDetection::check_environment` surfaces `AntiDetectionReport` objects; `MemoryScanner` folds trigger counts into `ScanSummary::anti_detection_triggers` and global `MemoryStats`.
- Anti-detection hooks are modular (`AntiDetectionHook` trait) so platforms can extend guardrails without updating the scanner; Linux ships with tracer, `LD_PRELOAD`, and cgroup fingerprints out of the box.
- Future telemetry work will feed `core::metrics` and SIEM exporters for dashboards and automated response.

### Security Boundaries
```
┌─────────────────────────────────────────────────────────────┐
│                    PRIVILEGED OPERATIONS                   │ Root/Admin
├─────────────────────────────────────────────────────────────┤
│ • Memory Scanning     • Process Injection                  │
│ • Kernel Interfaces   • Hardware Access                    │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    USER-LEVEL OPERATIONS                   │ User
├─────────────────────────────────────────────────────────────┤
│ • File Scanning       • Configuration                      │
│ • Network Analysis    • Report Generation                  │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 SECURITY DESIGN

### Memory Protection
- **Stack Canaries**: Buffer overflow protection
- **ASLR**: Address Space Layout Randomization
- **DEP/NX**: Data Execution Prevention
- **Control Flow Integrity**: CFI for function call protection

### Cryptographic Security
- **Key Derivation**: PBKDF2/Argon2 for key generation
- **Encryption**: AES-256-GCM for data at rest
- **HMAC**: SHA-256 for data integrity
- **Secure Random**: Hardware RNG where available

### Communication Security
- **TLS 1.3**: Modern TLS for all network communications
- **Certificate Pinning**: Prevent MITM attacks
- **Mutual Authentication**: Client and server verification
- **Perfect Forward Secrecy**: Ephemeral key exchange

## 📊 PERFORMANCE CHARACTERISTICS

### Scalability Targets
- **Memory Usage**: <100MB for 10,000 concurrent processes
- **CPU Utilization**: <5% on production systems
- **I/O Throughput**: 1GB/sec file scanning with SSDs
- **Network Bandwidth**: <1Mbps for SIEM reporting

### Optimization Strategies
- **SIMD Instructions**: AVX2/NEON for pattern matching
- **Memory Mapping**: mmap for large file operations
- **Batch Processing**: Group operations for efficiency
- **Caching**: Intelligent caching of frequently accessed data

This architecture ensures ECH can operate at enterprise scale while maintaining the security and stealth characteristics required for professional DFIR operations.
