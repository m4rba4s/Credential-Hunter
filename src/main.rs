/**
 * Enterprise Credential Hunter (ECH) - Main Entry Point
 * 
 * Ultra enterprise-grade credential hunting system designed for DFIR and Red Team operations.
 * This is the primary CLI interface that orchestrates all credential hunting operations
 * with military-grade security, stealth capabilities, and enterprise integration.
 * 
 * SECURITY NOTICE: This tool is designed for authorized security testing only.
 * Unauthorized use against systems you do not own is illegal and unethical.
 * 
 * Architecture:
 * - Modular design with plugin architecture for extensibility
 * - Cross-platform support (Linux, Windows, macOS)
 * - Memory-safe operations with zero-copy optimizations
 * - Atomic operations for race-condition resistance
 * - Self-destruct capabilities for operational security
 */

use anyhow::{Context, Result};
use clap::{Arg, ArgAction, Command, ValueEnum};
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod core;
mod detection;
mod memory;
mod filesystem;
mod container;
mod stealth;
mod remediation;
mod siem;

use crate::core::{
    config::{EchConfig, LogLevel, OutputFormat},
    engine::EchEngine,
    security::SecurityContext,
};

/// ECH CLI Commands
#[derive(Debug, Clone, ValueEnum)]
enum Command {
    /// Scan filesystem for credentials
    FileScan,
    /// Scan process memory for credentials
    MemoryScan,
    /// Scan containers for credentials
    ContainerScan,
    /// Continuous monitoring mode
    Monitor,
    /// Generate compliance report
    Report,
    /// Test SIEM integration
    TestSiem,
    /// Self-destruct and cleanup
    SelfDestruct,
    /// Show system capabilities
    Capabilities,
}

/// Stealth operation modes
#[derive(Debug, Clone, ValueEnum)]
enum StealthMode {
    /// Normal operation (visible to monitoring)
    None,
    /// Low-profile operation
    Low,
    /// High stealth with evasion
    High,
    /// Maximum stealth with injection
    Maximum,
}

/// Remediation actions for found credentials
#[derive(Debug, Clone, ValueEnum)]
enum RemediationAction {
    /// Only report findings (default)
    Report,
    /// Mask credentials in place
    Mask,
    /// Move credentials to quarantine
    Quarantine,
    /// Securely wipe credentials
    Wipe,
    /// Trigger credential rotation
    Rotate,
}

fn build_cli() -> Command {
    Command::new("ech")
        .version(env!("CARGO_PKG_VERSION"))
        .author("DFIR Security Team <security@ech-security.com>")
        .about("Enterprise Credential Hunter - Ultra-grade DFIR credential hunting system")
        .long_about(
            "ECH is a paranoid, enterprise-grade credential hunting system designed by senior \
            DFIR engineers for real-world threat hunting, incident response, and red team operations. \
            \n\nThis system provides military-grade credential detection with stealth capabilities \
            and enterprise SIEM integration."
        )
        .arg(
            Arg::new("command")
                .help("Operation to perform")
                .value_enum::<Command>()
                .required(true)
                .index(1)
        )
        .arg(
            Arg::new("target")
                .long("target")
                .short('t')
                .help("Target path, PID, or container to scan")
                .value_name("PATH|PID|CONTAINER")
                .action(ArgAction::Append)
        )
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .help("Configuration file path")
                .value_name("FILE")
                .default_value("/etc/ech/config.yaml")
        )
        .arg(
            Arg::new("stealth")
                .long("stealth")
                .short('s')
                .help("Stealth operation mode")
                .value_enum::<StealthMode>()
                .default_value("none")
        )
        .arg(
            Arg::new("remediation")
                .long("remediation")
                .short('r')
                .help("Remediation action for found credentials")
                .value_enum::<RemediationAction>()
                .default_value("report")
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Output file for results")
                .value_name("FILE")
        )
        .arg(
            Arg::new("format")
                .long("format")
                .short('f')
                .help("Output format")
                .value_enum::<OutputFormat>()
                .default_value("json")
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Verbose logging")
                .action(ArgAction::Count)
        )
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .short('q')
                .help("Quiet mode (minimal output)")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Analyze only, no modifications")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("siem-endpoint")
                .long("siem-endpoint")
                .help("SIEM endpoint URL for real-time reporting")
                .value_name("URL")
        )
        .arg(
            Arg::new("correlation-id")
                .long("correlation-id")
                .help("Correlation ID for distributed tracing")
                .value_name("UUID")
        )
        .arg(
            Arg::new("user-context")
                .long("user-context")
                .help("User context for audit logging")
                .value_name("USER")
        )
        .arg(
            Arg::new("parallel")
                .long("parallel")
                .short('j')
                .help("Number of parallel workers")
                .value_name("N")
                .default_value("0")  // 0 = auto-detect
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Operation timeout in seconds")
                .value_name("SECONDS")
                .default_value("3600")  // 1 hour default
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .help("Patterns to exclude from scanning")
                .value_name("PATTERN")
                .action(ArgAction::Append)
        )
        .arg(
            Arg::new("include")
                .long("include")
                .help("Patterns to include in scanning")
                .value_name("PATTERN")
                .action(ArgAction::Append)
        )
        .arg(
            Arg::new("plugin")
                .long("plugin")
                .short('p')
                .help("Load additional detection plugins")
                .value_name("PATH")
                .action(ArgAction::Append)
        )
        .arg(
            Arg::new("self-destruct")
                .long("self-destruct")
                .help("Self-destruct after operation (removes all traces)")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("memory-limit")
                .long("memory-limit")
                .help("Memory usage limit in MB")
                .value_name("MB")
                .default_value("512")
        )
        .arg(
            Arg::new("no-network")
                .long("no-network")
                .help("Disable network operations")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("privileged")
                .long("privileged")
                .help("Run with elevated privileges (required for memory scanning)")
                .action(ArgAction::SetTrue)
        )
}

fn setup_logging(log_level: LogLevel, quiet: bool) -> Result<()> {
    let level = if quiet {
        tracing::Level::ERROR
    } else {
        match log_level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    };

    // Enhanced logging for enterprise environments
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("ech={}", level).into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
                .json()  // Structured logging for enterprise SIEM integration
        );

    subscriber.init();
    Ok(())
}

async fn run_ech() -> Result<()> {
    let matches = build_cli().get_matches();

    // Parse command line arguments
    let command = matches.get_one::<Command>("command").unwrap();
    let config_path = matches.get_one::<String>("config").unwrap();
    let stealth_mode = matches.get_one::<StealthMode>("stealth").unwrap();
    let remediation_action = matches.get_one::<RemediationAction>("remediation").unwrap();
    let verbose = matches.get_count("verbose");
    let quiet = matches.get_flag("quiet");
    let dry_run = matches.get_flag("dry-run");
    let self_destruct = matches.get_flag("self-destruct");
    let privileged = matches.get_flag("privileged");

    // Determine log level based on verbosity
    let log_level = match verbose {
        0 => LogLevel::Info,
        1 => LogLevel::Debug,
        _ => LogLevel::Trace,
    };

    // Initialize logging system
    setup_logging(log_level, quiet)
        .context("Failed to initialize logging system")?;

    info!("🔥 Enterprise Credential Hunter (ECH) v{} starting", env!("CARGO_PKG_VERSION"));
    info!("Command: {:?}, Stealth: {:?}, Remediation: {:?}", command, stealth_mode, remediation_action);

    // Load configuration
    let mut config = EchConfig::load_from_file(config_path)
        .context("Failed to load configuration")?;

    // Override config with CLI arguments
    if let Some(output_file) = matches.get_one::<String>("output") {
        config.output.file_path = Some(output_file.clone());
    }

    if let Some(format) = matches.get_one::<OutputFormat>("format") {
        config.output.format = format.clone();
    }

    if let Some(siem_endpoint) = matches.get_one::<String>("siem-endpoint") {
        config.siem.endpoint = Some(siem_endpoint.clone());
    }

    if let Some(correlation_id) = matches.get_one::<String>("correlation-id") {
        config.audit.correlation_id = Some(correlation_id.clone());
    }

    if let Some(user_context) = matches.get_one::<String>("user-context") {
        config.audit.user_context = Some(user_context.clone());
    }

    config.operation.dry_run = dry_run;
    config.operation.self_destruct = self_destruct;
    config.security.privileged_mode = privileged;

    // Parse targets
    let targets: Vec<String> = matches
        .get_many::<String>("target")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    // Security context validation
    let security_context = SecurityContext::new(&config)
        .context("Failed to initialize security context")?;

    if !security_context.validate_privileges() {
        warn!("Running without sufficient privileges. Some operations may fail.");
        if matches!(command, Command::MemoryScan) && !privileged {
            error!("Memory scanning requires elevated privileges. Use --privileged flag.");
            return Err(anyhow::anyhow!("Insufficient privileges for memory scanning"));
        }
    }

    // Initialize ECH engine
    let engine = Arc::new(
        EchEngine::new(config.clone())
            .await
            .context("Failed to initialize ECH engine")?
    );

    info!("🚀 ECH engine initialized successfully");

    // Execute command
    let result = match command {
        Command::FileScan => {
            info!("📁 Starting filesystem credential scan");
            engine.scan_filesystem(targets).await
        }
        Command::MemoryScan => {
            info!("🧠 Starting memory credential scan");
            engine.scan_memory(targets).await
        }
        Command::ContainerScan => {
            info!("🐳 Starting container credential scan");
            engine.scan_containers(targets).await
        }
        Command::Monitor => {
            info!("👁️ Starting continuous monitoring mode");
            engine.start_monitoring().await
        }
        Command::Report => {
            info!("📊 Generating compliance report");
            engine.generate_report().await
        }
        Command::TestSiem => {
            info!("🔗 Testing SIEM integration");
            engine.test_siem_integration().await
        }
        Command::SelfDestruct => {
            warn!("💥 Initiating self-destruct sequence");
            engine.self_destruct().await
        }
        Command::Capabilities => {
            info!("🔍 Checking system capabilities");
            engine.show_capabilities().await
        }
    };

    match result {
        Ok(_) => {
            info!("✅ Operation completed successfully");
            if self_destruct {
                warn!("🔥 Self-destruct activated - removing traces");
                engine.self_destruct().await?;
            }
        }
        Err(e) => {
            error!("❌ Operation failed: {}", e);
            if self_destruct {
                warn!("🔥 Self-destruct activated due to failure");
                let _ = engine.self_destruct().await;
            }
            return Err(e);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    // Set up panic handler for security
    std::panic::set_hook(Box::new(|panic_info| {
        error!("💀 PANIC: {}", panic_info);
        eprintln!("ECH encountered a critical error and must terminate for security reasons.");
        std::process::exit(1);
    }));

    // Security: Ensure we're running in a controlled environment
    if cfg!(debug_assertions) {
        warn!("⚠️ Running in DEBUG mode - not suitable for production");
    }

    if let Err(e) = run_ech().await {
        error!("💀 ECH terminated with error: {:#}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let app = build_cli();
        
        // Test basic command parsing
        let matches = app.try_get_matches_from(&["ech", "file-scan", "--target", "/tmp"]);
        assert!(matches.is_ok());
        
        // Test stealth mode parsing
        let matches = app.try_get_matches_from(&["ech", "memory-scan", "--stealth", "high"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_security_validation() {
        // Test that security validations work correctly
        let config = EchConfig::default();
        let security_context = SecurityContext::new(&config);
        assert!(security_context.is_ok());
    }
}