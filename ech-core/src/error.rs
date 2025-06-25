/**
 * Enterprise Credential Hunter - Unified Error System
 * 
 * Centralized error handling for all ECH modules with proper categorization,
 * context preservation, and enterprise-grade error reporting.
 */

use std::fmt;
use serde::{Deserialize, Serialize};

/// Main error type for ECH operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EchError {
    /// Configuration related errors
    Configuration {
        message: String,
        source: Option<String>,
    },
    
    /// Detection engine errors
    Detection {
        message: String,
        detection_type: String,
        context: Option<String>,
    },
    
    /// Memory access and scanning errors
    Memory {
        message: String,
        process_id: Option<u32>,
        address: Option<u64>,
    },
    
    /// Filesystem operations errors
    Filesystem {
        message: String,
        path: Option<String>,
        operation: String,
    },
    
    /// Network and IMDS errors
    Network {
        message: String,
        endpoint: Option<String>,
        status_code: Option<u16>,
    },
    
    /// Stealth and evasion errors
    Stealth {
        message: String,
        technique: String,
        target: Option<String>,
    },
    
    /// Authentication and credential errors
    Authentication {
        message: String,
        auth_type: String,
        target: Option<String>,
    },
    
    /// Serialization/Deserialization errors
    Serialization {
        message: String,
        data_type: String,
    },
    
    /// External dependency errors
    External {
        message: String,
        dependency: String,
        original_error: String,
    },
    
    /// Internal logic errors (should not happen in production)
    Internal {
        message: String,
        location: String,
    },
    
    /// Permission and access control errors
    Permission {
        message: String,
        required_permission: String,
        resource: String,
    },
    
    /// Timeout errors
    Timeout {
        message: String,
        operation: String,
        duration_ms: u64,
    },
    
    /// Resource exhaustion errors
    Resource {
        message: String,
        resource_type: String,
        limit: Option<String>,
    },
}

impl fmt::Display for EchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EchError::Configuration { message, source } => {
                write!(f, "Configuration Error: {}", message)?;
                if let Some(src) = source {
                    write!(f, " (source: {})", src)?;
                }
                Ok(())
            }
            EchError::Detection { message, detection_type, context } => {
                write!(f, "Detection Error [{}]: {}", detection_type, message)?;
                if let Some(ctx) = context {
                    write!(f, " (context: {})", ctx)?;
                }
                Ok(())
            }
            EchError::Memory { message, process_id, address } => {
                write!(f, "Memory Error: {}", message)?;
                if let Some(pid) = process_id {
                    write!(f, " (PID: {})", pid)?;
                }
                if let Some(addr) = address {
                    write!(f, " (address: 0x{:x})", addr)?;
                }
                Ok(())
            }
            EchError::Filesystem { message, path, operation } => {
                write!(f, "Filesystem Error [{}]: {}", operation, message)?;
                if let Some(p) = path {
                    write!(f, " (path: {})", p)?;
                }
                Ok(())
            }
            EchError::Network { message, endpoint, status_code } => {
                write!(f, "Network Error: {}", message)?;
                if let Some(ep) = endpoint {
                    write!(f, " (endpoint: {})", ep)?;
                }
                if let Some(code) = status_code {
                    write!(f, " (status: {})", code)?;
                }
                Ok(())
            }
            EchError::Stealth { message, technique, target } => {
                write!(f, "Stealth Error [{}]: {}", technique, message)?;
                if let Some(tgt) = target {
                    write!(f, " (target: {})", tgt)?;
                }
                Ok(())
            }
            EchError::Authentication { message, auth_type, target } => {
                write!(f, "Authentication Error [{}]: {}", auth_type, message)?;
                if let Some(tgt) = target {
                    write!(f, " (target: {})", tgt)?;
                }
                Ok(())
            }
            EchError::Serialization { message, data_type } => {
                write!(f, "Serialization Error [{}]: {}", data_type, message)
            }
            EchError::External { message, dependency, original_error } => {
                write!(f, "External Error [{}]: {} (original: {})", dependency, message, original_error)
            }
            EchError::Internal { message, location } => {
                write!(f, "Internal Error at {}: {}", location, message)
            }
            EchError::Permission { message, required_permission, resource } => {
                write!(f, "Permission Error: {} (need: {} for: {})", message, required_permission, resource)
            }
            EchError::Timeout { message, operation, duration_ms } => {
                write!(f, "Timeout Error [{}]: {} ({}ms)", operation, message, duration_ms)
            }
            EchError::Resource { message, resource_type, limit } => {
                write!(f, "Resource Error [{}]: {}", resource_type, message)?;
                if let Some(lim) = limit {
                    write!(f, " (limit: {})", lim)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for EchError {}

/// Result type alias for ECH operations
pub type EchResult<T> = Result<T, EchError>;

/// Helper macros for creating specific error types
#[macro_export]
macro_rules! config_error {
    ($msg:expr) => {
        EchError::Configuration {
            message: $msg.to_string(),
            source: None,
        }
    };
    ($msg:expr, $source:expr) => {
        EchError::Configuration {
            message: $msg.to_string(),
            source: Some($source.to_string()),
        }
    };
}

#[macro_export]
macro_rules! detection_error {
    ($msg:expr, $type:expr) => {
        EchError::Detection {
            message: $msg.to_string(),
            detection_type: $type.to_string(),
            context: None,
        }
    };
    ($msg:expr, $type:expr, $ctx:expr) => {
        EchError::Detection {
            message: $msg.to_string(),
            detection_type: $type.to_string(),
            context: Some($ctx.to_string()),
        }
    };
}

#[macro_export]
macro_rules! memory_error {
    ($msg:expr) => {
        EchError::Memory {
            message: $msg.to_string(),
            process_id: None,
            address: None,
        }
    };
    ($msg:expr, $pid:expr) => {
        EchError::Memory {
            message: $msg.to_string(),
            process_id: Some($pid),
            address: None,
        }
    };
    ($msg:expr, $pid:expr, $addr:expr) => {
        EchError::Memory {
            message: $msg.to_string(),
            process_id: Some($pid),
            address: Some($addr),
        }
    };
}

#[macro_export]
macro_rules! internal_error {
    ($msg:expr) => {
        EchError::Internal {
            message: $msg.to_string(),
            location: format!("{}:{}", file!(), line!()),
        }
    };
}

/// Conversion from anyhow::Error for compatibility
impl From<anyhow::Error> for EchError {
    fn from(err: anyhow::Error) -> Self {
        EchError::External {
            message: "External library error".to_string(),
            dependency: "anyhow".to_string(),
            original_error: err.to_string(),
        }
    }
}

/// Conversion from std::io::Error
impl From<std::io::Error> for EchError {
    fn from(err: std::io::Error) -> Self {
        EchError::Filesystem {
            message: err.to_string(),
            path: None,
            operation: "io_operation".to_string(),
        }
    }
}

/// Conversion from serde_json::Error
impl From<serde_json::Error> for EchError {
    fn from(err: serde_json::Error) -> Self {
        EchError::Serialization {
            message: err.to_string(),
            data_type: "json".to_string(),
        }
    }
}

/// Conversion from reqwest::Error
impl From<reqwest::Error> for EchError {
    fn from(err: reqwest::Error) -> Self {
        EchError::Network {
            message: err.to_string(),
            endpoint: err.url().map(|u| u.to_string()),
            status_code: err.status().map(|s| s.as_u16()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = config_error!("Invalid configuration");
        assert!(error.to_string().contains("Configuration Error"));
        
        let error = detection_error!("Pattern not found", "regex", "test context");
        assert!(error.to_string().contains("Detection Error"));
        assert!(error.to_string().contains("test context"));
    }

    #[test]
    fn test_error_conversions() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let ech_err: EchError = io_err.into();
        match ech_err {
            EchError::Filesystem { .. } => {},
            _ => panic!("Wrong error type"),
        }
    }
}