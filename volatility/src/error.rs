//! Custom error types for the Volatility Rust memory forensics engine.

use std::fmt;

/// All errors that can occur during memory analysis.
#[derive(Debug)]
pub enum VolatilityError {
    /// The memory dump file could not be opened or read.
    IoError(std::io::Error),
    /// The requested analysis profile/plugin is not supported.
    UnsupportedProfile(String),
    /// The memory image format is unrecognized or corrupt.
    InvalidImage(String),
    /// A signature or structure scan failed to find expected data.
    ScanError(String),
    /// Progress channel was closed unexpectedly.
    ChannelClosed,
}

impl fmt::Display for VolatilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VolatilityError::IoError(e) => write!(f, "I/O error: {}", e),
            VolatilityError::UnsupportedProfile(p) => {
                write!(f, "Unsupported analysis profile: {}", p)
            }
            VolatilityError::InvalidImage(msg) => write!(f, "Invalid memory image: {}", msg),
            VolatilityError::ScanError(msg) => write!(f, "Scan error: {}", msg),
            VolatilityError::ChannelClosed => write!(f, "Progress channel closed unexpectedly"),
        }
    }
}

impl std::error::Error for VolatilityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VolatilityError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VolatilityError {
    fn from(e: std::io::Error) -> Self {
        VolatilityError::IoError(e)
    }
}

impl From<tokio::sync::mpsc::error::SendError<String>> for VolatilityError {
    fn from(_: tokio::sync::mpsc::error::SendError<String>) -> Self {
        VolatilityError::ChannelClosed
    }
}

/// Convenience Result alias.
pub type Result<T> = std::result::Result<T, VolatilityError>;
