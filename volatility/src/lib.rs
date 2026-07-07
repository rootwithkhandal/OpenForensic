//! # Volatility — Native Rust Memory Forensics Engine
//!
//! A high-performance, embeddable memory analysis library for OpenForensic.
//! Replaces the external Python-based Volatility framework with a native Rust
//! implementation that runs in-process without requiring Python installations.
//!
//! ## Supported Plugins
//!
//! | Profile                       | Description                              |
//! |-------------------------------|------------------------------------------|
//! | `windows.pslist.PsList`       | List running Windows processes           |
//! | `linux.pslist.PsList`         | List running Linux tasks                 |
//! | `mac.pslist.PsList`           | List running macOS processes             |
//! | `windows.netstat.NetStat`     | Network connections / listeners          |
//! | `windows.cmdline.CmdLine`     | Process command-line arguments           |
//! | `windows.filescan.FileScan`   | Open file object scanner                 |
//! | `windows.malfind.Malfind`     | Injected code / hidden PE detection      |
//!
//! ## Usage
//!
//! ```rust,no_run
//! use volatility::run_analysis;
//!
//! #[tokio::main]
//! async fn main() {
//!     let (tx, mut rx) = tokio::sync::mpsc::channel(256);
//!     tokio::spawn(async move {
//!         while let Some(line) = rx.recv().await {
//!             println!("{}", line);
//!         }
//!     });
//!     run_analysis("memory.raw", "windows.pslist.PsList", tx).await.unwrap();
//! }
//! ```

pub mod error;
pub mod reader;
pub mod plugins;

use error::{Result, VolatilityError};
use reader::MemoryReader;
use std::path::Path;
use tokio::sync::mpsc::Sender;

/// Primary entry point: analyze a memory dump file using the specified profile/plugin.
///
/// Opens the memory image at `image_path`, dispatches the requested `profile`
/// plugin, and streams structured output lines through `tx` in real-time.
///
/// # Arguments
/// * `image_path` — Path to the memory dump file (`.raw`, `.dmp`, `.vmem`, `.bin`, `.dd`)
/// * `profile` — Plugin name (e.g., `"windows.pslist.PsList"`, `"netstat"`, `"malfind"`)
/// * `tx` — Async channel sender for streaming output lines
///
/// # Errors
/// Returns `Err` if the file cannot be opened, the profile is unsupported,
/// or the progress channel is closed.
pub async fn run_analysis(
    image_path: &str,
    profile: &str,
    tx: Sender<String>,
) -> std::result::Result<(), String> {
    run_analysis_inner(image_path, profile, &tx)
        .await
        .map_err(|e| e.to_string())
}

/// Internal implementation with proper error types.
async fn run_analysis_inner(
    image_path: &str,
    profile: &str,
    tx: &Sender<String>,
) -> Result<()> {
    let path = Path::new(image_path);

    // Validate file exists
    if !path.exists() {
        return Err(VolatilityError::InvalidImage(format!(
            "Memory dump file not found: {}",
            image_path
        )));
    }

    // Validate extension
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let supported_extensions = ["raw", "dmp", "vmem", "bin", "dd", "mem", "img", "lime"];
    if !supported_extensions.contains(&ext.as_str()) && !ext.is_empty() {
        tx.send(format!(
            "[VOLATILITY] Warning: Unrecognized file extension '.{}'. Attempting analysis anyway.",
            ext
        ))
        .await?;
    }

    tx.send(format!(
        "[VOLATILITY] ═══════════════════════════════════════════════"
    ))
    .await?;
    tx.send(format!(
        "[VOLATILITY] OpenForensic Native Rust Volatility Engine v{}",
        env!("CARGO_PKG_VERSION")
    ))
    .await?;
    tx.send(format!(
        "[VOLATILITY] Image:   {}",
        image_path
    ))
    .await?;
    tx.send(format!(
        "[VOLATILITY] Profile: {}",
        profile
    ))
    .await?;
    tx.send(format!(
        "[VOLATILITY] ═══════════════════════════════════════════════"
    ))
    .await?;

    // Open memory dump
    let mut reader = MemoryReader::open(path)?;

    tx.send(format!(
        "[VOLATILITY] Opened memory image: {:.2} MB ({} bytes)",
        reader.size as f64 / 1_048_576.0,
        reader.size
    ))
    .await?;

    // Dispatch to the requested plugin
    plugins::dispatch(profile, &mut reader, tx).await?;

    tx.send("[VOLATILITY] ═══════════════════════════════════════════════".to_string())
        .await?;
    tx.send("[VOLATILITY] Analysis complete.".to_string())
        .await?;

    Ok(())
}

/// List all supported plugin profiles. Returns (name, description) pairs.
pub fn list_supported_plugins() -> &'static [(&'static str, &'static str)] {
    plugins::SUPPORTED_PLUGINS
}
