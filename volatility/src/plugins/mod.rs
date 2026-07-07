//! Plugin dispatcher — routes profile/plugin names to specific forensic analyzers.

pub mod pslist;
pub mod netstat;
pub mod cmdline;
pub mod filescan;
pub mod malfind;

use crate::error::{Result, VolatilityError};
use crate::reader::MemoryReader;
use tokio::sync::mpsc::Sender;

/// Canonical list of supported plugins for help/listing output.
pub const SUPPORTED_PLUGINS: &[(&str, &str)] = &[
    ("windows.pslist.PsList", "List running processes (Windows)"),
    ("pslist", "List running processes (Windows, short alias)"),
    ("linux.pslist.PsList", "List running processes (Linux)"),
    ("linux_pslist", "List running processes (Linux, short alias)"),
    ("mac.pslist.PsList", "List running processes (macOS)"),
    ("mac_pslist", "List running processes (macOS, short alias)"),
    ("windows.netstat.NetStat", "List network connections (Windows)"),
    ("netstat", "List network connections (short alias)"),
    ("connscan", "Scan for connection objects (alias)"),
    ("windows.cmdline.CmdLine", "Display process command-line args (Windows)"),
    ("cmdline", "Display process command-line args (short alias)"),
    ("windows.filescan.FileScan", "Scan for file objects (Windows)"),
    ("filescan", "Scan for file objects (short alias)"),
    ("windows.malfind.Malfind", "Find injected code and hidden PE (Windows)"),
    ("malfind", "Find injected code and hidden PE (short alias)"),
];

/// Run a specific analysis plugin against the opened memory image.
///
/// The `profile` string is matched case-insensitively against known plugin
/// names. Structured output lines are sent through `tx` for real-time
/// streaming to the frontend or CLI.
pub async fn dispatch(
    profile: &str,
    reader: &mut MemoryReader,
    tx: &Sender<String>,
) -> Result<()> {
    let profile_lower = profile.to_lowercase();
    let profile_lower = profile_lower.as_str();

    match profile_lower {
        "windows.pslist.pslist" | "pslist" => {
            pslist::run_windows(reader, tx).await
        }
        "linux.pslist.pslist" | "linux_pslist" => {
            pslist::run_linux(reader, tx).await
        }
        "mac.pslist.pslist" | "mac_pslist" => {
            pslist::run_mac(reader, tx).await
        }
        "windows.netstat.netstat" | "netstat" | "connscan" => {
            netstat::run(reader, tx).await
        }
        "windows.cmdline.cmdline" | "cmdline" => {
            cmdline::run(reader, tx).await
        }
        "windows.filescan.filescan" | "filescan" => {
            filescan::run(reader, tx).await
        }
        "windows.malfind.malfind" | "malfind" => {
            malfind::run(reader, tx).await
        }
        _ => Err(VolatilityError::UnsupportedProfile(profile.to_string())),
    }
}
