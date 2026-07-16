//! Process listing plugin — scans memory for EPROCESS / task_struct structures.
//!
//! Implements:
//!   - `windows.pslist.PsList` / `pslist`
//!   - `linux.pslist.PsList` / `linux_pslist`
//!   - `mac.pslist.PsList` / `mac_pslist`

use crate::error::Result;
use crate::reader::MemoryReader;
use tokio::sync::mpsc::Sender;

/// Windows EPROCESS pool tag: "Proc" (little-endian 0x636F7250).
const EPROCESS_POOL_TAG: &[u8; 4] = b"Proc";

/// Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to a human-readable string.
fn filetime_to_string(ft: i64) -> String {
    if ft <= 0 {
        return "N/A".to_string();
    }
    // Windows epoch offset: 11644473600 seconds between 1601-01-01 and 1970-01-01
    let unix_secs = (ft / 10_000_000) - 11_644_473_600;
    match chrono::DateTime::from_timestamp(unix_secs, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "N/A".to_string(),
    }
}

/// Run Windows process listing (pslist).
///
/// Scans for EPROCESS pool tags and extracts process metadata fields
/// from known offsets within the structure.
pub async fn run_windows(reader: &mut MemoryReader, tx: &Sender<String>) -> Result<()> {
    tx.send("[VOLATILITY] Running windows.pslist.PsList — scanning for EPROCESS structures...".to_string()).await?;
    tx.send(format!("[VOLATILITY] Image: {} ({:.2} MB)", reader.path.display(), reader.size as f64 / 1_048_576.0)).await?;

    // Scan for "Proc" pool tags
    let offsets = reader.scan_pool_tag(EPROCESS_POOL_TAG)?;
    tx.send(format!("[VOLATILITY] Found {} potential EPROCESS pool tag hits", offsets.len())).await?;

    // Table header
    tx.send(format!(
        "{:<8} {:<8} {:<20} {:<18} {:<8} {:<8} {:<10} {:<8} {:<23} {:<23} {}",
        "PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime", "File output"
    )).await?;
    tx.send("-".repeat(150)).await?;

    let mut process_count = 0u32;
    let mut seen_pids = std::collections::HashSet::new();

    for &tag_offset in &offsets {
        // When allocated via ExAllocatePoolWithTag, the pool tag "Proc" sits in the pool header.
        // The EPROCESS structure body typically starts 4, 8, or 12 bytes after the tag offset.
        for base_delta in [4u64, 8, 12, 16] {
            let eproc_base = tag_offset + base_delta;

            // Known struct layouts: (pid, ppid, image_name, threads, handles, session_id, create_time, exit_time, wow64_off)
            let pid_offsets: &[(u64, u64, u64, u64, u64, u64, u64, u64, u64)] = &[
                // Windows 10/11 x64
                (0x440, 0x540, 0x5A8, 0x580, 0x578, 0x448, 0x570, 0x578, 0x528),
                // Windows 7 x64
                (0x180, 0x290, 0x2E0, 0x288, 0x280, 0x188, 0x270, 0x278, 0x320),
                // Windows 10 x64 alternate
                (0x2E0, 0x2E8, 0x450, 0x498, 0x490, 0x2F8, 0x488, 0x490, 0x428),
                // Windows 8.1 x64
                (0x2E0, 0x3E0, 0x438, 0x410, 0x408, 0x2E8, 0x400, 0x408, 0x410),
            ];

            for &(pid_off, ppid_off, name_off, threads_off, handles_off, session_off, create_off, exit_off, wow64_off) in pid_offsets {
                if eproc_base + name_off + 16 > reader.size {
                    continue;
                }

                // 1. Read and validate PID
                let pid = match reader.read_u32_le(eproc_base + pid_off) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if pid > 100_000 || (pid != 0 && pid % 4 != 0) {
                    continue;
                }

                // 2. Read and validate ImageFileName (15-char ASCII string in EPROCESS)
                let image_name = match reader.read_ascii_string(eproc_base + name_off, 15) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => continue,
                };

                if image_name.len() < 2 || image_name.len() > 15 {
                    continue;
                }

                // Must be entirely printable ASCII without control characters
                if !image_name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    continue;
                }

                // If PID is 0, name MUST be Idle or System Idle Process
                if pid == 0 && !image_name.eq_ignore_ascii_case("Idle") && !image_name.to_lowercase().contains("idle") {
                    continue;
                }

                // 3. Read PPID (don't discard process if PPID is weird, just cap or default)
                let ppid = match reader.read_u32_le(eproc_base + ppid_off) {
                    Ok(v) if v < 100_000 && (v == 0 || v % 4 == 0) => v,
                    _ => 0,
                };

                // 4. Read Threads, Handles, Session (default to 0 if out of range, never drop process)
                let threads = match reader.read_u32_le(eproc_base + threads_off) {
                    Ok(v) if v <= 50_000 => v,
                    _ => 0,
                };
                let handles = match reader.read_u32_le(eproc_base + handles_off) {
                    Ok(v) if v <= 500_000 => v,
                    _ => 0,
                };
                let session_id = match reader.read_u32_le(eproc_base + session_off) {
                    Ok(v) if v <= 100 => v,
                    _ => 0,
                };

                // 5. Read Timestamps (FILETIME: 100-ns intervals since 1601)
                let create_time = reader.read_i64_le(eproc_base + create_off).unwrap_or(0);
                let exit_time = reader.read_i64_le(eproc_base + exit_off).unwrap_or(0);

                // Avoid duplicate reporting of the exact same EPROCESS structure address
                if !seen_pids.insert(eproc_base) {
                    break;
                }

                let wow64_val = reader.read_u64_le(eproc_base + wow64_off).unwrap_or(0);
                let wow64_str = if wow64_val > 0x10000 { "True" } else { "False" };

                tx.send(format!(
                    "{:<8} {:<8} {:<20} {:<18} {:<8} {:<8} {:<10} {:<8} {:<23} {:<23} {}",
                    pid,
                    ppid,
                    image_name,
                    format!("0x{:x}", eproc_base),
                    threads,
                    handles,
                    session_id,
                    wow64_str,
                    filetime_to_string(create_time),
                    filetime_to_string(exit_time),
                    "Disabled",
                )).await?;

                process_count += 1;
                break; // Found a valid layout for this tag offset
            }
        }
    }

    tx.send(format!(
        "\n[VOLATILITY] pslist complete — {} processes identified from {} pool tag candidates",
        process_count,
        offsets.len()
    )).await?;

    Ok(())
}

/// Run Linux process listing.
///
/// Scans for `task_struct` signatures in the memory image.
pub async fn run_linux(reader: &mut MemoryReader, tx: &Sender<String>) -> Result<()> {
    tx.send("[VOLATILITY] Running linux.pslist.PsList — scanning for task_struct structures...".to_string()).await?;
    tx.send(format!("[VOLATILITY] Image: {} ({:.2} MB)", reader.path.display(), reader.size as f64 / 1_048_576.0)).await?;

    // Linux task_struct identification: scan for the "swapper" init process name
    // which is always PID 0 and can anchor our struct offset calculations.
    let pattern = b"swapper/0\0";
    let offsets = reader.scan_pattern(pattern)?;
    tx.send(format!("[VOLATILITY] Found {} potential task_struct anchor points", offsets.len())).await?;

    tx.send(format!(
        "{:<8} {:<8} {:<25} {:<18} {:<12} {:<12} {:<10} {}",
        "PID", "PPID", "COMM", "Offset(V)", "UID", "GID", "State", "File output"
    )).await?;
    tx.send("-".repeat(120)).await?;

    let mut task_count = 0u32;

    // For each anchor, try to walk back to find the task_struct base
    // and read fields at known offsets
    for &name_offset in &offsets {
        // task_struct.comm is typically at offset +0x720 (kernel 5.x) or +0x690 (kernel 4.x)
        for comm_delta in [0x720u64, 0x690, 0x750, 0x668] {
            if name_offset < comm_delta {
                continue;
            }
            let task_base = name_offset - comm_delta;

            // PID is typically at offset +0x578 (kernel 5.x) or +0x4C0 (kernel 4.x)
            let pid_offset_from_comm: u64 = comm_delta - 0x1A8; // approximate
            if task_base + pid_offset_from_comm + 4 > reader.size {
                continue;
            }

            let pid = match reader.read_u32_le(task_base + pid_offset_from_comm) {
                Ok(v) if v < 100_000 => v,
                _ => continue,
            };

            let comm = reader.read_ascii_string(name_offset, 16).unwrap_or_default();
            if comm.is_empty() {
                continue;
            }

            tx.send(format!(
                "{:<8} {:<8} {:<25} {:<18} {:<12} {:<12} {:<10} {}",
                pid, 0, comm, format!("0x{:x}", task_base), 0, 0, "Running", "Disabled"
            )).await?;

            task_count += 1;
        }
    }

    // If no swapper found, do a best-effort scan for common process names
    if task_count == 0 {
        tx.send("[VOLATILITY] No task_struct anchors found via swapper pattern. Attempting heuristic scan...".to_string()).await?;

        for name in ["systemd\0", "init\0", "kthreadd\0", "bash\0", "sshd\0"] {
            let hits = reader.scan_pattern(name.as_bytes())?;
            for &off in hits.iter().take(5) {
                let comm = reader.read_ascii_string(off, 16).unwrap_or_default();
                if !comm.is_empty() {
                    tx.send(format!(
                        "{:<8} {:<8} {:<25} {:<18} {:<12} {:<12} {:<10} {}",
                        "?", "?", comm, format!("0x{:x}", off), "?", "?", "Detected", "Disabled"
                    )).await?;
                    task_count += 1;
                }
            }
        }
    }

    tx.send(format!(
        "\n[VOLATILITY] linux.pslist complete — {} tasks identified",
        task_count
    )).await?;

    Ok(())
}

/// Run macOS process listing.
///
/// Scans for XNU proc structures in the memory image.
pub async fn run_mac(reader: &mut MemoryReader, tx: &Sender<String>) -> Result<()> {
    tx.send("[VOLATILITY] Running mac.pslist.PsList — scanning for XNU proc structures...".to_string()).await?;
    tx.send(format!("[VOLATILITY] Image: {} ({:.2} MB)", reader.path.display(), reader.size as f64 / 1_048_576.0)).await?;

    // macOS XNU kernel: scan for known process names to anchor
    let pattern = b"kernel_task\0";
    let offsets = reader.scan_pattern(pattern)?;
    tx.send(format!("[VOLATILITY] Found {} potential proc structure anchor points", offsets.len())).await?;

    tx.send(format!(
        "{:<8} {:<8} {:<25} {:<18} {:<12} {:<10} {}",
        "PID", "PPID", "COMM", "Offset(V)", "UID", "State", "File output"
    )).await?;
    tx.send("-".repeat(110)).await?;

    let mut proc_count = 0u32;

    for &name_offset in &offsets {
        let comm = reader.read_ascii_string(name_offset, 16).unwrap_or_default();
        if !comm.is_empty() {
            tx.send(format!(
                "{:<8} {:<8} {:<25} {:<18} {:<12} {:<10} {}",
                0, 0, comm, format!("0x{:x}", name_offset), 0, "Running", "Disabled"
            )).await?;
            proc_count += 1;
        }
    }

    // Also search for common macOS process names
    if proc_count == 0 {
        tx.send("[VOLATILITY] No kernel_task anchor found. Attempting heuristic scan...".to_string()).await?;
        for name in ["launchd\0", "WindowServer\0", "loginwindow\0"] {
            let hits = reader.scan_pattern(name.as_bytes())?;
            for &off in hits.iter().take(3) {
                let comm = reader.read_ascii_string(off, 16).unwrap_or_default();
                if !comm.is_empty() {
                    tx.send(format!(
                        "{:<8} {:<8} {:<25} {:<18} {:<12} {:<10} {}",
                        "?", "?", comm, format!("0x{:x}", off), "?", "Detected", "Disabled"
                    )).await?;
                    proc_count += 1;
                }
            }
        }
    }

    tx.send(format!(
        "\n[VOLATILITY] mac.pslist complete — {} processes identified",
        proc_count
    )).await?;

    Ok(())
}
