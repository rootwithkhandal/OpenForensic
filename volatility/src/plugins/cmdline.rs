//! Command-line argument extraction plugin.
//!
//! Implements:
//!   - `windows.cmdline.CmdLine` / `cmdline`
//!
//! Scans for EPROCESS structures and extracts process command-line arguments
//! from the Process Environment Block (PEB).

use crate::error::Result;
use crate::reader::MemoryReader;
use tokio::sync::mpsc::Sender;

/// Windows EPROCESS pool tag: "Proc"
const EPROCESS_POOL_TAG: &[u8; 4] = b"Proc";

/// Run the command-line extraction plugin.
pub async fn run(reader: &mut MemoryReader, tx: &Sender<String>) -> Result<()> {
    tx.send("[VOLATILITY] Running windows.cmdline.CmdLine — extracting process command-line arguments...".to_string()).await?;
    tx.send(format!("[VOLATILITY] Image: {} ({:.2} MB)", reader.path.display(), reader.size as f64 / 1_048_576.0)).await?;

    let offsets = reader.scan_pool_tag(EPROCESS_POOL_TAG)?;
    tx.send(format!("[VOLATILITY] Found {} potential EPROCESS pool tag hits", offsets.len())).await?;

    // Table header
    tx.send(format!("{:<8} {:<25} {}", "PID", "Process", "Command Line")).await?;
    tx.send("-".repeat(120)).await?;

    let mut cmd_count = 0u32;
    let mut seen_pids = std::collections::HashSet::new();

    for &tag_offset in &offsets {
        for base_delta in [4u64, 8, 12, 16] {
            let eproc_base = tag_offset + base_delta;

            // Known layouts: (pid_off, image_name_off, peb_off, create_off, exit_off)
            let layout_sets: &[(u64, u64, u64, u64, u64)] = &[
                (0x440, 0x5A8, 0x550, 0x570, 0x578),
                (0x180, 0x2E0, 0x1A8, 0x270, 0x278),
                (0x2E0, 0x450, 0x338, 0x488, 0x490),
                (0x2E0, 0x438, 0x338, 0x400, 0x408),
            ];

            for &(pid_off, name_off, peb_off, create_off, exit_off) in layout_sets {
                if eproc_base + name_off + 16 > reader.size {
                    continue;
                }

                // 1. Validate PID
                let pid = match reader.read_u32_le(eproc_base + pid_off) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if pid > 100_000 || (pid != 0 && pid % 4 != 0) {
                    continue;
                }

                // 2. Validate ImageName
                let image_name = match reader.read_ascii_string(eproc_base + name_off, 15) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => continue,
                };

                if image_name.len() < 2 || image_name.len() > 15 {
                    continue;
                }

                if !image_name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    continue;
                }

                if pid == 0 && !image_name.eq_ignore_ascii_case("Idle") && !image_name.to_lowercase().contains("idle") {
                    continue;
                }

                if !seen_pids.insert(eproc_base) {
                    break;
                }

                // Try to read PEB pointer
                let peb_addr = reader.read_u64_le(eproc_base + peb_off).unwrap_or(0);
                let mut cmdline = String::new();

                if peb_addr != 0 {
                    let search_name: Vec<u8> = image_name
                        .bytes()
                        .flat_map(|b| [b, 0u8])
                        .collect();

                    let search_start = if eproc_base > 0x10000 { eproc_base - 0x10000 } else { 0 };
                    let search_end = std::cmp::min(eproc_base + 0x10000, reader.size);
                    let search_len = (search_end - search_start) as usize;
                    let mut search_buf = vec![0u8; search_len];

                    if let Ok(n) = reader.read_at(search_start, &mut search_buf) {
                        if n >= search_name.len() {
                            for i in 0..n.saturating_sub(search_name.len()) {
                                if search_buf[i..i + search_name.len()] == search_name[..] {
                                    let cmd_start = if i > 512 { i - 512 } else { 0 };
                                    let cmd_region = &search_buf[cmd_start..std::cmp::min(i + 1024, n)];

                                    let mut chars = Vec::new();
                                    let mut j = 0;
                                    while j + 1 < cmd_region.len() {
                                        let ch = u16::from_le_bytes([cmd_region[j], cmd_region[j + 1]]);
                                        if ch == 0 {
                                            if !chars.is_empty() {
                                                break;
                                            }
                                        } else if ch < 0x20 || ch > 0x7E {
                                            chars.clear();
                                        } else {
                                            chars.push(ch);
                                        }
                                        j += 2;
                                    }

                                    if chars.len() > image_name.len() {
                                        cmdline = String::from_utf16_lossy(&chars);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                if cmdline.is_empty() {
                    cmdline = format!("[{}]", image_name);
                }

                tx.send(format!("{:<8} {:<25} {}", pid, image_name, cmdline)).await?;
                cmd_count += 1;
                break; // Found valid layout
            }
        }
    }

    tx.send(format!(
        "\n[VOLATILITY] cmdline complete — {} process command lines extracted",
        cmd_count
    )).await?;

    Ok(())
}
