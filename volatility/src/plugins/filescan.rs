//! File object scanner plugin.
//!
//! Implements:
//!   - `windows.filescan.FileScan` / `filescan`
//!
//! Scans for _FILE_OBJECT pool tags in the memory image and extracts
//! file paths and access flags from located file object structures.

use crate::error::Result;
use crate::reader::MemoryReader;
use tokio::sync::mpsc::Sender;

/// Windows _FILE_OBJECT pool tag: "Fil\xe5" (File with 0xE5 marker, or "File")
/// In practice, the pool tag for file objects is "File" or "Fil\xe5".
const FILE_OBJECT_TAG_1: &[u8; 4] = b"File";
const FILE_OBJECT_TAG_2: &[u8; 4] = b"Fil\xe5";

/// Run the file object scanner.
pub async fn run(reader: &mut MemoryReader, tx: &Sender<String>) -> Result<()> {
    tx.send("[VOLATILITY] Running windows.filescan.FileScan — scanning for _FILE_OBJECT structures...".to_string()).await?;
    tx.send(format!("[VOLATILITY] Image: {} ({:.2} MB)", reader.path.display(), reader.size as f64 / 1_048_576.0)).await?;

    // Scan for both pool tag variants
    let mut offsets = reader.scan_pool_tag(FILE_OBJECT_TAG_1)?;
    let offsets2 = reader.scan_pool_tag(FILE_OBJECT_TAG_2)?;
    offsets.extend(offsets2);
    offsets.sort();
    offsets.dedup();

    tx.send(format!("[VOLATILITY] Found {} potential _FILE_OBJECT pool tag hits", offsets.len())).await?;

    // Table header
    tx.send(format!(
        "{:<18} {:<12} {}",
        "Offset", "Size", "Name"
    )).await?;
    tx.send("-".repeat(100)).await?;

    let mut file_count = 0u32;
    let mut seen_names = std::collections::HashSet::new();

    for &tag_offset in &offsets {
        let base = tag_offset + 4; // Skip past pool tag

        // _FILE_OBJECT layout for Windows 10 x64:
        // +0x058: _UNICODE_STRING FileName
        //   _UNICODE_STRING: Length (u16), MaximumLength (u16), padding (u32), Buffer (u64 ptr)
        // The FileName is a UNICODE_STRING whose Buffer pointer we can't directly
        // dereference without virtual-to-physical translation.
        //
        // Alternative approach: scan for path-like UTF-16LE strings near the file object.

        // Try multiple offsets where a UNICODE_STRING Length field might be
        let unicode_string_offsets = [0x58u64, 0x68, 0x48, 0x70];

        for &us_off in &unicode_string_offsets {
            if base + us_off + 16 > reader.size {
                continue;
            }

            // Read UNICODE_STRING.Length (in bytes)
            let mut len_buf = [0u8; 2];
            if reader.read_at(base + us_off, &mut len_buf).unwrap_or(0) < 2 {
                continue;
            }
            let str_len = u16::from_le_bytes(len_buf) as usize;

            // Sanity: reasonable path length (2 to 520 bytes = up to MAX_PATH chars)
            if str_len < 4 || str_len > 520 || str_len % 2 != 0 {
                continue;
            }

            // Read MaximumLength
            if reader.read_at(base + us_off + 2, &mut len_buf).unwrap_or(0) < 2 {
                continue;
            }
            let max_len = u16::from_le_bytes(len_buf) as usize;
            if max_len < str_len {
                continue;
            }

            // The Buffer pointer is at +8 in the UNICODE_STRING on x64
            // Since we can't translate virtual addresses, try reading inline data
            // that might follow the structure or search nearby for path-like strings

            // Attempt: read inline UTF-16 data right after the UNICODE_STRING header
            let inline_off = base + us_off + 16;
            if inline_off + str_len as u64 > reader.size {
                continue;
            }

            let filename = reader.read_utf16le_string(inline_off, str_len / 2)?;

            // Validate: should look like a Windows path
            if filename.len() < 2 {
                continue;
            }
            let has_path_chars = filename.contains('\\') || filename.contains('/');
            let has_extension = filename.contains('.');
            let is_device = filename.starts_with("\\Device\\") || filename.starts_with("\\??\\");

            if !has_path_chars && !has_extension && !is_device {
                continue;
            }

            // Additional check: ensure printable characters
            if !filename.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '\\' || c == '/' || c == ':' || c == '.') {
                continue;
            }

            if !seen_names.insert(filename.clone()) {
                break;
            }

            tx.send(format!(
                "0x{:<16X} {:<12} {}",
                tag_offset,
                str_len,
                filename
            )).await?;

            file_count += 1;
            break; // Found valid layout
        }
    }

    tx.send(format!(
        "\n[VOLATILITY] filescan complete — {} file objects identified",
        file_count
    )).await?;

    Ok(())
}
