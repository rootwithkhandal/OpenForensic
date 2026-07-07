//! Injected code and hidden PE detection plugin.
//!
//! Implements:
//!   - `windows.malfind.Malfind` / `malfind`
//!
//! Scans process memory for unbacked executable Virtual Address Descriptor (VAD)
//! regions and hidden PE headers. Emits hex dumps and hash values that can
//! trigger OpenForensic's VirusTotal enrichment pipeline.

use crate::error::Result;
use crate::reader::MemoryReader;
use sha2::{Sha256, Digest};
use tokio::sync::mpsc::Sender;

/// PE magic bytes: "MZ"
const PE_MAGIC: &[u8; 2] = b"MZ";

/// VAD pool tags for Virtual Address Descriptors
const VAD_TAG_SHORT: &[u8; 4] = b"VadS";
const VAD_TAG_LONG: &[u8; 4] = b"Vadl";
const VAD_TAG_FULL: &[u8; 4] = b"Vad ";

/// Format bytes as a hex dump string (up to 64 bytes per line).
fn hex_dump(data: &[u8], base_offset: u64, max_bytes: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let show = std::cmp::min(data.len(), max_bytes);

    for chunk_start in (0..show).step_by(16) {
        let chunk_end = std::cmp::min(chunk_start + 16, show);
        let chunk = &data[chunk_start..chunk_end];

        let hex: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect();

        lines.push(format!(
            "0x{:08X}  {:<48} {}",
            base_offset + chunk_start as u64,
            hex,
            ascii
        ));
    }

    lines
}

/// Compute SHA-256 hash of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Compute MD5 hash of a byte slice.
fn md5_hex(data: &[u8]) -> String {
    use md5::Digest as Md5Digest;
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Run the malfind plugin — scan for injected code and hidden PE headers.
pub async fn run(reader: &mut MemoryReader, tx: &Sender<String>) -> Result<()> {
    tx.send("[VOLATILITY] Running windows.malfind.Malfind — scanning for injected code and hidden PE headers...".to_string()).await?;
    tx.send(format!("[VOLATILITY] Image: {} ({:.2} MB)", reader.path.display(), reader.size as f64 / 1_048_576.0)).await?;

    // Phase 1: Scan for PE headers (MZ magic) that are NOT at typical image base alignments.
    // These could indicate injected DLLs or shellcode with PE stubs.
    tx.send("[VOLATILITY] Phase 1: Scanning for hidden/injected PE headers (MZ signatures)...".to_string()).await?;

    let mz_offsets = reader.scan_pattern(PE_MAGIC)?;
    tx.send(format!("[VOLATILITY] Found {} MZ signature candidates", mz_offsets.len())).await?;

    let mut finding_count = 0u32;

    for &mz_offset in &mz_offsets {
        // Read the potential PE header region (first 256 bytes)
        let mut pe_buf = vec![0u8; 256];
        let n = reader.read_at(mz_offset, &mut pe_buf)?;
        if n < 64 {
            continue;
        }

        // Check for valid PE signature: "PE\0\0" at the e_lfanew offset
        let e_lfanew = u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;

        if e_lfanew == 0 || e_lfanew > 0x400 || e_lfanew + 4 > n {
            continue;
        }

        // If e_lfanew points within our buffer, verify PE signature
        if e_lfanew + 4 <= n {
            let pe_sig = &pe_buf[e_lfanew..e_lfanew + 4];
            if pe_sig != b"PE\0\0" {
                continue;
            }
        } else {
            // Need to read more data
            let mut sig_buf = [0u8; 4];
            if reader.read_at(mz_offset + e_lfanew as u64, &mut sig_buf).unwrap_or(0) < 4 {
                continue;
            }
            if &sig_buf != b"PE\0\0" {
                continue;
            }
        }

        // This is a genuine PE header. Check if it's at a suspicious (non-aligned) offset.
        let is_aligned = mz_offset % 0x1000 == 0; // Normal PE alignment is page-aligned

        // Read a larger sample for hashing (up to 4KB)
        let hash_size = std::cmp::min(4096u64, reader.size - mz_offset) as usize;
        let mut hash_buf = vec![0u8; hash_size];
        let hash_n = reader.read_at(mz_offset, &mut hash_buf)?;

        let sha256 = sha256_hex(&hash_buf[..hash_n]);
        let md5 = md5_hex(&hash_buf[..hash_n]);

        let suspicion = if is_aligned { "EMBEDDED PE" } else { "⚠️ SUSPICIOUS INJECTED PE" };

        tx.send(format!(
            "\n{} at offset 0x{:X} (e_lfanew=0x{:X}):",
            suspicion, mz_offset, e_lfanew
        )).await?;
        tx.send(format!("  SHA-256: {}", sha256)).await?;
        tx.send(format!("  MD5:    {}", md5)).await?;

        // Hex dump of the first 64 bytes
        for line in hex_dump(&pe_buf[..std::cmp::min(64, n)], mz_offset, 64) {
            tx.send(format!("  {}", line)).await?;
        }

        finding_count += 1;
    }

    // Phase 2: Scan for VAD structures that indicate executable but private (unbacked) memory
    tx.send("\n[VOLATILITY] Phase 2: Scanning for suspicious VAD entries (executable private memory)...".to_string()).await?;

    let mut vad_offsets = reader.scan_pool_tag(VAD_TAG_SHORT)?;
    vad_offsets.extend(reader.scan_pool_tag(VAD_TAG_LONG)?);
    vad_offsets.extend(reader.scan_pool_tag(VAD_TAG_FULL)?);
    vad_offsets.sort();

    tx.send(format!("[VOLATILITY] Found {} VAD pool tag candidates", vad_offsets.len())).await?;

    let mut vad_suspicious_count = 0u32;

    for &vad_offset in &vad_offsets {
        let base = vad_offset + 4;

        // Read protection flags from the VAD structure
        // In Windows 10 x64, _MMVAD_SHORT has protection at various offsets
        // We check for PAGE_EXECUTE_READWRITE (0x40) which is highly suspicious
        let protection_offsets = [0x30u64, 0x38, 0x28, 0x40];

        for &prot_off in &protection_offsets {
            if base + prot_off + 4 > reader.size {
                continue;
            }

            let prot = reader.read_u32_le(base + prot_off).unwrap_or(0);

            // PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80
            // Extract the protection from the VAD flags (bits 3-7 typically)
            let mm_prot = (prot >> 3) & 0x1F;

            // Protection value 6 = PAGE_EXECUTE_READWRITE in MM terms
            if mm_prot == 6 || mm_prot == 7 {
                // Read start and end VPN (Virtual Page Number)
                let start_vpn = reader.read_u64_le(base + 0x18).unwrap_or(0);
                let end_vpn = reader.read_u64_le(base + 0x20).unwrap_or(0);

                if start_vpn == 0 || end_vpn == 0 || end_vpn < start_vpn {
                    continue;
                }

                let region_size = (end_vpn - start_vpn + 1) * 0x1000;

                tx.send(format!(
                    "\n⚠️ SUSPICIOUS VAD: Execute+ReadWrite memory region at VPN 0x{:X}-0x{:X} ({} bytes)",
                    start_vpn * 0x1000,
                    (end_vpn + 1) * 0x1000,
                    region_size
                )).await?;

                tx.send(format!("  VAD pool tag at offset 0x{:X}, protection flags: 0x{:X}", vad_offset, prot)).await?;

                vad_suspicious_count += 1;
                break;
            }
        }
    }

    tx.send(format!(
        "\n[VOLATILITY] malfind complete — {} PE headers found, {} suspicious VAD regions",
        finding_count, vad_suspicious_count
    )).await?;

    if finding_count > 0 || vad_suspicious_count > 0 {
        tx.send("[VOLATILITY] ⚠️ Potential code injection or process hollowing detected. Review findings above.".to_string()).await?;
    } else {
        tx.send("[VOLATILITY] No obvious injected code or hidden PE headers detected.".to_string()).await?;
    }

    Ok(())
}
