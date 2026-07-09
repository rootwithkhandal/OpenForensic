#![allow(
    clippy::type_complexity,
    clippy::collapsible_if,
    clippy::too_many_arguments,
    clippy::useless_format,
    clippy::needless_borrow
)]

use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcquisitionCheckpoint {
    pub evidence_id: String,
    pub source_path: String,
    pub destination_path: String,
    pub total_bytes: u64,
    pub completed_offset: u64,
    pub chunk_size: u64,
    pub overlap_window_bytes: u64,
    pub sha256_partial_hex: String,
    pub last_updated_time: String,
    pub format: String,
}

/// Returns the sidecar checkpoint file path: `<dest>.openforensic_checkpoint.json`
pub fn get_checkpoint_path(destination_path: &Path) -> PathBuf {
    let mut name = destination_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "acquisition".to_string());
    name.push_str(".openforensic_checkpoint.json");
    destination_path.with_file_name(name)
}

/// Atomically save checkpoint metadata to sidecar JSON file
pub fn save_checkpoint(checkpoint: &AcquisitionCheckpoint) -> Result<(), String> {
    let dest_path = Path::new(&checkpoint.destination_path);
    let checkpoint_file = get_checkpoint_path(dest_path);

    let temp_path = checkpoint_file.with_extension("tmp_chk");
    let json = serde_json::to_string_pretty(checkpoint)
        .map_err(|e| format!("Failed to serialize checkpoint: {}", e))?;

    let mut f = File::create(&temp_path)
        .map_err(|e| format!("Failed to create temporary checkpoint file: {}", e))?;
    f.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write checkpoint data: {}", e))?;
    f.flush().map_err(|e| e.to_string())?;
    drop(f);

    fs::rename(&temp_path, &checkpoint_file)
        .map_err(|e| format!("Failed to atomically update checkpoint file: {}", e))?;

    Ok(())
}

/// Load existing checkpoint metadata if valid and matching source/dest
pub fn load_checkpoint(
    source_path: &str,
    destination_path: &Path,
    expected_total_bytes: u64,
) -> Option<AcquisitionCheckpoint> {
    let checkpoint_file = get_checkpoint_path(destination_path);
    if !checkpoint_file.exists() || !destination_path.exists() {
        return None;
    }

    let content = fs::read_to_string(&checkpoint_file).ok()?;
    let chk: AcquisitionCheckpoint = serde_json::from_str(&content).ok()?;

    // Validate that source matches and completed_offset <= expected_total_bytes
    if chk.source_path == source_path
        && chk.completed_offset > 0
        && chk.completed_offset <= expected_total_bytes
    {
        Some(chk)
    } else {
        None
    }
}

/// Delete sidecar checkpoint file after complete & verified acquisition
pub fn delete_checkpoint(destination_path: &Path) {
    let checkpoint_file = get_checkpoint_path(destination_path);
    let _ = fs::remove_file(checkpoint_file);
}

/// Verify overlap window (e.g. 64KB) around the resume boundary to ensure no corruption at crash point.
/// Returns the verified resume offset (rolling back if mismatch detected at the tail).
#[allow(dead_code)]
pub fn verify_overlap_window(
    src_file: &mut File,
    dst_file: &mut File,
    completed_offset: u64,
    overlap_size: u64,
) -> Result<u64, String> {
    if completed_offset == 0 {
        return Ok(0);
    }

    let overlap_len = std::cmp::min(completed_offset, overlap_size);
    let verify_start = completed_offset.saturating_sub(overlap_len);

    let mut src_buf = vec![0u8; overlap_len as usize];
    let mut dst_buf = vec![0u8; overlap_len as usize];

    src_file
        .seek(SeekFrom::Start(verify_start))
        .map_err(|e| format!("Failed to seek source for overlap check: {}", e))?;
    src_file
        .read_exact(&mut src_buf)
        .map_err(|e| format!("Failed to read source overlap block: {}", e))?;

    dst_file
        .seek(SeekFrom::Start(verify_start))
        .map_err(|e| format!("Failed to seek destination image for overlap check: {}", e))?;
    dst_file
        .read_exact(&mut dst_buf)
        .map_err(|e| format!("Failed to read destination overlap block: {}", e))?;

    if src_buf == dst_buf {
        // Overlap matches perfectly! Safe to resume from completed_offset
        Ok(completed_offset)
    } else {
        // Corruption detected at crash boundary (e.g. half-written block prior to crash).
        // Find highest matching prefix or rollback to verify_start
        let mut match_len = 0usize;
        while match_len < src_buf.len() && src_buf[match_len] == dst_buf[match_len] {
            match_len += 1;
        }
        // Round down to nearest 4KB sector boundary for safety
        let safe_rollback = verify_start + (match_len as u64 / 4096) * 4096;
        Ok(safe_rollback)
    }
}

/// Compute SHA-256 state up to a specified offset for checkpoint hashing
#[allow(dead_code)]
pub fn hash_partial_file(file: &mut File, up_to_offset: u64) -> Result<String, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek failed: {}", e))?;

    let mut hasher = Sha256::new();
    let mut remaining = up_to_offset;
    let mut buf = vec![0u8; 1048576]; // 1MB buffer

    while remaining > 0 {
        let read_size = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = file
            .read(&mut buf[..read_size])
            .map_err(|e| format!("Read failed during partial hash: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining = remaining.saturating_sub(n as u64);
    }

    Ok(format!("{:x}", hasher.finalize()))
}
