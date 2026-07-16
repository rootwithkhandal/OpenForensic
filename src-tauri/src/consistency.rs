#![allow(dead_code)]
//! Filesystem consistency validation module.
//! Compares random blocks from the acquired image against the VSS snapshot
//! to detect drift or corruption.

use crate::acquisition::ProgressEvent;
use crate::error::{OpenForensicError, Result};
use std::io::{Read, Seek, SeekFrom};
use tokio::sync::mpsc::Sender;

/// Configuration for consistency validation.
#[derive(Debug, Clone)]
pub struct ConsistencyCheckConfig {
    /// Path to the acquired image file.
    pub image_path: String,
    /// VSS shadow copy device path to compare against.
    pub vss_device_path: String,
    /// Number of random blocks to sample for comparison.
    pub sample_count: u64,
    /// Block size for each comparison (default: 4096 bytes).
    pub block_size: usize,
}

/// Result of a consistency validation run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConsistencyReport {
    /// Total number of blocks checked.
    pub blocks_checked: u64,
    /// Number of blocks that matched.
    pub blocks_matched: u64,
    /// Number of blocks that did NOT match.
    pub blocks_mismatched: u64,
    /// Offsets where mismatches were found.
    pub mismatch_offsets: Vec<u64>,
    /// Overall consistency percentage.
    pub consistency_pct: f64,
    /// Whether the validation passed (100% match).
    pub passed: bool,
}

/// Validate consistency between an acquired image and the VSS snapshot.
///
/// This randomly samples `sample_count` blocks from the image, reads the same
/// offsets from the VSS shadow device, and compares them byte-for-byte.
pub async fn validate_consistency(
    config: &ConsistencyCheckConfig,
    progress_tx: Sender<ProgressEvent>,
) -> Result<ConsistencyReport> {
    use rand::Rng;

    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[CONSISTENCY] Starting consistency validation: {} samples, {} byte blocks",
            config.sample_count, config.block_size)
    )).await;

    // Open the acquired image
    let mut image_file = std::fs::File::open(&config.image_path)
        .map_err(|e| OpenForensicError::Backend(
            format!("Failed to open image file '{}': {}", config.image_path, e)
        ))?;

    let image_size = image_file.metadata()
        .map_err(|e| OpenForensicError::Backend(format!("Failed to get image metadata: {}", e)))?
        .len();

    if image_size == 0 {
        return Err(OpenForensicError::Backend("Image file is empty".to_string()));
    }

    // Open the VSS shadow copy device
    let mut vss_file = open_vss_device(&config.vss_device_path)?;

    let block_size = config.block_size;
    let max_offset = image_size.saturating_sub(block_size as u64);

    if max_offset == 0 {
        let _ = progress_tx.send(ProgressEvent::Log(
            "[CONSISTENCY] Image too small for block comparison, skipping.".to_string()
        )).await;
        return Ok(ConsistencyReport {
            blocks_checked: 0,
            blocks_matched: 0,
            blocks_mismatched: 0,
            mismatch_offsets: Vec::new(),
            consistency_pct: 100.0,
            passed: true,
        });
    }

    let sample_count = config.sample_count.min(max_offset / block_size as u64);
    let mut rng = rand::thread_rng();

    let mut blocks_matched = 0u64;
    let mut blocks_mismatched = 0u64;
    let mut mismatch_offsets = Vec::new();

    let mut image_buf = vec![0u8; block_size];
    let mut vss_buf = vec![0u8; block_size];

    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[CONSISTENCY] Image size: {} bytes, sampling {} blocks...", image_size, sample_count)
    )).await;

    for i in 0..sample_count {
        if progress_tx.is_closed() {
            return Err(OpenForensicError::Cancelled);
        }

        // Generate a random block-aligned offset
        let max_blocks = max_offset / block_size as u64;
        let random_block = rng.gen_range(0..=max_blocks);
        let offset = random_block * block_size as u64;

        // Read from image
        image_file.seek(SeekFrom::Start(offset))
            .map_err(|e| OpenForensicError::Backend(format!("Image seek error at offset {}: {}", offset, e)))?;
        let image_read = image_file.read(&mut image_buf)
            .map_err(|e| OpenForensicError::Backend(format!("Image read error at offset {}: {}", offset, e)))?;

        // Read from VSS
        vss_file.seek(SeekFrom::Start(offset))
            .map_err(|e| OpenForensicError::Backend(format!("VSS seek error at offset {}: {}", offset, e)))?;
        let vss_read = vss_file.read(&mut vss_buf)
            .map_err(|e| OpenForensicError::Backend(format!("VSS read error at offset {}: {}", offset, e)))?;

        // Compare
        if image_read == vss_read && image_buf[..image_read] == vss_buf[..vss_read] {
            blocks_matched += 1;
        } else {
            blocks_mismatched += 1;
            mismatch_offsets.push(offset);

            if mismatch_offsets.len() <= 10 {
                let _ = progress_tx.send(ProgressEvent::Log(
                    format!("[CONSISTENCY] Mismatch at offset 0x{:X} ({} bytes)", offset, offset)
                )).await;
            }
        }

        // Progress reporting every 10% or 100 blocks
        if (i + 1) % (sample_count / 10).max(1) == 0 {
            let pct = (i + 1) as f64 / sample_count as f64 * 100.0;
            let _ = progress_tx.send(ProgressEvent::Log(
                format!("[CONSISTENCY] Progress: {:.0}% ({}/{} blocks checked, {} mismatches)",
                    pct, i + 1, sample_count, blocks_mismatched)
            )).await;
        }
    }

    let total_checked = blocks_matched + blocks_mismatched;
    let consistency_pct = if total_checked > 0 {
        blocks_matched as f64 / total_checked as f64 * 100.0
    } else {
        100.0
    };
    let passed = blocks_mismatched == 0;

    let _ = progress_tx.send(ProgressEvent::Log(
        format!("[CONSISTENCY] Validation complete: {}/{} blocks matched ({:.2}%) — {}",
            blocks_matched, total_checked, consistency_pct,
            if passed { "PASSED ✓" } else { "FAILED ✗" })
    )).await;

    if !mismatch_offsets.is_empty() && mismatch_offsets.len() > 10 {
        let _ = progress_tx.send(ProgressEvent::Log(
            format!("[CONSISTENCY] ({} additional mismatches not shown)", mismatch_offsets.len() - 10)
        )).await;
    }

    Ok(ConsistencyReport {
        blocks_checked: total_checked,
        blocks_matched,
        blocks_mismatched,
        mismatch_offsets,
        consistency_pct,
        passed,
    })
}

/// Open the VSS device path for reading.
#[cfg(target_os = "windows")]
fn open_vss_device(vss_path: &str) -> Result<std::fs::File> {
    // On Windows, VSS shadow device paths can be opened with standard file APIs
    // as long as we use the \\?\ prefix correctly.
    std::fs::File::open(vss_path)
        .map_err(|e| OpenForensicError::Backend(
            format!("Failed to open VSS device '{}': {}", vss_path, e)
        ))
}

/// On non-Windows platforms, this is a no-op stub.
#[cfg(not(target_os = "windows"))]
fn open_vss_device(vss_path: &str) -> Result<std::fs::File> {
    std::fs::File::open(vss_path)
        .map_err(|e| OpenForensicError::Backend(
            format!("Failed to open device '{}': {}", vss_path, e)
        ))
}
