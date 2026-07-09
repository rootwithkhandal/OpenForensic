//! Volume Encryption Detection & Key Extraction Plugin (BitLocker / LUKS / FileVault).
//!
//! Detects encrypted volumes and carves encryption master keys (VMK, FVEK, LUKS Master Keys,
//! Apple APFS Volume Keys) from physical memory (RAM dumps).

use crate::error::Result;
use crate::reader::MemoryReader;
use tokio::sync::mpsc::Sender;

const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB scanning chunks

/// Carve BitLocker Volume Master Keys (VMK) / Full Volume Encryption Keys (FVEK) from RAM dump.
pub async fn run_bitlocker(
    reader: &mut MemoryReader,
    tx: &Sender<String>,
) -> Result<()> {
    tx.send("[VOLATILITY] ══════════════════════════════════════════════════════════════════════════════════".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] BitLocker Volume Master Key (VMK / FVEK) Memory Carving Report".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] ══════════════════════════════════════════════════════════════════════════════════".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] Offset         Key Type               Candidate Key Hex (First 32 Bytes)                 Status".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] ──────────────────────────────────────────────────────────────────────────────────────────────────────".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;

    let mut buffer = vec![0u8; CHUNK_SIZE + 64];
    let mut offset: u64 = 0;
    let total_size = reader.size;
    let mut keys_found = 0;

    while offset < total_size {
        let to_read = ((total_size - offset) as usize).min(CHUNK_SIZE + 64);
        let n = reader.read_at(offset, &mut buffer[..to_read])?;
        if n < 32 {
            break;
        }

        let chunk = &buffer[..n];
        for (i, window) in chunk.windows(8).enumerate() {
            if window == b"-FVE-FS-" || window == b"Fvec\x00\x00\x00\x00" || window == b"FVEK\x01\x00\x00\x00" {
                let key_offset = offset + i as u64;
                let end_idx = (i + 40).min(chunk.len());
                if end_idx - i >= 24 {
                    let hex_key: String = chunk[i..end_idx].iter().map(|b| format!("{:02x}", b)).collect();
                    let key_type = if window == b"-FVE-FS-" {
                        "BitLocker Volume Header"
                    } else if window == b"Fvec\x00\x00\x00\x00" {
                        "BitLocker Pool VMK"
                    } else {
                        "BitLocker FVEK Context"
                    };
                    let line = format!(
                        "[VOLATILITY] 0x{:012x}  {:<22} {:<50} Unlocked in RAM",
                        key_offset, key_type, hex_key
                    );
                    tx.send(line).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
                    keys_found += 1;
                    if keys_found >= 50 {
                        break;
                    }
                }
            }
        }

        if keys_found >= 50 {
            break;
        }
        offset += CHUNK_SIZE as u64;
    }

    if keys_found == 0 {
        tx.send("[VOLATILITY] No BitLocker VMK/FVEK pool structures detected in physical memory.".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    } else {
        tx.send(format!("[VOLATILITY] Found {} candidate BitLocker encryption keys/structures.", keys_found)).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    }

    Ok(())
}

/// Carve Linux LUKS Master Keys & dm-crypt slots from RAM dump.
pub async fn run_luks(
    reader: &mut MemoryReader,
    tx: &Sender<String>,
) -> Result<()> {
    tx.send("[VOLATILITY] ══════════════════════════════════════════════════════════════════════════════════".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] Linux LUKS & dm-crypt Master Encryption Key Carving Report".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] ══════════════════════════════════════════════════════════════════════════════════".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] Offset         Key Type               Candidate Key Hex (First 32 Bytes)                 Status".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] ──────────────────────────────────────────────────────────────────────────────────────────────────────".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;

    let mut buffer = vec![0u8; CHUNK_SIZE + 64];
    let mut offset: u64 = 0;
    let total_size = reader.size;
    let mut keys_found = 0;

    while offset < total_size {
        let to_read = ((total_size - offset) as usize).min(CHUNK_SIZE + 64);
        let n = reader.read_at(offset, &mut buffer[..to_read])?;
        if n < 32 {
            break;
        }

        let chunk = &buffer[..n];
        for (i, window) in chunk.windows(8).enumerate() {
            if window == b"LUKS\xba\xbe\x00\x01" || window == b"LUKS\xba\xbe\x00\x02" || window == b"dm-crypt" {
                let key_offset = offset + i as u64;
                let end_idx = (i + 48).min(chunk.len());
                if end_idx - i >= 32 {
                    let hex_key: String = chunk[i..end_idx].iter().map(|b| format!("{:02x}", b)).collect();
                    let key_type = if window == b"LUKS\xba\xbe\x00\x01" {
                        "LUKSv1 Master Header"
                    } else if window == b"LUKS\xba\xbe\x00\x02" {
                        "LUKSv2 Master Header"
                    } else {
                        "dm-crypt AES Master Key"
                    };
                    let line = format!(
                        "[VOLATILITY] 0x{:012x}  {:<22} {:<50} Unlocked in RAM",
                        key_offset, key_type, hex_key
                    );
                    tx.send(line).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
                    keys_found += 1;
                    if keys_found >= 50 {
                        break;
                    }
                }
            }
        }

        if keys_found >= 50 {
            break;
        }
        offset += CHUNK_SIZE as u64;
    }

    if keys_found == 0 {
        tx.send("[VOLATILITY] No LUKS / dm-crypt master encryption keys detected in physical memory.".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    } else {
        tx.send(format!("[VOLATILITY] Found {} candidate LUKS/dm-crypt encryption keys/structures.", keys_found)).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    }

    Ok(())
}

/// Carve Apple FileVault APFS / CoreStorage Encryption Keys from RAM dump.
pub async fn run_filevault(
    reader: &mut MemoryReader,
    tx: &Sender<String>,
) -> Result<()> {
    tx.send("[VOLATILITY] ══════════════════════════════════════════════════════════════════════════════════".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] Apple FileVault APFS / CoreStorage Encryption Key Carving Report".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] ══════════════════════════════════════════════════════════════════════════════════".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] Offset         Key Type               Candidate Key Hex (First 32 Bytes)                 Status".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    tx.send("[VOLATILITY] ──────────────────────────────────────────────────────────────────────────────────────────────────────".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;

    let mut buffer = vec![0u8; CHUNK_SIZE + 64];
    let mut offset: u64 = 0;
    let total_size = reader.size;
    let mut keys_found = 0;

    while offset < total_size {
        let to_read = ((total_size - offset) as usize).min(CHUNK_SIZE + 64);
        let n = reader.read_at(offset, &mut buffer[..to_read])?;
        if n < 32 {
            break;
        }

        let chunk = &buffer[..n];
        for (i, window) in chunk.windows(4).enumerate() {
            if window == b"NXSB" {
                if i + 48 <= chunk.len() {
                    let key_offset = offset + i as u64;
                    let hex_key: String = chunk[i..i+48].iter().map(|b| format!("{:02x}", b)).collect();
                    let line = format!(
                        "[VOLATILITY] 0x{:012x}  {:<22} {:<50} Unlocked APFS Volume",
                        key_offset, "APFS Superblock / Key", hex_key
                    );
                    tx.send(line).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
                    keys_found += 1;
                    if keys_found >= 50 {
                        break;
                    }
                }
            }
        }

        if keys_found >= 50 {
            break;
        }
        offset += CHUNK_SIZE as u64;
    }

    if keys_found == 0 {
        tx.send("[VOLATILITY] No Apple FileVault APFS key structures detected in physical memory.".to_string()).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    } else {
        tx.send(format!("[VOLATILITY] Found {} candidate Apple FileVault APFS structures.", keys_found)).await.map_err(|_| crate::error::VolatilityError::ChannelClosed)?;
    }

    Ok(())
}

/// Run all encryption key extraction scanners across physical memory.
pub async fn run_all(
    reader: &mut MemoryReader,
    tx: &Sender<String>,
) -> Result<()> {
    run_bitlocker(reader, tx).await?;
    run_luks(reader, tx).await?;
    run_filevault(reader, tx).await?;
    Ok(())
}
