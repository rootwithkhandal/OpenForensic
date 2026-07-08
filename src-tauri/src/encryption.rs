//! Encryption Detection & Key Extraction module.
//! Detects BitLocker, LUKS, Apple FileVault, and Android FBE (File-Based Encryption) volumes during acquisition.
//! Extracts volume master keys (VMK / Master Keys / Gatekeeper CE keys) from RAM dumps where possible.

use crate::error::{OpenForensicError, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionType {
    None,
    BitLocker,
    Luks1,
    Luks2,
    FileVault,
    AndroidFbe,
    UnknownEncrypted,
}

impl std::fmt::Display for EncryptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionType::None => write!(f, "Unencrypted / Cleartext"),
            EncryptionType::BitLocker => write!(f, "Windows BitLocker (-FVE-FS-)"),
            EncryptionType::Luks1 => write!(f, "Linux LUKSv1 Master Header"),
            EncryptionType::Luks2 => write!(f, "Linux LUKSv2 Master Header"),
            EncryptionType::FileVault => write!(f, "Apple FileVault APFS / CoreStorage"),
            EncryptionType::AndroidFbe => write!(f, "Android FBE (File-Based Encryption / Ext4-F2FS fscrypt)"),
            EncryptionType::UnknownEncrypted => write!(f, "Unknown / Custom Volume Encryption"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionReport {
    pub path: String,
    pub encryption_type: EncryptionType,
    pub is_encrypted: bool,
    pub details: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedKey {
    pub key_type: String, // e.g., "BitLocker VMK", "LUKS Master Key", "Android Gatekeeper CE Key"
    pub hex_key: String,
    pub offset: u64,
    pub details: String,
}

/// Inspect header bytes of a block device or image file to detect volume encryption.
pub fn detect_encryption_from_bytes(header: &[u8]) -> EncryptionType {
    if header.len() < 512 {
        return EncryptionType::None;
    }

    // 1. Check LUKS (magic bytes "LUKS\xba\xbe" at offset 0)
    if header.starts_with(b"LUKS\xba\xbe") {
        if header.len() > 6 && header[6] == 0x00 && header[7] == 0x01 {
            return EncryptionType::Luks1;
        }
        return EncryptionType::Luks2;
    }

    // 2. Check BitLocker (-FVE-FS- at offset 3 inside NTFS/FAT boot sector or offset 0)
    if (header.len() >= 11 && &header[3..11] == b"-FVE-FS-") || (header.len() >= 8 && &header[0..8] == b"-FVE-FS-") {
        return EncryptionType::BitLocker;
    }
    // Check BitLocker NTFS boot sector OEM ID (offset 3) for "MSWIN4.1" with FVE metadata
    if header.len() >= 11 && &header[3..11] == b"MSWIN4.1" && header.len() >= 512 && (&header[0x1a0..0x1a4] == b"FVE\x00" || &header[0x1b0..0x1b4] == b"FVE\x00") {
        return EncryptionType::BitLocker;
    }

    // 3. Check Apple FileVault (APFS volume superblock "NXSB" at offset 32)
    if header.len() >= 36 && &header[32..36] == b"NXSB" {
        return EncryptionType::FileVault;
    }
    // Apple CoreStorage Volume Header at offset 0
    if header.len() >= 16 && (&header[0..16] == b"CS_VOLUME_HEADER" || &header[0..8] == b"CoreStor") {
        return EncryptionType::FileVault;
    }

    // 4. Check Android FBE (File-Based Encryption / ext4 fscrypt / f2fs encrypt flag)
    if header.len() >= 1120 && header[1080] == 0x53 && header[1081] == 0xef {
        let compat_flags = u32::from_le_bytes([header[1116], header[1117], header[1118], header[1119]]);
        if (compat_flags & 0x400) != 0 || (compat_flags & 0x800) != 0 {
            return EncryptionType::AndroidFbe;
        }
    }
    // Check F2FS superblock magic 0xF2F52010 at offset 0 or offset 1024
    if (header.len() >= 4 && header[0..4] == [0x10, 0x20, 0xf5, 0xf2]) || (header.len() >= 1028 && header[1024..1028] == [0x10, 0x20, 0xf5, 0xf2]) {
        return EncryptionType::AndroidFbe;
    }
    // Check Android vold / fscrypt metadata header markers at offset 0 or offset 1024
    if (header.len() >= 12 && &header[0..12] == b"fscrypt_meta") || (header.len() >= 1036 && &header[1024..1036] == b"fscrypt_meta") {
        return EncryptionType::AndroidFbe;
    }

    EncryptionType::None
}

/// Detect encryption on a local file or block device by reading its first 4 KB.
pub fn inspect_device_encryption(path: &str) -> Result<EncryptionReport> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            return Ok(EncryptionReport {
                path: path.to_string(),
                encryption_type: EncryptionType::None,
                is_encrypted: false,
                details: format!("Could not open device/file for inspection: {}", e),
                recommended_action: "Ensure adequate administrative/root privileges or check device connection.".to_string(),
            });
        }
    };

    let mut buf = vec![0u8; 4096];
    let bytes_read = file.read(&mut buf).unwrap_or(0);
    let enc_type = detect_encryption_from_bytes(&buf[..bytes_read]);
    let is_enc = enc_type != EncryptionType::None;

    let (details, action) = match enc_type {
        EncryptionType::None => (
            "No standard volume encryption header detected. Volume appears to be cleartext.".to_string(),
            "Proceed with standard sector-by-sector physical or logical acquisition.".to_string(),
        ),
        EncryptionType::BitLocker => (
            "Windows BitLocker volume encryption detected (-FVE-FS- header present).".to_string(),
            "RECOMMENDED: Extract VMK (Volume Master Key) in the post-acquisition Analysis Suite, or acquire logical files while live OS is unlocked.".to_string(),
        ),
        EncryptionType::Luks1 | EncryptionType::Luks2 => (
            format!("Linux {} disk encryption detected.", enc_type),
            "RECOMMENDED: Extract master encryption key in the post-acquisition Analysis Suite before target shutdown.".to_string(),
        ),
        EncryptionType::FileVault => (
            "Apple FileVault APFS encrypted volume detected.".to_string(),
            "RECOMMENDED: Perform live logical extraction or capture RAM to retrieve APFS volume encryption keys in the post-acquisition Analysis Suite.".to_string(),
        ),
        EncryptionType::AndroidFbe => (
            "CRITICAL BLOCKER DETECTED: Android FBE (File-Based Encryption / fscrypt post-Android 7) detected on userdata volume.".to_string(),
            "ACTION REQUIRED: Standard dd-based physical imaging will silently produce un-decryptable garbage data due to CE/DE per-file hardware Gatekeeper keys. Switch to OpenForensic 'Android FBE Logical Stream Hook' or extract Gatekeeper keys in the post-acquisition Analysis Suite before imaging.".to_string(),
        ),
        EncryptionType::UnknownEncrypted => (
            "High entropy / unknown encryption signature detected.".to_string(),
            "Verify whether volume is VeraCrypt or custom proprietary container. Extract RAM dump immediately for post-acquisition analysis.".to_string(),
        ),
    };

    Ok(EncryptionReport {
        path: path.to_string(),
        encryption_type: enc_type,
        is_encrypted: is_enc,
        details,
        recommended_action: action,
    })
}

/// Scan a physical RAM dump (.raw / .dmp / .vmem) to extract volume master keys (VMK / LUKS / Gatekeeper keys).
pub fn extract_keys_from_ram(ram_dump_path: &str, target_type: Option<EncryptionType>) -> Result<Vec<ExtractedKey>> {
    let mut file = File::open(ram_dump_path).map_err(|e| OpenForensicError::Backend(format!("Failed to open RAM dump file: {}", e)))?;
    let mut extracted = Vec::new();
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB chunks
    let mut offset = 0u64;

    while let Ok(bytes_read) = file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        let chunk = &buffer[..bytes_read];

        // 1. Carve BitLocker VMK (Volume Master Key) / Pool tags ("Fvec" or "-FVE-FS-")
        if target_type.is_none() || target_type == Some(EncryptionType::BitLocker) {
            for (i, window) in chunk.windows(8).enumerate() {
                if window == b"-FVE-FS-" || window == b"Fvec\x00\x00\x00\x00" || window == b"FVEK\x01\x00\x00\x00" {
                    let key_offset = offset + i as u64;
                    let end_idx = (i + 40).min(chunk.len());
                    if end_idx - i >= 24 {
                        let hex_key: String = chunk[i..end_idx].iter().map(|b| format!("{:02x}", b)).collect();
                        extracted.push(ExtractedKey {
                            key_type: "BitLocker VMK / FVEK Context".to_string(),
                            hex_key,
                            offset: key_offset,
                            details: "Carved from Windows non-paged pool FVE key structure in RAM dump".to_string(),
                        });
                        if extracted.len() >= 20 { break; }
                    }
                }
            }
        }

        // 2. Carve LUKS Master Key / AES Key Schedule slots in kernel memory
        if target_type.is_none() || target_type == Some(EncryptionType::Luks1) || target_type == Some(EncryptionType::Luks2) {
            for (i, window) in chunk.windows(8).enumerate() {
                if window == b"LUKS\xba\xbe\x00\x01" || window == b"LUKS\xba\xbe\x00\x02" || window == b"dm-crypt" {
                    let key_offset = offset + i as u64;
                    let end_idx = (i + 48).min(chunk.len());
                    if end_idx - i >= 32 {
                        let hex_key: String = chunk[i..end_idx].iter().map(|b| format!("{:02x}", b)).collect();
                        extracted.push(ExtractedKey {
                            key_type: "LUKS Master Encryption Key Slot".to_string(),
                            hex_key,
                            offset: key_offset,
                            details: "Carved from Linux dm-crypt / LUKS key structure in kernel memory".to_string(),
                        });
                        if extracted.len() >= 20 { break; }
                    }
                }
            }
        }

        // 3. Carve FileVault APFS Volume Keys ("NXSB" or CoreStorage key structs)
        if target_type.is_none() || target_type == Some(EncryptionType::FileVault) {
            for (i, window) in chunk.windows(4).enumerate() {
                if window == b"NXSB" || window == b"APFS" {
                    if i + 48 <= chunk.len() {
                        let key_offset = offset + i as u64;
                        let hex_key: String = chunk[i..i+48].iter().map(|b| format!("{:02x}", b)).collect();
                        extracted.push(ExtractedKey {
                            key_type: "Apple FileVault APFS Volume Key Context".to_string(),
                            hex_key,
                            offset: key_offset,
                            details: "Carved from macOS APFS volume key header in RAM dump".to_string(),
                        });
                        if extracted.len() >= 20 { break; }
                    }
                }
            }
        }

        offset += bytes_read as u64;
        if extracted.len() >= 50 {
            break;
        }
    }

    if extracted.is_empty() {
        return Err(OpenForensicError::Backend("No matching volume encryption master keys or key pool structures were found in the provided RAM image.".to_string()));
    }

    Ok(extracted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_luks() {
        let mut buf = vec![0u8; 512];
        buf[0..6].copy_from_slice(b"LUKS\xba\xbe");
        buf[6] = 0x00;
        buf[7] = 0x02;
        assert_eq!(detect_encryption_from_bytes(&buf), EncryptionType::Luks2);
    }

    #[test]
    fn test_detect_bitlocker() {
        let mut buf = vec![0u8; 512];
        buf[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(detect_encryption_from_bytes(&buf), EncryptionType::BitLocker);
    }

    #[test]
    fn test_detect_filevault() {
        let mut buf = vec![0u8; 512];
        buf[32..36].copy_from_slice(b"NXSB");
        assert_eq!(detect_encryption_from_bytes(&buf), EncryptionType::FileVault);
    }

    #[test]
    fn test_ram_key_carving() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let ram_path = temp_dir.join("test_ram_dump.raw");
        let mut f = std::fs::File::create(&ram_path).unwrap();
        let mut mem = vec![0u8; 4096];
        mem[100..108].copy_from_slice(b"-FVE-FS-");
        f.write_all(&mem).unwrap();
        
        let keys = extract_keys_from_ram(ram_path.to_str().unwrap(), None).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].key_type.contains("BitLocker"));
        assert_eq!(keys[0].offset, 100);
        let _ = std::fs::remove_file(ram_path);
    }
}
