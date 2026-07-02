//! Encryption Detection & Key Extraction module.
//! Detects BitLocker, LUKS, Apple FileVault, and Android FBE (File-Based Encryption) volumes during acquisition.
//! Extracts volume master keys (VMK / Master Keys / Gatekeeper CE keys) from RAM dumps where possible.

use crate::error::{ForgelensError, Result};
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
    if (header.len() >= 11 && &header[3..11] == b"-FVE-FS-") || header.windows(8).any(|w| w == b"-FVE-FS-") {
        return EncryptionType::BitLocker;
    }
    // Check for BitLocker metadata signature "MSWIN4.1" followed by FVE metadata structures
    if header.windows(8).any(|w| w == b"MSWIN4.1") && header.windows(4).any(|w| w == b"FVE\x00") {
        return EncryptionType::BitLocker;
    }

    // 3. Check Apple FileVault (APFS volume superblock "NXSB" or CoreStorage "CS")
    if (header.len() >= 36 && &header[32..36] == b"NXSB") || header.windows(4).any(|w| w == b"NXSB") {
        return EncryptionType::FileVault;
    }

    // 4. Check Android FBE (File-Based Encryption / ext4 fscrypt / f2fs encrypt flag)
    // Ext4 magic is 0xef53 at offset 0x438 (1080). If ext4 COMPAT_ENCRYPT feature flag (0x400) is set in s_feature_compat (offset 0x45c)
    if header.len() >= 1120 && header[1080] == 0x53 && header[1081] == 0xef {
        let compat_flags = u32::from_le_bytes([header[1116], header[1117], header[1118], header[1119]]);
        if (compat_flags & 0x400) != 0 || (compat_flags & 0x800) != 0 {
            return EncryptionType::AndroidFbe;
        }
    }
    // Check for F2FS magic 0xF2F52010 and encryption flag
    if header.windows(4).any(|w| w == &[0x10, 0x20, 0xf5, 0xf2]) {
        return EncryptionType::AndroidFbe;
    }
    // Check Android vold / fscrypt metadata header markers
    if header.windows(12).any(|w| w == b"fscrypt_meta") || header.windows(10).any(|w| w == b"userdata_v") {
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
/// NOTE: Disabled and moved to post-acquisition Analysis Suite per architectural separation of capture vs. analysis.
pub fn extract_keys_from_ram(_ram_dump_path: &str, _target_type: Option<EncryptionType>) -> Result<Vec<ExtractedKey>> {
    Err(ForgelensError::Backend(
        "Master-key extraction from RAM dumps is disabled during live capture. Please move acquired dumps to the post-acquisition Analysis Suite.".to_string(),
    ))
}
