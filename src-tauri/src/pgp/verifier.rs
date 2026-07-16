use std::path::Path;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, Verifier};
use base64::{Engine as _, prelude::BASE64_STANDARD};
use crate::pgp::keys::Ed25519KeyManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpVerificationReport {
    pub is_valid: bool,
    pub signer_user_id: String,
    pub signer_fingerprint: String,
    pub message: String,
}

pub struct Ed25519ManifestVerifier;

impl Ed25519ManifestVerifier {
    pub fn verify_file(file_path: &Path, sig_path: &Path, pub_key_pem: &str) -> Result<PgpVerificationReport, String> {
        if !file_path.exists() {
            return Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: "N/A".to_string(),
                signer_fingerprint: "N/A".to_string(),
                message: format!("INTEGRITY FAILURE: Target evidence file not found at {}", file_path.display()),
            });
        }
        if !sig_path.exists() {
            return Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: "N/A".to_string(),
                signer_fingerprint: "N/A".to_string(),
                message: format!("INTEGRITY FAILURE: Signature manifest file not found at {}", sig_path.display()),
            });
        }

        let data = std::fs::read(file_path).map_err(|e| format!("Failed to read target file: {}", e))?;
        let sig_content = std::fs::read_to_string(sig_path).map_err(|e| format!("Failed to read signature file: {}", e))?;
        Self::verify_detached(&data, &sig_content, pub_key_pem)
    }

    pub fn verify_detached(data: &[u8], sig_pem: &str, pub_pem: &str) -> Result<PgpVerificationReport, String> {
        let key_info = Ed25519KeyManager::inspect_key(pub_pem).unwrap_or_else(|_| crate::pgp::keys::Ed25519KeyInfo {
            user_id: "Unknown Signer".to_string(),
            key_id: "00000000".to_string(),
            fingerprint: "0000 0000 0000 0000".to_string(),
            public_key_b64: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            has_private_key: false,
        });

        let mut expected_sig_b64 = String::new();
        let mut expected_sha256_hex = String::new();
        let mut signer_id = key_info.user_id.clone();
        let mut signer_fp = key_info.public_key_b64.clone();

        for line in sig_pem.lines() {
            let line_str = line.trim();
            if let Some(val) = line_str.strip_prefix("Signature:") {
                expected_sig_b64 = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("SHA256:") {
                expected_sha256_hex = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("Signer-ID:") {
                signer_id = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("Public-Key:") {
                signer_fp = val.trim().to_string();
            } else if !line_str.starts_with("-----")
                && !line_str.starts_with("Version:")
                && !line_str.starts_with("Algorithm:")
                && !line_str.starts_with("Signer-ID:")
                && !line_str.starts_with("Public-Key:")
                && !line_str.starts_with("SHA256:")
                && !line_str.starts_with("Signature:")
                && !line_str.is_empty()
            {
                if expected_sig_b64.is_empty() {
                    expected_sig_b64 = line_str.to_string();
                }
            }
        }

        if expected_sig_b64.is_empty() {
            return Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: "INTEGRITY FAILURE: Signature file is missing valid Ed25519 signature.".to_string(),
            });
        }

        // Verify SHA-256 hash first
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let actual_sha256_hex = hex::encode(hasher.finalize());
        if !expected_sha256_hex.is_empty() && !actual_sha256_hex.eq_ignore_ascii_case(&expected_sha256_hex) {
            return Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: format!("INTEGRITY VIOLATION: SHA-256 hash mismatch! Evidence payload has been modified or corrupted (Expected: {}, Actual: {}).", expected_sha256_hex, actual_sha256_hex),
            });
        }

        // Extract verifying key and verify Ed25519 signature
        let verifying_key = match Ed25519KeyManager::extract_verifying_key(pub_pem) {
            Ok(k) => k,
            Err(e) => {
                return Ok(PgpVerificationReport {
                    is_valid: false,
                    signer_user_id: signer_id,
                    signer_fingerprint: signer_fp,
                    message: format!("INTEGRITY FAILURE: Cannot extract verification key: {}", e),
                });
            }
        };

        let expected_sig_bytes = match BASE64_STANDARD.decode(&expected_sig_b64) {
            Ok(b) => b,
            Err(_) => {
                return Ok(PgpVerificationReport {
                    is_valid: false,
                    signer_user_id: signer_id,
                    signer_fingerprint: signer_fp,
                    message: "INTEGRITY FAILURE: Malformed base64 in Ed25519 signature.".to_string(),
                });
            }
        };

        if expected_sig_bytes.len() != 64 {
            return Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: format!("INTEGRITY FAILURE: Invalid Ed25519 signature length (expected 64 bytes, got {})", expected_sig_bytes.len()),
            });
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&expected_sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        match verifying_key.verify(data, &signature) {
            Ok(_) => Ok(PgpVerificationReport {
                is_valid: true,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: "VALID INTEGRITY SEAL: Ed25519 signature and SHA-256 payload hash verified successfully against chain-of-custody token.".to_string(),
            }),
            Err(_) => Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: "INTEGRITY VIOLATION: Ed25519 signature verification failed! The file contents or signature have been tampered with or do not match the provided verification key.".to_string(),
            }),
        }
    }
}
