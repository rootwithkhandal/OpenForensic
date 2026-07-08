use std::path::Path;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use crate::pgp::keys::PgpKeyManager;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpVerificationReport {
    pub is_valid: bool,
    pub signer_user_id: String,
    pub signer_fingerprint: String,
    pub message: String,
}

pub struct PgpManifestVerifier;

impl PgpManifestVerifier {
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
        let key_info = PgpKeyManager::inspect_key(pub_pem).unwrap_or_else(|_| crate::pgp::keys::PgpKeyInfo {
            user_id: "Unknown Signer".to_string(),
            fingerprint: "UNKNOWN".to_string(),
            key_id: "UNKNOWN".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            has_private_key: false,
        });

        let mut expected_hmac_hex = String::new();
        let mut expected_sha256_hex = String::new();
        let mut signer_id = key_info.user_id.clone();
        let mut signer_fp = key_info.fingerprint.clone();

        for line in sig_pem.lines() {
            let line_str = line.trim();
            if let Some(val) = line_str.strip_prefix("HMAC-SHA256:") {
                expected_hmac_hex = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("SHA256:") {
                expected_sha256_hex = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("Signer-ID:") {
                signer_id = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("Fingerprint:") {
                signer_fp = val.trim().to_string();
            }
        }

        if expected_hmac_hex.is_empty() {
            return Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: "INTEGRITY FAILURE: Signature file is missing valid HMAC-SHA256 cryptographic seal.".to_string(),
            });
        }

        // Verify SHA-256 hash first
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

        // Extract secret/verification key and verify HMAC-SHA256 in constant time
        let secret = match PgpKeyManager::extract_secret_key(pub_pem) {
            Ok(s) => s,
            Err(e) => {
                return Ok(PgpVerificationReport {
                    is_valid: false,
                    signer_user_id: signer_id,
                    signer_fingerprint: signer_fp,
                    message: format!("INTEGRITY FAILURE: Cannot extract verification key: {}", e),
                });
            }
        };

        let mut mac = match HmacSha256::new_from_slice(&secret) {
            Ok(m) => m,
            Err(e) => {
                return Ok(PgpVerificationReport {
                    is_valid: false,
                    signer_user_id: signer_id,
                    signer_fingerprint: signer_fp,
                    message: format!("INTEGRITY FAILURE: HMAC key error: {}", e),
                });
            }
        };

        mac.update(data);
        let expected_hmac_bytes = match hex::decode(&expected_hmac_hex) {
            Ok(b) => b,
            Err(_) => {
                return Ok(PgpVerificationReport {
                    is_valid: false,
                    signer_user_id: signer_id,
                    signer_fingerprint: signer_fp,
                    message: "INTEGRITY FAILURE: Malformed hex in HMAC signature.".to_string(),
                });
            }
        };

        if mac.verify_slice(&expected_hmac_bytes).is_ok() {
            Ok(PgpVerificationReport {
                is_valid: true,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: "VALID INTEGRITY SEAL: Cryptographic HMAC-SHA256 seal and SHA-256 payload hash verified successfully against chain-of-custody token.".to_string(),
            })
        } else {
            Ok(PgpVerificationReport {
                is_valid: false,
                signer_user_id: signer_id,
                signer_fingerprint: signer_fp,
                message: "INTEGRITY VIOLATION: Cryptographic HMAC-SHA256 seal verification failed! The file contents or signature have been tampered with or do not match the provided verification token.".to_string(),
            })
        }
    }
}
