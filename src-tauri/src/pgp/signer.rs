use std::path::{Path, PathBuf};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use crate::pgp::keys::PgpKeyManager;

type HmacSha256 = Hmac<Sha256>;

pub struct PgpManifestSigner;

impl PgpManifestSigner {
    pub fn sign_file(file_path: &Path, private_key_pem: &str) -> Result<PathBuf, String> {
        if !file_path.exists() {
            return Err(format!("Target file does not exist: {}", file_path.display()));
        }
        let data = std::fs::read(file_path).map_err(|e| format!("Failed to read target file: {}", e))?;
        let sig_pem = Self::sign_detached(&data, private_key_pem)?;
        
        let sig_path = file_path.with_extension("sig");
        std::fs::write(&sig_path, sig_pem).map_err(|e| format!("Failed to write signature file: {}", e))?;
        Ok(sig_path)
    }

    pub fn sign_detached(data: &[u8], private_key_pem: &str) -> Result<String, String> {
        let secret = PgpKeyManager::extract_secret_key(private_key_pem)?;
        let mut mac = HmacSha256::new_from_slice(&secret).map_err(|e| format!("HMAC initialization error: {}", e))?;
        mac.update(data);
        let hmac_res = mac.finalize();
        let hmac_hex = hex::encode(hmac_res.into_bytes());

        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256_hex = hex::encode(hasher.finalize());

        let key_info = PgpKeyManager::inspect_key(private_key_pem).unwrap_or_else(|_| crate::pgp::keys::PgpKeyInfo {
            user_id: "Unknown".to_string(),
            fingerprint: "UNKNOWN".to_string(),
            key_id: "UNKNOWN".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            has_private_key: true,
        });

        let sig_pem = format!(
            "-----BEGIN OPENFORENSIC INTEGRITY SIGNATURE-----\nVersion: OpenForensic v2.1.0\nSigner-ID: {}\nFingerprint: {}\nSHA256: {}\nHMAC-SHA256: {}\n-----END OPENFORENSIC INTEGRITY SIGNATURE-----\n",
            key_info.user_id, key_info.fingerprint, sha256_hex, hmac_hex
        );
        Ok(sig_pem)
    }
}
