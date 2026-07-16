use std::path::{Path, PathBuf};
use ed25519_dalek::Signer;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use crate::pgp::keys::Ed25519KeyManager;

pub struct Ed25519ManifestSigner;

impl Ed25519ManifestSigner {
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
        let signing_key = Ed25519KeyManager::extract_signing_key(private_key_pem)?;
        let key_info = Ed25519KeyManager::inspect_key(private_key_pem).unwrap_or_else(|_| crate::pgp::keys::Ed25519KeyInfo {
            user_id: "Unknown".to_string(),
            key_id: "00000000".to_string(),
            fingerprint: "0000 0000 0000 0000".to_string(),
            public_key_b64: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            has_private_key: true,
        });

        let signature: ed25519_dalek::Signature = signing_key.sign(data);
        let sig_b64 = BASE64_STANDARD.encode(signature.to_bytes());

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256_hex = hex::encode(hasher.finalize());

        let sig_pem = format!(
            "-----BEGIN OPENFORENSIC ED25519 SIGNATURE-----\n\
             Version: OpenForensic v2.1.0\n\
             Signer-ID: {}\n\
             Public-Key: {}\n\
             Algorithm: Ed25519\n\
             SHA256: {}\n\
             Signature: {}\n\
             \n{}\n\
             -----END OPENFORENSIC ED25519 SIGNATURE-----\n",
            key_info.user_id, key_info.public_key_b64, sha256_hex, sig_b64, sig_b64
        );
        Ok(sig_pem)
    }
}