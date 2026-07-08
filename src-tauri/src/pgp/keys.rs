use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpKeyInfo {
    pub user_id: String,
    pub fingerprint: String,
    pub key_id: String,
    pub created_at: String,
    pub has_private_key: bool,
}

pub struct PgpKeyManager;

impl PgpKeyManager {
    pub fn get_default_keypair_paths(app_data_dir: Option<&Path>) -> (PathBuf, PathBuf) {
        let base = app_data_dir.unwrap_or_else(|| Path::new("."));
        (base.join("openforensic_hmac.key"), base.join("openforensic_hmac.pub"))
    }

    pub fn generate_keypair(user_id: &str) -> Result<(String, String, PgpKeyInfo), String> {
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let hex_secret = hex::encode(secret_bytes);

        // Compute fingerprint and key ID from SHA-256 hash of user_id + secret
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        hasher.update(&secret_bytes);
        let hash_res = hasher.finalize();
        let fingerprint = hex::encode(hash_res).to_uppercase();
        let key_id = fingerprint[..8].to_string();
        let created_at = chrono::Utc::now().to_rfc3339();

        let info = PgpKeyInfo {
            user_id: user_id.to_string(),
            fingerprint: fingerprint.clone(),
            key_id: key_id.clone(),
            created_at: created_at.clone(),
            has_private_key: true,
        };

        let priv_pem = format!(
            "-----BEGIN OPENFORENSIC HMAC-SHA256 KEY-----\nVersion: OpenForensic v2.1.0\nUser-ID: {}\nCreated: {}\nKey-ID: {}\nFingerprint: {}\n\n{}\n-----END OPENFORENSIC HMAC-SHA256 KEY-----\n",
            user_id, created_at, key_id, fingerprint, hex_secret
        );

        let pub_pem = format!(
            "-----BEGIN OPENFORENSIC HMAC-SHA256 VERIFICATION TOKEN-----\nVersion: OpenForensic v2.1.0\nUser-ID: {}\nCreated: {}\nKey-ID: {}\nFingerprint: {}\n\n{}\n-----END OPENFORENSIC HMAC-SHA256 VERIFICATION TOKEN-----\n",
            user_id, created_at, key_id, fingerprint, hex_secret
        );

        Ok((priv_pem, pub_pem, info))
    }

    pub fn inspect_key(pem: &str) -> Result<PgpKeyInfo, String> {
        let mut user_id = "Unknown Examiner".to_string();
        let mut fingerprint = "0000000000000000".to_string();
        let mut key_id = "00000000".to_string();
        let mut created_at = chrono::Utc::now().to_rfc3339();
        let mut has_private = false;

        if pem.contains("BEGIN OPENFORENSIC HMAC-SHA256 KEY") || pem.contains("BEGIN SEAL KEY") {
            has_private = true;
        } else if pem.contains("BEGIN OPENFORENSIC HMAC-SHA256 VERIFICATION TOKEN") || pem.contains("BEGIN SEAL PUB") {
            has_private = false;
        } else if pem.is_empty() {
            return Ok(PgpKeyInfo {
                user_id: "Default Examiner".to_string(),
                fingerprint: "NONE".to_string(),
                key_id: "NONE".to_string(),
                created_at,
                has_private_key: false,
            });
        }

        for line in pem.lines() {
            let line_str = line.trim();
            if let Some(val) = line_str.strip_prefix("User-ID:") {
                user_id = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("Created:") {
                created_at = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("Key-ID:") {
                key_id = val.trim().to_string();
            } else if let Some(val) = line_str.strip_prefix("Fingerprint:") {
                fingerprint = val.trim().to_string();
            }
        }

        Ok(PgpKeyInfo {
            user_id,
            fingerprint,
            key_id,
            created_at,
            has_private_key: has_private,
        })
    }

    pub fn extract_secret_key(pem: &str) -> Result<Vec<u8>, String> {
        let mut key_hex = String::new();
        for line in pem.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("-----") || trimmed.contains(':') {
                continue;
            }
            key_hex.push_str(trimmed);
        }
        if key_hex.is_empty() {
            return Err("No secret key found in PEM/Token data".to_string());
        }
        hex::decode(&key_hex).map_err(|e| format!("Failed to decode hex secret key: {}", e))
    }

    pub fn save_keypair(priv_path: &Path, pub_path: &Path, priv_pem: &str, pub_pem: &str) -> Result<(), String> {
        if let Some(parent) = priv_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Some(parent) = pub_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(priv_path, priv_pem).map_err(|e| e.to_string())?;
        std::fs::write(pub_path, pub_pem).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_or_generate_default(app_data_dir: Option<&Path>) -> Result<(String, String, PgpKeyInfo), String> {
        let (priv_path, pub_path) = Self::get_default_keypair_paths(app_data_dir);
        if priv_path.exists() && pub_path.exists() {
            if let (Ok(priv_pem), Ok(pub_pem)) = (std::fs::read_to_string(&priv_path), std::fs::read_to_string(&pub_path)) {
                if let Ok(info) = Self::inspect_key(&priv_pem) {
                    return Ok((priv_pem, pub_pem, info));
                }
            }
        }
        let (priv_pem, pub_pem, info) = Self::generate_keypair("OpenForensic Default Examiner")?;
        let _ = Self::save_keypair(&priv_path, &pub_path, &priv_pem, &pub_pem);
        Ok((priv_pem, pub_pem, info))
    }

    pub fn inspect_default(app_data_dir: Option<&Path>) -> Result<PgpKeyInfo, String> {
        let (priv_path, _) = Self::get_default_keypair_paths(app_data_dir);
        if priv_path.exists() {
            if let Ok(priv_pem) = std::fs::read_to_string(&priv_path) {
                return Self::inspect_key(&priv_pem);
            }
        }
        Self::inspect_key("")
    }

    pub fn generate_default_with_user(app_data_dir: Option<&Path>, user_id: &str) -> Result<(String, String, PgpKeyInfo), String> {
        let (priv_path, pub_path) = Self::get_default_keypair_paths(app_data_dir);
        let (priv_pem, pub_pem, info) = Self::generate_keypair(user_id)?;
        Self::save_keypair(&priv_path, &pub_path, &priv_pem, &pub_pem)?;
        Ok((priv_pem, pub_pem, info))
    }
}
