use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use base64::{Engine as _, prelude::BASE64_STANDARD};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519KeyInfo {
    pub user_id: String,
    pub key_id: String,
    pub fingerprint: String,
    pub public_key_b64: String,
    pub created_at: String,
    pub has_private_key: bool,
}

fn compute_key_metadata(pubkey_b64: &str) -> (String, String) {
    if pubkey_b64.is_empty() {
        return ("00000000".to_string(), "0000 0000 0000 0000".to_string());
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey_b64.as_bytes());
    let hex_digest = hex::encode(hasher.finalize());
    let key_id = hex_digest[..16].to_uppercase();
    let fingerprint = hex_digest.chars().collect::<Vec<char>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join(" ")
        .to_uppercase();
    (key_id, fingerprint)
}

pub struct Ed25519KeyManager;

impl Ed25519KeyManager {
    pub fn get_default_keypair_paths(app_data_dir: Option<&Path>) -> (PathBuf, PathBuf) {
        let base = app_data_dir.unwrap_or_else(|| Path::new("."));
        (
            base.join("openforensic_ed25519_private.key"),
            base.join("openforensic_ed25519_public.key"),
        )
    }

    pub fn generate_keypair(user_id: &str) -> Result<(String, String, Ed25519KeyInfo), String> {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let private_b64 = BASE64_STANDARD.encode(signing_key.to_bytes());
        let public_b64 = BASE64_STANDARD.encode(verifying_key.to_bytes());
        let (key_id, fingerprint) = compute_key_metadata(&public_b64);

        let created_at = chrono::Utc::now().to_rfc3339();
        let info = Ed25519KeyInfo {
            user_id: user_id.to_string(),
            key_id,
            fingerprint,
            public_key_b64: public_b64.clone(),
            created_at: created_at.clone(),
            has_private_key: true,
        };

        let priv_pem = format!(
            "-----BEGIN OPENFORENSIC ED25519 PRIVATE KEY-----\n\
             Version: OpenForensic v2.1.0\n\
             User-ID: {}\n\
             Created: {}\n\
             \n{}\n\
             -----END OPENFORENSIC ED25519 PRIVATE KEY-----\n",
            user_id, created_at, private_b64
        );

        let pub_pem = format!(
            "-----BEGIN OPENFORENSIC ED25519 PUBLIC KEY-----\n\
             Version: OpenForensic v2.1.0\n\
             User-ID: {}\n\
             Created: {}\n\
             \n{}\n\
             -----END OPENFORENSIC ED25519 PUBLIC KEY-----\n",
            user_id, created_at, public_b64
        );

        Ok((priv_pem, pub_pem, info))
    }

    pub fn inspect_key(pem: &str) -> Result<Ed25519KeyInfo, String> {
        let lines: Vec<&str> = pem.lines().collect();
        let mut user_id = "Unknown Examiner".to_string();
        let mut created_at = chrono::Utc::now().to_rfc3339();
        let mut has_private = false;
        let mut public_key_b64 = String::new();

        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with("User-ID:") {
                user_id = trimmed.strip_prefix("User-ID:").unwrap().trim().to_string();
            } else if trimmed.starts_with("Created:") {
                created_at = trimmed.strip_prefix("Created:").unwrap().trim().to_string();
            } else if trimmed.starts_with("-----BEGIN OPENFORENSIC ED25519 PRIVATE KEY-----") {
                has_private = true;
            } else if trimmed.starts_with("-----BEGIN OPENFORENSIC ED25519 PUBLIC KEY-----") {
                has_private = false;
            } else if !trimmed.starts_with("-----")
                && !trimmed.starts_with("Version:")
                && !trimmed.starts_with("User-ID:")
                && !trimmed.starts_with("Created:")
                && !trimmed.is_empty() {
                public_key_b64.push_str(trimmed);
            }
        }

        if public_key_b64.is_empty() && !pem.is_empty() {
            return Ok(Ed25519KeyInfo {
                user_id: "Default Examiner".to_string(),
                key_id: "00000000".to_string(),
                fingerprint: "0000 0000 0000 0000".to_string(),
                public_key_b64: String::new(),
                created_at,
                has_private_key: false,
            });
        }
        let (key_id, fingerprint) = compute_key_metadata(&public_key_b64);

        Ok(Ed25519KeyInfo {
            user_id,
            key_id,
            fingerprint,
            public_key_b64,
            created_at,
            has_private_key: has_private,
        })
    }

    pub fn extract_signing_key(pem: &str) -> Result<SigningKey, String> {
        let mut key_b64 = String::new();
        for line in pem.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("-----")
                || trimmed.starts_with("Version:")
                || trimmed.starts_with("User-ID:")
                || trimmed.starts_with("Created:")
                || trimmed.is_empty() {
                continue;
            }
            key_b64.push_str(trimmed);
        }
        if key_b64.is_empty() {
            return Err("No private key data found in PEM".to_string());
        }
        let key_bytes = BASE64_STANDARD.decode(&key_b64)
            .map_err(|e| format!("Failed to decode base64 private key: {}", e))?;
        if key_bytes.len() != 32 {
            return Err(format!("Invalid private key length: {} (expected 32)", key_bytes.len()));
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        Ok(SigningKey::from_bytes(&key_array))
    }

    pub fn extract_verifying_key(pem: &str) -> Result<VerifyingKey, String> {
        let mut key_b64 = String::new();
        for line in pem.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("-----")
                || trimmed.starts_with("Version:")
                || trimmed.starts_with("User-ID:")
                || trimmed.starts_with("Created:")
                || trimmed.is_empty() {
                continue;
            }
            key_b64.push_str(trimmed);
        }
        if key_b64.is_empty() {
            return Err("No public key data found in PEM".to_string());
        }
        let key_bytes = BASE64_STANDARD.decode(&key_b64)
            .map_err(|e| format!("Failed to decode base64 public key: {}", e))?;
        if key_bytes.len() != 32 {
            return Err(format!("Invalid public key length: {} (expected 32)", key_bytes.len()));
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        Ok(VerifyingKey::from_bytes(&key_array)
            .map_err(|e| format!("Invalid public key: {}", e))?)
    }

    pub fn save_keypair(priv_path: &Path, pub_path: &Path, priv_pem: &str, pub_pem: &str) -> Result<(), String> {
        if let Some(parent) = priv_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if let Some(parent) = pub_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(priv_path, priv_pem).map_err(|e| e.to_string())?;
        std::fs::write(pub_path, pub_pem).map_err(|e| e.to_string())?;

        // Set restrictive permissions on private key (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(priv_path).map_err(|e| e.to_string())?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(priv_path, perms).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn load_or_generate_default(app_data_dir: Option<&Path>) -> Result<(String, String, Ed25519KeyInfo), String> {
        let (priv_path, pub_path) = Self::get_default_keypair_paths(app_data_dir);
        if priv_path.exists() && pub_path.exists() {
            let priv_pem = std::fs::read_to_string(&priv_path).map_err(|e| e.to_string())?;
            let pub_pem = std::fs::read_to_string(&pub_path).map_err(|e| e.to_string())?;
            if let Ok(info) = Self::inspect_key(&priv_pem) {
                return Ok((priv_pem, pub_pem, info));
            }
        }
        let (priv_pem, pub_pem, info) = Self::generate_keypair("OpenForensic Default Examiner")?;
        let _ = Self::save_keypair(&priv_path, &pub_path, &priv_pem, &pub_pem);
        Ok((priv_pem, pub_pem, info))
    }

    pub fn generate_default_with_user(app_data_dir: Option<&Path>, user_id: &str) -> Result<(String, String, Ed25519KeyInfo), String> {
        let (priv_path, pub_path) = Self::get_default_keypair_paths(app_data_dir);
        let (priv_pem, pub_pem, info) = Self::generate_keypair(user_id)?;
        Self::save_keypair(&priv_path, &pub_path, &priv_pem, &pub_pem)?;
        Ok((priv_pem, pub_pem, info))
    }
}