use sequoia_openpgp as openpgp;
use openpgp::cert::CertBuilder;
use openpgp::armor::Writer as ArmorWriter;
use openpgp::serialize::Serialize;
use openpgp::parse::Parse;
use std::path::{Path, PathBuf};
use std::fs;
use serde::{Deserialize, Serialize as SerdeSerialize};

#[derive(Debug, Clone, SerdeSerialize, Deserialize)]
pub struct PgpKeyInfo {
    pub key_id: String,
    pub fingerprint: String,
    pub user_id: String,
    pub public_key_pem: String,
    pub has_private_key: bool,
}

pub struct PgpKeyManager;

impl PgpKeyManager {
    pub fn get_default_app_dir() -> PathBuf {
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("org.openforensic.app")
    }

    /// Returns default paths for storing keypair in the application data directory
    pub fn get_default_keypair_paths(app_data_dir: Option<&Path>) -> (PathBuf, PathBuf) {
        let base_dir = app_data_dir.map(PathBuf::from).unwrap_or_else(Self::get_default_app_dir);
        let pgp_dir = base_dir.join("pgp");
        let _ = fs::create_dir_all(&pgp_dir);
        let priv_path = pgp_dir.join("openforensic_signing_key.asc");
        let pub_path = pgp_dir.join("openforensic_public_key.asc");
        (priv_path, pub_path)
    }

    /// Generates a new general-purpose OpenPGP certificate (with signing key) for the given user ID
    pub fn generate_keypair(user_id: &str) -> Result<(String, String, PgpKeyInfo), String> {
        let (cert, _revocation) = CertBuilder::general_purpose(Some(user_id))
            .generate()
            .map_err(|e| format!("Failed to generate OpenPGP certificate: {}", e))?;

        let mut private_armored = Vec::new();
        {
            let mut writer = ArmorWriter::new(
                &mut private_armored,
                openpgp::armor::Kind::SecretKey,
            )
            .map_err(|e| format!("Failed to create armored writer for secret key: {}", e))?;
            cert.as_tsk()
                .serialize(&mut writer)
                .map_err(|e| format!("Failed to serialize secret key: {}", e))?;
            writer.finalize().map_err(|e| format!("Failed to finalize secret key armor: {}", e))?;
        }
        let private_key_pem = String::from_utf8(private_armored)
            .map_err(|e| format!("Invalid UTF-8 in secret key armor: {}", e))?;

        let mut public_armored = Vec::new();
        {
            let mut writer = ArmorWriter::new(
                &mut public_armored,
                openpgp::armor::Kind::PublicKey,
            )
            .map_err(|e| format!("Failed to create armored writer for public key: {}", e))?;
            cert.serialize(&mut writer)
                .map_err(|e| format!("Failed to serialize public key: {}", e))?;
            writer.finalize().map_err(|e| format!("Failed to finalize public key armor: {}", e))?;
        }
        let public_key_pem = String::from_utf8(public_armored)
            .map_err(|e| format!("Invalid UTF-8 in public key armor: {}", e))?;

        let fingerprint = cert.fingerprint().to_hex();
        let key_id = cert.keyid().to_hex();

        let info = PgpKeyInfo {
            key_id,
            fingerprint,
            user_id: user_id.to_string(),
            public_key_pem: public_key_pem.clone(),
            has_private_key: true,
        };

        Ok((private_key_pem, public_key_pem, info))
    }

    /// Parses an ASCII-armored or binary OpenPGP certificate and extracts metadata
    pub fn inspect_key(pem: &str) -> Result<PgpKeyInfo, String> {
        let cert = openpgp::cert::CertParser::from_bytes(pem.as_bytes())
            .map_err(|e| format!("Failed to create PGP key parser: {}", e))?
            .next()
            .ok_or_else(|| "No certificate found in PGP key data".to_string())?
            .map_err(|e| format!("Failed to parse PGP key: {}", e))?;

        let fingerprint = cert.fingerprint().to_hex();
        let key_id = cert.keyid().to_hex();

        let mut user_id = String::new();
        for uid in cert.userids() {
            if let Ok(val) = std::str::from_utf8(uid.userid().value()) {
                user_id = val.to_string();
                break;
            }
        }
        if user_id.is_empty() {
            user_id = "OpenForensic Investigator".to_string();
        }

        let mut public_armored = Vec::new();
        {
            let mut writer = ArmorWriter::new(
                &mut public_armored,
                openpgp::armor::Kind::PublicKey,
            )
            .map_err(|e| format!("Failed to create armored writer: {}", e))?;
            cert.serialize(&mut writer)
                .map_err(|e| format!("Failed to serialize public key: {}", e))?;
            writer.finalize().map_err(|e| format!("Failed to finalize public key armor: {}", e))?;
        }
        let public_key_pem = String::from_utf8(public_armored)
            .map_err(|e| format!("Invalid UTF-8 in public key armor: {}", e))?;

        let has_private_key = cert.is_tsk();

        Ok(PgpKeyInfo {
            key_id,
            fingerprint,
            user_id,
            public_key_pem,
            has_private_key,
        })
    }

    /// Saves keypair to disk
    pub fn save_keypair(priv_path: &Path, pub_path: &Path, priv_pem: &str, pub_pem: &str) -> Result<(), String> {
        if let Some(parent) = priv_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(priv_path, priv_pem).map_err(|e| format!("Failed to write private key: {}", e))?;
        fs::write(pub_path, pub_pem).map_err(|e| format!("Failed to write public key: {}", e))?;
        Ok(())
    }

    /// Loads active keypair from disk, or generates a default one if none exists
    pub fn load_or_generate_default(app_data_dir: Option<&Path>) -> Result<(String, String, PgpKeyInfo), String> {
        let (priv_path, pub_path) = Self::get_default_keypair_paths(app_data_dir);
        if priv_path.exists() && pub_path.exists()
            && let (Ok(priv_pem), Ok(pub_pem)) = (fs::read_to_string(&priv_path), fs::read_to_string(&pub_path))
            && let Ok(info) = Self::inspect_key(&priv_pem)
        {
            return Ok((priv_pem, pub_pem, info));
        }

        let default_user = "OpenForensic Workstation <investigator@openforensic.local>";
        let (priv_pem, pub_pem, info) = Self::generate_keypair(default_user)?;
        let _ = Self::save_keypair(&priv_path, &pub_path, &priv_pem, &pub_pem);
        Ok((priv_pem, pub_pem, info))
    }

    pub fn inspect_default(app_data_dir: Option<&Path>) -> Result<PgpKeyInfo, String> {
        let (priv_path, _) = Self::get_default_keypair_paths(app_data_dir);
        if priv_path.exists() {
            let priv_pem = fs::read_to_string(&priv_path).map_err(|e| e.to_string())?;
            Self::inspect_key(&priv_pem)
        } else {
            Err("No key found".to_string())
        }
    }

    pub fn generate_default_with_user(app_data_dir: Option<&Path>, user_id: &str) -> Result<(String, String, PgpKeyInfo), String> {
        let (priv_path, pub_path) = Self::get_default_keypair_paths(app_data_dir);
        let (priv_pem, pub_pem, info) = Self::generate_keypair(user_id)?;
        Self::save_keypair(&priv_path, &pub_path, &priv_pem, &pub_pem)?;
        Ok((priv_pem, pub_pem, info))
    }
}
