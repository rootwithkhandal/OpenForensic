use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::parse::stream::*;
use serde::{Deserialize, Serialize as SerdeSerialize};
use std::path::Path;
use std::fs;

#[derive(Debug, Clone, SerdeSerialize, Deserialize)]
pub struct PgpVerificationReport {
    pub is_valid: bool,
    pub signer_fingerprint: String,
    pub signer_user_id: String,
    pub message: String,
}

struct ForensicVerifierHelper {
    cert: Cert,
    verified_fingerprint: Option<String>,
    verified_user_id: Option<String>,
}

impl VerificationHelper for ForensicVerifierHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for good_sig in results.into_iter().flatten() {
                    self.verified_fingerprint = Some(good_sig.ka.cert().fingerprint().to_hex());
                    
                    let mut uid_str = String::new();
                    for uid in good_sig.ka.cert().userids() {
                        if let Ok(val) = std::str::from_utf8(uid.userid().value()) {
                            uid_str = val.to_string();
                            break;
                        }
                    }
                    if uid_str.is_empty() {
                        uid_str = "OpenForensic Investigator".to_string();
                    }
                    self.verified_user_id = Some(uid_str);
                }
            }
        }
        Ok(())
    }
}

pub struct PgpManifestVerifier;

impl PgpManifestVerifier {
    /// Verifies a detached PGP signature (`signature_pem`) against data (`data`) using `public_key_pem`
    pub fn verify_detached(
        data: &[u8],
        signature_pem: &str,
        public_key_pem: &str,
    ) -> Result<PgpVerificationReport, String> {
        let p = &StandardPolicy::new();
        let cert = openpgp::cert::CertParser::from_bytes(public_key_pem.as_bytes())
            .map_err(|e| format!("Failed to initialize cert parser: {}", e))?
            .next()
            .ok_or_else(|| "No certificate found in public key data".to_string())?
            .map_err(|e| format!("Failed to parse public key for verification: {}", e))?;

        let helper = ForensicVerifierHelper {
            cert,
            verified_fingerprint: None,
            verified_user_id: None,
        };

        let sig_bytes = signature_pem.as_bytes();
        let mut verifier = DetachedVerifierBuilder::from_bytes(sig_bytes)
            .map_err(|e| format!("Failed to initialize PGP signature verifier: {}", e))?
            .with_policy(p, None, helper)
            .map_err(|e| format!("Signature verification initialization failed: {}", e))?;

        verifier
            .verify_bytes(data)
            .map_err(|e| format!("Cryptographic PGP verification failed: {}", e))?;

        let helper_after = verifier.into_helper();

        if let (Some(fp), Some(uid)) = (helper_after.verified_fingerprint, helper_after.verified_user_id) {
            Ok(PgpVerificationReport {
                is_valid: true,
                signer_fingerprint: fp.clone(),
                signer_user_id: uid.clone(),
                message: format!("VALID PGP SIGNATURE by {} (Fingerprint: {})", uid, fp),
            })
        } else {
            Ok(PgpVerificationReport {
                is_valid: false,
                signer_fingerprint: "N/A".to_string(),
                signer_user_id: "N/A".to_string(),
                message: "INVALID PGP SIGNATURE: No valid signature matched the provided public key.".to_string(),
            })
        }
    }

    /// Verifies an evidence manifest file against its `.asc` signature file using a public key
    pub fn verify_file(
        manifest_path: &Path,
        sig_path: &Path,
        public_key_pem: &str,
    ) -> Result<PgpVerificationReport, String> {
        let data = fs::read(manifest_path)
            .map_err(|e| format!("Failed to read manifest file {}: {}", manifest_path.display(), e))?;
        let sig_pem = fs::read_to_string(sig_path)
            .map_err(|e| format!("Failed to read signature file {}: {}", sig_path.display(), e))?;

        Self::verify_detached(&data, &sig_pem, public_key_pem)
    }
}
