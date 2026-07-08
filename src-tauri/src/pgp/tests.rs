#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use crate::pgp::{PgpKeyManager, PgpManifestSigner, PgpManifestVerifier};
    use std::fs;

    #[test]
    fn test_seal_keygen_and_inspect() {
        let user = "Investigator Test <test@dfir.local>";
        let res = PgpKeyManager::generate_keypair(user);
        assert!(res.is_ok());
        let (priv_pem, pub_pem, info) = res.unwrap();

        assert!(priv_pem.contains("-----BEGIN OPENFORENSIC HMAC-SHA256 KEY-----"));
        assert!(pub_pem.contains("-----BEGIN OPENFORENSIC HMAC-SHA256 VERIFICATION TOKEN-----"));
        assert_eq!(info.user_id, user);
        assert!(!info.fingerprint.is_empty());
        assert!(info.has_private_key);

        let inspect_res = PgpKeyManager::inspect_key(&pub_pem);
        assert!(inspect_res.is_ok());
        let inspect_info = inspect_res.unwrap();
        assert_eq!(inspect_info.fingerprint, info.fingerprint);
        assert!(!inspect_info.has_private_key);
    }

    #[test]
    fn test_detached_signing_and_verification() {
        let user = "Forensic Workstation <workstation@dfir.local>";
        let (priv_pem, pub_pem, _) = PgpKeyManager::generate_keypair(user).unwrap();

        let evidence_data = b"Case: 2026-DFIR-001\nMD5: e10adc3949ba59abbe56e057f20f883e\nExaminer: K. Priyansh";
        let sig_pem = PgpManifestSigner::sign_detached(evidence_data, &priv_pem).unwrap();

        assert!(sig_pem.contains("-----BEGIN OPENFORENSIC INTEGRITY SIGNATURE-----"));

        let verify_res = PgpManifestVerifier::verify_detached(evidence_data, &sig_pem, &pub_pem).unwrap();

        assert!(verify_res.is_valid, "Valid signature must pass verification!");
        assert!(verify_res.message.contains("VALID INTEGRITY SEAL"));
    }

    #[test]
    fn test_tampered_evidence_fails_verification() {
        let user = "Forensic Workstation <workstation@dfir.local>";
        let (priv_pem, pub_pem, _) = PgpKeyManager::generate_keypair(user).unwrap();

        let original_data = b"Case: 2026-DFIR-001\nStatus: SEIZED\nHash: 123456";
        let sig_pem = PgpManifestSigner::sign_detached(original_data, &priv_pem).unwrap();

        // 1. Test modifying payload data
        let tampered_data = b"Case: 2026-DFIR-001\nStatus: SEIZED\nHash: 654321";
        let verify_res_data = PgpManifestVerifier::verify_detached(tampered_data, &sig_pem, &pub_pem).unwrap();
        assert!(!verify_res_data.is_valid, "Tampered evidence data MUST fail verification!");
        assert!(verify_res_data.message.contains("INTEGRITY") || verify_res_data.message.contains("VIOLATION"));

        // 2. Test modifying signature string
        let tampered_sig = sig_pem.replace("HMAC-SHA256: ", "HMAC-SHA256: 0000000000000000");
        let verify_res_sig = PgpManifestVerifier::verify_detached(original_data, &tampered_sig, &pub_pem).unwrap();
        assert!(!verify_res_sig.is_valid, "Tampered signature MUST fail verification!");
    }

    #[test]
    fn test_file_signing_and_verification() {
        let temp_dir = std::env::temp_dir().join("openforensic_pgp_test");
        let _ = fs::create_dir_all(&temp_dir);
        let manifest_path = temp_dir.join("test_manifest.json");
        let _ = fs::write(&manifest_path, "{\"case\":\"2026-001\",\"hash\":\"abc\"}");

        let (priv_pem, pub_pem, _) = PgpKeyManager::generate_keypair("Test Examiner <exam@dfir.local>").unwrap();
        let sig_path = PgpManifestSigner::sign_file(&manifest_path, &priv_pem).unwrap();
        assert!(sig_path.exists());

        let report = PgpManifestVerifier::verify_file(&manifest_path, &sig_path, &pub_pem).unwrap();
        assert!(report.is_valid, "File signature verification failed!");

        // Modify file on disk and verify it fails
        let _ = fs::write(&manifest_path, "{\"case\":\"2026-001\",\"hash\":\"tampered\"}");
        let report_tampered = PgpManifestVerifier::verify_file(&manifest_path, &sig_path, &pub_pem).unwrap();
        assert!(!report_tampered.is_valid, "Tampered file on disk MUST fail verification!");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
