#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use crate::pgp::{PgpKeyManager, PgpManifestSigner, PgpManifestVerifier};
    use std::fs;

    #[test]
    fn test_keygen_and_inspect() {
        let user = "Investigator Test <test@dfir.local>";
        let res = PgpKeyManager::generate_keypair(user);
        assert!(res.is_ok(), "Key generation failed: {:?}", res.err());
        let (priv_pem, pub_pem, info) = res.unwrap();

        assert!(priv_pem.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(pub_pem.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert_eq!(info.user_id, user);
        assert!(!info.fingerprint.is_empty());
        assert!(!info.key_id.is_empty());

        let inspect_res = PgpKeyManager::inspect_key(&pub_pem);
        assert!(inspect_res.is_ok());
        let inspect_info = inspect_res.unwrap();
        assert_eq!(inspect_info.fingerprint, info.fingerprint);
        assert_eq!(inspect_info.key_id, info.key_id);
        assert!(!inspect_info.has_private_key);
    }

    #[test]
    fn test_detached_signing_and_verification() {
        let user = "Forensic Workstation <workstation@dfir.local>";
        let (priv_pem, pub_pem, _) = PgpKeyManager::generate_keypair(user).unwrap();

        let evidence_data = b"Case: 2026-DFIR-001\nMD5: e10adc3949ba59abbe56e057f20f883e\nExaminer: K. Priyansh";
        let sig_pem = PgpManifestSigner::sign_detached(evidence_data, &priv_pem)
            .expect("Signing failed");

        assert!(sig_pem.contains("-----BEGIN PGP SIGNATURE-----"));

        let verify_res = PgpManifestVerifier::verify_detached(evidence_data, &sig_pem, &pub_pem)
            .expect("Verification execution failed");

        assert!(verify_res.is_valid, "Signature should be valid: {}", verify_res.message);
        assert!(verify_res.message.contains("VALID PGP SIGNATURE"));
    }

    #[test]
    fn test_tamper_detection() {
        let user = "Forensic Workstation <workstation@dfir.local>";
        let (priv_pem, pub_pem, _) = PgpKeyManager::generate_keypair(user).unwrap();

        let original_data = b"Hash: 5d41402abc4b2a76b9719d911017c592";
        let sig_pem = PgpManifestSigner::sign_detached(original_data, &priv_pem).unwrap();

        let tampered_data = b"Hash: 00000000000000000000000000000000";
        let verify_res = PgpManifestVerifier::verify_detached(tampered_data, &sig_pem, &pub_pem)
            .expect("Verification execution failed");

        assert!(!verify_res.is_valid, "Tampered data should fail verification");
        assert!(verify_res.message.contains("INVALID PGP SIGNATURE"));
    }

    #[test]
    fn test_file_signing_and_verification() {
        let temp_dir = std::env::temp_dir().join("openforensic_pgp_test");
        let _ = fs::create_dir_all(&temp_dir);
        let manifest_path = temp_dir.join("test_manifest.txt");
        fs::write(&manifest_path, "=== OPENFORENSIC MANIFEST ===\nFile: memory.raw\nSize: 8589934592").unwrap();

        let (priv_pem, pub_pem, _) = PgpKeyManager::generate_keypair("Test Examiner <exam@dfir.local>").unwrap();

        let sig_path = PgpManifestSigner::sign_file(&manifest_path, &priv_pem).unwrap();
        assert!(sig_path.exists());
        assert_eq!(sig_path.extension().unwrap(), "asc");

        let report = PgpManifestVerifier::verify_file(&manifest_path, &sig_path, &pub_pem).unwrap();
        assert!(report.is_valid);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
