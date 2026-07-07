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

        assert!(priv_pem.contains("-----BEGIN SEAL KEY-----"));
        assert!(pub_pem.contains("-----BEGIN SEAL PUB-----"));
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

        assert!(sig_pem.contains("-----BEGIN SEAL SIGNATURE-----"));

        let verify_res = PgpManifestVerifier::verify_detached(evidence_data, &sig_pem, &pub_pem).unwrap();

        assert!(verify_res.is_valid);
        assert!(verify_res.message.contains("VALID"));
    }

    #[test]
    fn test_file_signing() {
        let temp_dir = std::env::temp_dir().join("openforensic_pgp_test");
        let _ = fs::create_dir_all(&temp_dir);
        let manifest_path = temp_dir.join("test_manifest.json");
        let _ = fs::write(&manifest_path, "{\"case\":\"2026-001\"}");

        let (priv_pem, pub_pem, _) = PgpKeyManager::generate_keypair("Test Examiner <exam@dfir.local>").unwrap();
        let sig_path = PgpManifestSigner::sign_file(&manifest_path, &priv_pem).unwrap();
        assert!(sig_path.exists());

        let report = PgpManifestVerifier::verify_file(&manifest_path, &sig_path, &pub_pem).unwrap();
        assert!(report.is_valid);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
