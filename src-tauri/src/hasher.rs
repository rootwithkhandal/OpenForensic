//! Cryptographic Hashing and Integrity Sealing Module
//!
//! Provides genuine multi-threaded computation of MD5, SHA1, SHA-256, and SHA-512 digests
//! for forensic evidence verification and NSRL/legacy matching.
//! Also provides workstation-keyed cryptographic report sealing.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA512,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::MD5    => f.write_str("MD5"),
            HashAlgorithm::SHA1   => f.write_str("SHA1"),
            HashAlgorithm::SHA256 => f.write_str("SHA256"),
            HashAlgorithm::SHA512 => f.write_str("SHA512"),
        }
    }
}

enum HasherInner {
    MD5(Md5),
    SHA1(Sha1),
    SHA256(Sha256),
    SHA512(Sha512),
}

impl HasherInner {
    fn update(&mut self, data: &[u8]) {
        match self {
            HasherInner::MD5(h)    => h.update(data),
            HasherInner::SHA1(h)   => h.update(data),
            HasherInner::SHA256(h) => h.update(data),
            HasherInner::SHA512(h) => h.update(data),
        }
    }
    fn finalize(self) -> String {
        match self {
            HasherInner::MD5(h)    => h.finalize().iter().map(|b| format!("{:02x}", b)).collect(),
            HasherInner::SHA1(h)   => h.finalize().iter().map(|b| format!("{:02x}", b)).collect(),
            HasherInner::SHA256(h) => h.finalize().iter().map(|b| format!("{:02x}", b)).collect(),
            HasherInner::SHA512(h) => h.finalize().iter().map(|b| format!("{:02x}", b)).collect(),
        }
    }
}

pub struct MultiHasher {
    senders: Vec<Sender<Option<Arc<Vec<u8>>>>>,
    handles: Vec<JoinHandle<(HashAlgorithm, String)>>,
}

impl MultiHasher {
    pub fn new(algorithms: &[HashAlgorithm]) -> Self {
        let mut senders = Vec::new();
        let mut handles = Vec::new();

        for &algo in algorithms {
            let (tx, rx) = mpsc::channel::<Option<Arc<Vec<u8>>>>();
            senders.push(tx);

            let handle = std::thread::spawn(move || {
                let mut inner = match algo {
                    HashAlgorithm::MD5    => HasherInner::MD5(Md5::new()),
                    HashAlgorithm::SHA1   => HasherInner::SHA1(Sha1::new()),
                    HashAlgorithm::SHA256 => HasherInner::SHA256(Sha256::new()),
                    HashAlgorithm::SHA512 => HasherInner::SHA512(Sha512::new()),
                };

                while let Ok(Some(chunk)) = rx.recv() {
                    inner.update(&chunk);
                }

                (algo, inner.finalize())
            });

            handles.push(handle);
        }

        Self { senders, handles }
    }

    pub fn update(&mut self, data: Arc<Vec<u8>>) {
        for tx in &self.senders {
            let _ = tx.send(Some(data.clone()));
        }
    }

    pub fn finalize(self) -> HashMap<HashAlgorithm, String> {
        for tx in &self.senders {
            let _ = tx.send(None);
        }

        let mut results = HashMap::new();
        for handle in self.handles {
            if let Ok((algo, hash_val)) = handle.join() {
                results.insert(algo, hash_val);
            }
        }
        results
    }
}

/// Generate a tamper-evident cryptographic report seal using a workstation-specific
/// 256-bit secret key stored securely in ~/.openforensic/investigator_seal.key.
/// This prevents arbitrary third-party signature synthesis without local investigator access.
pub fn generate_report_seal(report_content: &str, case_number: &str) -> String {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_else(|_| ".".to_string());
    let key_dir = std::path::PathBuf::from(home).join(".openforensic");
    let _ = std::fs::create_dir_all(&key_dir);
    let key_file = key_dir.join("investigator_seal.key");
    
    let secret_key = if let Ok(key) = std::fs::read(&key_file) {
        key
    } else {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let _ = std::fs::write(&key_file, &key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&key_file) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&key_file, perms);
            }
        }
        key
    };

    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&secret_key)
        .expect("HMAC can accept keys of any size");
    mac.update(case_number.as_bytes());
    mac.update(report_content.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_answer_md5() {
        let algos = vec![HashAlgorithm::MD5];
        let mut hasher = MultiHasher::new(&algos);
        hasher.update(Arc::new(b"abc".to_vec()));
        let res = hasher.finalize();
        // MD5("abc") == 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(res[&HashAlgorithm::MD5], "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_known_answer_sha1() {
        let algos = vec![HashAlgorithm::SHA1];
        let mut hasher = MultiHasher::new(&algos);
        hasher.update(Arc::new(b"abc".to_vec()));
        let res = hasher.finalize();
        // SHA1("abc") == a9993e364706816aba3e25717850c26c9cd0d89d
        assert_eq!(res[&HashAlgorithm::SHA1], "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_known_answer_sha256() {
        let algos = vec![HashAlgorithm::SHA256];
        let mut hasher = MultiHasher::new(&algos);
        hasher.update(Arc::new(b"abc".to_vec()));
        let res = hasher.finalize();
        // SHA256("abc") == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(res[&HashAlgorithm::SHA256], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_multi_hasher() {
        let algos = vec![HashAlgorithm::MD5, HashAlgorithm::SHA1, HashAlgorithm::SHA256, HashAlgorithm::SHA512];
        let mut hasher = MultiHasher::new(&algos);
        hasher.update(Arc::new(b"test forensic chunk".to_vec()));
        let res = hasher.finalize();
        assert_eq!(res.len(), 4);
        assert_eq!(res[&HashAlgorithm::MD5].len(), 32);
        assert_eq!(res[&HashAlgorithm::SHA1].len(), 40);
        assert_eq!(res[&HashAlgorithm::SHA256].len(), 64);
        assert_eq!(res[&HashAlgorithm::SHA512].len(), 128);
    }

    #[test]
    fn test_report_seal_consistency() {
        let seal1 = generate_report_seal("report data", "CASE-001");
        let seal2 = generate_report_seal("report data", "CASE-001");
        assert_eq!(seal1, seal2);
        assert_eq!(seal1.len(), 64);
    }
}
