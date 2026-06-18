use sha2::{Digest, Sha256, Sha512};
use md5::Md5;
use sha1::Sha1;
use std::collections::HashMap;

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
    hashers: Vec<(HashAlgorithm, HasherInner)>,
}

impl MultiHasher {
    pub fn new(algorithms: &[HashAlgorithm]) -> Self {
        let hashers = algorithms.iter().map(|&algo| {
            let inner = match algo {
                HashAlgorithm::MD5    => HasherInner::MD5(Md5::new()),
                HashAlgorithm::SHA1   => HasherInner::SHA1(Sha1::new()),
                HashAlgorithm::SHA256 => HasherInner::SHA256(Sha256::new()),
                HashAlgorithm::SHA512 => HasherInner::SHA512(Sha512::new()),
            };
            (algo, inner)
        }).collect();
        Self { hashers }
    }

    pub fn update(&mut self, data: &[u8]) {
        for (_, h) in &mut self.hashers {
            h.update(data);
        }
    }

    pub fn finalize(self) -> HashMap<HashAlgorithm, String> {
        self.hashers.into_iter().map(|(algo, h)| (algo, h.finalize())).collect()
    }
}

// ponytail: keyed hash for tamper-evident report seal, not asymmetric signing.
pub fn generate_report_seal(report_content: &str, case_number: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(report_content.as_bytes());
    hasher.update(case_number.as_bytes());
    hasher.update(b"FORGELENS-SECURE-FORENSIC-SIGNING-SALT-2026");
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}
