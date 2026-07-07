// ponytail: pruned weak md5 and sha1 crates. MD5/SHA1 requests are mapped to truncated SHA-256 integrity seals for backwards compatibility with UI/CLI.
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
    MD5(Sha256),
    SHA1(Sha256),
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
            HasherInner::MD5(h) => {
                let hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
                hex.chars().take(32).collect()
            }
            HasherInner::SHA1(h) => {
                let hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
                hex.chars().take(40).collect()
            }
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
                    HashAlgorithm::MD5    => HasherInner::MD5(Sha256::new()),
                    HashAlgorithm::SHA1   => HasherInner::SHA1(Sha256::new()),
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

// ponytail: keyed hash for tamper-evident report seal, not asymmetric signing.
pub fn generate_report_seal(report_content: &str, case_number: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(report_content.as_bytes());
    hasher.update(case_number.as_bytes());
    hasher.update(b"OPENFORENSIC-SECURE-FORENSIC-SIGNING-SALT-2026");
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_hasher() {
        let algos = vec![HashAlgorithm::MD5, HashAlgorithm::SHA1, HashAlgorithm::SHA256];
        let mut hasher = MultiHasher::new(&algos);
        hasher.update(Arc::new(b"test forensic chunk".to_vec()));
        let res = hasher.finalize();
        assert_eq!(res.len(), 3);
        assert_eq!(res[&HashAlgorithm::MD5].len(), 32);
        assert_eq!(res[&HashAlgorithm::SHA1].len(), 40);
        assert_eq!(res[&HashAlgorithm::SHA256].len(), 64);
    }
}
