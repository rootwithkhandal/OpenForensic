pub mod keys;
pub mod signer;
pub mod verifier;
#[cfg(test)]
pub mod tests;

pub use keys::{Ed25519KeyInfo, Ed25519KeyManager};
pub use signer::Ed25519ManifestSigner;
pub use verifier::{PgpVerificationReport, Ed25519ManifestVerifier};

pub type PgpKeyManager = Ed25519KeyManager;
pub type PgpManifestSigner = Ed25519ManifestSigner;
pub type PgpManifestVerifier = Ed25519ManifestVerifier;
