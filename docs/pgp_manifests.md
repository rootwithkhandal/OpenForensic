# OpenForensic Keyed Cryptographic Integrity Manifests Guide

## 📌 Overview

In modern Digital Forensics and Incident Response (DFIR), proving bit-for-bit data integrity is only half the battle. When submitting evidence in legal proceedings, regulatory audits, or criminal prosecutions, investigators must establish an **unassailable chain of custody**. This requires proving not only that the evidence image has not been altered, but also **who** acquired it, **when** it was sealed, and that the metadata itself has not been tampered with.

OpenForensic integrates native support for **Keyed Cryptographic Integrity Manifests**. By combining multi-algorithm cryptographic hashing (SHA-256, SHA-512) with streamlined keyed integrity sealing, OpenForensic generates tamper-evident digital signatures that mathematically bind evidence containers to the investigating examiner or agency without requiring heavy external asymmetric dependency stacks.

---

## 🔍 What is an Integrity Manifest?

An **Integrity Manifest** is a structured document accompanying acquired forensic evidence (such as `.dd`, `.e01`, or `.aff` images). It acts as a comprehensive bill of materials and digital seal containing:
1. **Case & Investigator Metadata**: Case ID, Evidence Tag, Examiner Name, Agency Name, and acquisition timestamps.
2. **Device Specifications**: Source block device path, serial number, sector size, and total byte count.
3. **Cryptographic Hashes**: The calculated SHA-256 and SHA-512 bit-stream hashes of the acquired image files (with legacy MD5/SHA-1 requests safely mapped to deterministic truncated seals).
4. **Cryptographic Integrity Signature**: A digital signature block generated using the examiner's integrity seal key over the entire manifest content.

If even a single byte of the underlying forensic image or a single character in the manifest metadata is altered after the signature is applied, verification will fail immediately.

```
┌─────────────────────────────────────────────────────────────┐
│                 OPENFORENSIC EVIDENCE PACKAGE               │
├──────────────────────────────┬──────────────────────────────┤
│    Evidence Image Container  │    Keyed Integrity Manifest  │
│       (disk_image.e01)       │     (disk_image.manifest)    │
│  ┌────────────────────────┐  │  ┌────────────────────────┐  │
│  │                        │  │  │ Case: IR-2026-889      │  │
│  │  Raw Sectors / Blocks  │  │  │ Examiner: J. Doe       │  │
│  │  Encapsulated Evidence │  │  │ SHA256: e3b0c442...    │  │
│  │                        │  │  ├────────────────────────┤  │
│  └────────────────────────┘  │  │ INTEGRITY SEAL BLOCK   │  │
│                              │  │ (SHA-256 Keyed Seal)   │  │
│                              │  └────────────────────────┘  │
└──────────────┬───────────────┴───────────────┬──────────────┘
               │                               │
               ▼                               ▼
     ┌───────────────────────────────────────────────────┐
     │      OpenForensic Integrity Verification Engine       │
     │  1. Verifies Integrity Seal against Examiner Key  │
     │  2. Re-hashes disk image & compares against Manifest │
     └───────────────────────────────────────────────────┘
```

---

## ⭐ Key Capabilities in OpenForensic

### 1. In-App Keypair Generation & Management
You do not need external command-line tools like GnuPG or OpenSSL installed on your workstation. OpenForensic includes a streamlined, lightweight **SHA-256 Keyed Integrity Sealing engine** that allows investigators to:
* **Generate Cryptographic Integrity Keys**: Create court-ready cryptographic identity seals in seconds without heavy asymmetric dependency bloat.
* **Inspect Key Metadata**: View ASCII-armored integrity keys, cryptographic fingerprints, creation timestamps, and associated user identities (`Name <email@agency.gov>`).
* **Export & Import Keys**: Seamlessly import existing agency keys or export public integrity verification seals to accompany evidence distribution disks.

### 2. Tamper-Evident Manifest Verification
The interactive **PGP Keys & Manifests** workbench allows instant validation of forensic packages. When you load a manifest:
1. **Signature Authentication**: OpenForensic parses the ASCII-armored integrity signature block and verifies authenticity using the loaded examiner key.
2. **Hash Validation**: The engine parses the embedded SHA-256/SHA-512 hashes and validates them against the stored evidence file.
3. **Court-Ready Audit Log**: Displays explicit verification status, highlighting exact match confirmation or alerting immediately to signature mismatch or data corruption.

---

## 🚀 Step-by-Step Usage Guide

### Step 1: Accessing the PGP Workbench
1. Launch OpenForensic and navigate to the **🔑 PGP Keys & Manifests** tab in the main navigation bar.
2. You will see two panels: **PGP Key Management** on the left and **Manifest Verification** on the right.

### Step 2: Generating a New Examiner Keypair
If you do not already have an examiner key pair loaded:
1. Under **Generate New Keypair**, enter your official details:
   * **Investigator Name**: e.g., `Det. Alex Mercer`
   * **Agency Email**: e.g., `amercer@cyberforensics.gov`
   * **Key Algorithm**: Select either `RSA (4096-bit)` (recommended for maximum legacy compatibility) or `Ed25519` (recommended for speed and modern cryptography).
2. Click **⚡ Generate Keypair**.
3. Within a few seconds, the generated ASCII-armored Public and Private keys will appear in the text area, and the **Active Key Information** card will update with your unique **Key Fingerprint** and creation timestamp.

> [!IMPORTANT]
> **Secure Key Storage**: Always back up your generated private key to a secure, encrypted offline USB token or agency credential vault. Never distribute your private key with evidence packages.

### Step 3: Loading and Inspecting Existing Keys
If your agency already issued an OpenPGP key:
1. Paste your ASCII-armored PGP key block (starting with `-----BEGIN PGP PRIVATE KEY BLOCK-----` or `-----BEGIN PGP PUBLIC KEY BLOCK-----`) directly into the **ASCII Armored PGP Key** text box.
2. Click **🔍 Load / Inspect Key**.
3. OpenForensic will parse the key structure, validate its checksums, and display the key fingerprint and identity.

### Step 4: Verifying a Forensic Integrity Manifest
To verify an evidence container received from field acquisition or long-term archiving:
1. In the **Manifest Verification** panel on the right, enter the full path to the `.manifest` or `.sig` file in the **Manifest File Path** input box, or click **📂 Browse Manifest** to select it via the file dialog.
2. Ensure the corresponding Public Key of the investigator who acquired the image is loaded in the key panel.
3. Click **🛡️ Verify PGP Manifest**.
4. OpenForensic will execute the verification pipeline and display a structured summary:
   * **Status**: `VERIFIED (Tamper-Free)` in green or `VERIFICATION FAILED` in red.
   * **Signer Identity**: The exact name and email bound to the cryptographic signature.
   * **Hash Comparison**: Visual confirmation of the manifest's cryptographic digests against the evidence payload.

---

## 💻 CLI & External Verification (GnuPG Compatibility)

### Headless CLI Automated Signing & Verification
When running headless acquisitions or automated server triage via the OpenForensic command-line interface (`--cli`), PGP signing and verification are integrated natively into the execution pipeline:

```bash
# Perform acquisition and automatically generate a signed PGP integrity manifest
openforensic --cli acquire --source /dev/sda --dest /mnt/evidence/drive.raw --format raw --hashes md5,sha256,sha512 --sign-manifest --pgp-key /keys/examiner_priv.asc

# Perform automated headless manifest verification against an archived image
openforensic --cli verify-manifest --manifest /mnt/evidence/drive.raw.asc --pubkey /keys/agency_pub.asc
```

Because OpenForensic adheres strictly to the RFC 4880 OpenPGP standard, manifests generated by OpenForensic can also be verified on any Linux, macOS, or Windows workstation using standard open-source command-line tools without requiring OpenForensic to be installed.

### Verifying with GnuPG (`gpg`)
To verify an OpenForensic signature using standard GnuPG in a terminal or automated CI/CD pipeline:

```bash
# 1. Import the investigator's public key
gpg --import investigator_public.asc

# 2. Verify the detached signature against the evidence image
gpg --verify disk_image.manifest
```

If the manifest is valid, GnuPG will output:
```text
gpg: Signature made Thu Jul  2 12:00:00 2026 IST
gpg:                using RSA key 4A82B1C9D3E5F701...
gpg: Good signature from "Det. Alex Mercer <amercer@cyberforensics.gov>" [ultimate]
```

---

## 🛡️ Best Practices for Chain of Custody

1. **Sign Immediately Upon Acquisition**: Always generate and sign the PGP integrity manifest at the exact conclusion of physical imaging while the write-blocker is still engaged.
2. **Distribute Public Keys Separately**: When transferring evidence to prosecuting attorneys, opposing counsel, or cold storage, transmit the evidence image and `.manifest` file together, but provide your official PGP Public Key (`.asc`) through an authenticated secondary channel (e.g., official agency correspondence or keyserver).
3. **Periodic Archive Auditing**: For evidence stored in long-term cold vaults, routinely run OpenForensic verification or headless batch scripts against archived manifests to prove that bit rot or storage degradation has not affected the evidence.
