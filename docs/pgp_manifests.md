# OpenForensic Keyed Cryptographic Integrity Manifests Guide

## 📌 Overview

In modern Digital Forensics and Incident Response (DFIR), proving bit-for-bit data integrity is only half the battle. When submitting evidence in legal proceedings, regulatory audits, or criminal prosecutions, investigators must establish an **unassailable chain of custody**. This requires proving not only that the evidence image has not been altered, but also **who** acquired it, **when** it was sealed, and that the metadata itself has not been tampered with.

OpenForensic integrates native support for **Keyed Cryptographic Integrity Manifests**. By combining simultaneous multi-algorithm cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512) with native **HMAC-SHA256 & SHA-256 Keyed Integrity Sealing**, OpenForensic generates tamper-evident digital signatures that mathematically bind evidence containers to the investigating examiner or agency without requiring heavy external asymmetric dependency stacks.

---

## 🔍 What is an Integrity Manifest?

An **Integrity Manifest** is a structured document accompanying acquired forensic evidence (such as `.dd`, `.e01`, or `.aff` images). It acts as a comprehensive bill of materials and digital seal containing:
1. **Case & Investigator Metadata**: Case ID, Evidence Tag, Examiner Name, Agency Name, and acquisition timestamps.
2. **Device Specifications**: Source block device path, serial number, sector size, and total byte count.
3. **Cryptographic Hashes**: The calculated genuine MD5, SHA-1, SHA-256, and SHA-512 bit-stream hashes of the acquired image files computed simultaneously during block acquisition.
4. **Cryptographic Integrity Signature**: A digital HMAC-SHA256 signature block generated using the examiner's 256-bit secret key over the entire manifest and evidence payload.

If even a single byte of the underlying forensic image or a single character in the manifest metadata is altered after the signature is applied, verification will fail immediately with an explicit `INTEGRITY VIOLATION` alert.

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
│                              │  │ (HMAC-SHA256 Seal)     │  │
│                              │  └────────────────────────┘  │
└──────────────┬───────────────┴───────────────┬──────────────┘
               │                               │
               ▼                               ▼
     ┌───────────────────────────────────────────────────┐
     │      OpenForensic Integrity Verification Engine       │
     │  1. Verifies HMAC-SHA256 Seal against Verification Key│
     │  2. Re-hashes disk image & compares SHA-256 Digest    │
     └───────────────────────────────────────────────────┘
```

---

## ⭐ Key Capabilities in OpenForensic

### 1. Native Keypair Generation & Management (`openforensic_hmac`)
You do not need external command-line tools like GnuPG or OpenSSL installed on your workstation. OpenForensic includes a native **HMAC-SHA256 & SHA-256 Keyed Integrity Sealing engine** that allows investigators to:
* **Generate Cryptographic Integrity Keys**: Create court-ready 256-bit cryptographic identity seals in seconds (`openforensic_hmac.key` and `openforensic_hmac.pub`) generated from OS entropy via `rand::RngCore`.
* **Inspect Key Metadata**: View ASCII-armored manifests (`-----BEGIN OPENFORENSIC HMAC-SHA256 KEY-----`), cryptographic SHA-256 fingerprints, creation timestamps, and associated user identities (`Name <email@agency.gov>`).
* **Export & Import Keys**: Seamlessly import existing agency keys or export public verification tokens (`-----BEGIN OPENFORENSIC HMAC-SHA256 VERIFICATION TOKEN-----`) to accompany evidence distribution disks.

### 2. Tamper-Evident Manifest Verification
The interactive **PGP Keys & Manifests** workbench allows instant validation of forensic packages. When you load a manifest:
1. **Signature Authentication**: OpenForensic parses the ASCII-armored integrity signature block and verifies HMAC-SHA256 authenticity in constant time (`mac.verify_slice`) using the loaded verification token.
2. **Hash Validation**: The engine re-reads the evidence file payload, computes its SHA-256 digest, and validates it against the recorded hash in the manifest.
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
2. Click **⚡ Generate Keypair**.
3. Within a few seconds, the generated ASCII-armored Secret Key and Verification Token will appear in the text area, and the **Active Key Information** card will update with your unique **SHA-256 Fingerprint** and creation timestamp.

> [!IMPORTANT]
> **Secure Key Storage**: Always back up your generated secret key (`openforensic_hmac.key`) to a secure, encrypted offline USB token or agency credential vault. Never distribute your secret key with evidence packages. Provide only the Verification Token (`openforensic_hmac.pub`) to external parties.

### Step 3: Loading and Inspecting Existing Keys
If your agency already issued an OpenForensic integrity key or verification token:
1. Paste your ASCII-armored key block directly into the **ASCII Armored Key / Token** text box.
2. Click **🔍 Load / Inspect Key**.
3. OpenForensic will parse the header structure, validate its format, and display the key fingerprint and identity.

### Step 4: Verifying a Forensic Integrity Manifest
To verify an evidence container received from field acquisition or long-term archiving:
1. In the **Manifest Verification** panel on the right, enter the full path to the `.manifest` or `.sig` file in the **Manifest File Path** input box, or click **📂 Browse Manifest** to select it via the file dialog.
2. Ensure the corresponding Verification Token of the investigator who acquired the image is loaded in the key panel.
3. Click **🛡️ Verify Manifest**.
4. OpenForensic will execute the two-stage verification pipeline and display a structured summary:
   * **Status**: `VALID INTEGRITY SEAL` in green or `INTEGRITY VIOLATION` in red.
   * **Signer Identity**: The exact name and fingerprint bound to the cryptographic signature.
   * **Hash Comparison**: Visual confirmation of the manifest's cryptographic digests against the evidence payload.
   * **Unified Case Architecture Storage (`v2.1.0+`)**: All signed `.manifest` and `.sig` integrity manifests generated during acquisition are automatically archived in `<CaseRoot>/<CaseNumber>/Log/` (or `Export/`) alongside the `<CaseName>.ofc` master case container file.

---

## 💻 CLI Automated Signing & Verification

When running headless acquisitions or automated server triage via the OpenForensic command-line interface (`--cli`), integrity signing and verification are integrated natively into the execution pipeline:

```bash
# Perform acquisition and automatically generate a signed HMAC-SHA256 integrity manifest
openforensic --cli acquire --source /dev/sda --dest /mnt/evidence/drive.raw --format raw --hashes md5,sha1,sha256,sha512 --sign-manifest --key /keys/openforensic_hmac.key

# Perform automated headless manifest verification against an archived image
openforensic --cli verify-manifest --manifest /mnt/evidence/drive.raw.sig --pubkey /keys/openforensic_hmac.pub
```

The resulting signature manifest (`drive.raw.sig`) is a cleartext ASCII-armored file recording the exact Signer ID, SHA-256 payload hash, and HMAC-SHA256 seal, allowing automated verification across agency CI/CD pipelines or forensic lab intake systems.

---

## 🛡️ Best Practices for Chain of Custody

1. **Sign Immediately Upon Acquisition**: Always generate and sign the integrity manifest at the exact conclusion of physical imaging while the write-blocker is still engaged.
2. **Distribute Verification Tokens Separately**: When transferring evidence to prosecuting attorneys, opposing counsel, or cold storage, transmit the evidence image and `.sig` file together, but provide your official Verification Token (`openforensic_hmac.pub`) through an authenticated secondary channel (e.g., official agency correspondence).
3. **Periodic Archive Auditing**: For evidence stored in long-term cold vaults, routinely run OpenForensic verification or headless batch scripts against archived manifests to prove that bit rot or storage degradation has not affected the evidence.
