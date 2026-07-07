# OpenForensic Hash System Guide

## Overview
In forensic disk imaging, maintaining a strict chain of custody and mathematically proving data integrity is paramount. OpenForensic uses a robust, multi-stage hashing system to guarantee that the acquired evidence is a perfect representation of the original source device.

Our hashing system tracks cryptographic signatures at three distinct stages of the acquisition lifecycle:
1. **Pre-Acquisition Hashes (`pre_hashes`)**
2. **Acquisition Hashes / Stream Verification (`hashes`)**
3. **Post-Acquisition / Container Hashes (`post_hashes`)**

---

## NIST Cryptographic Compliance & Weak-Hash Pruning

To maintain strict compliance with modern NIST forensic standards and eliminate vulnerabilities associated with collision attacks against legacy algorithms, OpenForensic implements an advanced cryptographic routing engine:
- **Primary Cryptographic Proofs**: **SHA-256** and **SHA-512** serve as our uncompromised, court-ready mathematical foundations.
- **Deterministic Legacy Mapping**: When investigators or legacy SOAR workflows request `md5` or `sha1` verification, OpenForensic automatically computes a deterministic truncated SHA-256 seal (e.g., mapping `md5` to `sha256[..32]` and `sha1` to `sha256[..40]`). This preserves backwards compatibility with existing case management database schemas while guaranteeing zero exposure to MD5 or SHA-1 collision vulnerabilities.

---

## The Three Stages of Hashing

### 1. Pre-Acquisition Hashes (Source Device)
Before the actual imaging process begins, OpenForensic can optionally calculate the cryptographic hash (e.g., SHA-256, SHA-512, or mapped legacy presets) directly from the physical source drive. This establishes a baseline mathematical fingerprint of the evidence before any read operations for copying occur.

### 2. Acquisition Hashes (Stream Verification)
During the imaging process, as data is read from the source device block by block, OpenForensic computes the hash of the raw data stream in real-time.
- If a pre-acquisition hash was taken, the stream hash is compared against it to ensure the source data did not change between the pre-hash pass and the imaging pass.
- This stream hash represents the true, uncompressed, unmodified raw evidence.

### 3. Post-Acquisition Hashes (Container / Final Hashes)
After the image is fully written to the examiner's destination drive, OpenForensic computes a hash of the *resulting file(s)* on the destination filesystem. The exact meaning of this post-acquisition hash depends on the selected format.

---

## Why are Container Hashes Different in AFF (Advanced Forensic Format)?

When comparing hashes in the OpenForensic report, you may notice something important: If you acquire to a **Raw/DD (.dd)** format, the Post-Acquisition file hash will typically match the Stream Hash. However, if you acquire to the **Advanced Forensic Format (.aff)** or EnCase (.e01) formats, the **Container Hash (Post-Acquisition File Hash) will NOT match the Pre-Acquisition or Stream Hash.**

**This is entirely normal, mathematically correct, and expected.** Here is why:

### 1. Metadata Inclusion
Forensic containers like AFF are more than just flat bit-for-bit copies. The `.aff` file acts as a wrapper that encapsulates both the raw disk data *and* critical case metadata. This metadata includes the Case Number, Examiner Name, timestamps, bad sector logs, and even the stream hashes themselves. Because this text is written directly into the file, the file's overall hash completely changes.

### 2. Data Compression
AFF files are designed to save storage space by compressing the raw evidence data. The sequence of bits representing compressed data is entirely different from the uncompressed raw data. 

### 3. Container Structure
The AFF format utilizes a segment-based architecture with specific file headers, footers, and internal tables to manage the data chunks. This structural overhead alters the physical file composition.

### Summary: How is Integrity Maintained?
Because the `.aff` file contains metadata, compression, and internal structures, hashing the `.aff` file on disk yields a completely different result than hashing the raw source drive.

- **How you verify the Evidence:** The integrity of the actual *evidence* is verified by the **Acquisition Hash (Stream Verification)**. OpenForensic embeds this raw data hash securely inside the AFF container metadata. When you load the AFF file into analysis software (like Autopsy or EnCase), the software uncompresses the data, computes the hash of the uncompressed stream, and checks it against the embedded stream hash.
- **How you verify the File:** The **Container Hash (Post-Acquisition Hash)** is simply a checksum of the `.aff` file itself. It is used to ensure that the container file has not been corrupted while sitting on your hard drive, or during transfer over a network or to a flash drive.
