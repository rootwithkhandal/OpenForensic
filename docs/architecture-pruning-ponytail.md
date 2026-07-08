# OpenForensic — Enterprise System & Volatile Memory Architecture Guide

## 📌 Overview

OpenForensic adheres to a lean, high-performance engineering philosophy designed for mission-critical digital forensics and incident response (DFIR). When building forensic tools that must run reliably in hostile field environments, air-gapped forensic labs, and headless server instances, software bloat and heavy external runtimes represent a direct liability.

This document outlines the architectural optimizations and design decisions implemented across OpenForensic to maximize execution velocity, eliminate vulnerability surface area, and guarantee zero runtime failures and courtroom-defensible evidentiary integrity during evidence acquisition.

---

## ⚡ Key Architectural Optimizations

### 1. Static Native Plugin Dispatch (`NativePlugin`)
Traditional extensible applications often rely on heavy dynamic trait dispatch (`Box<dyn Trait>`) or embedded WebAssembly runtimes (`wasmtime`) to support third-party plugins.
- **The Optimization**: OpenForensic avoids heavy dynamic trait abstraction layers and embedded WASM execution engines in favor of direct **static native dispatch** via `NativePlugin`.
- **The Benefit**: Compiled shared libraries (`.so`, `.dll`, `.dylib`) are loaded dynamically via FFI symbols (`_openforensic_plugin_create`) and dispatched through direct static method calls. This eliminates virtual table lookup overhead, reduces binary size, and guarantees zero-degradation disk streaming during block acquisition.

### 2. Keyed Cryptographic Integrity Manifest Sealing (`openforensic_hmac`)
Generating court-admissible chain-of-custody manifests previously required bundling massive asymmetric cryptographic stacks (like OpenPGP or GnuPG bindings) that introduce external dependency bloat and complex key management overhead.
- **The Optimization**: Implements a streamlined, native **HMAC-SHA256 & SHA-256 Keyed Integrity Sealing engine** ([src-tauri/src/pgp/](file:///d:/projects/private/Openforensic/src-tauri/src/pgp)).
- **The Benefit**: Evidence containers and case reports are signed using 256-bit cryptographically random secret keys (`openforensic_hmac.key` / `.pub`). Verification recomputes the SHA-256 payload digest and validates the HMAC-SHA256 seal in constant time (`mac.verify_slice`), guaranteeing an explicit `INTEGRITY VIOLATION` error if even a single byte of evidence or metadata is altered.

### 3. Multi-Destination SIEM & SOC Streaming (`SiemClient`)
Enterprise SIEM integration (Splunk HEC, Wazuh) must operate reliably without blocking live triage imaging pipelines.
- **The Optimization**: Implements an asynchronous, multi-destination telemetry streaming engine in [src-tauri/src/siem/client.rs](file:///d:/projects/private/Openforensic/src-tauri/src/siem/client.rs).
- **The Benefit**: During live triage, structured forensic JSON records are transmitted directly to enterprise destinations:
  - **Splunk HEC**: Live HTTP POST streaming via `reqwest` with Bearer token authentication and batch error tracking.
  - **Wazuh Socket & Local Log**: Direct TCP/UDP network streaming or structured JSON-L file appending (`WazuhLocalLog`) for instant OS agent ingestion.

### 4. Simultaneous Multi-Algorithm Cryptographic Hashing (`hasher.rs`)
Forensic standards mandate strict verification against established cryptographic hash algorithms without degrading disk acquisition velocity.
- **The Optimization**: Implements **simultaneous multi-algorithm cryptographic hashing** in [src-tauri/src/hasher.rs](file:///d:/projects/private/Openforensic/src-tauri/src/hasher.rs), computing genuine **MD5**, **SHA-1**, **SHA-256**, and **SHA-512** in a single streaming read pass over the evidence payload.
- **The Benefit**: While SHA-256 and SHA-512 serve as primary NIST-compliant integrity standards, computing genuine MD5 and SHA-1 simultaneously is essential in digital forensics for cross-referencing against standard legacy databases (such as NIST NSRL National Software Reference Library, CFTT toolboxes, and VirusTotal IOC feeds) without introducing any second-read disk I/O overhead.

---

## 🏗️ Comparative Architecture Scoreboard

| Architectural Area | Traditional Implementation | OpenForensic Architecture | Measured Impact & Courtroom Benefit |
| :--- | :--- | :--- | :--- |
| **Memory Analysis Engine** | External Python Volatility 3 Subprocess | Built-in Native Rust Engine (`volatility/`) | Zero Python dependencies; in-process real-time streaming; instant startup. |
| **Plugin Extension Runtime** | Dynamic Trait Objects & `wasmtime` Runtime | Static Native Dispatch (`NativePlugin` DLL/SO) | Eliminated virtual table overhead; pruned WASM runtime bloat; maximum throughput. |
| **Evidence Manifest Signing** | External OpenPGP Stack / GnuPG | Keyed HMAC-SHA256 & SHA-256 Sealing (`openforensic_hmac`) | Zero external dependency bloat; constant-time cryptographic seal verification. |
| **SIEM Telemetry Shipping** | Blocking HTTP Calls / Dummy Stubs | Asynchronous Splunk HEC HTTP & Wazuh Socket/Log Engine | Real-time SOC alerting with zero network blocking during physical imaging. |
| **Cryptographic Hashing** | 4-Algorithm Independent Computation | Simultaneous MD5, SHA-1, SHA-256, and SHA-512 Streaming | Full legacy database compatibility (NSRL/CFTT) + NIST compliance in a single read pass. |
| **Case Container Management** | External Database Import Scripts / Scattered Output Files | Native Unified Case Folder Architecture (`<CaseRoot>/<CaseNumber>/`) | Standardized `Cache/`, `Export/`, `Log/`, `ModuleOutput/`, `Reports/`, `.ofc` manifest, and portable `openforensic.db` with zero-import archiving. |

---

## 🛡️ Zero-Panic Reliability Guarantee

In addition to architectural optimization, OpenForensic enforces a strict compile-time reliability policy:
- **`#![deny(clippy::unwrap_used)]`**: Enforced across core entry points (`src-tauri/src/lib.rs` and `main.rs`).
- **Fallible Error Propagation**: All potential runtime errors during disk reading, memory scanning, or file writing are converted into structured `OpenForensicError` types and safely propagated to the UI dashboard or CLI standard error stream. Never panics during live acquisition.
