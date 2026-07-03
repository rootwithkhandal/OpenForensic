# Guide: OpenForensic Analysis Suite & Dynamic Mode-Gating

> [!IMPORTANT]
> **NEW IN v2.0.2+ (Dynamic Session Mode-Gating & Zero-Panic Guarantee)**: You do not need to modify source code or recompile the application to access analysis features. OpenForensic v2.0.2+ ships with built-in **Session Mode Toggling** and a compile-time **Zero-Panic Guarantee** (`#![deny(clippy::unwrap_used)]`). By default, the application boots strictly in **Capture Mode** (read-only acquisition and verification). All advanced analytical and streaming features can be dynamically unlocked per session.

---

## 🏛️ Forensic Boundary: Why Capture vs. Analysis?

OpenForensic Disk Imager adheres to a strict digital forensics design principle: **separation of capture and analysis**. In live field incident response (IR) and laboratory disk imaging, preserving chain-of-custody and guaranteeing zero evidence tampering are paramount. 

To keep the active acquisition footprint lightweight and prevent accidental evidence modification or external network contamination during live collections, OpenForensic establishes a defense-in-depth boundary:

1. **Default Capture Mode**: Confines the application to read-only block device cloning, physical memory acquisition, logical file copying, and cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512). External network connections (SIEM streaming, IOC API lookups) and deep data mutations are restricted.
2. **Opt-In Analysis Mode**: Unlocks post-acquisition investigative suites, memory inspection, interactive SQL databases, chronological timeline generation, and real-time SIEM event streaming.

---

## 🔓 How to Switch to Analysis Mode

Mode transitions are designed to be intentional, audited investigator actions rather than silent background toggles.

### 1. In the Desktop GUI Dashboard
1. Look at the top navigation header bar. By default, the status badge displays 🟢 **Capture Mode**.
2. Click the **"Switch to Analysis Mode"** button.
3. A modal confirmation dialog will appear:
   > *"Switching to Analysis Mode unlocks deep analysis features, threat intelligence API enrichment, and live SIEM streaming. This disables further read-only evidence safeguards for this session. Do you wish to proceed?"*
4. Click **Confirm**. The navigation bar will update to 🔴 **Analysis Mode Active**, and all previously locked analysis tabs will immediately become accessible.

### 2. In Headless CLI & Automation Mode
When running automated triage scripts or cloud server investigations via the command-line interface (`--cli`), pass the `--mode analysis` flag before your target subcommand:

```bash
# Run Rapid System Triage with real-time Splunk HEC SIEM streaming
openforensic --cli --mode analysis triage --dest /mnt/evidence/triage --siem-export --siem-type splunk_hec --siem-endpoint https://splunk.example.com:8088 --siem-token <HEC_TOKEN>

# Analyze acquired RAM dump using Volatility 3 and AbuseIPDB IOC enrichment
openforensic --cli --mode analysis ram --dump /mnt/evidence/memory.raw --profile windows.pslist.PsList --ioc-enrich
```

---

## 🌟 Features Gated by Analysis Mode

The following six advanced forensic capabilities are protected behind the Analysis Mode boundary:

| Feature Area | Description & Capabilities in Analysis Mode |
| :--- | :--- |
| **⚡ Triage SQL Workbench** | Unlocks an interactive SQLite query workbench directly within the Triage tab. Allows investigators to execute SQL queries (`SELECT * FROM processes WHERE pid > 1000`, etc.) against acquired system tables (`processes`, `network_connections`, `browser_history`, `event_logs`) without exporting to external database tools. |
| **🧠 Volatility 3 RAM Analysis UI** | Enables the dedicated **RAM Analysis** dashboard tab. Orchestrates local or containerized **Volatility 3** engines against acquired memory images (`.raw`, `.vmem`, `.dmp`), streaming real-time log outputs and structured process tables. |
| **💻 Headless CLI RAM Engine (`ram` / `volatility`)** | Unlocks the scriptable command-line memory analyzer for automated SOAR workflows and headless server triage. |
| **🛡️ Threat Intelligence Enrichment** | Enables automated real-time IOC verification during memory analysis. Extracts public IP addresses and process hashes, verifying them against **AbuseIPDB** reputation scores and **VirusTotal** detection matrices. |
| **⏱️ Timeline Generator Tab** | Unlocks the **Timeline** dashboard module. Parses timestamps from NTFS `$MFT` records, `$LogFile` transactions, and Linux Ext4 journals, synthesizing them into master chronological timelines exported as structured CSV or JSON files. |
| **🛡️ SIEM & SOC Streaming** | Enables real-time emission of forensic records during live triage to **Splunk HTTP Event Collector (HEC)** and **Wazuh Agent Sockets / Syslog** (TCP/UDP port 1514). |
| **🔑 RAM Master-Key Extraction** | Unlocks deep memory scanning routines that search physical RAM dumps for cryptographic master keys, including **BitLocker Volume Master Keys (VMKs)**, **Linux LUKS Master Keys**, and **Android Gatekeeper CE Keys**. |

---

## 🛡️ Technical Enforcement & Zero-Panic Architecture

OpenForensic enforces session mode-gating and application stability through three distinct layers in the Rust kernel:

### 1. Runtime State Guard (`require_analysis_mode`)
Every backend Tauri command and CLI handler responsible for analysis features invokes a mandatory state guard before executing any business logic:

```rust
pub fn require_analysis_mode(state: &AcquisitionModeState) -> std::result::Result<(), String> {
    let guard = state.lock().map_err(|_| "AcquisitionMode mutex poisoned".to_string())?;
    match *guard {
        AcquisitionMode::Analysis => Ok(()),
        AcquisitionMode::Capture => Err("This feature is disabled in Capture Mode. Switch to Analysis Mode to continue.".into()),
    }
}
```
If an unauthorized invocation is attempted while in Capture Mode, the handler rejects the request with an explicit error and logs an alert.

### 2. Dual Static Capability Allowlists
Tauri 2 permissions are organized into modular capability manifests:
* `capabilities/default.json`: Grants access strictly to capture, device scanning, hashing, and PGP manifest verification commands.
* `capabilities/analysis.json`: Defines allowlists for analysis suite invocations (`query_triage_db`, `start_volatility_analysis`, `generate_image_timeline`, `export_triage_to_siem`, `test_siem_connection`, `save_siem_config`, and `extract_memory_keys`).

### 3. Zero-Panic Forensic Reliability Guarantee (`#![deny(clippy::unwrap_used)]`)
In digital forensics, a crash or panic mid-acquisition is unacceptable—it corrupts multi-gigabyte image files, loses volatile live evidence, and breaks chain of custody. OpenForensic v2.0.2+ enforces a strict **Zero-Panic Reliability Guarantee**:
* **Compile-Time Prohibition**: Both `lib.rs` and `main.rs` enforce `#![deny(clippy::unwrap_used)]`. Any introduction of `.unwrap()` or `.expect()` in production code causes an immediate build failure.
* **Fallible Error Propagation**: All state mutex locks, SQLite row evaluations, I/O streams, and child process pipes utilize fallible pattern matching (`match`, `if let Some/Ok`, or `map_err(...)?`) returning descriptive `OpenForensicError` variants.
* **Strict Code Quality & Clippy Compliance**: Core acquisition, hashing, reporting, and plugin pipelines are maintained with zero compiler or clippy lint warnings (`-D warnings`), leveraging modern Rust idioms such as `&& let` chains and static zero-fill buffers for optimal memory efficiency.
* **Graceful Degradation**: If an external dependency (like a Volatility pipe or SIEM socket) fails, the error is caught, logged to the UI progress stream, and recorded without terminating the acquisition engine.

---

## 📋 Chain-of-Custody Audit Logging

To satisfy court admissibility and regulatory compliance (e.g., ISO/IEC 27037), every mode transition and feature unlock is cryptographically recorded in the active case's SQLite database (`audit_logs` table):

```sql
SELECT timestamp, event_type, details FROM audit_logs WHERE event_type = 'MODE_TRANSITION';
```

| Timestamp | Event Type | Details |
| :--- | :--- | :--- |
| `2026-07-03T07:15:00Z` | `APP_BOOT` | Application initialized in default Capture Mode. |
| `2026-07-03T07:18:22Z` | `MODE_TRANSITION` | Examiner 'ID-4402' switched session mode from Capture to Analysis Mode. |
| `2026-07-03T07:19:05Z` | `SIEM_EXPORT_START` | Triage database exported to Splunk HEC endpoint (index: `main_dfir`). |
