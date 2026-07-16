# ⚡ OpenForensic Disk Imager & Digital Forensics Suite

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg?style=for-the-badge&logo=semver)](package.json)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg?style=for-the-badge&logo=rust)](src-tauri/Cargo.toml)
[![Tauri](https://img.shields.io/badge/tauri-2.11-24C8DB.svg?style=for-the-badge&logo=tauri)](src-tauri/tauri.conf.json)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg?style=for-the-badge&logo=linux)]()
[![License](https://img.shields.io/badge/license-Proprietary-red.svg?style=for-the-badge)]()

**OpenForensic** is an enterprise-grade, cross-platform digital forensics and incident response (DFIR) application built in high-performance **Rust** and powered by **Tauri 2**. Designed for forensic investigators, incident responders, and law enforcement, OpenForensic provides an end-to-end, write-blocked investigation suite capable of physical disk cloning, live volatile system triage, deep memory analysis, IOC scanning, and automated chain-of-custody reporting.

---

## 🌟 Key Forensic Capabilities

| Module                                 | Features & Capabilities                                                                                                                                                                                                                                                                          |
| :------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **📂 Disk Imaging**                    | Physical sector-by-sector and logical file acquisition. Supports Raw (`.dd`), E01 (`.e01`), and Advanced Forensic Format (`.aff`). Automatic sparse zero-block skipping and multi-threaded compression (`zstd`, `gzip`).                                                                         |
| **🔴 Live Acquisition**                | Zero-downtime live evidence collection using Volume Shadow Copy Service (**VSS**) on Windows to freeze filesystem state. Safely captures OS-locked artifacts including NTFS MFT (`$MFT`), Registry Hives (`SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`), and Event Logs.                              |
| **⚡ Rapid System Triage**             | Instantaneous extraction of volatile system state: running processes, network connections, kernel modules, Chrome/Edge browser history databases, and EVTX/syslog event records. Includes an interactive **Triage SQL Workbench** to query and inspect sqlite databases directly within the app. |
| **💻 Headless CLI Mode**               | Full scriptable command-line interface (`--cli`) bypassing the GUI. Enables headless execution in IR automation pipelines, AWS EC2 / Linux servers without display managers, and automated triage scripts.                                                                                       |
| **🧠 Native Rust Volatility Engine** | Built-in, high-performance **native Rust memory forensics engine** (`volatility/`) for analyzing acquired RAM dumps (`.raw`, `.vmem`, `.dmp`). Runs in-process with zero Python dependencies. Supports Windows, Linux, and macOS memory profiles (`windows.pslist.PsList`, `windows.netstat.NetStat`, `windows.cmdline.CmdLine`, `windows.filescan.FileScan`, `windows.malfind.Malfind`) with real-time log streaming. |

| **🛡️ Threat Intelligence Enrichment** | Automated real-time IOC enrichment during memory analysis. Verifies extracted IP addresses against **AbuseIPDB** reputation scores and queries file/process hashes against **VirusTotal**. |
| **🛡️ SIEM & SOC Integration** | Direct real-time ingestion of structured JSON forensic records and threat intelligence IOCs into **Splunk HEC (HTTP Event Collector)** and **Wazuh Agent Socket / Syslog**. Employs lightweight local disk and socket shippers without heavy embedded HTTP client bloat. |
| **⏱️ Timeline Generator** | Automated chronological artifact reconstruction. Extracts and parses timestamps from MFT records, `$LogFile`, and Ext4 journals to produce unified master timelines exported to structured **CSV** and **JSON** formats. |
| **🔍 On-the-Fly YARA & Keyword Scanning** | Powered by a pure-Rust **YARA-X** engine. Performs real-time pattern matching against custom `.yar` rulesets and regular expression keyword searches simultaneously while streaming disk or memory data. |
| **🧩 Extensible Plugin Platform** | Modular plugin architecture supporting compiled native shared libraries (`.so`, `.dll`, `.dylib`) restricted to post-acquisition Analysis Mode. Features standardized lifecycle hooks (`pre_acquisition`, `on_block`, `post_acquisition`) with static native dispatch for data processing and automated report enrichment without dynamic trait or runtime overhead. |
| **🔐 Cryptographic Hash Verification** | Single-pass multi-threaded integrity verification using NIST-approved **SHA-256 and SHA-512** engines alongside genuine **MD5 and SHA-1** for NSRL/legacy matching and cross-tool verification. Includes built-in checkpointing to pause and resume long acquisitions without data corruption. |
| **🔑 Keyed Integrity Manifests** | Built-in cryptographic Keyed Integrity Sealing engine generating detached tamper-evident signatures (`.manifest` / `.sig` / `.signature`) for evidence containers and case reports using unique workstation-specific secret keys (`~/.openforensic/investigator_seal.key`). |
| **🔍 Parallel Data Recovery & File Carving** | Multi-threaded Rayon file carving with **Exact Structure Validation** across **23+ forensic file formats** (`.jpg`, `.png`, `.gif`, `.bmp`, `.webp`, `.avi`, `.wav`, `.pdf`, `.zip`/DOCX/XLSX, Legacy `.doc`, `.rtf`, `.gz`, `.7z`, `.rar`, `.sqlite`, `.evtx`, Registry Hives `.dat`, Shortcuts `.lnk`, Prefetch `.pf`, `.pcap`, PE `.exe/.dll`, and ELF binaries) across unallocated sectors and physical `.dd`/`.raw` dumps. Uses a **Batched Streaming Architecture (`batch_limit = 16`)** guaranteeing strict ~256 MB bounded memory usage across multi-terabyte disk images without Out-Of-Memory crashes or file corruption. Includes interactive single-threaded vs multi-threaded Rayon CPU benchmark verification. |
| **🛡️ Zero-Trust Security Allowlists** | Hardened security boundaries featuring exact SHA-256 binary hash verification (`~/.openforensic/memory_tools_allowlist.json`) before executing third-party memory acquisition drivers (`winpmem.exe`, `LiME`). Manageable directly from the GUI Settings panel without manual file edits. |
| **📁 Unified Case Management & Reporting** | Self-contained **Autopsy-style Unified Case Folder Architecture** (`Cache/`, `Export/`, `Log/`, `ModuleOutput/`, `Reports/`, `.ofc` manifest, and portable `openforensic.db`). All disk images, triage databases, timelines, and court-admissible HTML/PDF reports are automatically routed to one central directory per case. Zero external database import scripts required. |

> [!NOTE]
> **Strict Separation of Capture vs. Analysis (Defense-in-Depth)**: OpenForensic enforces a strict forensic boundary between data acquisition and post-acquisition analysis. On boot, the application defaults to **Capture Mode** (read-only physical/logical acquisition and hashing). To access analytical and streaming features (**Parallel Data Recovery & Carving**, **Triage SQL Workbench**, **Native Rust Volatility RAM Analysis**, **Threat-Intel Enrichment**, **SIEM & SOC Integration**, **Timeline Generation**, and **RAM Master-Key Extraction**), investigators must explicitly toggle to **Analysis Mode** per session via an interactive UI confirmation dialog or `--mode analysis` CLI flag. Mode transitions are enforced by Rust runtime guards (`require_analysis_mode`), backed by dual static capability allowlists (`capabilities/default.json` and `capabilities/analysis.json`), and automatically recorded in the SQLite case database (`audit_logs` table) for chain-of-custody compliance. See the **[Enabling Analysis Suite Features Guide](docs/enabling-analysis-suite-features.md)** for details.

---

## 🏛️ Architecture & Asynchronous Pipeline

OpenForensic achieves maximum I/O throughput by separating disk reading, cryptographic hashing, IOC scanning, and file writing into distinct asynchronous processing streams managed by Tokio runtime channels.

```mermaid
graph TD
    subgraph Storage & Memory Sources
        RawDisk[Physical Drive / dev/rdisk / sys/block]
        LiveSys[Live OS / VSS Shadow Copy]
        RamDump[Physical RAM / winpmem / lime / avml]
    end

    subgraph Rust Backend Engine
        Reader[Async Block Reader / Software Write-Blocker]
        Broadcast[Tokio MPSC Broadcast Channel]

        Hashers[Concurrent Hash Verification<br/>SHA256 | SHA512 | Mapped MD5/SHA1]
        Yara[YARA-X & Keyword Scanner]
        Plugins[Static Native Plugin Engine<br/>Compiled DLL / SO / DYLIB]
        Writer[Image Writer & Compression Engine<br/>Raw | E01 | AFF | Sparse]

        VolEngine[Native Rust Volatility Engine<br/>AbuseIPDB | VirusTotal IOC Enrichment]
    end

    subgraph Storage & UI
        CaseDB[(Global & Portable SQLite Case DBs)]
        CaseRoot[📁 Unified Case Folder Architecture]
        Reports[HTML / PDF Evidence Reports]
        UI[Tauri 2 / Vanilla CSS Forensic Dashboard]
    end

    RawDisk --> Reader
    LiveSys --> Reader
    RamDump --> VolEngine

    Reader --> Broadcast
    Broadcast --> Hashers
    Broadcast --> Yara
    Broadcast --> Plugins
    Broadcast --> Writer

    Hashers --> CaseDB
    Yara --> CaseDB
    Plugins --> CaseDB
    Writer --> CaseDB
    VolEngine --> CaseDB

    CaseDB --> CaseRoot
    CaseRoot --> Reports
    CaseDB -->|Structured JSON Stream| SIEM[Splunk HEC / Wazuh Socket]
    CaseDB <-->|Asynchronous IPC| UI
    VolEngine -->|Real-time Event Streams| UI
```

### 🔒 Capture vs. Analysis Mode (Defense-in-Depth Security)

To ensure digital evidence integrity and prevent accidental evidence modification during active field collections, OpenForensic implements a multi-layered boundary between data capture and analysis:

- **Default Capture Mode**: On launch, the application operates strictly in **Capture Mode**. In this mode, only non-invasive physical/logical acquisition, cryptographic hashing, and general utilities are active.
- **Session Analysis Mode Gate**: Switching to **Analysis Mode** requires explicit investigator confirmation via an interactive UI confirmation modal ("*Switching to Analysis Mode disables further evidence-modifying safeguards for this session*") or passing the `--mode analysis` flag in CLI mode.
- **Runtime Rust Enforcement (`require_analysis_mode`)**: All 7 post-acquisition analytical and streaming commands (`query_triage_db`, `generate_image_timeline`, `start_volatility_analysis`, `test_siem_connection`, `save_siem_config`, `export_triage_to_siem`, and `extract_memory_keys`) are gated at the Rust runtime layer. Any attempt to invoke these handlers while in Capture Mode is immediately blocked and rejected.
- **Chain-of-Custody Audit Logging**: Every session mode transition is cryptographically logged to the SQLite case database (`audit_logs` table) with timestamps and investigator actions.
- **Modular Capability Allowlists**: Command invocation permissions are organized into two distinct static capability files: `capabilities/default.json` (always-active capture commands) and `capabilities/analysis.json` (analysis suite commands).

### ⚡ Zero-Panic Forensic Reliability Guarantee

In digital forensics, a software panic or crash mid-acquisition is unacceptable—it corrupts multi-gigabyte evidence images, destroys unsaved volatile memory artifacts, and breaks chain of custody. OpenForensic v2.1.0 enforces an uncompromising reliability standard across the entire Rust backend:

- **Compile-Time Prohibition (`#![deny(clippy::unwrap_used)]`)**: Both core library modules (`lib.rs`) and the application binary (`main.rs`) enforce strict lint rules banning the use of `.unwrap()` and `.expect()` in production code. Any introduction of panic-prone assertions is caught and rejected at compile time.
- **Fallible Error Propagation**: All system mutex locks, SQLite table evaluations, I/O streams, and child process pipes utilize pattern matching (`match`, `if let`, or `map_err(...)?`) returning descriptive `OpenForensicError` variants.
- **Strict Code Quality & Clippy Compliance**: Core acquisition, hashing, reporting, and plugin engines are maintained with zero compiler or clippy lint warnings (`-D warnings`), leveraging modern Rust idioms such as `&& let` chains and static zero-fill buffers for optimal memory efficiency.
- **Graceful Degradation**: When interacting with unreliable external sources (e.g., disconnected SIEM endpoints, missing third-party memory tools, or locked OS handles), the engine captures the failure, logs a timestamped event to the progress stream, and continues acquisition without terminating the application.

### 🛡️ Real-Time SIEM & SOC Integration

OpenForensic bridges the gap between field disk imaging and Security Operations Center (SOC) incident response. During Rapid System Triage and live acquisitions, forensic findings are converted into timestamped, structured JSON records and streamed in real-time to enterprise SIEM platforms:

- **Splunk HTTP Event Collector (HEC)**: Emits structured events over HTTPS POST authenticated via HEC bearer tokens (`Authorization: Splunk <token>`). Automatically indexes running processes, network connections, browser visits, and OS event logs.
- **Wazuh Agent Socket / Syslog**: Formats forensic records into Wazuh JSON lines and streams them directly over TCP/UDP sockets (default port 1514) or appends to local log queues monitored by the active Wazuh agent.
- **One-Click IR Triage**: Responders can enable automatic SIEM emission during acquisition, instantly enriching enterprise SIEM dashboards with field IOCs without delaying physical data collection.
- **Zero-Configuration Leakage**: To protect against shipping internal lab URLs or hostnames in compiled binaries, SIEM endpoints default cleanly to empty strings. Whenever `--siem-export` is activated in CLI mode, supplying a target `--siem-endpoint` is strictly validated and required by clap (`required_if_eq("siem_export", "true")`).

### 💻 Headless CLI & Automation Mode

OpenForensic includes a native command-line interface powered by `clap`, allowing investigators and automated SOAR pipelines to execute the forensic engine without a GUI or display server (ideal for AWS EC2 cloud triage or remote IR SSH sessions):

```bash
# Enumerate detected physical block devices
openforensic --cli list-devices

# Perform headless E01 physical imaging with zstd compression and SHA-256 hashing
openforensic --cli acquire --source \\.\PhysicalDrive0 --dest D:\evidence\disk.e01 --format e01 --compression zstd --hashes md5,sha256

# Run rapid live triage with real-time Splunk HEC SIEM streaming (requires Analysis Mode)
openforensic --cli --mode analysis triage --dest C:\triage_output --siem-export --siem-type splunk_hec --siem-endpoint https://splunk.example.com:8088 --siem-token <token>

# Analyze acquired RAM dump via native Rust Volatility engine with AbuseIPDB threat intel enrichment (requires Analysis Mode)
openforensic --cli --mode analysis ram --dump memory.raw --profile windows.pslist.PsList --ioc-enrich
```

### 🔑 Keyed Cryptographic Integrity Manifests

To ensure court-admissible chain-of-custody without heavy asymmetric OpenPGP dependency bloat, OpenForensic integrates a lightweight **Keyed Integrity Manifest** engine:

- **Keyed HMAC Sealing**: Generate deterministic SHA-256 / SHA-512 integrity proofs directly within the dashboard using investigator case numbers and security salts.
- **Tamper-Evident Signatures**: Automatically generate detached integrity manifests (`.manifest` / `.sig`) containing case metadata, device geometry, and image digests.
- **1-Click Verification**: Validate manifests against evidence payloads to confirm zero tampering occurred after acquisition.

### 🧩 Extensible Native Plugin Architecture

OpenForensic operates as a modular digital forensics platform. Third-party modules integrate into the acquisition pipeline through standardized lifecycle hooks defined in `OpenForensicPlugin`:

- **`pre_acquisition`**: Called before imaging starts to inspect case metadata, volume geometry, and initialize resources.
- **`on_block`**: Invoked for every data chunk read from disk. Chunks are dispatched across non-blocking multi-producer channels to background worker threads, guaranteeing zero degradation to disk reading throughput.
- **`post_acquisition`**: Executed upon acquisition completion. Returns custom metrics, hashes, or analytical outputs that are embedded directly into official PDF, HTML, and text case reports.

#### Static Native Dispatch Security

- **Native Shared Libraries (`.so` / `.dll` / `.dylib`)**: High-performance compiled extensions loaded dynamically via FFI symbols (`_openforensic_plugin_create`) for OS-level operations with static dispatch for maximum execution speed and minimal binary footprint.

### 🛡️ Hardware & Software Write-Blocking

OpenForensic enforces read-only access at the OS kernel boundary:

- **Windows**: Opens block devices via `CreateFileW` requesting strictly `GENERIC_READ` with shared access attributes, preventing any write modification by the operating system or application.
- **Linux**: Opens block devices using `O_RDONLY | O_DIRECT` to bypass browser and OS page caches, and queries `BLKROSET` ioctls to verify read-only device enforcement.
- **macOS**: Communicates directly with raw disk nodes (`/dev/rdiskX`) to achieve unbuffered, read-only hardware speed.

---

## 💻 System Requirements & Supported Platforms

| Platform       | Supported Versions                  | Required Privileges             | Special Notes                                                                                   |
| :------------- | :---------------------------------- | :------------------------------ | :---------------------------------------------------------------------------------------------- |
| **🪟 Windows** | Windows 10, Windows 11 (64-bit)     | **Administrator (UAC Uplevel)** | Bundles `winpmem_mini_x64` for RAM capture; requires VSS privileges for locked file extraction. |
| **🐧 Linux**   | Ubuntu 20.04+, Debian, Arch, Fedora | **Root (`sudo` / `su`)**        | Requires raw block device access (`/dev/sdX`, `/dev/nvme0n1`). Bundles **LiME kernel module** (`lime.ko`) for symmetric kernel RAM capture; also supports `avml` & `/proc/kcore`. |
| **🍎 macOS**   | macOS 11.0 Big Sur or newer         | **Root + Full Disk Access**     | Terminal / app must be granted _Full Disk Access_ under System Settings ➔ Privacy & Security.   |

### Minimum Hardware

- **CPU**: 4+ Cores recommended for parallel SHA-512 hashing and YARA rule compilation.
- **RAM**: 4 GB minimum (8 GB+ recommended when analyzing multi-gigabyte RAM dumps with the native Rust Volatility engine).
- **Storage**: NVMe / SSD destination storage recommended to prevent write-bottlenecks during multi-algorithm hashing.

---

## 🚀 Quick Start & Installation

Because OpenForensic interacts directly with raw block storage devices and kernel memory, it **must be executed with elevated administrative privileges**.

### 1. Running on Windows

1. Download or compile the `openforensic.exe` binary.
2. Launch the application. The embedded UAC manifest will automatically prompt for **Administrator elevation**.
3. Click **Yes** on the UAC dialog.
4. Select your target device from the **Source Selector** sidebar and choose your investigation tab.

### 2. Running on Linux

Execute the binary via terminal using `sudo`:

```bash
sudo ./target/release/openforensic
```

### 3. Running on macOS

1. Open **System Settings** ➔ **Privacy & Security** ➔ **Full Disk Access**.
2. Enable access for your Terminal or target IDE.
3. Launch from terminal with superuser privileges:

```bash
sudo ./target/release/openforensic
```

---

## 🖥️ Dashboard Overview & Workflow

1. **📁 Case Management Tab** *(Default Landing Tab)*:
   - The application opens directly to Case Management. Initialize native **Unified Case Folder Architecture** containers (`Cache/`, `Export/`, `Log/`, `ModuleOutput/`, `Reports/`, `.ofc` manifest, and portable `openforensic.db`) with native OS directory browsing.
   - Inspect live item counts and storage consumption (MB) across case subfolders via the interactive **Case Architecture Visualizer**.
   - Click **Set Active Workspace** to automatically pre-populate acquisition, triage, and timeline export destinations directly to the active case folder.
   - Review historical acquisition jobs, verify stored SHA-256/SHA-512 hashes, and export self-contained HTML evidence reports. See the **[Unified Case Architecture Guide](docs/unified-case-architecture.md)** for details.

2. **📂 Disk Imaging Tab**:
   - Select a physical block device or logical directory.
   - Choose destination format (`Raw .dd`, `E01`, or `AFF`).
   - Enable sector compression, sparse zero-block skipping, and select verification hash algorithms.
   - Attach optional YARA rulesets (`.yar`) for real-time IOC alerting during the imaging process.

3. **⚡ System Triage Tab**:
   - One-click execution of rapid system collection: running processes, network sockets, browser histories, and event logs.
   - *(Note: The interactive **Triage SQL Workbench** is gated behind **Analysis Mode**; click "Switch to Analysis Mode" in the top bar to unlock).*

4. **🔴 Live Acquisition Tab**:
   - Acquire live system volume shadow copies without rebooting.
   - Check **Capture Physical Memory (RAM)** to dump volatile system memory using auto-detected or custom tools (`winpmem`, `avml`).

5. **⏱️ Timeline Generator Tab** *(Requires Analysis Mode)*:
   - Input any acquired raw disk image (`.dd`).
   - Specify output destination to generate a unified, chronological timeline (`timeline.csv` / `timeline.json`) of file system modifications and journal entries.
   - *Gated behind **Analysis Mode** to protect live acquisition sessions from evidence modification.*

6. **🧠 RAM Analysis Tab** *(Requires Analysis Mode)*:
   - Select an acquired memory dump (`.raw`, `.vmem`, `.dmp`) and optionally specify a custom Volatility engine executable path (uses the built-in native Rust engine by default).
   - Select an analysis profile (e.g., `windows.pslist.PsList`, `windows.netstat.NetStat`, `windows.malfind.Malfind`).
   - Enable **AbuseIPDB** and **VirusTotal** API enrichment to automatically flag malicious remote IP connections and suspicious process hashes in real time.
   - *Gated behind **Analysis Mode** to protect live acquisition sessions from evidence modification.*

---

## 🛠️ Building & Developing from Source

We use [**mise**](https://mise.jdx.dev/) to manage reproducible toolchains (Rust 1.85+, Node.js).

### Step 1: Clone & Install Dependencies

```bash
git clone https://github.com/rootwithkhandal/OpenForensic.git
cd OpenForensic
npm install
```

### Step 2: Clean Stale Cache & Artifacts (Recommended)

When switching branches or upgrading Tauri dependencies, clean stale build artifacts:

```bash
mise run clean
# Or manually:
cargo clean --manifest-path src-tauri/Cargo.toml
```

### Step 3: Verify Toolchain & Check Build

```bash
mise run check
# Or manually:
cargo check --manifest-path src-tauri/Cargo.toml
```

### Step 4: Run Application in Development Mode

To launch the OpenForensic desktop window with live reloading:

```bash
mise run run
# Or with npm:
npm run tauri dev
```

_(On Windows, run your terminal as Administrator if testing raw physical disk scanning)._

### Step 5: Compile Production Release Binary

To build the optimized release executable:

```bash
mise run build
# Or with npm:
npm run tauri build
```

The compiled standalone binary will be output to `src-tauri/target/release/openforensic.exe` (or `./target/release/openforensic` on Linux/macOS).

---

## 📚 Documentation & Reference Guides

- [**Unified Forensic Case Folder Architecture Guide**](docs/unified-case-architecture.md): Technical overview of our standardized case directories (`Cache/`, `Export/`, `Log/`, `ModuleOutput/`, `Reports/`), `.ofc` manifest specifications, and zero-import portable SQLite archiving.
- [**Native Rust Volatility Engine Architecture & Reference**](docs/volatility-rust-engine.md): Complete technical guide on our custom native Rust memory analysis engine (`volatility/`), supported profiles, and zero-dependency memory forensics.
- [**Ponytail Ultra Debt Pruning & System Architecture**](docs/architecture-pruning-ponytail.md): Deep dive into our streamlined architecture, static native plugins, local disk log shippers, and weak-hash elimination.
- [**OpenForensic Analysis Suite & Dynamic Mode-Gating Guide**](docs/enabling-analysis-suite-features.md): Comprehensive guide on the forensic boundary between Capture Mode and Analysis Mode, feature toggling, and the Zero-Panic reliability architecture.
- [**OpenForensic Hash System Guide**](docs/hashes_guides.md): Deep dive into our NIST cryptographic verification architecture, container hashes (E01/AFF), and deterministic SHA-256 seal mapping.
- [**Memory Capture & Volatile Triage Guide**](docs/memory-dump.md): Overview of live physical RAM acquisition, kernel drivers (WinPmem, LiME), and explanations for memory-mapped hardware offset sizing.
- [**PGP & Keyed Integrity Manifests Guide**](docs/pgp_manifests.md): Comprehensive guide on generating keyed integrity seals, signing evidence containers, and verifying chain of custody.
- [**Security Policy**](SECURITY.md): Vulnerability reporting guidelines and scope definitions.

---

## ⚠️ Known Forensic Limitations & Lab Boundaries

In digital forensics, transparency regarding tool capabilities and architectural boundaries is critical for court admissibility. Investigators relying on OpenForensic must note the following operational boundaries:

1. **Memory Forensics Offset Tables (`volatility/`)**:
   Our native Rust memory analysis engine currently employs static pool-tag scanning (e.g., searching kernel pool allocations for `"Proc"` tags and testing known `EPROCESS` structure offsets per Windows NT build). While fast and zero-dependency, it does not currently download or parse dynamic PDB/Symbol files from Microsoft Symbol Server (`msdl.microsoft.com`). Consequently, on untested or highly customized/hotfixed Windows kernel builds, process parsing may require fallback to manual offset overriding or external Symbol resolution.
2. **Access Control / Lab Multi-Tenancy**:
   OpenForensic is designed primarily as a single-investigator workstation application (`--mode capture` or `--mode analysis`). While case management separates files into isolated case directories (`Case/`), the application relies on OS-level user permissions rather than internal Role-Based Access Control (RBAC). For multi-examiner shared lab deployments, access must be governed via OS domain permissions and filesystem ACLs.
3. **Advanced Cryptographic Hardware Sealing**:
   Our HMAC-SHA256 integrity manifests (`openforensic_hmac`) securely seal evidence containers using 256-bit secret keys stored in user workspace directories (`~/.openforensic/`). While mathematically tamper-evident, hardware-backed key storage (e.g., YubiKey / PKCS#11 / TPM 2.0 enclave integration) is currently on the roadmap for future releases.

---

## ⚖️ Legal & Forensic Disclaimer

_OpenForensic is developed strictly for lawful digital forensics investigations, incident response, data recovery, and academic research. Accessing raw physical disks, acquiring volatile system memory, or imaging computer media without explicit legal authorization or device ownership may violate local, state, or international computer privacy and crime laws. The developers assume no liability for misuse._
