# Native Rust Volatility Engine — Architecture & Reference Guide

## 📌 Overview

OpenForensic includes a proprietary, high-performance **native Rust memory forensics engine** located in the workspace `volatility/` directory. Developed from scratch to eliminate external runtime dependencies, this engine replaces traditional Python-based frameworks (such as Volatility 3) with a standalone, in-process memory analyzer capable of real-time streaming and high-speed triage.

By integrating memory analysis directly into the compiled OpenForensic binary, investigators gain instantaneous execution speeds without installing Python 3, managing virtual environments (`venv`), or dealing with broken package dependencies on field triage laptops or cloud server instances.

---

## ⚡ Why a Native Rust Memory Engine?

Traditional memory analysis frameworks rely heavily on Python and dynamic symbol interpretation, which introduces significant friction during live incident response:
1. **Zero External Dependencies**: Operates as a pure native binary executable or in-process library. No Python interpreters, pip modules, or system libraries are required.
2. **In-Process Real-Time Streaming**: Rather than spawning external subprocesses and scraping console standard output (`stdout`), the native engine streams structured process tables and log events over asynchronous Tokio MPSC channels directly to the UI dashboard and SIEM pipelines.
3. **Memory Safety & Concurrency**: Built with Rust's strict borrow checker and zero-cost abstractions, preventing buffer overflows, race conditions, and memory leaks when parsing multi-gigabyte memory dumps (`.raw`, `.vmem`, `.dmp`).
4. **Instant Startup**: Eliminates Python interpreter startup overhead and symbol table compilation delays, beginning memory scanning immediately upon invocation.

---

## 🧠 Supported Analysis Profiles & Plugins

The native engine supports standard forensic profiles across Windows, Linux, and macOS operating systems. Profiles can be specified in the UI dashboard or via the headless command-line interface (`--cli`):

| Profile Identifier | Operating System | Description & Analytical Capability |
| :--- | :--- | :--- |
| `windows.pslist.PsList` | Windows (x64 / x86) | Enumerates active, terminated, and unlinked processes by traversing kernel `EPROCESS` doubly linked lists and validating active process structures. |
| `windows.netstat.NetStat` | Windows (x64 / x86) | Scans kernel network pool tags and TCP/UDP endpoint structures to list open listening ports, established connections, and remote IP addresses. |
| `windows.cmdline.CmdLine` | Windows (x64 / x86) | Extracts process command-line arguments and environment variables by reading the Process Environment Block (`PEB`) in user-space memory. |
| `windows.filescan.FileScan` | Windows (x64 / x86) | Scans memory pools for open `FILE_OBJECT` structures, revealing accessed files, memory-mapped drives, and hidden OS handles. |
| `windows.malfind.Malfind` | Windows (x64 / x86) | Detects injected DLLs, hollowed processes, and hidden portable executable (`PE`) headers by inspecting Virtual Address Descriptor (`VAD`) memory protection flags (`PAGE_EXECUTE_READWRITE`). |
| `linux.pslist.PsList` | Linux (x64 / ARM64) | Enumerates running Linux kernel tasks by traversing `task_struct` linked lists. |
| `mac.pslist.PsList` | macOS (x64 / Apple Silicon) | Enumerates active Darwin kernel processes and execution contexts. |

---

## 💻 Headless CLI & Automated Workflow

The native engine is fully integrated into OpenForensic's headless command-line interface, enabling automated SOAR pipelines and remote SSH triage without a graphical display server:

```bash
# Analyze a raw memory dump for running Windows processes
openforensic --cli --mode analysis ram --dump /mnt/evidence/server_ram.raw --profile windows.pslist.PsList

# Scan for code injection and automatically enrich remote IPs via AbuseIPDB & VirusTotal
openforensic --cli --mode analysis ram --dump /mnt/evidence/server_ram.raw --profile windows.malfind.Malfind --ioc-enrich
```

> [!IMPORTANT]
> **Strict Mode-Gating**: Memory analysis actively parses complex kernel structures and produces forensic conclusions. To protect live data collection integrity, all memory analysis execution (both CLI and GUI) is strictly gated behind **Analysis Mode** (`--mode analysis`).

---

## 🛡️ Real-Time Threat Intelligence Enrichment

When running memory analysis profiles (such as `windows.netstat.NetStat` or `windows.malfind.Malfind`), OpenForensic can automatically enrich extracted network indicators and process artifacts:
- **AbuseIPDB Integration**: Validates remote IP addresses against global threat reputation databases, flagging known command-and-control (C2) nodes or botnet infrastructure.
- **VirusTotal Hash Verification**: Calculates cryptographic digests of suspicious memory sections or unlinked executables, querying VirusTotal detection matrices in real-time.

---

## 🧩 In-Process Programmatic API

For custom forensic tool developers building on top of the OpenForensic workspace, the native `volatility` crate exports a clean asynchronous Rust API:

```rust,no_run
use volatility::run_analysis;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    // Create an asynchronous channel for real-time log streaming
    let (tx, mut rx) = mpsc::channel(256);
    
    // Spawn background receiver to handle streaming process rows
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            println!("[VOLATILITY STREAM] {}", line);
        }
    });
    
    // Execute native in-process memory analysis
    run_analysis("evidence.raw", "windows.pslist.PsList", tx).await.unwrap();
}
```

---

## ⚖️ License & Ownership Note

The OpenForensic `volatility/` engine is a standalone, proprietary native Rust implementation developed independently by the copyright holder. It takes architectural inspiration from standard memory analysis concepts but shares zero source code, dependencies, or licensing restrictions with the Volatility Foundation's Python framework or GPL licenses.
