# 📁 Unified Forensic Case Folder Architecture

OpenForensic implements a native, self-contained **Unified Forensic Case Folder Architecture** inspired by industry standard suites like Autopsy and EnCase. This architecture guarantees that **every export, disk image, triage database, timeline, module output, and report for a single forensic case resides in one standardized, central folder location** on disk.

By eliminating external database import requirements and scattered output files, OpenForensic ensures total case portability, seamless chain-of-custody tracking, and zero-configuration archiving.

---

## 🏛️ Directory Hierarchy & Standard Subfolders

When an investigator initializes a new case container via the **Case Management** tab or API, OpenForensic automatically generates a deterministic folder structure at the specified root path:

```
📁 <CaseRoot>/<CaseNumber>/
├── 📁 Cache/           # Temporary indexing, YARA compilation artifacts, and scratch space
├── 📁 Export/          # Raw physical/logical disk extractions, carved files & timeline CSVs
├── 📁 Log/             # Chain-of-custody acquisition logs, audit trails & hash verification records
├── 📁 ModuleOutput/    # Live Triage SQLite databases (triage_results.db) & RAM analysis outputs
├── 📁 Reports/         # Court-admissible HTML, JSON, and PDF forensic reports
├── 📄 <CaseName>.ofc   # JSON-based forensic case container manifest (Specification v2.0.2)
└── 🗄️ openforensic.db  # Self-contained per-case portable SQLite database
```

### Purpose of Each Container Directory

| Directory / File | Description |
| :--- | :--- |
| `📁 Cache/` | Holds ephemeral intermediate files during disk indexing, YARA rule compilation, and streaming compression. Can be safely pruned without affecting evidence integrity. |
| `📁 Export/` | The default destination for acquired forensic disk images (`.dd`, `.e01`), carved file evidence, and chronological supertimelines (`timeline.csv`). |
| `📁 Log/` | Contains cryptographic verification logs, acquisition timestamps, and execution traces required for legal admissibility. |
| `📁 ModuleOutput/` | Dedicated repository for analytical engine outputs, including automated Live Triage databases (`triage_results.db`), Volatility process listings, and network connection captures. |
| `📁 Reports/` | Automatically stores immutable copies of HTML and PDF case reports whenever they are generated from the dashboard. |
| `📄 <CaseName>.ofc` | The master JSON manifest describing case metadata, lead examiner details, creation timestamps, and subfolder schemas. |
| `🗄️ openforensic.db` | A self-contained SQLite database that mirrors all chain-of-custody evidence records, acquisition logs, and audit entries for this specific case. |

---

## 🔄 Dual-Database Syncing & Portability

OpenForensic maintains dual-database synchronization to provide both centralized indexing and standalone case portability:

1. **Global Workspace Database (`cases.db`)**: Used by the main OpenForensic application ribbon to quickly index and display all known cases across multiple disks without scanning directories.
2. **Per-Case Portable Database (`openforensic.db`)**: Stored directly inside the `<CaseRoot>/<CaseNumber>/` folder. Whenever an acquisition job completes or an evidence item is tagged, OpenForensic records the transaction simultaneously to both databases.

### Zero-Import Archiving
Because `openforensic.db` and `<CaseName>.ofc` reside inside the case root folder, an entire forensic case can be copied to an encrypted USB drive, network share, or cold storage archive. Another investigator can open the folder on a different workstation without running complex database import scripts or re-indexing files.

---

## 🖥️ Interactive Case Architecture Control Center

The **Case Management** tab is the **default landing tab** when OpenForensic launches, reflecting a case-first forensic workflow. Investigators create or select a case container before beginning any acquisition, ensuring all outputs are routed to the correct directory from the start.

- **New Case Folder Initialization**: Click **"+ New Case Folder"** to open a modal with native OS directory browsing (`browse_folder`). Enter the Case Number, Case Name, and Examiner Name to create the standardized folder tree instantly.
- **Live Storage & Item Metrics**: Selecting a case card displays a visual directory tree showing real-time item counts and storage consumption (in Megabytes) for each subfolder.
- **Active Workspace Pre-population**: Clicking **"Set Active Workspace"** binds the case number to the active application header. When navigating to **Disk Acquisition**, **Live Triage**, or **Timeline Generator**, output path fields are automatically pre-populated to the active case's corresponding subdirectories (`Export/` or `ModuleOutput/`).

---

## 🛡️ Integration with Capture vs. Analysis Mode

In accordance with OpenForensic's defense-in-depth security model:
- **Capture Mode**: Write operations are strictly limited to creating new case containers, writing acquisition disk images to `Export/`, and recording chain-of-custody logs to `Log/` and `openforensic.db`.
- **Analysis Mode**: Required for running post-acquisition analytics such as Volatility RAM dumps, Triage SQL extractions, and timeline generation. Results are routed cleanly into `ModuleOutput/` and `Export/` without modifying original evidence files.

---

## 🔗 Related Documentation
- [**Enabling Analysis Suite Features**](enabling-analysis-suite-features.md): How mode guards govern analytical outputs.
- [**PGP & Keyed Integrity Manifests**](pgp_manifests.md): Cryptographic sealing of exported case reports and images.
- [**Memory Dump & Analysis**](memory-dump.md): Routing Volatility engine outputs into case directories.
