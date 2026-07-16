# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in OpenForensic, please report it responsibly:

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. **Email** your report to the repository maintainer with the subject line `[SECURITY] OpenForensic Vulnerability Report`.
3. Include a detailed description of the vulnerability, steps to reproduce, and potential impact.
4. You can expect an initial acknowledgement within **72 hours** of your report.
5. We aim to provide a fix or mitigation within **14 days** for critical vulnerabilities.

## Scope

The following are in scope for security reports:

- Bypass of write-blocking mechanisms during forensic acquisition
- Unauthorized access to raw disk devices or physical memory
- Tampering with forensic hash integrity verification
- Bypass of Capture Mode vs. Analysis Mode capability boundaries (`require_analysis_mode`)
- SQLite injection in case management or triage databases
- Arbitrary code execution via YARA rule loading
- Path traversal in file acquisition or report generation

## Out of Scope

- Vulnerabilities in third-party tools (e.g., WinPmem, avml, Volatility)
- Issues requiring physical access to the examiner's workstation
- Social engineering attacks

## Automated Dependency Scan Assessment (Dependabot)

GitHub Dependabot alerts flagged on transitive lockfile dependencies (`Cargo.lock`) have been formally audited:
- **`wasmtime` (v26.0.1)**: Transitive dependency of `yara-x`. Flagged alerts (including the experimental ARM64 `Winch` backend and WASI component model string transcoding) are **Not Exploitable** in OpenForensic desktop deployments (`x86_64-pc-windows-msvc`).
- **`glib` (v0.18.5)**: Transitive Linux GTK dependency of `tauri`. **Not Exploitable** on Windows builds.

For the complete technical exploitability matrix and remediation commands, see [`docs/resources/dependabot-security-assessment.md`](file:///d:/projects/private/Openforensic/docs/resources/dependabot-security-assessment.md).
