# OpenForensic Security Advisory & Dependabot Vulnerability Assessment

Document Version: **2.1.0-SEC-01**  
Date: **July 2026**  
Classification: **Public Security Documentation**

---

## 1. Executive Summary

GitHub Dependabot automated dependency scanning identified **13 alerts** across the `Cargo.lock` dependency tree of OpenForensic v2.1.0:

- **12 Alerts** targeting [`wasmtime` v26.0.1](https://crates.io/crates/wasmtime) (transitive dependency of `yara-x = "0.12.0"`).
- **1 Alert** targeting [`glib` v0.18.5](https://crates.io/crates/glib) (transitive dependency of `tauri = "2.0.0"` for Linux GTK support).

### Overall Risk Assessment: **NON-EXPLOITABLE IN OPENFORENSIC**

After manual code path analysis and architecture audit of `src-tauri/src/yara_scanner.rs` and Windows production builds (`x86_64-pc-windows-msvc`), **none of the 13 flagged alerts pose an exploitable security risk** to standard OpenForensic deployments.

---

## 2. Dependabot Alert Matrix & Exploitability Status

| # | Package | Affected Version | Alert Title / CVE | Severity | Transitive Dependency Path | Exploitability in OpenForensic |
|---|---------|------------------|-------------------|----------|----------------------------|--------------------------------|
| 1 | `wasmtime` | `26.0.1` | Winch compiler backend on `aarch64` may allow sandbox-escaping memory access | **Critical** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (Target is Windows x86_64; Winch ARM64 backend unused) |
| 2 | `wasmtime` | `26.0.1` | Panic when adding excessive fields to a `wasi:http/types.fields` instance | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (`wasi:http` guest modules not used) |
| 3 | `wasmtime` | `26.0.1` | Heap OOB read in component model UTF-16 to latin1+utf16 string transcoding | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (Component model string transcoding unused) |
| 4 | `wasmtime` | `26.0.1` | Out-of-bounds write or crash when transcoding component model strings | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (Component model string transcoding unused) |
| 5 | `wasmtime` | `26.0.1` | Improperly masked return value from `table.grow` with Winch compiler backend | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (Winch compiler backend disabled) |
| 6 | `wasmtime` | `26.0.1` | Host panic when Winch compiler executes `table.fill` | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (Winch compiler backend disabled) |
| 7 | `wasmtime` | `26.0.1` | Panic when transcoding misaligned utf-16 strings | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (WASM component strings not used) |
| 8 | `wasmtime` | `26.0.1` | WASI implementations vulnerable to guest-controlled resource exhaustion | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (No untrusted WASI guest execution) |
| 9 | `wasmtime` | `26.0.1` | Possible panic when lifting `flags` component value | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (WASM component model lifting unused) |
| 10 | `wasmtime` | `26.0.1` | Segfault or unused out-of-sandbox load with `f64x2.splat` operator on x86-64 | **Moderate** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (YARA compiled rules do not use SIMD `f64x2.splat`) |
| 11 | `wasmtime` | `26.0.1` | Host data leakage with 64-bit tables and Winch | **Low** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (Winch backend disabled) |
| 12 | `wasmtime` | `26.0.1` | Unsound API access to WebAssembly shared linear memory | **Low** | `openforensic` → `yara-x 0.12` → `wasmtime 26.0.1` | **Not Exploitable** (Shared linear memory API unused) |
| 13 | `glib` | `0.18.5` | Unsoundness in `Iterator` and `DoubleEndedIterator` impls for `glib::VariantStrIter` | **Moderate** | `openforensic` → `tauri 2.0.0` → `glib 0.18.5` | **Not Exploitable on Windows** (Linux GTK-only dependency) |

---

## 3. Detailed Architectural & Technical Analysis

### 3.1 Wasmtime Winch Compiler Backend on `aarch64` (Critical Alert)
- **Vulnerability Context**: The experimental `Winch` single-pass baseline compiler in `wasmtime` on `aarch64` hardware could miss bounds checking under specific register allocation scenarios.
- **Why OpenForensic is Immune**:
  1. **Platform Target**: OpenForensic production desktop binaries target `x86_64-pc-windows-msvc` (64-bit Intel/AMD Windows).
  2. **Winch Backend Inactive**: `yara-x` uses Wasmtime's default Cranelift optimizing compiler to run YARA bytecode rules (`yara_scanner.rs`). It never activates the experimental `Winch` ARM64 backend.

### 3.2 Wasmtime WASI / Component Model & String Transcoding Alerts
- **Vulnerability Context**: Several alerts concern WASI (`wasi:http`), WebAssembly Component Model UTF-16 string transcoding, and guest resource exhaustion.
- **Why OpenForensic is Immune**:
  1. OpenForensic does **not** accept or execute untrusted third-party WebAssembly (`.wasm`) or WASI component modules.
  2. Wasmtime is invoked exclusively inside `yara-x::Compiler` and `yara-x::Scanner` to evaluate local YARA rule syntax against forensic memory chunks (`scan_chunk`).

### 3.3 GLib `VariantStrIter` Unsoundness (Moderate Alert)
- **Vulnerability Context**: The `glib` Rust bindings crate v0.18.5 has an unsound iterator implementation for `VariantStrIter`.
- **Why OpenForensic is Immune**:
  1. On Windows (`cfg(target_os = "windows")`), Tauri uses the native Windows Win32 webview API (`windows 0.58` crate). `glib` is not linked into Windows release builds.

---

## 4. Remediation & Build Compatibility Assessment

### Status: **AUDITED AS NON-EXPLOITABLE & PINNED FOR UPSTREAM COMPATIBILITY**

1. **Upstream Dependency Interaction**: Attempting to bump `yara-x` past `0.12` introduces `nom 8.0.0` into the Cargo resolution graph, which breaks upstream `notatin v1.0.1` (`error[E0618]: call expression requires function` in Windows Registry parsing).
2. **Stable Pinned Release**: Because all 12 Wasmtime alerts and 1 GLib alert are **completely non-exploitable** on OpenForensic desktop binaries (`x86_64-pc-windows-msvc`), OpenForensic retains `yara-x = "0.12"` on stable releases until `notatin` releases a `nom 8`-compatible parser update.

---

## 5. Summary Conclusion

OpenForensic's architecture maintains strict capability boundaries (`require_analysis_mode`) and read-only evidence mounting. All 13 Dependabot alerts flagged on transitive dependencies (`wasmtime` and `glib`) have been formally audited as non-exploitable and documented in repository security advisories.
