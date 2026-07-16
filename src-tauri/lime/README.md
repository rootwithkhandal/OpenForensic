# LiME (Linux Memory Extractor) Bundling & Cross-Platform Symmetry

OpenForensic mirrors the Windows memory acquisition architecture (WinPmem kernel driver bundling) on Linux by bundling prebuilt **LiME kernel modules (`.ko`)**.

## Why LiME over `/proc/kcore` or user-space scrapers?
On modern Linux kernels (5.10+, 6.x), `/proc/kcore` has significant reliability limitations due to kernel hardening, KASLR, strict memory boundaries, and unreadable kernel page tables (PTEs) that cause user-space read operations to fail or truncate prematurely. Furthermore, `/proc/kcore` represents virtual kernel memory rather than a direct physical RAM stream (`/dev/mem` is locked down by `CONFIG_STRICT_DEVMEM`).

By loading a compiled kernel module (`lime.ko`) directly into kernel space via `insmod`, OpenForensic achieves bit-for-bit physical RAM acquisition that is identical in reliability and forensic fidelity to WinPmem on Windows.

## Module Bundling Architecture
In `src-tauri/lime/`, OpenForensic ships prebuilt LiME kernel modules:
- `lime-x86_64.ko` — 64-bit AMD/Intel architecture module
- `lime-aarch64.ko` — ARM64 architecture module
- `lime.ko` — Generic symlink / fallback module

During build time, Tauri's bundler packages these resources into the distribution payload (`tauri.conf.json` -> `"lime/*"`).

## Automatic Lifecycle & Execution in OpenForensic
When an investigator initiates RAM acquisition on Linux without specifying a custom tool path:
1. **Resolution**: `find_memory_tool` prioritizes bundled LiME kernel modules (`lime/lime.ko`, `lime/lime-x86_64.ko`) over user-space tools (`avml`) or `/proc/kcore`.
2. **Pre-clean**: Executes `rmmod lime` to ensure no orphaned LiME instances are holding kernel locks.
3. **Kernel Loading & Dumping**: Executes:
   ```bash
   insmod /path/to/lime.ko "path=/target/destination.raw format=raw"
   ```
   LiME executes within kernel ring 0, streaming raw RAM blocks directly to the specified destination path with zero user-space buffer overhead.
4. **Post-clean**: Immediately executes `rmmod lime` upon dump completion or failure to ensure zero trace or system instability remains on the target machine.
