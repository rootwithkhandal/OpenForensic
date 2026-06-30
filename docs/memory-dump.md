# Understanding Memory Dumps

This document outlines the standard process for capturing volatile system memory (RAM) for forensic analysis, and explains common questions regarding the resulting file size.

## The Process of Creating a Memory Dump

Capturing a memory dump is one of the most critical steps in live incident response, as it preserves volatile evidence such as running processes, unencrypted passwords, network connections, and injected malware that would be lost if the machine is powered off.

### Using Forgelens (Live Acquisition)

1. **Navigate to Live Acquisition**: In Forgelens, switch to the "Live Acquisition" tab.
2. **Select Capabilities**: Check the box for "Capture Physical Memory (RAM)".
3. **Choose the Tool**: Forgelens can leverage robust kernel-level drivers to read physical memory safely. On Windows, it integrates with tools like `winpmem` or `DumpIt`. On Linux, it often leverages `avml` or `/dev/crash`.
4. **Acquire**: Click "Start Live Acquisition." The tool will load a temporary kernel driver to bypass OS protections, read the physical address space, stream it into a container (often a raw `.raw`, `.img`, or `.mem` file), and automatically unload the driver.

### Using External Tools (e.g., FTK Imager, DumpIt)

If running a manual triage on a target system:

1. Run the forensic tool from an external, sanitized USB drive (to minimize footprint on the target disk).
2. Launch the memory capture module as an Administrator.
3. Save the resulting memory dump to the external USB drive, ensuring you do not overwrite volatile evidence on the target's primary disk.

> [!CAUTION]
> Memory acquisition must always be done **before** full disk imaging or any significant triage scripts are run, as the footprint of running heavy software will overwrite unallocated physical memory, destroying potential evidence.

---

## Why is a Raw Memory Dump Bigger Than the Installed RAM?

It is very common for examiners to notice that a system with exactly **16 GB** of installed RAM produces a raw memory dump file that is **16.5 GB to 17 GB** in size. This is not an error, but rather a direct result of how modern CPU architectures and Operating Systems map hardware.

### 1. Memory-Mapped I/O (MMIO) and Hardware Reservations

The CPU's physical address space does not just contain your RAM. It is shared with various hardware devices. The BIOS/UEFI and Operating System reserve specific physical memory addresses for communicating with hardware components like:

- PCIe devices and graphics cards (VRAM mapping)
- ACPI tables (Power management)
- Network Interface Cards (NICs)

Because these devices are mapped into the physical address space (Memory-Mapped I/O), they create "holes" in the contiguous RAM addressing. To accommodate these hardware ranges, the operating system shifts the actual physical RAM addresses *higher* up the address space, pushing the maximum physical address well beyond the installed 16 GB limit.

### 2. Contiguous File Offsets

When a forensic tool (like WinPmem) captures a "raw" memory dump, its goal is to ensure that a byte located at physical address `0x100000000` in the computer is located at file offset `0x100000000` in the resulting file.

To maintain these accurate offsets for analysis tools like Volatility:

- The tool starts reading from address `0x0` up to the **highest physical address** used by the OS.
- When it encounters a "hole" (a range reserved for hardware MMIO that cannot or should not be read), it pads the file with zeros for that specific range.
- Because the highest physical address has been pushed past the 16 GB boundary (due to the MMIO holes), the final file size becomes the highest physical address, resulting in a file size larger than the physical RAM modules themselves.

> [!NOTE]
> If space is a concern, modern forensic memory formats (like the `.aff4` format or Crash Dumps) compress or omit these zero-padded hardware holes, resulting in a file size that is closer to, or smaller than, the actual installed RAM size. Raw format (`.raw`, `.mem`), however, retains the exact address mapping, which causes the size inflation.
