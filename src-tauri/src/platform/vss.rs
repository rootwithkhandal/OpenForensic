//! Volume Shadow Copy Service (VSS) integration for Windows.
//! Creates a frozen snapshot of a volume so we can image it consistently
//! while the system is running.

use crate::error::{OpenForensicError, Result};
use std::process::Command;

/// Represents an active VSS shadow copy snapshot.
#[derive(Debug, Clone)]
pub struct VssSnapshot {
    /// Shadow copy ID (GUID)
    pub shadow_id: String,
    /// Device path to the shadow copy, e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
    pub device_path: String,
    /// Volume that was snapshotted, e.g. C:
    #[allow(dead_code)]
    pub volume: String,
}

impl VssSnapshot {
    /// Create a new VSS shadow copy for the given volume (e.g. "C:").
    ///
    /// Uses WMI/vssadmin CLI as a robust fallback approach that works on both
    /// Windows Server and Client editions. The COM API (`IVssBackupComponents`)
    /// is complex and header-only in the SDK — the CLI approach is more reliable
    /// for a forensic tool that already requires admin privileges.
    pub fn create(volume: &str) -> Result<Self> {
        // Normalize volume to "X:\" format
        let vol = if volume.ends_with('\\') {
            volume.to_string()
        } else if volume.ends_with(':') {
            format!("{}\\", volume)
        } else {
            format!("{}:\\", volume)
        };

        // Use wmic shadowcopy call create to work on both Server and Client editions
        let wmic_output = Command::new("wmic")
            .args(["shadowcopy", "call", "create", &format!("Volume={}", vol)])
            .output();

        let mut shadow_id = None;
        if let Ok(out) = wmic_output
            && out.status.success()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            shadow_id = Self::parse_shadow_id_from_wmic(&stdout);
        }

        if shadow_id.is_none() {
            // Fallback to PowerShell using CIM (wmic is deprecated in Win 11 24H2+)
            let ps_cmd = format!("(Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{{Volume='{}'}}).ShadowID", vol);
            let ps_out = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_cmd])
                .output()
                .map_err(|e| OpenForensicError::VssError(format!("Failed to execute PowerShell VSS fallback: {}", e)))?;

            if ps_out.status.success() {
                let stdout = String::from_utf8_lossy(&ps_out.stdout);
                let id = stdout.trim();
                if !id.is_empty() {
                    shadow_id = Some(id.to_string());
                }
            } else {
                let stderr = String::from_utf8_lossy(&ps_out.stderr);
                return Err(OpenForensicError::VssError(format!("WMI and PowerShell VSS creation failed. PowerShell error: {}", stderr.trim())));
            }
        }

        let shadow_id = shadow_id.ok_or_else(|| OpenForensicError::VssError(
            "Could not parse ShadowID from VSS creation output".to_string()
        ))?;

        // Query the device path for this shadow copy
        let device_path = Self::query_device_path(&shadow_id)?;

        Ok(VssSnapshot {
            shadow_id,
            device_path,
            volume: vol,
        })
    }

    /// Parse the ShadowID GUID from wmic output.
    fn parse_shadow_id_from_wmic(output: &str) -> Option<String> {
        // Look for ShadowID = "{...}";
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.contains("ShadowID") {
                // Extract the GUID between quotes
                if let Some(start) = trimmed.find('"')
                    && let Some(end) = trimmed[start + 1..].find('"')
                {
                    return Some(trimmed[start + 1..start + 1 + end].to_string());
                }
                // Try braces format
                if let Some(start) = trimmed.find('{')
                    && let Some(end) = trimmed.find('}')
                {
                    return Some(trimmed[start..=end].to_string());
                }
            }
        }
        None
    }

    /// Query the device path for a given shadow copy ID using vssadmin.
    fn query_device_path(shadow_id: &str) -> Result<String> {
        let output = Command::new("vssadmin")
            .args(["list", "shadows"])
            .output()
            .map_err(|e| OpenForensicError::VssError(format!("Failed to execute vssadmin: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut current_id = String::new();
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Shadow Copy ID:") || trimmed.starts_with("Shadow copy ID:") {
                    current_id = trimmed
                        .split(':')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                } else if (trimmed.starts_with("Shadow Copy Volume Name:") || trimmed.starts_with("Shadow copy volume name:"))
                    && (current_id.eq_ignore_ascii_case(shadow_id) || current_id.contains(shadow_id))
                {
                    let vol_name = trimmed
                        .split(':')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    return Ok(vol_name);
                }
            }
        }

        // Fallback: construct the device path from the shadow ID pattern
        // Try querying via wmic for exact device object
        let wmic_out = Command::new("wmic")
            .args(["shadowcopy", "get", "DeviceObject,ID", "/format:list"])
            .output();

        if let Ok(out) = wmic_out
            && out.status.success()
        {
            let wmic_stdout = String::from_utf8_lossy(&out.stdout);
            let mut current_device = String::new();
            for line in wmic_stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("DeviceObject=") {
                    current_device = trimmed.strip_prefix("DeviceObject=").unwrap_or("").to_string();
                }
                if trimmed.starts_with("ID=") {
                    let id = trimmed.strip_prefix("ID=").unwrap_or("").trim();
                    if id == shadow_id && !current_device.is_empty() {
                        return Ok(current_device);
                    }
                }
            }
        }

        // Final fallback to PowerShell
        let ps_cmd = format!("(Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{}' }}).DeviceObject", shadow_id);
        let ps_out = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_cmd])
            .output()
            .map_err(|e| OpenForensicError::VssError(format!("Failed to run PowerShell Get-CimInstance: {}", e)))?;

        if ps_out.status.success() {
            let stdout = String::from_utf8_lossy(&ps_out.stdout);
            let device_object = stdout.trim();
            if !device_object.is_empty() {
                return Ok(device_object.to_string());
            }
        }

        Err(OpenForensicError::VssError(format!(
            "Could not find device path for shadow copy ID: {}",
            shadow_id
        )))
    }

    /// Delete this VSS shadow copy.
    pub fn delete(&self) -> Result<()> {
        let output = Command::new("vssadmin")
            .args(["delete", "shadows", &format!("/Shadow={}", self.shadow_id), "/Quiet"])
            .output()
            .map_err(|e| OpenForensicError::VssError(format!("Failed to delete shadow copy: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OpenForensicError::VssError(format!(
                "vssadmin delete shadows failed: {}",
                stderr.trim()
            )));
        }

        Ok(())
    }

    /// Get the device path for accessing files through this shadow copy.
    /// Files can be accessed at: device_path + "\" + relative_path
    /// e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
    #[allow(dead_code)]
    pub fn file_path(&self, relative_path: &str) -> String {
        let base = self.device_path.trim_end_matches('\\');
        let rel = relative_path.trim_start_matches('\\');
        format!("{}\\{}", base, rel)
    }
}
