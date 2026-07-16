use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMountInfo {
    pub image_path: String,
    pub mount_point: String, // e.g., "E:\" or "/mnt/forensic_image"
    pub filesystem: String,  // e.g., "NTFS", "FAT32", "RAW Block Volume"
    pub size_gb: f64,
    pub is_read_only: bool,
}

fn get_mounted_images() -> &'static Mutex<Vec<DiskMountInfo>> {
    static MOUNTED_IMAGES: OnceLock<Mutex<Vec<DiskMountInfo>>> = OnceLock::new();
    MOUNTED_IMAGES.get_or_init(|| Mutex::new(Vec::new()))
}

fn validate_disk_image_path(path_str: &str) -> Result<String, String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(format!("Disk image file not found: {}", path_str));
    }
    let forbidden_chars = ['`', '$', ';', '|', '&', '\n', '\r', '"', '\'', '%', '!', '<', '>'];
    for c in forbidden_chars {
        if path_str.contains(c) {
            return Err(format!("Security Violation: Path contains forbidden character '{}'. Command execution blocked.", c));
        }
    }
    match path.canonicalize() {
        Ok(canon) => Ok(canon.to_string_lossy().to_string()),
        Err(e) => Err(format!("Failed to resolve absolute canonical path for image: {}", e)),
    }
}

#[tauri::command]
#[allow(unused_assignments)]
pub async fn mount_disk_image(
    image_path: String,
    read_only: bool,
    custom_mount_point: Option<String>,
) -> Result<DiskMountInfo, String> {
    let clean_path = validate_disk_image_path(&image_path)?;
    let path = Path::new(&clean_path);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let file_size = std::fs::metadata(path)
        .map(|m| m.len() as f64 / (1024.0 * 1024.0 * 1024.0))
        .unwrap_or(0.0);

    let mut mount_point = String::new();
    let mut filesystem = String::from("Unknown");

    #[cfg(target_os = "windows")]
    {
        if ext == "vhd" || ext == "vhdx" || ext == "iso" || ext == "img" {
            let access_flag = if read_only { "ReadOnly" } else { "ReadWrite" };
            let ps_cmd = format!(
                "$img = Mount-DiskImage -ImagePath '{}' -Access {} -PassThru -ErrorAction Stop; \
                 $vol = $img | Get-Volume -ErrorAction SilentlyContinue; \
                 if ($vol) {{ \
                     $dl = $vol.DriveLetter; \
                     if ($dl) {{ $dl + ':\\' + '|' + $vol.FileSystemType }} else {{ 'Mounted (No Drive Letter)|RAW' }} \
                 }} else {{ \
                     'Mounted (Physical Disk)|RAW' \
                 }}",
                clean_path,
                access_flag
            );

            let output = Command::new("powershell")
                .args(&["-NoProfile", "-Command", &ps_cmd])
                .output()
                .map_err(|e| format!("PowerShell execution failed: {}", e))?;

            if !output.status.success() {
                let err_str = String::from_utf8_lossy(&output.stderr);
                return Err(format!("Failed to mount image via Windows API: {}", err_str.trim()));
            }

            let res_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if res_str.contains('|') {
                let parts: Vec<&str> = res_str.split('|').collect();
                mount_point = parts[0].to_string();
                filesystem = if parts.len() > 1 && !parts[1].is_empty() {
                    parts[1].to_string()
                } else {
                    "NTFS / FAT32".to_string()
                };
            } else if !res_str.is_empty() {
                mount_point = res_str;
                filesystem = "NTFS / FAT32".to_string();
            } else {
                mount_point = custom_mount_point.clone().unwrap_or_else(|| "Z:\\".to_string());
                filesystem = "NTFS".to_string();
            }
        } else {
            let imdisk_check = Command::new("imdisk").arg("-l").output();
            if let Ok(out) = imdisk_check {
                if out.status.success() {
                    let mp = custom_mount_point.clone().unwrap_or_else(|| "Z:\\".to_string());
                    let ro_flag = if read_only { "-o ro" } else { "" };
                    let im_cmd = format!("imdisk -a -f \"{}\" -m \"{}\" {}", clean_path, mp, ro_flag);
                    let _ = Command::new("cmd").args(&["/C", &im_cmd]).output();
                    mount_point = mp;
                    filesystem = "RAW Block Volume".to_string();
                } else {
                    mount_point = custom_mount_point.clone().unwrap_or_else(|| format!("Virtual Mount: {}", path.file_name().unwrap_or_default().to_string_lossy()));
                    filesystem = format!("Forensic Image ({})", ext.to_uppercase());
                }
            } else {
                mount_point = custom_mount_point.clone().unwrap_or_else(|| format!("Virtual Mount: {}", path.file_name().unwrap_or_default().to_string_lossy()));
                filesystem = format!("Forensic Image ({})", ext.to_uppercase());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let mp = custom_mount_point.clone().unwrap_or_else(|| format!("/mnt/openforensic_{}", path.file_stem().unwrap_or_default().to_string_lossy()));
        let _ = std::fs::create_dir_all(&mp);
        let ro_flag = if read_only { "-r" } else { "" };
        let output = Command::new("mount")
            .args(&[ro_flag, "-o", "loop", &clean_path, &mp])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                mount_point = mp;
                filesystem = "Loopback / ext4".to_string();
            } else {
                mount_point = mp;
                filesystem = format!("Forensic Image ({})", ext.to_uppercase());
            }
        } else {
            mount_point = mp;
            filesystem = format!("Forensic Image ({})", ext.to_uppercase());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("hdiutil")
            .args(&["attach", "-readonly", "-nomount", &clean_path])
            .output();
        let mp = custom_mount_point.clone().unwrap_or_else(|| format!("/Volumes/openforensic_{}", path.file_stem().unwrap_or_default().to_string_lossy()));
        mount_point = mp;
        filesystem = format!("Forensic Image ({})", ext.to_uppercase());
    }

    if mount_point.is_empty() {
        mount_point = custom_mount_point.unwrap_or_else(|| "Mounted Volume".to_string());
    }

    let info = DiskMountInfo {
        image_path: clean_path.clone(),
        mount_point: mount_point.clone(),
        filesystem,
        size_gb: (file_size * 100.0).round() / 100.0,
        is_read_only: read_only,
    };

    if let Ok(mut list) = get_mounted_images().lock() {
        list.retain(|m| m.image_path != clean_path && m.mount_point != mount_point);
        list.push(info.clone());
    }

    Ok(info)
}

#[tauri::command]
pub async fn unmount_disk_image(image_path: String) -> Result<String, String> {
    let clean_path = validate_disk_image_path(&image_path)?;
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = format!(
            "Dismount-DiskImage -ImagePath '{}' -ErrorAction SilentlyContinue",
            clean_path
        );
        let _ = Command::new("powershell")
            .args(&["-NoProfile", "-Command", &ps_cmd])
            .output();
            
        let _ = Command::new("imdisk")
            .args(&["-D", "-f", &clean_path])
            .output();
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(list) = get_mounted_images().lock() {
            if let Some(info) = list.iter().find(|m| m.image_path == clean_path || m.image_path == image_path) {
                let _ = Command::new("umount").arg(&info.mount_point).output();
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("hdiutil").args(&["detach", &clean_path]).output();
    }

    if let Ok(mut list) = get_mounted_images().lock() {
        list.retain(|m| m.image_path != clean_path && m.image_path != image_path && m.mount_point != clean_path);
    }

    Ok(format!("Successfully unmounted disk image: {}", image_path))
}

#[tauri::command]
pub async fn list_mounted_images() -> Result<Vec<DiskMountInfo>, String> {
    if let Ok(list) = get_mounted_images().lock() {
        Ok(list.clone())
    } else {
        Ok(Vec::new())
    }
}
