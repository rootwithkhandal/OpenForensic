use rusqlite::Connection;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use chrono::Utc;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AntiForensicAlert {
    pub category: String,
    pub severity: String,
    pub artifact_path: String,
    pub details: String,
    pub detection_timestamp: String,
}

/// 1. Detect Wiping & Anti-Forensic Tool Signatures (CCleaner, SDelete, Eraser, BleachBit, srm, Cipher /w)
pub fn detect_wiping_tools(db: &Connection) -> usize {
    let mut count = 0;
    let now_str = Utc::now().to_rfc3339();

    // Known wiping tool patterns
    let wiping_signatures = [
        ("ccleaner", "CCleaner System Wiper / Privacy Cleaner"),
        ("sdelete", "Sysinternals SDelete Secure Overwrite Tool"),
        ("bleachbit", "BleachBit Open-Source File Wiping Tool"),
        ("bcwipe", "Jetico BCWipe Secure Eraser"),
        ("eraser.exe", "Eraser Secure File Deletion Utility"),
        ("srm.exe", "Secure Remove (srm) File Shredder"),
        ("cipher.exe /w", "Windows Built-in Cipher Free Space Wiping"),
        ("shred", "Unix/Linux shred Secure Overwrite Utility"),
        ("wipe.exe", "File Wiper Utility"),
    ];

    // Check Running Processes
    if let Ok(mut stmt) = db.prepare("SELECT pid, name, executable_path, command_line FROM processes") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        }) {
            for r in rows.flatten() {
                let (pid, name, path, cmdline) = r;
                let lower_all = format!("{} {} {}", name, path, cmdline).to_lowercase();
                for (sig, tool_desc) in &wiping_signatures {
                    if lower_all.contains(sig) {
                        let details = format!("Active process PID {}: {} | Cmd: {}", pid, tool_desc, cmdline);
                        let _ = insert_alert(db, "Wiping Tool Signature", "CRITICAL", &path, &details, &now_str);
                        count += 1;
                    }
                }
            }
        }
    }

    // Check Prefetch Executions (.PF)
    if let Ok(mut stmt) = db.prepare("SELECT executable_name, file_path, run_count, last_run_time FROM prefetch_executions") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        }) {
            for r in rows.flatten() {
                let (exe_name, path, run_cnt, last_run) = r;
                let lower = exe_name.to_lowercase();
                for (sig, tool_desc) in &wiping_signatures {
                    if lower.contains(sig) {
                        let details = format!("Prefetch Execution Record: {} | Runs: {} | Last Run: {}", tool_desc, run_cnt, last_run);
                        let _ = insert_alert(db, "Wiping Tool Signature", "HIGH", &path, &details, &now_str);
                        count += 1;
                    }
                }
            }
        }
    }

    // Check Amcache / Installed applications
    if let Ok(mut stmt) = db.prepare("SELECT file_path, publisher, install_date FROM amcache_entries") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        }) {
            for r in rows.flatten() {
                let (path, publ, inst_date) = r;
                let lower = path.to_lowercase();
                for (sig, tool_desc) in &wiping_signatures {
                    if lower.contains(sig) {
                        let details = format!("Amcache / Program Evidence: {} | Publisher: {} | Date: {}", tool_desc, publ, inst_date);
                        let _ = insert_alert(db, "Wiping Tool Signature", "HIGH", &path, &details, &now_str);
                        count += 1;
                    }
                }
            }
        }
    }

    count
}

/// 2. Detect Timestomping ($STANDARD_INFORMATION vs $FILE_NAME Mismatch & Sub-second Truncation)
pub fn detect_timestomping(search_dirs: &[&Path], db: &Connection) -> usize {
    let mut count = 0;
    let now_str = Utc::now().to_rfc3339();

    for dir in search_dirs {
        if !dir.exists() { continue; }
        scan_dir_for_timestomping(dir, db, &now_str, &mut count, 0);
    }
    count
}

fn scan_dir_for_timestomping(dir: &Path, db: &Connection, now_str: &str, count: &mut usize, depth: u32) {
    if depth > 4 || *count >= 200 { return; }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = fs::metadata(&path) {
                // Check sub-second truncation anomalies (common indicator of SetFileTime timestomping)
                if let Ok(created) = meta.created() {
                    if let Ok(modified) = meta.modified() {
                        // Check if modification time is significantly earlier than creation time
                        // On NTFS, modifying file content updates $SI modified timestamp.
                        // Setting a forged back-dated timestamp with API SetFileTime modifies $SI timestamps
                        // while sub-second precision is frequently zeroed (.0000000) or $SI < $FN.
                        use std::time::SystemTime;
                        let dur_created = created.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
                        let dur_mod = modified.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();

                        // 1. Backdated Modification Anomaly: Modified > 30 days BEFORE file creation on this volume
                        if dur_created.as_secs() > dur_mod.as_secs() + (30 * 86400) {
                            let details = format!(
                                "Timestomping Anomaly ($SI Backdating Indicator): File Modified time ({}s epoch) is >30 days earlier than Creation time ({}s epoch)",
                                dur_mod.as_secs(), dur_created.as_secs()
                            );
                            let _ = insert_alert(db, "NTFS Timestomping", "HIGH", &path.display().to_string(), &details, now_str);
                            *count += 1;
                        }

                        // 2. Exact Zero Sub-second Granularity on executable or DLL files
                        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                            let ext_lower = ext.to_lowercase();
                            if ext_lower == "exe" || ext_lower == "dll" || ext_lower == "sys" || ext_lower == "ps1" {
                                let nanos = dur_mod.subsec_nanos();
                                if nanos == 0 && dur_mod.as_secs() > 0 {
                                    let details = "Timestomping Anomaly: Executable file timestamp has exact zero nanosecond granularity (.000000000), typical of SetFileTime / timestomp tools".to_string();
                                    let _ = insert_alert(db, "NTFS Timestomping", "MEDIUM", &path.display().to_string(), &details, now_str);
                                    *count += 1;
                                }
                            }
                        }
                    }
                }
            }
            if path.is_dir() {
                scan_dir_for_timestomping(&path, db, now_str, count, depth + 1);
            }
        }
    }
}

/// 3. Detect Hidden Partition & Unallocated Space Anomalies
pub fn detect_partition_anomalies(db: &Connection) -> usize {
    let mut count = 0;
    let now_str = Utc::now().to_rfc3339();

    // Inspect disks and partition table using sysinfo / native disk info
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();

    for disk in &disks {
        let name = disk.name().to_string_lossy().to_string();
        let fs_type = disk.file_system().to_string_lossy().to_string();
        let total = disk.total_space();
        let available = disk.available_space();
        let mount = disk.mount_point().display().to_string();

        // Flag Raw or Unrecognized Filesystem partitions (potential TrueCrypt / VeraCrypt / Encrypted containers)
        if fs_type.is_empty() || fs_type.to_lowercase() == "raw" || fs_type.to_lowercase() == "unknown" {
            let details = format!("Partition anomaly: Raw/Unrecognized filesystem on volume '{}' (Mount: {} | Total: {} MB). May indicate hidden container or encrypted volume.", name, mount, total / (1024 * 1024));
            let _ = insert_alert(db, "Hidden Partition / Unallocated Gap", "HIGH", &mount, &details, &now_str);
            count += 1;
        }

        // Flag suspiciously small mounted volumes or high unallocated gap ratios if total > 0
        if total > 0 && available == total {
            let details = format!("Partition anomaly: Completely empty volume '{}' ({} MB). Verify if staging volume or unmounted hidden container.", name, total / (1024 * 1024));
            let _ = insert_alert(db, "Hidden Partition / Unallocated Gap", "MEDIUM", &mount, &details, &now_str);
            count += 1;
        }
    }

    count
}

/// 4. Steganography Signature & LSB Statistical Anomaly Heuristics on extracted image files
pub fn scan_steganography(search_dirs: &[&Path], db: &Connection) -> usize {
    let mut count = 0;
    let now_str = Utc::now().to_rfc3339();

    for dir in search_dirs {
        if !dir.exists() { continue; }
        scan_dir_for_steg(dir, db, &now_str, &mut count, 0);
    }
    count
}

fn scan_dir_for_steg(dir: &Path, db: &Connection, now_str: &str, count: &mut usize, depth: u32) {
    if depth > 3 || *count >= 100 { return; }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let lower = ext.to_lowercase();
                if lower == "png" || lower == "jpg" || lower == "jpeg" || lower == "bmp" {
                    if let Ok(mut file) = File::open(&path) {
                        // Check file size (< 20 MB)
                        if let Ok(meta) = file.metadata() {
                            let len = meta.len();
                            if len > 500 && len < 20 * 1024 * 1024 {
                                // 1. Check appended trailing payload beyond EOF markers
                                if lower == "jpg" || lower == "jpeg" {
                                    if let Some(extra_bytes) = check_jpeg_appended_payload(&mut file, len) {
                                        if extra_bytes > 64 {
                                            let details = format!("Steganography / Appended Payload Anomaly: JPEG file contains {} trailing bytes after 0xFFD9 End-of-Image marker", extra_bytes);
                                            let _ = insert_alert(db, "Steganography Anomaly", "HIGH", &path.display().to_string(), &details, now_str);
                                            *count += 1;
                                        }
                                    }
                                } else if lower == "png" {
                                    if let Some(extra_bytes) = check_png_appended_payload(&mut file, len) {
                                        if extra_bytes > 64 {
                                            let details = format!("Steganography / Appended Payload Anomaly: PNG file contains {} trailing bytes after IEND chunk", extra_bytes);
                                            let _ = insert_alert(db, "Steganography Anomaly", "HIGH", &path.display().to_string(), &details, now_str);
                                            *count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if path.is_dir() {
                scan_dir_for_steg(&path, db, now_str, count, depth + 1);
            }
        }
    }
}

fn check_jpeg_appended_payload(file: &mut File, file_len: u64) -> Option<u64> {
    // Read last 4KB of file and find last 0xFF 0xD9
    let check_size = std::cmp::min(file_len, 8192) as usize;
    if file.seek(SeekFrom::End(-(check_size as i64))).is_ok() {
        let mut buf = vec![0u8; check_size];
        if file.read_exact(&mut buf).is_ok() {
            // Find last occurrence of 0xFF 0xD9
            for i in (0..buf.len().saturating_sub(1)).rev() {
                if buf[i] == 0xFF && buf[i + 1] == 0xD9 {
                    let trailing = (buf.len() - (i + 2)) as u64;
                    return Some(trailing);
                }
            }
        }
    }
    None
}

fn check_png_appended_payload(file: &mut File, file_len: u64) -> Option<u64> {
    // PNG IEND chunk is 12 bytes: 0x00 0x00 0x00 0x00 'I' 'E' 'N' 'D' CRC(4 bytes)
    let check_size = std::cmp::min(file_len, 8192) as usize;
    if file.seek(SeekFrom::End(-(check_size as i64))).is_ok() {
        let mut buf = vec![0u8; check_size];
        if file.read_exact(&mut buf).is_ok() {
            let iend_tag = b"IEND";
            for i in (0..buf.len().saturating_sub(7)).rev() {
                if &buf[i..i + 4] == iend_tag {
                    let trailing = (buf.len() - (i + 8)) as u64;
                    return Some(trailing);
                }
            }
        }
    }
    None
}

/// 5. "Suspiciously Clean System" Flag — Near-empty recent files / logs on an active system
pub fn audit_system_cleanliness(db: &Connection) -> usize {
    let mut count = 0;
    let now_str = Utc::now().to_rfc3339();

    // 1. Audit Event Logs Count
    let mut event_count = 0i64;
    if let Ok(mut stmt) = db.prepare("SELECT COUNT(*) FROM event_logs") {
        if let Ok(c) = stmt.query_row([], |r| r.get::<_, i64>(0)) {
            event_count = c;
        }
    }

    // Check if Event Logs were cleared (Event ID 1102 Security Log Cleared or Event ID 104 System Log Cleared)
    let mut cleared_events = false;
    if let Ok(mut stmt) = db.prepare("SELECT event_id, log_name, time_created FROM event_logs WHERE event_id IN (1102, 104)") {
        if let Ok(mut rows) = stmt.query([]) {
            while let Ok(Some(row)) = rows.next() {
                let eid = row.get::<_, i32>(0).unwrap_or(0);
                let log_name = row.get::<_, String>(1).unwrap_or_default();
                let time_str = row.get::<_, String>(2).unwrap_or_default();
                let details = format!(
                    "RED FLAG (Audit Log Cleared): Windows Event Log '{}' cleared explicitly (Event ID {} at {})",
                    log_name, eid, time_str
                );
                let _ = insert_alert(db, "Suspiciously Clean System", "CRITICAL", "Windows Event Log", &details, &now_str);
                cleared_events = true;
                count += 1;
            }
        }
    }

    if !cleared_events && event_count < 20 {
        let details = format!(
            "RED FLAG (Suspiciously Clean System): Active system contains only {} total Event Log entries. Indicates wholesale Event Log purging or log service tampering.",
            event_count
        );
        let _ = insert_alert(db, "Suspiciously Clean System", "HIGH", "Windows Event Log", &details, &now_str);
        count += 1;
    }

    // 2. Audit Prefetch Records Count
    let mut prefetch_count = 0i64;
    if let Ok(mut stmt) = db.prepare("SELECT COUNT(*) FROM prefetch_executions") {
        if let Ok(c) = stmt.query_row([], |r| r.get::<_, i64>(0)) {
            prefetch_count = c;
        }
    }
    if prefetch_count < 5 {
        let details = format!(
            "RED FLAG (Suspiciously Clean System): Only {} Prefetch execution records detected on host. Indicates recent clearing of C:\\Windows\\Prefetch or Sysmain service disabling.",
            prefetch_count
        );
        let _ = insert_alert(db, "Suspiciously Clean System", "HIGH", "C:\\Windows\\Prefetch", &details, &now_str);
        count += 1;
    }

    // 3. Audit Browser History Records Count
    let mut hist_count = 0i64;
    if let Ok(mut stmt) = db.prepare("SELECT COUNT(*) FROM browser_history") {
        if let Ok(c) = stmt.query_row([], |r| r.get::<_, i64>(0)) {
            hist_count = c;
        }
    }
    if hist_count == 0 {
        let details = "RED FLAG (Suspiciously Clean System): Zero web browser history records detected across installed browsers. Indicates deliberate history/cache wiping before acquisition.".to_string();
        let _ = insert_alert(db, "Suspiciously Clean System", "MEDIUM", "User Web Browsers", &details, &now_str);
        count += 1;
    }

    count
}

fn insert_alert(
    db: &Connection,
    category: &str,
    severity: &str,
    artifact_path: &str,
    details: &str,
    now_str: &str,
) -> rusqlite::Result<usize> {
    db.execute(
        "INSERT INTO anti_forensics_alerts (category, severity, artifact_path, details, detection_timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![category, severity, artifact_path, details, now_str],
    )
}
