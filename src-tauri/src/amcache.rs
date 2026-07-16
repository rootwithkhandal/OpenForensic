use std::fs::File;
use std::io::Read;
use std::path::Path;
use rusqlite::Connection;
use crate::error::{OpenForensicError, Result};
use crate::acquisition::ProgressEvent;
use crate::prefetch::filetime_to_rfc3339;
use tokio::sync::mpsc::Sender;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AmcacheEntry {
    pub source_type: String, // 'Amcache' or 'Shimcache'
    pub file_path: String,
    pub sha1_hash: String,
    pub publisher: String,
    pub install_date: String,
    pub last_modified_time: String,
    pub execution_flag: String,
}

pub fn parse_amcache_hive(path: &Path) -> Result<Vec<AmcacheEntry>> {
    let mut entries = Vec::new();
    let parser = match notatin::parser_builder::ParserBuilder::from_path(path.to_path_buf()).build() {
        Ok(p) => p,
        Err(e) => return Err(OpenForensicError::Backend(format!("Failed to parse Amcache hive {}: {}", path.display(), e))),
    };

    for key in notatin::parser::ParserIterator::new(&parser) {
        let key_path = key.path.clone();
        if key_path.contains("InventoryApplicationFile") || key_path.contains("Root\\File") || key_path.contains("AssociatedFileEntries") {
            let mut file_path = String::new();
            let mut sha1_hash = String::new();
            let mut publisher = String::new();
            let mut install_date = String::new();

            for val in key.value_iter() {
                let name = val.detail.value_name();
                let (content, _) = val.get_content();
                let content_str = format!("{:?}", content);
                let clean_str = content_str
                    .trim_start_matches("String(\"")
                    .trim_end_matches("\")")
                    .trim_start_matches('\"')
                    .trim_end_matches('\"')
                    .to_string();

                if name.eq_ignore_ascii_case("LowerCaseLongPath") || name.eq_ignore_ascii_case("Path") || name.eq_ignore_ascii_case("Name") {
                    file_path = clean_str;
                } else if name.eq_ignore_ascii_case("FileId") || name.eq_ignore_ascii_case("SHA1") || name.eq_ignore_ascii_case("Hash") {
                    sha1_hash = if clean_str.starts_with("0000") && clean_str.len() > 4 {
                        clean_str[4..].to_string()
                    } else {
                        clean_str
                    };
                } else if name.eq_ignore_ascii_case("Publisher") || name.eq_ignore_ascii_case("CompanyName") {
                    publisher = clean_str;
                } else if name.eq_ignore_ascii_case("LinkDate") || name.eq_ignore_ascii_case("InstallDate") || name.eq_ignore_ascii_case("FileTimestamp") {
                    install_date = clean_str;
                }
            }

            if !file_path.is_empty() || !sha1_hash.is_empty() {
                entries.push(AmcacheEntry {
                    source_type: "Amcache".to_string(),
                    file_path,
                    sha1_hash,
                    publisher: if publisher.is_empty() { "Unknown".to_string() } else { publisher },
                    install_date: if install_date.is_empty() { "N/A".to_string() } else { install_date },
                    last_modified_time: "N/A".to_string(),
                    execution_flag: "Yes (Amcache)".to_string(),
                });
            }
        }
    }

    Ok(entries)
}

pub fn extract_shimcache_from_bytes(buffer: &[u8]) -> Vec<AmcacheEntry> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i + 8 < buffer.len() {
        let is_drive = (buffer[i] >= b'A' && buffer[i] <= b'Z' || buffer[i] >= b'a' && buffer[i] <= b'z')
            && buffer[i + 1] == 0
            && buffer[i + 2] == b':'
            && buffer[i + 3] == 0
            && buffer[i + 4] == b'\\'
            && buffer[i + 5] == 0;

        let is_nt_path = i + 8 < buffer.len()
            && buffer[i] == b'\\'
            && buffer[i + 1] == 0
            && buffer[i + 2] == b'?'
            && buffer[i + 3] == 0
            && buffer[i + 4] == b'?'
            && buffer[i + 5] == 0
            && buffer[i + 6] == b'\\'
            && buffer[i + 7] == 0;

        if is_drive || is_nt_path {
            let start_idx = i;
            let mut end_idx = i;
            let mut chars = Vec::new();
            while end_idx + 1 < buffer.len() {
                let ch = u16::from_le_bytes([buffer[end_idx], buffer[end_idx + 1]]);
                if ch == 0 || !(ch == 0x5C || ch == 0x2E || ch == 0x3A || ch == 0x3F || ch == 0x2D || ch == 0x5F || (ch >= 0x20 && ch <= 0x7E) || ch > 0x7F) {
                    break;
                }
                chars.push(ch);
                end_idx += 2;
                if chars.len() >= 300 { break; }
            }

            let path_str = String::from_utf16_lossy(&chars).trim().to_string();
            let lower = path_str.to_lowercase();
            if lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys") || lower.ends_with(".com") || lower.ends_with(".bat") || lower.ends_with(".drv") {
                let mut found_ts = "Unknown".to_string();
                
                let search_end = (end_idx + 40).min(buffer.len());
                for pos in (end_idx..search_end.saturating_sub(7)).step_by(2) {
                    let ft = u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap_or([0; 8]));
                    if let Some(ts) = filetime_to_rfc3339(ft) {
                        found_ts = ts;
                        break;
                    }
                }

                if found_ts == "Unknown" {
                    let search_start = start_idx.saturating_sub(40);
                    for pos in (search_start..start_idx.saturating_sub(7)).step_by(2) {
                        let ft = u64::from_le_bytes(buffer[pos..pos + 8].try_into().unwrap_or([0; 8]));
                        if let Some(ts) = filetime_to_rfc3339(ft) {
                            found_ts = ts;
                            break;
                        }
                    }
                }

                entries.push(AmcacheEntry {
                    source_type: "Shimcache".to_string(),
                    file_path: path_str,
                    sha1_hash: "N/A".to_string(),
                    publisher: "N/A".to_string(),
                    install_date: "N/A".to_string(),
                    last_modified_time: found_ts,
                    execution_flag: "Yes (Cached in SYSTEM hive)".to_string(),
                });

                i = end_idx;
                continue;
            }
        }
        i += 1;
    }
    entries
}

pub fn parse_execution_hives(
    evidence_dir: &Path,
    db: &Connection,
    progress_tx: Sender<ProgressEvent>,
) -> Result<usize> {
    if !evidence_dir.exists() {
        return Ok(0);
    }

    let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[AMCACHE/SHIMCACHE] Scanning execution hives in: {}", evidence_dir.display())));
    let mut total_count = 0;

    let mut amcache_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(evidence_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.file_name().and_then(|n| n.to_str()).map(|n| n.to_lowercase().contains("amcache")).unwrap_or(false) {
                if !path.to_string_lossy().to_lowercase().ends_with(".log1") && !path.to_string_lossy().to_lowercase().ends_with(".log2") {
                    amcache_files.push(path);
                }
            }
        }
    }

    for path in amcache_files {
        let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[AMCACHE] Parsing Amcache hive: {}", path.display())));
        match parse_amcache_hive(&path) {
            Ok(entries) => {
                for entry in &entries {
                    let _ = db.execute(
                        "INSERT INTO amcache_entries (source_type, file_path, sha1_hash, publisher, install_date, last_modified_time, execution_flag) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        rusqlite::params![
                            entry.source_type,
                            entry.file_path,
                            entry.sha1_hash,
                            entry.publisher,
                            entry.install_date,
                            entry.last_modified_time,
                            entry.execution_flag
                        ],
                    );
                }
                let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[AMCACHE] Extracted {} records from {}", entries.len(), path.display())));
                total_count += entries.len();
            }
            Err(e) => {
                let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[AMCACHE WARNING] Failed to parse {}: {}", path.display(), e)));
            }
        }
    }

    let mut system_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(evidence_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.file_name().and_then(|n| n.to_str()).map(|n| n.eq_ignore_ascii_case("SYSTEM") || n.eq_ignore_ascii_case("system_hive.reg") || n.to_lowercase().starts_with("system")).unwrap_or(false) {
                system_files.push(path);
            }
        }
    }

    for path in system_files {
        let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[SHIMCACHE] Scanning SYSTEM hive for AppCompatCache: {}", path.display())));
        if let Ok(mut file) = File::open(&path) {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                let entries = extract_shimcache_from_bytes(&buf);
                if !entries.is_empty() {
                    for entry in &entries {
                        let _ = db.execute(
                            "INSERT INTO amcache_entries (source_type, file_path, sha1_hash, publisher, install_date, last_modified_time, execution_flag) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            rusqlite::params![
                                entry.source_type,
                                entry.file_path,
                                entry.sha1_hash,
                                entry.publisher,
                                entry.install_date,
                                entry.last_modified_time,
                                entry.execution_flag
                            ],
                        );
                    }
                    let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[SHIMCACHE] Extracted {} Shimcache records from {}", entries.len(), path.display())));
                    total_count += entries.len();
                }
            }
        }
    }

    let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[AMCACHE/SHIMCACHE] Total execution evidence records extracted: {}", total_count)));
    Ok(total_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shimcache_extraction() {
        let mut mock_buf = Vec::new();
        // Insert C:\Windows\System32\cmd.exe in UTF-16LE
        let path = "C:\\Windows\\System32\\cmd.exe";
        for ch in path.encode_utf16() {
            mock_buf.extend_from_slice(&ch.to_le_bytes());
        }
        mock_buf.extend_from_slice(&[0, 0]); // null terminator
        // Insert a valid FILETIME for Jan 1, 2021 (132539328000000000 u64)
        mock_buf.extend_from_slice(&132539328000000000u64.to_le_bytes());

        let entries = extract_shimcache_from_bytes(&mock_buf);
        assert!(!entries.is_empty());
        assert_eq!(entries[0].file_path, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(entries[0].last_modified_time, "2021-01-01T00:00:00+00:00");
    }
}
