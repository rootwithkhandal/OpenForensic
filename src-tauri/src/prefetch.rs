use std::fs::File;
use std::io::Read;
use std::path::Path;
use rusqlite::Connection;
use crate::error::{OpenForensicError, Result};
use crate::acquisition::ProgressEvent;
use tokio::sync::mpsc::Sender;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PrefetchEntry {
    pub executable_name: String,
    pub file_path: String,
    pub run_count: u32,
    pub last_run_time: String,
    pub prefetch_hash: String,
    pub loaded_files: String,
}

#[cfg(target_os = "windows")]
fn decompress_mam(compressed_buffer: &[u8]) -> Result<Vec<u8>> {
    if compressed_buffer.len() < 8 {
        return Err(OpenForensicError::Backend("Buffer too small for MAM compression header".to_string()));
    }
    let uncompressed_size = u32::from_le_bytes(compressed_buffer[4..8].try_into().unwrap_or([0; 4])) as usize;
    if uncompressed_size == 0 || uncompressed_size > 100 * 1024 * 1024 {
        return Err(OpenForensicError::Backend("Invalid uncompressed size in MAM header".to_string()));
    }

    unsafe {
        let lib = libloading::Library::new("ntdll.dll")
            .map_err(|e| OpenForensicError::Backend(format!("Failed to load ntdll.dll: {}", e)))?;
        
        type RtlGetCompressionWorkSpaceSizeFn = unsafe extern "system" fn(
            u16,
            *mut u32,
            *mut u32,
        ) -> i32;

        type RtlDecompressBufferExFn = unsafe extern "system" fn(
            u16,
            *mut u8,
            u32,
            *const u8,
            u32,
            *mut u32,
            *mut std::ffi::c_void,
        ) -> i32;

        let get_workspace_size: libloading::Symbol<RtlGetCompressionWorkSpaceSizeFn> = lib
            .get(b"RtlGetCompressionWorkSpaceSize\0")
            .map_err(|e| OpenForensicError::Backend(format!("Failed to find RtlGetCompressionWorkSpaceSize: {}", e)))?;

        let decompress_buffer_ex: libloading::Symbol<RtlDecompressBufferExFn> = lib
            .get(b"RtlDecompressBufferEx\0")
            .map_err(|e| OpenForensicError::Backend(format!("Failed to find RtlDecompressBufferEx: {}", e)))?;

        const COMPRESSION_FORMAT_XPRESS_HUFF: u16 = 0x0004;
        let mut buffer_workspace_size: u32 = 0;
        let mut fragment_workspace_size: u32 = 0;
        let res = get_workspace_size(COMPRESSION_FORMAT_XPRESS_HUFF, &mut buffer_workspace_size, &mut fragment_workspace_size);
        if res < 0 {
            return Err(OpenForensicError::Backend(format!("RtlGetCompressionWorkSpaceSize failed with NTSTATUS: 0x{:08X}", res)));
        }

        let mut workspace = vec![0u8; buffer_workspace_size as usize];
        let mut uncompressed = vec![0u8; uncompressed_size];
        let mut final_size: u32 = 0;

        let compressed_data = &compressed_buffer[8..];
        let res = decompress_buffer_ex(
            COMPRESSION_FORMAT_XPRESS_HUFF,
            uncompressed.as_mut_ptr(),
            uncompressed_size as u32,
            compressed_data.as_ptr(),
            compressed_data.len() as u32,
            &mut final_size,
            workspace.as_mut_ptr() as *mut std::ffi::c_void,
        );

        if res < 0 {
            return Err(OpenForensicError::Backend(format!("RtlDecompressBufferEx failed with NTSTATUS: 0x{:08X}", res)));
        }

        uncompressed.truncate(final_size as usize);
        Ok(uncompressed)
    }
}

#[cfg(not(target_os = "windows"))]
fn decompress_mam(_compressed_buffer: &[u8]) -> Result<Vec<u8>> {
    Err(OpenForensicError::Backend("XPRESS Huffman decompression (MAM) is currently only supported on Windows targets.".to_string()))
}

pub fn parse_prefetch_file(path: &Path) -> Result<PrefetchEntry> {
    let mut file = File::open(path)
        .map_err(|e| OpenForensicError::Backend(format!("Failed to open prefetch file {}: {}", path.display(), e)))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| OpenForensicError::Backend(format!("Failed to read prefetch file {}: {}", path.display(), e)))?;

    if buffer.len() < 84 {
        return Err(OpenForensicError::Backend("Prefetch file too small".to_string()));
    }

    let data = if &buffer[0..4] == b"MAM\x04" {
        decompress_mam(&buffer)?
    } else {
        buffer
    };

    if data.len() < 84 || &data[0..4] != b"SCCA" {
        return Err(OpenForensicError::Backend("Invalid Prefetch SCCA signature".to_string()));
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
    let hash = u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]));
    let prefetch_hash = format!("0x{:08X}", hash);

    let mut exec_chars = Vec::new();
    for chunk in data[12..72].chunks_exact(2) {
        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
        if ch == 0 { break; }
        exec_chars.push(ch);
    }
    let executable_name = String::from_utf16_lossy(&exec_chars).trim().to_string();

    let fib_offset = match version {
        17 => 68,
        23 | 26 | 30 => 84,
        _ => 84,
    };

    if data.len() < fib_offset + 128 {
        return Err(OpenForensicError::Backend(format!("Prefetch data too small for version {}", version)));
    }

    let filename_strings_offset = u32::from_le_bytes(data[fib_offset + 16..fib_offset + 20].try_into().unwrap_or([0; 4])) as usize;
    let filename_strings_size = u32::from_le_bytes(data[fib_offset + 20..fib_offset + 24].try_into().unwrap_or([0; 4])) as usize;

    let mut loaded_files_list = Vec::new();
    if filename_strings_offset + filename_strings_size <= data.len() && filename_strings_size > 0 {
        let str_data = &data[filename_strings_offset..filename_strings_offset + filename_strings_size];
        let mut cur_chars = Vec::new();
        for chunk in str_data.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                if !cur_chars.is_empty() {
                    let s = String::from_utf16_lossy(&cur_chars).trim().to_string();
                    if !s.is_empty() {
                        loaded_files_list.push(s);
                    }
                    cur_chars.clear();
                }
            } else {
                cur_chars.push(ch);
            }
        }
        if !cur_chars.is_empty() {
            let s = String::from_utf16_lossy(&cur_chars).trim().to_string();
            if !s.is_empty() {
                loaded_files_list.push(s);
            }
        }
    }

    let loaded_files = loaded_files_list.join(", ");

    let mut timestamps = Vec::new();
    let run_count: u32;

    match version {
        17 => {
            if data.len() >= fib_offset + 44 {
                let ft = u64::from_le_bytes(data[fib_offset + 36..fib_offset + 44].try_into().unwrap_or([0; 8]));
                if let Some(ts) = filetime_to_rfc3339(ft) { timestamps.push(ts); }
            }
            run_count = if data.len() >= fib_offset + 48 {
                u32::from_le_bytes(data[fib_offset + 44..fib_offset + 48].try_into().unwrap_or([0; 4]))
            } else { 1 };
        }
        23 => {
            if data.len() >= fib_offset + 44 {
                let ft = u64::from_le_bytes(data[fib_offset + 36..fib_offset + 44].try_into().unwrap_or([0; 8]));
                if let Some(ts) = filetime_to_rfc3339(ft) { timestamps.push(ts); }
            }
            run_count = if data.len() >= fib_offset + 72 {
                u32::from_le_bytes(data[fib_offset + 68..fib_offset + 72].try_into().unwrap_or([0; 4]))
            } else { 1 };
        }
        26 => {
            if data.len() >= fib_offset + 108 {
                for i in 0..8 {
                    let off = fib_offset + 44 + (i * 8);
                    if data.len() >= off + 8 {
                        let ft = u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]));
                        if let Some(ts) = filetime_to_rfc3339(ft) { timestamps.push(ts); }
                    }
                }
            }
            run_count = if data.len() >= fib_offset + 128 {
                u32::from_le_bytes(data[fib_offset + 124..fib_offset + 128].try_into().unwrap_or([0; 4]))
            } else { 1 };
        }
        30 | _ => {
            if data.len() >= fib_offset + 108 {
                for i in 0..8 {
                    let off = fib_offset + 44 + (i * 8);
                    if data.len() >= off + 8 {
                        let ft = u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]));
                        if let Some(ts) = filetime_to_rfc3339(ft) { timestamps.push(ts); }
                    }
                }
            }
            run_count = if data.len() >= fib_offset + 128 {
                let rc = u32::from_le_bytes(data[fib_offset + 124..fib_offset + 128].try_into().unwrap_or([0; 4]));
                if rc == 0 && data.len() >= fib_offset + 120 {
                    u32::from_le_bytes(data[fib_offset + 116..fib_offset + 120].try_into().unwrap_or([0; 4]))
                } else { rc }
            } else { 1 };
        }
    }

    let last_run_time = if timestamps.is_empty() {
        "Unknown".to_string()
    } else {
        timestamps.join(", ")
    };

    Ok(PrefetchEntry {
        executable_name,
        file_path: path.to_string_lossy().to_string(),
        run_count,
        last_run_time,
        prefetch_hash,
        loaded_files,
    })
}

pub fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    if filetime == 0 { return None; }
    const WINDOWS_TICK_TO_UNIX_EPOCH: u64 = 116444736000000000;
    if filetime <= WINDOWS_TICK_TO_UNIX_EPOCH {
        return None;
    }
    let unix_ticks = filetime - WINDOWS_TICK_TO_UNIX_EPOCH;
    let seconds = (unix_ticks / 10_000_000) as i64;
    let nanos = ((unix_ticks % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(seconds, nanos)
        .map(|dt| dt.to_rfc3339())
}

pub fn parse_prefetch_folder(
    prefetch_dir: &Path,
    db: &Connection,
    progress_tx: Sender<ProgressEvent>,
) -> Result<usize> {
    if !prefetch_dir.exists() {
        return Ok(0);
    }

    let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[PREFETCH] Scanning prefetch folder: {}", prefetch_dir.display())));

    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(prefetch_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|ext| ext.to_str()).map(|s| s.eq_ignore_ascii_case("pf")).unwrap_or(false) {
                match parse_prefetch_file(&path) {
                    Ok(entry_data) => {
                        let _ = db.execute(
                            "INSERT INTO prefetch_executions (executable_name, file_path, run_count, last_run_time, prefetch_hash, loaded_files) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            rusqlite::params![
                                entry_data.executable_name,
                                entry_data.file_path,
                                entry_data.run_count,
                                entry_data.last_run_time,
                                entry_data.prefetch_hash,
                                entry_data.loaded_files
                            ],
                        );
                        count += 1;
                    }
                    Err(e) => {
                        let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[PREFETCH WARNING] Failed to parse {}: {}", path.display(), e)));
                    }
                }
            }
        }
    }

    let _ = progress_tx.blocking_send(ProgressEvent::Log(format!("[PREFETCH] Successfully parsed {} prefetch files.", count)));
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_conversion() {
        // Test January 1, 2021 00:00:00 UTC (132539328000000000 ticks)
        let ts = filetime_to_rfc3339(132539328000000000);
        assert!(ts.is_some());
        assert_eq!(ts.unwrap(), "2021-01-01T00:00:00+00:00");
    }
}
