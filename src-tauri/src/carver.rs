use rayon::prelude::*;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CarvedFileRecord {
    pub file_type: String,
    pub extension: String,
    pub offset_start: u64,
    pub offset_end: u64,
    pub file_size: u64,
    pub sha256_hash: String,
    pub output_path: String,
    pub carved_time: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CarverBenchmarkResult {
    pub total_bytes: u64,
    pub single_thread_duration_ms: u128,
    pub multi_thread_duration_ms: u128,
    pub speedup_factor: f64,
    pub files_carved: usize,
    pub throughput_mb_per_sec: f64,
}

#[derive(Debug, Clone)]
pub struct FileSignature {
    pub name: &'static str,
    pub extension: &'static str,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_size: u64,
}

pub fn get_default_signatures() -> Vec<FileSignature> {
    vec![
        // 1. Media & Images
        FileSignature {
            name: "JPEG Image",
            extension: "jpg",
            header: &[0xFF, 0xD8, 0xFF],
            footer: Some(&[0xFF, 0xD9]),
            max_size: 50 * 1024 * 1024,
        },
        FileSignature {
            name: "PNG Image",
            extension: "png",
            header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
            max_size: 100 * 1024 * 1024,
        },
        FileSignature {
            name: "GIF Image",
            extension: "gif",
            header: b"GIF89a",
            footer: Some(&[0x00, 0x3B]),
            max_size: 50 * 1024 * 1024,
        },
        FileSignature {
            name: "GIF Legacy Image",
            extension: "gif",
            header: b"GIF87a",
            footer: Some(&[0x00, 0x3B]),
            max_size: 50 * 1024 * 1024,
        },
        FileSignature {
            name: "BMP Bitmap Image",
            extension: "bmp",
            header: b"BM",
            footer: None,
            max_size: 100 * 1024 * 1024,
        },
        FileSignature {
            name: "WebP Image",
            extension: "webp",
            header: b"RIFF",
            footer: None,
            max_size: 50 * 1024 * 1024,
        },
        FileSignature {
            name: "AVI Video File",
            extension: "avi",
            header: b"RIFF",
            footer: None,
            max_size: 500 * 1024 * 1024,
        },
        FileSignature {
            name: "WAV Audio File",
            extension: "wav",
            header: b"RIFF",
            footer: None,
            max_size: 200 * 1024 * 1024,
        },
        // 2. Documents & Office
        FileSignature {
            name: "PDF Document",
            extension: "pdf",
            header: b"%PDF-",
            footer: Some(b"%%EOF"),
            max_size: 200 * 1024 * 1024,
        },
        FileSignature {
            name: "ZIP / Office OpenXML (DOCX/XLSX)",
            extension: "zip",
            header: &[0x50, 0x4B, 0x03, 0x04],
            footer: None,
            max_size: 500 * 1024 * 1024,
        },
        FileSignature {
            name: "Legacy Microsoft Office Compound Binary",
            extension: "doc",
            header: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
            footer: None,
            max_size: 100 * 1024 * 1024,
        },
        FileSignature {
            name: "Rich Text Format (RTF)",
            extension: "rtf",
            header: b"{\\rtf1",
            footer: Some(b"}"),
            max_size: 50 * 1024 * 1024,
        },
        // 3. Archives & Compression
        FileSignature {
            name: "GZIP Compressed Archive",
            extension: "gz",
            header: &[0x1F, 0x8B, 0x08],
            footer: None,
            max_size: 200 * 1024 * 1024,
        },
        FileSignature {
            name: "7-Zip Compressed Archive",
            extension: "7z",
            header: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            footer: None,
            max_size: 500 * 1024 * 1024,
        },
        FileSignature {
            name: "RAR Archive",
            extension: "rar",
            header: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],
            footer: None,
            max_size: 500 * 1024 * 1024,
        },
        // 4. Databases & OS Artifacts
        FileSignature {
            name: "SQLite Database",
            extension: "sqlite",
            header: b"SQLite format 3\x00",
            footer: None,
            max_size: 500 * 1024 * 1024,
        },
        FileSignature {
            name: "Windows Event Log (EVTX)",
            extension: "evtx",
            header: b"ElfFile\x00",
            footer: None,
            max_size: 200 * 1024 * 1024,
        },
        FileSignature {
            name: "Windows Registry Hive",
            extension: "dat",
            header: b"regf",
            footer: None,
            max_size: 200 * 1024 * 1024,
        },
        FileSignature {
            name: "Windows Shortcut (LNK)",
            extension: "lnk",
            header: &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00],
            footer: None,
            max_size: 10 * 1024 * 1024,
        },
        FileSignature {
            name: "Windows Prefetch File",
            extension: "pf",
            header: b"SCCA",
            footer: None,
            max_size: 10 * 1024 * 1024,
        },
        FileSignature {
            name: "PCAP Network Capture",
            extension: "pcap",
            header: &[0xD4, 0xC3, 0xB2, 0xA1],
            footer: None,
            max_size: 500 * 1024 * 1024,
        },
        // 5. Executables & Binaries
        FileSignature {
            name: "Windows Portable Executable (EXE/DLL)",
            extension: "exe",
            header: b"MZ",
            footer: None,
            max_size: 100 * 1024 * 1024,
        },
        FileSignature {
            name: "ELF Executable Binary",
            extension: "elf",
            header: &[0x7F, 0x45, 0x4C, 0x46],
            footer: None,
            max_size: 100 * 1024 * 1024,
        },
    ]
}

#[allow(dead_code)]
pub struct CarveChunkJob {
    pub chunk_index: usize,
    pub base_offset: u64,
    pub buffer: Vec<u8>,
}

/// Scan a memory/file buffer for signatures single-threaded with exact structure validation
pub fn scan_buffer_signatures(
    base_offset: u64,
    buffer: &[u8],
    signatures: &[FileSignature],
) -> Vec<(String, String, u64, u64, Vec<u8>)> {
    let mut hits = Vec::new();

    for sig in signatures {
        let hdr_len = sig.header.len();
        if hdr_len == 0 || buffer.len() < hdr_len { continue; }

        let mut pos = 0;
        while pos + hdr_len <= buffer.len() {
            if &buffer[pos..pos + hdr_len] != sig.header {
                pos += 1;
                continue;
            }

            let start_offset = base_offset + pos as u64;
            let max_search = std::cmp::min(buffer.len(), pos + sig.max_size as usize);

            match sig.extension {
                "jpg" => {
                    // 1. JPEG: Verify 4th marker byte (0xE0..=0xEF JFIF/EXIF, 0xDB DQT, 0xC0..=0xC4 SOF)
                    if pos + 4 <= buffer.len() {
                        let b4 = buffer[pos + 3];
                        if !matches!(b4, 0xE0..=0xEF | 0xDB | 0xC0..=0xC4 | 0xDD | 0xFE) {
                            pos += 1;
                            continue;
                        }
                    }
                    // 2. Locate Start of Scan (SOS: 0xFF, 0xDA) so we bypass embedded EXIF thumbnail footers
                    let mut sos_pos = None;
                    if pos + 4 < max_search {
                        let search_slice = &buffer[pos + 4..max_search];
                        if let Some(rel_sos) = find_subsequence(search_slice, &[0xFF, 0xDA]) {
                            sos_pos = Some(pos + 4 + rel_sos);
                        }
                    }
                    // 3. Find true End of Image marker (0xFF, 0xD9) located AFTER sos_pos
                    let search_start = sos_pos.map(|s| s + 2).unwrap_or(pos + hdr_len);
                    if search_start < max_search {
                        let search_slice = &buffer[search_start..max_search];
                        if let Some(rel_end) = find_subsequence(search_slice, &[0xFF, 0xD9]) {
                            let end_idx = search_start + rel_end + 2;
                            if end_idx <= buffer.len() && end_idx > pos {
                                let file_data = buffer[pos..end_idx].to_vec();
                                hits.push((
                                    sig.name.to_string(),
                                    sig.extension.to_string(),
                                    start_offset,
                                    base_offset + end_idx as u64,
                                    file_data,
                                ));
                                pos = end_idx;
                                continue;
                            }
                        }
                    }
                    pos += 1;
                }
                "png" => {
                    // PNG: Verify IHDR magic chunk at pos+12 and extract exact IEND + 4 CRC bytes
                    if pos + 16 <= buffer.len() && &buffer[pos + 12..pos + 16] == b"IHDR" {
                        if pos + hdr_len < max_search {
                            let search_slice = &buffer[pos + hdr_len..max_search];
                            if let Some(rel_end) = find_subsequence(search_slice, &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]) {
                                let end_idx = pos + hdr_len + rel_end + 8;
                                if end_idx <= buffer.len() {
                                    let file_data = buffer[pos..end_idx].to_vec();
                                    hits.push((
                                        sig.name.to_string(),
                                        sig.extension.to_string(),
                                        start_offset,
                                        base_offset + end_idx as u64,
                                        file_data,
                                    ));
                                    pos = end_idx;
                                    continue;
                                }
                            }
                        }
                    }
                    pos += 1;
                }
                "bmp" => {
                    // BMP Bitmap: Read exact file_size from u32 at pos + 2
                    if pos + 26 <= buffer.len() {
                        let total_size = u32::from_le_bytes([
                            buffer[pos + 2], buffer[pos + 3], buffer[pos + 4], buffer[pos + 5]
                        ]) as u64;
                        if total_size >= 54 && total_size <= sig.max_size && pos + (total_size as usize) <= buffer.len() {
                            let end_idx = pos + (total_size as usize);
                            let file_data = buffer[pos..end_idx].to_vec();
                            hits.push((
                                sig.name.to_string(),
                                sig.extension.to_string(),
                                start_offset,
                                base_offset + end_idx as u64,
                                file_data,
                            ));
                            pos = end_idx;
                            continue;
                        }
                    }
                    pos += 1;
                }
                "webp" | "avi" | "wav" => {
                    // RIFF Container: Verify subtype and calculate exact size from RIFF length header
                    if pos + 12 <= buffer.len() {
                        let subtype = &buffer[pos + 8..pos + 12];
                        let matches_subtype = match sig.extension {
                            "webp" => subtype == b"WEBP",
                            "avi" => subtype == b"AVI ",
                            "wav" => subtype == b"WAVE",
                            _ => false,
                        };
                        if matches_subtype {
                            let riff_size = u32::from_le_bytes([
                                buffer[pos + 4], buffer[pos + 5], buffer[pos + 6], buffer[pos + 7]
                            ]) as u64;
                            let total_size = riff_size + 8;
                            if total_size >= 12 && total_size <= sig.max_size && pos + (total_size as usize) <= buffer.len() {
                                let end_idx = pos + (total_size as usize);
                                let file_data = buffer[pos..end_idx].to_vec();
                                hits.push((
                                    sig.name.to_string(),
                                    sig.extension.to_string(),
                                    start_offset,
                                    base_offset + end_idx as u64,
                                    file_data,
                                ));
                                pos = end_idx;
                                continue;
                            }
                        }
                    }
                    pos += 1;
                }
                "pdf" => {
                    // PDF: Verify %PDF-1. or %PDF-2. version byte
                    if pos + 7 <= buffer.len() && (buffer[pos + 5] == b'1' || buffer[pos + 5] == b'2') {
                        let mut last_eof = None;
                        let curr_search_pos = pos + hdr_len;
                        while curr_search_pos < max_search {
                            if let Some(rel_pdf) = find_subsequence(&buffer[curr_search_pos..max_search], b"%PDF-") {
                                // Another PDF begins here; search for %%EOF before this boundary
                                if let Some(rel_eof) = find_last_subsequence(&buffer[pos..curr_search_pos + rel_pdf], b"%%EOF") {
                                    last_eof = Some(pos + rel_eof + 5);
                                }
                                break;
                            } else {
                                if let Some(rel_eof) = find_last_subsequence(&buffer[pos..max_search], b"%%EOF") {
                                    last_eof = Some(pos + rel_eof + 5);
                                }
                                break;
                            }
                        }
                        if let Some(mut end_idx) = last_eof {
                            while end_idx < buffer.len() && (buffer[end_idx] == b'\r' || buffer[end_idx] == b'\n' || buffer[end_idx] == b' ') && end_idx - last_eof.unwrap() < 10 {
                                end_idx += 1;
                            }
                            if end_idx <= buffer.len() && end_idx > pos {
                                let file_data = buffer[pos..end_idx].to_vec();
                                hits.push((
                                    sig.name.to_string(),
                                    sig.extension.to_string(),
                                    start_offset,
                                    base_offset + end_idx as u64,
                                    file_data,
                                ));
                                pos = end_idx;
                                continue;
                            }
                        }
                    }
                    pos += 1;
                }
                "zip" => {
                    // ZIP / Office OpenXML: Locate exact End of Central Directory (PK\x05\x06) and comment length
                    if pos + 22 < max_search {
                        let search_slice = &buffer[pos + 4..max_search];
                        if let Some(rel_eocd) = find_last_subsequence(search_slice, &[0x50, 0x4B, 0x05, 0x06]) {
                            let eocd_pos = pos + 4 + rel_eocd;
                            if eocd_pos + 22 <= buffer.len() {
                                let comment_len = u16::from_le_bytes([buffer[eocd_pos + 20], buffer[eocd_pos + 21]]) as usize;
                                let end_idx = eocd_pos + 22 + comment_len;
                                if end_idx <= buffer.len() && end_idx > pos {
                                    let file_data = buffer[pos..end_idx].to_vec();
                                    hits.push((
                                        sig.name.to_string(),
                                        sig.extension.to_string(),
                                        start_offset,
                                        base_offset + end_idx as u64,
                                        file_data,
                                    ));
                                    pos = end_idx;
                                    continue;
                                }
                            }
                        }
                    }
                    pos += 1;
                }
                "sqlite" => {
                    // SQLite: Exact page_size * page_count calculation from database header bytes
                    if pos + 32 <= buffer.len() {
                        let page_size_raw = u16::from_be_bytes([buffer[pos + 16], buffer[pos + 17]]);
                        let page_size = if page_size_raw == 1 { 65536u64 } else { page_size_raw as u64 };
                        let page_count = u32::from_be_bytes([
                            buffer[pos + 28], buffer[pos + 29], buffer[pos + 30], buffer[pos + 31]
                        ]) as u64;
                        if page_size >= 512 && page_size <= 65536 && (page_size & (page_size - 1) == 0) && page_count > 0 {
                            let total_size = page_size * page_count;
                            if total_size >= 512 && total_size <= sig.max_size && pos + (total_size as usize) <= buffer.len() {
                                let end_idx = pos + (total_size as usize);
                                let file_data = buffer[pos..end_idx].to_vec();
                                hits.push((
                                    sig.name.to_string(),
                                    sig.extension.to_string(),
                                    start_offset,
                                    base_offset + end_idx as u64,
                                    file_data,
                                ));
                                pos = end_idx;
                                continue;
                            }
                        }
                    }
                    pos += 1;
                }
                "evtx" => {
                    // EVTX: ElfFile header (4096 bytes) + exact chunk_count * 65536 calculation
                    if pos + 44 <= buffer.len() {
                        let chunk_count = u16::from_le_bytes([buffer[pos + 42], buffer[pos + 43]]) as u64;
                        if chunk_count > 0 && chunk_count <= 20000 {
                            let total_size = 4096 + (chunk_count * 65536);
                            if total_size <= sig.max_size && pos + (total_size as usize) <= buffer.len() {
                                let end_idx = pos + (total_size as usize);
                                let file_data = buffer[pos..end_idx].to_vec();
                                hits.push((
                                    sig.name.to_string(),
                                    sig.extension.to_string(),
                                    start_offset,
                                    base_offset + end_idx as u64,
                                    file_data,
                                ));
                                pos = end_idx;
                                continue;
                            }
                        }
                    }
                    pos += 1;
                }
                _ => {
                    // Fallback for custom/unknown signatures using footer if provided
                    if let Some(footer_bytes) = sig.footer {
                        if pos + hdr_len < max_search {
                            let search_slice = &buffer[pos + hdr_len..max_search];
                            if let Some(rel_end) = find_subsequence(search_slice, footer_bytes) {
                                let end_idx = pos + hdr_len + rel_end + footer_bytes.len();
                                if end_idx <= buffer.len() {
                                    let file_data = buffer[pos..end_idx].to_vec();
                                    hits.push((
                                        sig.name.to_string(),
                                        sig.extension.to_string(),
                                        start_offset,
                                        base_offset + end_idx as u64,
                                        file_data,
                                    ));
                                    pos = end_idx;
                                    continue;
                                }
                            }
                        }
                    }
                    let slice_len = std::cmp::min(buffer.len() - pos, 65536);
                    if slice_len > 0 && pos + slice_len <= buffer.len() {
                        let file_data = buffer[pos..pos + slice_len].to_vec();
                        hits.push((
                            sig.name.to_string(),
                            sig.extension.to_string(),
                            start_offset,
                            start_offset + slice_len as u64,
                            file_data,
                        ));
                        pos += slice_len;
                    } else {
                        pos += 1;
                    }
                }
            }
        }
    }
    hits
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_last_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Multi-Threaded Parallel Carving Engine using Rayon (Batched Streaming)
pub fn run_parallel_carving(
    image_path: &Path,
    out_dir: &Path,
    chunk_size: usize,
    overlap_size: usize,
    progress_callback: Option<Arc<dyn Fn(u64, u64, usize) + Send + Sync>>,
) -> Result<Vec<CarvedFileRecord>, String> {
    let mut file = File::open(image_path).map_err(|e| format!("Failed to open image file: {}", e))?;
    let total_bytes = file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;

    fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;

    let signatures = get_default_signatures();
    let bytes_processed = Arc::new(AtomicU64::new(0));
    let files_found = Arc::new(AtomicUsize::new(0));
    let carved_records = Arc::new(Mutex::new(Vec::new()));

    let mut current_offset = 0u64;
    let mut chunk_idx = 0;
    // Process in batches of 16 chunks (~256 MB max memory) so we never OOM on massive .dd files
    let batch_limit = 16;

    while current_offset < total_bytes {
        let mut batch_chunks = Vec::with_capacity(batch_limit);

        for _ in 0..batch_limit {
            if current_offset >= total_bytes {
                break;
            }
            let read_len = std::cmp::min(chunk_size as u64, total_bytes - current_offset) as usize;
            if read_len == 0 {
                break;
            }
            let mut buf = vec![0u8; read_len];
            file.seek(SeekFrom::Start(current_offset)).map_err(|e| e.to_string())?;
            match file.read(&mut buf) {
                Ok(0) => break, // EOF reached or unaligned device bound
                Ok(n) => {
                    buf.truncate(n);
                    batch_chunks.push(CarveChunkJob {
                        chunk_index: chunk_idx,
                        base_offset: current_offset,
                        buffer: buf,
                    });
                    chunk_idx += 1;
                    if current_offset + n as u64 >= total_bytes {
                        current_offset = total_bytes;
                        break;
                    }
                    let step = if n > overlap_size { n - overlap_size } else { n };
                    if step == 0 {
                        current_offset = total_bytes;
                        break;
                    }
                    current_offset += step as u64;
                }
                Err(_) => {
                    break;
                }
            }
        }

        if batch_chunks.is_empty() {
            break;
        }

        // Parallelize chunk batch processing across Rayon thread pool
        batch_chunks.into_par_iter().for_each(|job| {
            let hits = scan_buffer_signatures(job.base_offset, &job.buffer, &signatures);
            for (file_type, ext, start_off, end_off, data) in hits {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let sha256 = format!("{:x}", hasher.finalize());

                let filename = format!("carved_{:08x}.{}", start_off, ext);
                let save_path = out_dir.join(&filename);
                if let Ok(mut f) = File::create(&save_path) {
                    let _ = f.write_all(&data);
                }

                let rec = CarvedFileRecord {
                    file_type,
                    extension: ext,
                    offset_start: start_off,
                    offset_end: end_off,
                    file_size: data.len() as u64,
                    sha256_hash: sha256,
                    output_path: save_path.display().to_string(),
                    carved_time: chrono::Utc::now().to_rfc3339(),
                };

                if let Ok(mut lock) = carved_records.lock() {
                    lock.push(rec);
                }
                files_found.fetch_add(1, Ordering::Relaxed);
            }

            bytes_processed.fetch_add(job.buffer.len() as u64, Ordering::Relaxed);
            if let Some(ref cb) = progress_callback {
                cb(
                    bytes_processed.load(Ordering::Relaxed),
                    total_bytes,
                    files_found.load(Ordering::Relaxed),
                );
            }
        });
    }

    let mut results = carved_records.lock().map_err(|e| e.to_string())?.clone();
    results.sort_by_key(|r| r.offset_start);
    results.dedup_by_key(|r| r.offset_start);
    Ok(results)
}

/// Benchmark Single-Threaded vs Multi-Threaded Rayon Carving Engine
pub fn benchmark_carving_engine(sample_size_bytes: usize) -> CarverBenchmarkResult {
    // Generate synthetic forensic test image containing embedded JPEGs, PNGs, PDFs, and random filler
    let mut synthetic_buf = vec![0u8; sample_size_bytes];
    // Fill with pseudo-random noise
    for (i, byte) in synthetic_buf.iter_mut().enumerate() {
        *byte = ((i * 1103515245 + 12345) % 256) as u8;
    }

    // Embed 4 sample JPEGs and 4 sample PDFs at various offsets
    let jpeg_sample = [
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00,
        0x60, 0x00, 0x60, 0x00, 0x00, 0xFF, 0xD9,
    ];
    let pdf_sample = b"%PDF-1.4 sample content\n%%EOF";

    let step = sample_size_bytes / 10;
    for i in 1..=8 {
        let offset = i * step;
        if offset + jpeg_sample.len() < synthetic_buf.len() && i % 2 == 0 {
            synthetic_buf[offset..offset + jpeg_sample.len()].copy_from_slice(&jpeg_sample);
        } else if offset + pdf_sample.len() < synthetic_buf.len() {
            synthetic_buf[offset..offset + pdf_sample.len()].copy_from_slice(pdf_sample);
        }
    }

    let signatures = get_default_signatures();

    // 1. Single-Threaded Sequential Baseline
    let t0 = Instant::now();
    let st_hits = scan_buffer_signatures(0, &synthetic_buf, &signatures);
    let st_dur = t0.elapsed().as_millis();

    // 2. Multi-Threaded Rayon Chunk Carving
    let t1 = Instant::now();
    let chunk_size = std::cmp::max(sample_size_bytes / 8, 4096);
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < synthetic_buf.len() {
        let end = std::cmp::min(offset + chunk_size, synthetic_buf.len());
        chunks.push((offset as u64, synthetic_buf[offset..end].to_vec()));
        offset = end;
    }

    let mt_hits: Vec<_> = chunks
        .into_par_iter()
        .flat_map(|(base_off, buf)| scan_buffer_signatures(base_off, &buf, &signatures))
        .collect();
    let mt_dur = t1.elapsed().as_millis();

    let speedup = if mt_dur > 0 {
        st_dur as f64 / mt_dur as f64
    } else {
        st_dur as f64
    };

    let mb_sec = if mt_dur > 0 {
        (sample_size_bytes as f64 / (1024.0 * 1024.0)) / (mt_dur as f64 / 1000.0)
    } else {
        0.0
    };

    CarverBenchmarkResult {
        total_bytes: sample_size_bytes as u64,
        single_thread_duration_ms: st_dur,
        multi_thread_duration_ms: mt_dur,
        speedup_factor: speedup,
        files_carved: mt_hits.len().max(st_hits.len()),
        throughput_mb_per_sec: mb_sec,
    }
}

pub fn save_carved_records_to_db(db: &Connection, records: &[CarvedFileRecord]) -> rusqlite::Result<usize> {
    let mut count = 0;
    for rec in records {
        db.execute(
            "INSERT INTO carved_files (file_type, extension, offset_start, offset_end, file_size, sha256_hash, output_path, carved_time) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                rec.file_type,
                rec.extension,
                rec.offset_start as i64,
                rec.offset_end as i64,
                rec.file_size as i64,
                rec.sha256_hash,
                rec.output_path,
                rec.carved_time
            ],
        )?;
        count += 1;
    }
    Ok(count)
}
