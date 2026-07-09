use rayon::prelude::*;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
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
        FileSignature {
            name: "JPEG Image",
            extension: "jpg",
            header: &[0xFF, 0xD8, 0xFF],
            footer: Some(&[0xFF, 0xD9]),
            max_size: 25 * 1024 * 1024,
        },
        FileSignature {
            name: "PNG Image",
            extension: "png",
            header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
            max_size: 50 * 1024 * 1024,
        },
        FileSignature {
            name: "PDF Document",
            extension: "pdf",
            header: b"%PDF-",
            footer: Some(b"%%EOF"),
            max_size: 100 * 1024 * 1024,
        },
        FileSignature {
            name: "ZIP / Office OpenXML",
            extension: "zip",
            header: &[0x50, 0x4B, 0x03, 0x04],
            footer: None,
            max_size: 200 * 1024 * 1024,
        },
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
            max_size: 100 * 1024 * 1024,
        },
    ]
}

pub struct CarveChunkJob {
    pub chunk_index: usize,
    pub base_offset: u64,
    pub buffer: Vec<u8>,
}

/// Scan a memory/file buffer for signatures single-threaded
pub fn scan_buffer_signatures(
    base_offset: u64,
    buffer: &[u8],
    signatures: &[FileSignature],
) -> Vec<(String, String, u64, u64, Vec<u8>)> {
    let mut hits = Vec::new();

    for sig in signatures {
        let hdr_len = sig.header.len();
        if buffer.len() < hdr_len { continue; }

        let mut pos = 0;
        while pos + hdr_len <= buffer.len() {
            if &buffer[pos..pos + hdr_len] == sig.header {
                let start_offset = base_offset + pos as u64;
                let max_search = std::cmp::min(buffer.len(), pos + sig.max_size as usize);

                if let Some(footer_bytes) = sig.footer {
                    let f_len = footer_bytes.len();
                    let mut found_footer = false;
                    let search_slice = &buffer[pos + hdr_len..max_search];
                    if let Some(rel_end) = find_subsequence(search_slice, footer_bytes) {
                        let end_idx = pos + hdr_len + rel_end + f_len;
                        let file_data = buffer[pos..end_idx].to_vec();
                        let end_offset = base_offset + end_idx as u64;
                        hits.push((
                            sig.name.to_string(),
                            sig.extension.to_string(),
                            start_offset,
                            end_offset,
                            file_data,
                        ));
                        pos = end_idx;
                        found_footer = true;
                    }
                    if !found_footer {
                        pos += 1;
                    }
                } else {
                    // Fixed fallback size extraction when no footer is defined (e.g. 64KB slice or header match)
                    let slice_len = std::cmp::min(buffer.len() - pos, 65536);
                    let file_data = buffer[pos..pos + slice_len].to_vec();
                    hits.push((
                        sig.name.to_string(),
                        sig.extension.to_string(),
                        start_offset,
                        start_offset + slice_len as u64,
                        file_data,
                    ));
                    pos += slice_len;
                }
            } else {
                pos += 1;
            }
        }
    }
    hits
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Multi-Threaded Parallel Carving Engine using Rayon
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

    // Prepare chunks
    let mut chunks = Vec::new();
    let mut current_offset = 0u64;
    let mut chunk_idx = 0;

    while current_offset < total_bytes {
        let read_len = std::cmp::min(chunk_size as u64, total_bytes - current_offset) as usize;
        let mut buf = vec![0u8; read_len];
        file.seek(SeekFrom::Start(current_offset)).map_err(|e| e.to_string())?;
        if let Ok(n) = file.read(&mut buf) {
            buf.truncate(n);
            chunks.push(CarveChunkJob {
                chunk_index: chunk_idx,
                base_offset: current_offset,
                buffer: buf,
            });
            chunk_idx += 1;
            if current_offset + n as u64 >= total_bytes {
                break;
            }
            // Advance by chunk_size minus overlap
            let step = if n > overlap_size { n - overlap_size } else { n };
            current_offset += step as u64;
        } else {
            break;
        }
    }

    let signatures = get_default_signatures();
    let bytes_processed = Arc::new(AtomicU64::new(0));
    let files_found = Arc::new(AtomicUsize::new(0));
    let carved_records = Arc::new(Mutex::new(Vec::new()));

    // Parallelize chunk processing across Rayon thread pool
    chunks.into_par_iter().for_each(|job| {
        let hits = scan_buffer_signatures(job.base_offset, &job.buffer, &signatures);
        for (file_type, ext, start_off, end_off, data) in hits {
            // Compute sha256
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
