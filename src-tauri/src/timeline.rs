use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use mbrman::MBR;
use gpt::GptConfig;
use mft::MftParser;
use ntfs::NtfsReadSeek;
use csv::Writer;

use serde::Serialize;
use crate::error::Result;

#[derive(Serialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub source: String,
    pub event_type: String, // e.g., "MFT_Creation", "MFT_Modification", etc.
    pub file_path: String,
    pub details: String,
}

pub struct OffsetReader {
    inner: File,
    offset: u64,
}

impl OffsetReader {
    pub fn new(mut inner: File, offset: u64) -> io::Result<Self> {
        inner.seek(SeekFrom::Start(offset))?;
        Ok(Self { inner, offset })
    }
}

impl Read for OffsetReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for OffsetReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => self.inner.seek(SeekFrom::Start(self.offset + p)).map(|x| x - self.offset),
            SeekFrom::Current(p) => self.inner.seek(SeekFrom::Current(p)).map(|x| x - self.offset),
            SeekFrom::End(_) => Err(io::Error::new(io::ErrorKind::Unsupported, "SeekFrom::End not supported")),
        }
    }
}

pub async fn generate_timeline(image_path: &Path, output_dir: &Path) -> Result<()> {
    let mut events = Vec::new();

    // Try parsing as MBR first
    let mut file = File::open(image_path)?;
    let mut partition_offsets = Vec::new();
    
    // Attempt MBR
    if let Ok(mbr) = MBR::read_from(&mut file, 512) {
        for (_, p) in mbr.iter() {
            if p.is_used() {
                partition_offsets.push(p.starting_lba as u64 * 512);
            }
        }
    }
    
    // Attempt GPT if MBR fails or is protective
    if (partition_offsets.is_empty() || partition_offsets.len() == 1)
        && let Ok(gpt) = GptConfig::new().open(image_path)
    {
        for p in gpt.partitions().values() {
            partition_offsets.push(p.first_lba * 512);
        }
    }
    
    // If no partitions found, maybe it's a raw filesystem image (offset 0)
    if partition_offsets.is_empty() {
        partition_offsets.push(0);
    }

    for offset in partition_offsets {
        let mut reader = match OffsetReader::new(File::open(image_path)?, offset) {
            Ok(r) => r,
            Err(_) => continue,
        };
        
        // Attempt to parse as NTFS
        if let Ok(ntfs) = ntfs::Ntfs::new(&mut reader) {
            let extracted_mft_path = output_dir.join(format!("extracted_mft_{}.bin", offset));
            
            // Extract $MFT
            if let Ok(mft_file) = ntfs.file(&mut reader, 0)
                && let Some(Ok(item)) = mft_file.data(&mut reader, "")
                && let Ok(attr) = item.to_attribute()
                && let Ok(mut data_val) = attr.value(&mut reader)
                && let Ok(mut out_file) = File::create(&extracted_mft_path)
            {
                let mut buf = vec![0; 4096];
                while let Ok(n) = data_val.read(&mut reader, &mut buf) {
                    if n == 0 { break; }
                    let _ = out_file.write_all(&buf[..n]);
                }
            }

            // Parse MFT if extracted
            if extracted_mft_path.exists()
                && let Ok(mut parser) = MftParser::from_path(&extracted_mft_path)
            {
                for e in parser.iter_entries().flatten() {
                    let path = "".to_string(); // In a real implementation we'd reconstruct the full path
                    
                    // Get MACB timestamps from Standard Information
                    for attr in e.iter_attributes().filter_map(|a| a.ok()) {
                        if let mft::attribute::MftAttributeContent::AttrX10(ref si) = attr.data {
                            events.push(TimelineEvent {
                                timestamp: si.created.to_string(),
                                source: "MFT".to_string(),
                                event_type: "Creation".to_string(),
                                file_path: path.clone(),
                                details: "Standard Information".to_string()
                            });
                            events.push(TimelineEvent {
                                timestamp: si.modified.to_string(),
                                source: "MFT".to_string(),
                                event_type: "Modification".to_string(),
                                file_path: path.clone(),
                                details: "Standard Information".to_string()
                            });
                            events.push(TimelineEvent {
                                timestamp: si.accessed.to_string(),
                                source: "MFT".to_string(),
                                event_type: "Access".to_string(),
                                file_path: path.clone(),
                                details: "Standard Information".to_string()
                            });
                            events.push(TimelineEvent {
                                timestamp: si.mft_modified.to_string(),
                                source: "MFT".to_string(),
                                event_type: "MFT Modified".to_string(),
                                file_path: path.clone(),
                                details: "Standard Information".to_string()
                            });
                        }
                        
                        if let mft::attribute::MftAttributeContent::AttrX30(ref fn_attr) = attr.data {
                            let filename = fn_attr.name.clone();
                            events.push(TimelineEvent {
                                timestamp: fn_attr.created.to_string(),
                                source: "MFT".to_string(),
                                event_type: "Creation (FileName)".to_string(),
                                file_path: filename.clone(),
                                details: "FileName Attribute".to_string()
                            });
                            events.push(TimelineEvent {
                                timestamp: fn_attr.modified.to_string(),
                                source: "MFT".to_string(),
                                event_type: "Modification (FileName)".to_string(),
                                file_path: filename.clone(),
                                details: "FileName Attribute".to_string()
                            });
                        }
                    }
                }
            }
        }
    }

    let triage_db_path = output_dir.join("triage.db");
    if let Ok(conn) = rusqlite::Connection::open_with_flags(&triage_db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
        add_triage_execution_events(&conn, &mut events);
    }

    // Sort events by timestamp
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Output to CSV
    let csv_path = output_dir.join("timeline.csv");
    let mut wtr = Writer::from_path(&csv_path)?;
    for e in &events {
        wtr.serialize(e)?;
    }
    wtr.flush()?;

    // Output to JSON
    let json_path = output_dir.join("timeline.json");
    let json_file = File::create(&json_path)?;
    serde_json::to_writer_pretty(json_file, &events)?;

    Ok(())
}

pub fn add_triage_execution_events(db: &rusqlite::Connection, events: &mut Vec<TimelineEvent>) {
    if let Ok(mut stmt) = db.prepare("SELECT executable_name, file_path, last_run_time, run_count FROM prefetch_executions") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
            ))
        }) {
            for r in rows.flatten() {
                let (name, path, ts_str, count) = r;
                for ts in ts_str.split(", ") {
                    let trim_ts = ts.trim();
                    if !trim_ts.is_empty() && trim_ts != "Unknown" {
                        events.push(TimelineEvent {
                            timestamp: trim_ts.to_string(),
                            source: "Prefetch".to_string(),
                            event_type: "Execution".to_string(),
                            file_path: if path.is_empty() { name.clone() } else { path.clone() },
                            details: format!("Run Count: {}", count),
                        });
                    }
                }
            }
        }
    }

    if let Ok(mut stmt) = db.prepare("SELECT source_type, file_path, last_modified_time, install_date, publisher FROM amcache_entries") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }) {
            for r in rows.flatten() {
                let (source, path, mod_time, install_time, pub_name) = r;
                if !mod_time.is_empty() && mod_time != "N/A" && mod_time != "Unknown" {
                    events.push(TimelineEvent {
                        timestamp: mod_time.clone(),
                        source: source.clone(),
                        event_type: "Last Modified / Execution Cached".to_string(),
                        file_path: path.clone(),
                        details: format!("Publisher: {}", pub_name),
                    });
                }
                if !install_time.is_empty() && install_time != "N/A" && install_time != "Unknown" {
                    events.push(TimelineEvent {
                        timestamp: install_time.clone(),
                        source: source.clone(),
                        event_type: "Install / Link Date".to_string(),
                        file_path: path.clone(),
                        details: format!("Publisher: {}", pub_name),
                    });
                }
            }
        }
    }

    if let Ok(mut stmt) = db.prepare("SELECT browser_name, url, title, visit_time FROM browser_history") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        }) {
            for r in rows.flatten() {
                let (b_name, url, title, time) = r;
                if !time.is_empty() && time != "0" {
                    events.push(TimelineEvent {
                        timestamp: time,
                        source: format!("Browser History ({})", b_name),
                        event_type: "Web Visit".to_string(),
                        file_path: url,
                        details: title,
                    });
                }
            }
        }
    }

    if let Ok(mut stmt) = db.prepare("SELECT browser_name, target_path, url, start_time, state FROM browser_downloads") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }) {
            for r in rows.flatten() {
                let (b_name, target_path, url, time, state) = r;
                if !time.is_empty() && time != "0" {
                    events.push(TimelineEvent {
                        timestamp: time,
                        source: format!("Browser Download ({})", b_name),
                        event_type: "File Download".to_string(),
                        file_path: target_path,
                        details: format!("Source URL: {} | Status: {}", url, state),
                    });
                }
            }
        }
    }

    if let Ok(mut stmt) = db.prepare("SELECT packet_timestamp, src_ip, dst_ip, dst_port, protocol, info, correlated_process_name, risk_flags FROM pcap_capture_packets") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i32>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        }) {
            for r in rows.flatten() {
                let (time, _src, dst, dport, proto, info, proc_name, risk) = r;
                if !time.is_empty() {
                    events.push(TimelineEvent {
                        timestamp: time,
                        source: "Live PCAP Network Capture".to_string(),
                        event_type: format!("Network Flow ({})", proto),
                        file_path: format!("{}:{}", dst, dport),
                        details: format!("Process: {} | {} | Risk: {}", proc_name, info, risk),
                    });
                }
            }
        }
    }

    if let Ok(mut stmt) = db.prepare("SELECT category, severity, artifact_path, details, detection_timestamp FROM anti_forensics_alerts") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }) {
            for r in rows.flatten() {
                let (cat, sev, path, details, time) = r;
                if !time.is_empty() {
                    events.push(TimelineEvent {
                        timestamp: time,
                        source: format!("Anti-Forensics Audit ({})", sev),
                        event_type: cat,
                        file_path: path,
                        details,
                    });
                }
            }
        }
    }
}
