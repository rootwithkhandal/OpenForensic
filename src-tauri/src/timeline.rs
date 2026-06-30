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
    if partition_offsets.is_empty() || partition_offsets.len() == 1 {
        if let Ok(gpt) = GptConfig::new().open(image_path) {
            for (_, p) in gpt.partitions() {
                partition_offsets.push(p.first_lba * 512);
            }
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
            if let Ok(mft_file) = ntfs.file(&mut reader, 0) {
                if let Some(Ok(item)) = mft_file.data(&mut reader, "") {
                    if let Ok(attr) = item.to_attribute() {
                        if let Ok(mut data_val) = attr.value(&mut reader) {
                        if let Ok(mut out_file) = File::create(&extracted_mft_path) {
                            let mut buf = vec![0; 4096];
                            loop {
                                let n = match data_val.read(&mut reader, &mut buf) {
                                    Ok(n) => n,
                                    Err(_) => break,
                                };
                                if n == 0 { break; }
                                let _ = out_file.write_all(&buf[..n]);
                            }
                        }
                        }
                    }
                }
            }

            // Parse MFT if extracted
            if extracted_mft_path.exists() {
                if let Ok(mut parser) = MftParser::from_path(&extracted_mft_path) {
                    for entry in parser.iter_entries() {
                        if let Ok(e) = entry {
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
        }
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
