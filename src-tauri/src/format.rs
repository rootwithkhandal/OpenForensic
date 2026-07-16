use std::io::{Seek, Write};
use std::path::Path;
use std::fs::File;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;
use uuid::Uuid;

pub trait FormatWriter: Send {
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
    fn flush(&mut self) -> std::io::Result<()>;
    fn finalize(&mut self) -> std::io::Result<()>;
}

/// AFF4 Format Writer (Pure Rust)
/// Implements a Zip64 container with RDF/Turtle metadata and Deflate compression.
pub struct Aff4Writer {
    zip: ZipWriter<File>,
}

impl Aff4Writer {
    pub fn new(path: &Path, case_number: &str, examiner: &str, notes: &str) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);
        
        // Generate a unique URN for this image
        let uuid = Uuid::new_v4();
        let urn = format!("urn:uuid:{}", uuid);

        // Write the metadata (information.turtle)
        let turtle_content = format!(
            "@prefix aff4: <http://aff4.org/Schema#> .\n\
             <urn:aff4:volume> a aff4:ZipVolume .\n\
             <{urn}> a aff4:ImageStream ;\n\
             aff4:case_number \"{case_number}\" ;\n\
             aff4:examiner \"{examiner}\" ;\n\
             aff4:notes \"{notes}\" .\n",
            urn = urn, case_number = case_number, examiner = examiner, notes = notes
        );

        let options = FileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .large_file(false);
        zip.start_file("information.turtle", options)?;
        zip.write_all(turtle_content.as_bytes())?;

        // Start the image data stream
        let stream_options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .large_file(true); // Zip64 for large evidence
        zip.start_file("image.dd", stream_options)?;

        Ok(Self { zip })
    }
}

impl FormatWriter for Aff4Writer {
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.zip.write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.zip.flush()
    }

    fn finalize(&mut self) -> std::io::Result<()> {
        self.zip.finish()?;
        Ok(())
    }
}

/// E01/EWF Format Writer (Sectioned Expert Witness Format implementation)
/// Outputs valid EVF magic signature, section descriptors (header, volume, data),
/// and sector chunk integrity checksums (Adler32 / CRC32).
pub struct EwfWriter {
    file: File,
    bytes_written: u64,
    chunk_buffer: Vec<u8>,
    chunk_size: usize,
    chunk_count: u64,
    table_offsets: Vec<u64>,
}

impl EwfWriter {
    pub fn new(path: &Path, case_number: &str, examiner: &str, evidence_id: &str, notes: &str) -> std::io::Result<Self> {
        let mut file = File::create(path)?;
        
        // 1. Write EVF File Header Magic: "EVF\x09\r\n\xff\0" (8 bytes) + flags (5 bytes)
        let mut evf_magic = [0u8; 13];
        evf_magic[0..8].copy_from_slice(b"EVF\x09\r\n\xff\0");
        evf_magic[8] = 0x01; // start of sections
        file.write_all(&evf_magic)?;

        // Helper to write a section header: type_name (16 bytes), next_offset (u64), size (u64), crc32 (u32)
        let write_section_header = |f: &mut File, name: &str, next_off: u64, size: u64, data: &[u8]| -> std::io::Result<()> {
            let mut type_buf = [0u8; 16];
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(15);
            type_buf[..len].copy_from_slice(&name_bytes[..len]);

            let mut header_buf = Vec::with_capacity(32 + data.len() + 4);
            header_buf.extend_from_slice(&type_buf);
            header_buf.extend_from_slice(&next_off.to_le_bytes());
            header_buf.extend_from_slice(&size.to_le_bytes());
            
            let header_crc = crc32fast::hash(&header_buf[..32]);
            header_buf.extend_from_slice(&header_crc.to_le_bytes());
            header_buf.extend_from_slice(data);
            
            let data_crc = crc32fast::hash(data);
            header_buf.extend_from_slice(&data_crc.to_le_bytes());

            f.write_all(&header_buf)
        };

        // 2. Write 'header' section (ASCII metadata payload)
        let metadata_payload = format!(
            "case_number\t{}\nexaminer_name\t{}\nevidence_number\t{}\nnotes\t{}\n",
            case_number, examiner, evidence_id, notes
        );
        let meta_bytes = metadata_payload.as_bytes();
        let meta_size = (32 + meta_bytes.len() + 4) as u64;
        write_section_header(&mut file, "header", 13 + meta_size, meta_size, meta_bytes)?;

        // 3. Write 'volume' section (media properties, chunk size 32768 bytes = 64 sectors)
        let mut vol_payload = [0u8; 1056];
        vol_payload[0..4].copy_from_slice(&(1u32).to_le_bytes()); // media type: fixed disk
        vol_payload[4..8].copy_from_slice(&(64u32).to_le_bytes()); // sectors per chunk
        vol_payload[8..12].copy_from_slice(&(512u32).to_le_bytes()); // bytes per sector
        let vol_size = (32 + vol_payload.len() + 4) as u64;
        let current_pos = file.stream_position()?;
        write_section_header(&mut file, "volume", current_pos + vol_size, vol_size, &vol_payload)?;

        Ok(Self {
            file,
            bytes_written: 0,
            chunk_buffer: Vec::with_capacity(32768),
            chunk_size: 32768,
            chunk_count: 0,
            table_offsets: Vec::new(),
        })
    }

    fn flush_chunk(&mut self) -> std::io::Result<()> {
        if self.chunk_buffer.is_empty() {
            return Ok(());
        }
        let chunk_pos = self.file.stream_position()?;
        self.table_offsets.push(chunk_pos);

        // Compute Adler32 checksum of chunk payload
        let mut adler: u32 = 1;
        let (mut s1, mut s2) = (adler & 0xffff, (adler >> 16) & 0xffff);
        for &byte in &self.chunk_buffer {
            s1 = (s1 + byte as u32) % 65521;
            s2 = (s2 + s1) % 65521;
        }
        adler = (s2 << 16) | s1;

        // Write raw chunk data followed by 4-byte Adler32
        self.file.write_all(&self.chunk_buffer)?;
        self.file.write_all(&adler.to_le_bytes())?;
        
        self.chunk_count += 1;
        self.chunk_buffer.clear();
        Ok(())
    }
}

impl FormatWriter for EwfWriter {
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut remaining = buf;
        while !remaining.is_empty() {
            let needed = self.chunk_size - self.chunk_buffer.len();
            let to_take = remaining.len().min(needed);
            self.chunk_buffer.extend_from_slice(&remaining[..to_take]);
            remaining = &remaining[to_take..];
            self.bytes_written += to_take as u64;

            if self.chunk_buffer.len() == self.chunk_size {
                self.flush_chunk()?;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_chunk()?;
        self.file.flush()
    }

    fn finalize(&mut self) -> std::io::Result<()> {
        self.flush_chunk()?;

        // Write 'table' section containing offset table of all chunks
        let mut table_payload = Vec::with_capacity(self.table_offsets.len() * 8 + 24);
        table_payload.extend_from_slice(&(self.chunk_count as u32).to_le_bytes());
        for &off in &self.table_offsets {
            table_payload.extend_from_slice(&off.to_le_bytes());
        }
        let table_crc = crc32fast::hash(&table_payload);
        table_payload.extend_from_slice(&table_crc.to_le_bytes());

        let mut type_buf = [0u8; 16];
        type_buf[..5].copy_from_slice(b"table");
        let next_off = self.file.stream_position()? + (32 + table_payload.len() + 4) as u64;
        let mut header_buf = Vec::new();
        header_buf.extend_from_slice(&type_buf);
        header_buf.extend_from_slice(&next_off.to_le_bytes());
        header_buf.extend_from_slice(&(table_payload.len() as u64 + 36).to_le_bytes());
        let h_crc = crc32fast::hash(&header_buf[..32]);
        header_buf.extend_from_slice(&h_crc.to_le_bytes());
        header_buf.extend_from_slice(&table_payload);
        let d_crc = crc32fast::hash(&table_payload);
        header_buf.extend_from_slice(&d_crc.to_le_bytes());
        self.file.write_all(&header_buf)?;

        // Write 'done' section descriptor
        let mut done_buf = [0u8; 36];
        done_buf[0..4].copy_from_slice(b"done");
        let done_crc = crc32fast::hash(&done_buf[..32]);
        done_buf[32..36].copy_from_slice(&done_crc.to_le_bytes());
        self.file.write_all(&done_buf)?;

        self.file.flush()
    }
}
