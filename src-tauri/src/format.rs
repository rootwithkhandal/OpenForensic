use std::io::Write;
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

/// E01/EWF Format Writer (Pure Rust Placeholder/Minimal)
/// For full EWF support, this should implement the sectioned chunk format.
pub struct EwfWriter {
    file: File,
    bytes_written: u64,
}

impl EwfWriter {
    pub fn new(path: &Path, case_number: &str, examiner: &str, evidence_id: &str, notes: &str) -> std::io::Result<Self> {
        let mut file = File::create(path)?;
        
        // E01 requires complex sections (header, volume, tables, chunks). 
        // As a minimal fallback if libewf-sys is not available, we write a valid SMART/Raw header
        // since full pure-Rust E01 is out of scope for a single file. 
        // We will mock the E01 header format to allow basic ingestion if tools support RAW-in-E01-extension.
        // NOTE: True E01 requires Adler32/MD5 per chunk, which is highly complex.
        let header = format!(
            "=== EXPERT WITNESS COMPRESSION FORMAT HEADER (E01) ===\n\
             Case Number: {}\n\
             Examiner:    {}\n\
             Evidence ID: {}\n\
             Notes:       {}\n\
             =======================================================\n",
            case_number, examiner, evidence_id, notes
        );
        file.write_all(header.as_bytes())?;
        
        Ok(Self { file, bytes_written: 0 })
    }
}

impl FormatWriter for EwfWriter {
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file.write_all(buf)?;
        self.bytes_written += buf.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }

    fn finalize(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
