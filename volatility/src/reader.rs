//! Memory dump reader with buffered streaming and signature/pattern scanning.
//!
//! Supports raw files (`.raw`, `.dmp`, `.vmem`, `.bin`, `.dd`).
//! The reader memory-maps or streams the file in configurable block sizes
//! and exposes helpers for scanning byte patterns (pool tags, magic numbers).

use crate::error::{Result, VolatilityError};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Default block size for streaming reads (4 MB).
const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// A handle to an opened memory dump file.
pub struct MemoryReader {
    file: File,
    pub path: PathBuf,
    pub size: u64,
    block_size: usize,
}

impl MemoryReader {
    /// Open a memory dump file for analysis.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();

        if size == 0 {
            return Err(VolatilityError::InvalidImage(
                "Memory dump file is empty".to_string(),
            ));
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
            size,
            block_size: DEFAULT_BLOCK_SIZE,
        })
    }

    /// Read a block of bytes at the given offset.
    /// Returns the actual number of bytes read (may be less at end of file).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.file.seek(SeekFrom::Start(offset))?;
        let n = self.file.read(buf)?;
        Ok(n)
    }

    /// Scan the entire image for a 4-byte pool tag pattern.
    /// Returns a list of offsets where the tag was found.
    pub fn scan_pool_tag(&mut self, tag: &[u8; 4]) -> Result<Vec<u64>> {
        let mut results = Vec::new();
        let mut buf = vec![0u8; self.block_size + 3]; // overlap for boundary matches
        let mut offset: u64 = 0;

        loop {
            self.file.seek(SeekFrom::Start(offset))?;
            let n = self.file.read(&mut buf)?;
            if n < 4 {
                break;
            }

            for i in 0..n - 3 {
                if &buf[i..i + 4] == tag {
                    results.push(offset + i as u64);
                }
            }

            if (n as u64) < self.block_size as u64 + 3 {
                break;
            }
            // Advance by block_size, keeping 3-byte overlap
            offset += self.block_size as u64;
        }

        Ok(results)
    }

    /// Scan for an arbitrary byte pattern in the image.
    /// Returns offsets of all matches.
    pub fn scan_pattern(&mut self, pattern: &[u8]) -> Result<Vec<u64>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }
        let plen = pattern.len();
        let overlap = plen - 1;
        let mut results = Vec::new();
        let mut buf = vec![0u8; self.block_size + overlap];
        let mut offset: u64 = 0;

        loop {
            self.file.seek(SeekFrom::Start(offset))?;
            let n = self.file.read(&mut buf)?;
            if n < plen {
                break;
            }

            for i in 0..n - (plen - 1) {
                if &buf[i..i + plen] == pattern {
                    results.push(offset + i as u64);
                }
            }

            if (n as u64) < self.block_size as u64 + overlap as u64 {
                break;
            }
            offset += self.block_size as u64;
        }

        Ok(results)
    }

    /// Read a null-terminated UTF-16LE string at the given offset (max `max_chars` characters).
    pub fn read_utf16le_string(&mut self, offset: u64, max_chars: usize) -> Result<String> {
        let byte_len = max_chars * 2;
        let mut buf = vec![0u8; byte_len];
        let n = self.read_at(offset, &mut buf)?;
        let usable = n / 2;
        let mut chars = Vec::with_capacity(usable);
        for i in 0..usable {
            let lo = buf[i * 2];
            let hi = buf[i * 2 + 1];
            let ch = u16::from_le_bytes([lo, hi]);
            if ch == 0 {
                break;
            }
            chars.push(ch);
        }
        Ok(String::from_utf16_lossy(&chars))
    }

    /// Read a null-terminated ASCII string at the given offset (max `max_len` bytes).
    pub fn read_ascii_string(&mut self, offset: u64, max_len: usize) -> Result<String> {
        let mut buf = vec![0u8; max_len];
        let n = self.read_at(offset, &mut buf)?;
        let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
        Ok(String::from_utf8_lossy(&buf[..end]).to_string())
    }

    /// Read a little-endian u32 at the given offset.
    pub fn read_u32_le(&mut self, offset: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        let n = self.read_at(offset, &mut buf)?;
        if n < 4 {
            return Err(VolatilityError::ScanError(format!(
                "Could not read 4 bytes at offset 0x{:X}",
                offset
            )));
        }
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a little-endian u64 at the given offset.
    pub fn read_u64_le(&mut self, offset: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        let n = self.read_at(offset, &mut buf)?;
        if n < 8 {
            return Err(VolatilityError::ScanError(format!(
                "Could not read 8 bytes at offset 0x{:X}",
                offset
            )));
        }
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a little-endian i64 at the given offset.
    pub fn read_i64_le(&mut self, offset: u64) -> Result<i64> {
        let mut buf = [0u8; 8];
        let n = self.read_at(offset, &mut buf)?;
        if n < 8 {
            return Err(VolatilityError::ScanError(format!(
                "Could not read 8 bytes at offset 0x{:X}",
                offset
            )));
        }
        Ok(i64::from_le_bytes(buf))
    }
}
