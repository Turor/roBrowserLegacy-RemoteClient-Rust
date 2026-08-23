//! GRF 0x200 / 0x300 reader.
//! Think of `GrfArchive` as a `@Singleton` that mmaps one `.grf` file.

mod des;

use flate2::read::ZlibDecoder;
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const HEADER_SIZE: usize = 0x2E;
pub const FLAG_FILE: u8 = 0x01;
pub const FLAG_ENCRYPT_HEADER: u8 = 0x02;
pub const FLAG_ENCRYPT_MIXED: u8 = 0x03;
pub const FLAG_ENCRYPT_MIXED_ALT: u8 = 0x05;
const MAX_READ: u64 = 100 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum GrfError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid GRF signature")]
    Signature,
    #[error("unsupported GRF version 0x{0:x}")]
    Version(u32),
    #[error("invalid table offset")]
    TableOffset,
    #[error("zlib error: {0}")]
    Zlib(String),
    #[error("file too large to extract")]
    TooLarge,
    #[error("unsupported encryption flag {0}")]
    Encrypt(u8),
}

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub original_name: String,
    pub original_bytes: Vec<u8>,
    pub pack_size: u32,
    pub length_aligned: u32,
    pub real_size: u32,
    pub flags: u8,
    pub position: u64,
}

pub struct GrfArchive {
    #[allow(dead_code)]
    pub path: PathBuf,
    pub filename: String,
    mmap: Mmap,
    pub version: u32,
    #[allow(dead_code)]
    pub uses_64bit: bool,
    pub entries: Vec<FileEntry>,
}

impl GrfArchive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GrfError> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        if mmap.len() < HEADER_SIZE {
            return Err(GrfError::Signature);
        }

        let sig = &mmap[0..16];
        let magic_ok = sig.starts_with(b"Master of Magic") || sig.starts_with(b"Event Horizon");
        if !magic_ok {
            return Err(GrfError::Signature);
        }

        let version = u32::from_le_bytes(mmap[42..46].try_into().unwrap());
        let (table_offset, uses_64bit, _filecount) = if version == 0x300 {
            let table_offset = u64::from_le_bytes(mmap[30..38].try_into().unwrap());
            let filecount = u32::from_le_bytes(mmap[38..42].try_into().unwrap());
            (table_offset, true, filecount)
        } else if version == 0x200 {
            let table_offset = u32::from_le_bytes(mmap[30..34].try_into().unwrap()) as u64;
            let _seeds = u32::from_le_bytes(mmap[34..38].try_into().unwrap());
            let filecount = u32::from_le_bytes(mmap[38..42].try_into().unwrap());
            (table_offset, false, filecount)
        } else {
            return Err(GrfError::Version(version));
        };

        // Pointer is at HEADER_SIZE after reading the header; table lives at HEADER + table_offset.
        let mut table_pos = HEADER_SIZE as u64 + table_offset;
        if version == 0x300 {
            table_pos += 4;
        }
        if table_pos as usize + 8 > mmap.len() {
            return Err(GrfError::TableOffset);
        }

        let pack_size = u32::from_le_bytes(
            mmap[table_pos as usize..table_pos as usize + 4]
                .try_into()
                .unwrap(),
        );
        let real_size = u32::from_le_bytes(
            mmap[table_pos as usize + 4..table_pos as usize + 8]
                .try_into()
                .unwrap(),
        );
        let packed_start = table_pos as usize + 8;
        let packed_end = packed_start + pack_size as usize;
        if packed_end > mmap.len() {
            return Err(GrfError::TableOffset);
        }

        let table = inflate(&mmap[packed_start..packed_end], real_size as usize)?;
        let entries = parse_table(&table, uses_64bit)?;

        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.grf")
            .to_string();

        Ok(Self {
            path,
            filename,
            mmap,
            version,
            uses_64bit,
            entries,
        })
    }

    pub fn extract(&self, entry: &FileEntry) -> Result<Vec<u8>, GrfError> {
        let encrypted = entry.flags != FLAG_FILE;
        let read_size = if encrypted {
            entry.length_aligned as u64
        } else {
            entry.pack_size as u64
        };
        if read_size > MAX_READ {
            return Err(GrfError::TooLarge);
        }
        let start = (entry.position as usize).saturating_add(HEADER_SIZE);
        let end = start + read_size as usize;
        if end > self.mmap.len() {
            return Err(GrfError::TableOffset);
        }
        let mut compressed = self.mmap[start..end].to_vec();

        if encrypted {
            let ext = entry
                .original_name
                .rsplit('.')
                .next()
                .map(|s| format!(".{}", s.to_ascii_lowercase()))
                .unwrap_or_default();
            let skip = [".gnd", ".gat", ".act", ".str"];
            let (cycle, is_data_crypted) = if skip.iter().any(|s| *s == ext) {
                (0usize, true)
            } else {
                let mut cycle = 1usize;
                let mut i = 10u32;
                while entry.pack_size >= i {
                    cycle += 1;
                    i = i.saturating_mul(10);
                }
                (cycle, false)
            };

            match entry.flags {
                FLAG_ENCRYPT_MIXED | FLAG_ENCRYPT_MIXED_ALT => {
                    des::decrypt_mixed(&mut compressed, cycle, is_data_crypted);
                }
                FLAG_ENCRYPT_HEADER => des::decrypt_header(&mut compressed),
                FLAG_FILE => {}
                other => return Err(GrfError::Encrypt(other)),
            }
            compressed.truncate(entry.pack_size as usize);
        }

        inflate(&compressed, entry.real_size as usize)
    }
}

fn inflate(src: &[u8], real_size: usize) -> Result<Vec<u8>, GrfError> {
    let mut decoder = ZlibDecoder::new(src);
    let mut out = Vec::with_capacity(real_size);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| GrfError::Zlib(e.to_string()))?;
    Ok(out)
}

fn parse_table(table: &[u8], uses_64bit: bool) -> Result<Vec<FileEntry>, GrfError> {
    let entry_size = if uses_64bit { 21 } else { 17 };
    let mut entries = Vec::new();
    let mut i = 0;
    while i < table.len() {
        let Some(null) = table[i..].iter().position(|&b| b == 0) else {
            break;
        };
        let name_bytes = table[i..i + null].to_vec();
        i += null + 1;
        if i + entry_size > table.len() {
            break;
        }
        let pack_size = u32::from_le_bytes(table[i..i + 4].try_into().unwrap());
        let length_aligned = u32::from_le_bytes(table[i + 4..i + 8].try_into().unwrap());
        let real_size = u32::from_le_bytes(table[i + 8..i + 12].try_into().unwrap());
        let flags = table[i + 12];
        let position = if uses_64bit {
            u64::from_le_bytes(table[i + 13..i + 21].try_into().unwrap())
        } else {
            u32::from_le_bytes(table[i + 13..i + 17].try_into().unwrap()) as u64
        };
        i += entry_size;

        if name_bytes.is_empty() {
            continue;
        }
        let original_name = String::from_utf8_lossy(&name_bytes).into_owned();
        entries.push(FileEntry {
            original_name,
            original_bytes: name_bytes,
            pack_size,
            length_aligned,
            real_size,
            flags,
            position,
        });
    }
    Ok(entries)
}

/// Build a tiny unencrypted 0x200 GRF for tests.
#[cfg(test)]
pub fn build_test_grf_200(files: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut data_blob = Vec::new();
    let mut table = Vec::new();
    for (name, content) in files {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(content).unwrap();
        let packed = enc.finish().unwrap();
        let position = data_blob.len() as u32;
        data_blob.extend_from_slice(&packed);

        table.extend_from_slice(name.as_bytes());
        table.push(0);
        table.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        table.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        table.extend_from_slice(&(content.len() as u32).to_le_bytes());
        table.push(FLAG_FILE);
        table.extend_from_slice(&position.to_le_bytes());
    }

    let mut tenc = ZlibEncoder::new(Vec::new(), Compression::default());
    tenc.write_all(&table).unwrap();
    let packed_table = tenc.finish().unwrap();

    let mut out = vec![0u8; HEADER_SIZE];
    let sig = b"Master of Magic";
    out[..sig.len()].copy_from_slice(sig);
    let table_offset = data_blob.len() as u32;
    out[30..34].copy_from_slice(&table_offset.to_le_bytes());
    out[34..38].copy_from_slice(&0u32.to_le_bytes());
    let filecount = files.len() as u32 + 7;
    out[38..42].copy_from_slice(&filecount.to_le_bytes());
    out[42..46].copy_from_slice(&0x200u32.to_le_bytes());

    out.extend_from_slice(&data_blob);
    out.extend_from_slice(&(packed_table.len() as u32).to_le_bytes());
    out.extend_from_slice(&(table.len() as u32).to_le_bytes());
    out.extend_from_slice(&packed_table);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn roundtrip_unencrypted_200() {
        let bytes = build_test_grf_200(&[
            ("data\\clientinfo.xml", b"<root/>"),
            ("data\\texture\\test.tga", b"TGA-BYTES"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.grf");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let grf = GrfArchive::open(&path).unwrap();
        assert_eq!(grf.version, 0x200);
        assert_eq!(grf.entries.len(), 2);
        let e = grf
            .entries
            .iter()
            .find(|e| e.original_name.contains("clientinfo"))
            .unwrap();
        assert_eq!(grf.extract(e).unwrap(), b"<root/>");
    }
}
