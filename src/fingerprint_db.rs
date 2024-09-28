//! Persistent fingerprint database for program similarity catalogs.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::bytecode_normalize::{NormalizeConfig, normalize_bytecode};
use crate::elf_loader;
use crate::minhash;
use crate::opcode_ngram;
use crate::simhash;

/// One stored program fingerprint record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFingerprint {
    pub program_id: String,
    pub source_path: String,
    pub ngram_count: usize,
    pub simhash: u64,
    pub minhash: Vec<u64>,
    pub ngram_sample: std::collections::HashSet<u64>,
    pub normalized_len: usize,
}

/// On disk fingerprint catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintDb {
    pub version: u32,
    pub entries: Vec<StoredFingerprint>,
}

impl Default for FingerprintDb {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

impl FingerprintDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&data).map_err(|e| e.to_string())
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(path, json).map_err(|e| e.to_string())
    }

    pub fn insert_from_file(
        &mut self,
        program_id: impl Into<String>,
        path: &Path,
        ngram_size: usize,
        num_hashes: usize,
    ) -> Result<(), String> {
        let entry = fingerprint_file_entry(program_id, path, ngram_size, num_hashes)?;
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.program_id == entry.program_id)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        Ok(())
    }

    pub fn find_by_id(&self, program_id: &str) -> Option<&StoredFingerprint> {
        self.entries.iter().find(|e| e.program_id == program_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Scan directory and build an in memory database without persisting.
    pub fn scan_directory(
        dir: &Path,
        ngram_size: usize,
        num_hashes: usize,
    ) -> Result<Self, String> {
        let mut db = FingerprintDb::new();
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if elf_loader::load_program(path).is_err() {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            db.insert_from_file(id, path, ngram_size, num_hashes)?;
        }
        Ok(db)
    }
}

pub fn fingerprint_file_entry(
    program_id: impl Into<String>,
    path: &Path,
    ngram_size: usize,
    num_hashes: usize,
) -> Result<StoredFingerprint, String> {
    let bytecode = elf_loader::load_program(path).map_err(|e| e.to_string())?;
    let normalized = normalize_bytecode(&bytecode.text, NormalizeConfig::default());
    let ngrams = opcode_ngram::extract_ngrams(&normalized.normalized, ngram_size);
    if ngrams.is_empty() {
        return Err(format!("no ngrams extracted from {}", path.display()));
    }
    let minhash = minhash::compute_signature(&ngrams, num_hashes);
    let sim = simhash::compute_simhash(&ngrams);

    Ok(StoredFingerprint {
        program_id: program_id.into(),
        source_path: path.display().to_string(),
        ngram_count: ngrams.len(),
        simhash: sim.0,
        minhash: minhash.values,
        ngram_sample: ngrams,
        normalized_len: normalized.normalized.len(),
    })
}

/// Merge two databases, preferring newer entries on id collision.
pub fn merge_databases(primary: &FingerprintDb, secondary: &FingerprintDb) -> FingerprintDb {
    let mut merged = primary.clone();
    for entry in &secondary.entries {
        if let Some(existing) = merged.entries.iter_mut().find(|e| e.program_id == entry.program_id)
        {
            *existing = entry.clone();
        } else {
            merged.entries.push(entry.clone());
        }
    }
    merged
}

/// Resolve program id from file path using stem name.
pub fn default_program_id(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// Export database summary for CLI display.
pub fn format_db_summary(db: &FingerprintDb) -> String {
    let mut lines = vec![
        format!("fingerprint_db version={} entries={}", db.version, db.len()),
    ];
    for entry in &db.entries {
        lines.push(format!(
            "  {} ngrams={} simhash={:016x} path={}",
            entry.program_id, entry.ngram_count, entry.simhash, entry.source_path
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode_ngram::DEFAULT_NGRAM_SIZE;

    fn sample_text(seed: u8) -> Vec<u8> {
        (0..32)
            .map(|i| {
                let opcode = seed.wrapping_add(i as u8) % 0x20;
                [opcode, i as u8, 0, 0, 0, 0, 0, 0]
            })
            .flatten()
            .collect()
    }

    fn write_test_elf(dir: &Path, name: &str, seed: u8) {
        let text = sample_text(seed);
        let elf = super::tests_support::build_test_elf(&text);
        fs::write(dir.join(name), elf).unwrap();
    }

    #[test]
    fn scan_directory_builds_entries() {
        let dir = tempfile::tempdir().unwrap();
        write_test_elf(dir.path(), "alpha.so", 1);
        write_test_elf(dir.path(), "beta.so", 50);
        let db = FingerprintDb::scan_directory(dir.path(), DEFAULT_NGRAM_SIZE, 64).unwrap();
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        write_test_elf(dir.path(), "gamma.so", 9);
        let db = FingerprintDb::scan_directory(dir.path(), DEFAULT_NGRAM_SIZE, 64).unwrap();
        let db_path = dir.path().join("fingerprints.json");
        db.save(&db_path).unwrap();
        let loaded = FingerprintDb::load(&db_path).unwrap();
        assert_eq!(loaded.len(), db.len());
    }
}

/// Test helpers for unit tests in this module.
#[cfg(test)]
pub mod tests_support {

    pub fn build_test_elf(text: &[u8]) -> Vec<u8> {
        let mut elf = Vec::new();
        const SHOFF: u64 = 256;
        const TEXT_OFFSET: u64 = 512;
        const SHSTRTAB_OFFSET: u64 = 768;

        elf.extend_from_slice(&[
            0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        push_u16(&mut elf, 2);
        push_u16(&mut elf, 247);
        push_u32(&mut elf, 1);
        push_u64(&mut elf, 0);
        push_u64(&mut elf, 0);
        push_u64(&mut elf, SHOFF);
        push_u32(&mut elf, 0);
        push_u16(&mut elf, 64);
        push_u16(&mut elf, 0);
        push_u16(&mut elf, 0);
        push_u16(&mut elf, 64);
        push_u16(&mut elf, 3);
        push_u16(&mut elf, 2);

        while elf.len() < SHOFF as usize {
            elf.push(0);
        }

        elf.extend_from_slice(&[0u8; 64]);
        push_u32(&mut elf, 1);
        push_u32(&mut elf, 1);
        push_u64(&mut elf, 0x6);
        push_u64(&mut elf, 0);
        push_u64(&mut elf, TEXT_OFFSET);
        push_u64(&mut elf, text.len() as u64);
        push_u32(&mut elf, 0);
        push_u32(&mut elf, 0);
        push_u64(&mut elf, 8);
        push_u64(&mut elf, 0);

        push_u32(&mut elf, 7);
        push_u32(&mut elf, 3);
        push_u64(&mut elf, 0);
        push_u64(&mut elf, SHSTRTAB_OFFSET);
        push_u64(&mut elf, 15);
        push_u32(&mut elf, 0);
        push_u32(&mut elf, 0);
        push_u64(&mut elf, 1);
        push_u64(&mut elf, 0);

        while elf.len() < TEXT_OFFSET as usize {
            elf.push(0);
        }
        elf.extend_from_slice(text);
        while elf.len() < SHSTRTAB_OFFSET as usize {
            elf.push(0);
        }
        elf.extend_from_slice(b"\0.text\0.shstrtab\0");
        elf
    }

    fn push_u16(buf: &mut Vec<u8>, val: u16) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn push_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn push_u64(buf: &mut Vec<u8>, val: u64) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
}
