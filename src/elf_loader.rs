//! Load Solana program binaries from ELF files.

use std::fs;
use std::path::Path;

use goblin::elf::Elf;

/// Parsed program bytecode extracted from an ELF executable section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramBytecode {
    pub text: Vec<u8>,
    pub entry_offset: usize,
}

/// Errors that can occur while loading a program binary.
#[derive(Debug)]
pub enum LoadError {
    Io(std::io::Error),
    NotElf(String),
    NoTextSection,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "io error: {e}"),
            LoadError::NotElf(msg) => write!(f, "not a valid elf: {msg}"),
            LoadError::NoTextSection => write!(f, "no executable text section found"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<std::io::Error> for LoadError {
    fn from(value: std::io::Error) -> Self {
        LoadError::Io(value)
    }
}

/// Load raw program bytes from a file path.
pub fn load_program(path: &Path) -> Result<ProgramBytecode, LoadError> {
    let data = fs::read(path)?;
    parse_elf_bytes(&data)
}

/// Parse ELF bytes and extract the primary executable text section.
pub fn parse_elf_bytes(data: &[u8]) -> Result<ProgramBytecode, LoadError> {
    let elf = Elf::parse(data).map_err(|e| LoadError::NotElf(e.to_string()))?;

    let header = elf
        .section_headers
        .iter()
        .find(|sh| sh.sh_type == goblin::elf::section_header::SHT_PROGBITS && sh.is_executable())
        .ok_or(LoadError::NoTextSection)?;

    let start = header.sh_offset as usize;
    let end = start.saturating_add(header.sh_size as usize);
    if end > data.len() {
        return Err(LoadError::NotElf("text section exceeds file bounds".into()));
    }

    let text = data[start..end].to_vec();
    let entry_offset = elf.header.e_entry as usize;

    Ok(ProgramBytecode { text, entry_offset })
}
