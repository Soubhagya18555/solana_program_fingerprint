//! Bytecode normalization pipeline for stable fingerprint extraction.

use std::collections::HashSet;

use crate::opcode_ngram::{self, NormalizedOpcode, DEFAULT_NGRAM_SIZE};

/// Normalization policy applied before ngram extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizeConfig {
    pub strip_nops: bool,
    pub collapse_lddw: bool,
    pub remap_registers: bool,
    pub min_text_len: usize,
}

impl Default for NormalizeConfig {
    fn default() -> Self {
        Self {
            strip_nops: true,
            collapse_lddw: true,
            remap_registers: true,
            min_text_len: opcode_ngram::INSTRUCTION_SIZE,
        }
    }
}

/// Result of normalizing raw text section bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedBytecode {
    pub original_len: usize,
    pub normalized: Vec<u8>,
    pub removed_instructions: usize,
    pub register_remap: RegisterRemap,
}

/// Register renaming map applied during normalization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegisterRemap {
    pub mapping: Vec<(u8, u8)>,
}

impl RegisterRemap {
    pub fn lookup(&self, reg: u8) -> u8 {
        self.mapping
            .iter()
            .find(|(from, _)| *from == reg)
            .map(|(_, to)| *to)
            .unwrap_or(reg)
    }
}

/// Normalize bytecode for fingerprinting.
pub fn normalize_bytecode(text: &[u8], config: NormalizeConfig) -> NormalizedBytecode {
    let mut normalized = Vec::new();
    let mut removed = 0usize;
    let mut register_remap = RegisterRemap::default();
    let mut next_reg = 0u8;

    let mut offset = 0usize;
    while offset + opcode_ngram::INSTRUCTION_SIZE <= text.len() {
        let chunk: &[u8; 8] = text[offset..offset + opcode_ngram::INSTRUCTION_SIZE]
            .try_into()
            .expect("aligned chunk");
        let opcode = chunk[0];

        if config.strip_nops && is_nop_like(opcode, chunk) {
            removed += 1;
            offset += opcode_ngram::INSTRUCTION_SIZE;
            continue;
        }

        if config.collapse_lddw && opcode == 0x18 {
            if offset + 16 <= text.len() {
                let mut insn = [0u8; 8];
                insn[0] = 0x18;
                insn[1] = chunk[1];
                append_normalized(&mut normalized, &insn, config, &mut register_remap, &mut next_reg);
                offset += 16;
                continue;
            }
        }

        append_normalized(
            &mut normalized,
            chunk,
            config,
            &mut register_remap,
            &mut next_reg,
        );
        offset += opcode_ngram::INSTRUCTION_SIZE;
    }

    NormalizedBytecode {
        original_len: text.len(),
        normalized,
        removed_instructions: removed,
        register_remap,
    }
}

/// Extract ngrams from normalized bytecode using default width.
pub fn normalized_ngrams(text: &[u8], config: NormalizeConfig) -> HashSet<u64> {
    let normalized = normalize_bytecode(text, config);
    opcode_ngram::extract_ngrams(&normalized.normalized, DEFAULT_NGRAM_SIZE)
}

/// Compute compression ratio after normalization.
pub fn compression_ratio(result: &NormalizedBytecode) -> f64 {
    if result.original_len == 0 {
        return 1.0;
    }
    result.normalized.len() as f64 / result.original_len as f64
}

fn append_normalized(
    out: &mut Vec<u8>,
    chunk: &[u8; 8],
    config: NormalizeConfig,
    remap: &mut RegisterRemap,
    next_reg: &mut u8,
) {
    let mut bytes = *chunk;
    if config.remap_registers {
        let dst = bytes[1] & 0x0f;
        let src = (bytes[1] >> 4) & 0x0f;
        let new_dst = map_register(remap, next_reg, dst);
        let new_src = if src != 0 {
            map_register(remap, next_reg, src)
        } else {
            0
        };
        bytes[1] = new_dst | (new_src << 4);
    }
    out.extend_from_slice(&bytes);
}

fn map_register(remap: &mut RegisterRemap, next_reg: &mut u8, reg: u8) -> u8 {
    if let Some((_, to)) = remap.mapping.iter().find(|(from, _)| *from == reg) {
        return *to;
    }
    let assigned = *next_reg;
    *next_reg = next_reg.saturating_add(1);
    remap.mapping.push((reg, assigned));
    assigned
}

fn is_nop_like(opcode: u8, chunk: &[u8]) -> bool {
    opcode == 0xb7 && chunk[1] == 0 && chunk[4..8] == [0, 0, 0, 0]
}

/// Decode normalized stream back into opcode tokens for diagnostics.
pub fn decode_normalized(text: &[u8]) -> Vec<NormalizedOpcode> {
    text.chunks(opcode_ngram::INSTRUCTION_SIZE)
        .filter_map(NormalizedOpcode::from_instruction)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mov(dst: u8, imm: u8) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = 0xb7;
        bytes[1] = dst;
        bytes[4] = imm;
        bytes
    }

    #[test]
    fn strips_nop_instructions() {
        let text = [make_mov(0, 0), make_mov(1, 5)].concat();
        let result = normalize_bytecode(&text, NormalizeConfig::default());
        assert_eq!(result.removed_instructions, 1);
        assert_eq!(result.normalized.len(), 8);
    }

    #[test]
    fn remaps_registers_canonical_order() {
        let text = [make_mov(3, 1), make_mov(7, 2)].concat();
        let result = normalize_bytecode(&text, NormalizeConfig::default());
        assert!(!result.register_remap.mapping.is_empty());
        let ops = decode_normalized(&result.normalized);
        assert_eq!(ops[0].dst_reg, 0);
        assert_eq!(ops[1].dst_reg, 1);
    }

    #[test]
    fn normalized_ngrams_differ_from_raw_on_nop_strip() {
        let nop = make_mov(0, 0);
        let real = make_mov(1, 9);
        let text = [nop, real, real].concat();
        let raw = opcode_ngram::extract_ngrams(&text, 2);
        let norm = normalized_ngrams(&text, NormalizeConfig::default());
        assert_ne!(raw, norm);
    }
}
