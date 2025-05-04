//! Extract normalized opcode n-grams from SBF bytecode.

use std::collections::HashSet;

/// Size of a single SBF instruction in bytes.
pub const INSTRUCTION_SIZE: usize = 8;

/// Default n-gram width for opcode sequences.
pub const DEFAULT_NGRAM_SIZE: usize = 3;

/// A normalized opcode token derived from one SBF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NormalizedOpcode {
    pub opcode: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
}

impl NormalizedOpcode {
    /// Decode and normalize an 8-byte SBF instruction.
    ///
    /// Immediate operands and branch offsets are stripped so that
    /// structurally similar instructions hash to the same token.
    pub fn from_instruction(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < INSTRUCTION_SIZE {
            return None;
        }
        let opcode = bytes[0];
        let dst_reg = bytes[1] & 0x0f;
        let src_reg = (bytes[1] >> 4) & 0x0f;
        Some(Self {
            opcode,
            dst_reg,
            src_reg,
        })
    }

    fn to_key(self) -> u32 {
        (self.opcode as u32) << 16 | (self.dst_reg as u32) << 8 | self.src_reg as u32
    }
}

/// Extract unique normalized opcode n-grams from raw text section bytes.
pub fn extract_ngrams(text: &[u8], n: usize) -> HashSet<u64> {
    let opcodes: Vec<NormalizedOpcode> = text
        .chunks(INSTRUCTION_SIZE)
        .filter_map(NormalizedOpcode::from_instruction)
        .collect();

    let mut ngrams = HashSet::new();
    if opcodes.len() < n {
        return ngrams;
    }

    for window in opcodes.windows(n) {
        let mut key: u64 = 0;
        for (i, token) in window.iter().enumerate() {
            key |= (token.to_key() as u64) << (i * 21);
        }
        ngrams.insert(key);
    }

    ngrams
}

/// Count total n-grams without deduplication (for diagnostics).
pub fn count_ngrams(text: &[u8], n: usize) -> usize {
    let opcodes: Vec<NormalizedOpcode> = text
        .chunks(INSTRUCTION_SIZE)
        .filter_map(NormalizedOpcode::from_instruction)
        .collect();

    if opcodes.len() < n {
        0
    } else {
        opcodes.len() - n + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_instruction_fields() {
        let bytes = [0x07, 0x12, 0, 0, 0, 0, 0, 0];
        let op = NormalizedOpcode::from_instruction(&bytes).unwrap();
        assert_eq!(op.opcode, 0x07);
        assert_eq!(op.dst_reg, 0x02);
        assert_eq!(op.src_reg, 0x01);
    }

    #[test]
    fn extracts_ngrams_from_aligned_bytecode() {
        let text: Vec<u8> = (0..24).map(|i| (i % 256) as u8).collect();
        let grams = extract_ngrams(&text, 2);
        assert!(!grams.is_empty());
    }
}
