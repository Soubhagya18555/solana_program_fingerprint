//! Bytecode similarity engine for Solana programs.
//!
//! Extracts normalized opcode n-grams from SBF ELF binaries and computes
//! MinHash and SimHash fingerprints for similarity comparison and clustering.

pub mod bytecode_normalize;
pub mod cluster;
pub mod elf_loader;
pub mod fingerprint_db;
pub mod lsh_index;
pub mod minhash;
pub mod opcode_ngram;
pub mod simhash;
pub mod similarity_report;

use std::collections::HashSet;
use std::path::Path;

use bytecode_normalize::{NormalizeConfig, normalize_bytecode};
use elf_loader::load_program;
use minhash::{compute_signature, estimate_jaccard, MinHashSignature, DEFAULT_NUM_HASHES};
use opcode_ngram::{extract_ngrams, DEFAULT_NGRAM_SIZE};
use simhash::{compute_simhash, similarity_from_simhash, SimHash};

/// Combined fingerprint for a Solana program binary.
#[derive(Debug, Clone)]
pub struct ProgramFingerprint {
    pub ngram_count: usize,
    pub minhash: MinHashSignature,
    pub simhash: SimHash,
    pub ngrams: HashSet<u64>,
}

/// Build a full fingerprint from a program file path.
pub fn fingerprint_file(path: &Path) -> Result<ProgramFingerprint, String> {
    let bytecode = load_program(path).map_err(|e| e.to_string())?;
    fingerprint_bytes(&bytecode.text)
}

/// Build a full fingerprint from raw text section bytes.
pub fn fingerprint_bytes(text: &[u8]) -> Result<ProgramFingerprint, String> {
    fingerprint_bytes_with_config(text, NormalizeConfig::default())
}

/// Build a fingerprint using a custom normalization policy.
pub fn fingerprint_bytes_with_config(
    text: &[u8],
    config: NormalizeConfig,
) -> Result<ProgramFingerprint, String> {
    let normalized = normalize_bytecode(text, config);
    let ngrams = extract_ngrams(&normalized.normalized, DEFAULT_NGRAM_SIZE);
    if ngrams.is_empty() {
        return Err("no opcode n-grams extracted from bytecode".into());
    }
    let minhash = compute_signature(&ngrams, DEFAULT_NUM_HASHES);
    let simhash = compute_simhash(&ngrams);
    Ok(ProgramFingerprint {
        ngram_count: ngrams.len(),
        minhash,
        simhash,
        ngrams,
    })
}

/// Comparison result between two program binaries.
#[derive(Debug)]
pub struct ComparisonResult {
    pub jaccard_estimate: f64,
    pub jaccard_exact: f64,
    pub simhash_similarity: f64,
    pub hamming_distance: u32,
}

/// Compare two program files and return similarity metrics.
pub fn compare_files(path_a: &Path, path_b: &Path) -> Result<ComparisonResult, String> {
    let fp_a = fingerprint_file(path_a)?;
    let fp_b = fingerprint_file(path_b)?;
    Ok(compare_fingerprints(&fp_a, &fp_b))
}

/// Compare two precomputed fingerprints.
pub fn compare_fingerprints(a: &ProgramFingerprint, b: &ProgramFingerprint) -> ComparisonResult {
    let jaccard_estimate = estimate_jaccard(&a.minhash, &b.minhash);
    let jaccard_exact = minhash::exact_jaccard(&a.ngrams, &b.ngrams);
    let simhash_similarity = similarity_from_simhash(a.simhash, b.simhash);
    let hamming_distance = simhash::hamming_distance(a.simhash, b.simhash);
    ComparisonResult {
        jaccard_estimate,
        jaccard_exact,
        simhash_similarity,
        hamming_distance,
    }
}

#[cfg(test)]
#[path = "../tests/fingerprint_test.rs"]
mod fingerprint_test;
