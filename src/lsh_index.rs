//! Locality Sensitive Hash index for fast approximate similarity search.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::fingerprint_db::FingerprintDb;
use crate::minhash::{self, MinHashSignature};

/// Number of bands for LSH bucketing (signature length must be divisible).
pub const DEFAULT_BANDS: usize = 16;

/// Rows per band derived from signature length and band count.
#[derive(Debug, Clone, Copy)]
pub struct LshConfig {
    pub bands: usize,
    pub rows_per_band: usize,
}

impl LshConfig {
    pub fn from_signature_len(signature_len: usize, bands: usize) -> Result<Self, String> {
        if bands == 0 || signature_len % bands != 0 {
            return Err(format!(
                "signature length {signature_len} must be divisible by bands {bands}"
            ));
        }
        Ok(Self {
            bands,
            rows_per_band: signature_len / bands,
        })
    }
}

/// Candidate match from LSH bucket lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct LshCandidate {
    pub program_id: String,
    pub band_index: usize,
    pub bucket_key: u64,
}

/// In memory LSH index over MinHash signatures.
#[derive(Debug, Clone)]
pub struct LshIndex {
    config: LshConfig,
    buckets: HashMap<(usize, u64), HashSet<String>>,
    signatures: HashMap<String, MinHashSignature>,
}

impl LshIndex {
    pub fn new(signature_len: usize, bands: usize) -> Result<Self, String> {
        Ok(Self {
            config: LshConfig::from_signature_len(signature_len, bands)?,
            buckets: HashMap::new(),
            signatures: HashMap::new(),
        })
    }

    pub fn insert(&mut self, program_id: impl Into<String>, signature: MinHashSignature) {
        let id = program_id.into();
        for (band_idx, key) in band_keys(&signature, &self.config).into_iter().enumerate() {
            self.buckets
                .entry((band_idx, key))
                .or_default()
                .insert(id.clone());
        }
        self.signatures.insert(id, signature);
    }

    pub fn query(&self, signature: &MinHashSignature) -> Vec<LshCandidate> {
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();

        for (band_idx, key) in band_keys(signature, &self.config).into_iter().enumerate() {
            if let Some(ids) = self.buckets.get(&(band_idx, key)) {
                for id in ids {
                    if seen.insert(id.clone()) {
                        candidates.push(LshCandidate {
                            program_id: id.clone(),
                            band_index: band_idx,
                            bucket_key: key,
                        });
                    }
                }
            }
        }

        candidates
    }

    pub fn query_with_scores(
        &self,
        signature: &MinHashSignature,
        min_jaccard: f64,
    ) -> Vec<(String, f64)> {
        let candidates = self.query(signature);
        let mut scored: Vec<(String, f64)> = candidates
            .into_iter()
            .filter_map(|c| {
                let stored = self.signatures.get(&c.program_id)?;
                let score = minhash::estimate_jaccard(signature, stored);
                if score >= min_jaccard {
                    Some((c.program_id, score))
                } else {
                    None
                }
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

/// Build LSH index from a fingerprint database on disk.
pub fn build_index_from_db(db: &FingerprintDb, bands: usize) -> Result<LshIndex, String> {
    if db.entries.is_empty() {
        return LshIndex::new(minhash::DEFAULT_NUM_HASHES, bands);
    }
    let sig_len = db.entries[0].minhash.len();
    let mut index = LshIndex::new(sig_len, bands)?;
    for entry in &db.entries {
        let signature = MinHashSignature {
            values: entry.minhash.clone(),
        };
        index.insert(entry.program_id.clone(), signature);
    }
    Ok(index)
}

/// Index all programs under a directory by fingerprinting each ELF file.
pub fn index_directory(
    dir: &Path,
    bands: usize,
    ngram_size: usize,
    num_hashes: usize,
) -> Result<LshIndex, String> {
    let db = FingerprintDb::scan_directory(dir, ngram_size, num_hashes)?;
    build_index_from_db(&db, bands)
}

fn band_keys(signature: &MinHashSignature, config: &LshConfig) -> Vec<u64> {
    let mut keys = Vec::with_capacity(config.bands);
    for band in 0..config.bands {
        let start = band * config.rows_per_band;
        let end = start + config.rows_per_band;
        let slice = &signature.values[start..end];
        keys.push(hash_band_slice(slice));
    }
    keys
}

fn hash_band_slice(values: &[u64]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for val in values {
        hash ^= *val;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn identical_signatures_share_buckets() {
        let features: HashSet<u64> = (0..50).collect();
        let sig = minhash::compute_signature(&features, 64);
        let mut index = LshIndex::new(64, 8).unwrap();
        index.insert("prog_a", sig.clone());
        let hits = index.query(&sig);
        assert!(hits.iter().any(|h| h.program_id == "prog_a"));
    }

    #[test]
    fn disjoint_sets_rarely_collide() {
        let a: HashSet<u64> = (0..50).collect();
        let b: HashSet<u64> = (1000..1050).collect();
        let sig_a = minhash::compute_signature(&a, 64);
        let sig_b = minhash::compute_signature(&b, 64);
        let mut index = LshIndex::new(64, 8).unwrap();
        index.insert("a", sig_a.clone());
        let scored = index.query_with_scores(&sig_b, 0.5);
        assert!(scored.is_empty());
    }
}
