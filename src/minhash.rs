//! MinHash signature generation and Jaccard similarity estimation.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

/// Number of hash permutations in the MinHash signature.
pub const DEFAULT_NUM_HASHES: usize = 128;

/// A MinHash signature over a set of 64-bit feature keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinHashSignature {
    pub values: Vec<u64>,
}

/// Build a MinHash signature from a set of feature hashes.
pub fn compute_signature(features: &HashSet<u64>, num_hashes: usize) -> MinHashSignature {
    let mut values = vec![u64::MAX; num_hashes];

    for &feature in features {
        for (i, slot) in values.iter_mut().enumerate() {
            let hash = permuted_hash(feature, i as u32);
            if hash < *slot {
                *slot = hash;
            }
        }
    }

    MinHashSignature { values }
}

/// Estimate Jaccard similarity from two MinHash signatures.
pub fn estimate_jaccard(a: &MinHashSignature, b: &MinHashSignature) -> f64 {
    if a.values.len() != b.values.len() || a.values.is_empty() {
        return 0.0;
    }
    let matches = a
        .values
        .iter()
        .zip(b.values.iter())
        .filter(|(x, y)| x == y)
        .count();
    matches as f64 / a.values.len() as f64
}

/// Exact Jaccard similarity between two feature sets.
pub fn exact_jaccard(a: &HashSet<u64>, b: &HashSet<u64>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

fn permuted_hash(value: u64, seed: u32) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(value.to_le_bytes());
    hasher.update(seed.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_sets_have_high_similarity() {
        let set: HashSet<u64> = (0..100).collect();
        let sig_a = compute_signature(&set, 64);
        let sig_b = compute_signature(&set, 64);
        let sim = estimate_jaccard(&sig_a, &sig_b);
        assert!((sim - 1.0).abs() < 0.01);
    }

    #[test]
    fn disjoint_sets_have_low_similarity() {
        let a: HashSet<u64> = (0..50).collect();
        let b: HashSet<u64> = (100..150).collect();
        let sig_a = compute_signature(&a, 128);
        let sig_b = compute_signature(&b, 128);
        let sim = estimate_jaccard(&sig_a, &sig_b);
        assert!(sim < 0.1);
    }
}
