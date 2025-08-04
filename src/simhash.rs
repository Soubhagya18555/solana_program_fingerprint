//! SimHash fingerprint generation for program bytecode features.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

/// A 64-bit SimHash fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SimHash(pub u64);

/// Compute a SimHash fingerprint from a set of feature hashes.
pub fn compute_simhash(features: &HashSet<u64>) -> SimHash {
    if features.is_empty() {
        return SimHash(0);
    }

    let mut weights = [0i64; 64];

    for &feature in features {
        let hash = feature_hash(feature);
        for bit in 0..64 {
            if (hash >> bit) & 1 == 1 {
                weights[bit] += 1;
            } else {
                weights[bit] -= 1;
            }
        }
    }

    let mut fingerprint = 0u64;
    for (bit, weight) in weights.iter().enumerate() {
        if *weight > 0 {
            fingerprint |= 1u64 << bit;
        }
    }

    SimHash(fingerprint)
}

/// Hamming distance between two SimHash values.
pub fn hamming_distance(a: SimHash, b: SimHash) -> u32 {
    (a.0 ^ b.0).count_ones()
}

/// Similarity score in [0.0, 1.0] derived from Hamming distance.
pub fn similarity_from_simhash(a: SimHash, b: SimHash) -> f64 {
    let dist = hamming_distance(a, b) as f64;
    1.0 - dist / 64.0
}

fn feature_hash(value: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(value.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_features_produce_same_simhash() {
        let set: HashSet<u64> = (0..50).collect();
        let a = compute_simhash(&set);
        let b = compute_simhash(&set);
        assert_eq!(a, b);
    }

    #[test]
    fn hamming_distance_is_zero_for_equal_hashes() {
        let h = SimHash(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(hamming_distance(h, h), 0);
    }
}
