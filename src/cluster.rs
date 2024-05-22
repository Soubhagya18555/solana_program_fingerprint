//! Cluster programs by bytecode similarity threshold.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::elf_loader;
use crate::minhash::{self, MinHashSignature};
use crate::opcode_ngram;

/// A cluster of program files that share similar bytecode fingerprints.
#[derive(Debug, Clone)]
pub struct Cluster {
    pub id: usize,
    pub members: Vec<PathBuf>,
    pub avg_similarity: f64,
}

/// Result of clustering a directory of program binaries.
#[derive(Debug)]
pub struct ClusterResult {
    pub clusters: Vec<Cluster>,
    pub signatures: HashMap<PathBuf, MinHashSignature>,
}

/// Cluster all ELF program files under `dir` using MinHash Jaccard estimation.
pub fn cluster_directory(
    dir: &Path,
    threshold: f64,
    ngram_size: usize,
    num_hashes: usize,
) -> Result<ClusterResult, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut signatures: HashMap<PathBuf, MinHashSignature> = HashMap::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(bytecode) = elf_loader::load_program(path) {
            let ngrams = opcode_ngram::extract_ngrams(&bytecode.text, ngram_size);
            if !ngrams.is_empty() {
                let sig = minhash::compute_signature(&ngrams, num_hashes);
                signatures.insert(path.to_path_buf(), sig);
                files.push(path.to_path_buf());
            }
        }
    }

    if files.is_empty() {
        return Ok(ClusterResult {
            clusters: vec![],
            signatures,
        });
    }

    let n = files.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], i: usize) -> usize {
        if parent[i] != i {
            let root = find(parent, parent[i]);
            parent[i] = root;
        }
        parent[i]
    }

    fn union(parent: &mut [usize], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent[rb] = ra;
        }
    }

    let mut pair_similarities: HashMap<(usize, usize), f64> = HashMap::new();

    for i in 0..n {
        for j in (i + 1)..n {
            let sig_a = signatures.get(&files[i]).unwrap();
            let sig_b = signatures.get(&files[j]).unwrap();
            let sim = minhash::estimate_jaccard(sig_a, sig_b);
            pair_similarities.insert((i, j), sim);
            if sim >= threshold {
                union(&mut parent, i, j);
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent.clone(), i);
        groups.entry(root).or_default().push(i);
    }

    let mut clusters: Vec<Cluster> = groups
        .into_values()
        .enumerate()
        .map(|(id, indices)| {
            let members: Vec<PathBuf> = indices.iter().map(|&i| files[i].clone()).collect();
            let mut sim_sum = 0.0;
            let mut pair_count = 0usize;
            for a in 0..indices.len() {
                for b in (a + 1)..indices.len() {
                    let key = if indices[a] < indices[b] {
                        (indices[a], indices[b])
                    } else {
                        (indices[b], indices[a])
                    };
                    if let Some(&sim) = pair_similarities.get(&key) {
                        sim_sum += sim;
                        pair_count += 1;
                    }
                }
            }
            let avg_similarity = if pair_count > 0 {
                sim_sum / pair_count as f64
            } else {
                1.0
            };
            Cluster {
                id,
                members,
                avg_similarity,
            }
        })
        .collect();

    clusters.sort_by(|a, b| b.members.len().cmp(&a.members.len()));

    Ok(ClusterResult {
        clusters,
        signatures,
    })
}
