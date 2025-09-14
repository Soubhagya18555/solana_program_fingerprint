//! Detailed similarity report generation for program comparisons.

use std::path::Path;

use crate::fingerprint_db::StoredFingerprint;
use crate::{
    compare_fingerprints, compare_files, fingerprint_file, minhash, simhash, ProgramFingerprint,
};

/// Severity tier for similarity based on estimated Jaccard score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimilarityTier {
    Identical,
    NearDuplicate,
    Related,
    Distinct,
}

/// Full comparison report between two programs.
#[derive(Debug, Clone)]
pub struct SimilarityReport {
    pub path_a: String,
    pub path_b: String,
    pub jaccard_estimate: f64,
    pub jaccard_exact: f64,
    pub simhash_similarity: f64,
    pub hamming_distance: u32,
    pub ngram_count_a: usize,
    pub ngram_count_b: usize,
    pub tier: SimilarityTier,
    pub notes: Vec<String>,
}

impl SimilarityReport {
    pub fn from_fingerprints(
        path_a: &str,
        path_b: &str,
        fp_a: &ProgramFingerprint,
        fp_b: &ProgramFingerprint,
    ) -> Self {
        let cmp = compare_fingerprints(fp_a, fp_b);
        let tier = classify_similarity(cmp.jaccard_estimate);
        let mut notes = Vec::new();

        if cmp.hamming_distance <= 3 {
            notes.push("simhash hamming distance within clone detection threshold".into());
        }
        if cmp.jaccard_exact >= 0.9 && cmp.jaccard_estimate < 0.7 {
            notes.push("minhash estimate diverges from exact jaccard; increase hash count".into());
        }
        if fp_a.ngram_count == 0 || fp_b.ngram_count == 0 {
            notes.push("one program produced empty ngram set".into());
        }

        Self {
            path_a: path_a.to_string(),
            path_b: path_b.to_string(),
            jaccard_estimate: cmp.jaccard_estimate,
            jaccard_exact: cmp.jaccard_exact,
            simhash_similarity: cmp.simhash_similarity,
            hamming_distance: cmp.hamming_distance,
            ngram_count_a: fp_a.ngram_count,
            ngram_count_b: fp_b.ngram_count,
            tier,
            notes,
        }
    }
}

/// Compare two files and build a detailed report.
pub fn compare_paths(path_a: &Path, path_b: &Path) -> Result<SimilarityReport, String> {
    let fp_a = fingerprint_file(path_a)?;
    let fp_b = fingerprint_file(path_b)?;
    Ok(SimilarityReport::from_fingerprints(
        &path_a.display().to_string(),
        &path_b.display().to_string(),
        &fp_a,
        &fp_b,
    ))
}

/// Compare stored database entry against a live fingerprint.
pub fn compare_stored(stored: &StoredFingerprint, live: &ProgramFingerprint) -> SimilarityReport {
    let sig_a = minhash::MinHashSignature {
        values: stored.minhash.clone(),
    };
    let sig_b = live.minhash.clone();
    let jaccard_estimate = minhash::estimate_jaccard(&sig_a, &sig_b);
    let jaccard_exact = minhash::exact_jaccard(&stored.ngram_sample, &live.ngrams);
    let sim_a = simhash::SimHash(stored.simhash);
    let simhash_similarity = simhash::similarity_from_simhash(sim_a, live.simhash);
    let hamming_distance = simhash::hamming_distance(sim_a, live.simhash);
    let tier = classify_similarity(jaccard_estimate);

    SimilarityReport {
        path_a: stored.program_id.clone(),
        path_b: stored.source_path.clone(),
        jaccard_estimate,
        jaccard_exact,
        simhash_similarity,
        hamming_distance,
        ngram_count_a: stored.ngram_count,
        ngram_count_b: live.ngram_count,
        tier,
        notes: Vec::new(),
    }
}

/// Batch compare one query program against many candidates.
#[derive(Debug, Clone)]
pub struct BatchSimilarityResult {
    pub query: String,
    pub matches: Vec<SimilarityReport>,
}

pub fn batch_compare(
    query_path: &Path,
    candidates: &[&Path],
    min_jaccard: f64,
) -> Result<BatchSimilarityResult, String> {
    let query_fp = fingerprint_file(query_path)?;
    let query_label = query_path.display().to_string();
    let mut matches = Vec::new();

    for candidate in candidates {
        if *candidate == query_path {
            continue;
        }
        let fp = fingerprint_file(candidate)?;
        let report = SimilarityReport::from_fingerprints(
            &query_label,
            &candidate.display().to_string(),
            &query_fp,
            &fp,
        );
        if report.jaccard_estimate >= min_jaccard {
            matches.push(report);
        }
    }

    matches.sort_by(|a, b| {
        b.jaccard_estimate
            .partial_cmp(&a.jaccard_estimate)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(BatchSimilarityResult {
        query: query_label,
        matches,
    })
}

pub fn classify_similarity(jaccard: f64) -> SimilarityTier {
    if jaccard >= 0.98 {
        SimilarityTier::Identical
    } else if jaccard >= 0.80 {
        SimilarityTier::NearDuplicate
    } else if jaccard >= 0.40 {
        SimilarityTier::Related
    } else {
        SimilarityTier::Distinct
    }
}

pub fn format_report(report: &SimilarityReport) -> String {
    let tier = match report.tier {
        SimilarityTier::Identical => "identical",
        SimilarityTier::NearDuplicate => "near_duplicate",
        SimilarityTier::Related => "related",
        SimilarityTier::Distinct => "distinct",
    };

    let mut lines = vec![
        format!("similarity report"),
        format!("  a: {}", report.path_a),
        format!("  b: {}", report.path_b),
        format!("  tier: {tier}"),
        format!("  jaccard_estimate: {:.4}", report.jaccard_estimate),
        format!("  jaccard_exact:    {:.4}", report.jaccard_exact),
        format!("  simhash_similarity: {:.4}", report.simhash_similarity),
        format!("  hamming_distance: {}", report.hamming_distance),
        format!(
            "  ngrams: {} vs {}",
            report.ngram_count_a, report.ngram_count_b
        ),
    ];

    for note in &report.notes {
        lines.push(format!("  note: {note}"));
    }

    lines.join("\n")
}

pub fn format_batch(result: &BatchSimilarityResult) -> String {
    let mut lines = vec![
        format!("batch similarity for {}", result.query),
        format!("matches: {}", result.matches.len()),
    ];
    for (idx, report) in result.matches.iter().enumerate() {
        lines.push(format!(
            "  [{idx}] {} jaccard={:.4} tier={:?}",
            report.path_b, report.jaccard_estimate, report.tier
        ));
    }
    lines.join("\n")
}

/// Convenience wrapper returning comparison from file paths via existing API.
pub fn quick_compare(path_a: &Path, path_b: &Path) -> Result<SimilarityReport, String> {
    let _ = compare_files(path_a, path_b)?;
    compare_paths(path_a, path_b)
}
