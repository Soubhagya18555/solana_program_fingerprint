use crate::{
    bytecode_normalize::{NormalizeConfig, compression_ratio, normalize_bytecode},
    fingerprint_db::FingerprintDb,
    lsh_index::{self, LshIndex},
    similarity_report::{self, SimilarityTier},
    fingerprint_bytes, fingerprint_bytes_with_config, fingerprint_file, minhash, opcode_ngram,
};

fn sample_bytecode(seed: u8) -> Vec<u8> {
    (0..32)
        .map(|i| {
            let opcode = (seed.wrapping_add(i as u8)) % 0x20;
            [opcode, (i % 16) | ((i % 16) << 4), 0, 0, 0, 0, 0, 0]
        })
        .flatten()
        .collect()
}

fn build_test_elf(text: &[u8]) -> Vec<u8> {
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

#[test]
fn bytecode_normalize_strips_nops() {
    let mut text = sample_bytecode(1);
    text[0..8].copy_from_slice(&[0xb7, 0, 0, 0, 0, 0, 0, 0]);
    let result = normalize_bytecode(&text, NormalizeConfig::default());
    assert!(result.removed_instructions >= 1);
    assert!(compression_ratio(&result) <= 1.0);
}

#[test]
fn lsh_index_finds_similar_program() {
    let text = sample_bytecode(42);
    let ngrams = opcode_ngram::extract_ngrams(&text, 3);
    let sig = minhash::compute_signature(&ngrams, 64);
    let mut index = LshIndex::new(64, 8).unwrap();
    index.insert("target", sig.clone());
    let hits = index.query_with_scores(&sig, 0.9);
    assert!(!hits.is_empty());
}

#[test]
fn similarity_report_tiers_identical() {
    let text = sample_bytecode(7);
    let fp_a = fingerprint_bytes(&text).unwrap();
    let fp_b = fingerprint_bytes(&text).unwrap();
    let report = similarity_report::SimilarityReport::from_fingerprints("a", "b", &fp_a, &fp_b);
    assert_eq!(report.tier, SimilarityTier::Identical);
}

#[test]
fn fingerprint_db_scan_and_query() {
    let dir = tempfile::tempdir().unwrap();
    let text = sample_bytecode(20);
    std::fs::write(dir.path().join("prog.so"), build_test_elf(&text)).unwrap();
    let db = FingerprintDb::scan_directory(dir.path(), 3, 64).unwrap();
    assert_eq!(db.len(), 1);
    let index = lsh_index::build_index_from_db(&db, 8).unwrap();
    assert_eq!(index.len(), 1);
}

#[test]
fn similarity_report_from_files() {
    let dir = tempfile::tempdir().unwrap();
    let text = sample_bytecode(15);
    let path_a = dir.path().join("a.so");
    let path_b = dir.path().join("b.so");
    std::fs::write(&path_a, build_test_elf(&text)).unwrap();
    std::fs::write(&path_b, build_test_elf(&text)).unwrap();
    let report = similarity_report::compare_paths(&path_a, &path_b).unwrap();
    assert!((report.jaccard_exact - 1.0).abs() < f64::EPSILON);
}

#[test]
fn normalized_fingerprint_differs_with_policy() {
    let mut text = sample_bytecode(3);
    text[0..8].copy_from_slice(&[0xb7, 0, 0, 0, 0, 0, 0, 0]);
    let raw = fingerprint_bytes(&text).unwrap();
    let norm = fingerprint_bytes_with_config(
        &text,
        NormalizeConfig {
            strip_nops: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(raw.ngram_count, norm.ngram_count);
}
