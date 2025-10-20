use std::io::Write;
use std::path::Path;

use crate::{
    compare_files, fingerprint_bytes, fingerprint_file, minhash, opcode_ngram, simhash,
};

fn push_u16(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn push_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Build a minimal valid ELF64 executable with a .text section for testing.
fn build_test_elf(text: &[u8]) -> Vec<u8> {
    let mut elf = Vec::new();
    const SHOFF: u64 = 256;
    const TEXT_OFFSET: u64 = 512;
    const SHSTRTAB_OFFSET: u64 = 768;

    // ELF ident + header (64 bytes)
    elf.extend_from_slice(&[
        0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    push_u16(&mut elf, 2);    // ET_EXEC
    push_u16(&mut elf, 247);  // EM_BPF
    push_u32(&mut elf, 1);    // e_version
    push_u64(&mut elf, 0);    // e_entry
    push_u64(&mut elf, 0);    // e_phoff (no program headers)
    push_u64(&mut elf, SHOFF); // e_shoff
    push_u32(&mut elf, 0);    // e_flags
    push_u16(&mut elf, 64);   // e_ehsize
    push_u16(&mut elf, 0);    // e_phentsize
    push_u16(&mut elf, 0);    // e_phnum
    push_u16(&mut elf, 64);   // e_shentsize
    push_u16(&mut elf, 3);    // e_shnum
    push_u16(&mut elf, 2);    // e_shstrndx

    while elf.len() < SHOFF as usize {
        elf.push(0);
    }

    let text_size = text.len() as u64;

    // Section header 0: NULL (64 bytes)
    elf.extend_from_slice(&[0u8; 64]);

    // Section header 1: .text
    push_u32(&mut elf, 1); // sh_name
    push_u32(&mut elf, 1); // SHT_PROGBITS
    push_u64(&mut elf, 0x6); // SHF_ALLOC | SHF_EXECINSTR
    push_u64(&mut elf, 0); // sh_addr
    push_u64(&mut elf, TEXT_OFFSET); // sh_offset
    push_u64(&mut elf, text_size); // sh_size
    push_u32(&mut elf, 0); // sh_link
    push_u32(&mut elf, 0); // sh_info
    push_u64(&mut elf, 8); // sh_addralign
    push_u64(&mut elf, 0); // sh_entsize

    // Section header 2: .shstrtab
    push_u32(&mut elf, 7); // sh_name
    push_u32(&mut elf, 3); // SHT_STRTAB
    push_u64(&mut elf, 0); // sh_flags
    push_u64(&mut elf, 0); // sh_addr
    push_u64(&mut elf, SHSTRTAB_OFFSET); // sh_offset
    push_u64(&mut elf, 15); // sh_size
    push_u32(&mut elf, 0); // sh_link
    push_u32(&mut elf, 0); // sh_info
    push_u64(&mut elf, 1); // sh_addralign
    push_u64(&mut elf, 0); // sh_entsize

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

fn sample_bytecode(seed: u8) -> Vec<u8> {
    (0..32)
        .map(|i| {
            let opcode = (seed.wrapping_add(i as u8)) % 0x20;
            [
                opcode,
                (i % 16) | ((i % 16) << 4),
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        })
        .flatten()
        .collect()
}

#[test]
fn elf_loader_extracts_text_section() {
    let text = sample_bytecode(1);
    let elf = build_test_elf(&text);
    let parsed = crate::elf_loader::parse_elf_bytes(&elf).unwrap();
    assert_eq!(parsed.text, text);
}

#[test]
fn fingerprint_identical_programs() {
    let text = sample_bytecode(42);
    let fp_a = fingerprint_bytes(&text).unwrap();
    let fp_b = fingerprint_bytes(&text).unwrap();
    let cmp = crate::compare_fingerprints(&fp_a, &fp_b);
    assert!((cmp.jaccard_exact - 1.0).abs() < f64::EPSILON);
    assert!((cmp.simhash_similarity - 1.0).abs() < f64::EPSILON);
}

#[test]
fn fingerprint_different_programs() {
    let fp_a = fingerprint_bytes(&sample_bytecode(1)).unwrap();
    let fp_b = fingerprint_bytes(&sample_bytecode(99)).unwrap();
    let cmp = crate::compare_fingerprints(&fp_a, &fp_b);
    assert!(cmp.jaccard_exact < 1.0);
}

#[test]
fn ngram_extraction_produces_features() {
    let text = sample_bytecode(7);
    let ngrams = opcode_ngram::extract_ngrams(&text, 3);
    assert!(!ngrams.is_empty());
}

#[test]
fn minhash_estimates_jaccard() {
    let text = sample_bytecode(10);
    let ngrams = opcode_ngram::extract_ngrams(&text, 3);
    let sig = minhash::compute_signature(&ngrams, 64);
    let est = minhash::estimate_jaccard(&sig, &sig);
    assert!((est - 1.0).abs() < 0.05);
}

#[test]
fn simhash_is_deterministic() {
    let text = sample_bytecode(5);
    let ngrams = opcode_ngram::extract_ngrams(&text, 3);
    let a = simhash::compute_simhash(&ngrams);
    let b = simhash::compute_simhash(&ngrams);
    assert_eq!(a, b);
}

#[test]
fn cluster_groups_similar_files() {
    let dir = tempfile::tempdir().unwrap();
    let text_a = sample_bytecode(20);
    let text_b = sample_bytecode(20);
    let text_c = sample_bytecode(200);

    let path_a = dir.path().join("prog_a.so");
    let path_b = dir.path().join("prog_b.so");
    let path_c = dir.path().join("prog_c.so");

    std::fs::write(&path_a, build_test_elf(&text_a)).unwrap();
    std::fs::write(&path_b, build_test_elf(&text_b)).unwrap();
    std::fs::write(&path_c, build_test_elf(&text_c)).unwrap();

    let result = crate::cluster::cluster_directory(
        dir.path(),
        0.8,
        opcode_ngram::DEFAULT_NGRAM_SIZE,
        64,
    )
    .unwrap();

    assert!(!result.clusters.is_empty());
    let total_members: usize = result.clusters.iter().map(|c| c.members.len()).sum();
    assert_eq!(total_members, 3);
}

#[test]
fn compare_files_integration() {
    let dir = tempfile::tempdir().unwrap();
    let text = sample_bytecode(33);
    let path_a = dir.path().join("a.so");
    let path_b = dir.path().join("b.so");
    std::fs::write(&path_a, build_test_elf(&text)).unwrap();
    std::fs::write(&path_b, build_test_elf(&text)).unwrap();

    let result = compare_files(Path::new(&path_a), Path::new(&path_b)).unwrap();
    assert!((result.jaccard_exact - 1.0).abs() < f64::EPSILON);
}

#[test]
fn fingerprint_file_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("program.so");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&build_test_elf(&sample_bytecode(11)))
        .unwrap();

    let fp = fingerprint_file(&path).unwrap();
    assert!(fp.ngram_count > 0);
}
