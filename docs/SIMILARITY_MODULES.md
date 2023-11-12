# Similarity Engine Modules

Author: Soubhagya

Extended modules for `solana_program_fingerprint` supporting catalog indexing, normalization, and detailed reporting.

## bytecode_normalize

Stabilizes fingerprints by preprocessing `.text` bytes before ngram extraction:

* Strip no op `mov64 r0, 0` sequences
* Collapse 16 byte `lddw` loads to canonical 8 byte representation
* Remap register indices to canonical order so renaming does not affect similarity

Use `normalize_bytecode` directly or `fingerprint_bytes_with_config` from the library root.

## fingerprint_db

JSON backed catalog of program fingerprints:

```bash
solana_program_fingerprint index ./programs --output catalog/fingerprints.json
```

Each `StoredFingerprint` record includes MinHash values, SimHash, ngram count, and a sample ngram set for exact Jaccard verification.

## lsh_index

Locality Sensitive Hash index over MinHash signatures for sub linear similarity search:

* Default 16 bands over 128 hash functions
* `query_with_scores` reranks bucket candidates by estimated Jaccard

```bash
solana_program_fingerprint query suspect.so --db catalog/fingerprints.json --min_jaccard 0.6
```

## similarity_report

Structured comparison output with tier classification:

| Tier | Jaccard estimate |
|------|------------------|
| identical | >= 0.98 |
| near_duplicate | >= 0.80 |
| related | >= 0.40 |
| distinct | < 0.40 |

```bash
solana_program_fingerprint report program_a.so program_b.so
```

## Pipeline overview

```
ELF load -> normalize_bytecode -> extract_ngrams
                |                      |
                v                      v
         fingerprint_db          minhash + simhash
                |                      |
                v                      v
           lsh_index  <------ similarity_report
```

## Testing

Integration tests in `tests/similarity_modules_test.rs` cover normalization, LSH lookup, database roundtrip, and report tiers.

```bash
cargo test
```
