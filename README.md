# solana_program_fingerprint

Bytecode similarity engine for Solana on-chain programs. Extracts normalized SBF opcode n-grams from ELF program binaries and computes MinHash and SimHash fingerprints for pairwise comparison and directory clustering.

**Author:** Soubhagya  
**License:** MIT

## Overview

Solana programs ship as ELF shared objects containing SBF (Solana Berkeley Packet Filter) bytecode. Two programs may differ in immediates or data sections while sharing the same control flow. This tool fingerprints the executable `.text` section using locality-sensitive hashing so that near-duplicate programs surface during audits, incident response, and malware triage.

## Installation

```bash
cargo build --release
```

The binary is placed at `target/release/solana_program_fingerprint`.

## Usage

### Compare two programs

```bash
solana_program_fingerprint compare program_a.so program_b.so
```

Output includes MinHash Jaccard estimate, exact Jaccard over n-gram sets, SimHash similarity, and Hamming distance.

### Fingerprint a single program

```bash
solana_program_fingerprint fingerprint my_program.so
```

Prints n-gram count, 64-bit SimHash, and the full MinHash signature.

### Cluster programs in a directory

```bash
solana_program_fingerprint cluster ./programs --threshold 0.5
```

Walks the directory recursively, loads every valid ELF program, and groups files whose estimated Jaccard similarity meets the threshold. Default threshold is `0.5`.

## Architecture

```
src/
  main.rs            CLI entry point
  lib.rs             Public API and fingerprint orchestration
  elf_loader.rs      Parse ELF and extract .text section
  opcode_ngram.rs    Normalize SBF instructions into n-grams
  minhash.rs         MinHash signatures and Jaccard estimation
  simhash.rs         64-bit SimHash fingerprints
  cluster.rs         Union-find clustering by similarity
```

## Algorithms

See [docs/ALGORITHMS.md](docs/ALGORITHMS.md) for detailed descriptions of opcode normalization, MinHash, SimHash, and the clustering procedure.

## Testing

```bash
cargo test
```

Integration tests build synthetic ELF binaries with injectable SBF text sections so the pipeline can be validated without real on-chain artifacts.

## Requirements

- Rust 1.70+
- Solana program binaries in standard ELF format (`.so`)

## Use Cases

- Detect redeployed or lightly modified drainer programs
- Group upgrade variants of the same Anchor program
- Build similarity indexes for threat intelligence pipelines
- Pre-filter candidates before manual disassembly
