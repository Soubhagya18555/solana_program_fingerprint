# Algorithms

Technical reference for the bytecode fingerprinting pipeline in `solana_program_fingerprint`.

## Pipeline

```
ELF file  -->  .text extraction  -->  SBF normalization  -->  n-grams
                                                              |
                                    +-------------------------+
                                    |
                                    v
                              MinHash signature
                              SimHash fingerprint
                                    |
                                    v
                         pairwise / cluster comparison
```

## ELF Loading

Solana deployable programs are ELF64 objects with `e_machine = EM_BPF (247)`. The loader scans section headers for the first `SHT_PROGBITS` section with the `SHF_EXECINSTR` flag set. That section contains the SBF instruction stream executed by the Solana runtime.

Non-executable sections (`.rodata`, `.data`, metadata) are ignored because they do not reflect control-flow structure.

## SBF Instruction Normalization

Each SBF instruction is 8 bytes:

| Offset | Field        | Size |
|--------|--------------|------|
| 0      | opcode       | 1    |
| 1      | dst/src regs | 1    |
| 2-3    | offset       | 2    |
| 4-7    | immediate    | 4    |

Normalization retains `opcode`, `dst_reg` (low nibble), and `src_reg` (high nibble). Branch offsets and immediates are discarded. Two programs that share instruction patterns but use different constants or jump targets still produce matching tokens.

A normalized token is packed into a 32-bit key:

```
key = (opcode << 16) | (dst_reg << 8) | src_reg
```

## Opcode N-Grams

An n-gram is a contiguous sequence of `n` normalized opcode tokens (default `n = 3`). Sliding over the instruction stream produces a multiset of 64-bit packed n-gram keys:

```
ngram_key = token_0 | (token_1 << 21) | (token_2 << 42) | ...
```

Each token occupies 21 bits (sufficient for the 32-bit normalized key with truncation). The resulting set is the feature set for all downstream hashing.

N-grams capture local instruction context. A single-register change in one instruction alters up to `n` n-grams, providing graded sensitivity rather than all-or-nothing byte equality.

## MinHash

MinHash estimates Jaccard similarity between two sets without computing the full intersection.

Given feature set `S` and `k` independent hash functions `h_0 ... h_{k-1}`, the signature is:

```
sig[i] = min_{x in S} h_i(x)
```

For two sets `A` and `B`:

```
J_hat(A, B) = (1/k) * |{ i : sig_A[i] == sig_B[i] }|
```

`J_hat` converges to the true Jaccard index `|A ∩ B| / |A ∪ B|` as `k` increases. This implementation uses `k = 128` permutations derived from SHA-256 over `(feature, seed)`.

### Properties

- Sublinear comparison: signatures are fixed size regardless of program length
- Unbiased estimator for Jaccard similarity of n-gram sets
- Robust to small edits when combined with n-gram features

## SimHash

SimHash produces a compact 64-bit fingerprint suitable for near-duplicate detection.

For each feature `f` in the set, compute a 64-bit hash `H(f)`. Maintain a weight vector `w[0..63]`. For each bit position `b`:

```
if bit b of H(f) is 1:  w[b] += 1
else:                   w[b] -= 1
```

The fingerprint bit `b` is set if `w[b] > 0`.

Similarity between two SimHash values is measured by Hamming distance:

```
sim = 1 - hamming(a, b) / 64
```

SimHash is sensitive to the majority orientation of feature bits. It complements MinHash: MinHash estimates set overlap; SimHash provides a single hash amenable to bucketing and fast pre-filtering.

## Clustering

Directory clustering operates on MinHash Jaccard estimates:

1. Load every ELF program under the target directory
2. Extract n-gram sets and compute MinHash signatures
3. For each pair `(i, j)`, compute `J_hat`. If `J_hat >= threshold`, union the pair
4. Emit connected components as clusters

Union-find with path compression groups transitively similar programs. Each cluster reports member paths and average pairwise similarity within the group.

Default threshold is `0.5`. Raise it to demand near-identical bytecode; lower it to catch loosely related variants.

## Complexity

| Stage            | Time                          | Space              |
|------------------|-------------------------------|--------------------|
| ELF parse        | O(file size)                  | O(text size)       |
| N-gram extract   | O(instructions)               | O(unique n-grams)  |
| MinHash          | O(|features| * k)             | O(k)               |
| SimHash          | O(|features|)                 | O(1)               |
| Cluster (n files)| O(n^2 * k) for pairwise pass  | O(n * k)           |

For large corpora, pre-bucket by SimHash Hamming distance before computing full MinHash comparisons.

## Limitations

- Opcode normalization ignores immediates; programs with identical structure but semantically different constants may appear similar
- Packing n-gram keys into 64 bits can collide for very long programs; increase `n` or use exact Jaccard for final verification
- MinHash is probabilistic; use `jaccard_exact` in compare output when precision matters
- Only the first executable `SHT_PROGBITS` section is analyzed; non-standard ELF layouts may require loader extensions

## References

- Broder, A. Z. "On the resemblance and containment of documents." (MinHash)
- Charikar, M. S. "Similarity estimation techniques from rounding algorithms." (SimHash)
- Solana SBF instruction set documentation
