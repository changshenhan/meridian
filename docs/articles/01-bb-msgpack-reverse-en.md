# Anatomy of a Barretenberg Proof Bundle: msgpack where you don't expect it, raw fields where you do

*Reverse-engineering the on-disk formats of `nargo`/`bb` (Barretenberg) artifacts, byte by byte.*

Environment pinned for everything below: **bb `6.0.0-nightly.20260724`**, **nargo/noirc `1.0.0-beta.26`** (`40d6574f851d926f93e0c3a271bac3e6e82ac905`), circuit = Mist's `spend_authorization` (82,742 constraints, 15,819 ACIR opcodes, `bb -t evm-no-zk` ⇒ UltraKeccak flavor). Every number in this article was produced by running the pipeline and parsing the outputs on that stack; the companion script [`01-bb-msgpack-parse.py`](./01-bb-msgpack-parse.py) (zero dependencies, stdlib-only Python) reproduces every table.

## TL;DR

| artifact | produced by | format |
|---|---|---|
| `<circuit>.gz` (witness) | `nargo execute` | **msgpack** (gzipped), 2 top-level objects |
| `<circuit>.json` `bytecode` field (ACIR) | `nargo compile` | **base64 → gzip → msgpack** (the gzip is undocumented) |
| `vk` | `bb write_vk` | raw 32-byte big-endian field elements, **not msgpack** |
| `proof` | `bb prove` | raw 32-byte big-endian field elements, **not msgpack** |
| `public_inputs` | `bb prove` | raw 32-byte big-endian field elements, **not msgpack** |
| `vk_hash` | `bb write_vk` | 32 bytes, and **not** `keccak256(vk)` |

If you take one thing away: the Noir/ACVM layer (witness, circuit bytecode) speaks msgpack; the Barretenberg proving layer (vk, proof, public inputs) speaks raw 254-bit field elements. Tools that assume one convention for "the bb bundle" get both halves wrong.

## The bundle

Commands (from the repo's ZK pipeline, `scripts/formal_zk.sh:30-41`):

```bash
cd circuits
nargo execute                                     # → target/spend_authorization.gz
bb write_vk -t evm-no-zk -b target/spend_authorization.json -o target   # → target/vk, target/vk_hash
bb prove    -t evm-no-zk -b target/spend_authorization.json \
            -w target/spend_authorization.gz -o target                  # → target/proof, target/public_inputs
bb verify   -t evm-no-zk -p target/proof -k target/vk                   # → "Proof verified successfully"
```

`-t evm-no-zk` translates to `oracle_hash=keccak` + `disable_zk=true`, i.e. the UltraKeccak flavor; if you write the VK with a different target and verify with another, bb silently mismatches (the VK sizes differ: 1,888 B for UltraKeccak vs 3,680 B for the default Poseidon2 flavor — this bit us in CI once, see `scripts/formal_zk.sh:31-35`).

On-disk sizes for this circuit:

```
spend_authorization.gz   214,636 B   (witness, gunzips to 466,231 B)
spend_authorization.json 555,629 B   (ACIR program, JSON wrapper)
vk                         1,888 B   (59 × 32 B)
vk_hash                       32 B
proof                      8,128 B   (254 × 32 B)
public_inputs              3,872 B   (121 × 32 B)
```

Opening bytes — this is where the split becomes visible:

```
witness (gunzipped):  03 91 91 92 00 de 31 43 00 c4 20 00 00 ...   ← msgpack
vk:                   0000...0011 0000...0081 0000...0005 ...      ← raw fields
proof:                0000...0000 0000...0000 ... (8 zero words)   ← raw fields
public_inputs:        0000...00ea 0000...00e1 ...                  ← raw fields
```

## The witness file: a msgpack stream with a bare version integer

Gunzip `spend_authorization.gz` and you are looking at **two msgpack objects back to back**, not one:

```
object 0: 03                        → positive fixint 3
object 1: 91 91 92 00 de 31 43 ...  → fixarray(1) [ fixarray(1) [ fixarray(2) [ 0, map16(12,611) ] ] ]
```

Decoded:

- A **bare leading integer `3`** precedes the payload. Every witness file we dumped starts with it (`spend_authorization`, `gen_witness`, `sdkproof`) — a format-version marker emitted by the serializer. Naive "decode one msgpack object" parsers either choke or silently drop it. We treat the value as opaque: pin it in a regression test, don't interpret it.
- The payload is positional, not a map: `[[[3, {…}]]]` — the inner map is the witness map itself.
- Map keys are **witness indices**, values are **`bin8` (prefix `c4 20`) holding exactly 32 bytes**, big-endian field elements. `c4 20` is the workhorse of this whole format: it appears once per witness slot.
- **The numbering is sparse.** 12,611 entries with keys spanning `0..15,460` — 2,850 indices in that range are simply absent, and 2,448 present values are zero:

```
witness spend_authorization: 12,611 entries, keys 0..15,460, gaps=2,850, zero values=2,448
witness gen_witness:          6,887 entries, keys 0..10,140, gaps=3,254, zero values=  790
witness sdkproof:            12,611 entries, keys 0..15,460, gaps=2,850, zero values=2,301
```

  Do not allocate `WitnessMap` as `vec![F::zero(); max_key+1]` and do not assume `keys == 0..n-1`; iterate the map.

The first three witness entries are a free cross-check that you're reading the right bytes. The circuit's `Prover.toml` starts with:

```toml
agent_commit = [0xea, 0xe1, 0xfc, 0x57, ...]
```

and witness `w0..w2` are `...00ea`, `...00e1`, `...00fc` — the first three bytes of `agent_commit`, one byte per field element, because the circuit declares `agent_commit` as `[u8; 32]` (each byte becomes its own BN254 field element). The `public_inputs` file's first three words end in the same three bytes. Three files, one truth.

## The circuit JSON: base64 → gzip → msgpack

`spend_authorization.json` is a JSON document with top-level keys `noir_version, hash, abi, bytecode, debug_symbols, file_map`. The `bytecode` field is base64 — but decoding it does *not* give you msgpack:

```
bytecode: 280,752 b64 chars → 210,563 bytes, first bytes 1f 8b 08 00 ...
          → GZIP. Decompressed: 2,650,445 bytes of msgpack.
```

That hidden gzip layer is not in any documentation we could find. (`base64 -d circuit.b64 | gunzip` is the pipeline.)

The decompressed payload is, again, a bare `3` followed by a positional array: `[functions, unconstrained_functions]`. There is exactly one function here (`main`), and it is **not a map either** — it's a positional array:

```
Function[0] = 'main'                        function name
Function[1] = opcodes (15,819 elements)     the ACIR opcodes
Function[2] = 520 ints, 121..640            (semantics inferred: derived witness block)
Function[3] = 121 ints, 0..120              witness indices of the public inputs
Function[4] = []                            return witness (main returns nothing)
Function[5] = 1,061 pairs                   (semantics inferred)
```

`Function[3]` is a nice confirmation of the input ordering: 121 public-input witness indices `0..120`, matching the 121 public-input fields of this circuit (see the input table in the circuit source, `circuits/src/main.nr`, and the repo spec §5.1).

Each opcode is a **single-key map** — serde's *externally tagged enum* representation — where the key is the variant name:

```jsonc
{"AssertZero":        [...]}   // 8,897 of them
{"BlackBoxFuncCall":  [...]}   // 3,682
{"BrilligCall":       [...]}   // 2,982
{"MemoryOp":          [...]}   //   254
{"MemoryInit":        [...]}   //     4
                                // 15,819 total — matches `bb info` exactly
```

`bb info` reports `acir_opcodes: 15819`; the msgpack array length is 15,819. When a tool and a format agree to the unit, you've found the right element.

The 12 **unconstrained (Brillig) functions** ride along as `[name, bytecode]` pairs, and their names are a tour of Noir's stdlib internals:

```
build_msg_block_helper ×2 (331 / 408 opcodes)   field_less_than (16)    decompose_hint (21)
lte_hint (33)   __add_unconstrained (38)        get_wnaf_slices ×2 (386 / 402)
get_borrow_flag (28)    directive_to_radix (17) directive_invert (9)    directive_integer_quotient (8)
```

The WNAF slices and borrow flags are the EdDSA-verification machinery; the `directive_*` functions are the ACVM's unconstrained hints.

## Where msgpack *isn't*: vk, proof, public_inputs

### vk — 1,888 bytes = 3 scalars + 28 curve points

The VK file is 59 field elements, 32 bytes each, big-endian. No msgpack, no framing, no header. The three scalars:

| word | value | meaning |
|---|---|---|
| 0 | 17 | `log_circuit_size` (N = 131,072 = 2¹⁷) |
| 1 | 129 | `num_public_inputs` — see the +8 story below |
| 2 | 5 | `pub_inputs_offset` |

Then 28 `(x, y)` pairs — **BN254 G1 points**, `y² = x³ + 3` over the base field. How do we know they're curve points without bb telling us? Scan every adjacent word pair and test the curve equation; 25 of the 28 pairs satisfy it and the remaining 3 are `(0, 0)` — barretenberg's encoding of the point at infinity (consistent with the transcript's "Point-at-infinity detection: auto-detected from (0, 0) coordinates", `barretenberg/cpp/src/barretenberg/transcript/README.md`).

Which points? The generated Solidity verifier (`circuits/artifacts/UltraVerifier.sol`) embeds the same 28 points *with names*, so we can label ours by value-matching. The result is instructive — **the file order is not the Solidity order**:

```
file  words 3..58:  s1 s2 s3 s4  id1 id2 id3 id4  lagrangeFirst lagrangeLast
                    qLookup t1 t2 t3 t4  qm qr qo qc ql q4
                    qArith qDeltaRange qElliptic qMemory
                    [zero ×3:  qNnf, qPoseidon2External, qPoseidon2Internal]

Solidity loadVerificationKey() order:
                    ql qr qo q4 qm qc  qLookup qArith qDeltaRange qElliptic qMemory
                    qNnf qPoseidon2External qPoseidon2Internal  s1 s2 s3 s4
                    t1 t2 t3 t4  id1 id2 id3 id4  lagrangeFirst lagrangeLast
```

Three selectors are zero points in this circuit (`qNnf`, `qPoseidon2External`, `qPoseidon2Internal` — no NNF lookups, no Poseidon2 gates), and they land at the *end* of the file but the *middle* of the Solidity initializer. Any code that maps file offsets to selector names via the Solidity order is off by a whole section. We pinned ours by value-matching, not by assuming order — and so should you.

One more trap we hit while getting here: **it's BN254 G1, not Grumpkin.** Grumpkin (`y² = x³ − 17`) is the curve where Noir's Pedersen hash generators live; Honk's EVM commitment points satisfy `y² = x³ + 3`. Checking the wrong equation finds nothing, and — worse — checking `y == x³ + b` instead of `y² == x³ + b` (a "polynomial evaluation pair" test, which is what our first scan accidentally implemented) also finds nothing. Both failures look identical from the outside: zero hits, as if the file had no structure at all.

### proof — 8,128 bytes = 254 field elements

Also raw. Structure visible from the outside:

```
words 0..7      : all zero                      ← 8 reserved words
words 8..23     : 8 BN254 G1 points             ← on-curve runs
words 24..184   : Fr scalars (sumcheck univariates / challenges / evals)
words 185..187  : zero
words 188..200  : Fr scalars
words 201..232  : 16 BN254 G1 points
words 233..249  : Fr scalars
words 250..253  : 2 BN254 G1 points
```

Two anchors:

- **The 8 leading zeros are structural, not padding-by-accident.** The generated Solidity verifier carries `PAIRING_POINTS_SIZE = 8` (`circuits/artifacts/UltraVerifier.sol:334`); every non-recursive proof on this stack begins with 8 zero field elements where recursive aggregation objects would go. If your prover/verifier glue slices the proof assuming `proof[0]` is the first "real" value, it's off by 256 bytes.
- The point runs were found by the same curve scan as the VK — 8 + 16 + 2 on-curve pairs. 16 ≈ `LOG_N − 1` (17), consistent with the fold-commitment section of an UltraHonk-family proof; the naming of the remaining sections is inferred from size/position, not from source, and is flagged as such.

Negative control, actually run (flip one bit of byte 4000 and re-verify):

```
tampered byte 4000 → 0x24
bb verify: "UltraVerifier: verification failed at reduction step"  (exit 1)
clean proof: "Proof verified successfully"                          (exit 0)
```

The binding is real: proof and public inputs are cryptographically tied, and any single-byte change anywhere in the 8,128 bytes is rejected.

### public_inputs — 121 × 32 B, and the "+8" discrepancy

`public_inputs` is 3,872 bytes = **121 fields**, big-endian, one per element, in circuit-parameter order `agent_commit ‖ delegation_hash ‖ recipient ‖ amount ‖ category ‖ spend_nonce ‖ expires_at ‖ revocation_root ‖ now`. Two encoding rules matter and are easy to get wrong (they cost us a whole debugging round — the serialization is reimplemented with tests at `aggregator/src/bb.rs:56-70`):

- `[u8; N]` arrays expand **one byte per field element** (32 B each, zero-padded, big-endian);
- a `u64` (e.g. `amount`) is **one** field element;
- a `pub Field` (here `revocation_root`) is **one** field element as a full 256-bit big-endian integer — even though the Rust-side type is `[u8; 32]`. Same 32 bytes, completely different semantics: byte-array means "32 separate field elements", Field means "one integer". If you split a Field into per-byte fields, you get 152 fields instead of 121 and bb fails the proof.

But the VK's scalar word 1 says **129**, and the generated Solidity verifier agrees: `NUMBER_OF_PUBLIC_INPUTS = 129` (`UltraVerifier.sol:7`). The difference is exactly `PAIRING_POINTS_SIZE = 8`: bb reserves 8 field slots for recursive pairing-point objects in its *internal* public-input accounting, while the on-disk `public_inputs` file and the circuit ABI carry the 121 "real" ones. Same word, two counts — and the Solidity verifier's `verify(bytes calldata proof, bytes32[] calldata publicInputs)` wants the array padded/handled according to the 129-side of the ledger. If you're wiring a custom verifier, decide explicitly which of the two conventions each interface speaks.

### vk_hash — not a file hash

The natural guess is `keccak256(vk)`. Measured:

```
keccak256(vk file) = 0x82a46ef89b9c1393e4d88c353164dc78de7c4c52e67ddf9d8037a8d0762aad94
vk_hash file       = 0x21dbd212d938d340743800c82e622bbe8e147bc1f30afe7af873bda8962aad92
```

Not equal (and not equal after dropping trailing zeros, reordering, or Montgomery-form re-encoding either — nine candidates tested). The value matches the `VK_HASH` constant embedded in `UltraVerifier.sol`, where it is consumed as a **Fiat-Shamir transcript seed**, not a file digest: barretenberg computes it via `vk->hash_with_origin_tagging(*transcript)` (`barretenberg/cpp/src/barretenberg/ultra_honk/oink_verifier.cpp`), i.e. the hash input is a transcript-tagged serialization, not the on-disk buffer. Practical rule: treat `vk_hash` as an opaque 32-byte handle, pass it through untouched, and never try to recompute it from the file.

## The parser

Everything above falls out of ~200 lines of dependency-free Python: a complete msgpack decoder (RFC 8949 subset — `bin8/16/32` kept as bytes so field elements stay byte-addressable), a "decode objects until exhausted" stream reader, a gzip sniff, and the curve scanner. The one design decision worth copying: **decode bins as bytes and print them as hex**, so witness values (`c4 20 …`) remain byte-addressable instead of being mangled into ints or UTF-8.

```bash
python3 01-bb-msgpack-parse.py circuits/target            # all sections
python3 01-bb-msgpack-parse.py circuits/target witness    # just the witness map
```

For the vk/proof side there is no library to lean on: read 32-byte big-endian words and test the curve equation you actually mean.

## Pitfall list (the parts the docs don't cover)

1. **Two serialization regimes, one bundle.** Witness + circuit bytecode = msgpack; vk + proof + public_inputs + vk_hash = raw 32-byte BE fields. Tools that grep for msgpack in a proof file find nothing, and tools that slice the witness as fixed 32-byte words find garbage.
2. **The circuit `bytecode` is `base64(gzip(msgpack))`** — the gzip layer is invisible in the JSON.
3. **msgpack streams, not objects.** Witness and program files open with a bare fixint `3` (version marker) and then the payload. Stream-decode.
4. **Witness maps are sparse.** 12,611 entries over a `0..15,460` key space with 2,850 holes. `keys.max() != len`.
5. **Positional structs, not maps.** Program/Function/opcode payloads are arrays; field meaning is position- and version-pinned. The opcode enum is the only map-shaped thing (`{"VariantName": payload}`).
6. **VK point order ≠ Solidity point order**, and `(0,0)` = point at infinity. Value-match, don't order-match.
7. **Honk EVM commitments are BN254 G1** (`y²=x³+3`), not Grumpkin (`y²=x³−17`) — both curves are in this stack, on different layers.
8. **129 vs 121 public inputs.** bb's internal count includes 8 reserved pairing-point slots; the file/ABI count doesn't.
9. **`vk_hash` is a transcript-tagged hash, not `keccak256(vk)`** — treat as opaque.
10. **`bb verify -i` defaults to `<cwd>/target/public_inputs`** — a path bound to the caller's working directory. Pass `-i` explicitly; this is codified in the repo's verifier wrapper (`aggregator/src/bb.rs:6-7`).
11. **Flavor tags must match end-to-end.** `-t evm-no-zk` (UltraKeccak, VK 1,888 B) vs default Poseidon2 (VK 3,680 B) — write_vk/prove/verify/write_solidity_verifier must all carry the same target (`scripts/formal_zk.sh:31-35`).

## Reproducing

WSL2 (Ubuntu), toolchain in `$HOME/.bb` and `$HOME/.nargo/bin`; repo at `/mnt/d/...`:

```bash
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
git clone <this repo> && cd mist
bash scripts/formal_zk.sh                    # full pipeline: witness → vk → proof → verify → EVM verifier
python3 /path/to/01-bb-msgpack-parse.py circuits/target all
```

Numbers you should see on the same stack: constraints 82,742 (budget 262,144), ACIR opcodes 15,819, prove p50 0.46 s, verify p99 15.1 ms (our measured baseline — note the CLI-process overhead; the pure verification math is far below that).

## Sources

- First-hand: all hex dumps, tables, and counts in this article were generated from the artifact bundle above (commands quoted inline; companion script re-derives every table).
- Repo: `scripts/formal_zk.sh` (pipeline + flavor notes), `aggregator/src/bb.rs` (public-input serialization contract, `verifier -i` behavior), `circuits/src/main.nr` (circuit), `circuits/bench/baseline_s09.json` (timings), `docs/TECH_SPEC.md` §5.1/§6.13 (input table, verifier wrapper spec).
- Upstream (read, not run): `barretenberg/cpp/src/barretenberg/ultra_honk/oink_verifier.cpp` (`hash_with_origin_tagging`), `barretenberg/cpp/src/barretenberg/api/api_ultra_honk.cpp` (which files `write_vk`/`prove` emit), `barretenberg/cpp/src/barretenberg/dsl/acir_proofs/honk_contract.hpp` (VK_HASH as transcript seed, verifier constants), `barretenberg/cpp/src/barretenberg/transcript/README.md` (hash-buffer semantics, `(0,0)` infinity).
- Marked as inferred (not source-confirmed): semantics of `Function[2]`/`Function[5]`, section names inside the proof beyond the curve-point runs, and the exact meaning of the leading `3`. Treat those as version-pinned observations for `nargo 1.0.0-beta.26` / `bb 6.0.0-nightly.20260724`.
