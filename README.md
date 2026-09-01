# Mist

[![CI](https://github.com/changshenhan/mist/actions/workflows/ci.yml/badge.svg)](https://github.com/changshenhan/mist/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Elastic--2.0-blue)

**Settlement infrastructure for the agent economy.** Mist is how AI agents pay each
other and vendors on-chain without paying one transaction per payment:
a **Delegated Spend Authority (DSA)** authorization primitive plus an **optimistic
batch-settlement aggregator**. Every line is written to survive published benchmarks.

简体中文文档：[README.zh-CN.md](README.zh-CN.md)

## Why batch settlement

Upstream x402 settles one payment as one EIP-3009 transaction. We measured what that
actually costs on Base — with the real USDC bytecode and mainnet receipts, all
commands and logs published:

- **61,105–90,053 gas per payment** (warm/fresh payee) — 1,000 payments burn
  15–23% of an entire 400M-gas Base block
- Mist replaces that with **one settlement transaction per batch**:
  ≈ (246,000 + 78,958 × R) / N per payment — at N=1,000, R=1 that is **325 gas, 188× cheaper**
- Honest negative result included: with all-unique recipients, batching is
  ~30% **more** expensive than direct — batching wins when recipients repeat
  (N/R > ~5), which is exactly merchant traffic

Full ledger: [`docs/articles/02-x402-gas-ledger-en.md`](docs/articles/02-x402-gas-ledger-en.md)

## Live on Base mainnet

Deployed and exercised against Base mainnet (chain_id 8453, native ETH mode):

| Contract | Address |
|---|---|
| DSA | [`0x0fF07b282C9c51720885F0a9B3bA8a6458b41385`](https://basescan.org/address/0x0fF07b282C9c51720885F0a9B3bA8a6458b41385) |
| RevocationRegistry | [`0x6e5c690ee2e76Cf920BE22e2583A9B7d0390d79F`](https://basescan.org/address/0x6e5c690ee2e76Cf920BE22e2583A9B7d0390d79F) |
| OperatorRegistry | [`0x278Fa3ff77d02b6caa981340Ca6f0CC5543bC57c`](https://basescan.org/address/0x278Fa3ff77d02b6caa981340Ca6f0CC5543bC57c) |
| BatchSettler #1 *(retired)* | [`0x247148601909395834e836CEa01B101D187E28a1`](https://basescan.org/address/0x247148601909395834e836CEa01B101D187E28a1) |
| BatchSettler #2 (`releaseBond`) | [`0xa3397ce4fDE01810F8540A25363A88D5e57f4166`](https://basescan.org/address/0xa3397ce4fDE01810F8540A25363A88D5e57f4166) |

Instance #1 is retired — it predates the challenge-path refund fix and `releaseBond`;
do not settle against it. Instance #2 is the live one.

Mainnet rehearsal (epoch 0, BatchSettler #2): commit escrows an operator-chosen bond
(0.0005 ETH), settle funds a 5-intent batch netting to 1000 wei, then a 6-hour
challenge window runs before claim and `releaseBond` return the funds — commit tx
[`0x2ed64056…66a8`](https://basescan.org/tx/0x2ed64056e57dfee9c818c5e3f7015994f837cdbb9b74b38733b7b91de7c166a8),
settle tx [`0x621045df…1434`](https://basescan.org/tx/0x621045dfd358d5ccfcb9d1138b43d389beb26a6e86d4c133aaac88cd961b1434).
**The full life cycle closed on 2026-09-02**: the window passed with zero challenges,
claim tx [`0x189e72c8…20f3e0`](https://basescan.org/tx/0x189e72c8a7a8ce4ef005cb3a03c2e1ddd1feb78e7f12ce01158aab76bd20f3e0)
paid the 1,000-wei net 74 s after unlock, and `releaseBond` tx
[`0x33b51686…e0afe1`](https://basescan.org/tx/0x33b51686b3adcb21aa9323502badd0a0105c3fa3c452d249846ad767f3e0afe1)
returned the bond in full — the settler contract is drained.
The bond is escrowed, not burned: honest settlement returns it in full via `releaseBond`
(`BatchSettler.sol:405`). The contracts are open source and permissionless — anyone can
deploy their own `BatchSettler` and self-register as operator.

## Measured performance

- **488,738 payments/s** in-process aggregator ingest (signature verify → nonce →
  budget, all cores) — PoC report with reproduction command
- Hot path is allocation-free, `std`-only HTTP/1.1 gateway and facilitator
- CI runs a performance gate on every push (zero-allocation benchmarks, automatic
  re-test on suspected regression)

## x402 compatibility

Mist ships an x402 adapter: the `mist-v1` scheme, an EIP-3009 bridge that routes
standard x402 clients through the full DSA gate (no protocol layer bypassed), a
facilitator reference implementation, and both v1 and v2 wire formats. An entry in the
upstream [x402 third-party extensions list](https://github.com/x402-foundation/x402/pull/3321) is in review.

## Quick start

```sh
git clone https://github.com/changshenhan/mist.git && cd mist
bash scripts/verify.sh                     # full gate: fmt/clippy/test/bench/contracts/noir
cd contracts/rust-smoke && cargo run --release --bin m1_demo   # 100k intents -> net settlement demo (needs foundry)
```

Developer docs: [`docs/developers/quickstart.md`](docs/developers/quickstart.md)
(5-minute walkthrough) and [`docs/developers/integration.md`](docs/developers/integration.md)
(agent / framework / vendor).

Measured-engineering pieces live in [`docs/articles/`](docs/articles/README.md): the
x402 gas ledger, a Barretenberg msgpack reverse-engineering, the pricing one-pager, the
mainnet settlement life cycle, and the position paper
[why machine commerce does not need a new chain](docs/why-no-new-chain.md).

## Repository layout

```
core/          DSA primitives + budget ledger (mist-core)
aggregator/    settlement kernel: ingest / commitment lattice / WAL / netting (mist-aggregator)
gateway/       multi-tenant network ingest gateway, std-only HTTP/1.1 (mist-gateway)
sdk/           agent integration: authorize / pay / attest + x402 fetch interception (mist-sdk)
facilitator/   x402 merchant reference implementation, fail-closed (mist-facilitator)
mcp-server/    MCP stdio server: 6 tools, keyless, real ZK proofs (mist-mcp)
monitor/       Prometheus /metrics + /healthz (mist-monitor)
bench/         benchmark base + allocation gate + CI gate (mist-bench)
contracts/     Solidity: DSA / RevocationRegistry / BatchSettler + rust-smoke
circuits/      Noir ZK circuits (intent_hash binding + revocation non-membership)
demos/         three-framework demos (LangChain / AutoGen / Eliza)
poc-delivery/  delivery proof via TLSNotary MPC-TLS (separate workspace)
```

## Honest status

* Contracts are live and exercised on mainnet; the epoch-0 rehearsal ran its full
  life cycle end to end (commit → settle → 6 h window → claim → `releaseBond`, bond
  returned, contract drained).
* Internally audited (slither + a 130-test invariant/fuzz suite); an external audit is
  planned — no audit tag has been issued yet.
* ZK path: Noir circuits with real Barretenberg proving in CI; the production prover
  integration is separate (see TECH_SPEC).
* Single-operator deployment so far; multi-operator governance is designed (§6.17) and
  partially landed (P2 series), not yet exercised with multiple live operators.

## License

Elastic License 2.0 — free for personal, internal, and research use; commercial
hosting/white-label settlement requires a license. See `THIRD_PARTY.md` for dependency
licenses.
