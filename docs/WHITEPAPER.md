# MERIDIAN
## Machine-Commerce Settlement Infrastructure

> **Status**: Phase 0 complete (2026-08-16). All three proofs of concept green.
> This document quotes measured numbers, not targets. Reference implementation follows (Phase 1).

---

## 1. The problem

Agents are about to transact: negotiate, buy access, pay for compute, settle delivery.
Today's agent frameworks (MCP, A2A, and the various SDKs) solve **messaging** — how an agent
finds a tool, calls it, and gets a result. None of them solve **money**: who authorized the
spend, within what budget, and how does the other side prove it got paid — or, when the other
side claims it didn't, how the payer proves it delivered.

Four gaps:

1. **Authorization** — an agent acting on behalf of a human needs a way to spend that scales
   with automation, without asking the human per transaction, and without handing the agent
   the owner's keys.
2. **Budget** — spending must be bounded: per-spend caps, per-window rate limits, lifetime
   totals, and instant revocation.
3. **Settlement** — thousands of micro-transactions per second need to be aggregated into
   net positions and settled cheaply on a chain that already has liquidity.
4. **Delivery proof** — in a dispute ("I never received it"), the payer needs cryptographic
   evidence that the delivery actually happened, without revealing secrets.

## 2. The stance: no new chain

Meridian is **not** a chain. It is a settlement and trust layer that sits **on top of**
existing L2s (Base first), in the same way Nethermind-style infrastructure sits on Ethereum:

- No new consensus. No new token. No validator set. No license or regulatory surface.
- Settlement happens on a chain that already has USDC liquidity and cheap gas.
- What we add is a reference implementation of the *protocol*: a Rust engine, a ZK circuit,
  a settlement aggregator, and a delivery-proof primitive.

For a detailed argument, see the position paper *Why Machine Commerce Does Not Need a New
Chain*.

## 3. Architecture

```
L1  Identity        .agent domains, key management            (out of scope, later)
L2  Authorization   DSA + ZK credential + budget ledger       ← THIS PAPER
L3  Settlement      Aggregator → commitment → netting → settle
L4  Trust           Delivery proof (TLSNotary), reputations
L5  Orchestration   Agent frameworks (MCP), SDKs
```

### 3.1 DSA — Delegated Spend Authority (L2)

The core primitive. The **owner** (a human or enterprise, ECDSA — the EVM ecosystem) issues
a `Delegation`: "this agent may spend, per spend at most X, per window at most Y, in total at
most Z, until time T." The **agent** holds a transport Ed25519 key (NodeId) for the
S-02 fast path, plus a **BabyJubJub attestation key** whose signature on the spend intent is
checked inside the ZK circuit (S-09).

Three keys, deliberately different curves:

| Role | Key | Verified where |
|---|---|---|
| Owner | ECDSA/secp256k1 | Off-circuit: on-chain `registerDelegation` + S-02 (EVM wallet ecosystem) |
| Agent (transport) | Ed25519 NodeId | Off-circuit fast path (S-02) |
| Agent (ZK authorization) | BabyJubJub + Poseidon EdDSA | **In-circuit** (`eddsa_verify` over `encode_field(intent_hash)`) |

The keys are **bound** at registration: the owner's Ed25519(NodeId) key signs a binding to the
agent's BabyJubJub public key, and the binding is checked outside the circuit
(`core/src/attestation.rs`). The circuit anchors the already-bound `delegation_hash`.

### 3.2 Budget ledger (L2)

A deterministic state machine. Each `(agent, delegation)` shard tracks spend against the
delegation's limits, in this order:

1. Validity window — `not_before ≤ now < expires_at`
2. Window roll — the budget window advances deterministically
3. Per-spend cap — `amount ≤ max_per_spend`
4. Window rate cap — sum within window ≤ window limit
5. Lifetime cap — cumulative ≤ total cap
6. Apply only if all passed

The order is fixed by spec; it cannot be renegotiated per transaction.

### 3.3 ZK credential (L2)

Authorization is a **zero-knowledge proof** that the intent satisfies the delegation and the
budget rules, without revealing the delegation to every counterparty. The `spend_authorization`
circuit (Noir/Barretenberg) enforces:

- the intent (`intent_hash`, field-bound) is signed by the agent's BabyJubJub attestation key,
- the delegation is valid (not expired, not revoked — via a sparse-Merkle non-membership root),
- amount and category are within bounds,
- the budget ledger state transition is correct (checked at the ledger, §3.2).

Owner ECDSA is verified **off-circuit** (S-09 decision): on-chain `registerDelegation` + the
S-02 fast path; the circuit anchors the already-bound `delegation_hash`.

Measured constraint budget (S-09): **66,736** gates (`bb gates` circuit_size; 9,044 ACIR
opcodes), far under the 2^18 ceiling — proof generation and verification stay interactive
for a per-transaction workflow (see §5.5 of the spec for prove/verify latency).

### 3.4 Aggregator (L3)

An **ingest → commit → net** pipeline:

- **Ingest**: verify agent Ed25519 signature (stateless → parallel), deduplicate by nonce,
  check budget atomically on a sharded ledger.
- **Commit**: seal the epoch (10 s or 100,000 intents), post the Merkle root on-chain
  (BatchSettler), backed by an operator bond.
- **Net**: deterministically reorder by intent hash (public rule → no front-running on
  position/amount), compute net positions per recipient, settle via `BatchSettler.settle`.
- **Dispute**: a `CHALLENGE_WINDOW` (default 6 h) allows anyone to challenge a
  `commit ≠ settle` mismatch; bonds are slashed to challengers. Fraud proofs are
  missing-recipient / under-payment against the commitment lattice (sound + bounded).
- **Settlement asset**: v1 settles **native ETH** — the operator posts a bond
  (`commit` msg.value) and funds each epoch's net positions (`settle` msg.value ≥ Σnet);
  recipients `claim()` after the window, and a successful challenge voids the epoch and
  refunds the settlement funds. USDC/ERC-20 is a Phase 2 seam: `NetInstruction
  { recipient, amount }` is asset-agnostic, so the swap does not touch the netting structure.

Netting collapses ~100k transactions into a few hundred net instructions — the on-chain gas
is trivial.

### 3.5 Delivery proof (L4, PoC ③)

"Prove you delivered, without revealing your secrets." A two-party MPC-TLS witness
(TLSNotary): when the payer delivers to the recipient's TLS endpoint, a **verifier**
(arbitrator) co-simulates the TLS session with the payer and obtains a selectively-disclosed
transcript. Measured (PoC ③, `docs/poc/poc-03-delivery-proof.md`):

- the request line, order ID, and payload are visible to the verifier,
- the delivery token is **hidden** (null bytes in the disclosed transcript),
- the server's `200 OK` + ack are visible — "the endpoint really answered".

The production form (S-18+) is 3-party notarized attestation, making the proof verifiable
offline.

## 4. Measured performance

All numbers below are **measured**, from fixed-seed, fixed-input benchmarks. Full methodology
in `docs/poc/poc-02-aggregator-throughput.md`. Machine: 32-core Windows x86_64, release build.

### 4.1 Aggregator ingest throughput (PoC ②)

The full fast path — intent↔delegation binding, agent Ed25519 verification, concurrent nonce
dedup, sharded budget accounting:

| Workers | Throughput (intents/s) |
|---|---|
| 1 | ~47,600 |
| 2 | ~90,800 |
| 4 | ~177,000 |
| 8 | ~307,000 |
| 16 | ~387,000 |
| **32** | **~488,700** |

The design target was **≥ 100,000 intents/s**. Measured: **488,738/s** — a 4.9× margin.
Scaling is near-linear with cores because the bottleneck (Ed25519 verification) is stateless
and parallelizable. This is the performance moat: at this ingest rate, a single operator can
serve the entire near-term machine-commerce volume.

### 4.2 ZK (PoC ①, S-05)

- `spend_authorization` main circuit: 6,880 ACIR + 1,289 Brillig constraints.
- Prove → verify → public-input readback pipeline green in CI.

### 4.3 Delivery proof (PoC ③, S-08b)

All four witness assertions pass: sent side shows the delivery request, the token is hidden,
the received side shows `200 OK` + ack, and the server identity matches the delivery domain.

## 5. Security model

| Threat | Countermeasure |
|---|---|
| Intent replay | Monotonic spend nonce + ledger-registered intent hash |
| Over-limit spending | Atomic budget check per shard (§3.2) |
| Spending after revocation | Revocation root in circuit + aggregator freshness penalty |
| Stolen agent key | Key rotation + owner DSA revocation |
| Malicious operator | Bond + fraud proof + challenge window (§3.4) |
| Front-running / sandwich | Commitment lattice + hash-deterministic reordering |
| ECDSA malleability | Low-`s` enforcement + canonical serialization |
| Circuit/ledger drift | Verifier returns public inputs; registration uses only those |

## 6. Roadmap

| Phase | Status | Content |
|---|---|---|
| Phase 0 — standards | **Done** (2026-08-16) | Three PoCs green; spec v1.0 frozen; repo ready for open-source (launch deferred, per S-08e) |
| S-09 (ZK circuit) | **Done** (2026-08-16) | Full `spend_authorization`: intent_hash field binding + sparse-Merkle revocation non-membership; owner ECDSA verified off-circuit (on-chain + S-02); EVM verifier (`UltraVerifier.sol`, keccak-flavor) generated |
| S-10 (aggregator kernel) | **Done** (2026-08-16) | Production kernel in `meridian-aggregator`: ingest fast-path (verify → SpendVerifier → budget → window → WAL), commitment lattice, crash recovery; B5 576,406/s @64t (≥100k PASS), B6 p99 0.03ms, B7 46.5ms/33MiB, B8 0-alloc, B10/B11 PASS |
| Phase 1 — reference impl | Next | In-process proving/verification wrapper (true B4), milestone M1 end-to-end |
| Phase 2 — operator | Later | Multi-operator, bond economy, Base mainnet, recursive aggregation |

Phase 0 exit criteria are all met. Phase 1 is in progress against `MASTER_PLAN.md` (linear,
S-09 → S-27; order is non-negotiable).

## 7. Project status

- Code: public, Apache-2.0 (this repository).
- The three PoC reports live in `docs/poc/`.
- Spec v1.0: `TECH_SPEC.md` (binding; change spec first, then code).
- Open invitation: agent frameworks that want a settlement primitive under their tool layer.

---

*Meridian · Machine-commerce settlement infrastructure · 2026-08-16*
