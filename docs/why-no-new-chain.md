# Why Machine Commerce Does Not Need a New Chain

**A position paper from the Meridian project** · 2026-08-16

> Companion to the [whitepaper](WHITEPAPER.md). Short version: agents don't need a new
> settlement network; they need a protocol for *authorization, budget, and delivery proof*
> running on the networks that already have liquidity. We built the reference implementation.

---

## 1. The reflex: "agents need their own chain"

Every new machine-commerce project reaches for the same shape: a new L1 (or a token-gated
rollup) where agents live natively, gas is metered in a new asset, and the agent economy
develops on a virgin ledger. The pitch writes itself: "today's chains weren't built for
agents; agent traffic is high-frequency and micro; we need a chain that speaks agent."

The reflex is understandable and almost always wrong. It confuses the *symptom* (agents
need fast, cheap settlement) with a *cure* (a new settlement layer) that imposes costs the
actual problem doesn't pay for.

## 2. What agents actually need

When an agent authorizes a spend, spends, and delivers, it needs four things:

1. **Authorization with granular delegation** — owner signs once; agent spends many times,
   bounded by caps and budgets. This is a *semantic* problem (delegation model, key binding,
   expiry, revocation), not a consensus problem.
2. **Budget as a deterministic state machine** — per-spend caps, window rate limits,
   lifetime totals, atomic accounting. Pure deterministic logic; nothing here needs a
   validator set.
3. **Settlement at micro-transaction scale** — thousands of intents per second, netted
   into a handful of positions, settled in USDC on a chain with liquidity.
4. **Delivery proof** — cryptographic evidence of delivery (TLSNotary witness), settled
   between the parties. Also a semantic problem.

None of these four is *fundamentally* a new-chain problem. The first, second, and fourth are
protocol logic — they belong in a reference implementation, not in a block. The third is the
only consensus-adjacent one, and it is already solved by existing L2s.

## 3. What a new chain costs

Measured against what a small, zero-capital technical team can actually afford:

| Cost | New chain | Existing L2 |
|---|---|---|
| Consensus / validator set | Build and secure it (or rent security) | None — inherited |
| Token / economic design | Mint, distribute, bootstrap liquidity | None — USDC is already liquid |
| Regulatory surface | Token, validators, settlement network | None — you're an app, not a network |
| Cold start | Seeded by zero, forever | Base already has the liquidity |
| Gas for micro-transactions | Yours to subsidize with the token | ~fractions of a cent on L2 |

The killer is not the engineering — it's the **economic cold start**. A new settlement asset
has no liquidity, so agents holding it can't actually buy anything with it, so no one accepts
it, so it stays worthless. You can't bootstrap a money network by having fewer users than the
networks it must replace.

## 4. The measured counter-argument

The "we need a chain for throughput" argument dies on our benchmark. The aggregator fast path
— agent signature verification, concurrent nonce dedup, sharded budget accounting, all atomic
— runs at **488,738 intents/s** on a single 32-core machine (PoC ②, target 100k, 4.9× margin).
Scaling is near-linear because the bottleneck is stateless verification.

That number is *before* the ZK proof (S-09) and on prototype sharding. Even at the Phase 0
prototype, one operator handles the entire near-term agent settlement volume on one box, and
settles net positions on Base. There is no volume in the foreseeable machine-commerce market
that justifies paying for a new network's security when this is the cost of the alternative.

## 5. What "on-chain" and "off-chain" actually mean here

- **Off-chain (deterministic, auditable)**: ingest, budget accounting, commitment lattice,
  deterministic reordering, netting. All reproducible from the same inputs — the aggregator's
  every step can be replayed and verified, and the commitment root is posted on-chain.
- **On-chain (minimal, final)**: the commitment root, the net instructions, the settle call,
  and the challenge window. ~100k intents collapse into a few hundred net positions.

The chain does what chains are good at — *finality and dispute resolution* — and nothing else.
The aggregator does what machines are good at — *deterministic state at high speed*.

## 6. When a new chain (layer) *is* right

Not never. The Meridian plan reserves a dedicated L3 (Arbitrum Orbit) for a later phase, but
gated on three conditions, all required:

1. Aggregate agent volume exceeds what a single (or a few) aggregator instances can serve;
2. The team has capital (the L3 is funded by Phase 2 operating revenue, not a token);
3. The base-layer cost of frequent `settle` calls becomes material.

Even then, it is an **execution layer for our own netting**, not a new consensus network — and
it inherits its security and liquidity from the L2 below it. The order is deliberate:
"rails first, execution layer later." The chain is a scaling option, not the premise.

## 7. Conclusion

Machine commerce doesn't need a new chain. It needs:

- a **protocol** — DSA authorization, deterministic budget, delivery proof;
- a **reference implementation** — measured, open, fast;
- a **settlement path** — on the L2 that already has USDC and liquidity.

The chain-shaped solution is a solution in search of a problem that the economics already
decline. Meridian builds the protocol and the implementation; Base settles it; agents get to
transact. That's the entire thesis — and PoC ②'s 488k intents/s is the number that makes it
credible.

---

*Meridian · 2026-08-16 · Apache-2.0*
