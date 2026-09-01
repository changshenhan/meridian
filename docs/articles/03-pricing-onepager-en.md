# Mist settlement — pricing one-pager

*Status: launch pricing, decided 2026-09-01. What is *not* a decision is the cost
floor: every gas number below is measured (mainnet receipts, a Base fork running real
USDC bytecode, and local sweeps) and documented with sources in article ②
(`02-x402-gas-ledger-en.md`). Prices above the floor are a founder decision, first
calibrated after one Enterprise customer's real (N, R) profile.*

---

## 1. The one-line pitch

You keep x402 exactly as it is on the client side. We replace **one settlement
transaction per payment** with **one settlement transaction per batch**, and we sell you
the difference.

Measured reality of the two worlds (Base mainnet, 2026-09-01):

| | x402 direct (exact / EIP-3009) | Mist batched |
|---|---|---|
| Chain tx per payment | 1 (`transferWithAuthorization`) | 0 |
| Gas per payment | **61,105 – 90,053** (measured, real USDC) | **(246,000 + 78,958·R)/N** (measured components) |
| 1,000 payments, 100 recipients | 61–90 M gas | 8.1 M gas (7.5× less) |
| 1,000 payments, 1 recipient | 61–90 M gas | 0.33 M gas (188× less) |
| 1,000 payments, all recipients distinct | 61–90 M gas | 79 M gas (30% **more**) |

The last row is deliberate: batched settlement only pays when recipients repeat. Our
recommendation to a prospective customer is routing by recipient cardinality — and the
pricing below is built so that the discount is **structural, not promotional**: the cost
floor itself falls with batch size.

## 2. Cost floor (measured — not negotiable, not invented)

Per epoch of N payments touching R distinct recipients:

```
gas cost floor = 246,000          commit (143,277, constant) + settle fixed (≈103,000)
               + 45,650 × R       settle rows (measured marginal 45,600–45,700)
               + 33,308 × R       claims, existing recipients (60,835 if fresh)
```

At the measured Base base fee of 0.005 gwei (block 50,729,172): the floor for
N=1,000/R=100 is ≈ 0.000041 ETH — USD: derive via §7 at publication time.

**What the floor deliberately excludes** (these are cost drivers, not margins, and none
is yet measured — each is **pending measurement**):

* ZK proving compute per payment (off-chain; seconds of CPU, no gas).
* Bond capital: the operator bond is escrowed per epoch at an operator-chosen
  amount (no protocol minimum — our mainnet rehearsal committed 0.0005 ETH), held
  through the 6-hour challenge window, then returned in full via `releaseBond` on
  honest settlement — at risk only if a fraud challenge succeeds. The unmeasured
  driver is the opportunity cost of the escrow, not the principal.
* Capital fronted at `settle{value: Σnet}` for up to the 6-hour challenge window
  (`CHALLENGE_WINDOW = 6 hours`, `BatchSettler.sol:167`) — carried by the operator
  (Mist) and priced inside the subscription, not passed through.
* Fraud-response ops: a successful challenge costs ≈1.76–1.97 M gas (≈0.0000098 ETH) and
  nets the challenger the operator's committed bond — i.e. insurance has a real premium line.

## 3. Launch pricing (three tiers)

| | **Builder** | **Scale** | **Enterprise** |
|---|---|---|---|
| Subscription | **$0** | **$2,500 / month** | **$20,000 / month +** |
| Included payments | 10,000 / month | 2,000,000 / month | custom (10M+ / month) |
| Overage per payment | **$0.002** | **$0.0005** | declining with volume |
| Recipients (R) | any | any | multi-merchant pooling |
| Bond & settlement fronting | ours | ours | ours |
| Fraud response, monitoring, support | community | standard | SLA + dedicated |

The three pricing principles behind these numbers:

1. **Free where there is no pain.** Under 10,000 payments/month, direct x402 settlement
   is genuinely fine and gas is a rounding error — so that segment is free. Our own
   marginal cost for a typical Builder profile (N = 10,000/month, R = 1,000) is
   ≈ 8,100 gas/payment ≈ **$1.30/month** of gas (§7 formula, illustrative ETH/USD =
   $3,000) plus ≈ $0.05 of ZK proving CPU at the measured 0.46 s/proof and commodity
   vCPU rates. Frictionless adoption is the top of the funnel; nobody should run their
   own BatchSettler for 10k payments.
2. **Price certainty, not gas.** Direct settlement costs scale linearly with Base's base
   fee, which has swung by more than an order of magnitude historically. At the
   measured 0.005 gwei, 2M direct payments cost ≈ $1,833/month (illustrative ETH/USD =
   $3,000, §7 formula); at 0.05 gwei the same traffic costs ≈ $18,330 — **and can get
   worse, because 1,000 payments are 15–23% of a Base block, so volume hits block-space
   economics directly**. Mist's overage is a flat $0.0005/payment: ≈5.5% of the
   high-fee direct cost, and the customer's bill stops depending on network congestion.
3. **Subscription carries the ops, not per-payment rent.** The per-epoch bond
   escrow (operator-chosen, returned in full on honest settlement), the
   settle-time fronting for the 6 h window, fraud response, RPC and proving
   infrastructure are all ours, priced inside the subscription. There is no separate
   "bond pass-through" line a customer has to reason about.

Volume discounting is structural, not promotional: the measured floor itself falls as
N grows ((246,000 + 78,958·R)/N), so the overage price keeps its margin at every tier
without the discount being a marketing concession.

**Why a customer cannot reproduce this by self-hosting:** identical contracts mean an
identical floor — but the floor is proportional to R, and an isolated operator's R/N
is its own traffic's. Cross-merchant pooling (Enterprise row) is the one lever that
lowers the floor itself, and it only exists on the managed service (§4).

## 4. Self-host comparison (the honest slide)

The contracts are open source and permissionless: anyone can deploy their own
`BatchSettler` and be its operator (that is how our own deployment works —
`registerOperator` is self-registration against `BatchSettler.operator()`, verified on
mainnet). So "why not self-host?" has to be answered with operations, not protocol rent:

| Self-host | Mist managed |
|---|---|
| Same measured gas floor (identical contracts) | same floor + markup |
| Own bond escrow (refunded on honest settlement) and fraud response | ours |
| Own 6 h window monitoring, key ops, RPC ops | ours |
| Aggregation limited to own traffic (R/N ratio = own) | **multi-merchant aggregation improves R/N** — the single biggest lever on the floor |
| Proving compute on own hardware | ours |

The third row is the real product: the floor is proportional to R (distinct recipients),
so **pooling two merchants with overlapping recipients cuts both floors**. That is the
only argument for a managed service that self-hosting cannot replicate, and the pitch
should lead with it.

## 5. Break-even table vs. direct x402 settlement

Floor per payment (gas) as a function of batch size N and distinct recipients R,
versus direct settle at 61,105 (warm) — from article ② §4:

| N \ R | 1 | 10 | 100 | N (all distinct) |
|---|---|---|---|---|
| 5 | 65 k | 207 k | 1.63 M | 128 k |
| 50 | 6.5 k | 20.7 k | 163 k | 83.9 k |
| 500 | 650 | 2.07 k | 16.3 k | 79.5 k |
| 5,000 | 65 | 207 | 2.07 k | 79.0 k |

Reading: at R = N/10 recipients the floor crosses the 61,105-gas direct-settle line at
**N ≈ 5 payments**; with every recipient identical, at N ≈ 5.3. Whenever recipients
repeat at all, one batch is enough. Price may be set well above the floor; the floor is
not the constraint. The
constraint is that a *managed* price must also carry §2's excluded lines (proving
compute, capital, fraud ops) — in the launch tiers these are priced inside the
subscription.

## 6. What this page does not claim

* No market-tested rate card: the §3 numbers are launch pricing, to be recalibrated
  after one real Enterprise (N, R) profile.
* No SLA, throughput commitment, or latency number: none has been measured under load.
* No rate card: no (N, R) profile from a real customer exists yet.
* No claim that the floor is the whole cost: §2's excluded lines are unpriced.
* The L2 authorization plane (register 40,807 / bind 47,648 / revoke 52,216 gas, once
  per delegation) is measured locally only — mainnet confirmation **pending**.

## 7. USD conversion protocol (method and fee regime fixed; rate snapshotted at publication)

When USD figures are filled in, they must be derived — not quoted ad hoc:

```
USD(x gas) = x × baseFeeGwei × 1e-9 × (ETH/USD at publication, source snapshot)
```

* **Fee regime — decided: (A) L2 base fee only.** All gas figures in article ② were
  priced against the measured 0.005 gwei, which is reproducible from
  `eth_getBlockByNumber`; (B) would add the L1 data-availability fee, which is not
  separately measured here. Regime A is also the fair one for the direct-vs-batched
  comparison: both sides omit the same L1 component, so the comparison stands. Published
  pieces must state that regime A excludes L1 DA (actual all-in cost is slightly higher
  for both paths).
* **Exchange rate:** snapshot from one named source (Chainlink ETH/USD or CoinGecko) at
  publication time, date stamped in the text. No live widgets, no unnamed sources.
* Every USD number published must be traceable to a gas number in article ② by this
  formula. If a USD figure cannot be derived from a measured gas figure, it does not
  belong in the piece.

### Sources

Every number on this page: `02-x402-gas-ledger-en.md` (this series, article ②), with
measurement commands, on-chain transaction hashes, and preserved logs. Repo citations:
`contracts/src/BatchSettler.sol:167,232,255,291,405` (window / commit / settle / claim / releaseBond); x402 upstream
`eip3009.ts:321-336` and `batch-settlement/README.md:3,5,47`.
