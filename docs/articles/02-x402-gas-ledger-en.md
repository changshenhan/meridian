# The x402 Gas Ledger: what a payment actually costs on-chain, and where batching pays

*Article ② of the Mist engineering series. All numbers below are either read off
Base mainnet through public RPC/explorer APIs or measured locally with Foundry on a fork
of Base mainnet. No price is invented: where a USD figure would require an exchange rate,
the number is left as **USD: to fill in**. Measurement logs ship next to this file
(`02-gas-measurement-log-local.txt`, `02-gas-measurement-log-fork-base-usdc.txt`).*

---

## 0. Method and provenance

Three independent sources, each with its own command:

| Source | Tool | Reproduce |
|---|---|---|
| Local unit gas (Mist contracts at commit `de782b6`) | `forge test --match-contract GasLedgerTmp -vvv` | `gasleft()` deltas around each external call — measures execution gas only, excluding the 21,000-gas tx base and calldata intrinsic. The harness was a temporary file deleted after the run; the full log is preserved beside this article. |
| Real Base USDC bytecode | `FORK_RPC=https://mainnet.base.org forge test --match-test test_fork_usdc_eip3009 -vvv` | `anvil` fork pinned at block **50,702,500**; the payer is funded by a cheatcode write, but the code that executes and the gas it burns are the deployed Base USDC proxy (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`). No transaction left the machine. |
| Mainnet receipts | `cast receipt <hash> --rpc-url https://mainnet.base.org --json` | The six deployment transactions of wallet `0xBE25c7F87128a66Ec270abeE3Cfdf6a64E3e08a6` (creation tx hashes read off Basescan; receipts read off public RPC). |

A word on why the local numbers can be trusted for a mainnet article: we deployed the same
contracts to Base mainnet on 2026-08-31, and the deployment *cost* recorded by
`forge --gas-report` matches the on-chain `gasUsed` of the creation transactions almost
exactly — two of four contracts bit-identical (§2). The measurement harness is not a
model of the contracts; it is the contracts.

Gas prices quoted below use two measured Base facts: block gas limit **400,000,000** and
`baseFeePerGas` **5,000,000 wei = 0.005 gwei** (read from `eth_getBlockByNumber("latest")`
at block 50,729,172, 2026-09-01). The deployment transactions of §2 actually paid
5,250,001 wei effective.

---

## 1. The lifecycle of one x402 payment

Upstream x402 (exact scheme, EVM) settles **one payment = one on-chain transaction**.
The facilitator's settle entry point is a single `transferWithAuthorization` call
(EIP-3009): `settleEIP3009` in
`x402/typescript/packages/mechanisms/evm/src/exact/facilitator/eip3009.ts:321-336`
("Settles an EIP-3009 payment by executing transferWithAuthorization").

The full loop for one payment:

1. Client requests a priced resource; server answers 402 with the payment requirements.
2. Client signs an EIP-3009 authorization offline (no gas).
3. Client retries with the payment header; facilitator verifies signature, expiry, balance.
4. **Facilitator submits `transferWithAuthorization` — the only gas-bearing step, and it
   repeats for every payment.**
5. Server serves the resource.

Mist keeps steps 1–3 and replaces step 4-5's per-payment settlement with a batched
optimistic settlement (`contracts/src/BatchSettler.sol`):

1. Once per delegation: `DSA.registerDelegation` then `bindOperator` (one tx each).
2. Per payment: client produces a ZK proof off-chain, aggregator verifies and ledgers it
   — **no gas**.
3. Per epoch (batch): operator seals the batch off-chain and posts
   `commit` — the batch reaches the chain only as a 32-byte root (`commit` takes
   `epochId, commitmentRoot, revocationRoot, acceptanceRoot, sealedAt`, all fixed-size
   scalars, `BatchSettler.sol:232-238`), so its cost cannot scale with batch size.
4. `settle` posts the **net** amount per distinct recipient (`settle`, `BatchSettler.sol:255-288`;
   the per-row loop is `ep.net.push(net[i])` at line 280).
5. Six-hour challenge window (`CHALLENGE_WINDOW = 6 hours`, `BatchSettler.sol:167`;
   `claim` refuses until `block.timestamp > settledAt + CHALLENGE_WINDOW`, line 295).
6. Each recipient `claim`s its row (line 304).

The whole gas question is: **what does step 4 of the direct path cost, and how does
Mist's steps 3+4+6 amortize over a batch?**

---

## 2. Fixed cost: the deployment ledger (mainnet, measured)

Six transactions, all mined 2026-08-31 16:37:39–16:37:49 UTC, blocks 50,702,456–50,702,461,
effective gas price 5,250,001 wei. Every row below is read from an on-chain receipt.

| # | Nonce | Block | Transaction | gasUsed | wei paid |
|---|---|---|---|---|---|
| 1 | 0 | 50,702,456 | deploy DSA (`0x0fF07b282C9c51720885F0a9B3bA8a6458b41385`) | 325,338 | 1,708,024,825,338 |
| 2 | 1 | 50,702,456 | deploy RevocationRegistry (`0x6e5c690eE2E76CF920BE22E2583a9B7D0390D79F`) | 200,922 | 1,054,840,700,922 |
| 3 | 2 | 50,702,457 | deploy OperatorRegistry (`0x278FA3Ff77D02B6CaA981340CA6F0CC5543bC57C`) | 519,108 | 2,725,317,519,108 |
| 4 | 3 | 50,702,458 | `appendSchedule(bond=1 ETH, challengeBond=0.1 ETH)` | 112,409 | 590,147,362,409 |
| 5 | 4 | 50,702,460 | deploy BatchSettler (`0x247148601909395834e836cea01b101d187e28a1`) | 1,834,692 | 9,632,134,834,692 |
| 6 | 5 | 50,702,461 | `registerOperator(BatchSettler)` | 185,823 | 975,570,935,823 |
| | | | **Total** | **3,178,292** | **16,686,036,178,292 ≈ 0.00001669 ETH** |

At the 0.005 gwei base fee of 2026-09-01 that is **USD: to fill in** (≈0.0000167 ETH).

How the contract identities were established (not assumed): addresses derived as
`keccak256(rlp([sender, nonce]))[12:]` for nonces 0–5 — nonces 3 and 5 have no bytecode,
exactly the two non-deployment calls — then confirmed by readbacks:
`RevocationRegistry.dsa()` returns the DSA address; `OperatorRegistry.registrar()` and
`BatchSettler.operator()` return the deploy wallet; `BatchSettler.challengeBond()` =
0.1 ETH, `asset()` = `0x0` (native mode), `CHALLENGE_WINDOW()` = 21,600 s.

**Cross-validation, local vs mainnet.** `forge --gas-report` deployment costs at the same
commit vs on-chain `gasUsed`:

| Contract | forge (local) | mainnet | Δ |
|---|---|---|---|
| DSA | 325,350 | 325,338 | 12 (0.004%) |
| RevocationRegistry | 200,922 | 200,922 | **0** |
| OperatorRegistry | 519,108 | 519,108 | **0** |
| BatchSettler | 1,834,932 | 1,834,692 | 240 (0.013%) |

The two registry functions measured locally also reproduce exactly:
`appendSchedule` max 112,409 and `registerOperator` max 185,823 in the gas report are the
same numbers the chain charged (nonces 3 and 5). The local lab and the chain agree to
five significant digits, which is the licence for using local numbers below.

---

## 3. The per-item gas ledger

Every "execution" figure is `gasleft()` delta; add §3.1's intrinsic to get a full tx.

### 3.1 The direct-settle baseline — one EIP-3009 payment on real Base USDC

| Item | gas | Source |
|---|---|---|
| `transferWithAuthorization`, first payment to a fresh payee | **66,313** (single fork run) | fork @ 50,702,500 |
| `transferWithAuthorization`, payee balance slot warm | **37,365** (identical both runs) | fork @ 50,702,500 |
| Tx intrinsic (21,000 base + 2,740 calldata for the 292-byte call) | **23,740** | fork @ 50,702,500 |
| Plain `transfer` from a whale (no auth layer, warm payee) | 8,638 | fork @ 50,702,500 |

**Full transaction cost of one x402 settlement on Base: ≈ 90,053 gas (fresh
payee) or 61,105 gas (warm payee).** At 0.005 gwei: 0.00000030–0.00000046 ETH, **USD: to fill
in** — per payment.

Two structural properties matter more than the constants:

* **It is linear and unamortizable.** One tx per payment, forever. 1,000 payments =
  61–90 M gas, i.e. 15–23% of an entire 400M-gas Base block.
* **The floor is not the transfer.** A bare USDC `transfer` costs 8,638 gas; the
  authorization layer (ecrecover + nonce slot + the 292-byte calldata) is what turns an
  8.6k transfer into a 37–66k settlement. x402 pays that premium on every single payment.

### 3.2 The Mist ledger — one-time L2 authorization plane

| Item | execution gas | Note |
|---|---|---|
| `DSA.registerDelegation` | 40,807 | once per delegation |
| `DSA.bindOperator` | 47,648 | once per delegation (`contracts/src/DSA.sol`) |
| `RevocationRegistry.revoke` | 52,216 | per revocation |

These are local forge measurements at `de782b6`. Unlike the deployment costs above, the
mainnet instances have registered no delegations yet (`operatorCount()=1`,
`scheduleCount()=1`), so **the mainnet runtime confirmation of these three is still
pending** (measured locally; to be re-read on mainnet once real delegations exist).

### 3.3 The Mist ledger — per-epoch settlement (L3)

`commit` measured 147,792 (first, cold) then **143,277 / 143,277** — constant, and it
*must* be: the function takes five fixed-size scalars (`BatchSettler.sol:232-238`).

`settle` swept over R net rows (distinct recipients, ETH mode):

| R | gas | marginal Δ per row |
|---|---|---|
| 1 | 148,693 | — |
| 2 | 191,813 | 43,120 |
| 4 | 283,062 | 45,625 |
| 8 | 465,568 | 45,627 |
| 16 | 830,610 | 45,630 |
| 32 | 1,560,808 | 45,637 |
| 64 | 3,021,656 | 45,652 |
| 128 | 5,945,146 | 45,680 |
| 256 | 11,799,266 | 45,735 |

That is the whole amortization story in one column: **fixed ≈ 103,000 + marginal
≈ 45,600–45,700 per row.** The marginal is the two storage slots a `NetInstruction`
occupies (`ep.net.push`, line 280) plus the loop; the fixed part is the netting-root
check (`nettingRoot != keccak256(abi.encode(net))`, line 263), `_sumNet` (line 264) and
the funding check (lines 267-271).

`claim` per row: **33,308** gas when the recipient account exists, **60,835** when it is
fresh (the 27,527 delta is EIP-161: paying a brand-new account costs +25,000 to create
it). USDC mode is the same shape: `settle`-usdc 167,624 (R=1) / 1,558,172 (R=32),
`claim`-usdc 54,269.

**Mainnet validation (S-79 run, 2026-09-01, Base).** The first real settlement epoch on
the current in-service settler (`0xa3397ce4fDE01810F8540A25363A88D5e57f4166`) measured
`commit` at **158,717** gas (tx `0x2ed64056…66a8`) and `settle` with R = 1 at
**164,013** gas (tx `0x621045df…1434`) — **+10.8% / +10.3%** over the local anvil
figures above. The offset is systematic (both functions shift together); we report it
without attributing it — the two measurement contexts differ (local anvil node vs Base
mainnet execution). The §4 model keeps the anvil-fitted coefficients and reads them as
a lower bound; a uniform +11% on the floor changes no conclusion below.

### 3.4 The insurance premium — challenge gas

The happy path pays zero for the challenge machinery. What it *insures* against,
measured (kind-2 fraud proofs, K intents carried against an N-leaf commitment tree):

| K | N (tree depth) | execution gas |
|---|---|---|
| 1 | 8 (d3) | 75,721 |
| 1 | 1,024 (d10) | 86,105 |
| 8 | 1,024 (d10) | 328,002 |
| 1 | 32,768 (d15) | 104,203 |
| 32 | 1,024 (d10) | 1,236,963 |
| 32 | 32,768 (d15) — the protocol cap | **1,760,135** |

Two readings:

* **Depth slope ≈ 3,300 gas per intent per level** (K=32: 523,172 gas over levels
  10→15 → 104,634/level ÷ 32 intents). At the comment's own premise in
  `BatchSettler.sol:163-165` (epoch capacity 100k → depth 17), the flagship K=32
  challenge extrapolates to **≈ 1.97 M gas**.
* **The in-code estimate was ~3× low.** The same comment claimed "32 intents ≈ 500–600k
  gas". Measured: 1,760,135 at depth 15, ≈1.97 M at depth 17. The sha256-count and
  depth premise in the comment stand; the gas figure did not. Fixed in
  `28fdce1` (chore(contracts): correct challenge gas comment) after this measurement.
* **It is still cheap relative to a block.** 1.97 M gas = **0.49%** of Base's 400M block
  gas limit. The comment's real claim — "block-includable" — survives measurement; its
  number just needed the 3× haircut.

Challenge economics, measured on the deployment calldata: the schedule bond is
**1 ETH** (`appendSchedule(1 ETH, 0.1 ETH)`, nonce 3) and the challenge bond **0.1 ETH**
(read back from `challengeBond()`). A successful challenger gets bond + operator bond in
one call and nets **+1 ETH** for ≈1.76–1.97 M gas (~0.0000098 ETH at 0.005 gwei); the 0.1
ETH challenge deposit itself comes back (net zero). A failed challenger burns 0.1 ETH.
(Context note: those schedule constants are settler #1's — retired after the
refund-path fix. On the current in-service settler #2 the operator bond is not a
schedule constant: the operator escrows whatever it chooses per `commit` — no protocol
minimum; our mainnet run escrowed 0.0005 ETH — and a successful challenger nets exactly
that amount.)

---

## 4. The amortization model

One epoch that settles N payments into R net rows costs:

```
per-epoch gas ≈ 246,000            (commit 143,277 + settle fixed ≈103,000)
             + 45,650 × R          (settle rows)
             + 33,308 × R          (claims, existing recipients)
             → 246,000 + 78,958 × R
per-payment gas ≈ (246,000 + 78,958 × R) / N
```

(With all-fresh recipients the row term becomes ≈106,485 instead of 78,958. Mainnet
anchor from §3.3: measured commit + settle(R=1) on Base land ≈ +10–11% above these
anvil figures — a systematic offset; read the coefficients as a lower bound. Conclusions
below are unchanged.)

Scenario table, N = 1,000 payments per epoch:

| R (distinct recipients) | gas per payment | vs direct settle (61,105 warm) |
|---|---|---|
| 1 | **325** | **188× cheaper** |
| 10 | 1,036 | 59× cheaper |
| 100 | 8,142 | 7.5× cheaper |
| 1,000 (no netting at all) | 79,204 | **30% more expensive** |

Break-even against the warm direct-settle cost of 61,105 gas/payment: with R = N/10
recipients, one epoch breaks even at **N ≈ 5 payments**; with all recipients identical,
at N ≈ 5.3. The fixed 246k dominates the curve, so Mist is not a "big batch only"
technology — **five payments to a repeating recipient already win.**

The honest negative result first: **if every payment has a unique recipient, batching is
not cheaper on-chain.** R = N costs ≈79 k/row warm (45,650 settle + 33,308 claim) against
61,105 for a direct transfer — ~30% more, because a claim is a second transaction that a
direct transfer does not need. Netting only pays when recipients repeat.

---

## 5. Direct settle vs batched settle: the full comparison

| | x402 direct (exact / EIP-3009) | x402 upstream batching (payment channels) | Mist (net settlement) |
|---|---|---|---|
| Chain tx per payment | **1** | ~0 (vouchers off-chain) | ~0 |
| Fixed chain work | — | 1 deposit per client | 1 `commit` + 1 `settle` per epoch (246k + 45.6k·R) |
| Per-recipient work | — | batched claim + separate settle sweep | `claim` 33.3k (or 60.8k fresh) |
| Client pre-funding | none | **required** — deposit escrow once per channel, `depositMultiplier` default 5 (`batch-settlement/README.md:3,5,47`) | none |
| Who fronts capital | nobody (atomic transfer) | the client | **the operator** at `settle{value: Σnet}`, recovered after the window |
| Latency to finality | one block | one block for a claim | payment is ledgered instantly; funds claimable after 6 h (`CHALLENGE_WINDOW`, `BatchSettler.sol:167`) |
| Trust model | facilitator honest per tx | channel escrow | optimistic: 6 h fraud window, operator bond in escrow (operator-chosen amount, returned in full on honest settlement), anyone may challenge |
| Client-side per-payment work | 1 EIP-712 signature (offline) | 1 voucher signature (offline) | 1 ZK proof (offline, no gas) |

The three designs are three different answers to the same question — *who waits, and
who locks capital*. Direct settle locks nothing and pays linearly. Channels move the
lockup to the client. Mist moves it to the operator and buys an N-fold reduction in
on-chain work with a 6-hour optimistic window.

---

## 6. Conclusions: when batching pays

1. **Rule of thumb: N/R > ~5.** Whenever a batch of N payments touches fewer than N/5
   distinct recipients, Mist's per-payment on-chain cost beats a direct x402 settlement,
   and it beats it hard at scale (59–188× at N=1,000). Recipient repetition is the normal
   case for a merchant, an API provider, or any per-seat service — which is exactly the
   x402 audience.
2. **Unique-recipient traffic should stay direct.** One-off payments to never-seen
   payees are ~30% cheaper as direct `transferWithAuthorization` than through net + claim.
   A production gateway would route by recipient-cardinality, not by ideology.
3. **The batch does not bloat the chain.** `commit` is constant at 143,277 gas because
   the batch arrives as a 32-byte root; only the *net* scales, at ≈45.65k per row. Batch
   size N is a purely off-chain knob (ZK proving time), not a gas knob.
4. **The optimistic window is the real price.** 6 hours of challenge latency, operator
   capital fronted at settle, and the operator bond escrowed for the window (returned in
   full on honest settlement). The insurance is cheap to buy
   (zero on the happy path) and cheap to exercise (0.49% of a Base block even at the
   protocol cap).
5. **USD figures are intentionally absent.** Everything above is in gas and ETH at a
   measured base fee; converting to USD needs an exchange-rate source and a decision
   about which fee regime to quote (Base base fee vs L1 data availability) — **USD: to
   fill in**.

### Measurement log

* `02-gas-measurement-log-local.txt` — full `forge test --match-contract GasLedgerTmp -vvv` output, 10/10 PASS, every LEDGER line quoted above.
* `02-gas-measurement-log-fork-base-usdc.txt` — full fork run, including the traced `transferWithAuthorization` call with its calldata, the `AuthorizationUsed`/`Transfer` events, and the 66,313/37,365/8,638 gas figures.
* Mainnet receipts: `cast receipt 0xd95c1a8b94798ed6452b65e47af2af1f67f49cc9d0db87476e163040b658f7e4` (DSA), `0x9724622441da49cad4a5215e62583cdcfacedceccdaf7350a9984698e8e2725a` (RevocationRegistry), `0x935a9433b354e69105cfe75c2a59c8950ac2a9890a9fcdeb1d78434184b72d24` (OperatorRegistry), `0xf6e0c4fc7c97d902a556c81af955ef005a9a14c2cbf177d4aa460df0d1bd9c77` (appendSchedule), `0xbada45738fc6042f870e0114aa0d5b0e85dbad018bf5b0438143b03de35b28dc` (BatchSettler), `0x7ea438ec2af0b58ba27400f454850ebf5fc35c83891fe5bb6edff384227bf9c2` (registerOperator), all against `https://mainnet.base.org`.
* The measurement harness (`contracts/test/GasLedgerTmp.t.sol`) was run once at repo commit `de782b6` and deleted. The only repo change that followed from this article is the one-line comment correction above (`28fdce1`).
