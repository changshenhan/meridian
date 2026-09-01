# A settlement epoch on Base mainnet, end to end: commit, settle, wait six hours, claim, release

*Article ⑤ of the Mist engineering series. Every number below is read off Base mainnet
(chain id 8453) through public RPC and Basescan: transaction hashes, `gasUsed` figures,
timestamps, and contract storage reads. The run transferred real ETH and really waited
out the challenge window. Nothing is simulated; where a figure could not be measured,
it is not printed.*

---

## 0. What this is, and what it is not

An x402 payment today settles as **one EIP-3009 transaction per payment**. There are
three known ways off that treadmill: keep paying per transaction; move to payment
channels (client-side pre-funding); or batch optimistically — ledger everything
off-chain, post one commitment, settle the *net*, and hold a challenge window so anyone
who can prove fraud takes the operator's bond.

This piece documents the first time the third design ran **its entire life cycle on a
public mainnet with real money**: five intents aggregated, committed with the operator's
bond in escrow, settled to a net of 1,000 wei, a six-hour challenge window that nobody
challenged, the net claimed, and the bond returned in full.

What it is **not**:

* **Not a cost demo.** The batch is N = 5, chosen so the real money at stake is tiny
  (0.0005 ETH bond, 1,000 wei of settlement). At N = 5 the batching economics have not
  kicked in yet — see §4 — the point here is the life cycle, not the price.
* **Not a security proof.** The settlement proof seam is still the `FormatVerifier`
  placeholder (the real ZK prover is a separate workstream); the challenge window's
  verification path is real and permissionless, but this run proves the *life cycle*,
  not the fraud-defence.

## 1. The six transactions, as they actually ran

All on BatchSettler **#2** (`0xa3397ce4fDE01810F8540A25363A88D5e57f4166`), the current
in-service instance — the second deployment on the public registry, carrying the S-77
`releaseBond` refund path. Operator/wallet: `0xBE25c7F87128a66Ec270abeE3Cfdf6a64E3e08a6`.

| # | Action | tx | gasUsed | Result |
|---|---|---|---|---|
| 1 | Deploy BatchSettler #2 | [`0x6a280219…30b40ba82`] | **1,921,390** | block 50,736,481 |
| 2 | `registerOperator` (self-registration) | [`0xc51fb75b…6cd6a7bf85`] | **151,689** | block 50,736,502 |
| 3 | `commit` — epoch 0, bond 0.0005 ETH escrowed | [`0x2ed64056…91de7c166a8`] | **158,717** | block 50,737,119 |
| 4 | `settle` — 1 net row, 1,000 wei funded | [`0x621045df…1b1434`] | **164,013** | block 50,737,120 |
| 5 | `claim` — recipient receives 1,000 wei | [`0x189e72c8…bd20f3e0`] | **63,981** | block 50,747,957 |
| 6 | `releaseBond` — bond returned in full | [`0x33b51686…e0afe1`] | **34,377** | block 50,747,959 |

The batch itself: 5 signed intents × 200 wei, all to one recipient (R = 1), sealed
off-chain into a commitment; `settle` funded the exact net (1,000 wei) and recorded
`settledAt` = `1788263587`. Every root the contract stores (`commitmentRoot`,
`revocationRoot`, `acceptanceRoot`, `nettingRoot`) was verified byte-identical against
the off-chain snapshot before the commit transaction was signed.

## 2. The bond is a lease, not a deposit

The most common misreading of optimistic settlement is that the bond is capital the
operator surrenders. After S-77 the contract's answer is precise:

* The bond amount is **chosen by the operator per `commit`** — there is no protocol
  minimum. This run escrowed **0.0005 ETH** (`5e14` wei), deliberately small.
* On honest settlement the bond sits in the contract through the window, then
  `releaseBond` returns it **in full** — [`0x33b51686…e0afe1`] emitted `BondReleased`
  for exactly `5e14` wei, and the settler contract's ETH balance reads **0** on-chain
  today (the contract is drained; it never held anything but this epoch's bond and
  settlement funding).
* "At risk" applies only when fraud is proven: a successful challenge (0.1 ETH
  challenger deposit, returned on success, burned on failure) transfers the operator's
  *entire escrowed bond* to the challenger. Insurance premium measured in article ②:
  ≈1.76–1.97 M gas to exercise.

So the honest sentence is: **bond = rent-free escrow for six hours, at risk only against
fraud.** The old "1 ETH locked and at risk" framing — ours, in earlier drafts — was
wrong in both halves: the amount is not fixed, and it is not lost on the happy path.

## 3. The window, from the outside

`settledAt` = `1788263587`; `CHALLENGE_WINDOW` = 21,600 s; unlock at `1788285187`
(2026-09-02, ~01:53 UTC+8). The claim tool reads the window off the chain and
**refuses to run early** — fail-closed, exiting with the remaining seconds rather than
guessing at block timestamps. The window closed with zero challenges filed; the claim
landed at block timestamp `1788285261` — **74 seconds after unlock** — and
`releaseBond` followed 2 blocks (4 seconds) later.

One incident from the run, kept in the record because it is exactly the kind of thing
that gets glossed over: right after `releaseBond` landed, our own tool panicked. The
post-release `bondedAmount` read hit a lagging node behind a load-balanced public RPC
and returned the pre-release value — a stale read, the same failure mode our deployment
tooling already guards against (the guards just never got wrapped around *this* read).
On-chain, the release had succeeded: `BondReleased` event, receipt status 1, contract
balance 0. We rebuilt the reconciliation from events and receipts instead of the tool's
stdout. The funds were never at risk — both transactions succeeded and the release
preconditions are idempotent — but the tooling lesson is real: every post-transaction
read belongs behind the same retry/backoff path as every other one.

One detail worth keeping: the recipient here is the operator's own address, so the
claim is a real transfer that happens to be self-directed. The contract's balance
assertion is therefore checked *contract-side* (`get_balance(settler)` deltas), not
recipient-side, where the same transaction's gas refund would pollute the delta.

## 4. Gas: mainnet vs the article-② ledger

Article ② fitted its amortization model on local anvil runs. This run is the first
check of those numbers against real Base execution:

| Action | anvil prediction (article ②) | mainnet measured (this run) | delta |
|---|---|---|---|
| `commit` | 143,277 | **158,717** | **+10.8%** |
| `settle` (R=1) | ≈148,650 (103k fixed + 45,650×1) | **164,013** | **+10.3%** |
| `claim` (R=1, existing account) | 33,308 * | **63,981** | different scope * |
| `releaseBond` | not measured in ② (S-77 face) | **34,377** | — |

\* Scope note: 33,308 is article ②'s harness figure — an *execution-only* `gasleft()`
delta that excludes the 21,000-gas tx base and calldata intrinsic. 63,981 is the
mainnet `gasUsed` — the *full transaction* figure. The ≈30.7k difference is the same
order as base + intrinsic + first-touch cold accesses, so we report both numbers side
by side without converting them into a percentage — same discipline as the
systematic-offset note above: measured, not attributed.

The offset is **systematic** — both measured functions shift together, ~+10–11% — and we
report it without attributing it: local anvil node and Base mainnet execution are
different measurement contexts. The article-② coefficients should be read as a lower
bound; a uniform +11% on the floor changes no conclusion there (the N=1,000 margins of
7.5×–188× survive intact).

And the honest arithmetic for *this* batch: at its actual N = 5, R = 1, the full
life-cycle cost — commit 158,717 + settle 164,013 + claim 63,981 + releaseBond 34,377 —
is ≈ 84,200 gas **per payment** against 61,105 for a direct warm transfer, i.e. ~38%
*more* expensive. That is not a surprise and not a scandal: N = 5 sits just before the
model's break-even (N ≈ 5.3), the batch was sized for a tiny-money life-cycle
demonstration, and the economics arrive where the model says they arrive — at N in the
hundreds, where the same fixed cost amortizes to hundreds of gas per payment. The run
bought the life cycle, not the margin.

## 5. Honest boundaries

Four things this run does not demonstrate, stated plainly:

1. **Proof seam.** Settlement verification uses the `FormatVerifier` placeholder; the
   real ZK prover (Noir/Barretenberg) is a separate workstream with its own published
   notes.
2. **Delegation registration is not consumed on-chain.** `commit`/`settle`/`claim` do
   not read the DSA on-chain registry; the delegation trail lives in the off-chain
   ledger and the challenge path can reconstruct it from evidence.
3. **Key identity.** The delegation owner is derived from the operator's own signer key
   (non-custodial but self-dealt); the agent key is a demo fixture.
4. **Self-directed funds.** The recipient is the operator's own address: real transfers,
   real escrow, but money moving from us to us. No third party's funds were involved at
   any point.

The tooling is open source: `contracts/rust-smoke/src/bin/mainnet_settle.rs` (two-phase
`--phase commit` / `--phase claim` sidecar; the split exists because a mainnet contract
cannot warp time for you), with the run snapshot retained as the claim phase's input.

## 6. What carries forward

* Article ②'s model gains a mainnet anchor: anvil-fitted coefficients = lower bound,
  measured mainnet = +10–11%.
* The bond life cycle is closed in the contract and now demonstrated end to end:
  escrow → (window) → claim rows → release, with the drained-contract assertion.
* The remaining gap between this run and production settlement is the one §5 opens with:
  the proof seam, and multi-operator traffic that makes R/N pooling real.

---

### Sources

All six transactions are readable on Basescan from wallet
`0xBE25c7F87128a66Ec270abeE3Cfdf6a64E3e08a6` (blocks 50,736,481–50,737,120 for the
deploy/register/commit/settle quartet; 50,747,957/50,747,959 for the claim/release
pair). Run snapshot:
[`05-mainnet-run-snapshot.json`](05-mainnet-run-snapshot.json) (roots, bond, net rows,
commit and settle tx hashes). Reconciliation was reconstructed from on-chain evidence — `Claimed` /
`BondReleased` event logs, transaction receipts (both status 1), and the drained
contract balance — because the claim tool's stdout died on the stale-read panic
described in §3. Contract source: `contracts/src/BatchSettler.sol` on `main`
(`releaseBond` at line 405, `CHALLENGE_WINDOW` at line 167).
