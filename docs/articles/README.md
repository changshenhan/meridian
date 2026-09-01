# Articles — measured engineering notes

Every number in these pieces is measured, and every measurement is reproducible:
commands, on-chain receipts, and preserved logs are included in the text. No invented
figures. Negative results are published as-is.

| # | Piece | What it establishes |
|---|---|---|
| 01 | [Reverse-engineering the Barretenberg proof msgpack format](01-bb-msgpack-reverse-en.md) | Real findings about the Noir/Barretenberg proof wire format: `vk_hash` is the Fiat-Shamir transcript annotation hash (not `keccak256(vk)`); the 129-vs-121 public-input gap is 8 pairing-point slots. Ships with a zero-dependency parser. |
| 02 | [What an x402 payment actually costs on-chain](02-x402-gas-ledger-en.md) | The measured gas ledger of x402 settlement on Base: 61,105–90,053 gas per payment; a Base fork running real USDC bytecode; batched settlement amortizes to (246k + 78,958×R)/N per payment; honest negative cases included (batching loses ~30% with all-unique recipients). |
| 03 | [Mist settlement — pricing one-pager](03-pricing-onepager-en.md) | Launch pricing built on the measured cost floor: every price is traceable to a gas number in article 02 by a fixed formula. What is *not* claimed is stated as carefully as what is. |
| — | [Why machine commerce does not need a new chain](../why-no-new-chain.md) | Position paper: agents don't need a new settlement network — they need a protocol for authorization, budget, and delivery proof running on the networks that already have liquidity. |
