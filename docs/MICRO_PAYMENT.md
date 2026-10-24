# Micro-payment ("satoshi") test: design note

Status: **design only, not implemented.** This note records why, and what an implementation would look like if a deployment wants it.

## What it is

EBA/GL/2024/11 para 83(c) lists, as one way to assess control of a self-hosted address, "sending of a predefined amount (preferably the smallest denomination of a given crypto-asset), set by the CASP, from and to the self-hosted address to the CASP's account". Para 85 says to combine methods only where one method alone is not reliable enough.

## Why the library does not ship it

| | Signed message (shipped) | Micro-payment |
|---|---|---|
| Cost to customer | none | network fee, every time |
| Time to result | seconds | until confirmed (minutes to an hour) |
| Works for an empty wallet | yes | no |
| Needs chain data | no | yes: the VASP's node or indexer |
| Binds to one transfer | yes (signed reference and direction) | only through the amount, within a time window |
| Leaves an on-chain trace linking customer and VASP | no | yes |

The library is deliberately offline: it holds no keys and makes no network calls (SPEC §2, non-goals). A micro-payment check cannot be done without observing the chain, and every VASP already has its own deposit-monitoring pipeline. Duplicating that here would add an untrusted data source.

It remains useful where signing is impossible: hardware or custodial-looking wallets without message signing, smart-contract wallets before EIP-1271 support, chains not yet covered. It is also a second method when a risk score calls for a combination (para 85).

## Shape of an implementation

Pure functions, with the deposit observation supplied by the caller:

```js
// 1. Issue: a unique, random amount, so that concurrent tests cannot be confused.
const test = issueMicroPayment({
  address,          // customer's self-hosted address
  network,          // e.g. 'bitcoin:mainnet', 'eip155:1'
  depositAddress,   // VASP-controlled, ideally unique per test
  minUnits, maxUnits, // e.g. 546..1546 sats; above dust, below meaningful value
  ttlMs,            // e.g. 24h
});
// → { testId, amountUnits, depositAddress, expiresAt }   stored like a challenge

// 2. Match: called by the VASP's deposit monitor for each confirmed incoming transfer.
matchMicroPayment(test, observed /* { txid, from, to, amountUnits, confirmations, seenAt } */);
// → evidence { claim: 'control', method: 'micro_payment', txid, ... } or a typed rejection
```

Rules the matcher must enforce:

- **Exact amount and exact destination.** No "at least" matching.
- **Sender must be the declared address.** For UTXO chains every input must belong to that address, so a payment from a mixed set of inputs does not count.
- **Inside the time window, confirmed to the VASP's own depth policy, single use.** These are the same atomic consume rules as challenges (store contract, SPEC §4).
- **Network fee is the customer's.** Return of the funds, if any, is a separate business decision.

## Limits to state up front

- A payment proves only that someone with access to that address's funds sent it. That is weaker than a signature bound to one transfer, because anyone the customer asks (or a service holding the key) can send it.
- Exchanges and custodial wallets can also send exact amounts, so a micro-payment does not by itself prove that the address is self-hosted.
