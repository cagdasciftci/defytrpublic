# wallet-ownership-proof — Specification (draft v0.1)

Status: draft v0.1, updated 2026-10-24. Sources and test vectors: [`research/test-vectors.md`](../research/test-vectors.md).

## 1. Purpose

A small, dependency-light library that lets a VASP **prove that a customer controls a self-hosted (unhosted) wallet address** before a Travel Rule transfer to or from that address is released, and that **records the proof as auditable evidence**.

It produces the evidence a Travel Rule policy engine needs for its "self-hosted address owned or controlled by the customer" decision, instead of trusting a caller-supplied boolean.

### What it proves — and what it does not

- **Proves:** at verification time, someone holding the private key of address *A* signed a challenge that is bound to this VASP, this chain, this address, this transfer and a fresh, single-use nonce.
- **Does not prove:** legal ownership, beneficial ownership, or that the signer is the KYC'd customer. Binding the signer to the customer is the VASP's session/KYC responsibility. The library states this limit in every evidence record (`claim: "control"`).

### Regulatory basis

- **EU, Regulation (EU) 2023/1113 Art. 14(5) and 16(2):** for transfers exceeding EUR 1,000 to or from a self-hosted address, the CASP "shall take adequate measures to assess whether that address is owned or controlled by" its customer.
- **EU, EBA Travel Rule Guidelines (EBA/GL/2024/11) para 83(d):** one listed method is "requesting the customer to digitally sign a specific message into the account and wallet software with the key corresponding to that address". At least one method is required (para 83); a combination only where one is not sufficiently reliable (para 85). The assessment happens before the transfer is initiated / funds are made available (para 79). Once satisfied, a CASP may whitelist the address (para 86) — a deployment policy, not part of this library.
- **Türkiye, Tedbirler Yönetmeliği Art. 24/A(6):** for wallets not registered at any crypto asset service provider, the rule found is a customer **declaration** about the wallet owner; no ownership-verification method is prescribed. This library can strengthen that declaration with cryptographic evidence; it is not a Turkish legal requirement. (Text read from a commercial republisher of the Resmî Gazete; confirm against the official gazette before citing.)

Switzerland (FINMA Guidance 02/2019) and the UK (MLR 2017 reg. 64G) are covered in [JURISDICTIONS.md](JURISDICTIONS.md), which also has the machine-readable profiles exported as `selfHostedRequirement`.

This is engineering analysis, not legal advice.

## 2. Scope

| Version | Chains / schemes | Notes |
| --- | --- | --- |
| v0.1 | EVM EOA: EIP-191 `personal_sign` over an EIP-4361 (SIWE) message | Phase 1 |
| v0.2 | Bitcoin: BIP-322 simple (P2WPKH; P2TR key-path), `smp`-prefixed or unprefixed; jurisdiction profiles (EU, CH, UK, TR) | Verifier done; challenge-service wiring next. `ful` variant, P2WSH, script-path, legacy BIP-137 → `SCHEME_UNSUPPORTED` |
| later | EVM smart-contract wallets (EIP-1271 via public RPC), Solana ed25519, Tron, micro-payment ("satoshi") test | Out of scope until requested |

Non-goals: holding keys, broadcasting transactions, custody, price feeds, KYC.

## 3. Challenge format (EVM)

The challenge is a standard **EIP-4361** message so wallets (MetaMask etc.) render it in a human-readable, phishing-resistant way. Travel Rule binding goes into `Resources`.

```
{domain} wants you to sign in with your Ethereum account:
{address (EIP-55 checksummed)}

I confirm I control this wallet for a Travel Rule transfer. This signature does not authorize any payment.

URI: https://{domain}/travel-rule/wallet-proof
Version: 1
Chain ID: {chainId}
Nonce: {nonce: ≥ 16 alphanumeric chars, CSPRNG}
Issued At: {ISO 8601 UTC}
Expiration Time: {Issued At + TTL, default 10 min}
Request ID: {challengeId (UUID)}
Resources:
- urn:travel-rule:vasp:{vaspId}
- urn:travel-rule:transfer:{transferReference}
- urn:travel-rule:direction:{inbound|outbound}
```

Binding (domain separation) fields and why each exists:

| Field | Prevents |
| --- | --- |
| `domain` + `URI` | A signature collected by another site/VASP being replayed here |
| `Chain ID` | Same address on another EVM chain being reused |
| `address` | Signature for address B presented as proof for address A |
| `Nonce` + `Request ID` | Replay of an old valid signature (single-use, server-stored) |
| `Issued At` / `Expiration Time` | Stale or pre-generated signatures |
| `urn:travel-rule:transfer:*` | Proof for transfer X reused to release transfer Y |
| Statement "does not authorize any payment" | Social-engineering the user into thinking they are approving a transfer |

## 4. Verification algorithm (EVM, v0.1)

Server keeps a challenge store: `challengeId → {message, address, chainId, transferReference, vaspId, expiresAt, state: issued|consumed|expired}`.

`verify({ challengeId, signature, now })`:

1. Load challenge by `challengeId`; reject `CHALLENGE_NOT_FOUND`.
2. Reject `CHALLENGE_CONSUMED` if state ≠ `issued` (single use; atomic compare-and-set to `consumed` *before* returning success, so two concurrent verifications cannot both pass).
3. Reject `CHALLENGE_EXPIRED` if `now ≥ expiresAt` or `now < issuedAt − clockSkew` (default skew 60 s).
4. Re-render the message from the **stored** fields (never accept a message string from the client). Parse-and-compare is a defence in depth, not the source of truth.
5. Signature format: 65 bytes `r‖s‖v`; accept `v ∈ {27, 28, 0, 1}` normalized to recovery id 0/1; reject anything else `SIGNATURE_MALFORMED`.
6. Reject **high-s** signatures (`s > n/2`) `SIGNATURE_NON_CANONICAL` (malleability).
7. Hash = `keccak256("\x19Ethereum Signed Message:\n" + len(messageBytes) + messageBytes)` (EIP-191 version `0x45`).
8. Recover public key (secp256k1), derive address = last 20 bytes of `keccak256(pubkey[1..])`.
9. Compare recovered address with stored address, case-insensitive on bytes; reject `ADDRESS_MISMATCH`.
10. Mark consumed; emit an **evidence record** (§6).

Every rejection is a typed error code; no rejection leaks which field failed beyond its code. Verification is constant-work with respect to the secret-free inputs (no early-exit on secret data — there is none, but the rule keeps future schemes honest).

## 5. Threat model

| # | Threat | Mitigation | Test |
| --- | --- | --- | --- |
| T1 | Caller sends `ownershipControlVerified: true` without any proof | Integration: in strict mode the flag is ignored unless backed by a stored evidence record | `strict mode rejects bare boolean` |
| T2 | Replay of a previously valid signature | Single-use nonce, atomic consume | `second verify of same challenge fails` |
| T3 | Signature for another address | Recover-and-compare | `wrong key → ADDRESS_MISMATCH` |
| T4 | Cross-chain / cross-domain / cross-transfer reuse | Bound fields re-rendered from server state | one test per bound field |
| T5 | Expired or future-dated challenge | TTL + skew | `expired`, `not yet valid` |
| T6 | Signature malleability (high-s) | Reject non-canonical s | vector with s' = n − s |
| T7 | Malformed input (length, hex, v) | Strict parsing | fuzz-style table test |
| T8 | Client-supplied message text differs from issued challenge | Server renders the message itself | `tampered message ignored` |
| T9 | Race: two concurrent verifies of one challenge | Compare-and-set consume | concurrent test |
| T10 | Phishing: user believes they authorize a payment | Explicit statement; SIWE format recognised by wallets | manual (demo) |
| T11 | Smart-contract wallet (Safe) cannot produce ECDSA sig | Returns `SCHEME_UNSUPPORTED` with reason; falls back to manual review (no false positive) | `contract wallet → unsupported` |
| T12 | Buggy crypto implementation | Use audited `@noble/curves` + `@noble/hashes`; official vectors in CI | vector suite |
| T13 | Evidence tampering after the fact | Evidence record carries message, signature, recovered address; anyone can re-verify offline | `re-verify evidence` |

## 6. Evidence record

```json
{
  "schema": "wallet-ownership-proof/evidence@1",
  "claim": "control",
  "result": "verified",
  "scheme": "eip191-siwe",
  "provenance": "self_hosted_verifier",
  "domain": "vasp.example",
  "vaspId": "…",
  "address": "0x…",
  "chainId": 1,
  "transferReference": "…",
  "challengeId": "…",
  "nonce": "…",
  "issuedAt": "…",
  "expirationTime": "…",
  "message": "…exact signed text…",
  "signature": "0x…",
  "verifiedAt": "2026-…Z",
  "verifierVersion": "0.1.0"
}
```

`provenance` distinguishes this verifier from any vendor (e.g. a future Sumsub mapping) so a policy and an auditor can tell evidence sources apart. The record is self-contained. Offline re-verification (`reverifyEvidence(record, { domain, vaspId, evidenceKey? })`) rebuilds the signed text from the record's own fields, requires it to equal `message` exactly and re-runs §4 steps 5–9. Editing any bound field, or a record for another domain, fails.

Limit: without a seal, a valid result (`signatureValid`) only proves that the address's key signed that exact text — anyone can construct and self-sign such a record. A VASP that configures `evidenceKey` (≥ 32-byte secret) gets an HMAC-SHA256 `seal` over the canonical record; re-verifying with the same key yields `issuerAttested: true`. Policy decisions must always go through the server-side proof lookup, never through a record supplied by a caller.

## 7. Integrating with a policy engine

Pattern for a Travel Rule engine that today accepts a caller-supplied "ownership/control verified" flag:

1. Expose two endpoints: issue a challenge (address, network, transfer reference, direction) and verify a signature for it.
2. The caller references the result by proof id instead of sending a boolean.
3. The engine resolves the proof id server-side, checks it is bound to the same API client, transfer reference, network and declared address, and only then marks the requirement as met. The evidence record is stored with the case.
4. **Compatibility mode (default):** a caller-supplied boolean keeps working, tagged `provenance: "caller_asserted"`.
5. **Strict mode (opt-in):** the boolean is ignored unless backed by a resolved proof.

If the engine's transfer payload carries no wallet address, the caller must declare the address next to the proof id; the engine can then bind the proof to it but cannot independently know the on-chain destination. State this limit to auditors.

## 8. Test plan

- Official and published vectors: web3.js, ethers.js and viem EIP-191 vectors plus an independent pure-Python vector (in CI); BIP-322 `basic-test-vectors.json` (message hashes, `to_spend`/`to_sign` txids, P2WPKH and P2TR signatures, error cases) in CI and in the independent Python reference `tools/bip322_reference.py`; spruceid/siwe vectors collected.
- Threat-model tests T1–T13 (one or more each).
- Property test: random keys → sign → verify succeeds; any single-byte flip in message or signature → fails.
- Integration: a policy case that requires ownership/control verification moves from manual review to allow only via a resolved proof; strict-mode test for T1.

## 9. Dependencies

`@noble/curves` 1.9.7 (MIT, one dependency: `@noble/hashes`; secp256k1 audited by Trail of Bits at v0.7.3, later modules by Kudelski Security and Cure53) and `@noble/hashes` 1.8.0 (MIT, zero dependencies; audited by Cure53 at v1.0.0). Why not Node.js built-ins: Node.js `crypto` offers SHA3-256 but not Keccak-256 (different padding), and no secp256k1 public-key recovery. The BIP-322 path additionally uses `ripemd160` (`@noble/hashes/legacy`) and BIP-340 `schnorr`; Node.js `crypto` does provide RIPEMD-160; the noble version is used so all hashing comes from one audited, pinned source.
