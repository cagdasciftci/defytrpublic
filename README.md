# wallet-ownership-proof

Prove — and keep auditable evidence — that a customer **controls** a self-hosted (unhosted) wallet before a crypto Travel Rule transfer is released.

> Status: work in progress (v0.1, EVM first). Not production-ready.

## Why

EU Travel Rule rules require a VASP to assess whether a self-hosted address is owned or controlled by its customer for transfers above EUR 1,000. Many compliance stacks store this as a single caller-supplied boolean. This library replaces the boolean with a **cryptographic proof**:

1. The VASP issues a challenge bound to its domain, the chain, the address, the transfer and a single-use nonce, in the standard [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) (Sign-In with Ethereum) format that wallets display clearly.
2. The customer signs it in their own wallet. Nothing is paid; no transaction is broadcast.
3. The library verifies the signature and emits a self-contained **evidence record** an auditor can re-verify offline.

It proves **control** of the key at verification time, not legal ownership. See [docs/SPEC.md](docs/SPEC.md) for the threat model and the exact limits, and [docs/JURISDICTIONS.md](docs/JURISDICTIONS.md) for what the EU, Swiss, UK and Turkish texts require.

## Roadmap

| Version | Scope |
| --- | --- |
| 0.1 | EVM externally-owned accounts: EIP-4361 challenge, EIP-191 verification, replay and malleability protection, official test vectors |
| 0.2 | Jurisdiction profiles (EU, CH, UK, TR); Bitcoin BIP-322 (P2WPKH, P2TR) |
| later | Smart-contract wallets (EIP-1271), Solana, Tron |

## Demo

```sh
npm ci
node examples/demo/server.js   # http://localhost:8787
```

One page, no build step. Pick a jurisdiction and amount, connect **MetaMask** (any chain; Sepolia is fine) or **UniSat** (Bitcoin, BIP-322), sign the challenge and see the verified, sealed evidence record and the requirement for that jurisdiction. No payment or gas is involved. The demo keeps everything in memory.

## Development

```bash
npm install
npm test
```

Requires Node.js 24. Tests use the built-in `node:test` runner.

## License

Apache-2.0
