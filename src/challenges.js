import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { decodeSegwitAddress, verifyBip322Simple } from './bip322.js';
import { ErrorCode, ProofError } from './errors.js';
import { isContractWalletSignature, toChecksumAddress, verifyPersonalSignature } from './evm.js';
import { generateNonce } from './nonce.js';
import { buildBitcoinChallengeMessage, buildSiweMessage } from './siwe.js';

export const VERIFIER_VERSION = '0.2.0';
export const SCHEME_EIP191_SIWE = 'eip191-siwe';
export const SCHEME_BIP322_SIMPLE = 'bip322-simple';
const SCHEMES = new Set([SCHEME_EIP191_SIWE, SCHEME_BIP322_SIMPLE]);
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_SKEW_MS = 60 * 1000;

/**
 * Challenge store contract (SPEC §4). Any durable implementation MUST satisfy all of:
 *
 * 1. `save(challenge)` inserts only. A duplicate `challengeId` is an error; it never upserts and
 *    never resets `state` to `issued`. Bound fields are immutable after insert.
 * 2. `get(challengeId)` returns a copy of the stored record (with `state`) or `null`.
 * 3. `consume(challengeId, now)` is ONE atomic conditional update that succeeds only if the record
 *    is still `issued` AND `now < expirationTime`, and returns `true` only to the single caller whose
 *    update changed a row — across processes and connections, e.g.
 *    `UPDATE challenges SET state='consumed', consumed_at=$2
 *       WHERE id=$1 AND state='issued' AND expires_at > $2 RETURNING id`
 *    The update MUST be committed before `consume` resolves.
 *    `now` is the application server's clock. With several app instances, keep clocks in sync (NTP)
 *    or substitute the database clock (`now()`) in the conditional update.
 *
 * `runStoreConformance` in `./storeConformance.js` checks these rules for any implementation.
 */
export class MemoryChallengeStore {
  #items = new Map();

  async save(challenge) {
    if (this.#items.has(challenge.challengeId)) throw new Error('duplicate challengeId');
    this.#items.set(challenge.challengeId, Object.freeze({ ...challenge, state: 'issued' }));
  }

  async get(challengeId) {
    const item = this.#items.get(challengeId);
    return item ? { ...item } : null;
  }

  async consume(challengeId, now) {
    // No `await` between check and set: atomic within one Node.js process.
    const item = this.#items.get(challengeId);
    if (!item || item.state !== 'issued') return false;
    if (!(now instanceof Date) || !(now.getTime() < Date.parse(item.expirationTime))) return false;
    this.#items.set(challengeId, Object.freeze({ ...item, state: 'consumed', consumedAt: now.toISOString() }));
    return true;
  }
}

function parseTime(value) {
  const t = Date.parse(value);
  if (!Number.isFinite(t)) throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, 'stored challenge has an invalid timestamp');
  return t;
}

/** Deterministic JSON with sorted keys, used as the HMAC input for evidence seals. */
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function sealFor(record, key) {
  const { seal: _ignored, ...unsealed } = record;
  return createHmac('sha256', key).update(canonicalJson(unsealed)).digest('hex');
}

function assertKey(key) {
  const len = typeof key === 'string' ? Buffer.byteLength(key) : key?.length;
  if (!(typeof key === 'string' || Buffer.isBuffer(key) || key instanceof Uint8Array) || len < 32) {
    throw new TypeError('evidenceKey must be a secret of at least 32 bytes');
  }
}

/** Render the signed text from the bound fields. Used at issue, verify and offline re-verify time. */
function renderChallenge(c) {
  const fields = {
    domain: c.domain,
    address: c.address,
    nonce: c.nonce,
    issuedAt: new Date(c.issuedAt),
    expirationTime: new Date(c.expirationTime),
    requestId: c.challengeId,
    vaspId: c.vaspId,
    transferReference: c.transferReference,
    direction: c.direction,
  };
  if (c.scheme === SCHEME_BIP322_SIMPLE) return buildBitcoinChallengeMessage({ ...fields, network: c.network });
  return buildSiweMessage({ ...fields, chainId: c.chainId });
}

/** Check the signature for the scheme; returns the canonical signer address or throws ProofError. */
function verifySignature(c, message, signature) {
  if (c.scheme === SCHEME_BIP322_SIMPLE) {
    return verifyBip322Simple({ address: c.address, message, signature }).address;
  }
  return verifyPersonalSignature({ message, signature, expectedAddress: c.address });
}

/** Resolve the scheme-specific bound fields for a new challenge. */
function bindAddress({ scheme, address, chainId, network }) {
  if (scheme === SCHEME_EIP191_SIWE) return { address: toChecksumAddress(address), chainId };
  if (scheme === SCHEME_BIP322_SIMPLE) {
    const d = decodeSegwitAddress(address);
    if (!((d.version === 0 && d.program.length === 20) || (d.version === 1 && d.program.length === 32))) {
      throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED, 'only P2WPKH and P2TR key-path addresses are supported');
    }
    if (network !== undefined && network !== d.network) {
      throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, `address is on ${d.network}, not ${String(network)}`);
    }
    return { address: address.toLowerCase(), network: d.network };
  }
  throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED, `unknown scheme: ${String(scheme)}`);
}

/**
 * Issues and verifies EIP-4361 wallet-control challenges (SPEC §3–§6).
 * `clock` is injectable so expiry logic is testable without real time.
 */
export class WalletProofService {
  #store;
  #domain;
  #vaspId;
  #ttlMs;
  #skewMs;
  #clock;
  #evidenceKey;
  #evidenceKeyId;

  /**
   * `evidenceKey` (optional, ≥ 32 bytes, kept in the VASP's secret store) seals every evidence record
   * with HMAC-SHA256 so the VASP can later prove the record came from its own verifier, not only that
   * some key signed the text.
   */
  constructor({ store, domain, vaspId, ttlMs = DEFAULT_TTL_MS, skewMs = DEFAULT_SKEW_MS, clock = () => new Date(), evidenceKey, evidenceKeyId }) {
    if (!store) throw new TypeError('store is required');
    if (evidenceKey !== undefined) {
      assertKey(evidenceKey);
      this.#evidenceKey = evidenceKey;
      this.#evidenceKeyId = evidenceKeyId ?? 'default';
    }
    this.#store = store;
    this.#domain = domain;
    this.#vaspId = vaspId;
    this.#ttlMs = ttlMs;
    this.#skewMs = skewMs;
    this.#clock = clock;
  }

  /**
   * Create a challenge for one address, chain and transfer. The returned `message` is what the wallet signs.
   * EVM (default): `{ address, chainId }`. Bitcoin: `{ scheme: SCHEME_BIP322_SIMPLE, address, network? }`;
   * the network is taken from the address prefix and, if given, must match.
   */
  async issue({ scheme = SCHEME_EIP191_SIWE, address, chainId, network, transferReference, direction }) {
    const issuedAt = this.#clock();
    const challenge = {
      challengeId: randomUUID(),
      scheme,
      domain: this.#domain,
      vaspId: this.#vaspId,
      ...bindAddress({ scheme, address, chainId, network }),
      transferReference,
      direction,
      nonce: generateNonce(),
      issuedAt: issuedAt.toISOString(),
      expirationTime: new Date(issuedAt.getTime() + this.#ttlMs).toISOString(),
    };
    const message = renderChallenge(challenge); // validates every field before anything is stored
    await this.#store.save(challenge);
    return { challengeId: challenge.challengeId, message, expiresAt: challenge.expirationTime };
  }

  /**
   * Verify a signature against a stored challenge. The message is re-rendered from stored fields
   * (T8). On success the challenge is consumed atomically with an expiry condition (T2, T5, T9) and
   * a self-contained evidence record is returned (T13).
   */
  async verify({ challengeId, signature }) {
    const challenge = await this.#store.get(challengeId);
    if (!challenge) throw new ProofError(ErrorCode.CHALLENGE_NOT_FOUND);
    if (!SCHEMES.has(challenge.scheme)) throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED);
    // Tenant isolation: a shared store must not let one VASP's service verify another's challenge.
    if (challenge.domain !== this.#domain || challenge.vaspId !== this.#vaspId) throw new ProofError(ErrorCode.CHALLENGE_NOT_FOUND);
    if (challenge.state !== 'issued') throw new ProofError(ErrorCode.CHALLENGE_CONSUMED);

    const now = this.#clock();
    const issuedAt = parseTime(challenge.issuedAt);
    const expiresAt = parseTime(challenge.expirationTime);
    if (now.getTime() >= expiresAt) throw new ProofError(ErrorCode.CHALLENGE_EXPIRED);
    if (now.getTime() < issuedAt - this.#skewMs) throw new ProofError(ErrorCode.CHALLENGE_NOT_YET_VALID);

    if (challenge.scheme === SCHEME_EIP191_SIWE && isContractWalletSignature(signature)) {
      // EIP-1271 / ERC-6492 need an on-chain call; v0.1 fails closed instead of guessing (T11).
      throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED, 'contract-wallet signatures are not supported in v0.1');
    }

    const message = renderChallenge(challenge);
    const recovered = verifySignature(challenge, message, signature);

    // Consume only after the signature checks out (a bad signature cannot burn a challenge). The
    // store re-checks expiry at commit time, so a slow store cannot consume an expired challenge.
    const consumedAt = this.#clock();
    if (!(await this.#store.consume(challengeId, consumedAt))) {
      const latest = await this.#store.get(challengeId);
      throw new ProofError(latest?.state === 'issued' ? ErrorCode.CHALLENGE_EXPIRED : ErrorCode.CHALLENGE_CONSUMED);
    }

    const record = {
      schema: 'wallet-ownership-proof/evidence@1',
      claim: 'control',
      result: 'verified',
      scheme: challenge.scheme,
      provenance: 'self_hosted_verifier',
      domain: challenge.domain,
      vaspId: challenge.vaspId,
      address: recovered,
      ...(challenge.scheme === SCHEME_BIP322_SIMPLE ? { network: challenge.network } : { chainId: challenge.chainId }),
      transferReference: challenge.transferReference,
      direction: challenge.direction,
      challengeId,
      nonce: challenge.nonce,
      issuedAt: challenge.issuedAt,
      expirationTime: challenge.expirationTime,
      message,
      signature,
      verifiedAt: consumedAt.toISOString(),
      verifierVersion: VERIFIER_VERSION,
    };
    if (this.#evidenceKey) {
      record.sealKeyId = this.#evidenceKeyId;
      record.seal = sealFor(record, this.#evidenceKey);
    }
    return Object.freeze(record);
  }
}

/**
 * Re-verify an evidence record offline, without the challenge store (T13).
 *
 * What a successful result means:
 * - `signatureValid: true` — the record's address key signed exactly the challenge text rebuilt from
 *   the record's own fields, for the expected domain and VASP. Editing any bound field fails.
 *   On its own this does NOT prove the VASP ever issued, consumed or recorded the challenge: anyone can
 *   build and self-sign such a record. Policy decisions must use the server-side proof lookup.
 * - `issuerAttested: true` — additionally, the record carries a valid HMAC seal under `evidenceKey`,
 *   i.e. it was produced by this VASP's own verifier. Pass `evidenceKey` to require this.
 */
export function reverifyEvidence(evidence, { domain, vaspId, evidenceKey } = {}) {
  if (!SCHEMES.has(evidence?.scheme)) throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED);
  if (typeof domain !== 'string' || typeof vaspId !== 'string') throw new TypeError('expected { domain, vaspId }');
  if (evidence.domain !== domain || evidence.vaspId !== vaspId) {
    throw new ProofError(ErrorCode.EVIDENCE_MISMATCH, 'evidence was issued for a different domain or VASP');
  }
  if (evidence.claim !== 'control' || evidence.result !== 'verified') {
    throw new ProofError(ErrorCode.EVIDENCE_MISMATCH, 'not a verified control evidence record');
  }
  parseTime(evidence.issuedAt);
  parseTime(evidence.expirationTime);
  const rebuilt = renderChallenge(evidence);
  if (rebuilt !== evidence.message) {
    throw new ProofError(ErrorCode.EVIDENCE_MISMATCH, 'evidence fields do not match the signed message');
  }
  if (verifySignature(evidence, rebuilt, evidence.signature) !== evidence.address) {
    throw new ProofError(ErrorCode.EVIDENCE_MISMATCH, 'evidence address is not in canonical form');
  }

  let issuerAttested = false;
  if (evidenceKey !== undefined) {
    assertKey(evidenceKey);
    const expected = Buffer.from(sealFor(evidence, evidenceKey), 'hex');
    const actual = typeof evidence.seal === 'string' && /^[0-9a-f]{64}$/.test(evidence.seal) ? Buffer.from(evidence.seal, 'hex') : null;
    if (!actual || !timingSafeEqual(expected, actual)) {
      throw new ProofError(ErrorCode.EVIDENCE_SEAL_INVALID, 'evidence seal missing or invalid');
    }
    issuerAttested = true;
  }
  return Object.freeze({ signatureValid: true, issuerAttested });
}
