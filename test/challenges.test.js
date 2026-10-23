import assert from 'node:assert/strict';
import { test } from 'node:test';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { MemoryChallengeStore, reverifyEvidence, WalletProofService } from '../src/challenges.js';
import { ErrorCode } from '../src/errors.js';
import { hashPersonalMessage, toChecksumAddress } from '../src/evm.js';
import { buildSiweMessage } from '../src/siwe.js';
import { runStoreConformance } from '../src/storeConformance.js';

const DOMAIN = 'vasp.example';
const VASP = 'demo-vasp';

// Address derived independently of the code under test (no recovery involved).
function wallet() {
  const key = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(key, false);
  const address = toChecksumAddress(`0x${bytesToHex(keccak_256(pub.subarray(1)).subarray(12))}`);
  const sign = (message) => {
    const sig = secp256k1.sign(hashPersonalMessage(message), key, { lowS: true });
    return `0x${bytesToHex(sig.toCompactRawBytes())}${(27 + sig.recovery).toString(16)}`;
  };
  return { address, sign };
}

function setup({ start = '2026-11-01T10:00:00.000Z', store = new MemoryChallengeStore(), domain = DOMAIN, vaspId = VASP } = {}) {
  let now = new Date(start);
  const clock = { now: () => now, advance: (ms) => (now = new Date(now.getTime() + ms)) };
  const service = new WalletProofService({ store, domain, vaspId, clock: clock.now });
  return { service, clock, store };
}

const transfer = (address, extra = {}) => ({ address, chainId: 1, transferReference: 'transfer-001', direction: 'outbound', ...extra });
const code = (c) => (e) => e.code === c;
const expected = { domain: DOMAIN, vaspId: VASP };
const EVIDENCE_KEY = 'k'.repeat(32);

async function verified() {
  const { service } = setup();
  const w = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address));
  return { evidence: await service.verify({ challengeId, signature: w.sign(message) }), w };
}

test('happy path: issue → wallet signs → verified evidence record', async () => {
  const { service } = setup();
  const w = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address.toLowerCase()));
  assert.match(message, /^vasp\.example wants you to sign in with your Ethereum account:\n0x/);
  const evidence = await service.verify({ challengeId, signature: w.sign(message) });
  assert.equal(evidence.result, 'verified');
  assert.equal(evidence.claim, 'control');
  assert.equal(evidence.provenance, 'self_hosted_verifier');
  assert.equal(evidence.address, w.address);
  assert.equal(evidence.domain, DOMAIN);
  assert.equal(evidence.vaspId, VASP);
  assert.equal(evidence.transferReference, 'transfer-001');
  assert.ok(Object.isFrozen(evidence));
});

test('T2: the same challenge cannot be verified twice', async () => {
  const { service } = setup();
  const w = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address));
  const signature = w.sign(message);
  await service.verify({ challengeId, signature });
  await assert.rejects(service.verify({ challengeId, signature }), code(ErrorCode.CHALLENGE_CONSUMED));
});

test('T9: concurrent verifications of one challenge — exactly one wins', async () => {
  const { service } = setup();
  const w = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address));
  const signature = w.sign(message);
  const results = await Promise.allSettled(Array.from({ length: 10 }, () => service.verify({ challengeId, signature })));
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.ok(results.filter((r) => r.status === 'rejected').every((r) => r.reason.code === ErrorCode.CHALLENGE_CONSUMED));
});

test('a bad signature does not burn the challenge', async () => {
  const { service } = setup();
  const w = wallet();
  const attacker = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address));
  await assert.rejects(service.verify({ challengeId, signature: attacker.sign(message) }), code(ErrorCode.ADDRESS_MISMATCH));
  const evidence = await service.verify({ challengeId, signature: w.sign(message) });
  assert.equal(evidence.result, 'verified');
});

test('T5: expired, not-yet-valid and unknown challenges are rejected', async () => {
  const { service, clock } = setup();
  const w = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address));
  const signature = w.sign(message);

  clock.advance(-2 * 60 * 1000); // client clock far behind issue time (beyond 60 s skew)
  await assert.rejects(service.verify({ challengeId, signature }), code(ErrorCode.CHALLENGE_NOT_YET_VALID));
  clock.advance(2 * 60 * 1000 + 10 * 60 * 1000);
  await assert.rejects(service.verify({ challengeId, signature }), code(ErrorCode.CHALLENGE_EXPIRED));
  await assert.rejects(service.verify({ challengeId: '00000000-0000-4000-8000-000000000000', signature }), code(ErrorCode.CHALLENGE_NOT_FOUND));
});

test('T5: a challenge that expires between get and consume is not consumed', async () => {
  let clock;
  class SlowStore extends MemoryChallengeStore {
    async consume(id, now) {
      clock.advance(10 * 60 * 1000); // store latency pushes past expiry
      return super.consume(id, clock.now());
    }
  }
  const ctx = setup({ store: new SlowStore() });
  clock = ctx.clock;
  const w = wallet();
  const { challengeId, message } = await ctx.service.issue(transfer(w.address));
  clock.advance(9 * 60 * 1000);
  await assert.rejects(ctx.service.verify({ challengeId, signature: w.sign(message) }), code(ErrorCode.CHALLENGE_EXPIRED));
  assert.equal((await ctx.store.get(challengeId)).state, 'issued');
});

test('T4: a signature for one transfer/chain/direction/domain does not verify another challenge', async () => {
  const { service } = setup();
  const w = wallet();
  const first = await service.issue(transfer(w.address));
  const signatureForFirst = w.sign(first.message);
  for (const extra of [{ transferReference: 'transfer-002' }, { chainId: 137 }, { direction: 'inbound' }]) {
    const other = await service.issue(transfer(w.address, extra));
    await assert.rejects(service.verify({ challengeId: other.challengeId, signature: signatureForFirst }), code(ErrorCode.ADDRESS_MISMATCH));
  }
  const otherVasp = setup({ domain: 'other.example' }).service;
  const foreign = await otherVasp.issue(transfer(w.address));
  await assert.rejects(otherVasp.verify({ challengeId: foreign.challengeId, signature: signatureForFirst }), code(ErrorCode.ADDRESS_MISMATCH));
});

test('tenant isolation: a service cannot verify another VASP\'s challenge in a shared store', async () => {
  const store = new MemoryChallengeStore();
  const a = setup({ store, vaspId: 'vasp-a' }).service;
  const b = setup({ store, vaspId: 'vasp-b' }).service;
  const w = wallet();
  const { challengeId, message } = await a.issue(transfer(w.address));
  await assert.rejects(b.verify({ challengeId, signature: w.sign(message) }), code(ErrorCode.CHALLENGE_NOT_FOUND));
  assert.equal((await a.verify({ challengeId, signature: w.sign(message) })).vaspId, 'vasp-a');
});

test('T8: a client cannot substitute its own message — the server re-renders it', async () => {
  const { service } = setup();
  const w = wallet();
  const { challengeId } = await service.issue(transfer(w.address));
  const forged = 'I agree to anything';
  await assert.rejects(service.verify({ challengeId, signature: w.sign(forged), message: forged }), code(ErrorCode.ADDRESS_MISMATCH));
});

test('T11: contract-wallet signatures fail closed as SCHEME_UNSUPPORTED and do not burn the challenge', async () => {
  const { service, store } = setup();
  const w = wallet();
  const { challengeId } = await service.issue(transfer(w.address));
  const erc6492Like = `0x${'ab'.repeat(200)}6492649264926492649264926492649264926492649264926492649264926492`;
  await assert.rejects(service.verify({ challengeId, signature: erc6492Like }), code(ErrorCode.SCHEME_UNSUPPORTED));
  assert.equal((await store.get(challengeId)).state, 'issued');
});

test('unknown schemes and corrupt stored timestamps fail closed', async () => {
  const store = new MemoryChallengeStore();
  const { service } = setup({ store });
  const w = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address));
  const original = store.get.bind(store);
  store.get = async (id) => ({ ...(await original(id)), scheme: 'bip322' });
  await assert.rejects(service.verify({ challengeId, signature: w.sign(message) }), code(ErrorCode.SCHEME_UNSUPPORTED));
  store.get = async (id) => ({ ...(await original(id)), expirationTime: 'not a date' });
  await assert.rejects(service.verify({ challengeId, signature: w.sign(message) }), code(ErrorCode.INVALID_CHALLENGE_INPUT));
});

test('T13: an evidence record re-verifies offline for the expected VASP', async () => {
  const { evidence } = await verified();
  assert.deepEqual({ ...reverifyEvidence(evidence, expected) }, { signatureValid: true, issuerAttested: false });
  assert.throws(() => reverifyEvidence(evidence, { domain: 'other.example', vaspId: VASP }), code(ErrorCode.EVIDENCE_MISMATCH));
  assert.throws(() => reverifyEvidence(evidence, { domain: DOMAIN, vaspId: 'other' }), code(ErrorCode.EVIDENCE_MISMATCH));
  assert.throws(() => reverifyEvidence({ ...evidence, scheme: 'bip322' }, expected), code(ErrorCode.SCHEME_UNSUPPORTED));
  assert.throws(() => reverifyEvidence(evidence), TypeError);
});

test('T13: editing ANY bound field of an evidence record is detected (not only the message)', async () => {
  const { evidence } = await verified();
  const edits = {
    transferReference: 'transfer-999',
    chainId: 137,
    direction: 'inbound',
    challengeId: '00000000-0000-4000-8000-000000000000',
    nonce: 'ZZZZZZZZZZZZZZZZZZZZZZ',
    issuedAt: '2026-11-01T09:00:00.000Z',
    expirationTime: '2026-12-01T10:10:00.000Z',
    address: wallet().address,
    message: evidence.message.replace('transfer-001', 'transfer-999'),
  };
  for (const [field, value] of Object.entries(edits)) {
    assert.throws(() => reverifyEvidence({ ...evidence, [field]: value }, expected), (e) => e.code === ErrorCode.EVIDENCE_MISMATCH, field);
  }
});

function selfSigned(attacker, domain, vaspId) {
  const fields = {
    domain,
    vaspId,
    address: attacker.address,
    chainId: 1,
    transferReference: 'transfer-001',
    direction: 'outbound',
    challengeId: '11111111-1111-4111-8111-111111111111',
    nonce: 'AbCdEf0123456789XyZ012',
    issuedAt: '2026-11-01T10:00:00.000Z',
    expirationTime: '2026-11-01T10:10:00.000Z',
  };
  const message = buildSiweMessage({ ...fields, requestId: fields.challengeId, issuedAt: new Date(fields.issuedAt), expirationTime: new Date(fields.expirationTime) });
  return { schema: 'wallet-ownership-proof/evidence@1', claim: 'control', result: 'verified', scheme: 'eip191-siwe', provenance: 'self_hosted_verifier', ...fields, message, signature: attacker.sign(message) };
}

test('T13: a self-signed record for a foreign domain is rejected', () => {
  assert.throws(() => reverifyEvidence(selfSigned(wallet(), 'attacker.example', 'attacker'), expected), code(ErrorCode.EVIDENCE_MISMATCH));
});

test('T13 limit: a self-signed record naming the expected VASP has a valid signature but is NOT issuer-attested', () => {
  const forged = selfSigned(wallet(), DOMAIN, VASP);
  // Documented limit: without a seal, offline re-verification only proves that key signed this text.
  assert.deepEqual({ ...reverifyEvidence(forged, expected) }, { signatureValid: true, issuerAttested: false });
  assert.throws(() => reverifyEvidence(forged, { ...expected, evidenceKey: EVIDENCE_KEY }), code(ErrorCode.EVIDENCE_SEAL_INVALID));
});


test('sealed evidence: issuer-attested offline; any change to a field or the seal is detected', async () => {
  const { service } = setup({ store: new MemoryChallengeStore() });
  const sealing = new WalletProofService({ store: new MemoryChallengeStore(), domain: DOMAIN, vaspId: VASP, evidenceKey: EVIDENCE_KEY, evidenceKeyId: 'k1' });
  const w = wallet();
  const { challengeId, message } = await sealing.issue(transfer(w.address));
  const evidence = await sealing.verify({ challengeId, signature: w.sign(message) });
  assert.equal(evidence.sealKeyId, 'k1');
  assert.match(evidence.seal, /^[0-9a-f]{64}$/);
  assert.deepEqual({ ...reverifyEvidence(evidence, { ...expected, evidenceKey: EVIDENCE_KEY }) }, { signatureValid: true, issuerAttested: true });
  assert.throws(() => reverifyEvidence(evidence, { ...expected, evidenceKey: 'x'.repeat(32) }), code(ErrorCode.EVIDENCE_SEAL_INVALID));
  assert.throws(() => reverifyEvidence({ ...evidence, verifiedAt: '2027-01-01T00:00:00.000Z' }, { ...expected, evidenceKey: EVIDENCE_KEY }), code(ErrorCode.EVIDENCE_SEAL_INVALID));
  assert.throws(() => reverifyEvidence({ ...evidence, seal: '00'.repeat(32) }, { ...expected, evidenceKey: EVIDENCE_KEY }), code(ErrorCode.EVIDENCE_SEAL_INVALID));
  assert.throws(() => reverifyEvidence({ ...evidence, seal: undefined }, { ...expected, evidenceKey: EVIDENCE_KEY }), code(ErrorCode.EVIDENCE_SEAL_INVALID));
  assert.throws(() => new WalletProofService({ store: new MemoryChallengeStore(), domain: DOMAIN, vaspId: VASP, evidenceKey: 'short' }), TypeError);
  void service;
});

test('signature shape: Safe-style multi-owner and ERC-6492 are unsupported; other odd lengths are malformed', async () => {
  const { service } = setup();
  const w = wallet();
  const { challengeId, message } = await service.issue(transfer(w.address));
  const one = w.sign(message);
  const safeTwoOwners = `${one}${one.slice(2)}`;
  await assert.rejects(service.verify({ challengeId, signature: safeTwoOwners }), code(ErrorCode.SCHEME_UNSUPPORTED));
  await assert.rejects(service.verify({ challengeId, signature: `${one}00` }), code(ErrorCode.SIGNATURE_MALFORMED));
});

test('MemoryChallengeStore passes the store conformance suite', async () => {
  await runStoreConformance(() => new MemoryChallengeStore());
});
