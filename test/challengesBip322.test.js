import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MemoryChallengeStore, reverifyEvidence, SCHEME_BIP322_SIMPLE, SCHEME_EIP191_SIWE, WalletProofService } from '../src/challenges.js';
import { ErrorCode } from '../src/errors.js';
import { buildBitcoinChallengeMessage } from '../src/siwe.js';
import { p2trWallet, p2wpkhWallet } from './helpers/btc.js';

const DOMAIN = 'vasp.example';
const VASP = 'demo-vasp';
const KEY = 'k'.repeat(32);
const expected = { domain: DOMAIN, vaspId: VASP };
const code = c => e => e.code === c;

function setup() {
  let now = new Date('2026-11-01T10:00:00.000Z');
  const store = new MemoryChallengeStore();
  const service = new WalletProofService({ store, domain: DOMAIN, vaspId: VASP, clock: () => now, evidenceKey: KEY });
  return { service, store, advance: ms => (now = new Date(now.getTime() + ms)) };
}

const btc = (address, extra = {}) => ({ scheme: SCHEME_BIP322_SIMPLE, address, transferReference: 'transfer-btc-1', direction: 'inbound', ...extra });

for (const [name, makeWallet] of [
  ['P2WPKH', p2wpkhWallet],
  ['P2TR', p2trWallet],
]) {
  test(`${name}: issue → BIP-322 sign → sealed evidence that re-verifies offline`, async () => {
    const { service } = setup();
    const w = makeWallet();
    const { challengeId, message } = await service.issue(btc(w.address.toUpperCase()));
    assert.match(message, /^vasp\.example wants you to prove control of this Bitcoin address:\nbc1/);
    assert.match(message, /\nNetwork: bitcoin:mainnet\n/);
    assert.ok(!message.includes('Chain ID'));

    const evidence = await service.verify({ challengeId, signature: w.sign(message) });
    assert.equal(evidence.scheme, SCHEME_BIP322_SIMPLE);
    assert.equal(evidence.address, w.address);
    assert.equal(evidence.network, 'mainnet');
    assert.equal(evidence.chainId, undefined);
    assert.equal(evidence.direction, 'inbound');
    assert.deepEqual({ ...reverifyEvidence(evidence, { ...expected, evidenceKey: KEY }) }, { signatureValid: true, issuerAttested: true });

    await assert.rejects(service.verify({ challengeId, signature: w.sign(message) }), code(ErrorCode.CHALLENGE_CONSUMED));
  });
}

test('BIP-322: a bad signature does not burn the challenge; another key is rejected', async () => {
  const { service } = setup();
  const w = p2wpkhWallet();
  const { challengeId, message } = await service.issue(btc(w.address));
  await assert.rejects(service.verify({ challengeId, signature: p2wpkhWallet().sign(message) }), code(ErrorCode.ADDRESS_MISMATCH));
  await assert.rejects(service.verify({ challengeId, signature: w.sign(`${message} `) }), code(ErrorCode.SIGNATURE_INVALID));
  await assert.rejects(service.verify({ challengeId, signature: 'smpAA==' }), code(ErrorCode.SIGNATURE_MALFORMED));
  assert.equal((await service.verify({ challengeId, signature: w.sign(message) })).result, 'verified');
});

test('BIP-322: expiry applies exactly as for EVM', async () => {
  const { service, advance } = setup();
  const w = p2trWallet();
  const { challengeId, message } = await service.issue(btc(w.address));
  advance(10 * 60 * 1000);
  await assert.rejects(service.verify({ challengeId, signature: w.sign(message) }), code(ErrorCode.CHALLENGE_EXPIRED));
});

test('BIP-322 issue: network comes from the address; mismatch, legacy and unsupported types are rejected', async () => {
  const { service } = setup();
  const testnet = p2wpkhWallet('tb');
  const { message } = await service.issue(btc(testnet.address));
  assert.match(message, /\nNetwork: bitcoin:testnet\n/);
  await assert.rejects(service.issue(btc(testnet.address, { network: 'mainnet' })), code(ErrorCode.INVALID_CHALLENGE_INPUT));
  await assert.rejects(service.issue(btc('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')), code(ErrorCode.SCHEME_UNSUPPORTED));
  await assert.rejects(service.issue(btc('bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9')), code(ErrorCode.SCHEME_UNSUPPORTED)); // P2WSH
  await assert.rejects(service.issue(btc('bc1qnotanaddress')), code(ErrorCode.ADDRESS_INVALID));
  await assert.rejects(service.issue({ ...btc(testnet.address), scheme: 'bip322-full' }), code(ErrorCode.SCHEME_UNSUPPORTED));
});

test('BIP-322 evidence: editing any bound field, or switching scheme, is detected', async () => {
  const { service } = setup();
  const w = p2wpkhWallet();
  const { challengeId, message } = await service.issue(btc(w.address));
  const evidence = await service.verify({ challengeId, signature: w.sign(message) });
  const edits = {
    address: p2wpkhWallet().address,
    network: 'testnet',
    transferReference: 'transfer-btc-2',
    direction: 'outbound',
    nonce: 'ZZZZZZZZZZZZZZZZZZZZZZ',
    message: evidence.message.replace('inbound', 'outbound'),
  };
  for (const [field, value] of Object.entries(edits)) {
    assert.throws(() => reverifyEvidence({ ...evidence, [field]: value }, expected), code(ErrorCode.EVIDENCE_MISMATCH), field);
  }
  assert.throws(() => reverifyEvidence({ ...evidence, scheme: SCHEME_EIP191_SIWE, chainId: 1 }, expected), code(ErrorCode.EVIDENCE_MISMATCH));
  assert.throws(() => reverifyEvidence({ ...evidence, address: w.address.toUpperCase() }, expected), code(ErrorCode.EVIDENCE_MISMATCH));
});

test('BIP-322 network binding: the Network line is signed; the same text with another network is rejected', async () => {
  const { service } = setup();
  const w = p2wpkhWallet('tb');
  const { challengeId, message } = await service.issue(btc(w.address));
  // Same key, same address, same nonce and request id: only the network line differs.
  const otherNetwork = message.replace('Network: bitcoin:testnet', 'Network: bitcoin:mainnet');
  assert.notEqual(otherNetwork, message);
  await assert.rejects(service.verify({ challengeId, signature: w.sign(otherNetwork) }), code(ErrorCode.SIGNATURE_INVALID));
  assert.equal((await service.verify({ challengeId, signature: w.sign(message) })).network, 'testnet');
});

test('Bitcoin challenge text refuses a network that contradicts the address prefix', () => {
  const fields = {
    domain: DOMAIN,
    address: p2wpkhWallet('bc').address,
    network: 'testnet',
    nonce: 'AbCdEf0123456789XyZ012',
    issuedAt: new Date('2026-11-01T10:00:00.000Z'),
    expirationTime: new Date('2026-11-01T10:10:00.000Z'),
    requestId: '11111111-1111-4111-8111-111111111111',
    vaspId: VASP,
    transferReference: 'transfer-btc-1',
    direction: 'inbound',
  };
  assert.throws(() => buildBitcoinChallengeMessage(fields), code(ErrorCode.INVALID_CHALLENGE_INPUT));
  assert.match(buildBitcoinChallengeMessage({ ...fields, network: 'mainnet' }), /Network: bitcoin:mainnet/);
});
