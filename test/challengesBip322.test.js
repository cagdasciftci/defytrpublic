import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MemoryChallengeStore, reverifyEvidence, SCHEME_BIP322_SIMPLE, SCHEME_EIP191_SIWE, WalletProofService } from '../src/challenges.js';
import { ErrorCode } from '../src/errors.js';
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
    assert.throws(() => reverifyEvidence({ ...evidence, [field]: value }, expected), e => e instanceof Error && 'code' in e, field);
  }
  assert.throws(() => reverifyEvidence({ ...evidence, scheme: SCHEME_EIP191_SIWE, chainId: 1 }, expected), e => 'code' in e);
  assert.throws(() => reverifyEvidence({ ...evidence, address: w.address.toUpperCase() }, expected), e => 'code' in e);
});

test('BIP-322 network binding: a proof for the mainnet address does not satisfy a testnet challenge for the same key', async () => {
  const { service } = setup();
  const key = new Uint8Array(32).fill(7);
  const main = p2wpkhWallet('bc', key);
  const test3 = p2wpkhWallet('tb', key);
  const mainChallenge = await service.issue(btc(main.address));
  const testChallenge = await service.issue(btc(test3.address));
  // The bare BIP-322 signature is network-agnostic; the signed challenge text is not.
  await assert.rejects(service.verify({ challengeId: testChallenge.challengeId, signature: main.sign(mainChallenge.message) }), code(ErrorCode.SIGNATURE_INVALID));
  assert.equal((await service.verify({ challengeId: testChallenge.challengeId, signature: test3.sign(testChallenge.message) })).network, 'testnet');
});
