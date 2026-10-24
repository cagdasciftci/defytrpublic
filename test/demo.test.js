import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { createDemoServer } from '../examples/demo/server.js';
import { hashPersonalMessage, toChecksumAddress } from '../src/evm.js';
import { p2trWallet } from './helpers/btc.js';

const port = 20000 + Math.floor(Math.random() * 20000);
let server;
before(() => new Promise(resolve => (server = createDemoServer({ port }).listen(port, '127.0.0.1', resolve))));
after(() => new Promise(resolve => server.close(resolve)));

const post = async (path, body) => {
  const r = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  return { status: r.status, data: await r.json() };
};

test('demo: EVM flow end to end over HTTP, with the EU requirement', async () => {
  const key = secp256k1.utils.randomPrivateKey();
  const address = toChecksumAddress(`0x${bytesToHex(keccak_256(secp256k1.getPublicKey(key, false).subarray(1)).subarray(12))}`);
  const c = await post('/api/challenges', { scheme: 'eip191-siwe', address, chainId: 11155111, jurisdiction: 'EU', amount: '1250', currency: 'EUR', direction: 'outbound' });
  assert.equal(c.status, 200);
  assert.equal(c.data.requirement.requirement, 'control_assessment');
  assert.match(c.data.message, new RegExp(`^localhost:${port} wants you to sign in`));
  const sig = secp256k1.sign(hashPersonalMessage(c.data.message), key, { lowS: true });
  const signature = `0x${bytesToHex(sig.toCompactRawBytes())}${(27 + sig.recovery).toString(16)}`;
  const v = await post('/api/verify', { challengeId: c.data.challengeId, signature });
  assert.equal(v.status, 200);
  assert.equal(v.data.evidence.result, 'verified');
  assert.deepEqual(v.data.offline, { signatureValid: true, issuerAttested: true });
  const again = await post('/api/verify', { challengeId: c.data.challengeId, signature });
  assert.deepEqual([again.status, again.data.code], [422, 'CHALLENGE_CONSUMED']);
});

test('demo: Bitcoin P2TR flow with the TR requirement', async () => {
  const w = p2trWallet('tb');
  const c = await post('/api/challenges', { scheme: 'bip322-simple', address: w.address, jurisdiction: 'TR', amount: '50000', currency: 'TRY' });
  assert.equal(c.data.requirement.requirement, 'declaration');
  const v = await post('/api/verify', { challengeId: c.data.challengeId, signature: w.sign(c.data.message) });
  assert.equal(v.data.evidence.network, 'testnet');
});

test('demo: typed errors, bad JSON and unknown routes', async () => {
  assert.equal((await post('/api/challenges', { scheme: 'eip191-siwe', address: '0x00', chainId: 1, jurisdiction: 'XX' })).data.code, 'INVALID_POLICY_INPUT');
  assert.equal((await post('/api/challenges', '{not json')).status, 400);
  assert.equal((await post('/api/challenges', '[]')).data.code, 'INVALID_POLICY_INPUT');
  assert.equal((await post('/api/nope', {})).status, 404);
  const page = await fetch(`http://127.0.0.1:${port}/`);
  assert.match(await page.text(), /Self-hosted wallet control proof/);
});
