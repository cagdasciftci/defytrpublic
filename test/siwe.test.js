import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ErrorCode } from '../src/errors.js';
import { generateNonce, isValidNonce, MIN_NONCE_LENGTH } from '../src/nonce.js';
import { buildSiweMessage, STATEMENT } from '../src/siwe.js';

const base = () => ({
  domain: 'vasp.example',
  address: '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  chainId: 1,
  nonce: 'AbCdEf0123456789Xy',
  issuedAt: new Date('2026-11-01T10:00:00.000Z'),
  expirationTime: new Date('2026-11-01T10:10:00.000Z'),
  requestId: '3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90',
  vaspId: 'defy-demo-vasp',
  transferReference: 'transfer-001',
  direction: 'outbound',
});

test('renders the exact EIP-4361 message with Travel Rule bindings', () => {
  const expected = [
    'vasp.example wants you to sign in with your Ethereum account:',
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '',
    STATEMENT,
    '',
    'URI: https://vasp.example/travel-rule/wallet-proof',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: AbCdEf0123456789Xy',
    'Issued At: 2026-11-01T10:00:00.000Z',
    'Expiration Time: 2026-11-01T10:10:00.000Z',
    'Request ID: 3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90',
    'Resources:',
    '- urn:travel-rule:vasp:defy-demo-vasp',
    '- urn:travel-rule:transfer:transfer-001',
    '- urn:travel-rule:direction:outbound',
  ].join('\n');
  assert.equal(buildSiweMessage(base()), expected);
});

test('every binding field changes the signed text (T4 domain separation)', () => {
  const original = buildSiweMessage(base());
  const variants = {
    domain: 'other-vasp.example',
    address: '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    chainId: 137,
    nonce: 'ZZZZZZZZZZZZZZZZZZ',
    requestId: '00000000-0000-4000-8000-000000000000',
    vaspId: 'another-vasp',
    transferReference: 'transfer-002',
    direction: 'inbound',
    expirationTime: new Date('2026-11-01T10:20:00.000Z'),
  };
  for (const [field, value] of Object.entries(variants)) {
    assert.notEqual(buildSiweMessage({ ...base(), [field]: value }), original, `${field} must be bound`);
  }
});

test('rejects invalid or injection-prone fields with a typed error', () => {
  const bad = {
    domain: 'evil.example\nURI: https://attacker',
    address: '0x123',
    chainId: 0,
    nonce: 'short',
    requestId: 'not-a-uuid',
    vaspId: 'has space',
    transferReference: 'line\nbreak',
    direction: 'sideways',
    issuedAt: new Date('invalid'),
    expirationTime: new Date('2026-11-01T09:00:00.000Z'),
  };
  for (const [field, value] of Object.entries(bad)) {
    assert.throws(
      () => buildSiweMessage({ ...base(), [field]: value }),
      (err) => err.code === ErrorCode.INVALID_CHALLENGE_INPUT,
      `${field} should be rejected`,
    );
  }
});

test('nonces are long, alphanumeric and unique', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i += 1) {
    const n = generateNonce();
    assert.ok(isValidNonce(n));
    seen.add(n);
  }
  assert.equal(seen.size, 1000);
  assert.throws(() => generateNonce(MIN_NONCE_LENGTH - 1), RangeError);
  assert.equal(isValidNonce('abc!defghijklmnop'), false);
});
