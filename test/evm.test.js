import assert from 'node:assert/strict';
import { test } from 'node:test';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ErrorCode } from '../src/errors.js';
import {
  hashPersonalMessage,
  parseSignature,
  recoverPersonalSigner,
  toChecksumAddress,
  verifyPersonalSignature,
} from '../src/evm.js';

// Independent vector: web3.js documentation, `web3.eth.accounts.sign('Some data', privateKey)`.
const WEB3_DOC = {
  privateKey: '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  address: '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23',
  message: 'Some data',
  messageHash: '0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655',
  signature:
    '0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c',
};

const N = secp256k1.CURVE.n;

function signPersonal(privateKeyHex, message) {
  const sig = secp256k1.sign(hashPersonalMessage(message), hexToBytes(privateKeyHex.slice(2)), { lowS: true });
  return `0x${bytesToHex(sig.toCompactRawBytes())}${(27 + sig.recovery).toString(16)}`;
}

function setByte(signatureHex, index, value) {
  const bytes = hexToBytes(signatureHex.slice(2));
  bytes[index] = value;
  return `0x${bytesToHex(bytes)}`;
}

test('EIP-55 checksum matches the EIP test cases', () => {
  for (const a of [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ]) {
    assert.equal(toChecksumAddress(a.toLowerCase()), a);
  }
});

test('EIP-191 digest and signer match an independent published vector', () => {
  assert.equal(`0x${bytesToHex(hashPersonalMessage(WEB3_DOC.message))}`, WEB3_DOC.messageHash);
  assert.equal(recoverPersonalSigner(WEB3_DOC.message, WEB3_DOC.signature), WEB3_DOC.address);
  assert.equal(
    verifyPersonalSignature({ message: WEB3_DOC.message, signature: WEB3_DOC.signature, expectedAddress: WEB3_DOC.address.toLowerCase() }),
    WEB3_DOC.address,
  );
});

// Produced by tools/independent_vectors.py (pure-Python Keccak + secp256k1, no shared code).
// The message is 20 JS characters but 27 UTF-8 bytes; the EIP-191 prefix must say "\n27".
const NON_ASCII = {
  message: 'Çağdaş — ödeme değil',
  digest: '0x648580b6087ef9dbde310b222c649633ac878271c337ce518961b467fd61634e',
  signature:
    '0x92d56912d658bdcf634cdd39cddcd487d0c62ba2582d67160f8fd8fa79d38bc94bc0ff9a10ae04d62d0a144d299a614a70300a186ba4fcd5fde94205331ab4911c',
};

test('message length is the UTF-8 byte length, not the JS string length (independent vector)', () => {
  assert.equal(NON_ASCII.message.length, 20);
  assert.equal(`0x${bytesToHex(hashPersonalMessage(NON_ASCII.message))}`, NON_ASCII.digest);
  assert.equal(recoverPersonalSigner(NON_ASCII.message, NON_ASCII.signature), WEB3_DOC.address);
});

// Further published vectors (research/test-vectors.md §3), each re-checked with tools/independent_vectors.py.
const PUBLISHED = [
  {
    source: 'ethers.js v5 docs, Wallet examples',
    privateKey: '0x1da6847600b0ee25e9ad9a52abbd786dd2502fa4005dd5af9310b7cc7a3b25db',
    address: '0x71CB05EE1b1F506fF321Da3dac38f25c0c9ce6E1',
    message: 'Hello World',
    digest: '0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2',
    signature:
      '0x14280e5885a19f60e536de50097e96e3738c7acae4e9e62d67272d794b8127d31c03d9cd59781d4ee31fb4e1b893bd9b020ec67dfa65cfb51e2bdadbb1de26d91c',
  },
  {
    source: 'viem docs, signMessage',
    privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    message: 'hello world',
    signature:
      '0xa461f509887bd19e312c0c58467ce8ff8e300d3c1a90b608a760c5b80318eaf15fe57c96f9175d6cd4daad4663763baa7e78836e067d0163e9a2ccf2ff753f5b1b',
  },
];

test('recovers the signer of further independently published EIP-191 vectors', () => {
  for (const v of PUBLISHED) {
    if (v.digest) assert.equal(`0x${bytesToHex(hashPersonalMessage(v.message))}`, v.digest, v.source);
    const pub = secp256k1.getPublicKey(hexToBytes(v.privateKey.slice(2)), false);
    assert.equal(toChecksumAddress(`0x${bytesToHex(keccak_256(pub.subarray(1)).subarray(12))}`), v.address, `${v.source}: key → address`);
    assert.equal(recoverPersonalSigner(v.message, v.signature), v.address, v.source);
  }
});

test('accepts v as 27/28 and 0/1 for the same signature', () => {
  const v = hexToBytes(WEB3_DOC.signature.slice(2))[64];
  const alt = setByte(WEB3_DOC.signature, 64, v - 27);
  assert.equal(recoverPersonalSigner(WEB3_DOC.message, alt), WEB3_DOC.address);
});

test('T3: a signature from another key is ADDRESS_MISMATCH', () => {
  const otherKey = `0x${bytesToHex(secp256k1.utils.randomPrivateKey())}`;
  const signature = signPersonal(otherKey, WEB3_DOC.message);
  assert.throws(
    () => verifyPersonalSignature({ message: WEB3_DOC.message, signature, expectedAddress: WEB3_DOC.address }),
    (e) => e.code === ErrorCode.ADDRESS_MISMATCH,
  );
});

test('T8: any change to the message breaks verification', () => {
  for (const tampered of ['Some data ', 'some data', 'Some dat', 'Some data']) {
    assert.throws(
      () => verifyPersonalSignature({ message: tampered, signature: WEB3_DOC.signature, expectedAddress: WEB3_DOC.address }),
      (e) => e.code === ErrorCode.ADDRESS_MISMATCH || e.code === ErrorCode.SIGNATURE_MALFORMED,
    );
  }
});

test('T6: the malleable high-s twin of a valid signature is rejected', () => {
  const bytes = hexToBytes(WEB3_DOC.signature.slice(2));
  const s = BigInt(`0x${bytesToHex(bytes.subarray(32, 64))}`);
  const highS = (N - s).toString(16).padStart(64, '0');
  const flippedV = bytes[64] === 27 ? 28 : 27;
  const twin = `0x${bytesToHex(bytes.subarray(0, 32))}${highS}${flippedV.toString(16)}`;
  assert.throws(() => parseSignature(twin), (e) => e.code === ErrorCode.SIGNATURE_NON_CANONICAL);
});

test('T7: malformed signatures are rejected with SIGNATURE_MALFORMED', () => {
  const zeroR = `0x${'00'.repeat(32)}${WEB3_DOC.signature.slice(66)}`;
  const rEqualsN = `0x${N.toString(16).padStart(64, '0')}${WEB3_DOC.signature.slice(66)}`;
  const cases = [
    WEB3_DOC.signature.slice(0, -2), // 64 bytes
    `${WEB3_DOC.signature}00`, // 66 bytes
    WEB3_DOC.signature.slice(2), // no 0x
    `0x${'zz'.repeat(65)}`,
    setByte(WEB3_DOC.signature, 64, 29),
    setByte(WEB3_DOC.signature, 64, 2),
    zeroR,
    rEqualsN,
    null,
    12345,
  ];
  for (const signature of cases) {
    assert.throws(() => parseSignature(signature), (e) => e.code === ErrorCode.SIGNATURE_MALFORMED, String(signature));
  }
});

const REJECTION_CODES = new Set([ErrorCode.ADDRESS_MISMATCH, ErrorCode.SIGNATURE_MALFORMED, ErrorCode.SIGNATURE_NON_CANONICAL]);

test('property: random keys round-trip; a flipped bit in any signature byte or in the message fails', () => {
  for (let i = 0; i < 65; i += 1) {
    const key = secp256k1.utils.randomPrivateKey();
    // Address derived without the code under test: keccak(uncompressed pubkey)[12:].
    const pub = secp256k1.getPublicKey(key, false);
    const address = toChecksumAddress(`0x${bytesToHex(keccak_256(pub.subarray(1)).subarray(12))}`);
    const message = `transfer-${i}-${bytesToHex(key).slice(0, 8)}`;
    const signature = signPersonal(`0x${bytesToHex(key)}`, message);
    assert.equal(verifyPersonalSignature({ message, signature, expectedAddress: address }), address);

    const sigBytes = hexToBytes(signature.slice(2));
    sigBytes[i] ^= 1 << (i % 8); // every byte position 0..64, including v
    assert.throws(
      () => verifyPersonalSignature({ message, signature: `0x${bytesToHex(sigBytes)}`, expectedAddress: address }),
      (e) => REJECTION_CODES.has(e.code),
      `flip in signature byte ${i}`,
    );

    const msgChars = [...message];
    const pos = i % msgChars.length;
    msgChars[pos] = String.fromCharCode(msgChars[pos].charCodeAt(0) ^ 1);
    assert.throws(
      () => verifyPersonalSignature({ message: msgChars.join(''), signature, expectedAddress: address }),
      (e) => REJECTION_CODES.has(e.code),
      `flip in message char ${pos}`,
    );
  }
});
