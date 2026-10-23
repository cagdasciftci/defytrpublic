import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { ErrorCode, ProofError } from './errors.js';

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE_RE = /^0x[0-9a-fA-F]{130}$/;
const N = secp256k1.CURVE.n;
const HALF_N = N >> 1n;
const SIGNATURE_BYTES = 65;

const ERC6492_MAGIC = '6492649264926492649264926492649264926492649264926492649264926492';

/**
 * Recognise contract-wallet signature shapes so they fail as SCHEME_UNSUPPORTED rather than MALFORMED:
 * an ERC-6492 wrapper (32-byte magic suffix) or concatenated multi-owner signatures (n × 65 bytes, n ≥ 2,
 * as produced by Safe). Any other non-65-byte input is simply malformed.
 */
export function isContractWalletSignature(signature) {
  if (typeof signature !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(signature)) return false;
  const bytes = (signature.length - 2) / 2;
  if (bytes <= SIGNATURE_BYTES) return false;
  return signature.toLowerCase().endsWith(ERC6492_MAGIC) || bytes % SIGNATURE_BYTES === 0;
}

/** EIP-55 mixed-case checksum. Throws on anything that is not a 20-byte hex address. */
export function toChecksumAddress(address) {
  if (typeof address !== 'string' || !ADDRESS_RE.test(address)) {
    throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, 'invalid EVM address');
  }
  const lower = address.slice(2).toLowerCase();
  const hash = bytesToHex(keccak_256(utf8ToBytes(lower)));
  let out = '0x';
  for (let i = 0; i < 40; i += 1) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/** EIP-191 version 0x45 ("personal_sign") digest. Length is the UTF-8 byte length. */
export function hashPersonalMessage(message) {
  if (typeof message !== 'string') {
    throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, 'message must be a string');
  }
  const body = utf8ToBytes(message);
  const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${body.length}`);
  const data = new Uint8Array(prefix.length + body.length);
  data.set(prefix, 0);
  data.set(body, prefix.length);
  return keccak_256(data);
}

/** Address = last 20 bytes of keccak-256 over the 64-byte uncompressed public key (no 0x04 prefix). */
function publicKeyToAddress(point) {
  const uncompressed = point.toRawBytes(false);
  return `0x${bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(12))}`;
}

/**
 * Parse a 65-byte `r‖s‖v` signature (SPEC §4 steps 5–6).
 * Rejects wrong length, v outside {0,1,27,28}, r/s out of range and high-s (malleability, T6).
 */
export function parseSignature(signature) {
  if (typeof signature !== 'string' || !SIGNATURE_RE.test(signature)) {
    throw new ProofError(ErrorCode.SIGNATURE_MALFORMED, 'signature must be 0x-prefixed 65-byte hex');
  }
  const bytes = hexToBytes(signature.slice(2));
  const v = bytes[64];
  let recovery;
  if (v === 27 || v === 28) recovery = v - 27;
  else if (v === 0 || v === 1) recovery = v;
  else throw new ProofError(ErrorCode.SIGNATURE_MALFORMED, 'unsupported recovery byte');

  // Explicit range check instead of relying on library internals: 1 ≤ r, s < n.
  const r = BigInt(`0x${bytesToHex(bytes.subarray(0, 32))}`);
  const s = BigInt(`0x${bytesToHex(bytes.subarray(32, 64))}`);
  if (r < 1n || r >= N || s < 1n || s >= N) {
    throw new ProofError(ErrorCode.SIGNATURE_MALFORMED, 'r or s out of range');
  }
  if (s > HALF_N) {
    throw new ProofError(ErrorCode.SIGNATURE_NON_CANONICAL, 'high-s signature');
  }
  let sig;
  try {
    sig = secp256k1.Signature.fromCompact(bytes.subarray(0, 64));
  } catch {
    throw new ProofError(ErrorCode.SIGNATURE_MALFORMED, 'invalid signature encoding');
  }
  return sig.addRecoveryBit(recovery);
}

/**
 * Recover the signer of an EIP-191 personal message. Pure function, no I/O.
 * Returns the EIP-55 checksummed address.
 */
export function recoverPersonalSigner(message, signature) {
  const sig = parseSignature(signature);
  const digest = hashPersonalMessage(message);
  let point;
  try {
    point = sig.recoverPublicKey(digest);
  } catch {
    throw new ProofError(ErrorCode.SIGNATURE_MALFORMED, 'public key recovery failed');
  }
  return toChecksumAddress(publicKeyToAddress(point));
}

/**
 * Verify that `signature` over `message` was produced by `expectedAddress` (SPEC §4 steps 5–9).
 * Comparison is on bytes (case-insensitive hex), never on checksum casing.
 */
export function verifyPersonalSignature({ message, signature, expectedAddress }) {
  const expected = toChecksumAddress(expectedAddress);
  const recovered = recoverPersonalSigner(message, signature);
  if (recovered.toLowerCase() !== expected.toLowerCase()) {
    throw new ProofError(ErrorCode.ADDRESS_MISMATCH, 'signature was not produced by the expected address');
  }
  return recovered;
}
