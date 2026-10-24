import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/legacy';
import { sha256 } from '@noble/hashes/sha2';
import { ErrorCode, ProofError } from './errors.js';

/*
 * BIP-322 "simple" signed messages for single-key segwit addresses:
 *   - P2WPKH (bc1q…, 20-byte program), ECDSA, SIGHASH_ALL, BIP-143 sighash
 *   - P2TR key-path (bc1p…), BIP-340 Schnorr, SIGHASH_DEFAULT or SIGHASH_ALL, BIP-341 sighash
 * Everything else fails closed with SCHEME_UNSUPPORTED: legacy (1…/3…) addresses, P2WSH,
 * Taproot script-path spends, and the "full" and "proof of funds" variants (`ful`, `pof` prefixes).
 * Signatures are accepted with the `smp` prefix and without any prefix; the current BIP text allows a
 * verifier to assume the simple variant when no prefix is present.
 */

const N = secp256k1.CURVE.n;
const enc = new TextEncoder();

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const zeros = n => new Uint8Array(n);
const dsha = b => sha256(sha256(b));
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const pushData = b => {
  if (b.length >= 0xfd) throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, 'push too long');
  return concat(Uint8Array.of(b.length), b);
};
const tagCache = new Map();
export function taggedHash(tag, message) {
  let t = tagCache.get(tag);
  if (!t) {
    t = sha256(enc.encode(tag));
    tagCache.set(tag, t);
  }
  return sha256(concat(t, t, message));
}

// ---------- bech32 / bech32m (BIP-173, BIP-350) ----------
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32 = 1;
const BECH32M = 0x2bc830a3;
const HRP_NETWORK = Object.freeze({ bc: 'mainnet', tb: 'testnet', bcrt: 'regtest' });

function polymod(values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk = (chk ^ gen[i]) >>> 0;
  }
  return chk;
}

const invalidAddress = why => new ProofError(ErrorCode.ADDRESS_INVALID, `invalid Bitcoin address: ${why}`);

/** Decode a segwit address. Returns { hrp, network, version, program }. Non-segwit input is ADDRESS_INVALID or SCHEME_UNSUPPORTED. */
export function decodeSegwitAddress(address) {
  if (typeof address !== 'string' || address.length < 8 || address.length > 90) throw invalidAddress('length');
  if (/^[13mn2]/.test(address)) throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED, 'legacy (base58) Bitcoin addresses are not supported');
  if (address !== address.toLowerCase() && address !== address.toUpperCase()) throw invalidAddress('mixed case');
  const a = address.toLowerCase();
  const sep = a.lastIndexOf('1');
  if (sep < 1 || a.length - sep - 1 < 7) throw invalidAddress('separator');
  const hrp = a.slice(0, sep);
  if (!Object.hasOwn(HRP_NETWORK, hrp)) throw invalidAddress('unknown network prefix');
  const data = [];
  for (const c of a.slice(sep + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw invalidAddress('character');
    data.push(v);
  }
  const expanded = [...[...hrp].map(c => c.charCodeAt(0) >> 5), 0, ...[...hrp].map(c => c.charCodeAt(0) & 31), ...data];
  const version = data[0];
  if (version > 16) throw invalidAddress('witness version');
  if (polymod(expanded) !== (version === 0 ? BECH32 : BECH32M)) throw invalidAddress('checksum');

  let acc = 0;
  let bits = 0;
  const program = [];
  for (const d of data.slice(1, -6)) {
    acc = (acc << 5) | d;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      program.push((acc >> bits) & 0xff);
    }
  }
  if (bits >= 5 || (acc & ((1 << bits) - 1)) !== 0) throw invalidAddress('padding');
  if (program.length < 2 || program.length > 40) throw invalidAddress('program length');
  if (version === 0 && program.length !== 20 && program.length !== 32) throw invalidAddress('v0 program length');
  return { hrp, network: HRP_NETWORK[hrp], version, program: Uint8Array.from(program) };
}

// ---------- virtual transactions (BIP-322 §Full) ----------
const scriptPubKey = ({ version, program }) => concat(Uint8Array.of(version === 0 ? 0x00 : 0x50 + version), pushData(program));
const OUTPUTS = concat(zeros(8), pushData(Uint8Array.of(0x6a))); // one output: value 0, OP_RETURN

export const bip322MessageHash = message => taggedHash('BIP0322-signed-message', enc.encode(message));

/** to_spend txid in internal byte order (reverse it for display). */
export function bip322ToSpendTxid(message, spk) {
  const scriptSig = concat(Uint8Array.of(0x00), pushData(bip322MessageHash(message)));
  return dsha(concat(zeros(4), Uint8Array.of(1), zeros(32), Uint8Array.of(0xff, 0xff, 0xff, 0xff), pushData(scriptSig), zeros(4), Uint8Array.of(1), zeros(8), pushData(spk), zeros(4)));
}

/** to_sign txid (non-witness serialization), internal byte order. */
export const bip322ToSignTxid = toSpendTxid => dsha(concat(zeros(4), Uint8Array.of(1), toSpendTxid, zeros(4), Uint8Array.of(0), zeros(4), Uint8Array.of(1), OUTPUTS, zeros(4)));

// ---------- signature decoding ----------
const malformed = why => new ProofError(ErrorCode.SIGNATURE_MALFORMED, `malformed BIP-322 signature: ${why}`);
const MAX_SIGNATURE_LENGTH = 4096;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function decodeBase64(text) {
  if (!BASE64.test(text)) throw malformed('base64');
  const bytes = Buffer.from(text, 'base64');
  // Canonical encoding only, so one witness has exactly one accepted signature string.
  if (bytes.toString('base64') !== text) throw malformed('non-canonical base64');
  return Uint8Array.from(bytes);
}

function parseWitness(bytes) {
  if (bytes.length === 0) throw malformed('empty');
  const count = bytes[0];
  if (count === 0 || count >= 0xfd) throw malformed('witness item count');
  const items = [];
  let i = 1;
  for (let k = 0; k < count; k += 1) {
    if (i >= bytes.length) throw malformed('truncated');
    const len = bytes[i];
    if (len >= 0xfd) throw malformed('witness item too long');
    if (i + 1 + len > bytes.length) throw malformed('truncated');
    items.push(bytes.subarray(i + 1, i + 1 + len));
    i += 1 + len;
  }
  if (i !== bytes.length) throw malformed('trailing bytes');
  return items;
}

/** Strip the variant prefix and decode the witness stack. */
export function decodeBip322Signature(signature) {
  if (typeof signature !== 'string' || signature.length === 0) throw malformed('empty');
  if (signature.length > MAX_SIGNATURE_LENGTH) throw malformed('too long');
  if (signature.startsWith('ful') || signature.startsWith('pof')) {
    throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED, 'BIP-322 full and proof-of-funds variants are not supported');
  }
  const body = signature.startsWith('smp') ? signature.slice(3) : signature;
  return parseWitness(decodeBase64(body));
}

/** BIP-66 strict DER, returns { r, s } as bigints. */
function parseStrictDer(der) {
  const fail = () => {
    throw malformed('non-strict DER');
  };
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) fail();
  const readInt = at => {
    if (at + 2 > der.length || der[at] !== 0x02) fail();
    const len = der[at + 1];
    if (len === 0 || at + 2 + len > der.length) fail();
    const v = der.subarray(at + 2, at + 2 + len);
    if (v[0] & 0x80) fail(); // negative
    if (len > 1 && v[0] === 0 && !(v[1] & 0x80)) fail(); // excess padding
    return [BigInt(`0x${Buffer.from(v).toString('hex')}`), at + 2 + len];
  };
  const [r, next] = readInt(2);
  const [s, end] = readInt(next);
  if (end !== der.length) fail();
  if (r <= 0n || r >= N || s <= 0n || s >= N) throw malformed('r or s out of range');
  return { r, s };
}

const invalid = () => new ProofError(ErrorCode.SIGNATURE_INVALID, 'BIP-322 signature does not verify');

function verifyP2wpkh(program, witness, txid) {
  if (witness.length !== 2) throw malformed('P2WPKH witness must have exactly two items');
  const [sigWithType, pubkey] = witness;
  if (sigWithType.length < 9 || sigWithType[sigWithType.length - 1] !== 0x01) throw malformed('P2WPKH requires SIGHASH_ALL');
  if (pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03)) throw malformed('compressed public key required');
  const { r, s } = parseStrictDer(sigWithType.subarray(0, -1));
  if (s > N >> 1n) throw new ProofError(ErrorCode.SIGNATURE_NON_CANONICAL, 'high-s signature');
  if (!equal(ripemd160(sha256(pubkey)), program)) throw new ProofError(ErrorCode.ADDRESS_MISMATCH, 'public key does not match the address');

  const outpoint = concat(txid, zeros(4));
  const scriptCode = concat(Uint8Array.of(0x19, 0x76, 0xa9, 0x14), program, Uint8Array.of(0x88, 0xac));
  const preimage = concat(zeros(4), dsha(outpoint), dsha(zeros(4)), outpoint, scriptCode, zeros(8), zeros(4), dsha(OUTPUTS), zeros(4), Uint8Array.of(1, 0, 0, 0));
  let ok = false;
  try {
    ok = secp256k1.verify(new secp256k1.Signature(r, s), dsha(preimage), pubkey, { lowS: true });
  } catch {
    ok = false;
  }
  if (!ok) throw invalid();
}

function verifyP2trKeyPath(program, spk, witness, txid) {
  if (witness.length !== 1) throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED, 'only Taproot key-path spends are supported');
  const [sig] = witness;
  let hashType;
  if (sig.length === 64) hashType = 0x00;
  else if (sig.length === 65 && sig[64] === 0x01) hashType = 0x01;
  else throw malformed('Taproot signature must be 64 bytes, or 65 with SIGHASH_ALL');

  const outpoint = concat(txid, zeros(4));
  const preimage = concat(
    Uint8Array.of(0x00, hashType), // epoch, hash_type
    zeros(4), // nVersion
    zeros(4), // nLockTime
    sha256(outpoint),
    sha256(zeros(8)), // amounts
    sha256(pushData(spk)), // scriptPubKeys
    sha256(zeros(4)), // sequences
    sha256(OUTPUTS),
    Uint8Array.of(0x00), // spend_type: key path, no annex
    zeros(4), // input index
  );
  let ok = false;
  try {
    ok = schnorr.verify(sig.subarray(0, 64), taggedHash('TapSighash', preimage), program);
  } catch {
    ok = false;
  }
  if (!ok) throw invalid();
}

/**
 * Verify a BIP-322 simple signature. Returns { address, network, type } on success; throws ProofError otherwise.
 * The returned address is lower-case (bech32 canonical form).
 *
 * `network` is derived from the address prefix (bc/tb/bcrt), which BIP-322 does NOT sign: the same
 * signature verifies for bc1q<prog>, tb1q<prog> and bcrt1q<prog>. Bind the network in the signed text
 * (WalletProofService does, via buildBitcoinChallengeMessage) if it matters.
 */
export function verifyBip322Simple(args = {}) {
  if (!args || typeof args !== 'object') throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, 'expected { address, message, signature }');
  const { address, message, signature } = args;
  if (typeof message !== 'string' || !message.isWellFormed()) {
    throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, 'message must be a well-formed string');
  }
  const decoded = decodeSegwitAddress(address);
  const witness = decodeBip322Signature(signature);
  const spk = scriptPubKey(decoded);
  const txid = bip322ToSpendTxid(message, spk);

  let type;
  if (decoded.version === 0 && decoded.program.length === 20) {
    verifyP2wpkh(decoded.program, witness, txid);
    type = 'p2wpkh';
  } else if (decoded.version === 1 && decoded.program.length === 32) {
    verifyP2trKeyPath(decoded.program, spk, witness, txid);
    type = 'p2tr';
  } else {
    throw new ProofError(ErrorCode.SCHEME_UNSUPPORTED, `segwit v${decoded.version} with a ${decoded.program.length}-byte program is not supported`);
  }
  return { address: address.toLowerCase(), network: decoded.network, type };
}
