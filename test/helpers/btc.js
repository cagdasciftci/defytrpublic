// Test-only BIP-322 signers, written from BIP-143/BIP-341 independently of src/bip322.js
// (except taggedHash, which is the standard BIP-340 construction).
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/legacy';
import { sha256 } from '@noble/hashes/sha2';
import { bip322ToSpendTxid, taggedHash } from '../../src/bip322.js';

const CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const d = b => sha256(sha256(b));
const cat = (...p) => Uint8Array.from(p.flatMap(x => [...x]));
const z = n => new Uint8Array(n);
const OUT = cat(z(8), [1, 0x6a]);

function polymod(v) {
  const g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let c = 1;
  for (const x of v) {
    const t = c >>> 25;
    c = (((c & 0x1ffffff) << 5) ^ x) >>> 0;
    for (let k = 0; k < 5; k += 1) if ((t >>> k) & 1) c = (c ^ g[k]) >>> 0;
  }
  return c;
}

export function encodeSegwit(hrp, version, program) {
  const constant = version === 0 ? 1 : 0x2bc830a3;
  const data = [version];
  let acc = 0;
  let bits = 0;
  for (const b of program) {
    acc = ((acc << 8) | b) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data.push((acc >> bits) & 31);
    }
  }
  if (bits) data.push((acc << (5 - bits)) & 31);
  const e = [...[...hrp].map(c => c.charCodeAt(0) >> 5), 0, ...[...hrp].map(c => c.charCodeAt(0) & 31)];
  const mod = (polymod([...e, ...data, 0, 0, 0, 0, 0, 0]) ^ constant) >>> 0;
  for (let k = 0; k < 6; k += 1) data.push((mod >>> (5 * (5 - k))) & 31);
  return `${hrp}1${data.map(x => CS[x]).join('')}`;
}

const witness = items => Buffer.from([items.length, ...items.flatMap(it => [it.length, ...it])]).toString('base64');

/** A fresh P2WPKH wallet: `{ address, sign(message) }` producing `smp`-prefixed BIP-322 signatures. */
export function p2wpkhWallet(hrp = 'bc', key = secp256k1.utils.randomPrivateKey()) {
  const pub = secp256k1.getPublicKey(key, true);
  const program = ripemd160(sha256(pub));
  const address = encodeSegwit(hrp, 0, program);
  const spk = cat([0, 20], program);
  return {
    address,
    sign(message) {
      const op = cat(bip322ToSpendTxid(message, spk), z(4));
      const sighash = d(cat(z(4), d(op), d(z(4)), op, [0x19, 0x76, 0xa9, 0x14], program, [0x88, 0xac], z(8), z(4), d(OUT), z(4), [1, 0, 0, 0]));
      const sig = secp256k1.sign(sighash, key, { lowS: true });
      return `smp${witness([cat(sig.toDERRawBytes(), [1]), pub])}`;
    },
  };
}

/** A fresh P2TR wallet (output key used directly; the verifier does not care about the tweak). */
export function p2trWallet(hrp = 'bc', key = secp256k1.utils.randomPrivateKey()) {
  const xOnly = schnorr.getPublicKey(key);
  const address = encodeSegwit(hrp, 1, xOnly);
  const spk = cat([0x51, 32], xOnly);
  return {
    address,
    sign(message) {
      const op = cat(bip322ToSpendTxid(message, spk), z(4));
      const m = taggedHash('TapSighash', cat([0, 0], z(8), sha256(op), sha256(z(8)), sha256(cat([spk.length], spk)), sha256(z(4)), sha256(OUT), [0], z(4)));
      return witness([schnorr.sign(m, key)]);
    },
  };
}
