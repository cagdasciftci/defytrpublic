import assert from 'node:assert/strict';
import { test } from 'node:test';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/legacy';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { bip322MessageHash, bip322ToSignTxid, bip322ToSpendTxid, decodeSegwitAddress, taggedHash, verifyBip322Simple } from '../src/bip322.js';
import { ErrorCode } from '../src/errors.js';
import { p2trWallet } from './helpers/btc.js';
import GENERATED from './fixtures/bip322-generated.json' with { type: 'json' };

// Official vectors: bitcoin/bips bip-0322/basic-test-vectors.json (research/test-vectors.md §2),
// re-checked by tools/bip322_reference.py (independent pure-Python implementation).
const P2WPKH = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
const P2WSH = 'bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9';
const P2TR = 'bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler';
const UTF8 = 'UTF-8 support: öäüéàè 测试文本 😄';

const HASHES = [
  ['', 'c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1', 'c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7', '1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6'],
  ['Hello World', 'f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a', 'b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b', '88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf'],
  [UTF8, '43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7', 'c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0', '8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586'],
];

const SIGS = [
  ['', 'smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI='],
  ['', 'smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy'],
  ['Hello World', 'smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI='],
  ['Hello World', 'smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy'],
];
const P2TR_SIG = 'AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R';
const MULTISIG_SIG =
  'smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=';

const code = c => e => e.code === c;
const rev = b => bytesToHex(Uint8Array.from(b).reverse());
const spkOf = a => {
  const { version, program } = decodeSegwitAddress(a);
  return Uint8Array.from([version === 0 ? 0 : 0x50 + version, program.length, ...program]);
};

test('tagged message hash and virtual txids match the official vectors', () => {
  for (const [m, mh, toSpend, toSign] of HASHES) {
    assert.equal(bytesToHex(bip322MessageHash(m)), mh, m);
    const t = bip322ToSpendTxid(m, spkOf(P2WPKH));
    assert.equal(rev(t), toSpend, m);
    assert.equal(rev(bip322ToSignTxid(t)), toSign, m);
  }
});

test('P2WPKH: every official simple signature verifies, both DER lengths', () => {
  for (const [m, s] of SIGS) {
    assert.deepEqual(verifyBip322Simple({ address: P2WPKH, message: m, signature: s }), { address: P2WPKH, network: 'mainnet', type: 'p2wpkh' });
    assert.equal(verifyBip322Simple({ address: P2WPKH.toUpperCase(), message: m, signature: s }).address, P2WPKH);
    // Older wallets emit the same witness without the `smp` prefix.
    assert.equal(verifyBip322Simple({ address: P2WPKH, message: m, signature: s.slice(3) }).type, 'p2wpkh');
  }
});

test('P2TR key-path: official "No prefix fallback" vector verifies', () => {
  assert.equal(verifyBip322Simple({ address: P2TR, message: 'No prefix fallback', signature: P2TR_SIG }).type, 'p2tr');
  assert.equal(verifyBip322Simple({ address: P2TR, message: 'No prefix fallback', signature: `smp${P2TR_SIG}` }).type, 'p2tr');
});

test('official error cases are rejected with typed codes', () => {
  const sig0 = SIGS[0][1];
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: 'not-valid-base64!!!' }), code(ErrorCode.SIGNATURE_MALFORMED));
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: '' }), code(ErrorCode.SIGNATURE_MALFORMED));
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: 'Wrong message that was not signed', signature: sig0 }), code(ErrorCode.SIGNATURE_INVALID));
  assert.throws(() => verifyBip322Simple({ address: P2WSH, message: '', signature: sig0 }), code(ErrorCode.SCHEME_UNSUPPORTED));
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: 'smpAA==' }), code(ErrorCode.SIGNATURE_MALFORMED));
  assert.throws(() => verifyBip322Simple({ address: P2WSH, message: 'This is not the message that was signed', signature: MULTISIG_SIG }), code(ErrorCode.SCHEME_UNSUPPORTED));
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: 'fooAA==' }), code(ErrorCode.SIGNATURE_MALFORMED));
  assert.throws(
    () =>
      verifyBip322Simple({
        address: 'bc1pyrgrm6cu6n54jrvkdjd9rvyd3xfyu84s2623awu2srn6mxhscwpsm5644w',
        message: 'incorrect prefix',
        signature: 'fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9srxS63eSWNGvH1NYbrBkPt1BJDUyWUz9zgUxfc63/QheT6M',
      }),
    code(ErrorCode.SCHEME_UNSUPPORTED),
  );
});

test('a valid signature for one address does not verify for another of the same type', () => {
  const other = secp256k1.utils.randomPrivateKey();
  const address = encodeSegwit('bc', 0, ripemd160(sha256(secp256k1.getPublicKey(other, true))));
  assert.throws(() => verifyBip322Simple({ address, message: '', signature: SIGS[0][1] }), code(ErrorCode.ADDRESS_MISMATCH));
  assert.throws(() => verifyBip322Simple({ address: P2TR, message: 'No prefix fallbacK', signature: P2TR_SIG }), code(ErrorCode.SIGNATURE_INVALID));
});

test('addresses: bad checksum, mixed case, unknown network, legacy and wrong bech32 variant are rejected', () => {
  const flip = P2WPKH.slice(0, -1) + (P2WPKH.endsWith('l') ? 'q' : 'l');
  assert.throws(() => decodeSegwitAddress(flip), code(ErrorCode.ADDRESS_INVALID));
  assert.throws(() => decodeSegwitAddress(`B${P2WPKH.slice(1)}`), code(ErrorCode.ADDRESS_INVALID));
  assert.throws(() => decodeSegwitAddress(`ltc${P2WPKH.slice(2)}`), code(ErrorCode.ADDRESS_INVALID));
  assert.throws(() => decodeSegwitAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'), code(ErrorCode.SCHEME_UNSUPPORTED));
  assert.throws(() => decodeSegwitAddress('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'), code(ErrorCode.SCHEME_UNSUPPORTED));
  // v0 program encoded with the bech32m constant, and v1 with bech32: both invalid (BIP-350).
  const prog = decodeSegwitAddress(P2WPKH).program;
  assert.throws(() => decodeSegwitAddress(encodeSegwit('bc', 0, prog, 0x2bc830a3)), code(ErrorCode.ADDRESS_INVALID));
  assert.throws(() => decodeSegwitAddress(encodeSegwit('bc', 1, decodeSegwitAddress(P2TR).program, 1)), code(ErrorCode.ADDRESS_INVALID));
  assert.equal(decodeSegwitAddress(encodeSegwit('tb', 0, prog)).network, 'testnet');
  for (const bad of [null, 42, '', 'bc1', 'x'.repeat(91)]) assert.throws(() => decodeSegwitAddress(bad), code(ErrorCode.ADDRESS_INVALID), String(bad));
});

test('P2WPKH strictness: high-s, non-SIGHASH_ALL, uncompressed key and non-strict DER are rejected', () => {
  const witness = Buffer.from(SIGS[0][1].slice(3), 'base64');
  const items = parseWitnessForTest(witness);
  const [der, pub] = [items[0].subarray(0, -1), items[1]];
  const { r, s } = secp256k1.Signature.fromDER(der);
  const highS = new secp256k1.Signature(r, secp256k1.CURVE.n - s).toDERRawBytes();
  const sig = (d, t, p) => buildWitness([Uint8Array.from([...d, t]), p]);
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: sig(highS, 1, pub) }), code(ErrorCode.SIGNATURE_NON_CANONICAL));
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: sig(der, 0x81, pub) }), code(ErrorCode.SIGNATURE_MALFORMED));
  const padded = Uint8Array.from([0x30, der[1] + 1, 0x02, der[3] + 1, 0x00, ...der.subarray(4)]);
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: sig(padded, 1, pub) }), code(ErrorCode.SIGNATURE_MALFORMED));
  const uncompressed = secp256k1.ProjectivePoint.fromHex(pub).toRawBytes(false);
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: sig(der, 1, uncompressed) }), code(ErrorCode.SIGNATURE_MALFORMED));
  const trailing = Buffer.concat([witness, Buffer.from([0])]).toString('base64');
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: `smp${trailing}` }), e => e.code === ErrorCode.SIGNATURE_MALFORMED && /trailing/.test(e.message));
});

test('property: fresh P2WPKH and P2TR keys round-trip; any flipped signature or message bit fails', () => {
  for (let i = 0; i < 24; i += 1) {
    const key = secp256k1.utils.randomPrivateKey();
    const message = `travel-rule challenge ${i} ${bytesToHex(key).slice(0, 6)} ✓`;

    const pub = secp256k1.getPublicKey(key, true);
    const wpkh = encodeSegwit('bc', 0, ripemd160(sha256(pub)));
    const txW = bip322ToSpendTxid(message, spkOf(wpkh));
    const ecdsa = secp256k1.sign(p2wpkhSighash(txW, decodeSegwitAddress(wpkh).program), key, { lowS: true });
    const wSig = `smp${buildWitness([Uint8Array.from([...ecdsa.toDERRawBytes(), 1]), pub])}`;
    assert.equal(verifyBip322Simple({ address: wpkh, message, signature: wSig }).type, 'p2wpkh');

    const xOnly = schnorr.getPublicKey(key);
    const tr = encodeSegwit('bc', 1, xOnly, 0x2bc830a3);
    const txT = bip322ToSpendTxid(message, spkOf(tr));
    const tSig = buildWitness([schnorr.sign(p2trSighash(txT, spkOf(tr)), key)]);
    assert.equal(verifyBip322Simple({ address: tr, message, signature: tSig }).type, 'p2tr');

    const msgFlip = message.slice(0, -1) + String.fromCharCode(message.charCodeAt(message.length - 1) ^ 1);
    assert.throws(() => verifyBip322Simple({ address: wpkh, message: msgFlip, signature: wSig }), code(ErrorCode.SIGNATURE_INVALID));
    assert.throws(() => verifyBip322Simple({ address: tr, message: msgFlip, signature: tSig }), code(ErrorCode.SIGNATURE_INVALID));

    const raw = Buffer.from(tSig, 'base64');
    raw[2 + (i % 64)] ^= 1 << (i % 8);
    assert.throws(() => verifyBip322Simple({ address: tr, message, signature: raw.toString('base64') }), code(ErrorCode.SIGNATURE_INVALID));
  }
});

// ---------- test-only helpers, written independently of src/bip322.js ----------
function encodeSegwit(hrp, version, program, constant = version === 0 ? 1 : 0x2bc830a3) {
  const cs = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
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
  const pm = v => {
    const g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let c = 1;
    for (const x of v) {
      const t = c >>> 25;
      c = (((c & 0x1ffffff) << 5) ^ x) >>> 0;
      for (let k = 0; k < 5; k += 1) if ((t >>> k) & 1) c = (c ^ g[k]) >>> 0;
    }
    return c;
  };
  const e = [...[...hrp].map(c => c.charCodeAt(0) >> 5), 0, ...[...hrp].map(c => c.charCodeAt(0) & 31)];
  const mod = (pm([...e, ...data, 0, 0, 0, 0, 0, 0]) ^ constant) >>> 0;
  for (let k = 0; k < 6; k += 1) data.push((mod >>> (5 * (5 - k))) & 31);
  return `${hrp}1${data.map(d => cs[d]).join('')}`;
}

function buildWitness(items) {
  return Buffer.from([items.length, ...items.flatMap(it => [it.length, ...it])]).toString('base64');
}

function parseWitnessForTest(buf) {
  const out = [];
  let i = 1;
  for (let k = 0; k < buf[0]; k += 1) {
    out.push(Uint8Array.from(buf.subarray(i + 1, i + 1 + buf[i])));
    i += 1 + buf[i];
  }
  return out;
}

const d = b => sha256(sha256(b));
const cat = (...p) => Uint8Array.from(p.flatMap(x => [...x]));
const z = n => new Uint8Array(n);
const OUT = cat(z(8), [1, 0x6a]);

function p2wpkhSighash(txid, program) {
  const op = cat(txid, z(4));
  return d(cat(z(4), d(op), d(z(4)), op, [0x19, 0x76, 0xa9, 0x14], program, [0x88, 0xac], z(8), z(4), d(OUT), z(4), [1, 0, 0, 0]));
}

function p2trSighash(txid, spk) {
  const op = cat(txid, z(4));
  return taggedHash('TapSighash', cat([0, 0], z(8), sha256(op), sha256(z(8)), sha256(cat([spk.length], spk)), sha256(z(4)), sha256(OUT), [0], z(4)));
}

test('review fix: a DER signature whose r length ends one byte early is SIGNATURE_MALFORMED, not a crash', () => {
  const signature = 'smpAgkwBgIDAQEBAgEhAgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB';
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: 'x', signature }), code(ErrorCode.SIGNATURE_MALFORMED));
});

test('review fixes: pof prefix, non-canonical base64, oversize input, bad arguments, lone surrogates, witness count', () => {
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: 'pofAA==' }), code(ErrorCode.SCHEME_UNSUPPORTED));
  const sig = SIGS[0][1];
  assert.ok(sig.endsWith('I='));
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: `${sig.slice(0, -2)}J=` }), e => e.code === ErrorCode.SIGNATURE_MALFORMED && /non-canonical/.test(e.message));
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: `smp${'A'.repeat(4096)}` }), e => e.code === ErrorCode.SIGNATURE_MALFORMED && /too long/.test(e.message));
  for (const bad of [undefined, null, 'x', 42]) {
    assert.throws(() => verifyBip322Simple(bad), code(ErrorCode.INVALID_CHALLENGE_INPUT), String(bad));
  }
  for (const message of ['a\uD800', 'a\uDC00', 42]) {
    assert.throws(() => verifyBip322Simple({ address: P2WPKH, message, signature: sig }), code(ErrorCode.INVALID_CHALLENGE_INPUT));
  }
  const oneItem = Buffer.from([1, 1, 0]).toString('base64');
  assert.throws(() => verifyBip322Simple({ address: P2WPKH, message: '', signature: oneItem }), code(ErrorCode.SIGNATURE_MALFORMED));
});

test('P2TR: 65-byte SIGHASH_ALL signatures verify; other 65-byte forms and an appended 0x01 do not', () => {
  const w = p2trWallet();
  const message = 'taproot sighash all';
  assert.equal(verifyBip322Simple({ address: w.address, message, signature: w.sign(message, { hashType: 0x01 }) }).type, 'p2tr');

  const def = Buffer.from(w.sign(message), 'base64'); // [1, 64, sig64]
  const with65 = last => Buffer.from([1, 65, ...def.subarray(2), last]).toString('base64');
  assert.throws(() => verifyBip322Simple({ address: w.address, message, signature: with65(0x00) }), code(ErrorCode.SIGNATURE_MALFORMED));
  assert.throws(() => verifyBip322Simple({ address: w.address, message, signature: with65(0x02) }), code(ErrorCode.SIGNATURE_MALFORMED));
  // A valid SIGHASH_DEFAULT signature with 0x01 appended commits to a different digest.
  assert.throws(() => verifyBip322Simple({ address: w.address, message, signature: with65(0x01) }), code(ErrorCode.SIGNATURE_INVALID));
  const all = Buffer.from(w.sign(message, { hashType: 0x01 }), 'base64');
  const stripped = Buffer.from([1, 64, ...all.subarray(2, 66)]).toString('base64');
  assert.throws(() => verifyBip322Simple({ address: w.address, message, signature: stripped }), code(ErrorCode.SIGNATURE_INVALID));
});

test('official generated vectors: P2WPKH and P2TR verify, P2WSH fails closed', () => {
  assert.equal(GENERATED.simple.length, 4);
  for (const v of GENERATED.simple) {
    for (const signature of v.bip322_signatures) {
      if (v.type === 'p2wpkh' || v.type === 'p2tr') {
        assert.equal(verifyBip322Simple({ address: v.address, message: v.message, signature }).type, v.type);
      } else {
        assert.throws(() => verifyBip322Simple({ address: v.address, message: v.message, signature }), code(ErrorCode.SCHEME_UNSUPPORTED), v.type);
      }
    }
  }
});

test('official generated error vectors: all 28 are rejected with a typed code; simple P2WPKH/P2TR ones as SIGNATURE_INVALID or ADDRESS_MISMATCH', () => {
  assert.equal(GENERATED.error.length, 28);
  for (const e of GENERATED.error) {
    assert.throws(
      () => verifyBip322Simple({ address: e.address, message: e.message, signature: e.signature }),
      err => {
        if (!Object.values(ErrorCode).includes(err.code)) return false;
        if (/(p2wpkh|p2tr) simple/.test(e.description)) return [ErrorCode.SIGNATURE_INVALID, ErrorCode.ADDRESS_MISMATCH].includes(err.code);
        return err.code === ErrorCode.SCHEME_UNSUPPORTED; // P2WSH, full variant, legacy addresses
      },
      e.description,
    );
  }
});

test('BIP-350 address vectors: valid ones decode to the listed scriptPubKey; invalid ones are rejected', () => {
  const VALID = {
    BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4: '0014751e76e8199196d454941c45d1b3a323f1433bd6',
    BC1SW50QGDZ25J: '6002751e',
    bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs: '5210751e76e8199196d454941c45d1b3a323',
  };
  for (const [a, hex] of Object.entries(VALID)) {
    const { version, program } = decodeSegwitAddress(a);
    assert.equal(bytesToHex(Uint8Array.from([version === 0 ? 0 : 0x50 + version, program.length, ...program])), hex, a);
  }
  const INVALID = [
    'tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
    'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf',
    'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
    'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47',
    'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
    'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
    'bc1pw5dgrnzv',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
    'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
    'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq',
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
    'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j',
    'bc1gmk9yu',
  ];
  for (const a of INVALID) assert.throws(() => decodeSegwitAddress(a), code(ErrorCode.ADDRESS_INVALID), a);
});
