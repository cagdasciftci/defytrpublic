"""Independent pure-Python BIP-322 "simple" verifier (P2WPKH, P2TR key-path).

Cross-checks the JS implementation against the official vectors in
bitcoin/bips bip-0322/basic-test-vectors.json. Uses only hashlib and the
secp256k1 arithmetic in independent_vectors.py. Run: python3 tools/bip322_reference.py
"""
import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from independent_vectors import G, N, P, add, mul  # noqa: E402

sha = lambda b: hashlib.sha256(b).digest()
dsha = lambda b: sha(sha(b))
def tagged(tag, msg):
    t = sha(tag.encode()); return sha(t + t + msg)
def varint(n):
    assert n < 0xfd; return bytes([n])
def push(b): return varint(len(b)) + b

# --- bech32 / bech32m (BIP-173, BIP-350) ---
CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def polymod(v):
    g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; c = 1
    for x in v:
        b = c >> 25; c = (c & 0x1ffffff) << 5 ^ x
        for i in range(5): c ^= g[i] if (b >> i) & 1 else 0
    return c
def decode_segwit(addr):
    a = addr.lower(); hrp, data = a[:a.rfind('1')], [CS.index(c) for c in a[a.rfind('1') + 1:]]
    const = polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data)
    ver = data[0]; assert const == (1 if ver == 0 else 0x2bc830a3)
    acc = bits = 0; out = []
    for d in data[1:-6]:
        acc = acc << 5 | d; bits += 5
        while bits >= 8: bits -= 8; out.append(acc >> bits & 255)
    return ver, bytes(out)

def script_pubkey(addr):
    ver, prog = decode_segwit(addr)
    return bytes([0x51 + ver - 1 if ver else 0]) + push(prog), ver, prog

def to_spend_txid(msg, spk):
    mh = tagged('BIP0322-signed-message', msg)
    tx = (b'\0' * 4 + b'\1' + b'\0' * 32 + b'\xff' * 4 + push(b'\0' + push(mh)) + b'\0' * 4
          + b'\1' + b'\0' * 8 + push(spk) + b'\0' * 4)
    return dsha(tx)  # internal byte order

def to_sign_txid(txid):
    tx = b'\0' * 4 + b'\1' + txid + b'\0' * 4 + b'\0' + b'\0' * 4 + b'\1' + b'\0' * 8 + push(b'\x6a') + b'\0' * 4
    return dsha(tx)

def read_witness(b):
    n = b[0]; i = 1; items = []
    for _ in range(n):
        l = b[i]; items.append(b[i + 1:i + 1 + l]); i += 1 + l
    assert i == len(b); return items

def lift_x(x):
    y2 = (pow(x, 3, P) + 7) % P; y = pow(y2, (P + 1) // 4, P); assert y * y % P == y2
    return (x, y if y % 2 == 0 else P - y)

def verify(addr, msg, sig_b64):
    if sig_b64.startswith('smp'): sig_b64 = sig_b64[3:]
    wit = read_witness(base64.b64decode(sig_b64, validate=True))
    spk, ver, prog = script_pubkey(addr)
    txid = to_spend_txid(msg.encode(), spk)
    outpoint = txid + b'\0' * 4
    outputs = b'\0' * 8 + push(b'\x6a')
    if ver == 0 and len(prog) == 20:
        der, pub = wit[0][:-1], wit[1]; assert wit[0][-1] == 1 and len(pub) == 33
        assert hashlib.new('ripemd160', sha(pub)).digest() == prog
        pre = (b'\0' * 4 + dsha(outpoint) + dsha(b'\0' * 4) + outpoint + b'\x19\x76\xa9\x14' + prog + b'\x88\xac'
               + b'\0' * 8 + b'\0' * 4 + dsha(outputs) + b'\0' * 4 + b'\1\0\0\0')
        z = int.from_bytes(dsha(pre), 'big')
        rl = der[3]; r = int.from_bytes(der[4:4 + rl], 'big'); s = int.from_bytes(der[6 + rl:], 'big')
        Q = lift_x(int.from_bytes(pub[1:], 'big'))
        if Q[1] % 2 != pub[0] - 2: Q = (Q[0], P - Q[1])
        w = pow(s, -1, N); R = add(mul(z * w % N, G), mul(r * w % N, Q))
        return R is not None and R[0] % N == r and s <= N // 2
    if ver == 1 and len(prog) == 32:
        sig = wit[0]; assert len(sig) == 64 or (len(sig) == 65 and sig[64] == 1)
        ht = b'\0' if len(sig) == 64 else b'\1'
        pre = (b'\0' + ht + b'\0' * 4 + b'\0' * 4 + sha(outpoint) + sha(b'\0' * 8) + sha(push(spk))
               + sha(b'\0' * 4) + sha(outputs) + b'\0' + b'\0' * 4)
        m = tagged('TapSighash', pre)
        Pk = lift_x(int.from_bytes(prog, 'big')); r = int.from_bytes(sig[:32], 'big'); s = int.from_bytes(sig[32:64], 'big')
        e = int.from_bytes(tagged('BIP0340/challenge', sig[:32] + prog + m), 'big') % N
        R = add(mul(s, G), mul(N - e, Pk))
        return R is not None and R[1] % 2 == 0 and R[0] == r
    raise ValueError('unsupported')

if __name__ == '__main__':
    A = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l'
    spk = script_pubkey(A)[0]
    for m, mh, sp, sg in [
        ('', 'c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1', 'c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7', '1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6'),
        ('Hello World', 'f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a', 'b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b', '88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf'),
        ('UTF-8 support: öäüéàè 测试文本 😄', '43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7', 'c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0', '8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586'),
    ]:
        assert tagged('BIP0322-signed-message', m.encode()).hex() == mh, m
        t = to_spend_txid(m.encode(), spk); assert t[::-1].hex() == sp, m
        assert to_sign_txid(t)[::-1].hex() == sg, m
    for m, s in [
        ('', 'smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI='),
        ('', 'smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy'),
        ('Hello World', 'smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI='),
        ('Hello World', 'smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy'),
    ]:
        assert verify(A, m, s), (m, s)
        assert not verify(A, m + 'x', s)
    assert verify('bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler', 'No prefix fallback',
                  'AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R')
    assert not verify('bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler', 'No prefix fallbacK',
                      'AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R')
    print('bip322 reference: all official vectors pass')
