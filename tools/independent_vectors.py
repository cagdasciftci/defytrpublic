"""Independent pure-Python Keccak-256 + secp256k1 used to cross-check test vectors.

No third-party packages; self-tests Keccak against hashlib.sha3_256 padding and the
known keccak("") digest. Run: python3 tools/independent_vectors.py
"""
import hashlib
RC=[0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M=(1<<64)-1
rol=lambda x,n:((x<<n)|(x>>(64-n)))&M if n else x
def f(A):
    for rc in RC:
        C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        A=[[A[x][y]^D[x] for y in range(5)] for x in range(5)]
        B=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2*x+3*y)%5]=rol(A[x][y],ROT[x][y])
        A=[[B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
        A[0][0]^=rc
    return A
def keccak(data,pad=0x01):
    r=136; d=bytearray(data); d.append(pad)
    while len(d)%r: d.append(0)
    d[-1]|=0x80
    A=[[0]*5 for _ in range(5)]
    for o in range(0,len(d),r):
        for i in range(r//8):
            A[i%5][i//5]^=int.from_bytes(d[o+8*i:o+8*i+8],'little')
        A=f(A)
    return b''.join(A[i%5][i//5].to_bytes(8,'little') for i in range(4))
# self-test: sha3 padding must equal hashlib.sha3_256, keccak('') known value
assert keccak(b'abc',0x06)==hashlib.sha3_256(b'abc').digest()
assert keccak(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
P=2**256-2**32-977; N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(p,q):
    if p is None: return q
    if q is None: return p
    if p[0]==q[0] and (p[1]+q[1])%P==0: return None
    l=((3*p[0]*p[0])*pow(2*p[1],-1,P) if p==q else (q[1]-p[1])*pow(q[0]-p[0],-1,P))%P
    x=(l*l-p[0]-q[0])%P; return (x,(l*(p[0]-x)-p[1])%P)
def mul(k,p):
    r=None
    while k:
        if k&1: r=add(r,p)
        p=add(p,p); k>>=1
    return r
def addr(pt): return keccak(pt[0].to_bytes(32,'big')+pt[1].to_bytes(32,'big'))[12:].hex()
def eip55(a):
    h=keccak(a.encode()).hex(); return '0x'+''.join(c.upper() if int(h[i],16)>=8 else c for i,c in enumerate(a))
def recover(h,r,s,v):
    x=r; y2=(pow(x,3,P)+7)%P; y=pow(y2,(P+1)//4,P); assert y*y%P==y2
    if y%2!=v: y=P-y
    R=(x,y); z=int.from_bytes(h,'big'); ri=pow(r,-1,N)
    return add(mul(s*ri%N,R),mul((-z*ri)%N,G))


def sign(priv, h, k):
    R = mul(k, G); r = R[0] % N
    s = pow(k, -1, N) * (int.from_bytes(h, 'big') + r * priv) % N
    v = R[1] % 2
    if s > N // 2:
        s = N - s; v ^= 1
    return r, s, v

def personal_hash(message):
    m = message.encode('utf-8')
    return keccak(b'\x19Ethereum Signed Message:\n' + str(len(m)).encode() + m)

if __name__ == '__main__':
    priv = 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318
    print('address', eip55(addr(mul(priv, G))))
    message = '\u00c7a\u011fda\u015f \u2014 \u00f6deme de\u011fil'
    h = personal_hash(message)
    r, s, v = sign(priv, h, k=0x1d2c3b4a59687766554433221100ffeeddccbbaa99887766554433221100abcd)
    assert eip55(addr(recover(h, r, s, v))) == eip55(addr(mul(priv, G)))
    print('message', message, 'utf8_len', len(message.encode()))
    print('digest 0x' + h.hex())
    print('signature 0x' + r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex() + format(27 + v, '02x'))

