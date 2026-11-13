"""Pure-Python secp256k1 reference (experiments only; not constant time)."""
import hashlib, random

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
O = None

def inv(a, m=q):
    return pow(a % m, m - 2, m)

def add(P, Q):
    if P is O: return Q
    if Q is O: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return O
    if P == Q:
        l = 3 * P[0] * P[0] * inv(2 * P[1], p) % p
    else:
        l = (Q[1] - P[1]) * inv(Q[0] - P[0], p) % p
    x = (l * l - P[0] - Q[0]) % p
    return (x, (l * (P[0] - x) - P[1]) % p)

def mul(k, P=G):
    k %= q; R = O
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

_rng = random.Random(20261031)

def set_seed(seed):
    """Fix the seed of all sampling (default seed 20261031)."""
    global _rng
    _rng = random.Random(seed)

def rnd():
    return _rng.randrange(1, q)

def H(*parts):
    h = hashlib.sha256()
    for x in parts: h.update(repr(x).encode())
    return int.from_bytes(h.digest(), 'big') % q

def xr(R):
    return R[0] % q

def verify(X, h, sig):
    r, s = sig
    if not (0 < r < q and 0 < s < q): return False
    w = inv(s)
    R = add(mul(h * w % q), mul(r * w % q, X))
    return R is not O and xr(R) == r
