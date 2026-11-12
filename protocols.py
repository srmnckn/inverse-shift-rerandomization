"""Two-party ECDSA of Kocaman and Talibi Alaoui (IMACC 2023), the protocol of Xue et al. (CCS 2021)
and the inverse-shift variant (Section 4 of the paper). MtA, commitments and ZK proofs are modeled
as ideal functionalities (trusted computation); there is no network and no malicious behaviour."""

class Abort(Exception):
    pass
from ec import *

def keygen():
    x1, x2 = rnd(), rnd()
    return x1, x2, add(mul(x1), mul(x2))           # Q = Q1 + Q2

def presign(x1):
    """Cevrimdisi faz: k1, k2, R = [k1 k2]P; F_MtA: a + b = x1 * k2^{-1}."""
    k1, k2 = rnd(), rnd()
    R1, R2 = mul(k1), mul(k2)
    R = mul(k2, R1)
    a = rnd(); b = (x1 * inv(k2) - a) % q
    Z = mul(a)
    assert mul(k2, add(Z, mul(b))) == mul(x1)        # P2'nin Z kontrolu
    tau = (R1, R2, Z)                                 # cevrimdisi transkript
    return dict(k1=k1, a=a, R1=R1, tau=tau, used=False), dict(k2=k2, b=b, R1=R1, R2=R2, tau=tau, used=False), R

def sign_imacc(P1, P2, R, x2, h):
    """Orijinal IMACC cevrimici faz: R onceden bilinir (ham presignature)."""
    r = xr(R)
    s2 = (inv(P2['k2']) * (h + x2 * r) + P2['b'] * r) % q          # P2 -> P1
    s = inv(P1['k1']) * (s2 + P1['a'] * r) % q
    return r, s

def deltas(Q, tau, h, mode, beacon=None):
    if mode == 'hash':
        d2, ctr = H('d2', Q, tau, h), 0
        while d2 == 0:                                # delta2 in Z_q^* (paper, Section 4.2)
            ctr += 1; d2 = H('d2', Q, tau, h, ctr)
        return H('d1', Q, tau, h), d2
    return beacon

def sign_inv(P1, P2, R, Q, x1, x2, h, mode='hash', beacon=None):
    """Inverse shift (Figure 1): P2 uses u = k2^{-1} + d2, P1 uses k1 + d1 and a + d2*x1.
    One online message P2 -> P1: (R_hat, s2). Raises Abort on the abort conditions of Section 4.2;
    each session is marked used before its online message."""
    for P in (P2, P1):
        if P['used']:
            raise Abort('session already used')
        P['used'] = True
    d1, d2 = deltas(Q, P2['tau'], h, mode, beacon)
    u = (inv(P2['k2']) + d2) % q
    base = add(P2['R1'], mul(d1))
    if u == 0 or base is O:
        raise Abort('P2: u = 0 or R1 g^d1 = 1')
    Rhat = mul(inv(u), base)                                        # (R1 g^{d1})^{1/u}
    r = xr(Rhat)
    if r == 0:
        raise Abort('P2: r_hat = 0')
    s2 = (u * (h + x2 * r) + P2['b'] * r) % q                       # P2 -> P1
    if (P1['k1'] + d1) % q == 0:
        raise Abort('P1: k1 + d1 = 0')
    s = inv(P1['k1'] + d1) * (s2 + (P1['a'] + d2 * x1) * r) % q
    if s == 0 or not verify(Q, h, (r, s)):
        raise Abort('P1: invalid signature')
    return (r, s), Rhat

def presign_xue(x1, x2):
    """Xue vd. (CCS'21) cevrimdisi faz, ideal MtA: x1'(r1+k2) + x2' = x; k = k1(r1+k2)."""
    k1, k2, r1 = rnd(), rnd(), rnd()
    K = (r1 + k2) % q
    x1p = rnd(); x2p = (x1 + x2 - x1p * K) % q
    R = mul(k1 * K % q)
    return dict(k1=k1, x1p=x1p), dict(K=K, x2p=x2p), R

def sign_xue(P1, P2, R, h):
    r = xr(R)
    s2 = inv(P2['K']) * (h + r * P2['x2p']) % q                    # P2 -> P1
    s = inv(P1['k1']) * (s2 + r * P1['x1p']) % q
    return r, s


def keygen_lindell():
    """Lindell (CRYPTO 2017), Protocol 3.1: multiplicative key shares, Q = [x1 x2]P."""
    x1, x2 = rnd(), rnd()
    return x1, x2, mul(x1 * x2 % q)

def presign_lindell():
    """Steps 1-3 of Lindell's Protocol 3.2, run offline as the paper allows: R = [k1 k2]P."""
    k1, k2 = rnd(), rnd()
    R1, R2 = mul(k1), mul(k2)
    R = mul(k2, R1)
    tau = (R1, R2)
    return (dict(k1=k1, R1=R1, tau=tau, used=False),
            dict(k2=k2, R1=R1, R2=R2, tau=tau, used=False), R)

def sign_lindell(P1, P2, R, x1, x2, h):
    """Step 4-5 with a precomputed R. The Paillier ciphertext c3 is modeled ideally:
    P1 obtains s' = k2^{-1}(h + r x1 x2) mod q (the rho*q term vanishes mod q)."""
    r = xr(R)
    sp = inv(P2['k2']) * (h + r * x1 * x2) % q        # Dec(c3) mod q
    s = inv(P1['k1']) * sp % q
    return r, min(s, q - s)

def sign_lindell_inv(P1, P2, R, Q, x1, x2, h):
    """Inverse shift applied to Lindell: P2 uses u = k2^{-1} + d2 in c3 and sends R_hat;
    P1 multiplies by (k1 + d1)^{-1}. Nonce (k1 + d1)/(k2^{-1} + d2), as for IMACC 2023."""
    for P in (P2, P1):
        if P['used']:
            raise Abort('session already used')
        P['used'] = True
    d1, d2 = deltas(Q, P2['tau'], h, 'hash')
    u = (inv(P2['k2']) + d2) % q
    base = add(P2['R1'], mul(d1))
    if u == 0 or base is O:
        raise Abort('P2: u = 0 or R1 g^d1 = 1')
    Rhat = mul(inv(u), base)
    r = xr(Rhat)
    if r == 0:
        raise Abort('P2: r_hat = 0')
    sp = u * (h + r * x1 * x2) % q                     # Dec(c3) mod q
    if (P1['k1'] + d1) % q == 0:
        raise Abort('P1: k1 + d1 = 0')
    s = inv(P1['k1'] + d1) * sp % q
    s = min(s, q - s)
    if s == 0 or not verify(Q, h, (r, s)):
        raise Abort('P1: invalid signature')
    return (r, s), Rhat
