"""Sections 3.3 and 6.2 of the paper. Experiment 1: correctness (Xue et al., IMACC 2023=Kocaman and Talibi Alaoui, Lindell, inverse shift).
Experiment 2: raw-signing form of the attack of Section 3.2; it succeeds against the plain protocols and
fails against the inverse shift, whose nonce point depends on the digest. Seed fixed (ec.set_seed)."""
import sys
from protocols import *

def correctness(n):
    ok1 = ok2 = ok3 = ok4 = ok5 = 0
    for _ in range(n):
        x1, x2, X = keygen(); h = rnd()
        P1, P2, R = presign(x1); ok1 += verify(X, h, sign_imacc(P1, P2, R, x2, h))
        P1, P2, R = presign(x1); sig, _ = sign_inv(P1, P2, R, X, x1, x2, h); ok2 += verify(X, h, sig)
        P1, P2, R = presign_xue(x1, x2); ok3 += verify(X, h, sign_xue(P1, P2, R, h))
        y1, y2, Y = keygen_lindell()
        P1, P2, R = presign_lindell(); ok4 += verify(Y, h, sign_lindell(P1, P2, R, y1, y2, h))
        P1, P2, R = presign_lindell(); sig, _ = sign_lindell_inv(P1, P2, R, Y, y1, y2, h); ok5 += verify(Y, h, sig)
    return ok1, ok2, ok3, ok4, ok5

def raw_signing_attack(scheme, trials):
    """The adversary sees the presignature R and wants a forgery on a target digest m0:
    R' = [c]R, r' = conv(R'); it asks the signing oracle for the raw digest m = m0 r / r'."""
    wins = 0
    for _ in range(trials):
        if scheme.startswith('lindell'):
            x1, x2, X = keygen_lindell(); P1, P2, R = presign_lindell()
        else:
            x1, x2, X = keygen()
            P1, P2, R = presign_xue(x1, x2) if scheme == 'xue' else presign(x1)
        m0, lam = rnd(), rnd()
        r = xr(R); Rp = mul(lam, R); rp = xr(Rp)
        m = m0 * r * inv(rp) % q
        if scheme == 'xue':
            _, s = sign_xue(P1, P2, R, m)
        elif scheme == 'imacc':
            _, s = sign_imacc(P1, P2, R, x2, m)
        elif scheme == 'lindell':
            _, s = sign_lindell(P1, P2, R, x1, x2, m)
        elif scheme == 'lindell_inv':
            (_, s), _ = sign_lindell_inv(P1, P2, R, X, x1, x2, m)
        else:
            (r_used, s), _ = sign_inv(P1, P2, R, X, x1, x2, m)
        forged = (rp, s * rp * inv(r * lam) % q)
        ok = verify(X, m0, forged)
        if not ok:
            forged = (rp, (q - s) * rp * inv(r * lam) % q)   # low-s normalisation in Lindell
            ok = verify(X, m0, forged)
        wins += ok and m0 != m
    return wins

if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    set_seed(int(sys.argv[2]) if len(sys.argv) > 2 else 20261031)
    c1, c2, c3, c4, c5 = correctness(n)
    print(f"Correctness (valid signatures / {n}): Xue {c3}, IMACC {c1}, inverse shift {c2}, "
          f"Lindell {c4}, Lindell with inverse shift {c5}")
    print(f"Raw-signing attack (successful / {n}): Xue {raw_signing_attack('xue', n)}, "
          f"IMACC {raw_signing_attack('imacc', n)}, inverse shift {raw_signing_attack('inv', n)}, "
          f"Lindell {raw_signing_attack('lindell', n)}, Lindell with inverse shift {raw_signing_attack('lindell_inv', n)}")
