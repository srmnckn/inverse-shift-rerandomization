"""Scaled experiments on y^2 = x^3 + 7 over F_p with p = 1048783 and prime group order q = 1050337.
Experiment S1 (Section 3.3): the Groth-Shoup ratio attack with hashed messages, on the protocol of
  Kocaman and Talibi Alaoui (IMACC 2023) and, with the same budget, on the inverse shift.
Experiment S2 (Section 4.1): correctness of the possible shifts of the nonce shares.
Experiment S3 (Section 4.1): with one-sided shifts the search has three independent lists against the
  party that shifts; against the inverse shift with a corrupted P2 it has two, as for plain ECDSA. Repetition sd uses random.Random(sd), sd = 0..reps-1."""
import hashlib, random, sys
from smallcurve import find_curve, make

p, q = find_curve(1 << 20)
add, mul, P = make(p, q)
inv = lambda a: pow(a % q, q - 2, q)
conv = lambda R: R[0] % q
H = lambda msg: int.from_bytes(hashlib.sha256(msg).digest(), 'big') % q
Hd = lambda tag, *a: int.from_bytes(hashlib.sha256(repr((tag,) + a).encode()).digest(), 'big') % q

def delta(Q, tau, h):
    d2, ctr = Hd(2, Q, tau, h), 0
    while d2 == 0:
        ctr += 1; d2 = Hd(2, Q, tau, h, ctr)
    return Hd(1, Q, tau, h), d2

def verify(Q, h, sig):
    r, s = sig
    if not (0 < r < q and 0 < s < q): return False
    w = inv(s); R = add(mul(h * w, P), mul(r * w, Q))
    return R is not None and conv(R) == r

def keygen():
    x1, x2 = random.randrange(1, q), random.randrange(1, q)
    return x1, x2, mul((x1 + x2) % q, P)

def offline(x1):
    k1, k2 = random.randrange(1, q), random.randrange(1, q)
    a = random.randrange(q); b = (x1 * inv(k2) - a) % q
    R1, R2 = mul(k1, P), mul(k2, P)
    return dict(k1=k1, a=a, k2=k2, b=b, R1=R1, R2=R2, R=mul(k2, R1), tau=(R1, R2, mul(a, P)))

def sign_plain(S, x2, h):
    r = conv(S['R'])
    s2 = (inv(S['k2']) * (h + x2 * r) + S['b'] * r) % q
    return r, inv(S['k1']) * (s2 + S['a'] * r) % q

def sign_shift(S, Q, x1, x2, h, d1, d2, kind='both'):
    """Online phase with a shift. kind: 'both' = k1 + d1 and k2^{-1} + d2 (Section 4.2);
    'P1' = only k1 + d1; 'P2inv' = only k2^{-1} + d2; 'P2' = k2 + d2 without any correction;
    'direct' = k1 + d1 and k2 + d2 without any correction."""
    k1h = S['k1'] + d1 if kind in ('both', 'P1', 'direct') else S['k1']
    if kind in ('both', 'P2inv'):
        w = (inv(S['k2']) + d2) % q; corr = d2 * x1
    elif kind in ('P2', 'direct'):
        w = inv(S['k2'] + d2); corr = 0
    else:
        w = inv(S['k2']); corr = 0
    k2h = inv(w)
    Rh = mul(k2h, mul(k1h, P)); r = conv(Rh)
    s2 = (w * (h + x2 * r) + S['b'] * r) % q
    s = inv(k1h) * (s2 + (S['a'] + corr) * r) % q
    return (r, s), Rh

def s1(scheme, N, U, C, seed):
    random.seed(seed)
    x1, x2, Q = keygen()
    pres = [offline(x1) for _ in range(U)]
    msgs = [f"{seed}-{i}".encode() for i in range(N)]
    cand, wins = 0, 0
    for S in pres:
        r = conv(S['R'])
        table = {}
        for m in msgs: table.setdefault(H(m) * inv(r) % q, m)
        found = None
        for _ in range(C):
            c = random.randrange(1, q); rs = conv(mul(c, S['R']))
            for ms in msgs:
                v = H(ms) * inv(rs) % q
                if v in table and table[v] != ms:
                    cand += 1
                    found = found or (table[v], ms, c, rs)
        if not found: continue
        m, ms, c, rs = found
        if scheme == 'plain':
            _, s = sign_plain(S, x2, H(m))
        else:
            d1, d2 = delta(Q, S['tau'], H(m))
            (_, s), _ = sign_shift(S, Q, x1, x2, H(m), d1, d2)
        wins += verify(Q, H(ms), (rs, s * rs * inv(c * r) % q))
    return cand, wins

def s2(trials):
    res = {}
    for kind in ('P1', 'P2inv', 'both', 'P2', 'direct'):
        ok = 0
        for sd in range(trials):
            random.seed(sd)
            x1, x2, Q = keygen(); S = offline(x1); h = random.randrange(1, q)
            d1, d2 = delta(Q, S['tau'], h)
            if (S['k1'] + d1) % q == 0 or (S['k2'] + d2) % q == 0 or (inv(S['k2']) + d2) % q == 0: continue
            sig, _ = sign_shift(S, Q, x1, x2, h, d1, d2, kind)
            ok += verify(Q, h, sig)
        res[kind] = ok
    return res

def s3(case, L, seed):
    """Equal query budget with hashed messages. 'P1' (corrupted P1) and 'P2inv' (corrupted P2): three
    independent lists of L messages m, L multipliers v and L messages m*, matched through
    H(m)/conv(R_hat(m)) * conv([v]base) = H(m*); this uses about 2L group operations and 2L hash queries.
    'both' (inverse shift, corrupted P2): r* depends on the digest and the multiplier together, so the same
    2L group operations are spent on pairs (m, c) with R* = [c]R_hat(m), matched against L messages m*."""
    random.seed(seed)
    x1, x2, Q = keygen(); S = offline(x1)
    base = S['R2'] if case == 'P1' else S['R1']
    def mult(d1, d2):
        return (S['k1'] + d1) % q if case == 'P1' else inv(inv(S['k2']) + d2)
    def point(h):
        d1, d2 = delta(Q, S['tau'], h)
        if case == 'both':
            return mul(mult(d1, d2), add(S['R1'], mul(d1, P)))
        return mul(mult(d1, d2), base)
    stars = {}
    for i in range(L):
        ms = f"star-{seed}-{i}".encode(); stars.setdefault(H(ms), ms)
    def forge(h, ms, c, rs):
        d1, d2 = delta(Q, S['tau'], h)
        (rh, s), _ = sign_shift(S, Q, x1, x2, h, d1, d2, case)
        return verify(Q, H(ms), (rs, s * rs * inv(c * rh) % q))
    sols = wins = 0
    if case == 'both':
        D = 10; C = (2 * L - D) // D
        for i in range(D):
            h = H(f"left-{seed}-{i}".encode()); Rh = point(h); rh = conv(Rh)
            for _ in range(C):
                c = random.randrange(1, q); rs = conv(mul(c, Rh)); t = h * rs * inv(rh) % q
                if t in stars and t != h:
                    sols += 1; wins += forge(h, stars[t], c, rs)
    else:
        left = []
        for i in range(L):
            h = H(f"left-{seed}-{i}".encode()); left.append((h, h * inv(conv(point(h))) % q))
        tried = False
        for _ in range(L):
            v = random.randrange(1, q); rs = conv(mul(v, base))
            for h, a in left:
                t = a * rs % q
                if t in stars and t != h:
                    sols += 1
                    if not tried:
                        tried = True
                        d1, d2 = delta(Q, S['tau'], h)
                        wins += forge(h, stars[t], v * inv(mult(d1, d2)) % q, rs)
    return sols, wins

if __name__ == '__main__':
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    print(f"curve: p = {p}, q = {q} ({q.bit_length()} bits)")
    N, U, C = 600, 4, 8
    print(f"S1: N = {N} messages, U = {U} sessions, C = {C} multipliers; expected pairs N^2 U C / q = {N*N*U*C/q:.1f}")
    for scheme in ('plain', 'inverse'):
        tc = tw = rw = 0
        for sd in range(reps):
            c, w = s1(scheme, N, U, C, sd); tc += c; tw += w; rw += w > 0
        print(f"  {scheme:8s}: {reps} repetitions, mean pairs {tc/reps:.1f}, forgeries {tw}/{reps*U}, repetitions with a forgery {rw}/{reps}")
    print(f"S2 (valid signatures / 200): {s2(200)}")
    L = 150
    print(f"S3: budget about 2L = {2*L} group operations and {2*L} hash queries; L^3 / q = {L**3/q:.2f}; pairs against L messages (2L-10) L / q = {(2*L-10)*L/q:.3f}")
    for case in ('P1', 'P2inv', 'both'):
        tc = tw = rw = 0
        for sd in range(5 * reps):
            c, w = s3(case, L, sd); tc += c; tw += w; rw += w > 0
        print(f"  {case:6s}: {5*reps} repetitions, mean solutions {tc/(5*reps):.2f}, repetitions with a forgery {rw}/{5*reps}")
