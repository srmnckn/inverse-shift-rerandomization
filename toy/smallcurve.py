"""Kucuk asal mertebeli egri: y^2 = x^3 + 7 uzerinde, p ~ 2^20. Yalniz olcekli deneyler icin."""
import numpy as np

def is_prime(n):
    if n < 2: return False
    i = 2
    while i * i <= n:
        if n % i == 0: return False
        i += 1
    return True

def count_points(p, b=7):
    x = np.arange(p, dtype=np.int64)
    rhs = (x * x % p * x + b) % p
    sq = np.zeros(p, dtype=np.int64)
    np.add.at(sq, (x * x) % p, 1)
    return 1 + int(sq[rhs].sum())

def find_curve(start):
    p = start
    while True:
        p += 1
        if p % 3 == 1 and p % 4 == 3 and is_prime(p):
            n = count_points(p)
            if is_prime(n):
                return p, n

def sqrt_mod(a, p):
    return pow(a, (p + 1) // 4, p)

def make(p, n, b=7):
    O = None
    def add(P, Q):
        if P is O: return Q
        if Q is O: return P
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return O
        if P == Q:
            l = 3 * P[0] * P[0] * pow(2 * P[1], p - 2, p) % p
        else:
            l = (Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p) % p
        x3 = (l * l - P[0] - Q[0]) % p
        return (x3, (l * (P[0] - x3) - P[1]) % p)
    def mul(k, P):
        k %= n; R = O
        while k:
            if k & 1: R = add(R, P)
            P = add(P, P); k >>= 1
        return R
    x = 1
    while True:
        rhs = (x ** 3 + b) % p
        y = sqrt_mod(rhs, p)
        if y * y % p == rhs and y != 0:
            return add, mul, (x, y)
        x += 1
