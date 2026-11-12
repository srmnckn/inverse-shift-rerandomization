# Rerandomizing Presignatures in Two-Party ECDSA with Multiplicatively Shared Nonces: code

Reference code for the experiments of Sections 3.3, 4.1 and 6.2 of the paper "Inverse-Shift Rerandomization for Two-Party ECDSA with Multiplicatively Shared Nonces" .

The code checks correctness and reproduces the attacks. It is not a production implementation and is not suitable for timing measurements: the elliptic-curve arithmetic is pure Python and not constant time, the MtA functionality, commitments and zero-knowledge proofs are modeled as ideal functionalities (a trusted computation), and there is no network and no malicious party. The paper does not report running times of the modified protocol.

## Files

- `toy/ec.py`: secp256k1 arithmetic, SHA-256 based hash, ECDSA verification, seeded sampling (`set_seed`).
- `toy/protocols.py`: the protocol of Xue et al. (CCS 2021), the protocol of Kocaman and Talibi Alaoui (IMACC 2023) and its inverse-shift variant (Section 4.2, Figure 1), and the protocol of Lindell (CRYPTO 2017) with its first three steps run offline, with and without the inverse shift (Section 6.2; the Paillier ciphertext is modeled by its plaintext modulo q). `sign_inv` implements the abort conditions of Section 4.2, marks each offline session as used before its online message (in memory only), and lets `P1` verify the signature under `Q` before output.
- `toy/experiments.py`: Section 3.3, first paragraph, and Section 6.2. Correctness of the five protocols, and the raw-signing form of the attack of Section 3.2 against each of them, on secp256k1.
- `toy/smallcurve.py`, `toy/small_curve_attacks.py`: scaled experiments on the curve y^2 = x^3 + 7 over F_p with p = 1048783 and prime group order q = 1050337. S1 (Section 3.3): the attack of Section 3.2 with hashed messages; N = 600 messages, U = 4 sessions, C = 8 multipliers; expected pairs N^2 U C / q ≈ 11. S2 (Section 4.1): correctness of the shifts of Cases 1 to 5. S3 (Section 4.1): with hashed messages and an equal budget, the three-list search of equation (eq:lists) against Case 1 (corrupted P1) and Case 3 (corrupted P2), and the two-list search against Case 5 (corrupted P2).

## Running

```
./run.sh [trials] [repetitions]
```

- `trials` (default 50): number of runs of each secp256k1 experiment.
- `repetitions` (default 20): number of repetitions of the scaled experiments S1 and S3.

Output goes to `results_experiments.txt` and `results_small_curve.txt`. With the defaults the run takes a few minutes.

## Seeds

- `experiments.py` uses the fixed seed 20261031 (an optional second argument of the script changes it).
- `small_curve_attacks.py` uses `random.seed(sd)` for repetition `sd = 0, ..., repetitions - 1`.

With the defaults, the output is:

```
Correctness (valid signatures / 50): Xue 50, IMACC 50, inverse shift 50, Lindell 50, Lindell with inverse shift 50
Raw-signing attack (successful / 50): Xue 50, IMACC 50, inverse shift 0, Lindell 50, Lindell with inverse shift 0
S1 plain   : mean pairs 12.5, forgeries 78/80, repetitions with a forgery 20/20
S1 inverse : mean pairs 12.5, forgeries 0/80, repetitions with a forgery 0/20
S2 (valid signatures / 200): Case 1: 200, Case 3: 200, Case 5: 200, Case 2: 0, Case 4: 0
S3 Case 1 (corrupted P1): mean solutions 3.29, repetitions with a forgery 97/100
S3 Case 3 (corrupted P2): mean solutions 3.14, repetitions with a forgery 96/100
S3 Case 5 (corrupted P2): mean solutions 0.03, repetitions with a forgery 3/100
```

## Requirements

Python 3.10 or later and NumPy (used by `smallcurve.py` to find the small curve).
