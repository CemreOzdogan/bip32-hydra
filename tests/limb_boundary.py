"""
limb_boundary.py -- boundary tests of the child-scalar limb routine
(paper-v3 Appendix C, Algorithm 3 / sec. C.1), added 2026-11-18 for
review item "Appendix C boundary tests" of paper-reviews-v3.md.

  python limb_boundary.py cases            -> writes limb_boundary_cases.txt
  python limb_boundary.py check <mpc log>  -> compares the MPC run with oracle.py

The MPC side (limb_boundary.mpc) runs poc_derive.mpc's own child_scalar,
ge_const and overflow_bit_and_limb_bits on chosen (I_L, k_par) pairs. The
expected result is oracle.child_scalar (BIP32's additive rule). For accepted
cases the two child limbs must match; for rejected ones only the opened
verdict is checked, since the candidate limbs of a rejected attempt are
never used.
"""
import random
import sys

from oracle import N_SECP, P_THESIS, child_scalar

M128 = (1 << 128) - 1
N = N_SECP
N_LO = N & M128


def cases():
    c = [
        ("IL_eq_n__kpar_1", N, 1),
        ("IL_eq_n__kpar_n-1", N, N - 1),
        ("IL_n+1__kpar_1", N + 1, 1),
        ("IL_2^256-1__kpar_n-1", 2**256 - 1, N - 1),   # largest S = 2^256+n-2
        ("IL_2^256-1__kpar_1", 2**256 - 1, 1),
        ("IL_n-1__kpar_n-1", N - 1, N - 1),             # largest valid S = 2n-2
        ("IL_n-1__kpar_1", N - 1, 1),                   # S = n -> k_child = 0
        ("IL_n-kpar__kpar_12345", N - 12345, 12345),    # S = n -> k_child = 0
        ("IL_n-kpar+1__kpar_12345", N - 12345 + 1, 12345),  # k_child = 1
        ("IL_0__kpar_1", 0, 1),
        ("IL_0__kpar_n-1", 0, N - 1),
        ("IL_2^128__kpar_n-1", 2**128, N - 1),          # S >= n with borrow
        ("IL_nlo__kpar_n-nlo", N_LO, N - N_LO),         # S = n exactly, lo limbs equal
        ("IL_2^256-n__kpar_n-1", 2**256 - N, N - 1),    # valid, S >= n
    ]
    rng = random.Random(20261118)
    for i in range(10):
        c.append((f"random_{i}", rng.randrange(N), rng.randrange(1, N)))
    for i in range(4):   # random S just above / below n
        k = rng.randrange(1, N)
        d = rng.randrange(1, 2**64)
        c.append((f"near_n_above_{i}", (N - k + d) % N, k))
        c.append((f"near_n_below_{i}", (N - k - d) % N, k))
    return c


def main():
    if sys.argv[1] == "cases":
        with open("limb_boundary_cases.txt", "w", newline="\n") as f:
            for name, il, kp in cases():
                f.write(f"{name} {il} {kp}\n")
        print(len(cases()), "cases written")
        return
    got = {}
    for line in open(sys.argv[2], encoding="utf-8", errors="replace"):
        t = line.split()
        if t and t[0] == "LIMB":
            # MP-SPDZ prints field elements above p/2 as negative numbers
            got[t[1]] = (t[2], int(t[3]), int(t[4]) % P_THESIS,
                         int(t[5]) % P_THESIS)
    fails = 0
    for name, il, kp in cases():
        ok, kc = child_scalar(il, kp)
        if name not in got:
            print("MISSING", name); fails += 1; continue
        ovf, bad, hi, lo = got[name]
        mpc_ok = bad == 0
        res = (ovf == "0") and (mpc_ok == ok) and \
              (not ok or ((hi << 128) | lo) == kc)
        fails += not res
        print(f"{'PASS' if res else 'FAIL'}  {name:26s} oracle "
              f"{'accept' if ok else 'reject'}  mpc {'accept' if mpc_ok else 'reject'}"
              + (f"  k_child match" if ok and res else ""))
    print(f"{len(cases()) - fails}/{len(cases())} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
