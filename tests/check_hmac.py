"""
check_hmac.py -- check the HMAC-SHA512 baseline (../mpc/hmac_derive.mpc)
against Python's hmac/hashlib, i.e. against BIP32 hardened derivation:

  I = HMAC-SHA512(c_par, 0x00 || ser256(k_par) || ser32(i))
  k_child = (I_L + k_par) mod n,  c_child = I_R

  python check_hmac.py            random parents (seed below), runs MP-SPDZ
  python check_hmac.py compare F  only compare a saved output file

Writes hmac_cases.txt and results/hmac_results.txt.
"""

import hashlib
import hmac
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SEED = 20261120
CASES = os.path.join(HERE, "hmac_cases.txt")
OUT = os.path.join(HERE, "results", "hmac_results.txt")


def bip32_hardened(k_par, c_par, i):
    data = b"\x00" + k_par.to_bytes(32, "big") + i.to_bytes(4, "big")
    I = hmac.new(c_par.to_bytes(32, "big"), data, hashlib.sha512).digest()
    I_L, I_R = int.from_bytes(I[:32], "big"), int.from_bytes(I[32:], "big")
    k_child = (I_L + k_par) % N
    bad = int(I_L >= N or k_child == 0)
    return bad, k_child, I_R


def cases():
    rng = random.Random(SEED)
    out = [("H0-small", 1, 0, 2**31)]
    for j in range(1, 4):
        out.append((f"H{j}-random", rng.randrange(1, N), rng.randrange(2**256),
                    rng.randrange(2**31, 2**32)))
    return out


def compare(path):
    want = {c[0]: bip32_hardened(*c[1:]) for c in cases()}
    got, cur = {}, None
    for line in open(path, encoding="utf-8-sig", errors="replace"):
        t = line.split()
        if not t:
            continue
        if t[0] == "CASE":
            cur = t[1]; got[cur] = {}
        elif cur and t[0] in ("HMAC_BAD", "HMAC_KCHILD", "HMAC_CCHILD"):
            got[cur][t[0]] = int(t[1]) % 2**256   # MP-SPDZ prints 256-bit values signed
    ok = True
    for cid, (bad, k, c) in want.items():
        g = got.get(cid, {})
        m = (g.get("HMAC_BAD") == bad and g.get("HMAC_KCHILD") == k
             and g.get("HMAC_CCHILD") == c)
        ok &= m
        print(f"{cid:10s} {'match' if m else 'MISMATCH'}")
    print("ALL MATCH" if ok else "FAILED")
    return 0 if ok else 1


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "compare":
        return compare(sys.argv[2])
    with open(CASES, "w", newline="\n") as f:
        for cid, k, c, i in cases():
            f.write(f"{cid}\t{k} {c} {i} 1\n")
    rc = subprocess.call([sys.executable, os.path.join(HERE, "indocker.py"),
                          "--out", OUT, "run_hmac_check.sh"])
    return rc or compare(OUT)


if __name__ == "__main__":
    sys.exit(main())
