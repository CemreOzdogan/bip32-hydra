"""
test_rejection.py -- validation of the two rejection branches.

WHY THIS IS NOT A DIFFERENTIAL TEST. Both rejection branches are statistically
unreachable by feeding inputs through the PRF:

  overflow  Pr[some c_j >= 2^128] = 1 - (2^128/p)^4 ~ 2^-116   (tex sec.7)
  I_L >= n  Pr                    = 1 - n/2^256      ~ 2^-128   (tex sec.8)

At ~2^-116 you would expect one hit per ~10^35 derivations. No test campaign
reaches that, so "generate inputs until the branch fires" is not an option.
The branches are therefore validated by DIRECT INJECTION of synthetic values
into the predicates and the retry loop, plus -- for the one predicate that
bip32-hydra.mpc implements differently from the oracle -- an EXHAUSTIVE
equivalence proof over the whole 385-element overflow band.

Scope note: the secp256k1 reduction of tex sec.8 is NOT implemented in
bip32-hydra.mpc at all, so its rejection rules can only be exercised oracle-
side. See README.md, "Coverage and its limits".
"""

import sys

from oracle import (P_THESIS, N_SECP, thesis_oracle, serialize,
                    scalars_from_words, child_scalar, derive)

REJECT_BAND = P_THESIS - 2**128          # == 385
results = []


def check(name, got, want):
    ok = got == want
    results.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"        got  {got!r}\n        want {want!r}")


def signed_display(v, p=P_THESIS):
    """How MP-SPDZ prints a field element: values > p/2 show as negative."""
    return v if v <= p // 2 else v - p


def main():
    print("Rejection-branch validation (injection, not reachable by sampling)")
    print(f"  overflow band = [2^128, p) = {REJECT_BAND} values\n")

    # ---- 1. serialization predicate, tex sec.7 ------------------------
    print("1. Serialization overflow rule (tex sec.7)")
    ok, _ = serialize([2**128 - 1] * 4, P_THESIS)
    check("largest in-range word (2^128 - 1) accepted", ok, True)
    ok, _ = serialize([2**128, 0, 0, 0], P_THESIS)
    check("word exactly 2^128 rejected", ok, False)
    ok, _ = serialize([P_THESIS - 1, 0, 0, 0], P_THESIS)
    check("word p-1 (top of band) rejected", ok, False)
    ok, _ = serialize([0, 0, 0, 2**128], P_THESIS)
    check("overflow in the LAST word also rejected", ok, False)
    ok, blob = serialize([1, 2, 3, 4], P_THESIS)
    check("accepted output is 512 bits", len(blob) * 8 if ok else None, 512)
    check("per-word encoding is big-endian (BIP32 byte order)",
          blob[:16].hex() if ok else None,
          (1).to_bytes(16, "big").hex())

    # ---- 1b. bytes <-> limbs round trip (tex sec.7 / sec.8, 2026-11-14) ---
    # The Brief's example: words (1, 0, ...) must give I_L = 2^128 both by
    # parse256 of the octet string and by the limb formula.
    print("\n1b. Octet string vs limb scalars (parse256 round trip)")
    import random
    from oracle import parse256, KeyEnc
    ok, blob = serialize([1, 0, 0, 0], P_THESIS)
    check("parse256(ser(1)||ser(0)) == 2^128 == limb formula",
          (parse256(blob[:32]), scalars_from_words([1, 0, 0, 0])[0]),
          (2**128, 2**128))
    rng = random.Random(20261114)
    edge = [0, 1, 2**64, 2**127, 2**128 - 1]
    trials = [[rng.choice(edge) for _ in range(4)] for _ in range(200)] + \
             [[rng.randrange(2**128) for _ in range(4)] for _ in range(2000)]
    rt_ok = True
    for w in trials:
        ok, blob = serialize(w, P_THESIS)
        I_L, I_R = scalars_from_words(w)
        # bytes -> scalars, scalars -> words (leading zeros kept: fixed 16 B)
        back = [int.from_bytes(blob[16*j:16*j+16], "big") for j in range(4)]
        rt_ok &= (ok and len(blob) == 64 and parse256(blob[:32]) == I_L
                  and parse256(blob[32:]) == I_R and back == w)
        # child chain code I_R re-enters the next level as limbs (c2, c3)
        K = KeyEnc(1, I_R)
        rt_ok &= (K[2], K[3]) == (w[2], w[3])
    check(f"{len(trials)} word vectors: bytes, parse256, limbs and KeyEnc agree",
          rt_ok, True)

    # ---- 2. equivalence with bip32-hydra.mpc's predicate --------------
    # bip32-hydra.mpc cannot reach this branch either, so instead of executing
    # it we prove its predicate equivalent to the specification's. It tests
    #     (displayed < 0) AND (displayed >= -REJECT_BAND)
    # where the spec tests canonical >= 2^128. Checked EXHAUSTIVELY over the
    # entire band plus a margin on both sides.
    print("\n2. bip32-hydra.mpc's REJECT_BAND predicate vs the spec rule")
    mismatches = []
    lo = 2**128 - 1000
    for v in range(lo, P_THESIS):
        spec = v >= 2**128
        disp = signed_display(v)
        mpc = (disp < 0) and (disp >= -REJECT_BAND)
        if spec != mpc:
            mismatches.append(v)
    check(f"exhaustive over [2^128-1000, p): {P_THESIS - lo} values, "
          f"band={REJECT_BAND}", mismatches, [])
    # and a spot check far below the band, where both must say "accept"
    far = [0, 1, 2**127, P_THESIS // 2]
    bad = [v for v in far
           if (v >= 2**128) != ((signed_display(v) < 0)
                                and (signed_display(v) >= -REJECT_BAND))]
    check("spot check well below the band", bad, [])

    # ---- 3. secp256k1 child-scalar rules, tex sec.8 -------------------
    print("\n3. secp256k1 child-scalar rules (tex sec.8) -- ORACLE ONLY")
    # BIP32 additive rule: k_child = (I_L + k_par) mod n, rejected if
    # I_L >= n or k_child == 0.
    K = 5
    ok, kc = child_scalar(N_SECP - 1, K)
    check("I_L = n-1 accepted, wraps: k_child = k_par - 1", (ok, kc), (True, K - 1))
    ok, _ = child_scalar(N_SECP, K)
    check("I_L = n rejected", ok, False)
    ok, _ = child_scalar(N_SECP + 1, K)
    check("I_L > n rejected", ok, False)
    ok, _ = child_scalar(2**256 - 1, K)
    check("I_L = 2^256-1 (largest serialisable) rejected", ok, False)
    ok, kc = child_scalar(0, K)
    check("I_L = 0 accepted (only k_child is zero-tested): k_child = k_par",
          (ok, kc), (True, K))
    ok, _ = child_scalar(N_SECP - K, K)
    check("I_L = n - k_par rejected: k_child == 0", ok, False)
    ok, _ = child_scalar(0, 0)
    check("I_L = 0, k_par = 0 rejected: k_child == 0", ok, False)
    ok, kc = child_scalar(N_SECP - K + 1, K)
    check("I_L = n - k_par + 1: wraps to k_child = 1", (ok, kc), (True, 1))
    ok, kc = child_scalar(12345, K)
    check("ordinary case: k_child = I_L + k_par", (ok, kc), (True, 12350))
    ok, kc = child_scalar(N_SECP - 1, N_SECP - 1)
    check("largest sum 2n-2 reduces to n-2", (ok, kc), (True, N_SECP - 2))
    # ---- 4. the retry loop actually advances the counter --------------
    print("\n4. Retry loop (tex Algorithm 1: ctr <- ctr + 1, continue)")

    class ScriptedOracle:
        """Returns a scripted word-vector per call, so the rejection path in
        derive() is genuinely executed rather than merely present."""
        p = P_THESIS

        def __init__(self, script):
            self.script = list(script)
            self.calls = 0

        def E_K(self, K, m, t=4):
            out = self.script[min(self.calls, len(self.script) - 1)]
            self.calls += 1
            return out

    good = [1, 2, 3, 4]
    # first attempt overflows, second is fine
    o = ScriptedOracle([[2**128, 0, 0, 0], good])
    r = derive(o, k_par=5, c_par=6, index=2**31)
    check("one overflow then success: 1 skip", r["skips"], 1)
    check("  counter advanced by 1", r["ctr_final"], 2**31 + 1)
    check("  first attempt recorded as overflow",
          r["attempts"][0]["reject"], "overflow")

    # two overflows then success
    o = ScriptedOracle([[2**128, 0, 0, 0], [0, 0, 0, P_THESIS - 1], good])
    r = derive(o, k_par=5, c_par=6, index=2**31)
    check("two overflows then success: 2 skips", r["skips"], 2)
    check("  counter advanced by 2", r["ctr_final"], 2**31 + 2)

    # I_L >= n then success: I_L = c0*2^128 + c1 must exceed n
    big = [2**128 - 1, 2**128 - 1, 0, 0]          # I_L = 2^256 - 1 > n
    I_L, _ = scalars_from_words(big)
    check("  constructed I_L really is >= n", I_L >= N_SECP, True)
    o = ScriptedOracle([big, good])
    r = derive(o, k_par=5, c_par=6, index=2**31)
    check("I_L >= n then success: 1 skip", r["skips"], 1)
    check("  rejection reason recorded", r["attempts"][0]["reject"], "I_L>=n")

    # k_child == 0 then success: I_L = n - k_par makes the sum exactly n
    zk = N_SECP - 5
    zero_words = [zk >> 128, zk & (2**128 - 1), 7, 8]
    o = ScriptedOracle([zero_words, good])
    r = derive(o, k_par=5, c_par=6, index=2**31)
    check("k_child == 0 then success: 1 skip", r["skips"], 1)
    check("  rejection reason recorded", r["attempts"][0]["reject"],
          "k_child==0")

    # accepted child key is (I_L + k_par) mod n, chain code is I_R
    o = ScriptedOracle([good])
    r = derive(o, k_par=5, c_par=6, index=2**31)
    I_L, I_R = scalars_from_words(good)
    check("accepted k_child == (I_L + k_par) mod n", r["k_child"],
          (I_L + 5) % N_SECP)
    check("accepted c_child == I_R", r["c_child"], I_R)

    # the test hook used by poc_derive.mpc: forced rejections advance ctr
    o = ScriptedOracle([good])
    r = derive(o, k_par=5, c_par=6, index=2**31, force_ovf=2, force_bad=1)
    check("hook: 2 forced overflow + 1 forced bad = 3 skips", r["skips"], 3)
    check("  counter advanced by 3", r["ctr_final"], 2**31 + 3)
    check("  reasons recorded in order",
          [x["reject"] for x in r["attempts"]],
          ["overflow(forced)", "overflow(forced)", "bad(forced)", None])

    # sanity: the happy path takes no skips
    o = ScriptedOracle([good])
    r = derive(o, k_par=5, c_par=6, index=2**31)
    check("no rejection: 0 skips, counter unchanged",
          (r["skips"], r["ctr_final"]), (0, 2**31))

    # ---- summary ------------------------------------------------------
    failed = [n for n, ok in results if not ok]
    print()
    if failed:
        print(f"REJECTION TESTS FAILED: {len(failed)}: {failed}")
        return 1
    print(f"ALL {len(results)} REJECTION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
