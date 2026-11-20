"""
test_anchor.py -- validate oracle.py against the Hydra authors' own
reference implementation (hydra.sage), at THEIR parameters.

The expected values below are verbatim output of `sage anchor.sage`, which
loads hydra.sage unmodified. See run_anchor.sh / README.md for how to
regenerate. The matrices are passed in as PARAMETERS (oracle.py deliberately
does not implement the SHAKE matrix search); everything else -- the round
constants, every round, the feed-forward, the truncation -- is computed by
oracle.py itself.

If this passes, oracle.py's PRF logic and its SHAKE128 round-constant
derivation are byte-exact against the authors' code at a prime and matrix set
that have nothing to do with this thesis.
"""

import sys
from oracle import HydraOracle, init_shake, gen_round_constants

P_AUTHORS = 170141183460469231731687303715884105773   # 2^127 + 45

MI_AUTHORS = [
    [148338975704289183078830725617480653087, 1, 1, 1],
    [81755400807643375524140152795819066604, 157510637476605425349690965550914172465, 1, 1],
    [144205323307769853887929355624798486816, 1, 134746447437603741985879507057763577037, 1],
    [97338312373589161471428904254291064221, 1, 1, 134886453377838965658537975854069066455],
]

MJ_AUTHORS = [
    [163601491807594223605198844291511598667, 1, 1, 1, 1, 1, 1, 1],
    [108514101966968812773805782140658587017, 155415696120173428700822693500116923621, 1, 1, 1, 1, 1, 1],
    [8074169233982186925081135419516962210, 1, 74584737185149108454918326386981402443, 1, 1, 1, 1, 1],
    [91999974057458503943175429222592370386, 1, 1, 9200069807639506447413581997606151775, 1, 1, 1, 1],
    [136490960659299672173109029955566650232, 1, 1, 1, 77516697531437935991848232396080275948, 1, 1, 1],
    [82403957467071892156650842781820313945, 1, 1, 1, 1, 60114992161939905182921775829234000138, 1, 1],
    [115367924998838323914257977331641616780, 1, 1, 1, 1, 1, 104563064919500699381072998579918933304, 1],
    [12423058366552370047591542822930846968, 1, 1, 1, 1, 1, 1, 42769761522049549139664467455313750226],
]

EXPECT_RCB0 = [50850035971646797898366487578164134579, 69082297024559148944758716228147811932,
               38510175028955187758180164646499368704, 160305654568359183701992988368717253435]
EXPECT_RCH0 = [111279543094850980990579100210160116626, 104556242376082957576929841583848136497,
               35604195575458590664509001865665229789, 143797209459700323813598137832045061704,
               95352107889765155754367132363474275109, 158729809622209513547616797114135967318,
               31235890585964056078739695668448963916, 47816327732580577028334550529999731901]

EXPECT_KS1 = [105501745672062905016195784675667515143, 14995242760504740738609113676332614977,
              114248437097472105425783463114770607797, 33642818330462079248225045533333605759,
              53075639832897045347417097084606252762]

EXPECT_KS2 = [26386912274975077312897637021682426131, 10016751175232503088911614309187001662,
              156757422106469143649747438343644377144, 103545889699850735907935642131906039470,
              135363439466639164826042997263577987956]

MK2 = [0x1234567890ABCDEF, 0xFEDCBA0987654321, 7, 2**100 + 3]
IV2 = [11, 22, 33]
N2 = 2**31


def main():
    failures = []
    o = HydraOracle(P_AUTHORS, MI_AUTHORS, MJ_AUTHORS, R_I=42, R_H=39)

    def check(name, got, want):
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            print(f"        got  {got}")
            print(f"        want {want}")
            failures.append(name)

    print("Anchor: oracle.py vs hydra.sage (Hydra authors' reference)")
    print(f"  prime  = {P_AUTHORS}  (= 2^127 + 45, the authors' own)")
    print(f"  d      = {o.d}")
    print(f"  R_I    = {o.R_I}, R_H = {o.R_H}")
    print()

    # SHAKE128 round-constant derivation, byte-exact.
    check("rc_B[0] (SHAKE round constants, body)", o.rc_B[0], EXPECT_RCB0)
    check("rc_H[0] (SHAKE round constants, head)", o.rc_H[0], EXPECT_RCH0)
    check("rc_B length", len(o.rc_B), 48)
    check("rc_H length", len(o.rc_H), 39)

    # Full PRF, all-zero key.
    ks1 = o.E_K([0, 0, 0, 0], [2, 1, 1, 1], t=5)
    check("keystream, K=0 IV=(1,1,1) N=2, t=5", ks1, EXPECT_KS1)

    # Full PRF, non-trivial key and input.
    ks2 = o.E_K(MK2, [N2] + IV2, t=5)
    check("keystream, non-trivial K/IV/N, t=5", ks2, EXPECT_KS2)

    print()
    if failures:
        print(f"ANCHOR FAILED: {len(failures)} check(s): {failures}")
        return 1
    print("ANCHOR PASSED -- oracle.py agrees with the authors' reference "
          "implementation at their own parameters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
