"""
run_tests.py -- run every check that does NOT need Docker.

  python run_tests.py

Covers: constants agreement (3 copies), the external anchor against the Hydra
authors' reference, rejection-branch injection tests, and re-verification of
the frozen vectors against the oracle.

The differential test against bip32-hydra.mpc itself needs MP-SPDZ and is a
separate, Docker-based step -- see README.md.
"""

import json
import subprocess
import sys

from oracle import thesis_oracle, KeyEnc, InEnc


def replay_frozen_vectors():
    """Recompute every frozen vector with the oracle and compare to the file.
    Catches accidental edits to test_vectors.json or drift in oracle.py."""
    print("Replaying frozen vectors (oracle vs test_vectors.json)")
    try:
        data = json.load(open("test_vectors.json"))
    except FileNotFoundError:
        print("  [SKIP] test_vectors.json not present -- run the "
              "differential step first")
        return 0
    o = thesis_oracle()
    bad = []
    for v in data["vectors"]:
        inp = v["input"]
        if v["mode"] == "prf":
            got = o.E_K(inp["K"], inp["m"], t=4)
        else:
            got = o.E_K(KeyEnc(inp["k_par"], inp["c_par"]),
                        InEnc(inp["index"]), t=4)
        if got != v["oracle"] or got != v["mpc"]:
            bad.append(v["id"])
    if bad:
        print(f"  [FAIL] {len(bad)} vector(s) do not replay: {bad}")
        return 1
    print(f"  [PASS] all {len(data['vectors'])} frozen vectors replay exactly")
    print(f"  [{'PASS' if data['all_match'] else 'FAIL'}] "
          f"recorded all_match = {data['all_match']}")
    return 0 if data["all_match"] else 1


def replay_poc_vectors():
    """Re-derive every level of every frozen PoC case with the oracle
    (BIP32 additive rule) and compare words, k_child, final counter and
    attempt count."""
    from oracle import derive, KeyEnc, InEnc
    print("Replaying PoC vectors (oracle vs poc_vectors.json)")
    try:
        data = json.load(open("poc_vectors.json"))
    except FileNotFoundError:
        print("  [SKIP] poc_vectors.json not present")
        return 0
    o = thesis_oracle()
    bad = []
    for c in data["cases"]:
        inp = c["input"]
        k_par, c_par = int(inp["k_par"]), int(inp["c_par"])
        for lv in c["levels"]:
            if inp["force_ovf"] < 0:
                got = o.E_K(KeyEnc(k_par, c_par), InEnc(lv["index"]), t=4)
                if got != lv["words"]:
                    bad.append(f"{c['id']}/L{lv['level']}")
                continue
            r = derive(o, k_par, c_par, lv["index"],
                       force_ovf=inp["force_ovf"], force_bad=inp["force_bad"])
            if (r["words"] != lv["words"] or r["ctr_final"] != lv["ctr_final"]
                    or len(r["attempts"]) != lv["attempts"]
                    or str(r["k_child"]) != lv["k_child"]):
                bad.append(f"{c['id']}/L{lv['level']}")
            k_par, c_par = r["k_child"], r["c_child"]
    if bad:
        print(f"  [FAIL] do not replay: {bad}")
        return 1
    n = sum(len(c["levels"]) for c in data["cases"])
    print(f"  [PASS] all {n} PoC levels across {len(data['cases'])} cases "
          f"replay exactly")
    print(f"  [{'PASS' if data['all_match'] else 'FAIL'}] "
          f"recorded all_match = {data['all_match']}")
    return 0 if data["all_match"] else 1


def main():
    rc = 0
    for script in ("test_constants.py", "test_anchor.py", "test_rejection.py"):
        print(f"\n{'=' * 68}\n{script}\n{'=' * 68}")
        rc |= subprocess.call([sys.executable, script])
    print(f"\n{'=' * 68}\nfrozen vectors\n{'=' * 68}")
    rc |= replay_frozen_vectors()
    rc |= replay_poc_vectors()
    print(f"\n{'=' * 68}")
    print("ALL LOCAL CHECKS PASSED" if rc == 0 else "SOME CHECKS FAILED")
    print("(the MP-SPDZ differential step is separate -- see README.md)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
