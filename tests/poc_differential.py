"""
poc_differential.py -- differential test of poc_derive.mpc (the full Derive
on secret shares, BIP32 additive child rule) against oracle.py.

  python poc_differential.py emit                 -> poc_cases.txt
  <docker ... bash /repo/tests/run_poc.sh>             -> poc_results.txt
  python poc_differential.py compare poc_results.txt  -> poc_vectors.json

For every level of every case, four things must agree with the oracle:
the four PRF output words, the child key k_child = (I_L + k_par) mod n,
the final counter value, and the number of attempts. The last two are what
show the retry path ran the same way on both sides.
"""

import json
import random
import sys

from oracle import (P_THESIS, N_SECP, thesis_oracle, KeyEnc, derive,
                    child_scalar,
                    scalars_from_words, InEnc)

SEED = 20261005


def build_cases():
    rng = random.Random(SEED)

    def parent():
        return rng.randrange(1, N_SECP), rng.randrange(2**256)

    def idx():
        return rng.randrange(2**31, 2**32)

    cases = [
        dict(id="P0-zero-parent", note="KeyEnc(0,0)/index 2^31: the input "
             "bip32-hydra.mpc's own derive_demo uses",
             k_par=0, c_par=0, path=[2**31], fo=0, fb=0, edabit=0),
    ]
    for i in (1, 2):
        k, c = parent()
        cases.append(dict(id=f"P{i}-random-1level", note="random parent",
                          k_par=k, c_par=c, path=[idx()], fo=0, fb=0,
                          edabit=0))
    k, c = parent()
    cases.append(dict(id="P3-forced-retry", note="2 forced overflow + 1 "
                      "forced sec.8 rejection: retry loop executes 3 times",
                      k_par=k, c_par=c, path=[idx()], fo=2, fb=1, edabit=0))
    k, c = parent()
    cases.append(dict(id="P4-chain-3level", note="3-level chain; each child "
                      "(k_child, I_R) is the next level's parent",
                      k_par=k, c_par=c, path=[idx(), idx(), idx()], fo=0,
                      fb=0, edabit=0))
    k, c = parent()
    cases.append(dict(id="P5-chain-3level-forced", note="3-level chain with "
                      "1 forced overflow + 1 forced sec.8 rejection per level",
                      k_par=k, c_par=c, path=[idx(), idx(), idx()], fo=1,
                      fb=1, edabit=0))
    k, c = parent()
    cases.append(dict(id="P6-edabit", note="same pipeline with "
                      "program.use_edabit(True)",
                      k_par=k, c_par=c, path=[idx()], fo=0, fb=0, edabit=1))
    # cost accounting: one straight-line attempt, finite compiler counts
    k, c = parent()
    ix = idx()
    cases.append(dict(id="COST-straight", note="cost accounting, default",
                      k_par=k, c_par=c, path=[ix], fo=-1, fb=0, edabit=0))
    cases.append(dict(id="COST-straight-edabit", note="cost accounting, "
                      "edaBits", k_par=k, c_par=c, path=[ix], fo=-1, fb=0,
                      edabit=1))
    return cases


def cmdline(c):
    k_hi, k_lo, c_hi, c_lo = KeyEnc(c["k_par"], c["c_par"])
    fo = "straight" if c["fo"] < 0 else c["fo"]
    return " ".join(str(x) for x in
                    [k_hi, k_lo, c_hi, c_lo, fo, c["fb"], c["edabit"]]
                    + c["path"])


def emit():
    cases = build_cases()
    with open("poc_cases.txt", "w") as f:
        for c in cases:
            f.write(f"{c['id']}\t{cmdline(c)}\n")
    print(f"wrote poc_cases.txt ({len(cases)} cases, seed={SEED})")
    for c in cases:
        print(f"  {c['id']:24s} levels={len(c['path'])} "
              f"force=({c['fo']},{c['fb']}) edabit={c['edabit']}")


def canon(v):
    v = int(v)
    return v + P_THESIS if v < 0 else v


def parse(path):
    res, cur = {}, None
    for line in open(path, encoding="utf-8-sig"):
        t = line.split()
        if not t:
            continue
        if t[0] == "CASE":
            cur = t[1]
            res[cur] = {"levels": {}, "stats": {}, "net": {},
                        "status": "ok"}
        elif cur is None:
            continue
        elif t[0] in ("COMPILE_FAILED", "RUN_FAILED"):
            res[cur]["status"] = t[0]
        elif t[0] == "STATS" and len(t) >= 4 and t[-1] != "requires:":
            # "STATS  <count> integer <kind>" / "... virtual machine rounds"
            res[cur]["stats"][" ".join(t[2:])] = t[1]
        elif t[0] == "POC_LEVEL":
            lvl = int(t[1])
            res[cur]["levels"].setdefault(lvl, {"words": {}})
            res[cur]["levels"][lvl].update(ctr=int(t[5]), attempts=int(t[7]))
        elif t[0] == "POC_STRAIGHT":
            lvl = int(t[1])
            res[cur]["levels"].setdefault(lvl, {"words": {}})
            res[cur]["levels"][lvl].update(
                ovf=int(t[2].split("=")[1]), bad=int(t[3].split("=")[1]))
        elif t[0] == "POC_KCHILD":
            lvl = int(t[1])
            res[cur]["levels"].setdefault(lvl, {"words": {}})
            res[cur]["levels"][lvl]["k_child"] = \
                (canon(t[2]) << 128) | canon(t[3])
        elif t[0] == "POC_WORD":
            lvl, i = int(t[1]), int(t[2])
            res[cur]["levels"].setdefault(lvl, {"words": {}})
            res[cur]["levels"][lvl]["words"][i] = canon(t[3])
        elif line.startswith("Global data sent"):
            # Global data sent = <MB> MB (all parties)
            res[cur]["net"]["global_MB"] = float(t[4])
        elif line.startswith("Data sent"):
            # Data sent = <MB> MB in ~<rounds> rounds (party 0)
            res[cur]["net"]["party0_MB"] = float(t[3])
            res[cur]["net"]["rounds"] = int(t[6].lstrip("~"))
        elif t[0] == "Time":
            res[cur]["net"]["seconds"] = float(t[2])
    return res


def compare(path, write=True):
    cases = build_cases()
    mpc = parse(path)
    o = thesis_oracle()
    out_cases, n_ok, n_bad = [], 0, 0

    for c in cases:
        got = mpc.get(c["id"])
        print(f"\n  {c['id']}  ({c['note']})")
        if got is None or got["status"] != "ok":
            print(f"    *** {got['status'] if got else 'MISSING'} ***")
            n_bad += 1
            continue
        k_par, c_par = c["k_par"], c["c_par"]
        levels_out, case_ok = [], True

        for lvl, index in enumerate(c["path"]):
            g = got["levels"].get(lvl)
            if c["fo"] < 0:                       # straight-line cost case
                want = o.E_K(KeyEnc(k_par, c_par), InEnc(index), t=4)
                gw = [g["words"][i] for i in range(4)]
                I_L, _ = scalars_from_words(want)
                want_ovf = int(any(w >= 2**128 for w in want))
                ok_c, want_kc = child_scalar(I_L, k_par)
                want_bad = int(not ok_c)
                ok = (gw == want and g["ovf"] == want_ovf
                      and g["bad"] == want_bad
                      and (not ok_c or g.get("k_child") == want_kc))
                levels_out.append({"level": lvl, "index": index,
                                   "words": want, "ovf": want_ovf,
                                   "bad": want_bad,
                                   "k_child": str(want_kc), "match": ok})
                print(f"    [{'MATCH' if ok else 'MISMATCH'}] level {lvl}: "
                      f"words, ovf={g['ovf']}, bad={g['bad']}")
                case_ok &= ok
                continue

            r = derive(o, k_par, c_par, index,
                       force_ovf=c["fo"], force_bad=c["fb"])
            gw = [g["words"][i] for i in range(4)]
            want_attempts = len(r["attempts"])
            checks = {
                "words": gw == r["words"],
                "k_child": g.get("k_child") == r["k_child"],
                "ctr": g["ctr"] == r["ctr_final"],
                "attempts": g["attempts"] == want_attempts,
            }
            ok = all(checks.values())
            case_ok &= ok
            print(f"    [{'MATCH' if ok else 'MISMATCH'}] level {lvl}: "
                  f"ctr={g['ctr']} (oracle {r['ctr_final']}), "
                  f"attempts={g['attempts']} (oracle {want_attempts})"
                  + ("" if checks["words"] else "  WORDS DIFFER")
                  + ("" if checks["k_child"] else "  K_CHILD DIFFERS"))
            levels_out.append({
                "level": lvl, "index": index,
                "parent": {"k_par": str(k_par), "c_par": str(c_par)},
                "ctr_final": r["ctr_final"], "attempts": want_attempts,
                "rejections": [a["reject"] for a in r["attempts"][:-1]],
                "words": r["words"],
                "k_child": str(r["k_child"]), "c_child": str(r["c_child"]),
                "match": ok,
            })
            # the accepted child is the next level's parent
            k_par, c_par = r["k_child"], r["c_child"]

        n_ok += case_ok
        n_bad += (not case_ok)
        out_cases.append({
            "id": c["id"], "note": c["note"],
            "input": {"k_par": str(c["k_par"]), "c_par": str(c["c_par"]),
                      "path": c["path"], "force_ovf": c["fo"],
                      "force_bad": c["fb"], "edabit": c["edabit"]},
            "levels": levels_out, "match": case_ok,
            "compiler_stats": got["stats"], "runtime": got["net"],
        })

    print(f"\n  {n_ok} case(s) match, {n_bad} mismatch/failed")
    if not write:          # --check-only: keep the recorded vectors
        return 1 if n_bad else 0
    with open("poc_vectors.json", "w") as f:
        json.dump({
            "description": "Known-answer vectors for the FULL hardened Derive "
                           "(PRF + sec.7 + sec.8) executed on shares by "
                           "poc_derive.mpc, cross-checked against oracle.py.",
            "design": "BIP32 additive: k_child = (I_L + k_par) mod n, "
                      "c_child = I_R. Restored 2026-11-02 (option (b) "
                      "vectors archived as poc_vectors_v2_optionb.json).",
            "prime": str(P_THESIS), "secp256k1_order": str(N_SECP),
            "seed": SEED, "backend": "shamir-party.x -N 5 -T 2",
            "all_match": n_bad == 0,
            "cases": out_cases,
        }, f, indent=2)
    print("  wrote poc_vectors.json")
    return 1 if n_bad else 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    elif len(sys.argv) > 2 and sys.argv[1] == "compare":
        sys.exit(compare(sys.argv[2], write="--check-only" not in sys.argv))
    else:
        print(__doc__)
