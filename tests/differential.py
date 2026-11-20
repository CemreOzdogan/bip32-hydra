"""
differential.py -- differential test of bip32-hydra.mpc against oracle.py.

Three phases, so the (slow) MP-SPDZ compile+run loop happens once:

  python differential.py emit                  -> writes cases.txt
  <docker ... bash /repo/tests/run_all.sh>          -> writes mpc_results.txt
  python differential.py compare mpc_results.txt

Input classes covered:
  A. the exact input bip32-hydra.mpc hardcodes (K=0, m=(2,1,1,1))
  B. random raw-PRF inputs (K, m) uniform in F_p^4
  C. random full Derive inputs (k_par, c_par, index) -- exercises KeyEnc/InEnc
  D. a multi-level derivation chain, each child fed back as the next parent

Rejection branches are handled separately in test_rejection.py: they are
statistically unreachable through the PRF (see README).
"""

import json
import random
import sys

from oracle import (P_THESIS, N_SECP, thesis_oracle, KeyEnc, InEnc,
                    serialize, scalars_from_words, child_scalar, derive)

SEED = 20260928
CHAIN_LEVELS = 3
N_RANDOM_PRF = 5
N_RANDOM_DERIVE = 4


def build_cases():
    """Deterministic given SEED. Returns a list of case dicts."""
    rng = random.Random(SEED)
    cases = []

    # A. the artifact's own hardcoded input
    cases.append({
        "id": "A0-hardcoded",
        "class": "A: bip32-hydra.mpc's hardcoded input",
        "mode": "prf",
        "K": [0, 0, 0, 0],
        "m": [2, 1, 1, 1],
    })

    # B. random raw PRF inputs
    for i in range(N_RANDOM_PRF):
        cases.append({
            "id": f"B{i}-random-prf",
            "class": "B: random raw PRF input",
            "mode": "prf",
            "K": [rng.randrange(P_THESIS) for _ in range(4)],
            "m": [rng.randrange(P_THESIS) for _ in range(4)],
        })

    # C. random full Derive inputs
    for i in range(N_RANDOM_DERIVE):
        cases.append({
            "id": f"C{i}-random-derive",
            "class": "C: random Derive (KeyEnc/InEnc exercised)",
            "mode": "derive",
            "k_par": rng.randrange(2**256),
            "c_par": rng.randrange(2**256),
            "index": rng.randrange(2**31, 2**32),
        })

    # D. multi-level chain: each level's child becomes the next level's parent.
    o = thesis_oracle()
    k_par = rng.randrange(1, N_SECP)          # a valid secp256k1 scalar
    c_par = rng.randrange(2**256)
    for lvl in range(CHAIN_LEVELS):
        index = rng.randrange(2**31, 2**32)
        cases.append({
            "id": f"D{lvl}-chain-level{lvl}",
            "class": "D: multi-level derivation chain",
            "mode": "derive",
            "k_par": k_par,
            "c_par": c_par,
            "index": index,
            "chain_level": lvl,
        })
        res = derive(o, k_par, c_par, index)
        # Feed the child forward. NOTE: the sec.8 child-scalar step is
        # oracle-only -- bip32-hydra.mpc does not implement it (see README).
        k_par, c_par = res["k_child"], res["c_child"]

    return cases


def case_to_cmdline(c):
    if c["mode"] == "prf":
        return "prf " + " ".join(str(x) for x in (c["K"] + c["m"]))
    k_hi, k_lo, c_hi, c_lo = KeyEnc(c["k_par"], c["c_par"])
    return f"derive {k_hi} {k_lo} {c_hi} {c_lo} {c['index']}"


def oracle_words(c):
    o = thesis_oracle()
    if c["mode"] == "prf":
        return o.E_K(c["K"], c["m"], t=4)
    return o.E_K(KeyEnc(c["k_par"], c["c_par"]), InEnc(c["index"]), t=4)


def emit():
    cases = build_cases()
    with open("cases.txt", "w") as f:
        for c in cases:
            f.write(f"{c['id']}\t{case_to_cmdline(c)}\n")
    with open("cases.json", "w") as f:
        json.dump(cases, f, indent=2)
    print(f"wrote cases.txt and cases.json ({len(cases)} cases, seed={SEED})")
    for c in cases:
        print(f"  {c['id']:24s} {c['class']}")


def parse_results(path):
    """Parse mpc_results.txt -> {case_id: [4 canonical field elements]}."""
    out, cur, words = {}, None, {}
    # utf-8-sig: PowerShell's Out-File -Encoding utf8 (PS 5.1) prepends a BOM,
    # which would otherwise corrupt the first CASE line.
    for line in open(path, encoding="utf-8-sig"):
        line = line.strip()
        if line.startswith("CASE "):
            cur, words = line.split(None, 1)[1], {}
        elif line.startswith("HARNESS_WORD "):
            _, idx, val = line.split()
            v = int(val)
            if v < 0:                      # MP-SPDZ signed display for v > p/2
                v += P_THESIS
            words[int(idx)] = v
        elif line == "HARNESS_END" and cur is not None:
            out[cur] = [words[i] for i in range(4)]
            cur = None
    return out


def compare(path):
    cases = build_cases()
    mpc = parse_results(path)
    o = thesis_oracle()

    rows, n_pass, n_fail, missing = [], 0, 0, []
    for c in cases:
        want = oracle_words(c)
        got = mpc.get(c["id"])
        if got is None:
            missing.append(c["id"])
            continue
        ok = got == want
        n_pass += ok
        n_fail += (not ok)
        row = {"id": c["id"], "class": c["class"], "mode": c["mode"],
               "oracle": want, "mpc": got, "match": ok}
        if c["mode"] == "prf":
            row["input"] = {"K": c["K"], "m": c["m"]}
        else:
            row["input"] = {"k_par": c["k_par"], "c_par": c["c_par"],
                            "index": c["index"]}
        # Serialization + secp256k1 layers (oracle-side; see README).
        acc, blob = serialize(want, P_THESIS)
        row["serialization"] = {"accepted": acc,
                                "I_hex": blob.hex() if acc else None}
        if acc:
            I_L, I_R = scalars_from_words(want)
            okc, kc = child_scalar(I_L, c["k_par"]) if c["mode"] == "derive" \
                else (None, None)                # BIP32: (I_L + k_par) mod n
            row["secp256k1"] = {"I_L": str(I_L), "I_R": str(I_R),
                                "accepted": okc,
                                "k_child": str(kc) if okc else None}
        rows.append(row)
        flag = "MATCH" if ok else "*** MISMATCH ***"
        print(f"  [{flag}] {c['id']:24s} {c['class']}")
        if not ok:
            for i, (a, b) in enumerate(zip(want, got)):
                mark = "" if a == b else "   <-- differs"
                print(f"        word {i}: oracle={a}{mark}")
                print(f"                 mpc   ={b}")

    print()
    print(f"  {n_pass} match, {n_fail} mismatch"
          + (f", {len(missing)} MISSING: {missing}" if missing else ""))

    with open("test_vectors.json", "w") as f:
        json.dump({
            "description": "Known-answer test vectors for bip32-hydra.mpc "
                           "(ao-prf_wProofs.tex Derive).",
            "prime": str(P_THESIS),
            "secp256k1_order": str(N_SECP),
            "seed": SEED,
            "generated_by": "oracle.py (independent cleartext reference), "
                            "cross-checked against bip32-hydra.mpc under "
                            "MP-SPDZ shamir-party.x -N 5 -T 2",
            "all_match": n_fail == 0 and not missing,
            "vectors": rows,
        }, f, indent=2)
    print("  wrote test_vectors.json")
    return 1 if (n_fail or missing) else 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    elif len(sys.argv) > 2 and sys.argv[1] == "compare":
        sys.exit(compare(sys.argv[2]))
    else:
        print(__doc__)
