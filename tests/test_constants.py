"""
test_constants.py -- check that the three copies of the frozen parameters
agree: constants.json (transcribed from the tex), oracle.py, and
bip32-hydra.mpc.

bip32-hydra.mpc stores M_I and M_J in a DIFFERENT representation: hydra.mpc's
optimized "sparse" form, in which every entry outside column 0 and the diagonal
is implicitly 1, and the stored value at those two positions is (actual - 1).
That conversion was originally done by hand. This file re-derives it
mechanically from the .mpc's own source text and checks it against the tex's
plain matrices, so the conversion is machine-verified rather than trusted.

bip32-hydra.mpc is only READ here, never imported or executed.
"""

import ast
import json
import os
import re
import sys

import oracle

MPC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "mpc", "bip32-hydra.mpc")
results = []


def check(name, got, want):
    ok = got == want
    results.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"        got  {got!r}\n        want {want!r}")


def parse_literal(src, name):
    """Pull a top-level `name = <literal>` assignment out of the .mpc source.

    Uses the AST rather than a regex: the matrices are multi-line nested lists,
    which no simple pattern matches reliably. The .mpc is parsed as Python
    text only -- never imported, never executed.
    """
    tree = ast.parse(src, filename=MPC_PATH)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return ast.literal_eval(node.value)
    raise LookupError(f"{name} not found as a top-level assignment in {MPC_PATH}")


def sparse_to_plain(code):
    """Invert hydra.mpc's storage convention: entries at column 0 and on the
    diagonal hold (actual - 1); everything else is literally 1."""
    n = len(code)
    return [[code[i][j] + 1 if (j == 0 or i == j) else code[i][j]
             for j in range(n)] for i in range(n)]


def main():
    cj = json.load(open("constants.json"))
    src = open(MPC_PATH, encoding="utf-8").read()

    print("A. constants.json (from the tex) vs oracle.py")
    check("prime", str(oracle.P_THESIS), cj["prime"])
    check("prime is 2^128 + 385", oracle.P_THESIS, 2**128 + 385)
    check("d", oracle.smallest_valid_d(oracle.P_THESIS), cj["d"])
    check("R_E1", oracle.R_E1, cj["R_E1"])
    check("R_E2", oracle.R_E2, cj["R_E2"])
    check("R_I", oracle.R_I_THESIS, cj["R_I"])
    check("R_H", oracle.R_H_THESIS, cj["R_H"])
    check("M_E", oracle.M_E, cj["M_E"])
    check("M_I", oracle.M_I_THESIS, cj["M_I"])
    check("M_J", oracle.M_J_THESIS, cj["M_J"])
    check("delta_0", str(oracle.DELTA_0), cj["delta_0"])
    check("delta_0 derives from the ASCII tag",
          int.from_bytes(cj["domain_tag_string"].encode("ascii"), "little"),
          int(cj["delta_0"]))
    check("secp256k1 n", str(oracle.N_SECP), cj["secp256k1_order_n"])
    check("n == n_hi*2^128 + n_lo",
          int(cj["n_hi"], 16) * 2**128 + int(cj["n_lo"], 16),
          int(cj["secp256k1_order_n"]))
    check("overflow band = p - 2^128",
          oracle.P_THESIS - 2**128, cj["overflow_band_size"])

    print("\nB. bip32-hydra.mpc's own copies vs the tex")
    check("THESIS_PRIME", parse_literal(src, "THESIS_PRIME"),
          int(cj["prime"]))
    check("BIP32_HYDRA_TAG", parse_literal(src, "BIP32_HYDRA_TAG"),
          int(cj["delta_0"]))
    check("REJECT_BAND", parse_literal(src, "REJECT_BAND"),
          cj["overflow_band_size"])

    print("\nC. bip32-hydra.mpc's sparse matrices reconstruct to the tex's")
    prec_mi = parse_literal(src, "PREC_M_I")
    prec_mj = parse_literal(src, "PREC_M_J")
    check("PREC_M_I -> M_I", sparse_to_plain(prec_mi), cj["M_I"])
    check("PREC_M_J -> M_J", sparse_to_plain(prec_mj), cj["M_J"])
    # Guard the inversion itself: off-diagonal, non-column-0 entries must all
    # be exactly 1, or the convention does not apply.
    off = [(i, j) for i, row in enumerate(prec_mj)
           for j, v in enumerate(row) if j != 0 and i != j and v != 1]
    check("PREC_M_J off-structure entries are all 1", off, [])

    failed = [n for n, ok in results if not ok]
    print()
    if failed:
        print(f"CONSTANT CHECKS FAILED: {len(failed)}: {failed}")
        return 1
    print(f"ALL {len(results)} CONSTANT CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
