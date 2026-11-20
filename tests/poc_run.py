"""
poc_run.py -- run the proof of concept (poc_derive.mpc) on YOUR inputs, with
one command, and check the result against the independent oracle.

Requires Docker Desktop running and the bip32-hydra image built.

EXAMPLES (from the tests folder, in PowerShell):

  # derive child 0' of a parent key / chain code
  python poc_run.py --k-par 0x1234...  --c-par 0xabcd...  --path 0h

  # a 3-level path  m/0'/5'/7'  (each level's child becomes the next parent)
  python poc_run.py --k-par 0x1234... --c-par 0xabcd... --path 0h 5h 7h

  # random parent, and watch the retry loop run: first 2 attempts forced to
  # fail the overflow check, the 3rd forced to fail the sec.8 check
  python poc_run.py --random --path 0h --force-ovf 2 --force-bad 1

  # the same derivation under another protocol (default: shamir)
  python poc_run.py --random --path 0h --protocol malshamir
  python poc_run.py --random --path 0h --protocol mascot

Protocols: shamir = semi-honest Shamir, 5 parties, T = 2 (default);
malshamir = malicious Shamir, 5 parties, T = 2 (uses the bip32-hydra
image, which has malicious-shamir-party.x); mascot = MASCOT, 2 parties.

Index notation: "5h" or "5'" means hardened index 2^31 + 5 (BIP32's 5').
A plain number is taken as-is and must already be in [2^31, 2^32).
k_par / c_par accept decimal or 0x-hex, each a 256-bit value.
"""

import argparse
import os
import random
import subprocess
import sys

from oracle import N_SECP, KeyEnc, derive, thesis_oracle
from poc_differential import parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
IMAGE = os.environ.get("BIP32_HYDRA_IMAGE", "bip32-hydra")
# malicious-shamir-party.x exists only in the thin benchmarking image
IMAGES = {"shamir": IMAGE, "mascot": IMAGE,
          "malshamir": IMAGE}
PROTO_TEXT = {"shamir": "5 parties, semi-honest Shamir",
              "malshamir": "5 parties, malicious Shamir",
              "mascot": "2 parties, MASCOT"}


def parse_index(s):
    s = s.strip()
    if s[-1] in "hH'":
        i = int(s[:-1])
        assert 0 <= i < 2**31, f"hardened index out of range: {s}"
        return 2**31 + i
    v = int(s, 0)
    assert 2**31 <= v < 2**32, f"{s} is not a hardened index (use e.g. 0h)"
    return v


def show_index(v):
    return f"{v - 2**31}' ({v})"


def main():
    ap = argparse.ArgumentParser(
        description="Run the full hardened Derive on secret shares "
                    "and check it against oracle.py.")
    ap.add_argument("--k-par", help="parent private key, 256-bit")
    ap.add_argument("--c-par", help="parent chain code, 256-bit")
    ap.add_argument("--random", action="store_true",
                    help="use a random valid parent key and chain code")
    ap.add_argument("--path", nargs="+", required=True,
                    help="hardened indices, e.g. 0h 5h 7h")
    ap.add_argument("--force-ovf", type=int, default=0,
                    help="TEST: force the first N attempts to fail sec.7")
    ap.add_argument("--force-bad", type=int, default=0,
                    help="TEST: then force M attempts to fail sec.8")
    ap.add_argument("--protocol", choices=sorted(IMAGES), default="shamir",
                    help="MPC protocol (default: shamir)")
    args = ap.parse_args()

    if args.random:
        rng = random.SystemRandom()
        k_par, c_par = rng.randrange(1, N_SECP), rng.randrange(2**256)
    elif args.k_par is not None and args.c_par is not None:
        k_par, c_par = int(args.k_par, 0), int(args.c_par, 0)
    else:
        ap.error("give --k-par and --c-par, or --random")
    assert 0 <= k_par < 2**256 and 0 <= c_par < 2**256
    path = [parse_index(s) for s in args.path]

    k_hi, k_lo, c_hi, c_lo = KeyEnc(k_par, c_par)
    cmd = " ".join(str(x) for x in [k_hi, k_lo, c_hi, c_lo, args.force_ovf,
                                    args.force_bad, 0] + path)
    case_file = os.path.join(HERE, "poc_run_case.txt")
    with open(case_file, "w", newline="\n") as f:
        f.write(f"RUN\t{cmd}\n")

    print(f"parent  k_par = {k_par:#066x}")
    print(f"        c_par = {c_par:#066x}")
    print(f"path    = " + " / ".join(show_index(i) for i in path))
    if args.force_ovf or args.force_bad:
        print(f"test hook: force {args.force_ovf} overflow + "
              f"{args.force_bad} sec.8 rejection(s) per level")
    print(f"\nrunning {PROTO_TEXT[args.protocol]} under MP-SPDZ "
          f"(compile + run, ~1 minute) ...")

    proc = subprocess.run(
        ["docker", "run", "--rm", "-e", f"PROTO={args.protocol}",
         "--tmpfs", "/tmp", "-v", f"{REPO}:/repo:ro",
         IMAGES[args.protocol], "bash", "/repo/tests/run_poc.sh",
         "/repo/tests/poc_run_case.txt"],
        capture_output=True, text=True)
    raw = os.path.join(HERE, "poc_run_output.txt")
    with open(raw, "w", encoding="utf-8") as f:
        f.write(proc.stdout + proc.stderr)
    if proc.returncode != 0 or "RUN_FAILED" in proc.stdout \
            or "COMPILE_FAILED" in proc.stdout:
        print("MP-SPDZ run failed -- see poc_run_output.txt")
        print(proc.stdout[-2000:], proc.stderr[-2000:])
        return 1

    got = parse(raw)["RUN"]
    o = thesis_oracle()
    kp, cp = k_par, c_par
    all_ok = True
    for lvl, index in enumerate(path):
        g = got["levels"][lvl]
        words = [g["words"][i] for i in range(4)]
        k_child = g["k_child"]                      # (I_L + k_par) mod n
        c_child = (words[2] << 128) | words[3]      # I_R
        r = derive(o, kp, cp, index, force_ovf=args.force_ovf,
                   force_bad=args.force_bad)
        ok = (words == r["words"] and k_child == r["k_child"]
              and g["ctr"] == r["ctr_final"]
              and g["attempts"] == len(r["attempts"]))
        all_ok &= ok
        print(f"\nlevel {lvl}: index {show_index(index)}")
        print(f"  attempts   {g['attempts']}  (accepted at counter "
              f"{show_index(g['ctr'])})")
        print(f"  k_child  = {k_child:#066x}")
        print(f"  c_child  = {c_child:#066x}")
        print(f"  oracle   : {'AGREES' if ok else '*** DISAGREES ***'}")
        kp, cp = r["k_child"], r["c_child"]

    n = got["net"]
    print(f"\nMPC cost: {n.get('seconds')} s, {n.get('party0_MB')} MB sent by "
          f"party 0, ~{n.get('rounds')} network rounds")
    print("\nRESULT:", "all levels agree with the oracle"
          if all_ok else "MISMATCH -- see above")
    print("(child keys are revealed here only so they can be checked; "
          "a real wallet would keep them shared)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
