"""bitdec_check.py -- host driver for bitdec_check.mpc (review brief, issue 6).

    python bitdec_check.py [shamir|malshamir|mascot ...]   (default: all three)

Runs MP-SPDZ's BitDecFull at p = 2^128 + 385 on boundary and random values
and checks every opened decomposition: 129 bits, each 0 or 1, the integer
they form is < p (canonical), and it equals the decomposed value.  Also
reports how many decompositions had a set top bit (values >= 2^128).
Results go to bitdec_results.txt.  Uses one `docker run --rm` per protocol.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
P = 2**128 + 385
REPO = os.path.dirname(HERE)
IMAGE = os.environ.get("BIP32_HYDRA_IMAGE", "bip32-hydra")
EXPECTED = 13 * 20 + 200        # FIXED x REPS + N_RANDOM in bitdec_check.mpc


def run(proto):
    proc = subprocess.run(
        ["docker", "run", "--rm", "--tmpfs", "/tmp", "-e", f"PROTO={proto}",
         "-v", f"{REPO}:/repo:ro", IMAGE, "bash", "/repo/tests/run_bitdec.sh"],
        capture_output=True, text=True)
    return proc.stdout + proc.stderr


def check(out):
    n = bad = top = 0
    tags = set()
    errors = []
    done = "BD_DONE" in out
    # MP-SPDZ prints e.g. "Warning generated 10000 squares\n" into the same
    # stream, sometimes in the middle of a BD line; drop it to rejoin the line.
    out = re.sub(r"Warning[^\n]*\n", "", out)
    for line in out.splitlines():
        if not line.startswith("BD ") or line.startswith("BD_DONE"):
            continue
        fields = line.split()
        if len(fields) != 4:
            bad += 1
            errors.append("malformed: " + line[:120])
            continue
        _, tag, x, bits = fields
        x = int(x) % P                       # MP-SPDZ may print signed
        n += 1
        tags.add(tag)
        ok = len(bits) == 129 and set(bits) <= {"0", "1"}
        a = sum(int(b) << i for i, b in enumerate(bits)) if ok else None
        ok = ok and a < P and a == x
        top += ok and bits[128] == "1"
        if not ok:
            bad += 1
            errors.append(line[:120])
    return done, n, bad, top, len(tags), errors


def main():
    protos = sys.argv[1:] or ["shamir", "malshamir", "mascot"]
    report = []
    all_ok = True
    for proto in protos:
        print(f"running {proto} ...", flush=True)
        out = run(proto)
        done, n, bad, top, ntags, errors = check(out)
        t = [l for l in out.splitlines() if l.startswith("Time =")]
        ok = done and n == EXPECTED and bad == 0
        all_ok &= ok
        line = (f"{proto:10s} {'PASS' if ok else 'FAIL'}: {n} decompositions "
                f"({ntags} value groups), {bad} wrong, {top} with bit 128 set; "
                f"{t[0] if t else 'no time'}")
        print(line)
        report.append(line)
        report += ["  " + e for e in errors[:10]]
        if not done:
            report.append("  run did not finish:\n" + out[-1500:])
            print(out[-1500:])
    with open(os.path.join(HERE, "results", "bitdec_results.txt"), "w") as f:
        f.write("bitdec_check (MP-SPDZ BitDecFull, p = 2^128+385, 129 bits)\n")
        f.write("\n".join(report) + "\n")
    print("ALL PASS" if all_ok else "SOME FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
