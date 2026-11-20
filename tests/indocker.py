"""
indocker.py -- run one of the in-container drivers of this folder in the
bip32-hydra Docker image, with the repository mounted read-only at /repo.

  python indocker.py [--env KEY=VALUE ...] [--out FILE] <driver.sh> [args ...]

The driver's standard output is written to FILE (UTF-8) or printed. Using this
wrapper instead of a hand-written `docker run` avoids two platform pitfalls:
Git Bash on Windows rewrites bind-mount paths, and PowerShell 5 redirection
writes UTF-16.

Image: $BIP32_HYDRA_IMAGE, default "bip32-hydra" (see ../docker/Dockerfile).
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
IMAGE = os.environ.get("BIP32_HYDRA_IMAGE", "bip32-hydra")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    ap.add_argument("--out", help="write the driver's stdout to this file")
    ap.add_argument("driver", help="a run_*.sh file in this folder")
    ap.add_argument("args", nargs="*")
    a = ap.parse_args()
    if not os.path.exists(os.path.join(HERE, a.driver)):
        sys.exit(f"no such driver: {a.driver}")
    cmd = ["docker", "run", "--rm", "--tmpfs", "/tmp", "-v", f"{REPO}:/repo:ro"]
    for e in a.env:
        cmd += ["-e", e]
    cmd += [IMAGE, "bash", f"/repo/tests/{a.driver}"] + a.args
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(proc.stdout)
        print(f"wrote {a.out} ({len(proc.stdout.splitlines())} lines)")
    else:
        sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-3000:])
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
