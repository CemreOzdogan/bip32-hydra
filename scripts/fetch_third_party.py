"""
fetch_third_party.py -- download the two third-party files this repository
uses but does not redistribute, at pinned versions, and check their SHA-256.

  python scripts/fetch_third_party.py

  third_party/hydra.sage            the Hydra designers' reference implementation,
                                    repository krypto/hydra at commit ff1957ef
                                    (used by tests/anchor.sage)
  third_party/circuits/sha512.txt   Bristol Fashion SHA-512 compression circuit,
                                    mkskeller/bristol-fashion at commit 9084528,
                                    the commit that MP-SPDZ e76014e pins
                                    (used by mpc/hmac_derive.mpc)

See THIRD_PARTY.md for their origin and terms.
"""

import hashlib
import os
import sys
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = [
    ("third_party/hydra.sage",
     "https://extgit.isec.tugraz.at/krypto/hydra/-/raw/"
     "ff1957ef4874c432d890734073df33f7d6077161/hydra.sage",
     "abea2cfc0373f285849a334173d9235f2763b448012147acd80c03545526714d"),
    ("third_party/circuits/sha512.txt",
     "https://raw.githubusercontent.com/mkskeller/bristol-fashion/"
     "908452826cbd67f9757850a4943871bf66574e48/sha512.txt",
     "43cadaa91b437e99173c9ffa33b20f49db80bb0c7993e5fcedb8de1388a25df2"),
]


def main():
    rc = 0
    for rel, url, sha in FILES:
        path = os.path.join(REPO, rel)
        if os.path.exists(path) and hashlib.sha256(open(path, "rb").read()).hexdigest() == sha:
            print(f"ok       {rel} (already present)")
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "bip32-hydra-fetch"})
        data = urllib.request.urlopen(req, timeout=60).read()
        got = hashlib.sha256(data).hexdigest()
        if got != sha:
            print(f"FAILED   {rel}: sha256 {got}, expected {sha}")
            rc = 1
            continue
        open(path, "wb").write(data)
        print(f"fetched  {rel} ({len(data)} bytes, sha256 ok)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
