# Third-party code and data

## Hydra (Grassi, Øygarden, Schofnegger, Walch)

Reference code for the paper "From Farfalle to Megafono via Ciminion: The PRF
Hydra for MPC Applications" (EUROCRYPT 2023, ePrint 2022/342), repository
<https://extgit.isec.tugraz.at/krypto/hydra>, commit
`ff1957ef4874c432d890734073df33f7d6077161` (2023-09-01).

- `hydra.sage` is **not** included. `scripts/fetch_third_party.py` downloads it
  from that commit into `third_party/` (SHA-256 checked). `tests/anchor.sage`
  loads it unmodified.
- `mpc/bip32-hydra.mpc` is **derived from** that repository's
  `MP-SPDZ/Programs/my_Programs/hydra.mpc`: the Hydra class is the designers'
  code, with our prime and matrices, renamed variables, and explicit Beaver
  multiplication steps (see "WHAT CHANGED FROM hydra.mpc" at the top of the file).

The Hydra repository states no licence. We publish `mpc/bip32-hydra.mpc` for
research use, with attribution to the Hydra authors, and it is not covered by
this repository's MIT licence. If the authors prefer different terms for it, we
will follow their wishes.

## MP-SPDZ

<https://github.com/data61/MP-SPDZ>, commit
`e76014e2e9f9a0b8d6c3dc629c80ae3410ad1e70`. Not included. `docker/Dockerfile`
clones it and builds it, together with its submodules (mpir, SimpleOT). Licence:
CSIRO Open Source Software Licence Agreement, a variation of the BSD/MIT licence,
with third-party components under the University of Bristol and COSIC-KU Leuven
licences (`License.txt` in that repository). The University of Bristol asks that
use of the software for scientific publications be reported to
OSI-notifications@bristol.ac.uk, quoting reference 1914.

## Bristol Fashion circuits

SHA-512 compression circuit `sha512.txt` from
<https://github.com/mkskeller/bristol-fashion>, commit
`908452826cbd67f9757850a4943871bf66574e48` (the commit MP-SPDZ `e76014e` pins as
its `Programs/Circuits` submodule). Not included. `scripts/fetch_third_party.py`
downloads it (SHA-256 checked). Licence: BSD-style, copyright University of
Bristol and COSIC-KU Leuven (`License.txt` in that repository).
