# Tests

The MPC programs in `../mpc/` are checked against `oracle.py`, an independent
cleartext implementation of the derivation written from the specification, and
`oracle.py` is itself checked against the Hydra designers' reference code.
Commands are in the top-level `README.md`.

## Files

| File | What it is |
|---|---|
| `oracle.py` | cleartext reference: Hydra PRF, `KeyEnc`/`InEnc`, serialization with rejection, child key `(I_L + k_par) mod n`; standard library only |
| `constants.json` | the instance's parameters, transcribed from the paper |
| `anchor.sage`, `run_anchor.sh`, `test_anchor.py` | load the designers' `hydra.sage` unmodified and check that `oracle.py` reproduces it at the designers' own parameters, round constants included |
| `test_constants.py` | `constants.json`, `oracle.py` and `../mpc/bip32-hydra.mpc` agree (21 checks) |
| `test_rejection.py` | both rejection branches by injection, since sampling cannot reach them (36 checks) |
| `run_tests.py` | runs the three scripts above and replays the frozen vectors |
| `harness.mpc`, `run_all.sh`, `differential.py` | PRF on shares against `oracle.py` (13 cases) |
| `poc_differential.py`, `run_poc.sh` | full derivation on shares against `oracle.py` (9 cases, 13 levels: random and zero parents, forced retries, 3-level paths) |
| `poc_run.py` | derive children of your own test parent: `python poc_run.py --random --path 0h 7h` |
| `limb_boundary.mpc`, `limb_boundary.py`, `run_limb_boundary.sh` | the child-scalar limb arithmetic of `poc_derive.mpc` on 32 boundary pairs `(I_L, k_par)` |
| `bitdec_check.mpc`, `bitdec_check.py`, `run_bitdec.sh` | MP-SPDZ's bit decomposition on boundary and random values, under all three protocols |
| `check_hmac.py`, `run_hmac_check.sh` | the HMAC-SHA512 baseline against Python's `hmac` |
| `indocker.py` | runs a `run_*.sh` driver in the Docker image |
| `test_vectors.json`, `poc_vectors.json` | frozen vectors (inputs, oracle output, MPC output) |
| `cases.*`, `poc_cases*.txt`, `limb_boundary_cases.txt` | case lists written by the `emit`/`cases` steps (deterministic seeds) |
| `results/` | recorded outputs of the runs reported in the paper |

All field elements in the vector files are canonical, in `[0, p)`. MP-SPDZ prints
values above `p/2` as negative, and the parsers add `p` back. Large scalars are
stored as strings.

## Limits of the tests

1. `oracle.py` was written after reading `bip32-hydra.mpc`, so it is not a
   clean-room implementation, and agreement between the two cannot exclude an
   error common to both. The anchor against `hydra.sage` is the independent
   part, and it covers the PRF only.
2. The rejection branches have probability about `2^-117` and `2^-128`, so no
   sampled test reaches them. They are tested by injection (`test_rejection.py`)
   and by the test switch of `poc_derive.mpc` that forces the first attempts to
   be rejected.
3. Hydra's rolling function is never evaluated: with four output words only one
   head runs.
4. Every program here opens values that a real wallet would keep secret (see
   the warning in the top-level `README.md`).
