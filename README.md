# bip32-hydra

Code, tests and measurements for the paper **"Threshold Hardened Derivation for
BIP32-Style Wallets from the Hydra PRF"**.

This work builds on the reference implementation of the Hydra PRF by Grassi,
Øygarden, Schofnegger and Walch (<https://extgit.isec.tugraz.at/krypto/hydra>,
commit `ff1957ef`). `mpc/bip32-hydra.mpc` is adapted from their `hydra.mpc`, and
the tests check our implementation against their `hydra.sage`. We thank the
authors for making their code available.

The paper replaces HMAC-SHA512 in BIP32 hardened key derivation by the
MPC-friendly PRF Hydra, so that a threshold wallet can derive hardened children
on secret shares. This repository contains the MP-SPDZ programs that run the
derivation on shares, an independent cleartext implementation that checks them,
the HMAC-SHA512 baseline, and the benchmark scripts with every recorded run.

> **Warning: test code, not a wallet.** The programs are written for testing and
> measurement. The parent key is supplied when a program is compiled, and the
> test programs open the PRF output words together with the child key, which
> reveals the parent key (`k_child - I_L = k_par mod n`). Never use them with
> real keys.

## Layout

| Path | Contents |
|---|---|
| `mpc/bip32-hydra.mpc` | Hydra PRF on shares (paper §2.2, Appendix A–B) |
| `mpc/poc_derive.mpc` | the full hardened derivation on shares: PRF, overflow test, `(I_L + k_par) mod n`, validity test, retries, multi-level paths (Algorithms 1 and 3) |
| `mpc/hmac_derive.mpc` | baseline: BIP32 hardened derivation with HMAC-SHA512 on binary shares |
| `tests/` | cleartext reference (`oracle.py`), test vectors, differential tests, boundary tests, recorded outputs; see `tests/README.md` |
| `bench/` | benchmark driver, recorded results of every run (`bench/results/*.csv`), notes (`RESULTS.md`) |
| `docker/Dockerfile` | MP-SPDZ at the pinned commit, with the tools the benchmarks need |
| `scripts/fetch_third_party.py` | downloads the two third-party files this repository does not redistribute |

## Setup

Requirements: Docker, Python 3.8 or later, and internet access for the first two
steps. All commands below are run from the repository root unless a `cd` is shown.

```
python scripts/fetch_third_party.py      # hydra.sage and the SHA-512 circuit, SHA-256 checked
docker build -t bip32-hydra docker/      # builds MP-SPDZ; takes a while
```

The scripts use the image `bip32-hydra`; set `BIP32_HYDRA_IMAGE` to use another.

## Checks

The tests run from the `tests/` folder. `indocker.py` runs one of the in-container
drivers with the repository mounted read-only, and writes its output as UTF-8.

| What (paper) | Commands (in `tests/`) | Expected |
|---|---|---|
| checks without MPC: constants, rejection rules, anchor replay, frozen vectors | `python run_tests.py` | all pass |
| PRF on shares against the cleartext reference (§7.1) | `python differential.py emit`<br>`python indocker.py --out results/mpc_results.txt run_all.sh`<br>`python differential.py compare results/mpc_results.txt` | 13/13 match |
| full derivation on shares, incl. forced retries and 3-level paths (§7.1) | `python poc_differential.py emit`<br>`python indocker.py --env PROTO=shamir --out results/poc_results.txt run_poc.sh`<br>`python poc_differential.py compare results/poc_results.txt` | 9/9 cases match (`compare` rewrites `poc_vectors.json`, identically except for timings) |
| the same under malicious Shamir and MASCOT | `python indocker.py --env PROTO=malshamir --out results/poc_results_malshamir.txt run_poc.sh`<br>`python indocker.py --env PROTO=mascot --out results/poc_results_mascot.txt run_poc.sh poc_cases_mascot.txt`<br>`python poc_differential.py compare <file> --check-only` | 9/9 for malicious Shamir; 3/3 for MASCOT, whose case list is a subset, so `compare` lists the other six as missing |
| limb arithmetic at its boundaries (§7.1, Appendix C) | `python limb_boundary.py cases`<br>`python indocker.py --out results/limb_boundary_results.txt run_limb_boundary.sh`<br>`python limb_boundary.py check results/limb_boundary_results.txt` | 32/32 pass |
| bit decomposition of MP-SPDZ, 3 protocols (Appendix D.3) | `python bitdec_check.py` | 460/460 per protocol |
| HMAC-SHA512 baseline against Python's `hmac` (§7.2) | `python check_hmac.py` | all match |
| cleartext reference against the Hydra designers' `hydra.sage` | `BIP32_HYDRA_IMAGE=sagemath/sagemath:latest python indocker.py run_anchor.sh` | prints the `ANCHOR_*` values that `test_anchor.py` checks |

On Windows PowerShell, set the variable with `$env:BIP32_HYDRA_IMAGE = "sagemath/sagemath:latest"`.

## Benchmarks

`bench/bench.py <experiment>` runs one experiment in a single container, with
network delay and bandwidth emulated by `tc netem` on the loopback interface, and
writes one row per run to `bench/results/<experiment>.csv` (this **overwrites**
the recorded file of that name). `python bench.py summary <experiment>` prints
medians from a recorded file without running anything.

| Paper table | Experiments (in `bench/`) |
|---|---|
| Table 2, one derivation | `malshamir_baseline` (malicious Shamir), `baseline` (semi-honest) |
| Table 3, network latency | `malshamir_latency`, `latency`; the HMAC-SHA512 entries with 5 runs and the 25 ms run are `rerun_malshamir_latency` (and `rerun_latency` for the semi-honest HMAC-SHA512 figure of §7.7) |
| Table 4, time per part | the timer columns of the Table 2 and Table 3 runs (`summary` prints them) |
| Table 5, bandwidth | `malshamir_bandwidth`, `bandwidth` |
| Table 6, parties and threshold | `malshamir_nodes`, `nodes` |
| Table 7, MASCOT | `mascot`; HMAC-SHA512 with delay is `rerun_mascot` |
| Table 8, rounds by message type | verbose runs recorded in `bench/results/logs_2026-11-18/` (the `runs.sh` there was written for an earlier folder layout) |

`smoke`, `malshamir` and `mascot_probe` are early or short experiments, kept for the
record. Times depend on the machine; rounds, data and multiplication counts do not.
The paper's runs used one laptop (Intel Core i5-12450H, Docker with 4 cores and
8 GB of memory).

## MP-SPDZ version

The paper's measurements used the copy of MP-SPDZ that the Hydra designers
distribute with their reference code (repository `krypto/hydra`, commit
`ff1957ef`), which their README describes as version 0.2.8, commit
`e76014e2e9f9a0b8d6c3dc629c80ae3410ad1e70`. Compared with upstream at that commit,
the copy differs in three files:

- `CONFIG` adds `CFLAGS += -DINSECURE` ("For benchmarking");
- `Protocols/ReplicatedPrep.hpp` prints "Warning generated N triples/squares/inverses";
- `Makefile` adds an `offline-party.x` target and drops the submodule fetches.

In this version, `-DINSECURE` enables insecure shortcuts only for reading
preprocessing from files and for options our runs do not use (unencrypted
channels, fake base OTs). Each such shortcut prints `WARNING: insecure ...` when
taken, and none appears in our logs. `docker/Dockerfile` builds upstream at
commit `e76014e` unchanged, without `-DINSECURE`. With that image every check
above passes, and rounds, data and compiler counts (10,120 triples per
derivation) are identical to the recorded runs under all three protocols; only
the times vary.

## Names

`mpc/bip32-hydra.mpc` is the file that was called `thesisHydra.mpc` during
development. Its code is unchanged; only its header comment was brought up to
date with the paper. Its `program.name` is still `thesisHydra`, so the compiled
stand-alone demo runs as `shamir-party.x ... thesisHydra`. That demo opens the
PRF output and serializes it little-endian, an earlier convention; the paper and
`poc_derive.mpc` use big-endian. Comments in `tests/` refer to the thesis draft from which
the paper was written (`ao-prf_wProofs.tex`); its §7 and §8 are the paper's §4.3
(serialization) and §4.4 (mapping to secp256k1 scalars).

## Licence

The code written for this project is under the MIT licence (`LICENSE`), except
`mpc/bip32-hydra.mpc`, which is derived from the Hydra designers' `hydra.mpc`.
`THIRD_PARTY.md` lists the third-party code and data and their terms.

## Citation

If you use this code, please cite the paper (reference to be added on publication).
