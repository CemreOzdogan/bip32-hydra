# Benchmark results — Hydra vs HMAC-SHA512 (2026-11-02)

One hardened BIP32 child derivation, one attempt, on secret shares under
MP-SPDZ 0.2.8, `shamir-party.x` (semi-honest Shamir), all parties on one laptop
(i5-12450H, Docker/WSL2 with 4 cores and 8 GB). Both programs compute the full
BIP32 rule `k_child = (I_L + k_par) mod n` plus the one-bit validity verdict.

- **Hydra**: `poc_derive.mpc` (straight-line mode), arithmetic shares over F_p.
- **HMAC-SHA512**: `hmac_derive.mpc`, binary shares, Bristol SHA-512 circuit,
  4 compressions (2 per parent, reusable for all its children; 2 per child).
  Verified against Python's `hmac` on two random parents.

Raw data: `results/<experiment>.csv` (one row per run), `results/*_stats.csv`
(compiler counts). Re-run: `python bench.py baseline nodes bandwidth latency`.
Numbers are medians; p95 is in the CSVs.

## 1. Baseline (N = 5, T = 2, no network delay; 20 / 10 runs)

| | Hydra | HMAC-SHA512 | ratio |
|---|---|---|---|
| time per derivation | **0.155 s** (p95 0.166) | 2.59 s (p95 2.71) | 17× |
| └ per child only (pads reused) | 0.155 s | ~1.31 s | 8× |
| network rounds | **351** | 15,033 | 43× |
| data sent per party | 6.75 MB | **0.94 MB** | 0.14× |
| CPU time per party | **0.13 s** | 1.69 s | 13× |
| ≈ CPU cycles per party (×2.0–4.4 GHz) | 0.26–0.57 G | 3.4–7.4 G | |
| peak memory per party | 29 MB | 28 MB | ≈ |
| multiplications (compiler) | 10,120 triples + 24 squares + 768 bits | 234,348 AND (bit) triples | |
| compile (one-off) | 3.4 s, 117 MB RAM | 19.8 s, 972 MB RAM | |
| derivations / minute (sequential) | ~390 | ~23 (46 with pads reused) | |

Where Hydra's time goes: PRF 0.081 s (52%), §7 overflow test 0.015 s (10%),
§8 add mod n + verdict 0.057 s (37%). HMAC: per-child 1.22 s, per-parent pads
1.23 s, add mod n 0.08 s.

## 2. Latency (N = 5, T = 2; RTT emulated with `tc netem` on loopback)

| RTT | Hydra | HMAC-SHA512 | ratio |
|---|---|---|---|
| 0 ms | 0.155 s | 2.59 s | 17× |
| 1 ms | 0.35 s | 10.7 s | 30× |
| 5 ms | 1.23 s | 48.3 s | 39× |
| 10 ms | 2.33 s | 93.4 s | 40× |
| 25 ms | 5.38 s | — | |
| 50 ms | 9.99 s | — (≈ 460 s extrapolated) | |
| 100 ms | 19.3 s | — (≈ 915 s extrapolated) | |

Least-squares slopes: **Hydra 0.19 s per ms of RTT, HMAC 9.13 s per ms of
RTT**, i.e. each derivation waits for about 190 sequential round trips with
Hydra and about 9,100 with HMAC (MP-SPDZ's "rounds" counter is higher because
it counts message batches, not sequential round trips). The straight-line fit
is within 5% for RTT ≥ 5 ms; below that, local computation overlaps with the
delay and the fit overestimates. Communication time = time(RTT) − time(0): at
10 ms, 2.2 s for Hydra vs 91 s for HMAC. HMAC was not run above 10 ms (one run
would take 8–15 min); its 50 and 100 ms values are extrapolated from the fit
(2.2 s + 9.13 s × RTT).

Under latency the PRF dominates Hydra's time (71% at 100 ms: 13.7 of 19.3 s),
because it has the longest chain of dependent multiplications.

## 3. Bandwidth (N = 5, T = 2; `netem rate` on loopback)

| cap | Hydra | HMAC-SHA512 |
|---|---|---|
| 1000 Mbit/s | 0.35 s | 4.2 s |
| 100 Mbit/s | 2.79 s | 7.4 s |
| 10 Mbit/s | 28.3 s | 70.5 s |

Hydra sends 7× more data, so this is its weakest axis, but it is still faster at
every cap tested. Caveat: the cap applies to the loopback interface as a whole,
i.e. it is shared by all five parties' traffic (31.7 MB total for Hydra). Real
point-to-point links would each have their own capacity, so these numbers are
pessimistic for both.

## 4. Number of parties (no delay)

| N, T | Hydra time | rounds | MB/party | HMAC time | MB/party |
|---|---|---|---|---|---|
| 3, 1 | 0.064 s | 350 | 3.13 | 1.45 s | 0.47 |
| 5, 1 | 0.089 s | 350 | 5.55 | 1.70 s | 0.94 |
| 5, 2 | 0.155 s | 351 | 6.75 | 2.41 s | 0.94 |
| 7, 1 | 0.133 s | 350 | 7.96 | 2.29 s | 1.41 |
| 7, 2 | 0.230 s | 351 | 9.55 | 3.40 s | 1.41 |
| 7, 3 | 0.348 s | 352 | 11.20 | 4.64 s | 1.41 |
| 9, 4 | 0.687 s | 353 | 16.57 | 7.73 s | 1.87 |

- **Rounds barely depend on N or T** (Hydra 350–353, growing slightly with T;
  HMAC 15,033 throughout), so the latency results above carry over to any
  party count.
- "MB/party" is party 0's count (the log we record); for Hydra at N=5, T=2 all
  parties together sent 31.7 MB, i.e. ~6.3 MB per party on average.
- The N=5, T=2 HMAC time here (2.41 s) differs from section 1 (2.59 s) because
  these are separate runs (run-to-run variation); both are as measured.
- Data per party grows with both N and T for Hydra; for HMAC it is
  ≈ 0.47 MB × (N − 1)/2 and independent of T.
- Times for N > 4 are inflated by running all parties on 4 cores. Rounds and
  data are exact regardless; times should be read as relative.
- Hydra stays 11–23× faster across all settings.

## 5. Active security: MASCOT, N = 2 (added 2026-11-08)

`python bench.py mascot` → `results/mascot.csv`. Same bytecode, run with
`mascot-party.x -N 2`: Hydra on MASCOT's arithmetic shares, HMAC on MASCOT's
binary-share protocol (Tinier). Both outputs re-checked under MASCOT (Hydra on
2026-11-02, HMAC vs Python `hmac` on 2026-11-08).

| | Hydra | HMAC-SHA512 | ratio |
|---|---|---|---|
| time, no delay (5 runs) | 3.30 s | **1.95 s** | HMAC 1.7× faster |
| time, RTT 1 ms (3 / 2 runs) | **3.66 s** | 27.7 s | 7.6× |
| time, RTT 10 ms (3 / 2 runs) | **7.37 s** | 175.1 s | 24× |
| rounds | 660 | 31,374 | 48× |
| data, party 0 | 443 MB | 510 MB | Hydra 1.2× less |
| CPU per party | 3.29 s | 1.60 s | |
| peak memory | 197 MB | 78 MB | |

- **Without delay HMAC wins.** Hydra's PRF takes only 0.26 s; its §7/§8
  bit-level steps take 3.0 s, because shared random bits are expensive with
  active security. HMAC is all binary shares.
- **Slopes:** Hydra +0.41 s per ms of RTT, HMAC +17.3 s per ms, so Hydra is
  faster for any RTT above about 0.1 ms.
- 2 parties here vs 5 under Shamir: don't compare the two settings directly.

## 6. Active security, honest majority: malicious Shamir, N = 5, T = 2 (2026-11-14)

`python bench.py malshamir` → `results/malshamir.csv`. Binary
`malicious-shamir-party.x` (built into `thesishydra-bench`). Outputs verified:
PoC 9/9, HMAC vs Python `hmac`.

| | Hydra | HMAC-SHA512 | ratio |
|---|---|---|---|
| time, no delay (5 runs) | **0.330 s** | 3.14 s | 9.5× |
| time, RTT 1 ms (3 / 2 runs) | **0.458 s** | 11.0 s | 24× |
| time, RTT 10 ms (3 / 2 runs) | **1.80 s** | 93.4 s | 52× |
| rounds | 243 | 15,226 | 63× |
| data, party 0 | 22.1 MB | 53.4 MB | 2.4× less |
| data, all parties | 108.6 MB | 267.0 MB | |
| CPU per party | 0.24 s | 1.96 s | |
| peak memory | 39 MB | 32 MB | |

- Hydra wins everywhere, including data (it sent 7× more under semi-honest).
- Hydra needs fewer rounds than under semi-honest Shamir (243 vs 351) and is
  faster at 10 ms (1.80 vs 2.33 s); likely the different multiplication
  strategy (batched, checked triples). Not analysed further.
- Slopes: Hydra +0.15 s per ms RTT, HMAC +9.0 s per ms.
- Same protocol as Das et al.'s baseline (68.7 s at 10 ms per round, 1.40 s no
  delay, 104.59 MB total, 14-core M3 Max); ours 93.4 s / 3.14 s / 267 MB with
  the full HMAC (4 compressions + add) on 4 cores.

## 7. Full malicious-Shamir suite (2026-11-14) — now the thesis headline

`python bench.py malshamir_baseline malshamir_nodes malshamir_bandwidth
malshamir_latency` → `results/malshamir_*.csv` (181 runs, same settings as
sections 1–4). The thesis tables now show HMAC (malicious) | Hydra (malicious) |
ratio | Hydra (semi-honest, reference).

| | HMAC (mal) | Hydra (mal) | ratio | Hydra (semi) |
|---|---|---|---|---|
| time, no delay | 3.32 s | 0.327 s | 10× | 0.155 s |
| rounds | 15,226 | 243 | 63× | 351 |
| data P1 / all | 53.4 / 267 MB | 22.1 / 108.6 MB | 2.4× | 6.75 / 31.7 MB |
| RTT 10 ms | 93.8 s | 1.91 s | 49× | 2.33 s |
| RTT 100 ms | ≈912 s (extrap.) | 14.1 s | ≈65× | 19.3 s |
| 10 Mbit/s | 311.9 s | 92.2 s | 3.4× | 28.3 s |
| N = 3..9 | | | 8–16× | |

Fits: Hydra-mal 0.138 s/ms; HMAC-mal 3.0 s + 9.09 s/ms. Hydra-mal time without
delay: k_par bit decomposition 45%, PRF 24%, addition+verdict 23%, overflow 6%.

## Caveats (state these whenever citing the numbers)

1. All parties run on one machine; network effects are emulated.
2. Sections 1–4 are semi-honest Shamir (`malicious-shamir-party.x` is not
   built in the image). Active security only via MASCOT with 2 parties
   (section 5).
3. Shamir in MP-SPDZ does multiplication by local product + resharing, so
   there is no separate offline phase to split out; the "triples" are the
   compiler's multiplication count.
4. CPU cycles are estimated from CPU time × the clock range (2.0 GHz base to
   4.4 GHz boost); `perf` does not work inside Docker on WSL2.
5. One attempt per derivation; retries (probability ~2^-116) are not
   benchmarked.
6. Derivations run sequentially; batching several children per run is not
   measured yet.
