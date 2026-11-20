"""
bench.py -- benchmark Hydra (poc_derive.mpc) against the HMAC-SHA512 baseline
(hmac_derive.mpc) under MP-SPDZ, with minimal disk use.

  python bench.py <experiment> [<experiment> ...]
  python bench.py summary <experiment>          (re-print a saved summary)

Experiments: smoke, baseline, latency, nodes, bandwidth.

Disk use: one `docker run --rm` per experiment; compiled programs, logs and
certificates live in tmpfs (RAM) inside the container, so nothing is written
to Docker's disk image. On the host only results/<experiment>.csv (one row
per run) and results/<experiment>_stats.csv (compiler counts) are kept.

Both programs derive ONE hardened child of a fixed random parent, straight
line (one attempt): poc_derive.mpc with force_ovf = straight, and
hmac_derive.mpc with reveal = 0. Backends: shamir-party.x, malicious-shamir-party.x, mascot-party.x.
"""

import csv
import os
import random
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RESULTS = os.path.join(HERE, "results")
IMAGE = os.environ.get("BIP32_HYDRA_IMAGE", "bip32-hydra")
N_SECP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SEED = 20261102

ROW_FIELDS = ["label", "prog", "N", "T", "rtt_ms", "rate_mbit", "rep",
              "time_s", "t1_s", "t2_s", "t3_s", "t4_s", "party0_MB",
              "rounds", "global_MB", "cpu_avg_s", "cpu_max_s", "rss_max_KB"]


def max_T(n):
    return (n - 1) // 2


# label prog N T rtt_ms rate_mbit reps
EXPERIMENTS = {
    "smoke": [("hydra", "hydra", 5, 2, 0, 0, 2),
              ("hmac", "hmac", 5, 2, 0, 0, 1)],
    "baseline": [("hydra", "hydra", 5, 2, 0, 0, 20),
                 ("hmac", "hmac", 5, 2, 0, 0, 10)],
    "latency": [(f"{p}-rtt{r}", p, 5, 2, r, 0, reps)
                for p, rtts, reps in (("hydra", (1, 5, 10, 25, 50, 100), 5),
                                      ("hmac", (1, 5, 10), 2))
                for r in rtts],
    "nodes": [(f"{p}-N{n}-T{t}", p, n, t, 0, 0, reps)
              for p, reps in (("hydra", 10), ("hmac", 3))
              for n, t in ((3, 1), (5, 1), (5, 2), (7, 1), (7, 2), (7, 3),
                           (9, 4))],
    "bandwidth": [(f"{p}-{b}mbit", p, 5, 2, 0, b, reps)
                  for p, reps in (("hydra", 5), ("hmac", 3))
                  for b in (1000, 100, 10)],
    # Active security: MASCOT (dishonest majority), arithmetic shares for
    # Hydra, MASCOT's bit protocol (Tinier) for HMAC-SHA512. T is unused.
    "mascot_probe": [("hydra-mascot-N2", "hydra", 2, 0, 0, 0, 1, "mascot"),
                     ("hmac-mascot-N2", "hmac", 2, 0, 0, 0, 1, "mascot")],
    # Active security, honest majority: malicious Shamir (Lindell-Nof style),
    # same 5 parties and T = 2 as the semi-honest runs.
    "malshamir": [(f"{p}-malshamir-rtt{r}", p, 5, 2, r, 0, reps, "malshamir")
                  for p, plan in (("hydra", ((0, 5), (1, 3), (10, 3))),
                                  ("hmac", ((0, 5), (1, 2), (10, 2))))
                  for r, reps in plan],
    # Full malicious-Shamir suite, same settings as the semi-honest
    # experiments above, so the two can share tables column by column.
    "malshamir_baseline": [("hydra-mal", "hydra", 5, 2, 0, 0, 20, "malshamir"),
                           ("hmac-mal", "hmac", 5, 2, 0, 0, 10, "malshamir")],
    "malshamir_latency": [(f"{p}-mal-rtt{r}", p, 5, 2, r, 0, reps, "malshamir")
                          for p, rtts, reps in (("hydra", (1, 5, 10, 25, 50, 100), 5),
                                                ("hmac", (1, 5, 10), 2))
                          for r in rtts],
    "malshamir_nodes": [(f"{p}-mal-N{n}-T{t}", p, n, t, 0, 0, reps, "malshamir")
                        for p, reps in (("hydra", 10), ("hmac", 3))
                        for n, t in ((3, 1), (5, 1), (5, 2), (7, 1), (7, 2),
                                     (7, 3), (9, 4))],
    "malshamir_bandwidth": [(f"{p}-mal-{b}mbit", p, 5, 2, 0, b, reps, "malshamir")
                            for p, reps in (("hydra", 5), ("hmac", 3))
                            for b in (1000, 100, 10)],
    "mascot": [(f"{p}-mascot-rtt{r}", p, 2, 0, r, 0, reps, "mascot")
               for p, plan in (("hydra", ((0, 5), (1, 3), (10, 3))),
                               ("hmac", ((0, 5), (1, 2), (10, 2))))
               for r, reps in plan],
    # 2026-11-18 (paper-reviews-v3 item 8, reduced): fresh 5-run reruns of
    # the eight configurations that had only 2 runs, plus one measured
    # HMAC-SHA512 point at 25 ms under malicious Shamir. Same labels as the
    # original experiments; results go to rerun_*.csv, originals untouched.
    "rerun_latency": [(f"hmac-rtt{r}", "hmac", 5, 2, r, 0, 5)
                      for r in (1, 5, 10)],
    "rerun_malshamir_latency": [(f"hmac-mal-rtt{r}", "hmac", 5, 2, r, 0, reps,
                                 "malshamir")
                                for r, reps in ((1, 5), (5, 5), (10, 5), (25, 1))],
    "rerun_mascot": [(f"hmac-mascot-rtt{r}", "hmac", 2, 0, r, 0, 5, "mascot")
                     for r in (1, 10)],
}


def program_args():
    rng = random.Random(SEED)
    k_par, c_par = rng.randrange(1, N_SECP), rng.randrange(2**256)
    index = rng.randrange(2**31, 2**32)
    m = (1 << 128) - 1
    hydra = [k_par >> 128, k_par & m, c_par >> 128, c_par & m,
             "straight", 0, 0, index]
    hmac = [k_par, c_par, index, 0]
    return " ".join(map(str, hydra)), " ".join(map(str, hmac))


def run(name):
    cfg_rows = EXPERIMENTS[name]
    os.makedirs(RESULTS, exist_ok=True)
    cfg = os.path.join(HERE, f"_{name}.cfg")
    with open(cfg, "w", newline="\n") as f:
        for r in cfg_rows:
            f.write(" ".join(map(str, r)) + "\n")
    hydra_args, hmac_args = program_args()
    cmd = ["docker", "run", "--rm", "--cap-add", "NET_ADMIN",
           "--tmpfs", "/tmp", "--tmpfs", "/mp-spdz/Programs/Bytecode",
           "--tmpfs", "/mp-spdz/Programs/Schedules",
           "-e", f"HYDRA_ARGS={hydra_args}", "-e", f"HMAC_ARGS={hmac_args}",
           "-v", f"{REPO}:/repo:ro",
           IMAGE, "bash", "/repo/bench/run_bench.sh", f"/repo/bench/_{name}.cfg"]
    print(f"== {name}: {len(cfg_rows)} configurations, "
          f"{sum(r[6] for r in cfg_rows)} runs")
    rows, stats = [], []
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        t = line.split()
        if not t:
            continue
        if t[0] == "ROW":
            rows.append(dict(zip(ROW_FIELDS, t[1:])))
            r = rows[-1]
            print(f"  {r['label']:22s} rep {r['rep']:>2}: {r['time_s']} s, "
                  f"{r['rounds']} rounds, {r['party0_MB']} MB", flush=True)
        elif t[0] == "STAT":
            stats.append({"prog": t[1], "value": t[2],
                          "quantity": " ".join(t[3:])})
        else:
            print("  " + line.rstrip(), flush=True)
    proc.wait()
    os.remove(cfg)
    if rows:
        with open(os.path.join(RESULTS, f"{name}.csv"), "w",
                  newline="") as f:
            w = csv.DictWriter(f, fieldnames=ROW_FIELDS)
            w.writeheader()
            w.writerows(rows)
    if stats:
        with open(os.path.join(RESULTS, f"{name}_stats.csv"), "w",
                  newline="") as f:
            w = csv.DictWriter(f, fieldnames=["prog", "quantity", "value"])
            w.writeheader()
            w.writerows(stats)
    summary(name)
    return proc.returncode


def p95(xs):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]


def summary(name):
    path = os.path.join(RESULTS, f"{name}.csv")
    if not os.path.exists(path):
        print(f"no results for {name}")
        return
    rows = list(csv.DictReader(open(path)))
    labels = list(dict.fromkeys(r["label"] for r in rows))
    print(f"\n{name}: median over reps (p95 of time in brackets)")
    print(f"{'config':22s} {'time s':>15s} {'PRF/HMAC':>9s} {'§7/pads':>8s} "
          f"{'§8':>7s} {'rounds':>7s} {'MB/party':>9s} {'CPU s':>7s} "
          f"{'RSS MB':>7s}")
    for lb in labels:
        g = [r for r in rows if r["label"] == lb]
        med = lambda k: statistics.median(float(r[k]) for r in g
                                          if r[k] not in ("NA", ""))
        times = [float(r["time_s"]) for r in g]
        # hmac: t1 = per-parent pads, t2 = per-child HMAC, t3 = add mod n
        # hydra: t1 = PRF, t2 = sec.7, t3 = sec.8 (+ t4 = k_par bits)
        if g[0]["prog"] == "hmac":
            c1, c2, c3 = med("t2_s"), med("t1_s"), med("t3_s")
        else:
            c1, c2, c3 = med("t1_s"), med("t2_s"), med("t3_s") + med("t4_s")
        print(f"{lb:22s} {statistics.median(times):7.3f} [{p95(times):6.3f}]"
              f" {c1:9.3f} {c2:8.3f} {c3:7.3f} {med('rounds'):7.0f} "
              f"{med('party0_MB'):9.2f} {med('cpu_avg_s'):7.2f} "
              f"{med('rss_max_KB') / 1024:7.1f}")
    print("columns: hydra = PRF | sec.7 overflow | sec.8 (incl. k_par bits);"
          " hmac = per-child HMAC | per-parent pads | add mod n")


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "summary":
        summary(sys.argv[2])
    elif len(sys.argv) > 1 and all(a in EXPERIMENTS for a in sys.argv[1:]):
        rc = 0
        for a in sys.argv[1:]:
            rc |= run(a)
        sys.exit(rc)
    else:
        print(__doc__)
