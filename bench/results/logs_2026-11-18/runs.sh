#!/bin/bash
# v3 review runs: item 3 (Hydra reference depth), item 10 (verbose round types),
# item 11 (-Q bits from squares under malicious Shamir). Logs go to /out.
set -u
P_OURS=340282366920938463463374607431768211841
P_HYDRA=170141183460469231731687303715884105773
cd /mp-spdz
mkdir -p Programs/my_Programs
cp /host-mpspdz/Programs/my_Programs/thesisHydra.mpc /verify/poc_derive.mpc \
   /host-mpspdz/Programs/my_Programs/hydra.mpc Programs/my_Programs/

runN() {  # $1 = tag, $2 = N, rest = party command without -p
  local tag=$1 N=$2; shift 2
  for i in $(seq 0 $((N - 1))); do
    "$@" -p $i > /tmp/$tag.p$i.log 2>&1 &
  done
  wait
  cp /tmp/$tag.p0.log /out/$tag.log
  echo "== $tag"; grep -E "^Data sent|^Global data|^Time =|depth|Expected|Correct|Error" /out/$tag.log
}

echo "#### item 3: authors' hydra.mpc, t=8, squares, MASCOT N=2"
./compile.py -P $P_HYDRA Programs/my_Programs/hydra.mpc 8 1 > /out/compile_hydra_ref.log 2>&1 \
  || { echo COMPILE_FAILED hydra; tail /out/compile_hydra_ref.log; }
grep -A12 "Program requires" /out/compile_hydra_ref.log
./Scripts/setup-ssl.sh 5 > /dev/null 2>&1
for r in 1 2; do runN hydra_ref_mascot_r$r 2 ./mascot-party.x -N 2 -v hydra-8-1; done

echo "#### compile poc_derive"
./compile.py -P $P_OURS Programs/my_Programs/poc_derive.mpc $HYDRA_ARGS > /out/compile_poc.log 2>&1 \
  || { echo COMPILE_FAILED poc; tail /out/compile_poc.log; exit 1; }
grep -A12 "Program requires" /out/compile_poc.log

echo "#### item 10: verbose, N=5 T=2, no delay"
for r in 1 2 3; do runN sh_v_r$r 5 ./shamir-party.x -N 5 -T 2 -v poc_derive; done
for r in 1 2 3; do runN mal_v_r$r 5 ./malicious-shamir-party.x -N 5 -T 2 -v poc_derive; done

echo "#### item 11: malicious Shamir with -Q"
for r in 1 2; do runN malQ_v_r$r 5 ./malicious-shamir-party.x -N 5 -T 2 -Q -v poc_derive; done
echo RUNS_DONE
