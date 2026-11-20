#!/bin/bash
# Compile + run harness.mpc once per case listed in cases.txt.
# Each line of cases.txt: <case_id><TAB><mode> <args...>
set -u
PRIME=340282366920938463463374607431768211841

mkdir -p /mp-spdz/Programs/my_Programs
cp /repo/mpc/bip32-hydra.mpc /mp-spdz/Programs/my_Programs/
cp /repo/tests/harness.mpc /mp-spdz/Programs/my_Programs/harness.mpc
cd /mp-spdz
# The image's TLS certificates expire one month after it was built;
# make fresh ones for this run (all parties live in this container).
./Scripts/setup-ssl.sh 5 > /dev/null 2>&1

while IFS=$'\t' read -r CASE_ID CMD; do
  [ -z "${CASE_ID:-}" ] && continue
  echo "CASE $CASE_ID"
  if ! ./compile.py -P "$PRIME" Programs/my_Programs/harness.mpc $CMD > /tmp/c.log 2>&1; then
    echo "COMPILE_FAILED"; tail -5 /tmp/c.log; continue
  fi
  for i in 0 1 2 3 4; do
    ./shamir-party.x -N 5 -T 2 -p $i harness > /tmp/r$i.log 2>&1 &
  done
  wait
  sed -z -i -E 's/Warning generated [0-9]+ [a-z]+\n//g' /tmp/r0.log   # see README, MP-SPDZ version
  grep -E '^HARNESS_' /tmp/r0.log || { echo "RUN_FAILED"; tail -5 /tmp/r0.log; }
done < /repo/tests/cases.txt

echo "ALL_CASES_DONE"
