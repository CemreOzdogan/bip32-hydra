#!/bin/bash
# Compile + run hmac_derive.mpc with reveal = 1 (the test hook that opens the
# child) once per line of the case file, under semi-honest Shamir, N = 5, T = 2.
# Each line: <case_id><TAB><k_par> <c_par> <index> 1
# Host side: python check_hmac.py (writes the cases, runs this, compares).
set -u
PRIME=340282366920938463463374607431768211841
CASES=${1:-/repo/tests/hmac_cases.txt}
[ -f "$CASES" ] || CASES=/repo/tests/$CASES    # a bare name means tests/<name>
[ -f "$CASES" ] || { echo "NO_CASE_FILE $CASES"; exit 1; }
cd /mp-spdz
mkdir -p Programs/my_Programs Programs/Circuits
cp /repo/mpc/hmac_derive.mpc Programs/my_Programs/
cp /repo/third_party/circuits/sha512.txt Programs/Circuits/
./Scripts/setup-ssl.sh 5 > /dev/null 2>&1
while IFS=$'\t' read -r CASE_ID CMD; do
  [ -z "${CASE_ID:-}" ] && continue
  echo "CASE $CASE_ID"
  if ! ./compile.py -P "$PRIME" Programs/my_Programs/hmac_derive.mpc $CMD \
        > /tmp/c.log 2>&1; then
    echo "COMPILE_FAILED"; tail -15 /tmp/c.log; continue
  fi
  for i in 0 1 2 3 4; do
    timeout 3000 ./shamir-party.x -N 5 -T 2 -p $i hmac_derive > /tmp/r$i.log 2>&1 &
  done
  wait
  sed -z -i -E 's/Warning generated [0-9]+ [a-z]+\n//g' /tmp/r0.log   # see README, MP-SPDZ version
  grep -E '^HMAC_' /tmp/r0.log || { echo "RUN_FAILED"; tail -10 /tmp/r0.log; }
done < "$CASES"
echo "ALL_HMAC_DONE"
