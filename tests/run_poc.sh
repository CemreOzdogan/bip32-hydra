#!/bin/bash
# Compile + run poc_derive.mpc once per line of poc_cases.txt.
# Each line: <case_id><TAB><compile-time args for poc_derive.mpc>
# Env PROTO selects the protocol (same bytecode for all three):
#   shamir    (default) semi-honest Shamir, 5 parties, T = 2
#   malshamir malicious Shamir, 5 parties, T = 2 (needs the bip32-hydra
#             image, which has malicious-shamir-party.x)
#   mascot    MASCOT, 2 parties (active security, dishonest majority)
set -u
PRIME=340282366920938463463374607431768211841
CASES=${1:-/repo/tests/poc_cases.txt}
[ -f "$CASES" ] || CASES=/repo/tests/$CASES    # a bare name means tests/<name>
[ -f "$CASES" ] || { echo "NO_CASE_FILE $CASES"; exit 1; }
PROTO=${PROTO:-shamir}
case "$PROTO" in
  shamir)    PARTY="./shamir-party.x -N 5 -T 2";           NP=5 ;;
  malshamir) PARTY="./malicious-shamir-party.x -N 5 -T 2"; NP=5 ;;
  mascot)    PARTY="./mascot-party.x -N 2";                NP=2 ;;
  *) echo "unknown PROTO=$PROTO"; exit 1 ;;
esac
echo "PROTO $PROTO"

mkdir -p /mp-spdz/Programs/my_Programs
cp /repo/mpc/bip32-hydra.mpc /mp-spdz/Programs/my_Programs/
cp /repo/mpc/poc_derive.mpc /mp-spdz/Programs/my_Programs/
cd /mp-spdz
# The image's TLS certificates expire one month after it was built;
# make fresh ones for this run (all parties live in this container).
./Scripts/setup-ssl.sh 5 > /dev/null 2>&1

while IFS=$'\t' read -r CASE_ID CMD; do
  [ -z "${CASE_ID:-}" ] && continue
  echo "CASE $CASE_ID"
  if ! ./compile.py -P "$PRIME" Programs/my_Programs/poc_derive.mpc $CMD \
        > /tmp/c.log 2>&1; then
    echo "COMPILE_FAILED"; tail -25 /tmp/c.log; continue
  fi
  grep -A8 'Program requires' /tmp/c.log | sed 's/^/STATS /'
  for i in $(seq 0 $((NP - 1))); do
    timeout 3000 $PARTY -p $i poc_derive > /tmp/r$i.log 2>&1 &
  done
  wait
  sed -z -i -E 's/Warning generated [0-9]+ [a-z]+\n//g' /tmp/r0.log   # see README, MP-SPDZ version
  grep -E '^POC_|Data sent|Global data|^Time =' /tmp/r0.log \
    || { echo "RUN_FAILED"; tail -15 /tmp/r0.log; }
done < "$CASES"
echo "ALL_POC_DONE"
