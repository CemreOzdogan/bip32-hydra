#!/bin/bash
# Compile + run bitdec_check.mpc under one protocol (env PROTO, as run_poc.sh).
# Run from the host via bitdec_check.py.
set -u
PRIME=340282366920938463463374607431768211841
PROTO=${PROTO:-shamir}
case "$PROTO" in
  shamir)    PARTY="./shamir-party.x -N 5 -T 2";           NP=5 ;;
  malshamir) PARTY="./malicious-shamir-party.x -N 5 -T 2"; NP=5 ;;
  mascot)    PARTY="./mascot-party.x -N 2";                NP=2 ;;
  *) echo "unknown PROTO=$PROTO"; exit 1 ;;
esac
echo "PROTO $PROTO"
mkdir -p /mp-spdz/Programs/my_Programs
cp /repo/tests/bitdec_check.mpc /mp-spdz/Programs/my_Programs/
cd /mp-spdz
./Scripts/setup-ssl.sh 5 > /dev/null 2>&1
if ! ./compile.py -P "$PRIME" Programs/my_Programs/bitdec_check.mpc > /tmp/c.log 2>&1; then
  echo "COMPILE_FAILED"; tail -25 /tmp/c.log; exit 1
fi
for i in $(seq 0 $((NP - 1))); do
  timeout 3000 $PARTY -p $i bitdec_check > /tmp/r$i.log 2>&1 &
done
wait
grep -q 'BD_DONE' /tmp/r0.log || echo "RUN_FAILED"
# whole log: an MP-SPDZ warning can split a BD line, the parser rejoins it
cat /tmp/r0.log
