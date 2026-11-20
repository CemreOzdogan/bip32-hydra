#!/bin/bash
# Compile + run limb_boundary.mpc (semi-honest Shamir, N = 5, T = 2).
# Host: python limb_boundary.py cases ; then this in the container ;
#       then python limb_boundary.py check limb_boundary_results.txt
set -u
PRIME=340282366920938463463374607431768211841
cd /mp-spdz
mkdir -p Programs/my_Programs
cp /repo/mpc/poc_derive.mpc /repo/tests/limb_boundary.mpc Programs/my_Programs/
cp /repo/mpc/bip32-hydra.mpc Programs/my_Programs/
./compile.py -P $PRIME Programs/my_Programs/limb_boundary.mpc /repo/tests/limb_boundary_cases.txt \
  > /tmp/c.log 2>&1 || { echo COMPILE_FAILED; tail -25 /tmp/c.log; exit 1; }
grep -A8 'Program requires' /tmp/c.log
./Scripts/setup-ssl.sh 5 > /dev/null 2>&1
for i in 0 1 2 3 4; do
  ./shamir-party.x -N 5 -T 2 -p $i limb_boundary > /tmp/r$i.log 2>&1 &
done
wait
sed -z -i -E 's/Warning generated [0-9]+ [a-z]+\n//g' /tmp/r0.log   # see README, MP-SPDZ version
grep -E '^LIMB|Data sent|^Time =' /tmp/r0.log
