#!/bin/bash
cd /mp-spdz; mkdir -p Programs/my_Programs
cp /host-mpspdz/Programs/my_Programs/hydra.mpc Programs/my_Programs/
./compile.py -P 170141183460469231731687303715884105773 Programs/my_Programs/hydra.mpc 8 1 > /out/compile_hydra_ref.log 2>&1
ls Programs/Schedules
./Scripts/setup-ssl.sh 2 > /dev/null 2>&1
for r in 1 2 3; do
  for i in 0 1; do ./mascot-party.x -N 2 -v -p $i hydra > /tmp/p$i.log 2>&1 & done; wait
  cp /tmp/p0.log /out/hydra_ref_mascot_r$r.log
  echo "== run $r"; grep -E "Expected|inverses|squares$|muls|depth|Correct|Error|^Data sent|Sending|Broadcast|Exchang|Passing|rounds" /tmp/p0.log
done
