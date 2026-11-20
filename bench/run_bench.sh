#!/bin/bash
# In-container benchmark runner. Everything it writes goes to tmpfs (RAM);
# stdout carries only STAT / ROW lines for the host to keep.
#
# Usage: run_bench.sh <config file>
# Config lines (whitespace-separated, # comments allowed):
#   label  prog(hydra|hmac)  N  T  rtt_ms  rate_mbit(0 = unlimited)  reps  [proto]
# proto: shamir (default; semi-honest, uses T), malshamir (malicious Shamir,
# honest majority, uses T) or mascot (active, dishonest majority; T is
# ignored). The same compiled bytecode runs under all three.
# Env: HYDRA_ARGS, HMAC_ARGS = compile-time args of the two programs.
set -u
CFG=$1
PRIME=340282366920938463463374607431768211841

cd /mp-spdz
mkdir -p Programs/my_Programs Programs/Circuits
cp /repo/third_party/circuits/sha512.txt Programs/Circuits/
cp /repo/mpc/bip32-hydra.mpc /repo/mpc/poc_derive.mpc \
   /repo/mpc/hmac_derive.mpc Programs/my_Programs/

compile() {   # $1 = prog label, $2 = file, rest = args
  local label=$1 file=$2; shift 2
  /usr/bin/time -f "%e %M" -o /tmp/ctime ./compile.py -P $PRIME \
      Programs/my_Programs/$file "$@" > /tmp/c_$label.log 2>&1 \
    || { echo "COMPILE_FAILED $label"; tail -15 /tmp/c_$label.log; exit 1; }
  read ce cm < /tmp/ctime
  echo "STAT $label $ce compile seconds"
  echo "STAT $label $cm compile peak KB"
  grep -A10 'Program requires' /tmp/c_$label.log | grep -E '^ +[0-9]' \
    | sed -E "s/^ +([0-9]+) +(.*)/STAT $label \1 \2/"
}
compile hydra poc_derive.mpc $HYDRA_ARGS
compile hmac hmac_derive.mpc $HMAC_ARGS
declare -A BIN=([hydra]=poc_derive [hmac]=hmac_derive)

SSL_DONE=0
grep -vE '^\s*(#|$)' "$CFG" | while read -r label prog N T rtt rate reps proto; do
  proto=${proto:-shamir}
  case "$proto" in
    mascot)    PARTY="./mascot-party.x -N $N" ;;
    malshamir) PARTY="./malicious-shamir-party.x -N $N -T $T" ;;
    *)         PARTY="./shamir-party.x -N $N -T $T" ;;
  esac
  if [ "$SSL_DONE" -lt "$N" ]; then
    ./Scripts/setup-ssl.sh "$N" > /dev/null 2>&1; SSL_DONE=$N
  fi
  tc qdisc del dev lo root 2>/dev/null
  NETEM=""
  if [ "$rtt" != "0" ]; then
    NETEM="delay $(awk "BEGIN{print $rtt/2}")ms"     # per direction
  fi
  if [ "$rate" != "0" ]; then NETEM="$NETEM rate ${rate}mbit"; fi
  [ -n "$NETEM" ] && tc qdisc add dev lo root netem $NETEM

  for rep in $(seq 1 "$reps"); do
    for i in $(seq 0 $((N - 1))); do
      /usr/bin/time -f "%e %U %S %M" -o /tmp/t$i \
        timeout 3600 $PARTY -p $i ${BIN[$prog]} \
        > /tmp/r$i.log 2>&1 &
    done
    wait
    if ! grep -q '^Time =' /tmp/r0.log; then
      echo "RUN_FAILED $label $rep"; tail -5 /tmp/r0.log; continue
    fi
    t=$(awk '/^Time =/{print $3}' /tmp/r0.log)
    tm=()
    for k in 1 2 3 4; do
      tm+=("$(awk -v k="Time$k" '$1==k{print $3}' /tmp/r0.log)")
    done
    mb=$(awk '/^Data sent/{print $4}' /tmp/r0.log)
    rounds=$(awk '/^Data sent/{gsub("~","",$7); print $7}' /tmp/r0.log)
    gmb=$(awk '/^Global data sent/{print $5}' /tmp/r0.log)
    cpu=$(cat /tmp/t* | awk '{c=$2+$3; s+=c; if(c>m)m=c; if($4>r)r=$4} END{printf "%.3f %.3f %d", s/NR, m, r}')
    echo "ROW $label $prog $N $T $rtt $rate $rep $t ${tm[0]:-NA} ${tm[1]:-NA} ${tm[2]:-NA} ${tm[3]:-NA} $mb $rounds $gmb $cpu"
    rm -f /tmp/t*
  done
done
tc qdisc del dev lo root 2>/dev/null
echo "BENCH_DONE"
