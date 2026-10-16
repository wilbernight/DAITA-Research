#!/bin/zsh
# usage: ./run-cand.sh <name>   (uses configs/cand-<name>.toml; run from this directory)
# search -> combo (19k) -> sim -> eval with RF/DF. Blocking searches need a big stack.
set -e
cd "${0:A:h}"
export RUST_MIN_STACK=${RUST_MIN_STACK:-268435456}
mb=../../upstream/maybenot/target/release/maybenot
mkdir -p logs
n=$1; c=configs/cand-$n.toml
{ time $mb search -c $c -o def-$n; } > logs/$n-search.log 2>&1 || exit 1
{ time $mb combo -c $c -i def-$n -o def-$n-19k; } > logs/$n-combo.log 2>&1 || exit 1
{ time $mb sim -c $c -i def-$n-19k -o sim-$n; } > logs/$n-sim.log 2>&1 || exit 1
{ time $mb eval -c $c -i sim-$n; } > logs/$n-eval.log 2>&1 || exit 1
