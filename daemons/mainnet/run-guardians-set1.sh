#!/usr/bin/env bash
# Starts the two laptop guardians of set 1 (indices 6 and 7). The other six run
# on their own droplets (docs/guardian-hosts.md). Each process is given exactly
# one key, read from ~/.rand-bridge/mainnet-set1/guardian-<i>.key (mode 600).
# On chain 14 neither holds a Dilithium seed: the PQ quorum comes from the droplets.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
bin=target/release/rand-guardian
[[ -x "$bin" ]] || cargo build --release --bin rand-guardian
mkdir -p data/mainnet/logs
for i in 7 8; do
  keyfile="$HOME/.rand-bridge/mainnet-set1/guardian-$i.key"
  [[ -s "$keyfile" ]] || { echo "error: $keyfile is missing" >&2; exit 1; }
  pq=()
  # From chain 15 on (GUARDIAN_PQ_FROM_NEXT=1, set by cut-chain15.sh) each laptop guardian also
  # co-signs with its own Dilithium2 seed, position 6/7 of the chain-15 pq_guardians.
  if [[ "${GUARDIAN_PQ_FROM_NEXT:-0}" == 1 ]]; then
    pq=("GUARDIAN${i}_PQ_SEED=$(tr -d '\n ' < "$HOME/.rand-bridge/mainnet-set1/pq-next-$i.seed")")
  fi
  env -i PATH="$PATH" HOME="$HOME" "GUARDIAN${i}_PRIV_KEY=$(<"$keyfile")" "${pq[@]}" \
    nohup "$bin" --config "mainnet/guardian-$i.toml" >>"data/mainnet/logs/guardian-$i.log" 2>&1 &
  echo "guardian $i: pid $! (log data/mainnet/logs/guardian-$i.log)"
done
