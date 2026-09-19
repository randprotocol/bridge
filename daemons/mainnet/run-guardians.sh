#!/usr/bin/env bash
# Starts the six mainnet guardians on this machine, one process each, each
# given exactly one key: GUARDIAN<i>_PRIV_KEY from the calling environment.
#
# Six guardians on one host is a stop-gap: whoever controls this machine
# controls the bridge. Move each guardian to its own operator before custody
# holds real value.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
bin=target/release/rand-guardian
[[ -x "$bin" ]] || cargo build --release --bin rand-guardian
mkdir -p data/mainnet/logs
for i in 1 2 3 4 5 6; do
  var="GUARDIAN${i}_PRIV_KEY"
  [[ -n "${!var:-}" ]] || { echo "error: $var is not set" >&2; exit 1; }
  # `env -i`: the child sees its own key and nothing else from this shell.
  pq="GUARDIAN${i}_PQ_SEED"   # optional until chain 14 requires the co-signature
  env -i PATH="$PATH" HOME="$HOME" "$var=${!var}" ${!pq:+"$pq=${!pq}"} \
    nohup "$bin" --config "mainnet/guardian-$i.toml" >>"data/mainnet/logs/guardian-$i.log" 2>&1 &
  echo "guardian $i: pid $! (log data/mainnet/logs/guardian-$i.log)"
done
