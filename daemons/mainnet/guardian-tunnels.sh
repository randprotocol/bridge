#!/usr/bin/env bash
# Keeps an SSH tunnel open to each droplet guardian's signature API, so the
# relayer reaches droplet i at 127.0.0.1:717<i>. The droplets expose nothing
# but SSH; the API stays on their loopback.
#
# Hosts: ~/.rand-bridge/mainnet-set1/hosts.txt, lines "<i> <ip>" (kept out of
# this public repo). Key: ~/.ssh/rand_guardian_ed25519.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
hosts="$HOME/.rand-bridge/mainnet-set1/hosts.txt"
mkdir -p data/mainnet/logs
while read -r i ip; do
  [[ -n "$i" ]] || continue
  nohup bash -c "while true; do
    ssh -N -i \$HOME/.ssh/rand_guardian_ed25519 \
      -o UserKnownHostsFile=\$HOME/.ssh/rand_guardian_known_hosts -o StrictHostKeyChecking=yes \
      -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
      -L 127.0.0.1:717$i:127.0.0.1:7071 root@$ip
    sleep 5
  done" >>"data/mainnet/logs/tunnel-$i.log" 2>&1 &
  echo "tunnel $i: 127.0.0.1:717$i -> $ip (pid $!)"
done <"$hosts"
