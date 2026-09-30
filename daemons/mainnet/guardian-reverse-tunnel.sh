#!/usr/bin/env bash
# Keeps the two laptop guardians (set-1 indices 6 and 7, 127.0.0.1:7077 and :7078 here) reachable
# from the relayer on rand-relayer-1: a reverse SSH forward to that droplet's loopback, as its
# forwarding-only `tunnel` user (permitlisten 127.0.0.1:7077 and :7078 only). While the laptop is
# off the relayer has the six droplet guardians, exactly a quorum.
#
# Host: ~/.rand-bridge/relayer-host/host.txt, line "public <ip>" (kept out of this public repo).
# Key: ~/.ssh/rand_guardian_tunnel_ed25519. Known hosts: ~/.ssh/rand_relayer_known_hosts.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ip=$(awk '$1=="public"{print $2}' "$HOME/.rand-bridge/relayer-host/host.txt")
[[ -n "$ip" ]] || { echo "error: no relayer host in ~/.rand-bridge/relayer-host/host.txt" >&2; exit 1; }
mkdir -p data/mainnet/logs
nohup bash -c "while true; do
  ssh -N -i \$HOME/.ssh/rand_guardian_tunnel_ed25519 \
    -o UserKnownHostsFile=\$HOME/.ssh/rand_relayer_known_hosts -o StrictHostKeyChecking=yes \
    -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -R 127.0.0.1:7077:127.0.0.1:7077 -R 127.0.0.1:7078:127.0.0.1:7078 tunnel@$ip
  sleep 5
done" >>data/mainnet/logs/reverse-tunnel.log 2>&1 &
echo "reverse tunnel: laptop 7077/7078 -> relayer droplet loopback (pid $!)"
