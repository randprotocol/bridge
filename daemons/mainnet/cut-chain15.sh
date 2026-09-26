#!/usr/bin/env bash
# Moves the bridge daemons from Rand chain 14 to chain 15 (2026-09-26 cut). Prints every
# command; runs them only with --yes. One step at a time, in this order:
#
#   stop                  relayer + laptop guardians 7-8 + droplet guardians (before chain 14 stops)
#   droplet <1..6>        on that droplet: verify and install the chain-15 rand-node, start it on a
#                         fresh /var/lib/randnode/data-15 with the chain-15 genesis; guardian config
#                         to chain_id 15, its GUARDIAN_PQ_SEED to pq-next.seed, Rand cursor to 7.
#                         The guardian is NOT started (the node must sync first).
#   droplet-guardian <i>  start that droplet's guardian once its node answers for chain 15
#   laptop                relayer.toml + guardian-7/8.toml to chain_id 15, Rand cursors to 7
#   start-laptop          laptop guardians 7-8 (with their pq-next seeds) and the relayer
#
# Inputs (from the fullnode session at the cut):
#   GENESIS=<chain-15 genesis.json>  GENESIS_SHA=<its sha256>
#   NODE_BIN=<linux x86_64 rand-node> NODE_SHA=<its sha256>
#   BOOTSTRAP="<multiaddr> <multiaddr> ..."
# Droplet IPs come from ~/.rand-bridge/mainnet-set1/hosts.txt (not in this public repo).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

BURN_SEQ_START=7   # chain 15 genesis bridge.burn_sequence (chain 14's final value)
HOSTS="$HOME/.rand-bridge/mainnet-set1/hosts.txt"
SSH=(ssh -n -o BatchMode=yes -o UserKnownHostsFile="$HOME/.ssh/rand_guardian_known_hosts" -i "$HOME/.ssh/rand_guardian_ed25519")
SCP=(scp -o BatchMode=yes -o UserKnownHostsFile="$HOME/.ssh/rand_guardian_known_hosts" -i "$HOME/.ssh/rand_guardian_ed25519")

step="${1:-}"; shift || true
arg=""; yes=0
for a in "$@"; do [[ "$a" == --yes ]] && yes=1 || arg="$a"; done

run() { echo "+ $*"; if (( yes )); then "$@"; fi; }
ip_of() { awk -v i="$1" '$1==i{print $2}' "$HOSTS"; }
need() { for v in "$@"; do [[ -n "${!v:-}" ]] || { echo "error: $v is not set" >&2; exit 1; }; done; }
sha_ok() { [[ "$(shasum -a 256 "$1" | cut -d' ' -f1)" == "$2" ]] || { echo "error: sha256 of $1 != $2" >&2; exit 1; }; }
cursor7='{"next_block": 0, "next_sequence": '"$BURN_SEQ_START"'}'

case "$step" in
  stop)
    run pkill -f 'rand-relayer --config mainnet/relayer.toml' || true
    run pkill -f 'rand-guardian --config mainnet/guardian-[78].toml' || true
    for i in 1 2 3 4 5 6; do run "${SSH[@]}" "root@$(ip_of "$i")" 'systemctl stop rand-guardian'; done
    ;;
  droplet)
    need GENESIS GENESIS_SHA NODE_BIN NODE_SHA BOOTSTRAP
    [[ "$arg" =~ ^[1-6]$ ]] || { echo "usage: droplet <1..6>" >&2; exit 1; }
    sha_ok "$GENESIS" "$GENESIS_SHA"; sha_ok "$NODE_BIN" "$NODE_SHA"
    host="root@$(ip_of "$arg")"
    boot=""; for b in $BOOTSTRAP; do boot+=" --bootstrap $b"; done
    run "${SCP[@]}" "$NODE_BIN" "$host:/tmp/rand-node-15"
    run "${SCP[@]}" "$GENESIS" "$host:/tmp/genesis-15.json"
    # Everything below runs on the droplet; each file is re-checked there before use.
    remote=$(cat <<EOF
set -euo pipefail
[ "\$(sha256sum /tmp/rand-node-15 | cut -d' ' -f1)" = "$NODE_SHA" ]
[ "\$(sha256sum /tmp/genesis-15.json | cut -d' ' -f1)" = "$GENESIS_SHA" ]
systemctl stop rand-guardian rand-node
install -m 755 /usr/local/bin/rand-node /usr/local/bin/rand-node-14
install -m 755 /tmp/rand-node-15 /usr/local/bin/rand-node
install -d -o randnode -g randnode /var/lib/randnode/data-15
install -m 644 -o randnode -g randnode /tmp/genesis-15.json /var/lib/randnode/data-15/genesis.json
mkdir -p /etc/systemd/system/rand-node.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/local/bin/rand-node run --datadir /var/lib/randnode/data-15 --key /var/lib/randnode/node.key.json --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 --no-mdns --verify-chain off$boot\n' > /etc/systemd/system/rand-node.service.d/chain15.conf
sed -i.bak14 -E 's/^chain_id = 14 /chain_id = 15 /' /etc/rand-guardian.toml
grep -q '^chain_id = 15 ' /etc/rand-guardian.toml
cp -p /etc/rand-guardian/env /etc/rand-guardian/env.chain14
sed -i -E "s/^GUARDIAN_PQ_SEED=.*/GUARDIAN_PQ_SEED=\$(tr -d '\n ' < /etc/rand-guardian/pq-next.seed)/" /etc/rand-guardian/env
cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain14
echo '$cursor7' > /var/lib/rand-guardian/data/cursors/rand.json
systemctl daemon-reload
systemctl start rand-node
EOF
)
    run "${SSH[@]}" "$host" "$remote"
    ;;
  droplet-guardian)
    [[ "$arg" =~ ^[1-6]$ ]] || { echo "usage: droplet-guardian <1..6>" >&2; exit 1; }
    run "${SSH[@]}" "root@$(ip_of "$arg")" 'systemctl start rand-guardian; sleep 5; journalctl -u rand-guardian -n 5 --no-pager'
    ;;
  laptop)
    for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml; do
      run sed -i '' -E 's/^chain_id = 14 /chain_id = 15 /' "$f"
    done
    for d in relayer guardian-7 guardian-8; do
      run cp -Rp "data/mainnet/$d/cursors" "data/mainnet/$d/cursors.chain14"
      echo "+ echo '$cursor7' > data/mainnet/$d/cursors/rand.json"
      (( yes )) && echo "$cursor7" > "data/mainnet/$d/cursors/rand.json"
    done
    echo "then: point [rand].rpc / rand_cli in mainnet/relayer.toml at the chain-15 node and build"
    ;;
  start-laptop)
    for i in 7 8; do
      seed="$HOME/.rand-bridge/mainnet-set1/pq-next-$i.seed"
      [[ -s "$seed" ]] || { echo "error: $seed is missing" >&2; exit 1; }
    done
    echo "+ GUARDIAN{7,8}_PQ_SEED from ~/.rand-bridge/mainnet-set1/pq-next-{7,8}.seed; mainnet/run-guardians-set1.sh; mainnet/run-relayer.sh"
    if (( yes )); then
      GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh
      mainnet/run-relayer.sh
    fi
    ;;
  *)
    sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
(( yes )) || echo "DRY RUN: nothing was executed; re-run with --yes."
