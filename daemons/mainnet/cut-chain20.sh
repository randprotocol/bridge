#!/usr/bin/env bash
# Moves the bridge daemons from Rand chain 19 to chain 20 (fullnode v0.6.8: RPL-2, binding_domain 1,
# the zUSD bridge fees). The endpoints do not change, so their stores and cursors are kept; only the
# Rand side moves. Prints every command; runs them only with --yes. In this order:
#
#   stop                  droplet relayer + laptop guardians 7-8 + droplet guardians (before the snapshot)
#   droplet <1..6>        once that droplet's rand-node answers for chain 20: guardian config to
#                         chain_id 20, Rand cursor to BURN_SEQ, guardian started
#   laptop                guardian-7/8.toml and relayer.toml to chain_id 20, their Rand cursors to BURN_SEQ
#   relayer               on rand-relayer-1: /etc/rand-relayer.toml to chain_id 20, Rand cursor to
#                         BURN_SEQ, its `rand` to the v0.6.8 build (/usr/local/bin/rand-v068, checked
#                         against RAND_SHA), relayer started
#   start-laptop          laptop guardians 7-8 (pq-next seeds)
#
# Inputs: BURN_SEQ (chain 20 genesis bridge.burn_sequence), RAND_SHA (sha256 of the Linux v0.6.8 rand).
# On chain 20 a burn's signed body carries release_amount (amount − the zUSD fee); the daemons sign
# and release the body verbatim, so nothing else changes. setProtocolFee(0) on the four endpoints is
# a separate step (docs/mainnet-deployment.md), done once chain 20 serves `fees`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

FROM=19; TO=20
HOSTS="$HOME/.rand-bridge/mainnet-set1/hosts.txt"
SSH=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o UserKnownHostsFile="$HOME/.ssh/rand_guardian_known_hosts" -i "$HOME/.ssh/rand_guardian_ed25519")
relayer_ip=$(awk '$1=="public"{print $2}' "$HOME/.rand-bridge/relayer-host/host.txt")
RSSH=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o UserKnownHostsFile="$HOME/.ssh/rand_relayer_known_hosts" -i "$HOME/.ssh/rand_guardian_ed25519" "root@$relayer_ip")

step="${1:-}"; shift || true
arg=""; yes=0
for a in "$@"; do [[ "$a" == --yes ]] && yes=1 || arg="$a"; done
run() { echo "+ $*"; if (( yes )); then "$@"; fi; }
ip_of() { awk -v i="$1" '$1==i{print $2}' "$HOSTS"; }
need() { for v in "$@"; do [[ -n "${!v:-}" ]] || { echo "error: $v is not set" >&2; exit 1; }; done; }
answers() { printf 'curl -s -m 5 -X POST -H "content-type: application/json" --data '"'"'{"jsonrpc":"2.0","id":1,"method":"rand_chainId","params":[]}'"'"' http://127.0.0.1:8545 | grep -q '"'"'"result":%s\\b'"'"'' "$TO"; }

case "$step" in
  stop)
    run "${RSSH[@]}" 'systemctl stop rand-relayer; systemctl is-active rand-relayer || true'
    run pkill -f 'rand-guardian --config mainnet/guardian-[78].toml' || true
    for i in 1 2 3 4 5 6; do run "${SSH[@]}" "root@$(ip_of "$i")" 'systemctl stop rand-guardian; systemctl is-active rand-guardian || true'; done
    ;;
  droplet)
    need BURN_SEQ
    [[ "$arg" =~ ^[1-6]$ ]] || { echo "usage: droplet <1..6>" >&2; exit 1; }
    run "${SSH[@]}" "root@$(ip_of "$arg")" "set -e
! systemctl is-active -q rand-guardian || { echo 'error: rand-guardian is still running' >&2; exit 1; }
$(answers) || { echo 'error: this droplet does not answer for chain $TO' >&2; exit 1; }
[ ! -e /etc/rand-guardian.toml.chain$FROM ]
cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain$FROM
sed -i -E 's/^chain_id = $FROM /chain_id = $TO /' /etc/rand-guardian.toml
grep -q '^chain_id = $TO ' /etc/rand-guardian.toml
cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain$FROM
echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > /var/lib/rand-guardian/data/cursors/rand.json
chown -R guardian: /var/lib/rand-guardian/data
systemctl start rand-guardian; sleep 6; systemctl is-active rand-guardian; journalctl -u rand-guardian -n 3 --no-pager"
    ;;
  laptop)
    need BURN_SEQ
    for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml; do
      run cp -p "$f" "$f.chain$FROM"
      run sed -i '' -E "s/^chain_id = $FROM /chain_id = $TO /" "$f"
    done
    for d in guardian-7 guardian-8 relayer; do
      run cp -Rp "data/mainnet/$d/cursors" "data/mainnet/$d/cursors.chain$FROM"
      echo "+ echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > data/mainnet/$d/cursors/rand.json"
      (( yes )) && echo "{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}" > "data/mainnet/$d/cursors/rand.json"
    done
    ;;
  relayer)
    need BURN_SEQ RAND_SHA
    run "${RSSH[@]}" "set -e
! systemctl is-active -q rand-relayer || { echo 'error: the relayer is still running' >&2; exit 1; }
$(answers) || { echo 'error: the relayer droplet does not reach a chain-$TO node' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand-v068 | cut -d' ' -f1)\" = $RAND_SHA ]
cp -p /etc/rand-relayer.toml /etc/rand-relayer.toml.chain$FROM
sed -i -E 's/^chain_id = $FROM /chain_id = $TO /' /etc/rand-relayer.toml
grep -q '^chain_id = $TO ' /etc/rand-relayer.toml
install -m 755 /usr/local/bin/rand-v068 /usr/local/bin/rand
cp -rp /var/lib/rand-relayer/data/cursors /var/lib/rand-relayer/data/cursors.chain$FROM
echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > /var/lib/rand-relayer/data/cursors/rand.json
chown -R relayer: /var/lib/rand-relayer/data
rand --version
systemctl start rand-relayer; sleep 15; systemctl is-active rand-relayer; journalctl -u rand-relayer -n 4 --no-pager"
    ;;
  start-laptop)
    grep -q "^chain_id = $TO " mainnet/guardian-7.toml || { echo "error: guardian-7.toml is not on chain $TO" >&2; exit 1; }
    echo "+ GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh"
    if (( yes )); then GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh; fi
    ;;
  *)
    sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
(( yes )) || echo "DRY RUN: nothing was executed; re-run with --yes."
