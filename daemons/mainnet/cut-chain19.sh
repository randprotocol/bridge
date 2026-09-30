#!/usr/bin/env bash
# Moves the bridge daemons from Rand chain 18 to chain 19 AND from the 2026-09-19 Ethereum/BSC/Tron
# endpoints to the ones redeployed on 2026-09-30 (docs/mainnet-deployment.md, last section).
# Prints every command; runs them only with --yes. One step at a time, in this order:
#
#   check                 read-only: what every daemon and endpoint says now
#   stop                  relayer + laptop guardians 7-8 + droplet guardians (before chain 18 stops)
#   droplet <1..6>        on that droplet, once its rand-node answers for chain 19 (the fleet
#                         cutover moves the node): guardian config to chain_id 19 and the new
#                         endpoints, stores of chains 2-4 archived, cursors rewritten, guardian started
#   laptop                the same for relayer.toml + guardian-7/8.toml and their data directories
#   start-laptop          laptop guardians 7-8 (pq-next seeds) and the relayer
#
# Inputs, all public, from the consume step on each new endpoint and from the chain-19 genesis:
#   START_ETH, START_BSC, START_TRON   first block the daemons read on each new endpoint: the block
#                                      AFTER its replayed release (so the operator's sequence-0 lock
#                                      is never observed; every cursor starts at sequence 1)
#   BURN_SEQ                           chain 19 genesis bridge.burn_sequence
#
# Why the stores move: guardian `signed/` and relayer `done/`, `observed/` are keyed by
# (chain, sequence), not by contract, and a new endpoint restarts at sequence 0. Old entries
# would stop a guardian on a false equivocation and make the relayer skip real deposits.
# Why sequence 1: an EVM source refuses a log whose sequence is not the cursor's next one.
#
# Droplet IPs come from ~/.rand-bridge/mainnet-set1/hosts.txt (not in this public repo).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

FROM=18; TO=19
OLD_EVM=0xd6EBD21C3dF90c9175EBdc8d6b377a9361604892          # Ethereum and BSC, 2026-09-19
NEW_EVM=0x7aF6b17047C1db6cB54347FdEa45cF9179075bfA          # Ethereum and BSC, 2026-09-30
OLD_TRON=0x0992df85dcce77ded2c0387f1fa9cf98ac859700         # TAqq2i8KfYpACPUc9f5e2gAjdSgXqmPpkU
NEW_TRON=0x6410797df959987a5baf65b5fab97edeb34d5163         # TK6JJv55CCkFjNHq7WwoU91GKaZEiC93me
HOSTS="$HOME/.rand-bridge/mainnet-set1/hosts.txt"
SSH=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o UserKnownHostsFile="$HOME/.ssh/rand_guardian_known_hosts" -i "$HOME/.ssh/rand_guardian_ed25519")

step="${1:-}"; shift || true
arg=""; yes=0
for a in "$@"; do [[ "$a" == --yes ]] && yes=1 || arg="$a"; done

run() { echo "+ $*"; if (( yes )); then "$@"; fi; }
ip_of() { awk -v i="$1" '$1==i{print $2}' "$HOSTS"; }
need() {
  for v in "$@"; do
    [[ "${!v:-}" =~ ^[0-9]+$ ]] || { echo "error: $v must be set to a number" >&2; exit 1; }
  done
}

# The edits one config file needs, as a sed program. `chain_id`, the three contracts (with the
# Tron comment) and the three start blocks; every other line stays as it is.
sed_program() {
  cat <<EOF
s/^chain_id = $FROM /chain_id = $TO /
/^name = "ethereum"/,/^start_block/ { s/^contract = "$OLD_EVM"/contract = "$NEW_EVM"/; s/^start_block = [0-9]+.*/start_block = $START_ETH          # the block after the consume step on the 2026-09-30 endpoint/; }
/^name = "bsc"/,/^start_block/ { s/^contract = "$OLD_EVM"/contract = "$NEW_EVM"/; s/^start_block = [0-9]+.*/start_block = $START_BSC          # the block after the consume step on the 2026-09-30 endpoint/; }
/^name = "tron"/,/^start_block/ { s/^contract = "$OLD_TRON".*/contract = "$NEW_TRON"   # TK6JJv55CCkFjNHq7WwoU91GKaZEiC93me/; s/^start_block = [0-9]+.*/start_block = $START_TRON          # the block after the consume step on the 2026-09-30 endpoint/; }
EOF
}
# What a correctly edited config must contain (checked after the edit, locally or remotely).
verify_lines() {
  printf '%s\n' "chain_id = $TO " "contract = \"$NEW_EVM\"" "contract = \"$NEW_TRON\"" \
    "start_block = $START_ETH " "start_block = $START_BSC " "start_block = $START_TRON "
}
cursor() { printf '{"next_block": %s, "next_sequence": %s}' "$1" "$2"; }

# Archives the (chain, sequence) stores of chains 2-4 under $1/pre-redeploy and rewrites the
# cursors. Runs locally through `bash -c` or remotely through ssh; $1 is the data directory.
store_script() {
  cat <<EOF
set -euo pipefail
d="$1"
[ -d "\$d/cursors" ]
[ ! -e "\$d/cursors.chain$FROM" ] || { echo "error: \$d/cursors.chain$FROM exists: this step already ran" >&2; exit 1; }
cp -Rp "\$d/cursors" "\$d/cursors.chain$FROM"
mkdir -p "\$d/pre-redeploy"
for k in signed refused observed done; do
  for c in 2 3 4; do
    if [ -d "\$d/\$k/\$c" ]; then mv "\$d/\$k/\$c" "\$d/pre-redeploy/\$k-\$c"; fi
  done
done
echo '$(cursor "$START_ETH" 1)' > "\$d/cursors/ethereum.json"
echo '$(cursor "$START_BSC" 1)' > "\$d/cursors/bsc.json"
echo '$(cursor "$START_TRON" 1)' > "\$d/cursors/tron.json"
echo '$(cursor 0 "$BURN_SEQ")' > "\$d/cursors/rand.json"
for f in ethereum bsc tron rand solana; do echo "\$d/cursors/\$f.json \$(tr -d '\n ' < "\$d/cursors/\$f.json")"; done
EOF
}

case "$step" in
  check)
    pgrep -fl 'rand-(relayer|guardian) --config mainnet/' || echo "laptop: no relayer or guardian running"
    grep -H -E '^(chain_id|contract|start_block|rand_cli)' mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml
    for d in relayer guardian-7 guardian-8; do
      for f in ethereum bsc tron rand solana; do echo "$d/$f $(tr -d '\n ' < "data/mainnet/$d/cursors/$f.json")"; done
    done
    for i in 1 2 3 4 5 6; do
      echo "droplet $i: $("${SSH[@]}" "root@$(ip_of "$i")" 'echo "guardian $(systemctl is-active rand-guardian), $(grep -E "^chain_id" /etc/rand-guardian.toml | cut -c1-13), node chain $(curl -s -m 4 -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_chainId\",\"params\":[]}" http://127.0.0.1:8545 | grep -o "\"result\":[0-9]*"), rand cursor $(tr -d "\n " < /var/lib/rand-guardian/data/cursors/rand.json)"' 2>&1 | tail -1)"
    done
    exit 0
    ;;
  stop)
    run pkill -f 'rand-relayer --config mainnet/relayer.toml' || true
    run pkill -f 'rand-guardian --config mainnet/guardian-[78].toml' || true
    for i in 1 2 3 4 5 6; do run "${SSH[@]}" "root@$(ip_of "$i")" 'systemctl stop rand-guardian; systemctl is-active rand-guardian || true'; done
    ;;
  droplet)
    need START_ETH START_BSC START_TRON BURN_SEQ
    [[ "$arg" =~ ^[1-6]$ ]] || { echo "usage: droplet <1..6>" >&2; exit 1; }
    remote=$(cat <<EOF
set -euo pipefail
! systemctl is-active -q rand-guardian || { echo "error: rand-guardian is still running" >&2; exit 1; }
curl -s -m 5 -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"rand_chainId","params":[]}' http://127.0.0.1:8545 | grep -q '"result":$TO\b' || { echo "error: this droplet's rand-node does not answer for chain $TO" >&2; exit 1; }
[ ! -e /etc/rand-guardian.toml.chain$FROM ] || { echo "error: /etc/rand-guardian.toml.chain$FROM exists: this step already ran" >&2; exit 1; }
cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain$FROM
sed -i -E '$(sed_program)' /etc/rand-guardian.toml
$(verify_lines | while IFS= read -r l; do printf "grep -qF -- '%s' /etc/rand-guardian.toml\n" "$l"; done)
! grep -qiF -- '$OLD_EVM' /etc/rand-guardian.toml
! grep -qiF -- '$OLD_TRON' /etc/rand-guardian.toml
$(store_script /var/lib/rand-guardian/data)
chown -R guardian: /var/lib/rand-guardian/data
systemctl start rand-guardian; sleep 6; systemctl is-active rand-guardian; journalctl -u rand-guardian -n 6 --no-pager
EOF
)
    run "${SSH[@]}" "root@$(ip_of "$arg")" "$remote"
    ;;
  laptop)
    need START_ETH START_BSC START_TRON BURN_SEQ
    if (( yes )) && pgrep -f 'rand-(relayer|guardian) --config mainnet/' >/dev/null; then
      echo "error: a laptop daemon is still running (run the stop step)" >&2; exit 1
    fi
    for f in mainnet/relayer.toml mainnet/guardian-7.toml mainnet/guardian-8.toml; do
      [[ ! -e "$f.chain$FROM" ]] || { echo "error: $f.chain$FROM exists: this step already ran" >&2; exit 1; }
      run cp -p "$f" "$f.chain$FROM"
      run sed -i '' -E "$(sed_program)" "$f"
      if (( yes )); then
        while IFS= read -r l; do grep -qF -- "$l" "$f" || { echo "error: $f lacks '$l' after the edit" >&2; exit 1; }; done < <(verify_lines)
        ! grep -qiF -e "$OLD_EVM" -e "$OLD_TRON" "$f" || { echo "error: $f still names an old endpoint" >&2; exit 1; }
      fi
    done
    for d in relayer guardian-7 guardian-8; do
      echo "+ archive chains 2-4 and rewrite the cursors in data/mainnet/$d"
      if (( yes )); then bash -c "$(store_script "data/mainnet/$d")"; fi
    done
    ;;
  start-laptop)
    for i in 7 8; do
      seed="$HOME/.rand-bridge/mainnet-set1/pq-next-$i.seed"
      [[ -s "$seed" ]] || { echo "error: $seed is missing" >&2; exit 1; }
    done
    grep -q "^chain_id = $TO " mainnet/relayer.toml || { echo "error: relayer.toml is not on chain $TO (run the laptop step)" >&2; exit 1; }
    echo "+ mainnet/guardian-tunnels.sh (if down); GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh; mainnet/run-relayer.sh"
    if (( yes )); then
      curl -s -m 3 http://127.0.0.1:7171/v1/health >/dev/null || mainnet/guardian-tunnels.sh
      GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh
      mainnet/run-relayer.sh
    fi
    ;;
  *)
    sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
(( yes )) || echo "DRY RUN: nothing was executed; re-run with --yes."
