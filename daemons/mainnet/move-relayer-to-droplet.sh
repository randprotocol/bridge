#!/usr/bin/env bash
# Moves the mainnet relayer from this laptop to the droplet rand-relayer-1 (user ruling 2026-09-30:
# a dedicated droplet, paying gas with the deployer keys, right after the chain-19 cut). Prints
# every step; runs them only with --yes. In this order:
#
#   check     read-only: laptop relayer, droplet units, the eight guardians and the Rand RPC as the
#             droplet sees them (tunnels: rand-relayer-tunnel@1..6, the laptop's reverse tunnel)
#   move      stop the laptop relayer; copy its config (paths rewritten), its data directory
#             (cursors, done, observed, recipients) and its Rand wallet (key + note store) to the
#             droplet; write the droplet's env file from ~/.zshrc through ssh's stdin (never argv);
#             start rand-relayer.service; show its log
#   back      the rollback: stop the droplet relayer, copy its data directory back, start the laptop
#             relayer (mainnet/run-relayer.sh)
#
# One relayer at a time: two relayers on one EVM key race each other's nonces. `move` refuses while
# the droplet relayer is active; `back` refuses while the laptop one runs.
#
# Host: ~/.rand-bridge/relayer-host/host.txt ("public <ip>"), root key ~/.ssh/rand_guardian_ed25519,
# known hosts ~/.ssh/rand_relayer_known_hosts. Nothing here prints a key.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

ip=$(awk '$1=="public"{print $2}' "$HOME/.rand-bridge/relayer-host/host.txt")
[[ -n "$ip" ]] || { echo "error: no relayer host in ~/.rand-bridge/relayer-host/host.txt" >&2; exit 1; }
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15 -o UserKnownHostsFile="$HOME/.ssh/rand_relayer_known_hosts" -i "$HOME/.ssh/rand_guardian_ed25519" "root@$ip")
RSYNC_SSH="ssh -o BatchMode=yes -o UserKnownHostsFile=$HOME/.ssh/rand_relayer_known_hosts -i $HOME/.ssh/rand_guardian_ed25519"
WALLET="$HOME/.rand-chain14/wallets/relayer.key.json"

step="${1:-}"; shift || true
yes=0; for a in "$@"; do [[ "$a" == --yes ]] && yes=1; done
run() { echo "+ $*"; if (( yes )); then "$@"; fi; }

# The laptop config with the droplet's paths: data dir, the two CLIs. The Rand RPC stays
# 127.0.0.1:8545 (on the droplet: guardian host 6's node through rand-relayer-tunnel@6), the
# guardians stay 127.0.0.1:7171-7176 and 7077/7078, the listen address 127.0.0.1:7080.
droplet_config() {
  sed -E \
    -e 's#^data_dir = .*#data_dir = "/var/lib/rand-relayer/data"#' \
    -e 's#^solana_cli = .*#solana_cli = "/usr/local/bin/rand-bridge-cli"#' \
    -e 's|^rand_cli = .*|rand_cli = "/usr/local/bin/rand"   # the fullnode v0.6.7 release binary|' \
    -e '1s#^.*$#&  (on rand-relayer-1: /etc/rand-relayer.toml, written by mainnet/move-relayer-to-droplet.sh)#' \
    mainnet/relayer.toml
}

case "$step" in
  check)
    pgrep -fl 'rand-relayer --config mainnet/relayer.toml' || echo "laptop: no relayer running"
    grep -E '^(chain_id|contract|rand_cli)' mainnet/relayer.toml
    "${SSH[@]}" 'echo "droplet relayer: $(systemctl is-active rand-relayer)"; for i in 1 2 3 4 5 6; do printf "717$i %s " "$(systemctl is-active rand-relayer-tunnel@$i)"; curl -s -m 4 http://127.0.0.1:717$i/v1/health; echo; done; for p in 7077 7078; do printf "$p (laptop, reverse) "; curl -s -m 4 http://127.0.0.1:$p/v1/health || printf "down"; echo; done; printf "rand rpc chain "; curl -s -m 5 -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_chainId\",\"params\":[]}" http://127.0.0.1:8545; echo'
    ;;
  move)
    [[ -s "$WALLET" && -s "$WALLET.notes.json" ]] || { echo "error: $WALLET or its note store is missing" >&2; exit 1; }
    if (( yes )) && "${SSH[@]}" 'systemctl is-active -q rand-relayer'; then
      echo "error: the droplet relayer is already running" >&2; exit 1
    fi
    run pkill -f 'rand-relayer --config mainnet/relayer.toml' || true
    if (( yes )); then
      sleep 3
      ! pgrep -f 'rand-relayer --config mainnet/relayer.toml' >/dev/null || { echo "error: the laptop relayer did not stop" >&2; exit 1; }
    fi
    echo "+ write /etc/rand-relayer.toml (the laptop config, droplet paths)"
    if (( yes )); then droplet_config | "${SSH[@]}" 'umask 022; cat > /etc/rand-relayer.toml'; else droplet_config | sed 's/^/    /' | head -12; fi
    run rsync -a --delete -e "$RSYNC_SSH" data/mainnet/relayer/ "root@$ip:/var/lib/rand-relayer/data/"
    run rsync -a -e "$RSYNC_SSH" "$WALLET" "$WALLET.notes.json" "root@$ip:/var/lib/rand-relayer/wallet/"
    echo "+ write /etc/rand-relayer/env (root, 600) from ~/.zshrc via stdin: RELAYER_EVM_KEY RELAYER_TRON_KEY SOL_PRIVATE_KEY RAND_KEY RAND_RPC"
    if (( yes )); then
      (
        eval "$(grep -E '^\s*export (ETH_PRIVATE_KEY|TRON_PRIVATE_KEY|SOL_PRIVATE_KEY)=' ~/.zshrc)"
        [[ -n "${ETH_PRIVATE_KEY:-}" && -n "${TRON_PRIVATE_KEY:-}" && -n "${SOL_PRIVATE_KEY:-}" ]] || { echo "error: a key is missing from ~/.zshrc" >&2; exit 1; }
        printf 'RELAYER_EVM_KEY=%s\nRELAYER_TRON_KEY=%s\nSOL_PRIVATE_KEY=%s\nRAND_KEY=/var/lib/rand-relayer/wallet/relayer.key.json\nRAND_RPC=http://127.0.0.1:8545\n' \
          "$ETH_PRIVATE_KEY" "$TRON_PRIVATE_KEY" "$SOL_PRIVATE_KEY" \
          | "${SSH[@]}" 'umask 077; cat > /etc/rand-relayer/env; chmod 600 /etc/rand-relayer/env'
      )
    fi
    run "${SSH[@]}" 'chown -R relayer:relayer /var/lib/rand-relayer/data /var/lib/rand-relayer/wallet && chmod 600 /var/lib/rand-relayer/wallet/* && systemctl enable -q --now rand-relayer && sleep 20 && systemctl is-active rand-relayer && journalctl -u rand-relayer -n 12 --no-pager'
    ;;
  back)
    if (( yes )) && pgrep -f 'rand-relayer --config mainnet/relayer.toml' >/dev/null; then
      echo "error: the laptop relayer is running" >&2; exit 1
    fi
    run "${SSH[@]}" 'systemctl disable -q --now rand-relayer; systemctl is-active rand-relayer || true'
    run rsync -a -e "$RSYNC_SSH" "root@$ip:/var/lib/rand-relayer/data/" data/mainnet/relayer/
    run rsync -a -e "$RSYNC_SSH" "root@$ip:/var/lib/rand-relayer/wallet/relayer.key.json.notes.json" "$WALLET.notes.json"
    run mainnet/run-relayer.sh
    ;;
  *)
    sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 1 ;;
esac
(( yes )) || echo "DRY RUN: nothing was executed; re-run with --yes."
