#!/usr/bin/env bash
# Deploys the Ethereum or BSC endpoint from the command line.
#
#   deploy/evm.sh <network> [--dry-run] [--yes] [--verify]
#
#   network   ethereum | sepolia | bsc | bsc-testnet | anvil
#   --dry-run simulate only (no --broadcast)
#   --yes     skip the confirmation prompt (DEPLOY_YES=1 does too, on testnets only)
#   --verify  submit the source to Etherscan/BscScan afterwards
#
# Keys and RPC endpoints come from the environment / deploy/.env:
#   ETH_PRIVATE_KEY   signs on ethereum and sepolia
#   BSC_PRIVATE_KEY   signs on bsc and bsc-testnet
#   ANVIL_PRIVATE_KEY signs on anvil (defaults to anvil's account 0)
#   <NETWORK>_RPC_URL the JSON-RPC endpoint, e.g. ETH_RPC_URL, BSC_TESTNET_RPC_URL
# plus the constructor arguments ADMIN, PAUSER, RAND_EMITTER, GUARDIANS.
#
# The key is handed to `forge script` through DEPLOYER_PRIVATE_KEY in the
# environment (read by evm/script/Deploy.s.sol), never as an argument.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" >&2; exit 1; }

network="${1:-}"; shift || true
[[ -n "$network" ]] || usage
dry_run=0; verify=0; DEPLOY_YES_CLI=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --yes) DEPLOY_YES_CLI=1 ;;
    --verify) verify=1 ;;
    *) usage ;;
  esac
done

load_env

# network -> (Deploy.s.sol CHAIN, chain id, key variable, rpc variable, mainnet?)
case "$network" in
  ethereum)    chain=ethereum; chain_id=1;        key_var=ETH_PRIVATE_KEY;   rpc_var=ETH_RPC_URL;         mainnet=1; scan_key_var=ETHERSCAN_API_KEY ;;
  sepolia)     chain=ethereum; chain_id=11155111; key_var=ETH_PRIVATE_KEY;   rpc_var=SEPOLIA_RPC_URL;     mainnet=0; scan_key_var=ETHERSCAN_API_KEY ;;
  bsc)         chain=bsc;      chain_id=56;       key_var=BSC_PRIVATE_KEY;   rpc_var=BSC_RPC_URL;         mainnet=1; scan_key_var=BSCSCAN_API_KEY ;;
  bsc-testnet) chain=bsc;      chain_id=97;       key_var=BSC_PRIVATE_KEY;   rpc_var=BSC_TESTNET_RPC_URL; mainnet=0; scan_key_var=BSCSCAN_API_KEY ;;
  anvil)       chain=ethereum; chain_id=31337;    key_var=ANVIL_PRIVATE_KEY; rpc_var=ANVIL_RPC_URL;       mainnet=0; scan_key_var= ;;
  *) die "unknown network '$network' (ethereum | sepolia | bsc | bsc-testnet | anvil)" ;;
esac

if [[ "$network" == "anvil" ]]; then
  : "${ANVIL_PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
  : "${ANVIL_RPC_URL:=http://127.0.0.1:8545}"
  : "${ALLOW_SMALL_GUARDIAN_SET:=1}"
  export ANVIL_PRIVATE_KEY ANVIL_RPC_URL ALLOW_SMALL_GUARDIAN_SET
fi

need_tool forge "install Foundry: https://getfoundry.sh"
need_tool jq
require "$key_var" "$rpc_var" ADMIN
check_common_args "$mainnet"
is_hex_key "${!key_var}" || die "$key_var must be 0x + 64 hex"
if [[ -z "${PAUSER:-}" ]]; then
  echo "warning: PAUSER is unset; the endpoint deploys with no pauser (only the admin can pause)" >&2
fi
if [[ "$mainnet" == "1" && "$dry_run" == "0" && -z "${PAUSER:-}" ]]; then
  die "refusing a mainnet deployment without PAUSER"
fi

rpc="${!rpc_var}"
info "network $network (bridge CHAIN=$chain, expected chain id $chain_id)"
rpc_shown="$(redact_url "$rpc")"
info "rpc $rpc_shown"

# RPC URLs and explorer keys are secrets too (a provider URL embeds its
# API key): cast reads ETH_RPC_URL, forge FOUNDRY_ETH_RPC_URL / ETHERSCAN_API_KEY, from the
# environment, so neither is ever an argument.
export ETH_RPC_URL="$rpc" FOUNDRY_ETH_RPC_URL="$rpc"

# Refuse to sign against the wrong chain before forge even starts.
actual_id="$(cast chain-id)" || die "cannot reach $rpc_shown"
[[ "$actual_id" == "$chain_id" ]] || die "$rpc_shown reports chain id $actual_id, expected $chain_id for $network"

# The key never goes on a command line, so the deployer address is not
# derived here: `cast wallet address` only takes a key as an argument.
# Deploy.s.sol logs the deployer itself (forge computes it from the
# DEPLOYER_PRIVATE_KEY environment) before it broadcasts. Set the
# non-secret DEPLOYER_ADDRESS to get a pre-flight balance line.
if [[ -n "${DEPLOYER_ADDRESS:-}" ]]; then
  info "deployer $DEPLOYER_ADDRESS (balance $(cast balance --ether "$DEPLOYER_ADDRESS" 2>/dev/null || echo '?') native)"
fi

if [[ "$dry_run" == "0" ]]; then
  confirm "$network" "$mainnet"
fi

forge_args=(script script/Deploy.s.sol:Deploy -vv)
if [[ "$dry_run" == "0" ]]; then
  forge_args+=(--broadcast)
fi
if [[ "$verify" == "1" ]]; then
  [[ -n "$scan_key_var" ]] || die "--verify is not supported on $network"
  require "$scan_key_var"
  forge_args+=(--verify)
  export ETHERSCAN_API_KEY="${!scan_key_var}"
fi

cd "$BRIDGE_ROOT/evm"
# Pinned: forge-std runs inside the script VM that holds the deployer key.
[[ -d lib/forge-std ]] || forge install foundry-rs/forge-std@v1.16.2 --no-git >/dev/null

run="broadcast/Deploy.s.sol/$chain_id/run-latest.json"
if [[ "$dry_run" == "0" ]]; then
  rm -f "$run"   # a stale run must never be read back as this one
fi

# DEPLOYER_PRIVATE_KEY is read by Deploy.s.sol via vm.envUint; load_env
# keeps every key un-exported, so forge is the only process that sees it.
forge_rc=0
CHAIN="$chain" EXPECTED_CHAIN_ID="$chain_id" \
ADMIN="$ADMIN" PAUSER="${PAUSER:-}" RAND_EMITTER="$RAND_EMITTER" GUARDIANS="$GUARDIANS" \
DEPLOYER_PRIVATE_KEY="${!key_var}" \
  forge "${forge_args[@]}" || forge_rc=$?

if [[ "$dry_run" == "1" ]]; then
  (( forge_rc == 0 )) || die "forge exited $forge_rc"
  info "dry run only; nothing was broadcast"
  exit 0
fi

# forge also exits non-zero when only `--verify` failed, after a broadcast
# that did land: the record is written whenever a deployment exists.
if [[ ! -f "$run" ]]; then
  die "forge exited $forge_rc and wrote no $run; nothing was deployed"
fi
address="$(jq -r '[.transactions[] | select(.transactionType == "CREATE")][0].contractAddress' "$run")"
tx="$(jq -r '[.transactions[] | select(.transactionType == "CREATE")][0].hash' "$run")"
[[ "$address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "could not read the deployed address from $run"

echo
echo "deployed  $address"
echo "tx        $tx"
echo "emitter   $(emitter_wire_form "$address")   <- bridge.emitters[\"$( [[ $chain == bsc ]] && echo 3 || echo 2 )\"] in the Rand genesis"
record_deployment "$network" "$chain" "$address" "$tx" \
  "$(jq -n --arg e "$(emitter_wire_form "$address")" --argjson id "$chain_id" '{emitter_wire_form:$e, chain_id:$id}')"
if (( forge_rc != 0 )); then
  die "forge exited $forge_rc after the broadcast (explorer verification?); the deployment above is live and recorded"
fi
