#!/usr/bin/env bash
# Deploys the Ethereum or BSC endpoint from the command line.
#
#   deploy/evm.sh <network> [--dry-run] [--yes] [--verify]
#
#   network   ethereum | sepolia | bsc | bsc-testnet | anvil
#   --dry-run simulate only (no --broadcast)
#   --yes     skip the confirmation prompt (or DEPLOY_YES=1)
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
dry_run=0; verify=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --yes) export DEPLOY_YES=1 ;;
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
require "$key_var" "$rpc_var"
check_common_args
is_hex_key "${!key_var}" || die "$key_var must be 0x + 64 hex"
if [[ -z "${PAUSER:-}" ]]; then
  echo "warning: PAUSER is unset; the endpoint deploys with no pauser (only the admin can pause)" >&2
fi
if [[ "$mainnet" == "1" && "$dry_run" == "0" && -z "${PAUSER:-}" ]]; then
  die "refusing a mainnet deployment without PAUSER"
fi

rpc="${!rpc_var}"
info "network $network (bridge CHAIN=$chain, expected chain id $chain_id)"
info "rpc $rpc"

# Refuse to sign against the wrong chain before forge even starts.
actual_id="$(cast chain-id --rpc-url "$rpc")" || die "cannot reach $rpc"
[[ "$actual_id" == "$chain_id" ]] || die "$rpc reports chain id $actual_id, expected $chain_id for $network"

deployer="$(DEPLOYER_PRIVATE_KEY="${!key_var}" cast wallet address --private-key "${!key_var}" 2>/dev/null || true)"
[[ -n "$deployer" ]] && info "deployer $deployer (balance $(cast balance --rpc-url "$rpc" --ether "$deployer" 2>/dev/null || echo '?') native)"

if [[ "$dry_run" == "0" ]]; then
  confirm "$network" "$mainnet"
fi

forge_args=(script script/Deploy.s.sol:Deploy --rpc-url "$rpc" -vv)
if [[ "$dry_run" == "0" ]]; then
  forge_args+=(--broadcast)
fi
if [[ "$verify" == "1" ]]; then
  [[ -n "$scan_key_var" ]] || die "--verify is not supported on $network"
  require "$scan_key_var"
  forge_args+=(--verify --etherscan-api-key "${!scan_key_var}")
fi

cd "$BRIDGE_ROOT/evm"
[[ -d lib/forge-std ]] || forge install foundry-rs/forge-std --no-git >/dev/null

# DEPLOYER_PRIVATE_KEY is read by Deploy.s.sol via vm.envUint; it is
# exported for this one process only.
CHAIN="$chain" EXPECTED_CHAIN_ID="$chain_id" \
ADMIN="$ADMIN" PAUSER="${PAUSER:-}" RAND_EMITTER="$RAND_EMITTER" GUARDIANS="$GUARDIANS" \
DEPLOYER_PRIVATE_KEY="${!key_var}" \
  forge "${forge_args[@]}"

if [[ "$dry_run" == "1" ]]; then
  info "dry run only; nothing was broadcast"
  exit 0
fi

run="broadcast/Deploy.s.sol/$chain_id/run-latest.json"
[[ -f "$run" ]] || die "forge did not write $run"
address="$(jq -r '[.transactions[] | select(.transactionType == "CREATE")][0].contractAddress' "$run")"
tx="$(jq -r '[.transactions[] | select(.transactionType == "CREATE")][0].hash' "$run")"
[[ "$address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "could not read the deployed address from $run"

echo
echo "deployed  $address"
echo "tx        $tx"
echo "emitter   $(emitter_wire_form "$address")   <- bridge.emitters[\"$( [[ $chain == bsc ]] && echo 3 || echo 2 )\"] in the Rand genesis"
record_deployment "$network" "$chain" "$address" "$tx" \
  "$(jq -n --arg e "$(emitter_wire_form "$address")" --argjson id "$chain_id" '{emitter_wire_form:$e, chain_id:$id}')"
