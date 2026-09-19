#!/usr/bin/env bash
# Deploys the Tron endpoint (TronRandBridge, bridge chain 4) with TronBox.
#
#   deploy/trx.sh [nile|shasta|mainnet] [--dry-run] [--yes]
#
#   --dry-run  mirror the sources and compile only; no transaction
#   --yes      skip the confirmation prompt (DEPLOY_YES=1 does too, on testnets only)
#
# Environment / deploy/.env:
#   TRON_PRIVATE_KEY  0x + 64 hex (the 0x prefix is optional); pays the deployment
#   TRON_RPC_URL      optional; overrides the public TronGrid endpoint
#   ADMIN, PAUSER, RAND_EMITTER, GUARDIANS   constructor arguments (tron/migrations/2_deploy.js)
#
# TronBox is installed locally in tron/node_modules (tron/package.json), so
# nothing global is needed beyond node and npm.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { sed -n '2,16p' "${BASH_SOURCE[0]}" >&2; exit 1; }

network="${1:-nile}"; shift || true
dry_run=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --yes) DEPLOY_YES_CLI=1 ;;
    *) usage ;;
  esac
done
case "$network" in
  nile|shasta) mainnet=0 ;;
  mainnet) mainnet=1 ;;
  *) die "unknown network '$network' (nile | shasta | mainnet)" ;;
esac

load_env
need_tool node "install Node.js 18+"
need_tool npm
need_tool rsync
need_tool jq
require TRON_PRIVATE_KEY ADMIN
check_common_args "$mainnet"
require PAUSER   # 2_deploy.js insists on an explicit pauser

key="${TRON_PRIVATE_KEY#0x}"
[[ "$key" =~ ^[0-9a-fA-F]{64}$ ]] || die "TRON_PRIVATE_KEY must be 64 hex characters (0x prefix optional)"

cd "$BRIDGE_ROOT/tron"
if [[ ! -x node_modules/.bin/tronbox ]]; then
  info "installing tronbox into tron/node_modules"
  npm ci --no-audit --no-fund >/dev/null   # the tracked lockfile, exactly
fi

# TronBox compiles what it finds under tron/contracts, a mirror of evm/src.
mkdir -p contracts
rsync -a --delete ../evm/src/ contracts/
info "mirrored evm/src -> tron/contracts"

# TRON_RPC_URL overrides the host for whichever network was named, so the
# chain is identified by its genesis block rather than by that name.
case "$network" in
  nile) default_host=https://nile.trongrid.io ;;
  shasta) default_host=https://api.shasta.trongrid.io ;;
  mainnet) default_host=https://api.trongrid.io ;;
esac
host="${TRON_RPC_URL:-$default_host}"
info "network $network (rpc $(redact_url "$host"))"
need_tool curl
tron_mainnet_genesis=00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc
genesis="$(curl -fsS -X POST -H 'content-type: application/json' -d '{"num":0}' "${host%/}/wallet/getblockbynum" | jq -r '.blockID // empty')" \
  || die "cannot reach $(redact_url "$host")"
[[ -n "$genesis" ]] || die "$(redact_url "$host") returned no genesis block"
if [[ "$mainnet" == "1" && "$genesis" != "$tron_mainnet_genesis" ]]; then
  die "$(redact_url "$host") is not Tron mainnet (genesis $genesis)"
fi
if [[ "$mainnet" == "0" && "$genesis" == "$tron_mainnet_genesis" ]]; then
  die "$(redact_url "$host") is Tron MAINNET, but the network named is $network"
fi
npx tronbox compile

if [[ "$dry_run" == "1" ]]; then
  info "dry run only; compiled but nothing was deployed"
  exit 0
fi
confirm "$network" "$mainnet"

# TronBox reads the key from the environment of this one process (see
# tron/tronbox.js); it is never passed as an argument.
log="$(mktemp "${TMPDIR:-/tmp}/trx-migrate.XXXXXX")"
trap 'rm -f "$log"' EXIT
TRON_PRIVATE_KEY="$key" ADMIN="$ADMIN" PAUSER="$PAUSER" RAND_EMITTER="$RAND_EMITTER" GUARDIANS="$GUARDIANS" \
  npx tronbox migrate --network "$network" --reset 2>&1 | tee "$log"

# Only that line counts: `--reset` also redeploys Migrations, and its
# address must never be read back as the emitter.
# TronBox prints the name on one line and the two address forms on the next two.
line="$(grep -A2 -E 'TronRandBridge:' "$log" | tail -3 | tr '\n' ' ' || true)"
hex="$(grep -Eo '\(hex\) 41[0-9a-fA-F]{40}' <<<"$line" | awk '{print $2}' || true)"
base58="$(grep -Eo '\(base58\) T[1-9A-HJ-NP-Za-km-z]{33}' <<<"$line" | awk '{print $2}' || true)"
[[ -n "$hex" && -n "$base58" ]] || die "could not find the deployed address in tronbox's output; check tron/build/"
evm_form="0x${hex:2}"

echo
echo "deployed  $base58  (hex $hex, EVM form $evm_form)"
echo "emitter   $(emitter_wire_form "$evm_form")   <- bridge.emitters[\"4\"] in the Rand genesis"
record_deployment "tron-$network" "tron" "$base58" "" \
  "$(jq -n --arg hex "$hex" --arg evm "$evm_form" --arg e "$(emitter_wire_form "$evm_form")" '{address_hex:$hex, address_evm:$evm, emitter_wire_form:$e}')"
