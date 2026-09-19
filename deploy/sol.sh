#!/usr/bin/env bash
# Builds, deploys and initializes the Solana program (rand_bridge, bridge
# chain 5) from the command line.
#
#   deploy/sol.sh [devnet|testnet|mainnet-beta|localnet] [--dry-run] [--yes] [--skip-build]
#
#   --dry-run    build and print what would happen; no deployment
#   --yes        skip the confirmation prompt (DEPLOY_YES=1 does too, on testnets only)
#   --skip-build reuse solana/target/deploy/rand_bridge.so
#
# Environment / deploy/.env:
#   SOL_KEYPAIR          path to the deployer's solana-keygen JSON file, or
#   SOL_PRIVATE_KEY      the secret inline (JSON byte array, or base58 secret/seed)
#   SOL_PROGRAM_KEYPAIR  optional: the program id keypair; generated under
#                        deploy/keys/ and reused if absent
#   SOL_RPC_URL          optional: overrides the network's public endpoint
#   SOL_ADMIN            the admin pubkey (a multisig in production)
#   SOL_PAUSER           optional pauser pubkey; defaults to SOL_ADMIN
#   RAND_EMITTER, GUARDIANS   as for the EVM endpoints
#
# The deployer is the program's upgrade authority, which is what `Initialize`
# requires. Hand the authority to a multisig afterwards:
#   solana program set-upgrade-authority <PROGRAM_ID> --new-upgrade-authority <MULTISIG>
#
# Needs the Solana CLI (agave) for `cargo build-sbf` and `solana program deploy`:
#   sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { sed -n '2,27p' "${BASH_SOURCE[0]}" >&2; exit 1; }

network="${1:-devnet}"; shift || true
dry_run=0; skip_build=0; DEPLOY_YES_CLI=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --yes) DEPLOY_YES_CLI=1 ;;
    --skip-build) skip_build=1 ;;
    *) usage ;;
  esac
done
case "$network" in
  devnet)       default_rpc=https://api.devnet.solana.com;       mainnet=0 ;;
  testnet)      default_rpc=https://api.testnet.solana.com;      mainnet=0 ;;
  mainnet-beta) default_rpc=https://api.mainnet-beta.solana.com; mainnet=1 ;;
  localnet)     default_rpc=http://127.0.0.1:8899;               mainnet=0 ;;
  *) die "unknown network '$network' (devnet | testnet | mainnet-beta | localnet)" ;;
esac

load_env
need_tool cargo
need_tool solana "install the Solana CLI: sh -c \"\$(curl -sSfL https://release.anza.xyz/stable/install)\""
need_tool solana-keygen
need_tool cargo-build-sbf "part of the Solana CLI install"
need_tool jq
require SOL_ADMIN RAND_EMITTER GUARDIANS
check_common_args "$mainnet"
[[ -n "${SOL_KEYPAIR:-}" || -n "${SOL_PRIVATE_KEY:-}" ]] || die "set SOL_KEYPAIR (file) or SOL_PRIVATE_KEY (inline secret)"
rpc="${SOL_RPC_URL:-$default_rpc}"
export SOL_RPC_URL="$rpc"

# SOL_RPC_URL overrides the cluster for whichever network was named, so
# the cluster is identified by its genesis hash rather than by that name.
case "$network" in
  devnet)       want_genesis=EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG ;;
  testnet)      want_genesis=4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY ;;
  mainnet-beta) want_genesis=5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d ;;
  localnet)     want_genesis= ;;
esac
rpc_shown="$(redact_url "$rpc")"
got_genesis="$(solana genesis-hash --url "$rpc")" || die "cannot reach $rpc_shown"
if [[ -n "$want_genesis" ]]; then
  [[ "$got_genesis" == "$want_genesis" ]] || die "$rpc_shown is not $network (genesis hash $got_genesis)"
else
  case "$got_genesis" in
    EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG|4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY|5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d)
      die "$rpc_shown is a public cluster, but the network named is localnet" ;;
  esac
fi

# The CLI reads the deployer from SOL_KEYPAIR / SOL_PRIVATE_KEY in its own
# environment. load_env keeps the inline secret un-exported, so it is
# exported inside this subshell only, to the built binary only (not to
# cargo and its build scripts).
cli_manifest="$BRIDGE_ROOT/solana/Cargo.toml"
cli_bin="$BRIDGE_ROOT/solana/target/release/rand-bridge-cli"
cli() (
  if [[ -n "${SOL_PRIVATE_KEY:-}" ]]; then export SOL_PRIVATE_KEY; fi
  exec "$cli_bin" "$@"
)

info "building rand-bridge-cli"
cargo build --quiet --release --manifest-path "$cli_manifest" -p rand-bridge-cli
[[ -x "$cli_bin" ]] || die "build did not produce $cli_bin"

# The deployer keypair as a file, which `solana program deploy` needs. An
# inline secret is written to a private temp file that is removed on exit.
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/sol-deploy.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT
if [[ -n "${SOL_KEYPAIR:-}" ]]; then
  deployer_file="$SOL_KEYPAIR"
else
  deployer_file="$tmpdir/deployer.json"
  cli export-keypair --out "$deployer_file"
fi
deployer="$(cli address)"
info "network $network (rpc $rpc_shown)"
info "deployer $deployer (balance $(solana balance --url "$rpc" "$deployer" 2>/dev/null || echo '?'))"

# The program id is a keypair: generated once per network and kept under
# deploy/keys (git-ignored). Losing it is not fatal — upgrades use the
# upgrade authority, not this key — but keep it anyway.
mkdir -p "$DEPLOY_DIR/keys"
program_file="${SOL_PROGRAM_KEYPAIR:-$DEPLOY_DIR/keys/solana-$network-program.keypair.json}"
if [[ ! -f "$program_file" ]]; then
  info "generating program keypair $program_file"
  solana-keygen new --no-bip39-passphrase --silent --outfile "$program_file"
fi
program_id="$(solana-keygen pubkey "$program_file")"
info "program id $program_id"

# `declare_id!` in lib.rs is part of the program: every PDA is derived
# from it, so it must match the keypair the program is deployed under.
lib_rs="$BRIDGE_ROOT/solana/programs/rand-bridge/src/lib.rs"
declared="$(sed -nE 's/^solana_program::declare_id!\("([1-9A-HJ-NP-Za-km-z]+)"\);/\1/p' "$lib_rs")"
if [[ "$declared" != "$program_id" ]]; then
  info "updating declare_id! in $lib_rs ($declared -> $program_id)"
  sed -i.bak -E "s/^solana_program::declare_id!\(\"[1-9A-HJ-NP-Za-km-z]+\"\);/solana_program::declare_id!(\"$program_id\");/" "$lib_rs"
  rm -f "$lib_rs.bak"
  grep -qF "declare_id!(\"$program_id\");" "$lib_rs" || die "could not rewrite declare_id! in $lib_rs"
  echo "note: src/lib.rs now declares the $network program id; commit that change with the deployment record" >&2
  skip_build=0
fi

# SBPF v3: live on devnet and mainnet (SIMD-0178/0189/0377), and the only
# format left once SIMD-0500 disables v0-v2 deployments. cargo build-sbf
# still defaults to v0, which a default solana-test-validator (every
# feature active) already refuses.
so="$BRIDGE_ROOT/solana/target/deploy/rand_bridge.so"
if [[ "$skip_build" == "0" || ! -f "$so" ]]; then
  info "cargo build-sbf --arch v3"
  (cd "$BRIDGE_ROOT/solana" && cargo build-sbf --arch v3 --manifest-path programs/rand-bridge/Cargo.toml)
fi
[[ -f "$so" ]] || die "build did not produce $so"
info "program binary $so ($(du -h "$so" | cut -f1))"

if [[ "$dry_run" == "1" ]]; then
  info "dry run only; would deploy $program_id to $network and initialize with admin $SOL_ADMIN"
  exit 0
fi
confirm "$network" "$mainnet"

solana program deploy "$so" \
  --url "$rpc" \
  --keypair "$deployer_file" \
  --program-id "$program_file" \
  --upgrade-authority "$deployer_file"

# The program is live from here on: write the record before anything
# else can fail, so a deployment never exists without one.
# The emitter is the program id's 32 bytes: the second half of the keypair file.
wire="0x$(jq -r '"0123456789abcdef" as $h | .[32:] | map($h[(. / 16 | floor):(. / 16 | floor) + 1] + $h[(. % 16):(. % 16) + 1]) | join("")' "$program_file")"
[[ "$wire" =~ ^0x[0-9a-f]{64}$ ]] || die "could not read the program id out of $program_file"
ADMIN="$SOL_ADMIN" PAUSER="${SOL_PAUSER:-$SOL_ADMIN}" record_deployment "solana-$network" "solana" "$program_id" "" \
  "$(jq -n --arg e "$wire" --arg d "$deployer" '{emitter_wire_form:$e, upgrade_authority:$d}')"

info "initializing (admin $SOL_ADMIN, pauser ${SOL_PAUSER:-$SOL_ADMIN})"
cli initialize --program "$program_id" --admin "$SOL_ADMIN" ${SOL_PAUSER:+--pauser "$SOL_PAUSER"} \
  --rand-emitter "$RAND_EMITTER" --guardians "$GUARDIANS"

shown="$(cli show --program "$program_id" | jq -r .program_hex)"
[[ "$shown" == "$wire" ]] || die "the program reports emitter $shown, the record says $wire"
echo
echo "deployed  $program_id"
echo "emitter   $wire   <- bridge.emitters[\"5\"] in the Rand genesis"
echo "next: solana program set-upgrade-authority $program_id --new-upgrade-authority <MULTISIG> --url $rpc" >&2
