#!/usr/bin/env bash
# Shared helpers for the deploy scripts. Sourced, never executed.
#
# Keys are read from the environment (usually loaded from `deploy/.env`,
# which is git-ignored) and handed to the tools through the environment
# too, never on a command line, so they do not show up in `ps` output or
# shell history. Nothing here ever prints a key.

set -euo pipefail

BRIDGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$BRIDGE_ROOT/deploy"
DEPLOYMENTS_DIR="$DEPLOY_DIR/deployments"

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*" >&2; }

# Loads `deploy/.env` (or $DEPLOY_ENV_FILE) into the environment without
# echoing anything. Variables already set in the environment win, so a
# one-off `ETH_RPC_URL=... deploy/eth.sh sepolia` overrides the file.
load_env() {
  local file="${DEPLOY_ENV_FILE:-$DEPLOY_DIR/.env}"
  if [[ -f "$file" ]]; then
    local perms
    perms="$(stat -f '%Lp' "$file" 2>/dev/null || stat -c '%a' "$file")"
    if [[ "$perms" != "600" && "$perms" != "400" ]]; then
      echo "warning: $file is mode $perms; consider chmod 600" >&2
    fi
    # Only fill in what the caller has not already exported.
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
      line="${line#export }"
      local name="${line%%=*}"
      local value="${line#*=}"
      [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
      # Strip one layer of matching quotes.
      if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then
        value="${BASH_REMATCH[1]}"
      fi
      # The mainnet confirmation can only be waived on the command line.
      [[ "$name" == "DEPLOY_YES_CLI" ]] && continue
      if [[ -z "${!name:-}" ]]; then
        export "$name=$value"
      fi
    done < "$file"
  fi
  # Keys stay shell variables: each script hands exactly one of them to
  # the one process that signs, so `npm`, `cargo` and `forge install`
  # (and whatever install scripts they run) never see any of them.
  export -n ETH_PRIVATE_KEY BSC_PRIVATE_KEY TRON_PRIVATE_KEY SOL_PRIVATE_KEY \
    ANVIL_PRIVATE_KEY DEPLOYER_PRIVATE_KEY 2>/dev/null || true
}

# `https://host/path?key` -> `https://host`: RPC URLs often embed an API
# key, so only the origin is ever logged.
redact_url() { sed -E 's#^([a-zA-Z]+://)([^/@]*@)?([^/?]+).*#\1\3#' <<<"$1"; }

# Fails unless every named variable is set and non-empty.
require() {
  local missing=()
  local v
  for v in "$@"; do
    [[ -n "${!v:-}" ]] || missing+=("$v")
  done
  if (( ${#missing[@]} )); then
    die "missing required variable(s): ${missing[*]} (see deploy/.env.example)"
  fi
}

# `0x` + 64 hex: an EVM/Tron secp256k1 private key.
is_hex_key() { [[ "$1" =~ ^0x[0-9a-fA-F]{64}$ ]]; }
is_hex32() { [[ "$1" =~ ^0x[0-9a-fA-F]{64}$ ]]; }
is_evm_address() { [[ "$1" =~ ^0x[0-9a-fA-F]{40}$ ]]; }

# Validates the attestation arguments every endpoint shares. The admin is
# chain-specific (an EVM address for the EVM/Tron scripts, a pubkey for
# Solana), so each script requires its own.
check_common_args() {
  local is_mainnet="${1:-0}"
  require RAND_EMITTER GUARDIANS
  is_hex32 "$RAND_EMITTER" || die "RAND_EMITTER must be 0x + 64 hex (the 32-byte Rand burn emitter from genesis)"
  local n
  n="$(tr ',' '\n' <<<"$GUARDIANS" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
  (( n >= 1 )) || die "GUARDIANS must list at least one guardian address"
  (( n <= 255 )) || die "GUARDIANS lists $n keys; a rotation's key count is one byte"
  local g seen=""
  while IFS= read -r g; do
    g="$(tr -d '[:space:]' <<<"$g" | tr 'A-F' 'a-f')"
    [[ -z "$g" ]] && die "GUARDIANS has an empty entry (it would shift every later index)"
    is_evm_address "$g" || die "GUARDIANS entry '$g' is not 0x + 40 hex"
    [[ "$g" != "0x0000000000000000000000000000000000000000" ]] || die "GUARDIANS has a zero key"
    [[ "$seen" != *"$g"* ]] || die "GUARDIANS lists $g twice"
    seen+=" $g"
  done < <(tr ',' '\n' <<<"$GUARDIANS")
  if [[ "$n" -lt 6 ]]; then
    [[ "$is_mainnet" == "0" ]] || die "GUARDIANS lists $n keys; a mainnet deployment needs the launch set of 6"
    [[ "${ALLOW_SMALL_GUARDIAN_SET:-0}" == "1" ]] \
      || die "GUARDIANS lists $n keys; the launch set is 6 (set ALLOW_SMALL_GUARDIAN_SET=1 for a testnet rehearsal)"
  fi
  if [[ "$is_mainnet" == "1" ]]; then
    check_network_separation
  fi
}

# An attestation's digest covers only its body, and testnets share the
# mainnet bridge chain ids and the governance emitter: a guardian key or a
# Rand emitter that ever served a testnet bridge would let that testnet's
# rotations and burns replay against mainnet. Refuse a mainnet deployment
# that reuses anything a non-mainnet deployment record carries.
check_network_separation() {
  local f
  shopt -s nullglob
  for f in "$DEPLOYMENTS_DIR"/*.json; do
    case "$(basename "$f" .json)" in ethereum|bsc|tron-mainnet|solana-mainnet-beta) continue ;; esac
    local reused
    reused="$(jq -r --arg e "$RAND_EMITTER" --arg g "$GUARDIANS" '
      ($g | ascii_downcase | split(",") | map(gsub("\\s";""))) as $mine
      | [ .[] | ((.guardians // []) | map(ascii_downcase)) as $theirs
          | (if (.rand_emitter // "" | ascii_downcase) == ($e | ascii_downcase) then "RAND_EMITTER" else empty end),
            ($mine[] | select(. as $k | $theirs | index($k))) ]
      | unique | join(" ")' "$f")"
    [[ -z "$reused" ]] || die "mainnet must not reuse testnet values (found in $f): $reused"
  done
  shopt -u nullglob
}

# Asks before touching a live network. `--yes` skips it; DEPLOY_YES=1
# (environment or .env) skips it on testnets only, so a leftover setting
# can never waive the mainnet prompt, which requires the network name to
# be typed back.
confirm() {
  local network="$1" is_mainnet="$2"
  if [[ "${DEPLOY_YES_CLI:-0}" == "1" ]]; then
    return 0
  fi
  if [[ "$is_mainnet" == "0" && "${DEPLOY_YES:-0}" == "1" ]]; then
    return 0
  fi
  if [[ "$is_mainnet" == "1" ]]; then
    echo "This deploys to MAINNET ($network) and spends real funds." >&2
    read -r -p "Type the network name to continue: " typed
    [[ "$typed" == "$network" ]] || die "aborted"
  else
    read -r -p "Deploy to $network? [y/N] " yn
    [[ "$yn" =~ ^[Yy]$ ]] || die "aborted"
  fi
}

# Appends a deployment record: deploy/deployments/<network>.json (an
# array, newest last), so the address that goes into the Rand genesis
# `bridge.emitters` table is written down the moment it exists.
record_deployment() {
  local network="$1" chain="$2" address="$3" tx="$4" extra_json="${5:-{\}}"
  mkdir -p "$DEPLOYMENTS_DIR"
  local file="$DEPLOYMENTS_DIR/$network.json"
  local commit
  commit="$(git -C "$BRIDGE_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  local entry
  entry="$(jq -n \
    --arg network "$network" --arg chain "$chain" --arg address "$address" \
    --arg tx "$tx" --arg admin "${ADMIN:-}" --arg pauser "${PAUSER:-}" \
    --arg rand_emitter "${RAND_EMITTER:-}" --arg guardians "${GUARDIANS:-}" \
    --arg commit "$commit" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson extra "$extra_json" \
    '{network:$network, chain:$chain, address:$address, tx:$tx, admin:$admin, pauser:$pauser,
      rand_emitter:$rand_emitter, guardians:($guardians|split(",")|map(gsub("^\\s+|\\s+$";""))),
      bridge_commit:$commit, deployed_at:$at} + $extra')"
  if [[ -f "$file" ]]; then
    jq --argjson e "$entry" '. + [$e]' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
  else
    jq -n --argjson e "$entry" '[$e]' > "$file"
  fi
  info "recorded in $file"
}

# The 32-byte, left-padded wire form of a 20-byte address: what goes into
# the Rand genesis `bridge.emitters` entry for this chain.
emitter_wire_form() {
  local addr="${1#0x}"
  printf '0x%024d%s\n' 0 "$(tr 'A-F' 'a-f' <<<"$addr")"
}

need_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not installed${2:+: $2}"
}
