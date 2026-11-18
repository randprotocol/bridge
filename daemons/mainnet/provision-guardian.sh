#!/usr/bin/env bash
# Lays a guardian down on a NEW host (BR-402): the binary, its config, the systemd unit, an
# empty secrets file and the data directory. Run it ON that host, as root. It contacts nothing,
# reads no key, writes no key, and does not start the service: the key holder puts the keys in
# the secrets file by hand, on that host, and starts it (docs/guardian-hosts.md, "Bringing a
# guardian up on its own host").
#
#   provision-guardian.sh --index 7 --binary ./rand-guardian --sha256 <64 hex> \
#       --config ./guardian-7.toml [--root <dir>] [--dry-run]
#
# --sha256   the checksum of the binary as built and recorded elsewhere; a mismatch stops here.
# --root     install under <dir> instead of / (a rehearsal or a test): no user is created and
#            systemd is not touched.
# It never overwrites: an existing binary, config, unit or secrets file that differs stops it.
set -euo pipefail

index="" binary="" sha="" config="" root="" dry=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --index) index="$2"; shift 2 ;;
    --binary) binary="$2"; shift 2 ;;
    --sha256) sha="$2"; shift 2 ;;
    --config) config="$2"; shift 2 ;;
    --root) root="${2%/}"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    *) echo "error: unknown argument $1" >&2; exit 2 ;;
  esac
done
die() { echo "error: $*" >&2; exit 1; }
[[ "$index" =~ ^[1-9][0-9]?$ ]] || die "--index <guardian number> is required"
[[ -f "$binary" ]] || die "--binary: $binary is not a file"
[[ "$sha" =~ ^[0-9a-fA-F]{64}$ ]] || die "--sha256 takes the binary's 64-hex checksum"
[[ -f "$config" ]] || die "--config: $config is not a file"

if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$binary" | cut -d' ' -f1)
else got=$(shasum -a 256 "$binary" | cut -d' ' -f1); fi
[[ "$(printf %s "$got" | tr A-F a-f)" == "$(printf %s "$sha" | tr A-F a-f)" ]] \
  || die "the binary's sha256 is $got, not the one given: do not install it"

# The config must be this guardian's: its key variables carry its number, and its API stays on
# loopback. Nothing in it is a secret.
key_env="GUARDIAN${index}_PRIV_KEY"
pq_env="GUARDIAN${index}_PQ_SEED"
grep -Eq "^key_env *= *\"$key_env\"" "$config" || die "the config's key_env is not \"$key_env\": wrong guardian's file?"
grep -Eq '^listen *= *"127\.0\.0\.1:[0-9]+"' "$config" || die "the config's [guardian] listen is not on 127.0.0.1"
grep -Eqi '(priv_key|pq_seed) *= *"[0-9a-f]{64}' "$config" && die "the config seems to carry key material; keys go in the secrets file only"

bin_to="$root/usr/local/bin/rand-guardian"
cfg_to="$root/etc/rand-guardian.toml"
env_to="$root/etc/rand-guardian/env"
unit_to="$root/etc/systemd/system/rand-guardian.service"
data_to="$root/var/lib/rand-guardian/data"

unit=$(cat <<UNIT
[Unit]
Description=Rand bridge guardian $index
After=network-online.target rand-node.service
Wants=network-online.target

[Service]
User=rand-guardian
Group=rand-guardian
EnvironmentFile=/etc/rand-guardian/env
ExecStart=/usr/local/bin/rand-guardian --config /etc/rand-guardian.toml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/rand-guardian

[Install]
WantedBy=multi-user.target
UNIT
)
envfile=$(cat <<ENV
# Secrets of guardian $index. Mode 600, root only; systemd reads it. Fill the two values ON THIS
# HOST, by the key holder; never copy this file anywhere.
$key_env=
$pq_env=
ENV
)

# Refuse to overwrite anything that is there and differs.
same_or_absent() { [[ ! -e "$1" ]] || cmp -s "$1" "$2" || die "$1 exists and differs; this script does not overwrite (move it aside after review)"; }
same_or_absent "$bin_to" "$binary"
same_or_absent "$cfg_to" "$config"
[[ ! -e "$unit_to" ]] || [[ "$(cat "$unit_to")" == "$unit" ]] || die "$unit_to exists and differs; this script does not overwrite"

echo "guardian $index: binary sha256 $got"
echo "  $bin_to"
echo "  $cfg_to"
echo "  $unit_to"
echo "  $env_to $([[ -e "$env_to" ]] && echo '(exists: left as it is)' || echo '(empty template)')"
echo "  $data_to"
if [[ $dry == 1 ]]; then echo "dry run: nothing written"; exit 0; fi

if [[ -z "$root" ]]; then
  [[ $EUID -eq 0 ]] || die "run as root (or pass --root <dir> for a rehearsal)"
  id rand-guardian >/dev/null 2>&1 || useradd --system --home /var/lib/rand-guardian --shell /usr/sbin/nologin rand-guardian
fi
install -d -m 755 "$root/usr/local/bin" "$root/etc/systemd/system"
install -d -m 700 "$root/etc/rand-guardian" "$root/var/lib/rand-guardian" "$data_to"
install -m 755 "$binary" "$bin_to"
install -m 640 "$config" "$cfg_to"
printf '%s\n' "$unit" >"$unit_to"
if [[ ! -e "$env_to" ]]; then (umask 077; printf '%s\n' "$envfile" >"$env_to"); fi
chmod 600 "$env_to"
if [[ -z "$root" ]]; then
  chown -R rand-guardian:rand-guardian /var/lib/rand-guardian
  chown root:rand-guardian "$cfg_to"
  systemctl daemon-reload
fi

cat <<NEXT
done; the service is NOT started. Next, on this host:
  1. the key holder fills $key_env and $pq_env in /etc/rand-guardian/env (mode 600)
  2. systemctl enable --now rand-guardian; journalctl -u rand-guardian -f
  3. curl -s http://127.0.0.1:<listen port>/v1/health   # names this guardian's address
  4. from the relayer host: rand-bridge-audit --config <relayer.toml> --headroom
NEXT
