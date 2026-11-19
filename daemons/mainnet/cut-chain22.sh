#!/usr/bin/env bash
# Moves the bridge daemons from Rand chain 21 to chain 22 (fullnode v0.8.7: zkVM constraint set 11).
# Derived from cut-chain21.sh; the fleet side is fullnode deploy/cutover-fleet-chain22.sh (main
# e79070a7), whose `bridge-start` waits for BRIDGE_ON_CHAIN22=yes, i.e. for this script's steps 4-5.
# The endpoints, emitters, guardian sets and fees do not change (cut-chain22-genesis.sh carries chain
# 21's `bridge` section and asserts it). What changes in the daemons: chain_id 21 -> 22, genesis_hash
# chain 21's -> chain 22's (BR-1005: a cut changes BOTH lines), the Rand burn cursor, and the
# relayer's `rand` (-> v0.8.7: set 11 moves every Poseidon2 output — note commitments, nullifiers,
# the owner field `pk` of every rand1 address — so a set-9 `rand` cannot mint on chain 22 and a
# v0.8.7 `rand` cannot serve chain 21). The guardian and relayer binaries themselves compute no
# Poseidon2 and need no rebuild for set 11. Prints every command; runs them only with --yes. In this
# order:
#
#   status                [0] read-only: the relayer's installed `rand` (sha256, --version); gives RAND_OLD_SHA
#   stop                  [1] relayer + laptop guardians 7-8 + droplet guardians (before the snapshot)
#   relayer-rand RANDFILE [3] on rand-relayer-1, relayer STOPPED, after the fleet's `switch`: back up the
#                         installed `rand` as /usr/local/bin/rand.pre-c22 (checked against
#                         RAND_OLD_SHA), install the v0.8.7 `rand` from RANDFILE (checked against
#                         RAND_NEW_SHA locally and on the host), check the installed sha
#   droplet <1..6>        [4] once that droplet's rand-node answers for chain 22 with GENESIS_HASH:
#                         guardian config to chain_id 22 + GENESIS_HASH, Rand cursor to BURN_SEQ,
#                         guardian started
#   relayer               [5] /etc/rand-relayer.toml to chain_id 22 + GENESIS_HASH, Rand cursor to
#                         BURN_SEQ, `rand` is v0.8.7 (the relayer is NOT started here)
#   laptop                [5] guardian-7/8.toml to chain_id 22 + GENESIS_HASH, their Rand cursors to BURN_SEQ
#   start                 [6] laptop guardians 7-8 (pq-next seeds), THEN the relayer, never before
#   rollback-rand         rollback: restore rand.pre-c22 as `rand` (relayer stopped; sha checked twice)
#   selftest              rehearsal with ssh/scp/ssh-keyscan/curl shimmed by fakes: contacts nothing
#
# Inputs, none of which exists before the cut (so none has a default):
#   GENESIS_HASH  chain 22's genesis hash, 64 hex, from fullnode deploy/cut-records/chain22.record
#                 (the second operator's confirmed hash), NOT read from a node. Every step that
#                 writes it checks it against RAND_RPC's rand_getGenesisHash and, on a guardian
#                 host, against that host's own node.
#   BURN_SEQ      chain 22's rand_getBridgeState.burn_sequence (= chain 21's at the snapshot, carried).
#                 Every step that writes it into a cursor first reads it from RAND_RPC (default
#                 http://127.0.0.1:8545, a tunnel to a chain-22 node; it must answer rand_chainId 22)
#                 and refuses unless BURN_SEQ equals it (BR-401); the guardian-host step checks the
#                 same against that host's own node before it writes.
#   RAND_OLD_SHA  the sha256 of the relayer's installed `rand` today (read it with `status`).
#   RAND_NEW_SHA  the sha256 of the Linux `rand` in fullnode v0.8.7's signed SHA256SUMS.
# Modes: no --yes = print only; --yes = run; DRY_RUN=1 = print every command, contact/touch nothing
# (wins over --yes). Relayer host key is checked against RELAYER_HOSTKEY before any relayer ssh.
# shellcheck disable=SC2015,SC2016
set -euo pipefail
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
cd "$(dirname "$SELF")/.."

FROM=21; TO=22
NEW_VERSION=0.8.7
NEW_VERSION_RE='0\.8\.7'   # what `rand --version` must contain
# Chain 21's genesis hash (fullnode deploy/cut-records/chain21.record): the line every config holds today.
OLD_GENESIS=ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a
# The relayer host's address and SSH host-key fingerprint are not in this public repository: from
# the environment, or from ~/.rand-bridge/relayer-host/host.txt (lines `public <ip>` and
# `hostkey SHA256:<fingerprint>`).
RELAYER_HOST_FILE="$HOME/.rand-bridge/relayer-host/host.txt"
RELAYER_IP="${RELAYER_IP:-$(awk '$1=="public"{print $2}' "$RELAYER_HOST_FILE" 2>/dev/null || true)}"
RELAYER_HOSTKEY="${RELAYER_HOSTKEY:-$(awk '$1=="hostkey"{print $2}' "$RELAYER_HOST_FILE" 2>/dev/null || true)}"
# TODO(chain-22 cut): both from the environment. RAND_OLD_SHA = what `status` reads on the relayer
# host; RAND_NEW_SHA = the Linux `rand` line of v0.8.7's signed SHA256SUMS (not tagged yet).
RAND_OLD_SHA="${RAND_OLD_SHA:-}"
RAND_NEW_SHA="${RAND_NEW_SHA:-}"
GENESIS_HASH="${GENESIS_HASH:-}"
RAND_RPC="${RAND_RPC:-http://127.0.0.1:8545}"
HOSTS="$HOME/.rand-bridge/mainnet-set1/hosts.txt"
KEY="$HOME/.ssh/rand_guardian_ed25519"
SSH=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o UserKnownHostsFile="$HOME/.ssh/rand_guardian_known_hosts" -i "$KEY")
RSSH=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$HOME/.ssh/rand_relayer_known_hosts" -i "$KEY" "root@$RELAYER_IP")
RSCP=(scp -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$HOME/.ssh/rand_relayer_known_hosts" -i "$KEY")

step="${1:-}"; shift || true
arg=""; yes=0
for a in "$@"; do [[ "$a" == --yes ]] && yes=1 || arg="$a"; done
dry=0; [[ "${DRY_RUN:-}" == 1 ]] && { dry=1; yes=0; }
run() { echo "+ $*"; if (( yes )); then "$@"; fi; }
ip_of() { awk -v i="$1" '$1==i{print $2}' "$HOSTS"; }
need() { for v in "$@"; do [[ -n "${!v:-}" ]] || { echo "error: $v is not set" >&2; exit 1; }; done; }
need_sha() { for v in "$@"; do need "$v"; [[ "${!v}" =~ ^[0-9a-f]{64}$ ]] || { echo "error: $v is not 64 lowercase hex" >&2; exit 1; }; done; }
need_genesis() {
  need_sha GENESIS_HASH
  [[ "$GENESIS_HASH" != "$OLD_GENESIS" ]] || { echo "error: GENESIS_HASH is chain $FROM's genesis, not chain $TO's" >&2; exit 1; }
}
die() { echo "error: $*" >&2; exit 1; }
local_sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
answers() { printf 'curl -s -m 5 -X POST -H "content-type: application/json" --data '"'"'{"jsonrpc":"2.0","id":1,"method":"rand_chainId","params":[]}'"'"' http://127.0.0.1:8545 | grep -q '"'"'"result":%s\\b'"'"'' "$TO"; }
# The remote twin of check_burn_seq: the guardian host's own node must say burn_sequence == BURN_SEQ.
burn_seq_matches() { printf 'curl -s -m 5 -X POST -H "content-type: application/json" --data '"'"'{"jsonrpc":"2.0","id":1,"method":"rand_getBridgeState","params":[]}'"'"' http://127.0.0.1:8545 | grep -q '"'"'"burn_sequence":%s\\b'"'"'' "$BURN_SEQ"; }
# The remote twin of check_genesis: the guardian host's own node must serve GENESIS_HASH.
genesis_matches() { printf 'curl -s -m 5 -X POST -H "content-type: application/json" --data '"'"'{"jsonrpc":"2.0","id":1,"method":"rand_getGenesisHash","params":[]}'"'"' http://127.0.0.1:8545 | grep -qE '"'"'"result":"(0x)?%s"'"'"'' "$GENESIS_HASH"; }
# The two config lines a cut changes (BR-1005), as one sed program, and the check that both took.
SWITCH_SED='s/^chain_id = '"$FROM"' /chain_id = '"$TO"' /; s/^genesis_hash = "'"$OLD_GENESIS"'"/genesis_hash = "'"${GENESIS_HASH:-GENESIS_HASH}"'"/'
# A host config from before BR-1005 (rand-guardian / rand-relayer up to the v0.8.6 tag have no
# `genesis_hash` field and refuse an unknown one) has no genesis line: it is left without one, and
# the step says so. A config that has the line must end up holding chain 22's, never chain 21's.
switched() {
  local f=$1
  echo "grep -q '^chain_id = $TO ' $f && ! grep -q '$OLD_GENESIS' $f && { ! grep -q '^genesis_hash' $f || grep -q '^genesis_hash = \"$GENESIS_HASH\"' $f; } && { if grep -q '^genesis_hash' $f; then echo '$f: genesis_hash is chain $TO genesis'; else echo '$f: NOTE no genesis_hash line (a pre-BR-1005 daemon), chain_id only'; fi; }"
}
sedi() { sed -i.bak -E "$1" "$2" && rm -f "$2.bak"; }
rpc_result() { curl -s -m 5 -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" "$RAND_RPC"; }

# BR-401: BURN_SEQ is the next Rand burn sequence every daemon's cursor is set to. It must be
# chain $TO's own rand_getBridgeState.burn_sequence, read from the chain-$TO node this machine
# reaches (RAND_RPC), which must answer for chain $TO — never a number typed from memory.
check_burn_seq() {
  echo "+ curl $RAND_RPC rand_chainId / rand_getGenesisHash / rand_getBridgeState   # expect chain $TO, GENESIS_HASH and burn_sequence == BURN_SEQ ($BURN_SEQ)"
  (( yes )) || return 0
  local id seq
  id=$(rpc_result rand_chainId | grep -oE '"result":[0-9]+' | cut -d: -f2 || true)
  [[ "$id" == "$TO" ]] || die "the node at $RAND_RPC answers for chain '${id:-?}', not $TO (set RAND_RPC to a chain-$TO node); nothing was run"
  local gen
  gen=$(rpc_result rand_getGenesisHash | grep -oE '"result":"(0x)?[0-9a-f]{64}"' | cut -d'"' -f4 | sed 's/^0x//' || true)
  [[ "$gen" == "$GENESIS_HASH" ]] || die "the node at $RAND_RPC serves genesis '${gen:-?}', not GENESIS_HASH $GENESIS_HASH; nothing was run"
  seq=$(rpc_result rand_getBridgeState | grep -oE '"burn_sequence":[0-9]+' | cut -d: -f2 || true)
  [[ -n "$seq" ]] || die "the node at $RAND_RPC did not serve rand_getBridgeState.burn_sequence; nothing was run"
  [[ "$seq" == "$BURN_SEQ" ]] || die "BURN_SEQ is $BURN_SEQ but chain $TO's burn_sequence is $seq (cursors must not run ahead of the chain); nothing was run"
}

# The relayer host key must be the recorded one before any command reaches it.
check_hostkey() {
  [[ -n "$RELAYER_IP" && -n "$RELAYER_HOSTKEY" ]] || die "the relayer host is not configured: set RELAYER_IP and RELAYER_HOSTKEY, or put 'public <ip>' and 'hostkey SHA256:…' in $RELAYER_HOST_FILE; nothing was run"
  echo "+ ssh-keyscan -t ed25519 $RELAYER_IP | ssh-keygen -lf -   # expect $RELAYER_HOSTKEY"
  (( yes )) || return 0
  local got
  got=$(ssh-keyscan -t ed25519 "$RELAYER_IP" 2>/dev/null | ssh-keygen -lf - | awk '{print $2}')
  [[ "$got" == "$RELAYER_HOSTKEY" ]] || die "relayer host key is '$got', not $RELAYER_HOSTKEY; nothing was run"
}

case "$step" in
  status)
    check_hostkey
    run "${RSSH[@]}" 'sha256sum /usr/local/bin/rand; /usr/local/bin/rand --version; ls -l /usr/local/bin/rand*; systemctl is-active rand-relayer || true; grep -E "^(chain_id|genesis_hash) = " /etc/rand-relayer.toml'
    ;;
  stop)
    check_hostkey
    run "${RSSH[@]}" 'systemctl stop rand-relayer; systemctl is-active rand-relayer || true'
    run pkill -f 'rand-guardian --config mainnet/guardian-[78].toml' || true
    for i in 1 2 3 4 5 6; do run "${SSH[@]}" "root@$(ip_of "$i")" 'systemctl stop rand-guardian; systemctl is-active rand-guardian || true'; done
    ;;
  relayer-rand)
    [[ -n "$arg" ]] || die "usage: relayer-rand <path to the v$NEW_VERSION Linux rand> [--yes]"
    need_sha RAND_OLD_SHA RAND_NEW_SHA
    if (( dry )) && [[ ! -f "$arg" ]]; then
      echo "# (dry run: $arg not present, local sha check skipped; --yes refuses unless it is $RAND_NEW_SHA)"
    else
      [[ -f "$arg" ]] || die "$arg: no such file"
      [[ "$(local_sha "$arg")" == "$RAND_NEW_SHA" ]] || die "$arg sha256 is not $RAND_NEW_SHA; SHA MISMATCH, nothing sent"
    fi
    check_hostkey
    run "${RSCP[@]}" "$arg" "root@$RELAYER_IP:/root/rand.c22"
    run "${RSSH[@]}" "set -e
! systemctl is-active -q rand-relayer || { echo 'stop the relayer first' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'installed rand is NOT RAND_OLD_SHA (read it with status) - no backup made, nothing installed' >&2; exit 1; }
[ -e /usr/local/bin/rand.pre-c22 ] || cp -a /usr/local/bin/rand /usr/local/bin/rand.pre-c22
[ \"\$(sha256sum /usr/local/bin/rand.pre-c22 | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'rand.pre-c22 is NOT RAND_OLD_SHA - sort it out by hand; nothing installed' >&2; exit 1; }
[ \"\$(sha256sum /root/rand.c22 | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { rm -f /root/rand.c22; echo 'SHA MISMATCH' >&2; exit 1; }
install -m 755 /root/rand.c22 /usr/local/bin/rand
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { echo 'the installed rand is NOT the v$NEW_VERSION binary - stop here' >&2; exit 1; }
/usr/local/bin/rand --version | grep -q '$NEW_VERSION_RE'
/usr/local/bin/rand --version"
    ;;
  droplet)
    need BURN_SEQ; need_genesis
    [[ "$arg" =~ ^[1-6]$ ]] || { echo "usage: droplet <1..6>" >&2; exit 1; }
    check_burn_seq
    run "${SSH[@]}" "root@$(ip_of "$arg")" "set -e
! systemctl is-active -q rand-guardian || { echo 'error: rand-guardian is still running' >&2; exit 1; }
$(answers) || { echo 'error: this droplet does not answer for chain $TO' >&2; exit 1; }
$(genesis_matches) || { echo 'error: this host'\\''s node does not serve genesis $GENESIS_HASH' >&2; exit 1; }
$(burn_seq_matches) || { echo 'error: this host'\\''s node does not say burn_sequence $BURN_SEQ' >&2; exit 1; }
[ ! -e /etc/rand-guardian.toml.chain$FROM ]
cp -p /etc/rand-guardian.toml /etc/rand-guardian.toml.chain$FROM
sed -i -E '$SWITCH_SED' /etc/rand-guardian.toml
$(switched /etc/rand-guardian.toml) || { echo 'error: /etc/rand-guardian.toml did not take chain $TO and its genesis' >&2; exit 1; }
cp -rp /var/lib/rand-guardian/data/cursors /var/lib/rand-guardian/data/cursors.chain$FROM
echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > /var/lib/rand-guardian/data/cursors/rand.json
chown -R guardian: /var/lib/rand-guardian/data
systemctl start rand-guardian; sleep 6; systemctl is-active rand-guardian; journalctl -u rand-guardian -n 3 --no-pager"
    ;;
  relayer)
    need BURN_SEQ; need_genesis; need_sha RAND_NEW_SHA
    check_burn_seq
    check_hostkey
    run "${RSSH[@]}" "set -e
! systemctl is-active -q rand-relayer || { echo 'error: the relayer is still running' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { echo 'error: installed rand is not v$NEW_VERSION; run relayer-rand first' >&2; exit 1; }
[ ! -e /etc/rand-relayer.toml.chain$FROM ]
cp -p /etc/rand-relayer.toml /etc/rand-relayer.toml.chain$FROM
sed -i -E '$SWITCH_SED' /etc/rand-relayer.toml
$(switched /etc/rand-relayer.toml) || { echo 'error: /etc/rand-relayer.toml did not take chain $TO and its genesis' >&2; exit 1; }
cp -rp /var/lib/rand-relayer/data/cursors /var/lib/rand-relayer/data/cursors.chain$FROM
echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > /var/lib/rand-relayer/data/cursors/rand.json
chown -R relayer: /var/lib/rand-relayer/data
/usr/local/bin/rand --version | grep -q '$NEW_VERSION_RE'
systemctl is-active rand-relayer || true   # inactive: it starts at 'start', after the guardians"
    ;;
  laptop)
    need BURN_SEQ; need_genesis
    check_burn_seq
    for f in mainnet/guardian-7.toml mainnet/guardian-8.toml; do
      run cp -p "$f" "$f.chain$FROM"
      echo "+ sed -i -E '$SWITCH_SED' $f"
      if (( yes )); then
        sedi "$SWITCH_SED" "$f"
        grep -q "^chain_id = $TO " "$f" && grep -q "^genesis_hash = \"$GENESIS_HASH\"" "$f" || die "$f is not on chain $TO with genesis $GENESIS_HASH"
      fi
    done
    for d in guardian-7 guardian-8; do
      run cp -Rp "data/mainnet/$d/cursors" "data/mainnet/$d/cursors.chain$FROM"
      echo "+ echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > data/mainnet/$d/cursors/rand.json"
      (( yes )) && echo "{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}" > "data/mainnet/$d/cursors/rand.json"
    done
    ;;
  start)
    need_genesis; need_sha RAND_NEW_SHA
    for g in 7 8; do
      { grep -q "^chain_id = $TO " "mainnet/guardian-$g.toml" && grep -q "^genesis_hash = \"$GENESIS_HASH\"" "mainnet/guardian-$g.toml"; } \
        || { (( dry )) && echo "# (dry run: guardian-$g.toml is not on chain $TO yet; --yes would refuse)" || die "guardian-$g.toml is not on chain $TO with genesis $GENESIS_HASH"; }
    done
    echo "+ GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh"
    if (( yes )); then GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh; fi
    # Last of all, after every guardian (droplets started by `droplet`, laptop just above).
    check_hostkey
    run "${RSSH[@]}" "set -e
$(switched /etc/rand-relayer.toml) || { echo 'error: relayer toml is not on chain $TO with its genesis' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { echo 'error: installed rand is not v$NEW_VERSION' >&2; exit 1; }
systemctl start rand-relayer; sleep 15; systemctl is-active rand-relayer; journalctl -u rand-relayer -n 4 --no-pager"
    ;;
  rollback-rand)
    need_sha RAND_OLD_SHA
    check_hostkey
    run "${RSSH[@]}" "set -e
! systemctl is-active -q rand-relayer || { echo 'stop the relayer first' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand.pre-c22 | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'rand.pre-c22 is NOT RAND_OLD_SHA - NOTHING RESTORED; stop here' >&2; exit 1; }
install -m 755 /usr/local/bin/rand.pre-c22 /usr/local/bin/rand
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'the restored rand is NOT RAND_OLD_SHA - stop here' >&2; exit 1; }
/usr/local/bin/rand --version"
    ;;
  selftest)
    T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
    SRC=$SELF
    mkdir -p "$T/bin" "$T/home/.rand-bridge/mainnet-set1" "$T/home/.ssh" "$T/tree/mainnet"
    for i in 1 2 3 4 5 6; do echo "$i 10.0.0.$i"; done > "$T/home/.rand-bridge/mainnet-set1/hosts.txt"
    mkdir -p "$T/home/.rand-bridge/relayer-host"
    printf 'public 10.0.0.9\nhostkey SHA256:selftest-relayer-host-key\n' > "$T/home/.rand-bridge/relayer-host/host.txt"
    unset RELAYER_IP RELAYER_HOSTKEY
    cp "$SRC" "$T/tree/mainnet/cut-chain22.sh"
    G22=2222222222222222222222222222222222222222222222222222222222222222   # a stand-in chain-22 genesis
    for g in 7 8; do
      printf 'chain_id = 21                         # comment\ngenesis_hash = "%s"   # chain 21\n' "$OLD_GENESIS" > "$T/tree/mainnet/guardian-$g.toml"
      mkdir -p "$T/tree/data/mainnet/guardian-$g/cursors"
    done
    printf '#!/bin/sh\necho "RUN-GUARDIANS pq=$GUARDIAN_PQ_FROM_NEXT" >> "$FAKELOG"\n' > "$T/tree/mainnet/run-guardians-set1.sh"
    printf '#!/bin/sh\necho "pkill $*" >> "$FAKELOG"\n' > "$T/bin/pkill"
    printf '#!/bin/sh\necho "ssh $*" >> "$FAKELOG"\n' > "$T/bin/ssh"
    printf '#!/bin/sh\necho "scp $*" >> "$FAKELOG"\n' > "$T/bin/scp"
    printf '#!/bin/sh\necho "x 256 [fake]"\n' > "$T/bin/ssh-keyscan"
    # The chain-22 node at RAND_RPC: chain FAKE_CHAIN (22), genesis FAKE_GENESIS, burn_sequence FAKE_BURN_SEQ (14).
    cat > "$T/bin/curl" <<'CURL'
#!/bin/sh
echo "curl $*" >> "$FAKELOG"
case "$*" in
  *rand_chainId*) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":${FAKE_CHAIN:-22}}" ;;
  *rand_getGenesisHash*) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"${FAKE_GENESIS}\"}" ;;
  *rand_getBridgeState*) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"enabled\":true,\"burn_sequence\":${FAKE_BURN_SEQ:-14},\"guardian_set_index\":1}}" ;;
  *) echo '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}' ;;
esac
CURL
    cat > "$T/bin/ssh-keygen" <<'KG'
#!/bin/sh
cat >/dev/null; echo "256 ${FAKE_FPR:-SHA256:selftest-relayer-host-key} fake (ED25519)"
KG
    chmod +x "$T"/bin/* "$T/tree/mainnet/run-guardians-set1.sh"
    good="$T/rand-v087"; echo good > "$good"
    export FAKELOG="$T/log" HOME="$T/home" PATH="$T/bin:$PATH" BURN_SEQ=14 GENESIS_HASH=$G22 FAKE_GENESIS=$G22
    export RAND_NEW_SHA; RAND_NEW_SHA=$(local_sha "$good")
    export RAND_OLD_SHA=1111111111111111111111111111111111111111111111111111111111111111
    S="$T/tree/mainnet/cut-chain22.sh"
    fails=0
    ok() { echo "ok   - $1"; }
    bad() { echo "FAIL - $1"; fails=$((fails+1)); }
    : > "$FAKELOG"
    "$S" status --yes >/dev/null
    grep -q 'sha256sum /usr/local/bin/rand' "$FAKELOG" && ok "status reads the installed rand" || bad "status"
    : > "$FAKELOG"
    "$S" stop --yes >/dev/null
    "$S" relayer-rand "$good" --yes >/dev/null
    for i in 1 2 3 4 5 6; do "$S" droplet "$i" --yes >/dev/null; done
    "$S" relayer --yes >/dev/null
    "$S" laptop --yes >/dev/null
    "$S" start --yes >/dev/null
    L=$(grep -n 'systemctl start rand-relayer' "$FAKELOG" | cut -d: -f1)
    [[ $(grep -c 'systemctl start rand-relayer' "$FAKELOG") == 1 ]] && ok "relayer started exactly once" || bad "relayer start count"
    G=$(grep -n 'systemctl start rand-guardian' "$FAKELOG" | tail -1 | cut -d: -f1)
    P=$(grep -n 'RUN-GUARDIANS pq=1' "$FAKELOG" | cut -d: -f1)
    (( L > G && L > P )) && ok "relayer starts after all droplet and laptop guardians" || bad "start order"
    [[ $(tail -1 "$FAKELOG") == *'systemctl start rand-relayer'* ]] && ok "relayer start is the last command" || bad "relayer start not last"
    SW=$(grep -n 'rand.c22' "$FAKELOG" | head -1 | cut -d: -f1); ST=$(grep -n 'systemctl stop rand-relayer' "$FAKELOG" | head -1 | cut -d: -f1)
    (( ST < SW )) && ok "binary swap after stop" || bad "swap before stop"
    grep -q "rand.pre-c22.*cut" "$FAKELOG" && grep -q "$RAND_OLD_SHA" "$FAKELOG" && grep -q 'SHA MISMATCH' "$FAKELOG" && ok "remote backup + sha guards present" || bad "remote guards missing"
    grep -q "genesis_hash = \"$OLD_GENESIS\"/genesis_hash = \"$G22\"" "$FAKELOG" && grep -q 'rand_getGenesisHash' "$FAKELOG" && ok "host configs take chain 22's genesis, checked against each host's node" || bad "host genesis switch"
    grep -q '^chain_id = 22 ' "$T/tree/mainnet/guardian-7.toml" && grep -q "^genesis_hash = \"$G22\"   # chain 21" "$T/tree/mainnet/guardian-7.toml" && [[ -f "$T/tree/mainnet/guardian-8.toml.chain21" ]] && ok "laptop tomls moved (both lines, comments kept), .chain21 kept" || bad "laptop tomls"
    grep -q '"next_sequence": 14' "$T/tree/data/mainnet/guardian-8/cursors/rand.json" && [[ -d "$T/tree/data/mainnet/guardian-7/cursors.chain21" ]] && ok "laptop cursors reset, copy kept" || bad "laptop cursors"
    grep -q 'rand_getBridgeState' "$FAKELOG" && grep -qF '"burn_sequence":14' "$FAKELOG" && ok "BURN_SEQ checked against the chain (local) and the guardian hosts' nodes" || bad "burn_sequence checks missing"
    # The host-side check after the sed, run here on three configs: switched with the genesis line,
    # a pre-BR-1005 config with no genesis line (accepted, with a NOTE), one still on chain 21's genesis.
    GENESIS_HASH=$G22
    printf 'chain_id = 22 \ngenesis_hash = "%s"\n' "$G22" > "$T/h-new.toml"
    printf 'chain_id = 22 \n' > "$T/h-old-binary.toml"
    printf 'chain_id = 22 \ngenesis_hash = "%s"\n' "$OLD_GENESIS" > "$T/h-stale.toml"
    bash -c "$(switched "$T/h-new.toml")" >/dev/null && ok "host check: chain 22 + its genesis accepted" || bad "host check refused a switched config"
    bash -c "$(switched "$T/h-old-binary.toml")" | grep -q NOTE && ok "host check: a config without a genesis line passes with a NOTE" || bad "host check on a pre-BR-1005 config"
    if bash -c "$(switched "$T/h-stale.toml")" >/dev/null; then bad "host check accepted chain 21's genesis"; else ok "host check: chain 21's genesis refused"; fi
    # BURN_SEQ and GENESIS_HASH against the chain: a cursor or a genesis line is never written wrong.
    : > "$FAKELOG"; echo '{"next_block": 0, "next_sequence": 14}' > "$T/tree/data/mainnet/guardian-7/cursors/rand.json"
    if BURN_SEQ=15 "$S" laptop --yes >/dev/null 2>&1; then bad "BURN_SEQ 15 accepted with the chain at 14"; else ok "BURN_SEQ ahead of the chain refused"; fi
    grep -q '"next_sequence": 14' "$T/tree/data/mainnet/guardian-7/cursors/rand.json" && ok "refused local step wrote no cursor" || bad "refused local step wrote a cursor"
    if FAKE_BURN_SEQ=13 "$S" relayer --yes >/dev/null 2>&1; then bad "chain at 13 accepted for BURN_SEQ 14"; else ok "BURN_SEQ behind the chain refused"; fi
    if FAKE_BURN_SEQ=13 "$S" droplet 2 --yes >/dev/null 2>&1; then bad "guardian-host step with the chain at 13"; else ok "guardian-host step refused when the chain disagrees"; fi
    if FAKE_CHAIN=21 "$S" relayer --yes >/dev/null 2>&1; then bad "a chain-21 node accepted as the chain-22 RPC"; else ok "a node on another chain refused"; fi
    if FAKE_GENESIS=$OLD_GENESIS "$S" droplet 3 --yes >/dev/null 2>&1; then bad "a node serving another genesis accepted"; else ok "a node serving another genesis refused"; fi
    grep -q 'ssh' "$FAKELOG" && bad "a refused step still reached a host" || ok "refused steps contacted no host"
    # inputs that do not exist before the cut are required, never defaulted
    if GENESIS_HASH='' "$S" relayer --yes >/dev/null 2>&1; then bad "no GENESIS_HASH accepted"; else ok "GENESIS_HASH required"; fi
    if GENESIS_HASH=$OLD_GENESIS FAKE_GENESIS=$OLD_GENESIS "$S" laptop --yes >/dev/null 2>&1; then bad "chain 21's genesis accepted as chain 22's"; else ok "chain 21's genesis refused as GENESIS_HASH"; fi
    if GENESIS_HASH=abc "$S" droplet 1 --yes >/dev/null 2>&1; then bad "a short GENESIS_HASH accepted"; else ok "a malformed GENESIS_HASH refused"; fi
    if RAND_NEW_SHA='' "$S" relayer-rand "$good" --yes >/dev/null 2>&1; then bad "no RAND_NEW_SHA accepted"; else ok "RAND_NEW_SHA required"; fi
    if RAND_OLD_SHA='' "$S" rollback-rand --yes >/dev/null 2>&1; then bad "no RAND_OLD_SHA accepted"; else ok "RAND_OLD_SHA required"; fi
    grep -q 'ssh' "$FAKELOG" && bad "a step missing an input reached a host" || ok "missing inputs contacted no host"
    # refusals
    echo bad > "$T/rand-bad"; : > "$FAKELOG"
    if "$S" relayer-rand "$T/rand-bad" --yes >/dev/null 2>&1; then bad "mismatched rand accepted"; else ok "mismatched rand refused"; fi
    [[ ! -s "$FAKELOG" ]] && ok "mismatch sent nothing to the host" || bad "mismatch contacted the host"
    if FAKE_FPR=SHA256:wrong "$S" relayer-rand "$good" --yes >/dev/null 2>&1; then bad "wrong host key accepted"; else ok "wrong host key refused"; fi
    [[ ! -s "$FAKELOG" ]] && ok "wrong host key sent nothing" || bad "host-key mismatch contacted the host"
    mv "$T/home/.rand-bridge/relayer-host/host.txt" "$T/host.txt.away"; : > "$FAKELOG"
    if "$S" relayer-rand "$good" --yes >/dev/null 2>&1; then bad "relayer step ran with no relayer host configured"; else ok "no relayer host configured: refused"; fi
    [[ ! -s "$FAKELOG" ]] && ok "an unconfigured relayer host is never contacted" || bad "unconfigured relayer host contacted"
    mv "$T/host.txt.away" "$T/home/.rand-bridge/relayer-host/host.txt"
    if "$S" start --yes >/dev/null 2>&1 && printf 'chain_id = 21 \ngenesis_hash = "%s"\n' "$OLD_GENESIS" > "$T/tree/mainnet/guardian-7.toml" && "$S" start --yes >/dev/null 2>&1; then bad "start with guardian-7 on 21"; else ok "start refused while a guardian is on chain 21"; fi
    printf 'chain_id = 22 \ngenesis_hash = "%s"\n' "$OLD_GENESIS" > "$T/tree/mainnet/guardian-7.toml"
    if "$S" start --yes >/dev/null 2>&1; then bad "start with guardian-7 on 22 under chain 21's genesis"; else ok "start refused while a guardian holds chain 21's genesis"; fi
    : > "$FAKELOG"; DRY_RUN=1 "$S" droplet 1 --yes >/dev/null; DRY_RUN=1 "$S" start --yes >/dev/null 2>&1 || true
    [[ ! -s "$FAKELOG" ]] && ok "DRY_RUN contacts nothing" || bad "DRY_RUN contacted something"
    (( fails == 0 )) && echo "SELFTEST PASSED" || { echo "SELFTEST: $fails failure(s)"; exit 1; }
    exit 0
    ;;
  *)
    sed -n '2,44p' "$SELF"; exit 1 ;;
esac
(( dry )) && echo "DRY_RUN: every command above was printed only; nothing was contacted or changed."
(( yes || dry )) || echo "DRY RUN: nothing was executed; re-run with --yes."
