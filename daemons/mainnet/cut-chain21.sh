#!/usr/bin/env bash
# Moves the bridge daemons from Rand chain 20 to chain 21 (fullnode v0.8.0: constraint set 9, private
# multisig). Mirrors fullnode's deploy/chain21-bridge-steps.md (origin/main 74c73b5a) step for step.
# The endpoints, emitters and fees do not change; only chain_id and the Rand burn cursor do, plus the
# relayer's `rand` (0.6.8 -> v0.8.0). Prints every command; runs them only with --yes. In this order:
#
#   stop                  [1] relayer + laptop guardians 7-8 + droplet guardians (before the snapshot)
#   relayer-rand RANDFILE [3] on rand-relayer-1, relayer STOPPED, after the fleet's `switch`: back up the
#                         installed 0.6.8 `rand` as /usr/local/bin/rand.pre-c21 (checked against
#                         RAND_OLD_SHA), install the v0.8.0 `rand` from RANDFILE (checked against
#                         RAND_NEW_SHA locally and on the host), check the installed sha
#   droplet <1..6>        [4] once that droplet's rand-node answers for chain 21: guardian config to
#                         chain_id 21, Rand cursor to BURN_SEQ, guardian started
#   relayer               [5] /etc/rand-relayer.toml to chain_id 21, Rand cursor to BURN_SEQ, `rand` is
#                         0.8.0 (the relayer is NOT started here)
#   laptop                [5] guardian-7/8.toml to chain_id 21, their Rand cursors to BURN_SEQ
#   start                 [6] laptop guardians 7-8 (pq-next seeds), THEN the relayer, never before
#   rollback-rand         rollback: restore rand.pre-c21 as `rand` (relayer stopped; sha checked twice)
#   selftest              rehearsal with ssh/scp/ssh-keyscan shimmed by fakes: contacts nothing
#
# Inputs: BURN_SEQ (chain 21 rand_getBridgeState.burn_sequence; 14 expected).
# Modes: no --yes = print only; --yes = run; DRY_RUN=1 = print every command, contact/touch nothing
# (wins over --yes). Relayer host key is checked against RELAYER_HOSTKEY before any relayer ssh.
# shellcheck disable=SC2015,SC2016
set -euo pipefail
SELF=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
cd "$(dirname "$SELF")/.."

FROM=20; TO=21
RELAYER_IP=167.172.65.45
RELAYER_HOSTKEY='SHA256:emiVrQXryU8L12wv4PWsmkap04SAh8bfqss2bpR0pyI'
RAND_OLD_SHA=155dfe6667a85ea8071977512dc40c750127b9baa9b4fa4796d101c8fc1eee2d   # rand 0.6.8
RAND_NEW_SHA=e3a38e74ee28743a960fc1c3eb1ac6c538e18dc259411e10afff7f54e268bbf4   # rand 0.8.0
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
die() { echo "error: $*" >&2; exit 1; }
local_sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
answers() { printf 'curl -s -m 5 -X POST -H "content-type: application/json" --data '"'"'{"jsonrpc":"2.0","id":1,"method":"rand_chainId","params":[]}'"'"' http://127.0.0.1:8545 | grep -q '"'"'"result":%s\\b'"'"'' "$TO"; }
sedi() { sed -i.bak -E "$1" "$2" && rm -f "$2.bak"; }

# The relayer host key must be the recorded one before any command reaches it.
check_hostkey() {
  echo "+ ssh-keyscan -t ed25519 $RELAYER_IP | ssh-keygen -lf -   # expect $RELAYER_HOSTKEY"
  (( yes )) || return 0
  local got
  got=$(ssh-keyscan -t ed25519 "$RELAYER_IP" 2>/dev/null | ssh-keygen -lf - | awk '{print $2}')
  [[ "$got" == "$RELAYER_HOSTKEY" ]] || die "relayer host key is '$got', not $RELAYER_HOSTKEY; nothing was run"
}

case "$step" in
  stop)
    check_hostkey
    run "${RSSH[@]}" 'systemctl stop rand-relayer; systemctl is-active rand-relayer || true'
    run pkill -f 'rand-guardian --config mainnet/guardian-[78].toml' || true
    for i in 1 2 3 4 5 6; do run "${SSH[@]}" "root@$(ip_of "$i")" 'systemctl stop rand-guardian; systemctl is-active rand-guardian || true'; done
    ;;
  relayer-rand)
    [[ -n "$arg" ]] || die "usage: relayer-rand <path to the v0.8.0 Linux rand> [--yes]"
    if (( dry )) && [[ ! -f "$arg" ]]; then
      echo "# (dry run: $arg not present, local sha check skipped; --yes refuses unless it is $RAND_NEW_SHA)"
    else
      [[ -f "$arg" ]] || die "$arg: no such file"
      [[ "$(local_sha "$arg")" == "$RAND_NEW_SHA" ]] || die "$arg sha256 is not $RAND_NEW_SHA; SHA MISMATCH, nothing sent"
    fi
    check_hostkey
    run "${RSCP[@]}" "$arg" "root@$RELAYER_IP:/root/rand.c21"
    run "${RSSH[@]}" "set -e
! systemctl is-active -q rand-relayer || { echo 'stop the relayer first' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'installed rand is NOT the 0.6.8 binary recorded 2026-10-12 - no backup made, nothing installed' >&2; exit 1; }
[ -e /usr/local/bin/rand.pre-c21 ] || cp -a /usr/local/bin/rand /usr/local/bin/rand.pre-c21
[ \"\$(sha256sum /usr/local/bin/rand.pre-c21 | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'rand.pre-c21 is NOT the 0.6.8 binary - sort it out by hand; nothing installed' >&2; exit 1; }
[ \"\$(sha256sum /root/rand.c21 | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { rm -f /root/rand.c21; echo 'SHA MISMATCH' >&2; exit 1; }
install -m 755 /root/rand.c21 /usr/local/bin/rand
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { echo 'the installed rand is NOT the v0.8.0 binary - stop here' >&2; exit 1; }
/usr/local/bin/rand --version | grep -q '0\\.8\\.0'
/usr/local/bin/rand --version"
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
  relayer)
    need BURN_SEQ
    check_hostkey
    run "${RSSH[@]}" "set -e
! systemctl is-active -q rand-relayer || { echo 'error: the relayer is still running' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { echo 'error: installed rand is not v0.8.0; run relayer-rand first' >&2; exit 1; }
[ ! -e /etc/rand-relayer.toml.chain$FROM ]
cp -p /etc/rand-relayer.toml /etc/rand-relayer.toml.chain$FROM
sed -i -E 's/^chain_id = $FROM /chain_id = $TO /' /etc/rand-relayer.toml
grep -q '^chain_id = $TO ' /etc/rand-relayer.toml
cp -rp /var/lib/rand-relayer/data/cursors /var/lib/rand-relayer/data/cursors.chain$FROM
echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > /var/lib/rand-relayer/data/cursors/rand.json
chown -R relayer: /var/lib/rand-relayer/data
/usr/local/bin/rand --version | grep -q '0\\.8\\.0'
systemctl is-active rand-relayer || true   # inactive: it starts at 'start', after the guardians"
    ;;
  laptop)
    need BURN_SEQ
    for f in mainnet/guardian-7.toml mainnet/guardian-8.toml; do
      run cp -p "$f" "$f.chain$FROM"
      echo "+ sed -i -E 's/^chain_id = $FROM /chain_id = $TO /' $f"
      if (( yes )); then sedi "s/^chain_id = $FROM /chain_id = $TO /" "$f"; grep -q "^chain_id = $TO " "$f" || die "$f is not on chain $TO"; fi
    done
    for d in guardian-7 guardian-8; do
      run cp -Rp "data/mainnet/$d/cursors" "data/mainnet/$d/cursors.chain$FROM"
      echo "+ echo '{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}' > data/mainnet/$d/cursors/rand.json"
      (( yes )) && echo "{\"next_block\": 0, \"next_sequence\": $BURN_SEQ}" > "data/mainnet/$d/cursors/rand.json"
    done
    ;;
  start)
    for g in 7 8; do
      grep -q "^chain_id = $TO " "mainnet/guardian-$g.toml" || { (( dry )) && echo "# (dry run: guardian-$g.toml is not on chain $TO yet; --yes would refuse)" || die "guardian-$g.toml is not on chain $TO"; }
    done
    echo "+ GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh"
    if (( yes )); then GUARDIAN_PQ_FROM_NEXT=1 mainnet/run-guardians-set1.sh; fi
    # Last of all, after every guardian (droplets started by `droplet`, laptop just above).
    check_hostkey
    run "${RSSH[@]}" "set -e
grep -q '^chain_id = $TO ' /etc/rand-relayer.toml || { echo 'error: relayer toml is not on chain $TO' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_NEW_SHA' ] || { echo 'error: installed rand is not v0.8.0' >&2; exit 1; }
systemctl start rand-relayer; sleep 15; systemctl is-active rand-relayer; journalctl -u rand-relayer -n 4 --no-pager"
    ;;
  rollback-rand)
    check_hostkey
    run "${RSSH[@]}" "set -e
! systemctl is-active -q rand-relayer || { echo 'stop the relayer first' >&2; exit 1; }
[ \"\$(sha256sum /usr/local/bin/rand.pre-c21 | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'rand.pre-c21 is NOT the 0.6.8 rand (155dfe66...ee2d) - NOTHING RESTORED; stop here' >&2; exit 1; }
install -m 755 /usr/local/bin/rand.pre-c21 /usr/local/bin/rand
[ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$RAND_OLD_SHA' ] || { echo 'the restored rand is NOT 0.6.8 - stop here' >&2; exit 1; }
/usr/local/bin/rand --version"
    ;;
  selftest)
    T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
    SRC=$SELF
    mkdir -p "$T/bin" "$T/home/.rand-bridge/mainnet-set1" "$T/home/.ssh" "$T/tree/mainnet"
    for i in 1 2 3 4 5 6; do echo "$i 10.0.0.$i"; done > "$T/home/.rand-bridge/mainnet-set1/hosts.txt"
    cp "$SRC" "$T/tree/mainnet/cut-chain21.sh"
    for g in 7 8; do
      echo 'chain_id = 20 ' > "$T/tree/mainnet/guardian-$g.toml"
      mkdir -p "$T/tree/../tree/data/mainnet/guardian-$g/cursors"
    done
    printf '#!/bin/sh\necho "RUN-GUARDIANS pq=$GUARDIAN_PQ_FROM_NEXT" >> "$FAKELOG"\n' > "$T/tree/mainnet/run-guardians-set1.sh"
    printf '#!/bin/sh\necho "pkill $*" >> "$FAKELOG"\n' > "$T/bin/pkill"
    printf '#!/bin/sh\necho "ssh $*" >> "$FAKELOG"\n' > "$T/bin/ssh"
    printf '#!/bin/sh\necho "scp $*" >> "$FAKELOG"\n' > "$T/bin/scp"
    printf '#!/bin/sh\necho "x 256 [fake]"\n' > "$T/bin/ssh-keyscan"
    cat > "$T/bin/ssh-keygen" <<'KG'
#!/bin/sh
cat >/dev/null; echo "256 ${FAKE_FPR:-SHA256:emiVrQXryU8L12wv4PWsmkap04SAh8bfqss2bpR0pyI} fake (ED25519)"
KG
    chmod +x "$T"/bin/* "$T/tree/mainnet/run-guardians-set1.sh"
    export FAKELOG="$T/log" HOME="$T/home" PATH="$T/bin:$PATH" BURN_SEQ=14
    S="$T/tree/mainnet/cut-chain21.sh"
    good="$T/rand-v080"; echo good > "$good"
    # the selftest uses a stand-in sha: override via a patched copy so no real binary is needed
    gsha=$(local_sha "$good")
    sed -i.bak "s/^RAND_NEW_SHA=[0-9a-f]*/RAND_NEW_SHA=$gsha/" "$S"; rm -f "$S.bak"
    fails=0
    ok() { echo "ok   - $1"; }
    bad() { echo "FAIL - $1"; fails=$((fails+1)); }
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
    SW=$(grep -n 'rand.c21' "$FAKELOG" | head -1 | cut -d: -f1); ST=$(grep -n 'systemctl stop rand-relayer' "$FAKELOG" | head -1 | cut -d: -f1)
    (( ST < SW )) && ok "binary swap after stop" || bad "swap before stop"
    grep -q "rand.pre-c21.*cut" "$FAKELOG" && grep -q "$RAND_OLD_SHA" "$FAKELOG" && grep -q 'SHA MISMATCH' "$FAKELOG" && ok "remote backup + sha guards present" || bad "remote guards missing"
    grep -q '^chain_id = 21 ' "$T/tree/mainnet/guardian-7.toml" && [[ -f "$T/tree/mainnet/guardian-8.toml.chain20" ]] && ok "laptop tomls moved, .chain20 kept" || bad "laptop tomls"
    grep -q '"next_sequence": 14' "$T/tree/data/mainnet/guardian-8/cursors/rand.json" && [[ -d "$T/tree/data/mainnet/guardian-7/cursors.chain20" ]] && ok "laptop cursors reset, copy kept" || bad "laptop cursors"
    # refusals
    echo bad > "$T/rand-bad"; : > "$FAKELOG"
    if "$S" relayer-rand "$T/rand-bad" --yes >/dev/null 2>&1; then bad "mismatched rand accepted"; else ok "mismatched rand refused"; fi
    [[ ! -s "$FAKELOG" ]] && ok "mismatch sent nothing to the host" || bad "mismatch contacted the host"
    if FAKE_FPR=SHA256:wrong "$S" relayer-rand "$good" --yes >/dev/null 2>&1; then bad "wrong host key accepted"; else ok "wrong host key refused"; fi
    [[ ! -s "$FAKELOG" ]] && ok "wrong host key sent nothing" || bad "host-key mismatch contacted the host"
    if "$S" start --yes >/dev/null 2>&1 && echo 'chain_id = 20 ' > "$T/tree/mainnet/guardian-7.toml" && "$S" start --yes >/dev/null 2>&1; then bad "start with guardian-7 on 20"; else ok "start refused while a guardian is on chain 20"; fi
    : > "$FAKELOG"; DRY_RUN=1 "$S" droplet 1 --yes >/dev/null; DRY_RUN=1 "$S" start --yes >/dev/null 2>&1 || true
    [[ ! -s "$FAKELOG" ]] && ok "DRY_RUN contacts nothing" || bad "DRY_RUN contacted something"
    (( fails == 0 )) && echo "SELFTEST PASSED" || { echo "SELFTEST: $fails failure(s)"; exit 1; }
    exit 0
    ;;
  *)
    sed -n '2,25p' "$SELF"; exit 1 ;;
esac
(( dry )) && echo "DRY_RUN: every command above was printed only; nothing was contacted or changed."
(( yes || dry )) || echo "DRY RUN: nothing was executed; re-run with --yes."
