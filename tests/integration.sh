#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${CS2_DISPOSABLE_NETWORK:-} == yes ]] || { printf '%s\n' 'Requires a disposable network namespace' >&2; exit 1; }
# shellcheck source=../cs2monitor.sh
source "$(dirname -- "$0")/../cs2monitor.sh"
make_work
trap cleanup EXIT
ip link set lo up
ip addr add 193.23.195.8/32 dev lo
ip addr add 8.8.8.8/32 dev lo
nft add table inet unrelated
fixture="$WORK/fixture.json"
jq -n --argjson now "$(date +%s)" '{schemaVersion:2,categories:["abuse"],includePorts:true,includeDerived:true,generatedAt:($now*1000),count:4,items:[{type:"ip",value:"8.8.8.8"},{type:"subnet",value:"8.8.8.0/24"},{type:"server_address",value:"193.23.195.8:27013"},{type:"server_address",value:"193.23.195.8:27013"}]}' > "$fixture"
apply_list "$fixture"
probe() {
    local ip=$1 port=$2 protocol=$3 expected=$4 listener received=false
    rm -f "$WORK/received"
    if [[ $protocol == TCP ]]; then
        timeout 2 socat -u "TCP4-LISTEN:$port,bind=$ip,reuseaddr" "OPEN:$WORK/received,creat" 2>/dev/null &
    else
        timeout 2 socat -u "UDP4-RECVFROM:$port,bind=$ip" "OPEN:$WORK/received,creat" 2>/dev/null &
    fi
    listener=$!
    sleep 0.1
    printf test | timeout 1 socat -u - "$protocol"4:"$ip":"$port" 2>/dev/null || true
    wait "$listener" || true
    if [[ -s $WORK/received ]]; then received=true; fi
    [[ $received == "$expected" ]] || die "Unexpected $protocol result for $ip:$port: $received"
}
for protocol in TCP UDP; do
    probe 193.23.195.8 27013 "$protocol" false
    probe 193.23.195.8 27014 "$protocol" true
    probe 8.8.8.8 27015 "$protocol" false
done
jq '.items=.items[:2] | .count=2' "$fixture" > "$WORK/released.json"
apply_list "$WORK/released.json"
for protocol in TCP UDP; do probe 193.23.195.8 27013 "$protocol" true; done
nft list table inet unrelated >/dev/null
printf 'delete table inet cs2monitor\nthis is invalid\n' > "$WORK/bad.nft"
if nft -f "$WORK/bad.nft" 2>/dev/null; then die 'Invalid transaction was accepted'; fi
table_exists
probe 8.8.8.8 27016 TCP false
nft delete table inet cs2monitor
jq '.generatedAt=1' "$WORK/released.json" > "$WORK/cached.json"
apply_list "$WORK/cached.json" false
probe 8.8.8.8 27016 UDP false
nft delete table inet cs2monitor
nft list table inet unrelated >/dev/null
# Check generated services with the real systemd parser (no host installation).
create_units
install -D -m755 "$SOURCE" "$PROGRAM"
install -m644 "$WORK/restore.service" "$UNITS/cs2monitor-firewall-restore.service"
install -m644 "$WORK/update.service" "$UNITS/cs2monitor-firewall-update.service"
install -m644 "$WORK/update.timer" "$UNITS/cs2monitor-firewall-update.timer"
systemd-analyze verify "$UNITS/cs2monitor-firewall-restore.service" "$UNITS/cs2monitor-firewall-update.service" "$UNITS/cs2monitor-firewall-update.timer"
printf '%s\n' 'PASS: real TCP/UDP filtering, exact ports, overlapping subnet merge, release, atomic failure, reboot restore, unrelated tables and systemd units'
