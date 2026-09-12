#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=../cs2monitor.sh
source "$(dirname -- "$0")/../cs2monitor.sh"
make_work
trap cleanup EXIT
fixture="$WORK/fixture.json"
jq -n --argjson now "$(date +%s)" '{schemaVersion:2,categories:["abuse"],includePorts:true,includeDerived:true,generatedAt:($now*1000),count:4,items:[{type:"ip",value:"8.8.8.8"},{type:"subnet",value:"8.8.8.0/24"},{type:"server_address",value:"193.23.195.8:27013"},{type:"server_address",value:"193.23.195.8:27013"}]}' > "$fixture"
expect_fail() { if ( "$@" ) >"$WORK/failure.log" 2>&1; then die "Unexpected success: $*"; fi; }
validate_json "$fixture"
render_rules "$fixture" "$WORK/fixture.nft"
grep -q '193.23.195.8 . 27013' "$WORK/fixture.nft"
grep -q 'tcp dport @endpoints' "$WORK/fixture.nft"
grep -q 'udp dport @endpoints' "$WORK/fixture.nft"
if grep -q 'flush ruleset' "$WORK/fixture.nft"; then die 'Unexpected global firewall reset'; fi
for filter in '.categories=["unclassified"]' '.includePorts=false' '.includeDerived=false' '.schemaVersion=1' '.count=5' '.items=[]' '.generatedAt=1' '.items[0].value="8.8.8.8; flush ruleset"' '.items[0].value="127.0.0.1"' '.items[0].value="10.0.0.1"' '.items[0].value="224.0.0.1"' '.items[0].value="08.8.8.8"' '.items[1].value="0.0.0.0/0"' '.items[1].value="8.8.8.1/24"' '.items[2].value="193.23.195.8:65536"' '.items[2].value="193.23.195.8:0"'; do
    jq "$filter" "$fixture" > "$WORK/invalid.json"
    expect_fail validate_json "$WORK/invalid.json"
done
jq '.generatedAt=1' "$fixture" > "$WORK/old.json"
validate_json "$WORK/old.json" false
jq '.categories=["restricted"]' "$WORK/old.json" > "$WORK/invalid.json"
expect_fail validate_json "$WORK/invalid.json" false
[[ $(dependency_command arch) == *pacman* ]]
[[ $(dependency_command ubuntu) == *apt* ]]
[[ $(dependency_command fedora) == *dnf* ]]
[[ $(dependency_command opensuse-tumbleweed) == *zypper* ]]
expect_fail main update --manual

# Mock only kernel/system services for lifecycle tests; exercise the actual files.
STATE="$WORK/state"; PROGRAM="$WORK/lib/cs2monitor.sh"; LEGACY_PROGRAM="$WORK/lib/cs2monitor.py"; UNITS="$WORK/units"
mkdir -p "$STATE" "$WORK/lib" "$UNITS"
printf legacy > "$LEGACY_PROGRAM"
printf unrelated > "$UNITS/unrelated.service"
cp "$fixture" "$STATE/last-good.json"
download_list() { cp "$fixture" "$1"; }
table_exists() { return 0; }
apply_list() { validate_json "$1" "${2:-true}"; }
systemctl() { printf '%s\n' "$*" >> "$WORK/systemctl.log"; }
install_updater true
[[ -x $PROGRAM && ! -e $LEGACY_PROGRAM ]]
grep -q 'cs2monitor.sh restore' "$UNITS/cs2monitor-firewall-restore.service"
grep -q 'OnUnitActiveSec=3h' "$UNITS/cs2monitor-firewall-update.timer"
grep -q 'enable --now cs2monitor-firewall-update.timer' "$WORK/systemctl.log"
install_updater false
grep -q 'disable --now cs2monitor-firewall-update.timer' "$WORK/systemctl.log"
cp "$STATE/last-good.json" "$WORK/before.json"
apply_list() { die 'Injected nft failure'; }
expect_fail update_list
cmp "$STATE/last-good.json" "$WORK/before.json"
download_list() { die 'Injected download failure'; }
expect_fail update_list
cmp "$STATE/last-good.json" "$WORK/before.json"
table_exists() { return 1; }
uninstall_updater
[[ ! -e $PROGRAM && ! -e $STATE/last-good.json ]]
[[ $(cat "$UNITS/unrelated.service") == unrelated ]]

# Cross-process exclusion (also uses v1 lock path on a real installation).
LOCK="$WORK/test.lock"
acquire_lock
expect_fail flock --nonblock "$LOCK" true
flock --unlock "$lock_fd"
printf '%s\n' 'PASS: JSON validation, injection rejection, exact ports, cached restore, distro commands, migration from v1, install/manual/uninstall, update failure and locking'
