#!/usr/bin/env bash
# CS2monitor Linux firewall updater. No Python or other language runtime.
set -Eeuo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

VERSION=2.1.0
URL='https://www.cs2monitor.com/api/blocklist/export?categories=abuse&includeDerived=true&includePorts=true'
TABLE=cs2monitor
STATE=/var/lib/cs2monitor-firewall
PROGRAM=/usr/local/lib/cs2monitor-firewall/cs2monitor.sh
LEGACY_PROGRAM=/usr/local/lib/cs2monitor-firewall/cs2monitor.py
UNITS=/etc/systemd/system
LOCK=/run/lock/cs2monitor-firewall.lock
MAX_BYTES=16777216
WORK=
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SOURCE="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
cleanup() { if [[ -n $WORK && -d $WORK ]]; then rm -r -- "$WORK"; fi; }
make_work() { WORK=$(mktemp -d /tmp/cs2monitor-firewall.XXXXXXXX) || die 'Cannot create temporary directory'; }

dependency_command() {
    local family=${1:-} key value
    if [[ -z $family && -r /etc/os-release ]]; then
        while IFS='=' read -r key value; do
            case $key in ID|ID_LIKE) family+=" ${value//\"/}" ;; esac
        done < /etc/os-release
    fi
    case " $family " in
        *' arch '*|*' manjaro '*|*' endeavouros '*) printf '%s\n' 'sudo pacman -Syu --needed bash curl jq nftables ca-certificates util-linux' ;;
        *' debian '*|*' ubuntu '*|*' linuxmint '*) printf '%s\n' 'sudo apt install bash curl jq nftables ca-certificates util-linux' ;;
        *' fedora '*|*' rhel '*|*' rocky '*|*' almalinux '*) printf '%s\n' 'sudo dnf install bash curl-minimal jq nftables ca-certificates util-linux' ;;
        *' opensuse'*|*' suse '*) printf '%s\n' 'sudo zypper install bash curl jq nftables ca-certificates util-linux' ;;
        *) printf '%s\n' 'Install Bash 4.4+, curl, jq 1.6+, nftables, CA certificates, coreutils, util-linux and systemd.' ;;
    esac
}

require_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null || die "Missing $tool. $(dependency_command)"
    done
}

check_firewalls() {
    local service properties key value loaded active
    for service in ufw firewalld; do
        loaded=; active=
        properties=$(systemctl show "$service.service" --property=LoadState --property=ActiveState) || die "Cannot inspect $service.service through systemd"
        while IFS='=' read -r key value; do
            case $key in LoadState) loaded=$value ;; ActiveState) active=$value ;; esac
        done <<< "$properties"
        [[ -n $loaded && -n $active ]] || die "Incomplete systemd response for $service.service"
        if [[ $loaded == loaded && ( $active == active || $active == activating || $active == reloading ) ]]; then
            die "$service.service is loaded and $active in systemd. Check: systemctl status $service.service"
        fi
    done
}

install_dependencies() {
    local tool package manager
    local -a packages=()
    for tool in curl jq nft flock timeout; do
        if ! command -v "$tool" >/dev/null; then
            case $tool in nft) package=nftables ;; flock) package=util-linux ;; timeout) package=coreutils ;; *) package=$tool ;; esac
            packages+=("$package")
        fi
    done
    if [[ ! -s /etc/ssl/certs/ca-certificates.crt && ! -s /etc/pki/tls/certs/ca-bundle.crt && ! -s /etc/ssl/ca-bundle.pem ]]; then packages+=(ca-certificates); fi
    (( ${#packages[@]} )) || return 0
    printf 'Installing missing dependencies: %s\n' "${packages[*]}"
    for manager in apt-get pacman dnf zypper; do
        command -v "$manager" >/dev/null || continue
        case $manager in
            apt-get)
                apt-get update || die 'Package index update failed'
                apt-get install -y -- "${packages[@]}" || die 'Dependency installation failed' ;;
            pacman) pacman -S --needed --noconfirm -- "${packages[@]}" || die 'Dependency installation failed. Update Arch with sudo pacman -Syu, then retry.' ;;
            dnf) dnf install -y -- "${packages[@]}" || die 'Dependency installation failed' ;;
            zypper) zypper --non-interactive install -- "${packages[@]}" || die 'Dependency installation failed' ;;
        esac
        return
    done
    die "No supported package manager found. $(dependency_command)"
}

check_environment() {
    [[ -d /run/systemd/system ]] || die 'A running systemd system is required, also for --manual installation.'
    require_tools nft systemctl flock curl jq timeout install mktemp stat
    check_firewalls
}

acquire_lock() {
    [[ ! -L $LOCK ]] || die 'Refusing a symbolic-link lock file'
    # Same lock as v1, so upgrades cannot race a Python updater already running.
    exec {lock_fd}>>"$LOCK" || die 'Cannot open operation lock'
    flock --nonblock "$lock_fd" || die 'Another CS2monitor operation is running; try again shortly'
}

validate_json() {
    local file=$1 fresh=${2:-true} bytes
    bytes=$(stat -c %s -- "$file") || die 'Cannot read list'
    (( bytes > 0 && bytes <= MAX_BYTES )) || die 'Empty or oversized list; existing rules preserved'
    # Reject reserved/local destinations and networks overlapping them. Only canonical
    # numeric addresses reach nft, never arbitrary text from the HTTP response.
    jq -e --argjson now "$(date +%s)" --argjson fresh "$fresh" '
      def integer: type == "number" and . == floor;
      def ipnum:
        if type != "string" or (test("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}$")|not)
        then error("invalid IPv4") else split(".")|map(tonumber)|
          if all(.[]; . >= 0 and . <= 255) then reduce .[] as $o (0; . * 256 + $o)
          else error("invalid octet") end end;
      def public_range($a;$b):
        [[0,16777215],[167772160,184549375],[1681915904,1686110207],
         [2130706432,2147483647],[2851995648,2852061183],[2886729728,2887778303],
         [3221225472,3221225727],[3221225984,3221226239],[3227017984,3227018239],
         [3232235520,3232301055],[3323068416,3323199487],[3325256704,3325256959],
         [3405803776,3405804031],[3758096384,4294967295]] |
        all(.[]; $b < .[0] or $a > .[1]);
      def valid_entry:
        if type != "object" or (.value|type) != "string" then false
        elif .type == "ip" then (.value|ipnum) as $n | public_range($n;$n)
        elif .type == "subnet" then
          (.value|split("/")) as $p |
          if ($p|length) != 2 or ($p[1]|test("^(8|9|[12][0-9]|3[0-2])$")|not) then false
          else ($p[0]|ipnum) as $n | ($p[1]|tonumber) as $prefix | pow(2;32-$prefix) as $size |
            ($n % $size == 0 and public_range($n;$n+$size-1)) end
        elif .type == "server_address" then
          (.value|split(":")) as $p |
          if ($p|length) != 2 or ($p[1]|test("^[1-9][0-9]{0,4}$")|not) then false
          else ($p[0]|ipnum) as $n | ($p[1]|tonumber) as $port |
            ($port <= 65535 and public_range($n;$n)) end
        else false end;
      type == "object" and .schemaVersion == 2 and .categories == ["abuse"] and
      .includePorts == true and .includeDerived == true and
      (.generatedAt|type) == "number" and .generatedAt > 0 and .generatedAt < 1e16 and
      (($fresh|not) or (.generatedAt >= ($now*1000-1800000) and .generatedAt <= ($now*1000+300000))) and
      (.items|type) == "array" and (.items|length) > 0 and (.items|length) <= 100000 and
      (.count|integer) and .count == (.items|length) and all(.items[]; valid_entry)
    ' "$file" >/dev/null || die 'Invalid, empty or stale list; existing firewall preserved'
}

download_list() {
    local file=$1 status content_type
    curl --disable --proto '=https' --tlsv1.2 --fail --silent --show-error \
        --connect-timeout 10 --max-time 45 --max-redirs 0 --max-filesize "$MAX_BYTES" \
        --user-agent "CS2monitor-Linux/$VERSION" --header 'Accept: application/json' \
        --output "$file" --write-out '%{http_code}\n%{content_type}\n' "$URL" > "$WORK/http-meta" \
        || die 'Download failed; existing firewall preserved'
    { read -r status; read -r content_type; } < "$WORK/http-meta"
    [[ $status == 200 && $content_type == application/json* ]] || die 'Expected HTTP 200 JSON; redirects are not accepted'
    validate_json "$file"
}

render_rules() {
    local file=$1 output=$2 fresh=${3:-true} addresses endpoints
    validate_json "$file" "$fresh"
    addresses=$(jq -r '[.items[]|select(.type=="ip" or .type=="subnet")|.value]|unique|join(", ")' "$file") || die 'Cannot render addresses'
    endpoints=$(jq -r '[.items[]|select(.type=="server_address")|.value|split(":")|.[0]+" . "+.[1]]|unique|join(", ")' "$file") || die 'Cannot render ports'
    {
        printf 'table inet %s {\n set addresses { type ipv4_addr; flags interval; auto-merge;\n' "$TABLE"
        if [[ -n $addresses ]]; then printf ' elements = { %s }\n' "$addresses"; fi
        printf ' }\n set endpoints { type ipv4_addr . inet_service;\n'
        if [[ -n $endpoints ]]; then printf ' elements = { %s }\n' "$endpoints"; fi
        printf '%s\n' ' }' ' chain output { type filter hook output priority -10; policy accept;' \
            ' ip daddr @addresses counter drop' ' ip daddr . tcp dport @endpoints counter drop' \
            ' ip daddr . udp dport @endpoints counter drop' ' }' '}'
    } > "$output" || die 'Cannot write ruleset'
}

table_exists() {
    timeout 90 nft -j list tables > "$WORK/tables.json" || die 'Cannot inspect nftables'
    jq -e --arg table "$TABLE" 'any(.nftables[]; .table.family=="inet" and .table.name==$table)' "$WORK/tables.json" >/dev/null
}

apply_list() {
    local file=$1 fresh=${2:-true}
    render_rules "$file" "$WORK/rules.nft" "$fresh"
    : > "$WORK/transaction.nft"
    if table_exists; then printf 'delete table inet %s\n' "$TABLE" > "$WORK/transaction.nft"; fi
    cat "$WORK/rules.nft" >> "$WORK/transaction.nft"
    timeout 90 nft --check -f "$WORK/transaction.nft" || die 'nftables validation failed; existing rules preserved'
    timeout 90 nft -f "$WORK/transaction.nft" || die 'Atomic firewall update failed'
}

write_file() {
    local source=$1 target=$2 mode=$3 temporary directory
    directory=$(dirname -- "$target")
    [[ ! -L $directory && ! -L $target ]] || die 'Refusing a symbolic-link installation target'
    mkdir -p -- "$directory"
    temporary=$(mktemp "$directory/.cs2monitor.XXXXXXXX") || die 'Cannot stage installed file'
    install -m "$mode" -- "$source" "$temporary" || { rm -f -- "$temporary"; die 'Cannot write installed file'; }
    mv -f -- "$temporary" "$target" || die 'Cannot promote installed file'
}

update_list() {
    local pending="$STATE/pending.json"
    [[ ! -L $STATE && ! -L $pending && ! -L $STATE/last-good.json ]] || die 'Refusing symbolic-link state'
    mkdir -p -- "$STATE"
    chmod 700 -- "$STATE"
    download_list "$WORK/download.json"
    write_file "$WORK/download.json" "$pending" 600
    apply_list "$pending"
    mv -f -- "$pending" "$STATE/last-good.json" || die 'Rules applied, but persistent state could not be saved'
    printf 'Updated %s entries; abuse only, exact TCP/UDP ports retained.\n' "$(jq -r .count "$STATE/last-good.json")"
}

create_units() {
    cat > "$WORK/restore.service" <<'UNIT'
[Unit]
Description=Restore CS2monitor firewall
After=local-fs.target nftables.service
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/lib/cs2monitor-firewall/cs2monitor.sh restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
    cat > "$WORK/update.service" <<'UNIT'
[Unit]
Description=Update CS2monitor firewall
Wants=network-online.target
After=network-online.target cs2monitor-firewall-restore.service
[Service]
Type=oneshot
ExecStart=/usr/local/lib/cs2monitor-firewall/cs2monitor.sh update
TimeoutStartSec=300
Nice=10
UMask=0077
UNIT
    cat > "$WORK/update.timer" <<'UNIT'
[Unit]
Description=Update CS2monitor blocklist every three hours
[Timer]
OnBootSec=1min
OnUnitActiveSec=3h
RandomizedDelaySec=1min
Unit=cs2monitor-firewall-update.service
[Install]
WantedBy=timers.target
UNIT
}

install_updater() {
    local automatic=$1
    if table_exists && [[ ! -f $STATE/last-good.json ]]; then die 'An unmanaged inet cs2monitor table exists'; fi
    update_list
    write_file "$SOURCE" "$PROGRAM" 755
    create_units
    write_file "$WORK/restore.service" "$UNITS/cs2monitor-firewall-restore.service" 644
    write_file "$WORK/update.service" "$UNITS/cs2monitor-firewall-update.service" 644
    write_file "$WORK/update.timer" "$UNITS/cs2monitor-firewall-update.timer" 644
    systemctl daemon-reload || die 'Could not reload systemd; rerun install to finish'
    systemctl enable cs2monitor-firewall-restore.service || die 'Could not enable reboot restoration'
    if [[ $automatic == true ]]; then
        systemctl enable --now cs2monitor-firewall-update.timer || die 'Could not enable automatic updates'
    else
        systemctl disable --now cs2monitor-firewall-update.timer || die 'Could not disable automatic updates'
    fi
    # v1 uses the same JSON state and lock; only remove its program after replacing units.
    rm -f -- "$LEGACY_PROGRAM"
    printf 'Installed Bash updater %s. Automatic updates: %s.\n' "$VERSION" "$automatic"
}

uninstall_updater() {
    local unit
    for unit in cs2monitor-firewall-update.timer cs2monitor-firewall-restore.service; do
        if [[ -f $UNITS/$unit ]]; then systemctl disable --now "$unit" || die "Cannot stop $unit"; fi
    done
    if table_exists; then timeout 90 nft delete table inet "$TABLE" || die 'Cannot remove CS2monitor table'; fi
    for unit in cs2monitor-firewall-update.timer cs2monitor-firewall-update.service cs2monitor-firewall-restore.service; do rm -f -- "$UNITS/$unit"; done
    rm -f -- "$STATE/pending.json" "$STATE/last-good.json" "$PROGRAM" "$LEGACY_PROGRAM"
    systemctl daemon-reload || die 'Could not reload systemd'
    printf '%s\n' 'Removed CS2monitor rules, services and saved list. Downloaded files and journal logs remain.'
}

main() {
    (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )) || die 'Bash 4.4+ is required'
    local command=${1:-help} automatic=true confirmed=false answer
    if (( $# )); then shift; fi
    while (( $# )); do
        case "$1" in
            --manual) [[ $command == install ]] || die '--manual is only valid for install'; automatic=false ;;
            --yes) [[ $command == install || $command == uninstall ]] || die '--yes is only valid for install/uninstall'; confirmed=true ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done
    case "$command" in
        help|--help|-h) printf '%s\n' 'Usage: bash cs2monitor.sh {doctor|install [--manual] [--yes]|update|restore|status|uninstall [--yes]|snapshot}'; return ;;
        doctor) printf 'Dependencies: %s\n' "$(dependency_command)"; check_environment; printf '%s\n' 'Prerequisites found. Installation also checks nftables kernel support.'; return ;;
        install|update|restore|status|uninstall|snapshot) ;;
        *) die "Unknown command: $command" ;;
    esac
    if [[ $command == install ]]; then
        (( EUID == 0 )) || die 'Run sudo bash cs2monitor.sh install (installs missing dependencies)'
        [[ -d /run/systemd/system ]] || die 'A running systemd system is required'
        require_tools systemctl
        check_firewalls
        if [[ $confirmed == false ]]; then
            printf 'Install missing system packages and CS2monitor outbound firewall rules? Type INSTALL: '
            read -r answer || die 'Cancelled'
            [[ $answer == INSTALL ]] || die 'Cancelled'
            confirmed=true
        fi
        install_dependencies
    fi
    require_tools jq curl timeout nft flock mktemp stat
    umask 077
    make_work
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ $command == snapshot ]]; then download_list "$WORK/list.json"; render_rules "$WORK/list.json" "$WORK/snapshot.nft"; cat "$WORK/snapshot.nft"; return; fi
    (( EUID == 0 )) || die 'Run this command with sudo'
    if [[ $confirmed == false && ( $command == install || $command == uninstall ) ]]; then
        printf 'CS2monitor manages outbound IPv4 blocks for all local applications in its own nftables table.\nType %s to continue: ' "${command^^}"
        read -r answer || die 'Cancelled'
        [[ $answer == "${command^^}" ]] || die 'Cancelled'
    fi
    acquire_lock
    case "$command" in install|update|restore) check_environment ;; esac
    case "$command" in
        install) install_updater "$automatic" ;;
        update) [[ -f $PROGRAM ]] || die 'Run install first'; update_list ;;
        restore) apply_list "$STATE/last-good.json" false; printf '%s\n' 'Restored last successful blocklist' ;;
        uninstall) uninstall_updater ;;
        status)
            if table_exists; then printf '%s\n' 'Firewall table: present'; else printf '%s\n' 'Firewall table: absent'; fi
            if [[ -f $STATE/last-good.json ]]; then jq -r '"Last list: \(.generatedAt / 1000 | todateiso8601), \(.count) entries"' "$STATE/last-good.json"; fi
            printf 'Automatic updates: '; systemctl is-enabled cs2monitor-firewall-update.timer || true ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
