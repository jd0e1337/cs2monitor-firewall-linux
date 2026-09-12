#!/usr/bin/env python3
"""CS2monitor Linux firewall updater. Python standard library only."""
import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request

VERSION = '1.1.0'
URL = 'https://www.cs2monitor.com/api/blocklist/export?categories=abuse&includeDerived=true&includePorts=true'
TABLE = 'cs2monitor'
STATE = Path('/var/lib/cs2monitor-firewall')
PROGRAM = Path('/usr/local/lib/cs2monitor-firewall/cs2monitor.py')
UNITS = Path('/etc/systemd/system')
MAX_BYTES = 16 * 1024 * 1024


def run(args, text=None):
    return subprocess.run(args, input=text, text=True, capture_output=True, check=True, timeout=90).stdout


def validate(data, now=None, fresh=True):
    now = time.time() * 1000 if now is None else now
    if not isinstance(data, dict) or data.get('schemaVersion') != 2:
        raise ValueError('Unsupported blocklist format')
    if data.get('categories') != ['abuse'] or data.get('includePorts') is not True or data.get('includeDerived') is not True:
        raise ValueError('Expected abuse-only list with exact ports and derived addresses')
    stamp = data.get('generatedAt')
    if type(stamp) not in (int, float) or not 0 < stamp < float('inf'):
        raise ValueError('Invalid list timestamp')
    if fresh and not now - 1800000 <= stamp <= now + 300000:
        raise ValueError('Stale list; existing firewall preserved')
    items = data.get('items')
    if not isinstance(items, list) or not 0 < len(items) <= 100000 or type(data.get('count')) is not int or data['count'] != len(items):
        raise ValueError('Empty, oversized or incomplete list; existing firewall preserved')
    networks, endpoints = set(), set()
    for row in items:
        if not isinstance(row, dict) or not isinstance(row.get('value'), str):
            raise ValueError('Invalid list entry')
        kind, value = row.get('type'), row['value']
        if kind == 'ip':
            ip = ipaddress.IPv4Address(value)
            if not ip.is_global:
                raise ValueError('Non-public IP rejected')
            networks.add(ipaddress.IPv4Network(str(ip) + '/32'))
        elif kind == 'subnet':
            network = ipaddress.IPv4Network(value, strict=True)
            if network.prefixlen < 8 or not network.network_address.is_global or not network.broadcast_address.is_global:
                raise ValueError('Non-public or overly broad subnet rejected')
            networks.add(network)
        elif kind == 'server_address':
            ip_text, port_text = value.split(':')
            ip = ipaddress.IPv4Address(ip_text)
            if not ip.is_global or not port_text.isascii() or not port_text.isdecimal() or not 1 <= int(port_text) <= 65535:
                raise ValueError('Invalid IP:port')
            endpoints.add((str(ip), int(port_text)))
        else:
            raise ValueError('Unknown entry type')
    return list(ipaddress.collapse_addresses(networks)), sorted(endpoints, key=lambda row: (int(ipaddress.IPv4Address(row[0])), row[1]))


def render(data, fresh=True):
    networks, endpoints = validate(data, fresh=fresh)
    lines = [f'table inet {TABLE} {{', ' set addresses { type ipv4_addr; flags interval;']
    if networks:
        lines.append(' elements = { ' + ', '.join(map(str, networks)) + ' }')
    lines += [' }', ' set endpoints { type ipv4_addr . inet_service;']
    if endpoints:
        lines.append(' elements = { ' + ', '.join(f'{ip} . {port}' for ip, port in endpoints) + ' }')
    lines += [' }', ' chain output { type filter hook output priority -10; policy accept;',
              ' ip daddr @addresses counter drop',
              ' ip daddr . tcp dport @endpoints counter drop',
              ' ip daddr . udp dport @endpoints counter drop', ' }', '}', '']
    return '\n'.join(lines)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirect rejected; existing firewall preserved')


def download():
    request = urllib.request.Request(URL, headers={'User-Agent': f'CS2monitor-Linux/{VERSION}', 'Accept': 'application/json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        if response.headers.get_content_type() != 'application/json':
            raise ValueError('Expected JSON response')
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Download too large')
    data = json.loads(raw)
    validate(data)
    return data


def root():
    if os.geteuid() != 0:
        raise ValueError('Run this command with sudo')
    os.umask(0o077)


@contextlib.contextmanager
def lock():
    # Keep the lock file after uninstall so concurrent invocations share one inode.
    with open('/run/lock/cs2monitor-firewall.lock', 'a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another CS2monitor operation is running; try again shortly')
        yield


def distribution():
    values = {}
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                values[key] = ' '.join(shlex.split(value))
    except (OSError, ValueError):
        pass
    return values


def dependency_command(info=None):
    info = distribution() if info is None else info
    families = [info.get('ID', ''), *info.get('ID_LIKE', '').split()]
    for family in families:
        if family in ('arch', 'manjaro', 'endeavouros'):
            return 'sudo pacman -Syu --needed python nftables ca-certificates'
        if family in ('debian', 'ubuntu', 'linuxmint'):
            return 'sudo apt install python3 nftables ca-certificates'
        if family in ('fedora', 'rhel', 'centos', 'rocky', 'almalinux'):
            return 'sudo dnf install python3 nftables ca-certificates'
        if family in ('opensuse', 'opensuse-tumbleweed', 'opensuse-leap', 'suse'):
            return 'sudo zypper install python3 nftables ca-certificates'
    return 'Install Python 3.9+, nftables, CA certificates and systemd using your distribution package manager.'


def check_environment():
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('A running systemd system is required, including for --manual installation. Containers, OpenRC and non-systemd WSL are not supported.')
    for tool in ('nft', 'systemctl'):
        if not shutil.which(tool):
            raise ValueError(f'Missing {tool}. {dependency_command()}')
    for service in ('ufw', 'firewalld'):
        if subprocess.run(['systemctl', 'is-active', '--quiet', service], capture_output=True).returncode == 0:
            raise ValueError(f'Active {service} is not supported; no firewall changes made. Do not disable your firewall just to install this updater.')


def table_exists():
    data = json.loads(run(['nft', '-j', 'list', 'tables']))
    return any(item.get('table', {}).get('family') == 'inet' and item.get('table', {}).get('name') == TABLE for item in data['nftables'])


def apply(data, fresh=True):
    text = render(data, fresh=fresh)
    if table_exists():
        text = f'delete table inet {TABLE}\n' + text
    run(['nft', '--check', '-f', '-'], text)
    run(['nft', '-f', '-'], text)  # Single atomic transaction, including deletion.


def atomic_write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def update():
    data = download()
    # Stage persistent state before touching the firewall. Promote only after success.
    pending = STATE / 'pending.json'
    atomic_write(pending, json.dumps(data))
    apply(data)
    os.replace(pending, STATE / 'last-good.json')
    print(f'Updated {data["count"]} entries; abuse only, exact TCP/UDP ports retained.')


RESTORE = '''[Unit]
Description=Restore CS2monitor firewall
After=local-fs.target nftables.service
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/lib/cs2monitor-firewall/cs2monitor.py restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
UPDATE = '''[Unit]
Description=Update CS2monitor firewall
Wants=network-online.target
After=network-online.target cs2monitor-firewall-restore.service
[Service]
Type=oneshot
ExecStart=/usr/local/lib/cs2monitor-firewall/cs2monitor.py update
TimeoutStartSec=180
Nice=10
UMask=0077
'''
TIMER = '''[Unit]
Description=Update CS2monitor blocklist every three hours
[Timer]
OnBootSec=1min
OnUnitActiveSec=3h
RandomizedDelaySec=1min
Unit=cs2monitor-firewall-update.service
[Install]
WantedBy=timers.target
'''


def install(automatic):
    if table_exists() and not (STATE / 'last-good.json').exists():
        raise ValueError('An unmanaged inet cs2monitor table exists; inspect it before installing')
    update()  # Validate download and nft support before installing services.
    atomic_write(PROGRAM, Path(__file__).read_text(), 0o755)
    atomic_write(UNITS / 'cs2monitor-firewall-restore.service', RESTORE, 0o644)
    atomic_write(UNITS / 'cs2monitor-firewall-update.service', UPDATE, 0o644)
    atomic_write(UNITS / 'cs2monitor-firewall-update.timer', TIMER, 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'cs2monitor-firewall-restore.service'])
    if automatic:
        run(['systemctl', 'enable', '--now', 'cs2monitor-firewall-update.timer'])
    else:
        run(['systemctl', 'disable', '--now', 'cs2monitor-firewall-update.timer'])
    print('Installed. Automatic updates: ' + ('every three hours' if automatic else 'disabled'))


def uninstall():
    # The shared lock prevents uninstall from racing an update.
    for unit in ('cs2monitor-firewall-update.timer', 'cs2monitor-firewall-restore.service'):
        if (UNITS / unit).exists():
            run(['systemctl', 'disable', '--now', unit])
    if table_exists():
        run(['nft', 'delete', 'table', 'inet', TABLE])
    for name in ('cs2monitor-firewall-update.timer', 'cs2monitor-firewall-update.service', 'cs2monitor-firewall-restore.service'):
        (UNITS / name).unlink(missing_ok=True)
    for name in ('pending.json', 'last-good.json'):
        (STATE / name).unlink(missing_ok=True)
    PROGRAM.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    print('Removed CS2monitor rules and services. Downloaded files and journal logs remain.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['install', 'update', 'restore', 'status', 'uninstall', 'snapshot', 'doctor'])
    parser.add_argument('--manual', action='store_true', help='Install without automatic updates')
    parser.add_argument('--yes', action='store_true', help='Confirm install or uninstall without prompting')
    args = parser.parse_args()
    if args.command == 'doctor':
        print('Distribution: ' + distribution().get('PRETTY_NAME', 'Unknown Linux'))
        print('Dependencies: ' + dependency_command())
        check_environment()
        print('Prerequisites found. Installation will also validate nftables kernel support before applying rules.')
        return
    if args.command == 'snapshot':
        print(render(download()), end='')
        return
    root()
    if args.command in ('install', 'uninstall') and not args.yes:
        print('CS2monitor manages outbound IPv4 blocks for all local applications in its own nftables table.')
        if input(f'Type {args.command.upper()} to continue: ').strip() != args.command.upper():
            raise ValueError('Cancelled')
    with lock():
        if args.command in ('install', 'update', 'restore'):
            check_environment()
        if args.command == 'install':
            install(not args.manual)
        elif args.command == 'update':
            if not PROGRAM.exists():
                raise ValueError('Run install first')
            update()
        elif args.command == 'restore':
            apply(json.loads((STATE / 'last-good.json').read_text()), fresh=False)
            print('Restored last successful blocklist')
        elif args.command == 'status':
            print('Firewall table: ' + ('present' if table_exists() else 'absent'))
            if (STATE / 'last-good.json').exists():
                data = json.loads((STATE / 'last-good.json').read_text())
                print(f'Last list: {time.ctime(data["generatedAt"] / 1000)}, {data["count"]} entries')
            result = subprocess.run(['systemctl', 'is-enabled', 'cs2monitor-firewall-update.timer'], capture_output=True, text=True)
            print('Automatic updates: ' + result.stdout.strip())
        else:
            uninstall()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'Error: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
