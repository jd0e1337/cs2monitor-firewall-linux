# cs2monitor-firewall-linux

Block unwanted CS2 servers on Linux. Uses the CS2monitor **Abuse Servers** list and nftables.

Version 2 is written in **Bash**. Python is not required. HTTPS downloads use curl, JSON validation uses jq, and firewall changes use nftables.

**Platforms:** Debian 12/13, Ubuntu 24.04, Arch Linux, Fedora and openSUSE Tumbleweed with systemd, Bash 4.4+, curl, jq 1.6+ and nftables. Manjaro and EndeavourOS use the Arch instructions but are not individually tested. Requires sudo. Active UFW or firewalld is not supported; installation stops instead of changing their configuration.

## Install

1. Download the **tar.gz** from [Releases](https://github.com/jd0e1337/cs2monitor-firewall-linux/releases/latest) and extract it.
2. Open a terminal in the extracted folder.
3. Install the dependencies for your distribution:

| Distribution | Install dependencies |
|---|---|
| Debian / Ubuntu / Linux Mint | `sudo apt install bash curl jq nftables ca-certificates util-linux` |
| Arch / Manjaro / EndeavourOS | `sudo pacman -Syu --needed bash curl jq nftables ca-certificates util-linux` |
| Fedora | `sudo dnf install bash curl-minimal jq nftables ca-certificates util-linux` |
| openSUSE Tumbleweed | `sudo zypper install bash curl jq nftables ca-certificates util-linux` |

4. Check the system and install:

```sh
bash cs2monitor.sh doctor
sudo bash cs2monitor.sh install
```

Type **INSTALL** when asked. The first blocklist is applied immediately. Automatic updates run about one minute after boot and every three hours afterwards. The last successful list is restored on reboot, even without an internet connection.

For manual updates only, use `sudo bash cs2monitor.sh install --manual` instead.

## What is blocked?

- Only **Abuse Servers**. Restricted and Unclassified entries are excluded.
- An IP or network entry blocks all outgoing connections to it.
- An IP:port entry blocks only that TCP and UDP destination port. Other ports remain accessible unless another rule blocks them.
- Capacity pauses (more than 64 slots or more players than slots) are included when classified as Abuse.

Rules affect **all applications on this Linux machine**. They do not filter incoming traffic, IPv6, or forwarded container/router traffic. Existing firewall tables remain untouched. CS2monitor only manages its own `inet cs2monitor` table.

## Update and status

```sh
sudo bash /usr/local/lib/cs2monitor-firewall/cs2monitor.sh update
sudo bash /usr/local/lib/cs2monitor-firewall/cs2monitor.sh status
journalctl -u cs2monitor-firewall-update.service -n 30
```

New valid lists replace old rules, including removal of released servers. If the download fails, is empty or invalid, the existing rules stay in place. Only the blocklist updates automatically, not the program.

To upgrade the program, download the new release and run its installation command again.

Upgrading from version 1 works the same way: `sudo bash cs2monitor.sh install`. The installer replaces the old systemd commands, preserves the saved-list format and removes the old Python script. Use `--manual` again if you do not want automatic updates. Python itself is never uninstalled.

## Remove

```sh
sudo bash /usr/local/lib/cs2monitor-firewall/cs2monitor.sh uninstall
```

Type **UNINSTALL**. This removes the CS2monitor firewall table, timer, services and saved list. Downloaded files and system journal logs remain. Other firewall rules are preserved.

## Download a snapshot

```sh
bash cs2monitor.sh snapshot > cs2monitor-snapshot.nft
```

This only downloads and renders the current list for inspection. It does not change the firewall. For applying the list without a timer, use the manual installation above.

## Notes

- Firewall reloads by another tool can remove the CS2monitor table. Run `update` to restore it; the timer also rebuilds it on the next successful update.
- Test support is intentionally limited to nftables without UFW/firewalld. The installer never disables another firewall manager.
- The first installation needs access to `www.cs2monitor.com`. No account or API key is needed.
- Release downloads include a separate `SHA256SUMS` checksum file.

## Development

```sh
bash tests/unit.sh
```

CI runs in Debian 12, Debian 13, Ubuntu 24.04, Arch Linux, Fedora and openSUSE Tumbleweed containers. It exercises distribution packages and real packet filtering on the runner kernel, not a full desktop boot. Linux Mint, Manjaro and EndeavourOS are compatible-family instructions, not individual test targets.

The integration test exercises real nftables rules and TCP/UDP filtering. Run it only in a disposable network namespace (see the CI workflow). It must never run directly on a normal host. OpenRC, non-systemd WSL and immutable systems such as SteamOS are outside the supported installation path.
