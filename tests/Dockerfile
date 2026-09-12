ARG BASE=debian:12-slim
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then apt-get update && apt-get install -y --no-install-recommends python3 nftables iproute2 ca-certificates systemd && rm -rf /var/lib/apt/lists/*; \
    elif command -v pacman >/dev/null; then pacman -Syu --noconfirm --needed python nftables iproute2 ca-certificates systemd; \
    elif command -v dnf >/dev/null; then dnf install -y python3 nftables iproute ca-certificates systemd && dnf clean all; \
    elif command -v zypper >/dev/null; then zypper --non-interactive install python3 nftables iproute2 ca-certificates systemd && zypper clean --all; \
    else exit 1; fi
WORKDIR /test
COPY . .
CMD ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]
