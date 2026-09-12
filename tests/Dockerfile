ARG BASE=debian:12-slim
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then apt-get update && apt-get install -y --no-install-recommends bash curl jq nftables iproute2 ca-certificates systemd util-linux socat && rm -rf /var/lib/apt/lists/*; \
    elif command -v pacman >/dev/null; then pacman -Syu --noconfirm --needed bash curl jq nftables iproute2 ca-certificates systemd util-linux socat diffutils; \
    elif command -v dnf >/dev/null; then dnf install -y bash curl-minimal jq nftables iproute ca-certificates systemd util-linux socat && dnf clean all; \
    elif command -v zypper >/dev/null; then zypper --non-interactive install bash curl jq nftables iproute2 ca-certificates systemd util-linux socat && zypper clean --all; \
    else exit 1; fi
WORKDIR /test
COPY . .
CMD ["bash", "tests/unit.sh"]
