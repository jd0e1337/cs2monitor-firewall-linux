ARG BASE=debian:12-slim
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 nftables iproute2 ca-certificates systemd && rm -rf /var/lib/apt/lists/*
WORKDIR /test
COPY . .
CMD ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]
