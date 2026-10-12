FROM node:20-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    AUTO_INSTALL_TOOLS=0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils iperf3 iputils-ping mtr-tiny \
    net-tools nmap openssl snmp tcpdump traceroute tshark tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY public ./public
COPY server ./server

RUN mkdir -p /app/data && chmod 0755 /app/data

EXPOSE 8787
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8787/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "server/index.js"]
