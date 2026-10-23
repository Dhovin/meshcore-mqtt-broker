# Dockerfile for MeshCore MQTT Broker
FROM node:22-alpine

WORKDIR /app

# Install build tools for native C++ extensions (better-sqlite3) and runtime utilities
RUN apk add --no-cache python3 make g++ wget su-exec && \
    mkdir -p /data

# Copy package manifests
COPY package*.json tsconfig.json ./

# Install production dependencies (includes tsx and native dependencies)
# Use --jitless during build to prevent V8 ARM64 JIT SIGILL under QEMU emulation in CI
RUN NODE_OPTIONS="--jitless" npm ci --omit=dev && \
    apk del python3 make g++

# Copy application source code and entrypoint
COPY src/ ./src/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Environment variable defaults
ENV NODE_ENV=production \
    PUID=1000 \
    PGID=1000 \
    MQTT_WS_PORT=8883 \
    ENABLE_TCP_MQTT=false \
    MQTT_TCP_PORT=1883 \
    MQTT_HOST=0.0.0.0 \
    AUTH_EXPECTED_AUDIENCE="" \
    HTTP_REDIRECT_URL="" \
    SUBSCRIBER_MAX_CONNECTIONS_DEFAULT=2 \
    ABUSE_ENFORCEMENT_ENABLED=false \
    ABUSE_DUPLICATE_WINDOW_SIZE=100 \
    ABUSE_DUPLICATE_WINDOW_MS=300000 \
    ABUSE_DUPLICATE_THRESHOLD=10 \
    ABUSE_MAX_DUPLICATES_PER_PACKET=5 \
    ABUSE_DUPLICATE_RATE_THRESHOLD=0.3 \
    ABUSE_DUPLICATE_RATE_WINDOW_MS=300000 \
    ABUSE_BUCKET_CAPACITY=20 \
    ABUSE_BUCKET_REFILL_RATE=3 \
    ABUSE_MAX_PACKET_SIZE=255 \
    ABUSE_MAX_TOPICS_PER_DAY=3 \
    ABUSE_ANOMALY_THRESHOLD=10 \
    ABUSE_MAX_IATA_CHANGES_24H=3 \
    ABUSE_TOPIC_HISTORY_SIZE=50 \
    ABUSE_TOPIC_HISTORY_WINDOW_MS=86400000 \
    ABUSE_PERSISTENCE_PATH=/data/abuse-detection.db \
    ABUSE_PERSISTENCE_INTERVAL_MS=300000 \
    ABUSE_STATE_RETENTION_MS=604800000

# Ensure entrypoint has LF line endings and is executable, and set initial ownership on /data
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh && \
    chown -R node:node /data

EXPOSE 8883 1883

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --max-redirect=0 --spider http://127.0.0.1:${MQTT_WS_PORT:-8883}/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["npx", "tsx", "src/server.ts"]
