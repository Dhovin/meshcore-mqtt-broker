#!/bin/sh
set -e

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

if [ "$(id -u)" = "0" ]; then
  DATA_DIR=$(dirname "${ABUSE_PERSISTENCE_PATH:-/data/abuse-detection.db}")
  mkdir -p "$DATA_DIR"
  chown -R "${PUID}:${PGID}" "$DATA_DIR"
  exec su-exec "${PUID}:${PGID}" "$@"
fi

exec "$@"
