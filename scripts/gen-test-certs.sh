#!/bin/sh
# Generate a self-signed cert for nginx + angie integration tests.
# Runs on the host (openssl is assumed available) — avoids the ~90s
# `apk add openssl` inside the container which races the healthcheck.
# Idempotent: skips if a valid (≥7 days left) cert already exists.
set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)/testdata/certs"
mkdir -p "$DIR"

CERT="$DIR/test.pem"
KEY="$DIR/test.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    if openssl x509 -in "$CERT" -noout -checkend 604800 2>/dev/null; then
        echo "test-certs: $CERT valid for ≥7 days, skipping"
        exit 0
    fi
    echo "test-certs: $CERT expiring or invalid, regenerating"
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$KEY" -out "$CERT" \
    -days 365 -nodes -subj "/CN=test.example.com/O=topsrv-test" 2>/dev/null
chmod 0644 "$CERT" "$KEY"
echo "test-certs: generated $CERT (valid 365 days)"
