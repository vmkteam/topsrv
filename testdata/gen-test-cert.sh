#!/bin/sh
set -e
DIR="${1:-/etc/nginx/ssl}"
mkdir -p "$DIR"
if [ ! -f "$DIR/test.pem" ]; then
  apk add --no-cache openssl >/dev/null 2>&1 || true
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$DIR/test.key" -out "$DIR/test.pem" \
    -days 30 -nodes -subj "/CN=test.example.com/O=topsrv-test" 2>/dev/null
fi
