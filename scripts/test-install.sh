#!/bin/bash
# shellcheck disable=SC2016 # single-quoted sed patterns are intentional
set -euo pipefail

# Test install.sh in Docker containers.
# Uses locally built goreleaser binaries instead of GitHub releases.
# Forces --platform linux/amd64 for consistent arch detection on Apple Silicon.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PLATFORM="linux/amd64"

log() { echo "==> $*"; }
err() { echo "FAIL: $*" >&2; }
ok()  { echo "  OK: $*"; }

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    shift
    if "$@"; then
        ok "$name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        err "$name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# --- Test 1: ShellCheck ---
log "Test 1: ShellCheck"
run_test "ShellCheck passed" \
    docker run --rm -v "${PROJECT_DIR}:/work" koalaman/shellcheck:stable /work/scripts/install.sh

# --- Test 2: Fails without root ---
log "Test 2: Fails without root"
OUTPUT=$(docker run --rm --platform "$PLATFORM" --user 1000:1000 \
    -v "${PROJECT_DIR}:/work:ro" ubuntu:22.04 \
    bash -c "bash /work/scripts/install.sh" 2>&1 || true)
run_test "Correctly requires root" echo "$OUTPUT" | grep -q "requires root"

# --- Test 3: Fails on missing curl ---
log "Test 3: Fails on missing curl (alpine without curl)"
OUTPUT=$(docker run --rm --platform "$PLATFORM" \
    -v "${PROJECT_DIR}:/work:ro" alpine:3.19 \
    sh -c "apk add --no-cache bash >/dev/null 2>&1 && bash /work/scripts/install.sh" 2>&1 || true)
run_test "Correctly detects missing curl" echo "$OUTPUT" | grep -q "Required command not found: curl"

# --- Test 4: Fails on non-Linux ---
log "Test 4: Rejects non-Linux OS"
OUTPUT=$(bash -c '
    # Override uname to return FreeBSD
    uname() { if [ "$1" = "-s" ]; then echo "FreeBSD"; elif [ "$1" = "-m" ]; then echo "x86_64"; fi; }
    export -f uname
    id() { echo "uid=0(root)"; }
    export -f id
    source /dev/stdin <<< "$(cat scripts/install.sh)"
' 2>&1 || true)
run_test "Correctly rejects non-Linux" echo "$OUTPUT" | grep -q "Linux only"

# --- Prepare fake release for integration tests ---
log "Preparing fake release..."
FAKE_RELEASE=$(mktemp -d)
BINARY_SRC="${PROJECT_DIR}/dist/topsrv_linux_amd64_v1/topsrv"

if [ ! -f "$BINARY_SRC" ]; then
    err "Binary not found: $BINARY_SRC. Run 'goreleaser build --snapshot --clean' first."
    exit 1
fi

TARBALL_NAME="topsrv_0.0.1_linux_amd64.tar.gz"
tar -czf "${FAKE_RELEASE}/${TARBALL_NAME}" -C "$(dirname "$BINARY_SRC")" topsrv
(cd "$FAKE_RELEASE" && sha256sum "$TARBALL_NAME" > checksums.txt)

# Create patched install script that uses local files instead of GitHub.
sed \
    -e 's|curl -fsSL -o "${TMPDIR}/${TARBALL}" "${BASE_URL}/${TARBALL}"|cp "/fake-release/${TARBALL}" "${TMPDIR}/${TARBALL}"|' \
    -e 's|curl -fsSL -o "${TMPDIR}/checksums.txt" "${BASE_URL}/checksums.txt"|cp "/fake-release/checksums.txt" "${TMPDIR}/checksums.txt"|' \
    scripts/install.sh > "${FAKE_RELEASE}/install-patched.sh"

DOCKER_COMMON=(--rm --platform "$PLATFORM"
    -v "${PROJECT_DIR}:/work:ro"
    -v "${FAKE_RELEASE}:/fake-release:ro"
    -e VERSION=0.0.1)

# --- Test 5: Full install on Ubuntu 22.04 ---
log "Test 5: Full install on Ubuntu 22.04"
OUTPUT=$(docker run "${DOCKER_COMMON[@]}" ubuntu:22.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq curl >/dev/null 2>&1 && bash /fake-release/install-patched.sh" 2>&1)
echo "$OUTPUT"
run_test "Full install on Ubuntu 22.04 succeeded" echo "$OUTPUT" | grep -q "Checksum verified"

# --- Test 6: Full install on Ubuntu 20.04 ---
log "Test 6: Full install on Ubuntu 20.04"
OUTPUT=$(docker run "${DOCKER_COMMON[@]}" ubuntu:20.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq curl >/dev/null 2>&1 && bash /fake-release/install-patched.sh" 2>&1)
echo "$OUTPUT"
run_test "Full install on Ubuntu 20.04 succeeded" echo "$OUTPUT" | grep -q "Checksum verified"

# --- Test 7: Full install on Debian 12 ---
log "Test 7: Full install on Debian 12"
OUTPUT=$(docker run "${DOCKER_COMMON[@]}" debian:12 \
    bash -c "apt-get update -qq && apt-get install -y -qq curl >/dev/null 2>&1 && bash /fake-release/install-patched.sh" 2>&1)
echo "$OUTPUT"
run_test "Full install on Debian 12 succeeded" echo "$OUTPUT" | grep -q "Checksum verified"

# --- Test 8: Full install on Alpine 3.19 ---
log "Test 8: Full install on Alpine 3.19"
OUTPUT=$(docker run "${DOCKER_COMMON[@]}" alpine:3.19 \
    sh -c "apk add --no-cache bash curl tar >/dev/null 2>&1 && bash /fake-release/install-patched.sh" 2>&1)
echo "$OUTPUT"
run_test "Full install on Alpine 3.19 succeeded" echo "$OUTPUT" | grep -q "Checksum verified"

# --- Test 9: Checksum mismatch detection ---
log "Test 9: Checksum mismatch detection"
BAD_RELEASE=$(mktemp -d)
cp "${FAKE_RELEASE}/${TARBALL_NAME}" "${BAD_RELEASE}/${TARBALL_NAME}"
echo "0000000000000000000000000000000000000000000000000000000000000000  ${TARBALL_NAME}" > "${BAD_RELEASE}/checksums.txt"
sed \
    -e 's|curl -fsSL -o "${TMPDIR}/${TARBALL}" "${BASE_URL}/${TARBALL}"|cp "/bad-release/${TARBALL}" "${TMPDIR}/${TARBALL}"|' \
    -e 's|curl -fsSL -o "${TMPDIR}/checksums.txt" "${BASE_URL}/checksums.txt"|cp "/bad-release/checksums.txt" "${TMPDIR}/checksums.txt"|' \
    scripts/install.sh > "${BAD_RELEASE}/install-patched.sh"
OUTPUT=$(docker run --rm --platform "$PLATFORM" \
    -v "${BAD_RELEASE}:/bad-release:ro" \
    -e VERSION=0.0.1 \
    ubuntu:22.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq curl >/dev/null 2>&1 && bash /bad-release/install-patched.sh" 2>&1 || true)
echo "$OUTPUT"
run_test "Correctly detects checksum mismatch" echo "$OUTPUT" | grep -q "Checksum mismatch"
rm -rf "$BAD_RELEASE"

# Cleanup.
rm -rf "$FAKE_RELEASE"

# --- Summary ---
echo ""
log "Results: ${TESTS_PASSED} passed, ${TESTS_FAILED} failed"
if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
