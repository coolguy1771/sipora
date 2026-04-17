#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Usage: $0 <target_host:port>}"
DURATION="${2:-60}"
RATE="${3:-100}"

echo "=== SIP Load Test ==="
echo "Target: $TARGET"
echo "Duration: ${DURATION}s"
echo "Rate: ${RATE} calls/sec"
echo ""

echo "--- REGISTER test (p99 < 100ms target) ---"
sipp "$TARGET" \
  -sf register.xml \
  -inf users.csv \
  -r "$RATE" \
  -d "$((DURATION * 1000))" \
  -l 5000 \
  -t tn \
  -trace_stat \
  -stf register_stats.csv \
  -fd 1 \
  -m "$((RATE * DURATION))"

echo ""
echo "--- INVITE test (p99 < 500ms target) ---"
sipp "$TARGET" \
  -sf invite.xml \
  -inf users.csv \
  -r "$((RATE / 10))" \
  -d "$((DURATION * 1000))" \
  -l 5000 \
  -t tn \
  -trace_stat \
  -stf invite_stats.csv \
  -fd 1 \
  -m "$((RATE / 10 * DURATION))"

echo ""
echo "=== Tests complete. See *_stats.csv for results. ==="
