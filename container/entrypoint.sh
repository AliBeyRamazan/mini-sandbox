#!/usr/bin/env bash
set -u

SAMPLE="/sample/input"
OUT="/out"
LIMIT="${SANDBOX_TIMEOUT:-15}"

mkdir -p "$OUT"
: > "$OUT/processes.log"
: > "$OUT/network.log"
: > "$OUT/stdout.log"
: > "$OUT/stderr.log"
: > "$OUT/strace.log"

snapshot_loop() {
  while true; do
    {
      echo "===== $(date -Iseconds) ====="
      ps auxww
      echo
    } >> "$OUT/processes.log" 2>&1

    {
      echo "===== $(date -Iseconds) ====="
      ss -tunap 2>/dev/null || true
      ip route 2>/dev/null || true
      echo
    } >> "$OUT/network.log" 2>&1

    sleep 1
  done
}

snapshot_loop &
SNAPSHOT_PID="$!"

cleanup() {
  kill "$SNAPSHOT_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [ ! -f "$SAMPLE" ]; then
  echo "Sample not found at $SAMPLE" >> "$OUT/stderr.log"
  exit 2
fi

if [ -x "$SAMPLE" ]; then
  TARGET=("$SAMPLE")
else
  TARGET=("/bin/sh" "$SAMPLE")
fi

timeout --kill-after=2s "$LIMIT" \
  strace -f -tt -s 256 -o "$OUT/strace.log" "${TARGET[@]}" \
  > "$OUT/stdout.log" \
  2> "$OUT/stderr.log"

STATUS="$?"
echo "$STATUS" > "$OUT/exit_code"
exit 0
